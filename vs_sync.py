#!/usr/bin/env python3
"""
vs_sync.py : Fetch CVEs from the NVD API 2.0 and store them locally in SQLite.

Stdlib only, no dependencies.

Usage:
  python3 vs_sync.py init                          # create the DB
  python3 vs_sync.py sync --days 7                 # initial pull: last N days of modifications
  python3 vs_sync.py sync                          # incremental: since last successful sync
  python3 vs_sync.py stats                         # summary of what's stored
  python3 vs_sync.py list --severity CRITICAL --status new --limit 20
  python3 vs_sync.py mark CVE-2026-1234 reviewed --note "patched on edge fleet"

Environment:
  NVD_API_KEY   optional; raises rate limit from 5 to 50 req / 30 s
  CVE_DB_PATH   optional; defaults to ./cve.db
"""

import argparse
import http.client
import json
import os
import sqlite3
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 2000
MAX_WINDOW_DAYS = 120          # NVD hard limit on lastModStartDate..lastModEndDate
DB_PATH = os.environ.get("CVE_DB_PATH", "cve.db")
API_KEY = os.environ.get("NVD_API_KEY", "")
SLEEP_BETWEEN_PAGES = 0.7 if API_KEY else 6.5   # stay under 50/30s or 5/30s

SCHEMA = """
CREATE TABLE IF NOT EXISTS cves (
    cve_id         TEXT PRIMARY KEY,
    published      TEXT,
    last_modified  TEXT,
    vuln_status    TEXT,
    description    TEXT,
    cvss_version   TEXT,
    cvss_score     REAL,
    cvss_severity  TEXT,
    cvss_vector    TEXT,
    cwes           TEXT,          -- JSON array of CWE ids
    reference_urls TEXT,          -- JSON array
    raw            TEXT,          -- full NVD JSON for the CVE
    review_status  TEXT DEFAULT 'new',   -- new | reviewed | ignored | watch
    review_note    TEXT,
    reviewed_at    TEXT,
    ingested_at    TEXT
);
CREATE INDEX IF NOT EXISTS idx_cves_severity ON cves (cvss_severity);
CREATE INDEX IF NOT EXISTS idx_cves_status   ON cves (review_status);
CREATE INDEX IF NOT EXISTS idx_cves_modified ON cves (last_modified);

CREATE TABLE IF NOT EXISTS sync_state (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""


def db_connect():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def db_init():
    conn = db_connect()
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()
    print(f"Database initialised at {os.path.abspath(DB_PATH)}")


# ---------------------------------------------------------------- NVD fetch

def nvd_get(params: dict) -> dict:
    qs = urllib.parse.urlencode(params)
    attempts = 8
    for attempt in range(attempts):
        req = urllib.request.Request(f"{NVD_URL}?{qs}")
        req.add_header("User-Agent", "cve-pipeline/1.0")
        if API_KEY:
            req.add_header("apiKey", API_KEY)
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            if e.code in (403, 429, 503):
                wait = 10 * (attempt + 1)
                print(f"  NVD returned {e.code}, backing off {wait}s...", file=sys.stderr)
                time.sleep(wait)
                continue
            raise
        except (urllib.error.URLError, OSError, TimeoutError,
                http.client.HTTPException, json.JSONDecodeError) as e:
            # covers ConnectionResetError, IncompleteRead, truncated bodies, DNS blips
            wait = 10 * (attempt + 1)
            print(f"  transfer error ({type(e).__name__}), retrying in {wait}s...",
                  file=sys.stderr)
            time.sleep(wait)
    raise RuntimeError(f"NVD API unreachable after {attempts} attempts")


def extract_cvss(metrics: dict):
    """Prefer v4.0, then v3.1, then v3.0, then v2. Prefer Primary source."""
    for key, version in (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"),
                         ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        entries = metrics.get(key) or []
        if not entries:
            continue
        entry = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        data = entry.get("cvssData", {})
        severity = data.get("baseSeverity") or entry.get("baseSeverity") or ""
        return version, data.get("baseScore"), severity.upper(), data.get("vectorString", "")
    return None, None, None, None


def parse_cve(item: dict) -> dict:
    cve = item["cve"]
    desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")
    version, score, severity, vector = extract_cvss(cve.get("metrics", {}))
    cwes = sorted({
        d["value"]
        for w in cve.get("weaknesses", [])
        for d in w.get("description", [])
        if d.get("value", "").startswith("CWE-")
    })
    refs = [r["url"] for r in cve.get("references", [])]
    return {
        "cve_id": cve["id"],
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "vuln_status": cve.get("vulnStatus"),
        "description": desc,
        "cvss_version": version,
        "cvss_score": score,
        "cvss_severity": severity,
        "cvss_vector": vector,
        "cwes": json.dumps(cwes),
        "reference_urls": json.dumps(refs),
        "raw": json.dumps(cve, separators=(",", ":")),
    }


UPSERT = """
INSERT INTO cves (cve_id, published, last_modified, vuln_status, description,
                  cvss_version, cvss_score, cvss_severity, cvss_vector,
                  cwes, reference_urls, raw, ingested_at)
VALUES (:cve_id, :published, :last_modified, :vuln_status, :description,
        :cvss_version, :cvss_score, :cvss_severity, :cvss_vector,
        :cwes, :reference_urls, :raw, :ingested_at)
ON CONFLICT(cve_id) DO UPDATE SET
    last_modified  = excluded.last_modified,
    vuln_status    = excluded.vuln_status,
    description    = excluded.description,
    cvss_version   = excluded.cvss_version,
    cvss_score     = excluded.cvss_score,
    cvss_severity  = excluded.cvss_severity,
    cvss_vector    = excluded.cvss_vector,
    cwes           = excluded.cwes,
    reference_urls = excluded.reference_urls,
    raw            = excluded.raw,
    ingested_at    = excluded.ingested_at
"""
# Note: review_status / review_note are deliberately NOT touched on update,
# so your triage survives NVD re-modifying a CVE.


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def sync_full(conn, now):
    """Pull the ENTIRE NVD corpus (no date filter). ~360k CVEs, ~180 pages.
    Progress is checkpointed after every page: rerun `sync --full` to resume."""
    row = conn.execute(
        "SELECT value FROM sync_state WHERE key='full_start_index'"
    ).fetchone()
    start_index = int(row[0]) if row else 0
    if start_index:
        print(f"Resuming full pull at index {start_index}")

    total_upserted = 0
    while True:
        data = nvd_get({"resultsPerPage": PAGE_SIZE, "startIndex": start_index})
        batch = data.get("vulnerabilities", [])
        total = data.get("totalResults", 0)

        ingested_at = iso(now)
        rows = [{**parse_cve(v), "ingested_at": ingested_at} for v in batch]
        start_index += len(batch)
        with conn:
            conn.executemany(UPSERT, rows)
            conn.execute(
                "INSERT INTO sync_state (key, value) VALUES ('full_start_index', ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (str(start_index),),
            )
        total_upserted += len(rows)

        print(f"  {start_index}/{total}")
        if start_index >= total or not batch:
            break
        time.sleep(SLEEP_BETWEEN_PAGES)

    with conn:
        conn.execute("DELETE FROM sync_state WHERE key='full_start_index'")
    return total_upserted


def sync(days: int | None, full: bool = False):
    conn = db_connect()
    conn.executescript(SCHEMA)

    now = datetime.now(timezone.utc)

    if full:
        n = sync_full(conn, now)
        with conn:
            conn.execute(
                "INSERT INTO sync_state (key, value) VALUES ('last_sync', ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (now.isoformat(),),
            )
        conn.close()
        print(f"Full pull done. {n} CVE records upserted. "
              f"Next `sync` resumes incrementally from {now:%Y-%m-%d %H:%M} UTC.")
        return

    row = conn.execute("SELECT value FROM sync_state WHERE key='last_sync'").fetchone()

    if days is not None:
        start = now - timedelta(days=days)
    elif row:
        start = datetime.fromisoformat(row[0])
    else:
        print("No previous sync found; defaulting to last 7 days. Use --days N to control this.")
        start = now - timedelta(days=7)

    total_upserted = 0
    window_start = start
    while window_start < now:
        window_end = min(window_start + timedelta(days=MAX_WINDOW_DAYS), now)
        print(f"Window {window_start:%Y-%m-%d %H:%M} -> {window_end:%Y-%m-%d %H:%M} UTC")

        start_index = 0
        while True:
            data = nvd_get({
                "lastModStartDate": iso(window_start),
                "lastModEndDate": iso(window_end),
                "resultsPerPage": PAGE_SIZE,
                "startIndex": start_index,
            })
            batch = data.get("vulnerabilities", [])
            total = data.get("totalResults", 0)

            ingested_at = iso(now)
            rows = [{**parse_cve(v), "ingested_at": ingested_at} for v in batch]
            with conn:
                conn.executemany(UPSERT, rows)
            total_upserted += len(rows)

            start_index += len(batch)
            print(f"  {start_index}/{total}")
            if start_index >= total or not batch:
                break
            time.sleep(SLEEP_BETWEEN_PAGES)

        window_start = window_end

    with conn:
        conn.execute(
            "INSERT INTO sync_state (key, value) VALUES ('last_sync', ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (now.isoformat(),),
        )
    conn.close()
    print(f"Done. {total_upserted} CVE records upserted. Next `sync` resumes from {now:%Y-%m-%d %H:%M} UTC.")


# ---------------------------------------------------------------- reporting

def stats():
    conn = db_connect()
    total = conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
    print(f"Total CVEs stored: {total}")
    print("\nBy severity:")
    for sev, n in conn.execute(
        "SELECT COALESCE(cvss_severity,'(none)'), COUNT(*) FROM cves GROUP BY 1 ORDER BY 2 DESC"
    ):
        print(f"  {sev:<10} {n}")
    print("\nBy review status:")
    for st, n in conn.execute(
        "SELECT review_status, COUNT(*) FROM cves GROUP BY 1 ORDER BY 2 DESC"
    ):
        print(f"  {st:<10} {n}")
    row = conn.execute("SELECT value FROM sync_state WHERE key='last_sync'").fetchone()
    print(f"\nLast sync: {row[0] if row else 'never'}")
    conn.close()


def list_cves(severity, status, since, limit):
    conn = db_connect()
    q = "SELECT cve_id, cvss_severity, cvss_score, review_status, substr(description,1,90) FROM cves WHERE 1=1"
    args = []
    if severity:
        q += " AND cvss_severity = ?"; args.append(severity.upper())
    if status:
        q += " AND review_status = ?"; args.append(status)
    if since:
        q += " AND last_modified >= ?"; args.append(since)
    q += " ORDER BY cvss_score DESC NULLS LAST, last_modified DESC LIMIT ?"
    args.append(limit)
    for cid, sev, score, st, desc in conn.execute(q, args):
        print(f"{cid:<18} {sev or '-':<9} {score if score is not None else '-':<5} {st:<9} {desc}")
    conn.close()


def mark(cve_id, status, note):
    conn = db_connect()
    with conn:
        cur = conn.execute(
            "UPDATE cves SET review_status=?, review_note=?, reviewed_at=? WHERE cve_id=?",
            (status, note, datetime.now(timezone.utc).isoformat(), cve_id.upper()),
        )
    if cur.rowcount:
        print(f"{cve_id.upper()} -> {status}")
    else:
        print(f"{cve_id} not found in local DB", file=sys.stderr)
        sys.exit(1)
    conn.close()


# ---------------------------------------------------------------- CLI

def main():
    p = argparse.ArgumentParser(description="Local CVE pipeline (NVD -> SQLite)")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init")

    s = sub.add_parser("sync")
    s.add_argument("--days", type=int, default=None,
                   help="pull CVEs modified in the last N days (default: since last sync)")
    s.add_argument("--full", action="store_true",
                   help="pull the entire NVD database (~300k CVEs), then continue incrementally")

    sub.add_parser("stats")

    l = sub.add_parser("list")
    l.add_argument("--severity", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"], type=str.upper)
    l.add_argument("--status", choices=["new", "reviewed", "ignored", "watch"])
    l.add_argument("--since", help="ISO date, e.g. 2026-06-01")
    l.add_argument("--limit", type=int, default=25)

    m = sub.add_parser("mark")
    m.add_argument("cve_id")
    m.add_argument("status", choices=["new", "reviewed", "ignored", "watch"])
    m.add_argument("--note", default=None)

    a = p.parse_args()
    if a.cmd == "init":
        db_init()
    elif a.cmd == "sync":
        sync(a.days, full=a.full)
    elif a.cmd == "stats":
        stats()
    elif a.cmd == "list":
        list_cves(a.severity, a.status, a.since, a.limit)
    elif a.cmd == "mark":
        mark(a.cve_id, a.status, a.note)


if __name__ == "__main__":
    main()
