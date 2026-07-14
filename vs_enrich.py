#!/usr/bin/env python3
"""
vs_enrich.py : Enrich the local cve.db with exploitation intel and match it
against software actually installed on this machine.

Stdlib only, no dependencies. Works alongside vs_sync.py / vs_dashboard.py.

Subcommands:
  python3 vs_enrich.py kev          # download CISA Known Exploited Vulns catalog
  python3 vs_enrich.py epss         # download FIRST EPSS scores (daily CSV)
  python3 vs_enrich.py scan         # discover installed software on THIS machine
  python3 vs_enrich.py index        # build CPE index from stored raw NVD JSON
  python3 vs_enrich.py match        # correlate assets <-> CVEs via CPE index
  python3 vs_enrich.py all          # kev + epss + scan + index + match
  python3 vs_enrich.py assets       # show discovered assets
  python3 vs_enrich.py hits         # show matched CVEs for your stack

Typical cron/scheduled-task order:  pipeline sync  ->  enrich all

Environment:  CVE_DB_PATH (default ./cve.db)
"""

import argparse
import csv
import gzip
import io
import json
import os
import platform
import re
import socket
import sqlite3
import subprocess
import sys
import urllib.request
from datetime import datetime, timezone

DB_PATH = os.environ.get("CVE_DB_PATH", "cve.db")
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"

SCHEMA = """
CREATE TABLE IF NOT EXISTS kev (
    cve_id     TEXT PRIMARY KEY,
    date_added TEXT,
    due_date   TEXT,
    ransomware TEXT,
    vendor     TEXT,
    product    TEXT
);
CREATE TABLE IF NOT EXISTS epss (
    cve_id     TEXT PRIMARY KEY,
    score      REAL,
    percentile REAL
);
CREATE TABLE IF NOT EXISTS assets (
    id         INTEGER PRIMARY KEY,
    hostname   TEXT,
    vendor     TEXT,
    product    TEXT,
    version    TEXT,
    source     TEXT,          -- winreg | dpkg | rpm | manual
    norm_tokens TEXT,         -- JSON array of normalized match tokens
    scanned_at TEXT,
    UNIQUE (hostname, product, version, source)
);
CREATE TABLE IF NOT EXISTS cpe_index (
    cve_id  TEXT,
    vendor  TEXT,
    product TEXT,
    PRIMARY KEY (cve_id, vendor, product)
);
CREATE INDEX IF NOT EXISTS idx_cpe_product ON cpe_index (product);
CREATE TABLE IF NOT EXISTS asset_matches (
    cve_id    TEXT,
    asset_id  INTEGER,
    matched_on TEXT,          -- which token matched
    matched_at TEXT,
    PRIMARY KEY (cve_id, asset_id)
);
CREATE TABLE IF NOT EXISTS asset_exclusions (
    pattern TEXT PRIMARY KEY,        -- SQL LIKE pattern against product name
    added_at TEXT
);
CREATE TABLE IF NOT EXISTS enrich_state (key TEXT PRIMARY KEY, value TEXT);
"""

now_iso = lambda: datetime.now(timezone.utc).isoformat()


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(SCHEMA)
    return conn


def http_get(url, timeout=120):
    req = urllib.request.Request(url, headers={"User-Agent": "cve-pipeline-enrich/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


# ------------------------------------------------------------------- KEV

def cmd_kev():
    print("Downloading CISA KEV catalog...")
    data = json.loads(http_get(KEV_URL).decode())
    vulns = data.get("vulnerabilities", [])
    conn = db()
    with conn:
        conn.execute("DELETE FROM kev")
        conn.executemany(
            "INSERT OR REPLACE INTO kev VALUES (?,?,?,?,?,?)",
            [(v["cveID"], v.get("dateAdded"), v.get("dueDate"),
              v.get("knownRansomwareCampaignUse"), v.get("vendorProject"),
              v.get("product")) for v in vulns])
        conn.execute("INSERT OR REPLACE INTO enrich_state VALUES ('kev_updated',?)", (now_iso(),))
    print(f"KEV: {len(vulns)} known-exploited CVEs stored.")


# ------------------------------------------------------------------- EPSS

def cmd_epss():
    print("Downloading EPSS scores (~10 MB)...")
    raw = gzip.decompress(http_get(EPSS_URL))
    rows = []
    for line in io.StringIO(raw.decode()):
        if line.startswith("#"):
            continue
        rows.append(line)
    reader = csv.DictReader(rows)
    batch = [(r["cve"], float(r["epss"]), float(r["percentile"])) for r in reader]
    conn = db()
    with conn:
        conn.execute("DELETE FROM epss")
        conn.executemany("INSERT OR REPLACE INTO epss VALUES (?,?,?)", batch)
        conn.execute("INSERT OR REPLACE INTO enrich_state VALUES ('epss_updated',?)", (now_iso(),))
    print(f"EPSS: scores stored for {len(batch)} CVEs.")


# ------------------------------------------------------------------- scan

# generic tokens that would match half the CVE database — never match on these
STOPWORDS = {
    "microsoft", "windows", "update", "runtime", "redistributable", "driver",
    "drivers", "software", "tools", "client", "server", "service", "pack",
    "x64", "x86", "amd64", "arm64", "en", "us", "fr", "version", "edition",
    "setup", "installer", "application", "app", "the", "for", "and", "of",
    "component", "components", "package", "framework", "library", "core",
    "intel", "nvidia", "amd", "corporation", "inc", "ltd", "llc", "gmbh",
    "desktop", "online", "free", "pro", "professional", "standard", "plus",
    "launcher", "helper", "agent", "manager", "console", "viewer", "web",
}

# single tokens that are individually too ambiguous to match on — they only
# survive as part of a compound token (e.g. android_studio, foxit_pdf_reader)
BAD_TOKENS = {
    "linux", "reader", "android", "player", "viewer", "writer", "editor",
    "browser", "media", "studio", "code", "shell", "mail", "chat", "meeting",
    "security", "network", "audio", "video", "graphics", "bluetooth",
}

VERSION_RE = re.compile(r"\b\d+(\.\d+)*\b")
PAREN_RE = re.compile(r"\([^)]*\)")


def normalize_tokens(name: str, publisher: str = "") -> list:
    """Turn 'Mozilla Firefox (x64 en-US) 127.0' into candidate CPE-style tokens."""
    s = PAREN_RE.sub(" ", name)
    s = VERSION_RE.sub(" ", s)
    s = re.sub(r"[^a-zA-Z0-9]+", " ", s).lower().strip()
    words = [w for w in s.split() if len(w) > 2 and w not in STOPWORDS]
    tokens = set()
    if words:
        tokens.add("_".join(words))               # e.g. mozilla_firefox
        if len(words) > 1:
            tokens.add("_".join(words[1:]))       # firefox
            tokens.add(words[-1])                 # last word often = product
        tokens.add(words[0])
    pub = re.sub(r"[^a-zA-Z0-9]+", " ", publisher or "").lower().split()
    pub = [w for w in pub if len(w) > 2 and w not in STOPWORDS]
    # drop tokens that are still too generic to be safe
    return sorted(t for t in tokens
                  if t not in BAD_TOKENS and (len(t) > 3 or t in {"git", "vlc", "php"}))


def scan_windows():
    import winreg
    roots = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]
    seen = {}
    for hive, path in roots:
        try:
            key = winreg.OpenKey(hive, path)
        except OSError:
            continue
        for i in range(winreg.QueryInfoKey(key)[0]):
            try:
                sub = winreg.OpenKey(key, winreg.EnumKey(key, i))
                def val(n):
                    try:
                        return str(winreg.QueryValueEx(sub, n)[0]).strip()
                    except OSError:
                        return ""
                name, ver, pub = val("DisplayName"), val("DisplayVersion"), val("Publisher")
                if name and not val("SystemComponent") == "1":
                    seen[(name, ver)] = (pub, name, ver, "winreg")
            except OSError:
                continue
    return list(seen.values())


def scan_linux():
    out = []
    try:
        r = subprocess.run(["dpkg-query", "-W", "-f", "${Package}\t${Version}\t${Maintainer}\n"],
                           capture_output=True, text=True, timeout=60)
        for line in r.stdout.splitlines():
            p = line.split("\t")
            if len(p) >= 2:
                out.append((p[2] if len(p) > 2 else "", p[0], p[1], "dpkg"))
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    if not out:
        try:
            r = subprocess.run(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}\t%{VENDOR}\n"],
                               capture_output=True, text=True, timeout=60)
            for line in r.stdout.splitlines():
                p = line.split("\t")
                if len(p) >= 2:
                    out.append((p[2] if len(p) > 2 else "", p[0], p[1], "rpm"))
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
    return out


def cmd_scan():
    host = socket.gethostname()
    system = platform.system()
    print(f"Scanning installed software on {host} ({system})...")
    entries = scan_windows() if system == "Windows" else scan_linux()
    if not entries:
        sys.exit("No packages discovered (unsupported platform?). "
                 "You can INSERT INTO assets manually.")
    conn = db()
    excl = [r[0] for r in conn.execute("SELECT pattern FROM asset_exclusions")]
    ts = now_iso()
    skipped = 0
    with conn:
        conn.execute("DELETE FROM assets WHERE hostname=? AND source!='manual'", (host,))
        for pub, name, ver, source in entries:
            if any(_like(name, pat) for pat in excl):
                skipped += 1
                continue
            toks = normalize_tokens(name, pub)
            if not toks:
                continue
            conn.execute(
                "INSERT OR IGNORE INTO assets (hostname,vendor,product,version,source,norm_tokens,scanned_at) "
                "VALUES (?,?,?,?,?,?,?)",
                (host, pub, name, ver, source, json.dumps(toks), ts))
    n = conn.execute("SELECT COUNT(*) FROM assets WHERE hostname=?", (host,)).fetchone()[0]
    print(f"Assets: {n} packages recorded for {host}"
          + (f" ({skipped} excluded by your rules)." if skipped else "."))
    print("Reminder: run `match` to refresh correlations.")


def _like(text: str, pattern: str) -> bool:
    """Case-insensitive SQL-LIKE semantics (% and _) in Python."""
    rx = "".join(".*" if ch == "%" else "." if ch == "_" else re.escape(ch)
                 for ch in pattern.lower())
    return re.fullmatch(rx, text.lower()) is not None


# ------------------------------------------------------------------- index

CPE_RE = re.compile(r"cpe:2\.3:[aho]:([^:]+):([^:]+):")


def cmd_index():
    """Extract vendor/product pairs from stored raw NVD JSON (configurations
    + CPE strings anywhere in the record). Incremental: only unindexed CVEs."""
    conn = db()
    total = conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
    done = 0
    cur = conn.execute(
        "SELECT cve_id, raw FROM cves WHERE cve_id NOT IN (SELECT DISTINCT cve_id FROM cpe_index)")
    batch = []
    for cve_id, raw in cur:
        pairs = set(CPE_RE.findall(raw or ""))
        if not pairs:
            pairs = {("__none__", "__none__")}     # marker: indexed, no CPE
        batch += [(cve_id, v, p) for v, p in pairs]
        done += 1
        if len(batch) >= 5000:
            with conn:
                conn.executemany("INSERT OR IGNORE INTO cpe_index VALUES (?,?,?)", batch)
            batch = []
            print(f"  indexed {done}...", end="\r")
    if batch:
        with conn:
            conn.executemany("INSERT OR IGNORE INTO cpe_index VALUES (?,?,?)", batch)
    n = conn.execute("SELECT COUNT(DISTINCT cve_id) FROM cpe_index").fetchone()[0]
    print(f"\nCPE index covers {n}/{total} CVEs.")


# ------------------------------------------------------------------- match

def cmd_match():
    conn = db()
    assets = conn.execute("SELECT id, product, norm_tokens FROM assets").fetchall()
    if not assets:
        sys.exit("No assets. Run `scan` first.")
    ts = now_iso()
    total_new = 0
    with conn:
        conn.execute("DELETE FROM asset_matches")
        for aid, product, toks_json in assets:
            for tok in json.loads(toks_json):
                rows = conn.execute(
                    "SELECT DISTINCT cve_id FROM cpe_index WHERE product=?", (tok,)).fetchall()
                for (cve_id,) in rows:
                    cur = conn.execute(
                        "INSERT OR IGNORE INTO asset_matches VALUES (?,?,?,?)",
                        (cve_id, aid, tok, ts))
                    total_new += cur.rowcount
        conn.execute("INSERT OR REPLACE INTO enrich_state VALUES ('match_updated',?)", (ts,))
    n = conn.execute("SELECT COUNT(DISTINCT cve_id) FROM asset_matches").fetchone()[0]
    print(f"Matched {n} distinct CVEs against your installed software "
          f"({total_new} asset-CVE pairs).")
    print("Note: matching is product-level (CPE product name). Version-range "
          "checking is up to the reviewer — treat hits as candidates, not confirmations.")


# ------------------------------------------------------------------- views

def cmd_assets():
    conn = db()
    print(f"{'ID':<5} {'PRODUCT':<50} {'VERSION':<20} {'SRC':<8} HOST")
    for i, h, p, v, s in conn.execute(
            "SELECT id, hostname, product, version, source FROM assets ORDER BY product LIMIT 500"):
        print(f"{i:<5} {p:<50.50} {v or '':<20.20} {s:<8} {h}")


def cmd_exclude(pattern):
    conn = db()
    with conn:
        conn.execute("INSERT OR IGNORE INTO asset_exclusions VALUES (?,?)", (pattern, now_iso()))
        cur = conn.execute(
            "DELETE FROM assets WHERE product LIKE ? AND source!='manual'", (pattern,))
        conn.execute("DELETE FROM asset_matches WHERE asset_id NOT IN (SELECT id FROM assets)")
    print(f"Excluded pattern {pattern!r}: {cur.rowcount} asset(s) removed now; "
          f"future scans will skip it. Run `match` to refresh correlations.")


def cmd_include(pattern):
    conn = db()
    with conn:
        cur = conn.execute("DELETE FROM asset_exclusions WHERE pattern=?", (pattern,))
    print("Exclusion removed. Re-run `scan` to pick matching software up again."
          if cur.rowcount else f"No exclusion {pattern!r} found.")


def cmd_exclusions():
    conn = db()
    rows = conn.execute("SELECT pattern, added_at FROM asset_exclusions ORDER BY pattern").fetchall()
    if not rows:
        print('No exclusions. Add one:  vs_enrich.py exclude "Update for Microsoft Office%"')
    for pat, ts in rows:
        print(f"{pat:<60} added {ts[:10]}")


def cmd_hosts():
    conn = db()
    this = socket.gethostname()
    print(f"{'HOST':<24} {'ASSETS':<8} {'LAST SCAN':<12} NOTE")
    for h, n, ts in conn.execute(
            "SELECT hostname, COUNT(*), MAX(scanned_at) FROM assets GROUP BY hostname ORDER BY 2 DESC"):
        print(f"{h:<24} {n:<8} {(ts or '')[:10]:<12} {'<- this machine' if h == this else ''}")


def cmd_forget_host(hostname):
    conn = db()
    n = conn.execute("SELECT COUNT(*) FROM assets WHERE hostname=?", (hostname,)).fetchone()[0]
    if not n:
        sys.exit(f"No assets recorded for host {hostname!r}. See `hosts` for known hosts.")
    with conn:
        conn.execute("DELETE FROM assets WHERE hostname=?", (hostname,))
        conn.execute("DELETE FROM asset_matches WHERE asset_id NOT IN (SELECT id FROM assets)")
    print(f"Removed {n} asset(s) for host {hostname!r} (including manual ones) "
          f"and pruned their matches. Run `match` to refresh correlations.")


def cmd_add(product, vendor, version):
    conn = db()
    host = socket.gethostname()
    toks = normalize_tokens(product, vendor or "")
    if not toks:
        sys.exit(f"Could not derive usable match tokens from {product!r}.")
    with conn:
        conn.execute(
            "INSERT OR IGNORE INTO assets (hostname,vendor,product,version,source,norm_tokens,scanned_at) "
            "VALUES (?,?,?,?,'manual',?,?)",
            (host, vendor or "", product, version or "", json.dumps(toks), now_iso()))
    print(f"Manual asset added: {product} (tokens: {', '.join(toks)}). "
          f"Manual assets survive re-scans. Run `match` to refresh.")


def cmd_hits():
    conn = db()
    q = """SELECT c.cve_id, c.cvss_severity, c.cvss_score,
                  CASE WHEN k.cve_id IS NULL THEN '' ELSE 'KEV' END AS kev,
                  COALESCE(e.score,0) AS epss,
                  COUNT(DISTINCT a.id) AS n_assets,
                  MIN(a.product) AS sample_asset,
                  GROUP_CONCAT(DISTINCT m.matched_on) AS tokens
           FROM asset_matches m
           JOIN cves c   ON c.cve_id = m.cve_id
           JOIN assets a ON a.id = m.asset_id
           LEFT JOIN kev k  ON k.cve_id = c.cve_id
           LEFT JOIN epss e ON e.cve_id = c.cve_id
           WHERE c.review_status IN ('new','watch')
           GROUP BY c.cve_id
           ORDER BY (k.cve_id IS NOT NULL) DESC, e.score DESC NULLS LAST,
                    c.cvss_score DESC NULLS LAST
           LIMIT 100"""
    print(f"{'CVE':<18} {'SEV':<9} {'CVSS':<5} {'KEV':<4} {'EPSS':<7} {'ASSETS':<42} MATCHED ON")
    for r in conn.execute(q):
        asset = r[6][:30] + (f"  (+{r[5]-1} more)" if r[5] > 1 else "")
        print(f"{r[0]:<18} {r[1] or '-':<9} {r[2] or '-':<5} {r[3]:<4} "
              f"{r[4]:<7.4f} {asset:<42} {r[7]}")


def main():
    ap = argparse.ArgumentParser(description="CVE enrichment + asset correlation")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for c in ("kev", "epss", "scan", "index", "match", "all", "assets",
              "hits", "exclusions", "hosts"):
        sub.add_parser(c)
    f = sub.add_parser("forget-host", help="remove all assets recorded for a hostname")
    f.add_argument("hostname")
    e = sub.add_parser("exclude",
                       help='exclude assets by SQL LIKE pattern, e.g. "Update for Microsoft%%"')
    e.add_argument("pattern")
    i = sub.add_parser("include", help="remove a previously added exclusion pattern")
    i.add_argument("pattern")
    m = sub.add_parser("add", help="add a manual asset that survives re-scans")
    m.add_argument("product")
    m.add_argument("--vendor", default="")
    m.add_argument("--version", default="")
    a = ap.parse_args()
    if a.cmd == "all":
        cmd_kev(); cmd_epss(); cmd_scan(); cmd_index(); cmd_match()
    elif a.cmd == "exclude":
        cmd_exclude(a.pattern)
    elif a.cmd == "include":
        cmd_include(a.pattern)
    elif a.cmd == "forget-host":
        cmd_forget_host(a.hostname)
    elif a.cmd == "add":
        cmd_add(a.product, a.vendor, a.version)
    else:
        {"kev": cmd_kev, "epss": cmd_epss, "scan": cmd_scan, "index": cmd_index,
         "match": cmd_match, "assets": cmd_assets, "hits": cmd_hits,
         "exclusions": cmd_exclusions, "hosts": cmd_hosts}[a.cmd]()


if __name__ == "__main__":
    main()
