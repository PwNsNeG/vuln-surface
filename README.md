# vuln-surface

Map a host's **vulnerability surface**: mirror the NVD locally, enrich it with
real-world exploitation intel (CISA KEV + FIRST EPSS), discover what software is
actually installed, and correlate the two into an exploitation-ranked triage list.

Answers the only question that matters after a scan: *of the 360,000 known CVEs,
which ones are exploitable, known-exploited, and present on this machine — right now?*

Zero dependencies. Pure Python standard library. Three small scripts, one SQLite file.

---

## Why

A local NVD mirror is worth exactly what NVD is worth: free. The value is in the
enrichment. `vuln-surface` turns a raw feed into a decision:

- **CISA KEV** flags CVEs that are *known to be exploited in the wild* — a far
  stronger signal than CVSS alone.
- **EPSS** (FIRST) scores the *probability of exploitation in the next 30 days*,
  so a 9.8 nobody exploits ranks below a 7.5 that everyone does.
- **Asset correlation** filters 360k CVEs down to the ~dozens that touch software
  you actually run, discovered from the system itself.

Triage order becomes: *KEV first, then EPSS, then CVSS* — the order that reflects
risk, not paperwork.

## Design

- **Local-first.** One SQLite file. The dashboard binds to `127.0.0.1` only.
- **No dependencies.** Standard library only — no pip install, runs on a clean
  Python 3.9+.
- **Idempotent & resumable.** Syncs checkpoint and resume; triage decisions
  survive re-syncs.
- **Composable.** Three scripts that share a database, not a monolith. Each runs
  and reads standalone.

## Components

| Script | Role |
|--------|------|
| `vs_sync.py` | Ingest CVEs from the NVD API 2.0 into local SQLite (incremental or full corpus) |
| `vs_enrich.py` | Download KEV + EPSS, scan installed software, correlate assets ↔ CVEs |
| `vs_dashboard.py` | Local web UI: filter, sort by EPSS, flag KEV / your-stack, triage |

## Quick start

```bash
# 1. Pull the corpus (get a free NVD API key first — much faster & more stable)
export NVD_API_KEY=...            # optional but recommended
python3 vs_sync.py sync --full    # one-time full pull; resumable if interrupted

# 2. Enrich + discover + correlate
python3 vs_enrich.py all          # kev + epss + scan + index + match

# 3a. Triage in the terminal
python3 vs_enrich.py hits         # exploitation-ranked CVEs on your stack

# 3b. …or in the browser
python3 vs_dashboard.py           # http://127.0.0.1:8742
```

Thereafter, a nightly `vs_sync.py sync && vs_enrich.py all` keeps it current.

## Asset discovery

`vs_enrich.py scan` inventories installed software from the system itself —
the Windows registry uninstall hives on Windows, `dpkg`/`rpm` on Linux — and
normalizes each product name into CPE-style match tokens, with a stopword and
blacklist pass so generic terms (`update`, `runtime`, `linux`, `reader`) don't
produce spurious matches.

Correlation is **product-level**: a hit means "this product has this CVE in some
version." Installed versions are shown so you can confirm; treat hits as
candidates, not confirmations. (CPE version-range checking is on the roadmap.)

Housekeeping for the inventory:

```bash
python3 vs_enrich.py assets                                  # list, with IDs
python3 vs_enrich.py exclude "Update for Microsoft Office%"  # drop noise, permanently
python3 vs_enrich.py add "Microsoft Office 2013" --version 15.0   # record a real asset
python3 vs_enrich.py hosts                                   # multi-machine inventory
python3 vs_enrich.py forget-host OLD-DESKTOP                 # evict a stale machine
```

## Triage workflow

Every CVE carries a review status (`new` / `watch` / `reviewed` / `ignored`) plus
a note. Decisions persist across syncs — NVD re-touching a CVE never resets your
triage.

```bash
python3 vs_sync.py mark CVE-2026-XXXX reviewed --note "auto-updated past fix"
python3 vs_sync.py list --severity CRITICAL --status new
```

## Dashboard

`vs_dashboard.py` serves a local, single-file web UI: a proportional severity
strip that doubles as a filter, KEV badges, an EPSS column, a "my stack" toggle,
free-text search, and a detail drawer with the CVSS vector, CWEs, references, raw
NVD JSON, and one-click triage that writes straight back to the shared database.

Localhost-only, no auth — a personal tool, not a service. Don't expose it beyond
`127.0.0.1`.

## Data sources

- [NVD API 2.0](https://nvd.nist.gov/developers/vulnerabilities) — CVE records, CVSS, CPE
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) — known-exploited catalog
- [FIRST EPSS](https://www.first.org/epss/) — exploitation-probability scores


## Notes

- Full corpus is ~360k CVEs; expect a multi-GB SQLite file (raw NVD JSON is kept
  per record so extraction logic can evolve without re-downloading).
- Not affiliated with NIST, CISA, or FIRST. Respect their rate limits and terms.

## License

MIT
