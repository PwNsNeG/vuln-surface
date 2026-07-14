#!/usr/bin/env python3
"""
vs_dashboard.py — Local web dashboard for the cve.db built by vs_sync.py.

Stdlib only, no dependencies. Serves on http://127.0.0.1:8742

Usage:
  python3 vs_dashboard.py            # uses ./cve.db (or CVE_DB_PATH)
  python3 vs_dashboard.py --port 9000 --db C:/path/to/cve.db

Local tool: binds to 127.0.0.1 only, no authentication. Do not expose it
beyond localhost.
"""

import argparse
import json
import os
import sqlite3
import sys
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

DB_PATH = os.environ.get("CVE_DB_PATH", "cve.db")

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
STATUSES = ["new", "watch", "reviewed", "ignored"]
SORTS = {
    "score": "c.cvss_score DESC NULLS LAST, c.published DESC",
    "epss": "e.score DESC NULLS LAST, c.cvss_score DESC NULLS LAST",
    "published": "c.published DESC",
    "modified": "c.last_modified DESC",
}


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ------------------------------------------------------------------ queries

def build_where(p):
    where, args = ["1=1"], []
    sevs = [s for s in p.get("severity", [""])[0].split(",") if s]
    if sevs:
        if "NONE" in sevs:
            rest = [s for s in sevs if s != "NONE"]
            if rest:
                where.append(f"(c.cvss_severity IS NULL OR c.cvss_severity IN ({','.join('?'*len(rest))}))")
                args += rest
            else:
                where.append("c.cvss_severity IS NULL")
        else:
            where.append(f"c.cvss_severity IN ({','.join('?'*len(sevs))})")
            args += sevs
    sts = [s for s in p.get("status", [""])[0].split(",") if s]
    if sts:
        where.append(f"c.review_status IN ({','.join('?'*len(sts))})")
        args += sts
    q = p.get("q", [""])[0].strip()
    if q:
        if q.upper().startswith("CVE-"):
            where.append("c.cve_id LIKE ?")
            args.append(q.upper() + "%")
        else:
            where.append("(c.description LIKE ? OR c.cve_id LIKE ?)")
            args += [f"%{q}%", f"%{q}%"]
    since = p.get("since", [""])[0].strip()
    if since:
        where.append("c.published >= ?")
        args.append(since)
    min_score = p.get("min_score", [""])[0].strip()
    if min_score:
        where.append("c.cvss_score >= ?")
        args.append(float(min_score))
    if p.get("kev", ["0"])[0] == "1":
        where.append("k.cve_id IS NOT NULL")
    if p.get("mine", ["0"])[0] == "1":
        where.append("EXISTS (SELECT 1 FROM asset_matches m WHERE m.cve_id = c.cve_id)")
    return " AND ".join(where), args


FROM_JOINED = ("cves c LEFT JOIN kev k ON k.cve_id = c.cve_id "
               "LEFT JOIN epss e ON e.cve_id = c.cve_id")


def api_cves(p):
    where, args = build_where(p)
    sort = SORTS.get(p.get("sort", ["score"])[0], SORTS["score"])
    limit = min(int(p.get("limit", ["50"])[0]), 200)
    offset = max(int(p.get("offset", ["0"])[0]), 0)
    conn = db()
    total = conn.execute(
        f"SELECT COUNT(*) c FROM {FROM_JOINED} WHERE {where}", args).fetchone()["c"]
    sev_counts = {r["s"] or "NONE": r["c"] for r in conn.execute(
        f"SELECT c.cvss_severity s, COUNT(*) c FROM {FROM_JOINED} WHERE {where} "
        f"GROUP BY c.cvss_severity", args)}
    rows = conn.execute(
        f"""SELECT c.cve_id, c.published, c.last_modified, c.vuln_status,
                   c.cvss_severity, c.cvss_score, c.review_status,
                   substr(c.description,1,220) AS description,
                   (k.cve_id IS NOT NULL) AS kev, e.score AS epss,
                   EXISTS (SELECT 1 FROM asset_matches m WHERE m.cve_id = c.cve_id) AS mine
            FROM {FROM_JOINED} WHERE {where} ORDER BY {sort} LIMIT ? OFFSET ?""",
        args + [limit, offset]).fetchall()
    conn.close()
    return {"total": total, "sev_counts": sev_counts, "offset": offset,
            "limit": limit, "rows": [dict(r) for r in rows]}


def api_stats():
    conn = db()
    total = conn.execute("SELECT COUNT(*) c FROM cves").fetchone()["c"]
    by_status = {r["review_status"]: r["c"] for r in conn.execute(
        "SELECT review_status, COUNT(*) c FROM cves GROUP BY review_status")}
    row = conn.execute("SELECT value FROM sync_state WHERE key='last_sync'").fetchone()
    recent = conn.execute(
        "SELECT COUNT(*) c FROM cves WHERE published >= date('now','-7 day')").fetchone()["c"]
    conn.close()
    return {"total": total, "by_status": by_status,
            "last_sync": row["value"] if row else None, "published_7d": recent}


def api_cve(cve_id):
    conn = db()
    row = conn.execute("SELECT * FROM cves WHERE cve_id=?", (cve_id.upper(),)).fetchone()
    if not row:
        conn.close()
        return None
    d = dict(row)
    d["cwes"] = json.loads(d["cwes"] or "[]")
    d["reference_urls"] = json.loads(d["reference_urls"] or "[]")
    d["raw"] = json.loads(d["raw"] or "{}")
    k = conn.execute("SELECT date_added, due_date, ransomware FROM kev WHERE cve_id=?",
                     (d["cve_id"],)).fetchone()
    d["kev"] = dict(k) if k else None
    e = conn.execute("SELECT score, percentile FROM epss WHERE cve_id=?",
                     (d["cve_id"],)).fetchone()
    d["epss"] = dict(e) if e else None
    d["assets"] = [dict(r) for r in conn.execute(
        """SELECT a.product, a.version, MIN(m.matched_on) AS matched_on
           FROM asset_matches m JOIN assets a ON a.id = m.asset_id
           WHERE m.cve_id=? GROUP BY a.product, a.version LIMIT 12""", (d["cve_id"],))]
    conn.close()
    return d


def api_mark(body):
    cve_id = body["cve_id"].upper()
    status = body["status"]
    if status not in STATUSES:
        raise ValueError("bad status")
    conn = db()
    with conn:
        cur = conn.execute(
            "UPDATE cves SET review_status=?, review_note=?, reviewed_at=? WHERE cve_id=?",
            (status, body.get("note") or None,
             datetime.now(timezone.utc).isoformat(), cve_id))
    ok = cur.rowcount > 0
    conn.close()
    return {"ok": ok, "cve_id": cve_id, "status": status}


# ------------------------------------------------------------------ HTML UI

PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CVE Console</title>
<style>
:root{
  --bg:#0F141A; --surface:#171E26; --surface2:#1D2631; --line:#26303B;
  --text:#D5DEE7; --muted:#7C8B99; --faint:#4A5866;
  --crit:#FF4D5E; --high:#FF9838; --med:#F2C744; --low:#4DC591; --none:#5A6B7B;
  --cyan:#62B6CB;
  --mono:'Cascadia Code',Consolas,'SF Mono',ui-monospace,monospace;
  --sans:'Segoe UI',system-ui,-apple-system,sans-serif;
}
*{box-sizing:border-box;margin:0;padding:0}
html,body{background:var(--bg);color:var(--text);font-family:var(--sans);font-size:14px}
a{color:var(--cyan)}
button{font:inherit;cursor:pointer;color:inherit;background:none;border:none}
:focus-visible{outline:2px solid var(--cyan);outline-offset:2px}

header{display:flex;align-items:baseline;gap:16px;padding:18px 24px 10px}
header h1{font-family:var(--mono);font-size:17px;font-weight:600;letter-spacing:.04em}
header h1 .dot{color:var(--crit)}
#syncinfo{color:var(--muted);font-size:12px;margin-left:auto;font-family:var(--mono)}

/* signature: proportional severity strip, segments are filter toggles */
#strip{display:flex;height:34px;margin:6px 24px 0;border:1px solid var(--line);border-radius:6px;overflow:hidden}
#strip button{display:flex;align-items:center;justify-content:center;gap:6px;
  font-family:var(--mono);font-size:11.5px;font-weight:600;min-width:0;
  transition:filter .12s,flex-basis .25s ease;white-space:nowrap;overflow:hidden}
#strip button .n{opacity:.85;font-weight:400}
#strip button.off{filter:saturate(.15) brightness(.55)}
#strip button:hover{filter:brightness(1.15)}
#striplegend{margin:4px 24px 0;color:var(--faint);font-size:11px}

#filters{display:flex;flex-wrap:wrap;gap:10px;align-items:center;padding:14px 24px}
#filters input,#filters select{background:var(--surface);border:1px solid var(--line);
  color:var(--text);border-radius:6px;padding:7px 10px;font-family:var(--mono);font-size:12.5px}
#q{width:280px}
.chip{border:1px solid var(--line);border-radius:99px;padding:5px 12px;font-size:12px;
  color:var(--muted);background:var(--surface)}
.chip.on{color:var(--text);border-color:var(--cyan);background:var(--surface2)}
.chip.special.on{border-color:var(--crit);color:var(--crit)}
#minechip.on{border-color:var(--low);color:var(--low)}
.kevbadge{display:inline-block;font-family:var(--mono);font-size:10px;font-weight:700;
  color:#fff;background:var(--crit);border-radius:3px;padding:2px 5px;margin-left:6px;vertical-align:1px}
td.epss{font-family:var(--mono);text-align:right;white-space:nowrap;color:var(--muted)}
td.epss.hot{color:var(--high)}
#count{color:var(--muted);font-size:12px;margin-left:auto;font-family:var(--mono)}

table{width:calc(100% - 48px);margin:0 24px;border-collapse:collapse}
th{color:var(--faint);text-align:left;font-size:11px;text-transform:uppercase;
  letter-spacing:.08em;padding:8px 10px;border-bottom:1px solid var(--line)}
td{padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:top}
tr.row:hover td{background:var(--surface)}
tr.row{cursor:pointer}
td.id{font-family:var(--mono);white-space:nowrap;color:var(--cyan)}
td.score{font-family:var(--mono);text-align:right;white-space:nowrap}
.sev{display:inline-block;min-width:74px;text-align:center;font-family:var(--mono);
  font-size:11px;font-weight:600;padding:3px 8px;border-radius:4px;background:var(--surface2)}
.sev.CRITICAL{color:var(--crit)} .sev.HIGH{color:var(--high)}
.sev.MEDIUM{color:var(--med)}  .sev.LOW{color:var(--low)} .sev.NONE{color:var(--none)}
.st{font-family:var(--mono);font-size:11px;color:var(--muted)}
.st.new::before{content:"● ";color:var(--cyan)}
.st.watch::before{content:"◐ ";color:var(--med)}
.st.reviewed::before{content:"○ ";color:var(--low)}
.st.ignored::before{content:"– ";color:var(--faint)}
td.desc{color:var(--muted);max-width:640px}
td.date{font-family:var(--mono);font-size:12px;color:var(--muted);white-space:nowrap}

#pager{display:flex;gap:10px;align-items:center;justify-content:center;padding:16px;color:var(--muted);font-family:var(--mono);font-size:12px}
#pager button{border:1px solid var(--line);border-radius:6px;padding:6px 14px;background:var(--surface)}
#pager button:disabled{opacity:.35;cursor:default}
#empty{padding:60px;text-align:center;color:var(--muted)}

/* detail drawer */
#drawer{position:fixed;top:0;right:0;bottom:0;width:min(560px,92vw);background:var(--surface);
  border-left:1px solid var(--line);transform:translateX(102%);transition:transform .18s ease;
  overflow-y:auto;padding:22px;z-index:10}
#drawer.open{transform:none}
#drawer h2{font-family:var(--mono);font-size:16px;margin-bottom:4px}
#drawer .meta{color:var(--muted);font-size:12px;font-family:var(--mono);margin-bottom:14px}
#drawer p.desc{line-height:1.55;margin:12px 0;color:var(--text)}
#drawer .kv{display:grid;grid-template-columns:110px 1fr;gap:6px 12px;font-size:12.5px;margin:14px 0}
#drawer .kv dt{color:var(--faint)} #drawer .kv dd{font-family:var(--mono);word-break:break-all}
#drawer h3{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--faint);margin:18px 0 8px}
#drawer ul.refs{list-style:none;font-size:12px}
#drawer ul.refs li{margin:4px 0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
#triage{display:flex;gap:8px;margin:14px 0;flex-wrap:wrap}
#triage button{border:1px solid var(--line);border-radius:6px;padding:7px 14px;background:var(--surface2);font-size:12.5px}
#triage button.active{border-color:var(--cyan);color:var(--cyan)}
#note{width:100%;background:var(--bg);border:1px solid var(--line);border-radius:6px;
  color:var(--text);padding:8px;font:12.5px var(--mono);min-height:56px;resize:vertical}
#savednote{color:var(--low);font-size:12px;margin-left:8px}
#rawtoggle{color:var(--cyan);font-size:12px;margin-top:16px}
pre#raw{display:none;background:var(--bg);border:1px solid var(--line);border-radius:6px;
  padding:10px;font:11px/1.5 var(--mono);overflow-x:auto;margin-top:8px;max-height:420px;overflow-y:auto}
#close{position:absolute;top:14px;right:16px;color:var(--muted);font-size:20px}
#overlay{position:fixed;inset:0;background:rgba(6,10,14,.55);opacity:0;pointer-events:none;transition:opacity .18s;z-index:9}
#overlay.open{opacity:1;pointer-events:auto}
@media (prefers-reduced-motion:reduce){#drawer,#overlay,#strip button{transition:none}}
@media (max-width:760px){
  td.desc,th.desc{display:none}
  #q{width:100%}
  table{width:calc(100% - 16px);margin:0 8px}
}
</style>
</head>
<body>
<header>
  <h1>CVE CONSOLE<span class="dot">_</span></h1>
  <span id="syncinfo"></span>
</header>

<div id="strip" role="group" aria-label="Severity distribution and filter"></div>
<div id="striplegend">severity distribution of current result set — click a segment to toggle it</div>

<div id="filters">
  <input id="q" type="search" placeholder="search description or CVE id…" aria-label="Search">
  <span id="statuschips"></span>
  <button class="chip special" id="kevchip" aria-pressed="false">⚑ KEV</button>
  <button class="chip special" id="minechip" aria-pressed="false">◈ my stack</button>
  <select id="sort" aria-label="Sort">
    <option value="score">sort: score</option>
    <option value="epss">sort: epss</option>
    <option value="published">sort: published</option>
    <option value="modified">sort: modified</option>
  </select>
  <input id="since" type="date" aria-label="Published since" title="published since">
  <input id="minscore" type="number" min="0" max="10" step="0.1" placeholder="min score" style="width:92px" aria-label="Minimum score">
  <span id="count"></span>
</div>

<table>
  <thead><tr>
    <th>CVE</th><th>Severity</th><th style="text-align:right">Score</th>
    <th style="text-align:right">EPSS</th>
    <th>Status</th><th class="desc">Description</th><th>Published</th>
  </tr></thead>
  <tbody id="rows"></tbody>
</table>
<div id="empty" hidden>No CVEs match these filters.</div>
<div id="pager">
  <button id="prev">‹ prev</button><span id="page"></span><button id="next">next ›</button>
</div>

<div id="overlay"></div>
<aside id="drawer" aria-label="CVE details">
  <button id="close" aria-label="Close details">✕</button>
  <div id="detail"></div>
</aside>

<script>
const SEV_COLORS={CRITICAL:'--crit',HIGH:'--high',MEDIUM:'--med',LOW:'--low',NONE:'--none'};
const SEVS=['CRITICAL','HIGH','MEDIUM','LOW','NONE'];
const STATUSES=['new','watch','reviewed','ignored'];
let state={severity:new Set(),status:new Set(['new','watch']),q:'',since:'',min_score:'',sort:'score',offset:0,limit:50,kev:false,mine:false};
let debounce;

const $=s=>document.querySelector(s);
const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));

function params(){
  const p=new URLSearchParams();
  if(state.severity.size)p.set('severity',[...state.severity].join(','));
  if(state.status.size)p.set('status',[...state.status].join(','));
  if(state.q)p.set('q',state.q);
  if(state.since)p.set('since',state.since);
  if(state.min_score)p.set('min_score',state.min_score);
  if(state.kev)p.set('kev','1');
  if(state.mine)p.set('mine','1');
  p.set('sort',state.sort);p.set('offset',state.offset);p.set('limit',state.limit);
  return p;
}

$('#kevchip').onclick=()=>{state.kev=!state.kev;$('#kevchip').classList.toggle('on',state.kev);
  $('#kevchip').setAttribute('aria-pressed',state.kev);state.offset=0;load()};
$('#minechip').onclick=()=>{state.mine=!state.mine;$('#minechip').classList.toggle('on',state.mine);
  $('#minechip').setAttribute('aria-pressed',state.mine);state.offset=0;load()};

async function load(){
  const r=await fetch('/api/cves?'+params());
  const d=await r.json();
  renderStrip(d.sev_counts);
  renderRows(d.rows);
  $('#count').textContent=d.total.toLocaleString()+' results';
  const page=Math.floor(d.offset/d.limit)+1, pages=Math.max(1,Math.ceil(d.total/d.limit));
  $('#page').textContent=page+' / '+pages;
  $('#prev').disabled=d.offset===0;
  $('#next').disabled=d.offset+d.limit>=d.total;
  $('#empty').hidden=d.rows.length>0;
}

function renderStrip(counts){
  const total=SEVS.reduce((a,s)=>a+(counts[s]||0),0)||1;
  $('#strip').innerHTML=SEVS.map(s=>{
    const n=counts[s]||0;
    const share=Math.max(n/total*100, n>0?4:0);
    const off=state.severity.size&&!state.severity.has(s);
    return `<button style="flex:${share} 1 0;background:color-mix(in srgb,var(${SEV_COLORS[s]}) 22%,var(--surface));color:var(${SEV_COLORS[s]});${n===0?'display:none;':''}"
      class="${off?'off':''}" data-sev="${s}" aria-pressed="${!off}">
      ${s}<span class="n">${n.toLocaleString()}</span></button>`;
  }).join('');
  document.querySelectorAll('#strip button').forEach(b=>b.onclick=()=>{
    const s=b.dataset.sev;
    state.severity.has(s)?state.severity.delete(s):state.severity.add(s);
    state.offset=0;load();
  });
}

function renderRows(rows){
  $('#rows').innerHTML=rows.map(r=>`<tr class="row" data-id="${r.cve_id}" tabindex="0">
    <td class="id">${r.cve_id}${r.kev?'<span class="kevbadge">KEV</span>':''}${r.mine?' <span title="matches your installed software" style="color:var(--low)">◈</span>':''}</td>
    <td><span class="sev ${r.cvss_severity||'NONE'}">${r.cvss_severity||'—'}</span></td>
    <td class="score">${r.cvss_score??'—'}</td>
    <td class="epss ${r.epss>0.1?'hot':''}">${r.epss!=null?r.epss.toFixed(3):'—'}</td>
    <td><span class="st ${r.review_status}">${r.review_status}</span></td>
    <td class="desc">${esc(r.description)}</td>
    <td class="date">${(r.published||'').slice(0,10)}</td></tr>`).join('');
  document.querySelectorAll('tr.row').forEach(tr=>{
    tr.onclick=()=>openDetail(tr.dataset.id);
    tr.onkeydown=e=>{if(e.key==='Enter')openDetail(tr.dataset.id)};
  });
}

function renderStatusChips(){
  $('#statuschips').innerHTML=STATUSES.map(s=>
    `<button class="chip ${state.status.has(s)?'on':''}" data-st="${s}" aria-pressed="${state.status.has(s)}">${s}</button>`).join(' ');
  document.querySelectorAll('#statuschips .chip').forEach(c=>c.onclick=()=>{
    const s=c.dataset.st;
    state.status.has(s)?state.status.delete(s):state.status.add(s);
    state.offset=0;renderStatusChips();load();
  });
}

async function openDetail(id){
  const r=await fetch('/api/cve/'+id);
  if(!r.ok)return;
  const d=await r.json();
  $('#detail').innerHTML=`
    <h2>${d.cve_id}</h2>
    <div class="meta">published ${(d.published||'').slice(0,10)} · modified ${(d.last_modified||'').slice(0,10)} · ${esc(d.vuln_status||'')}</div>
    <span class="sev ${d.cvss_severity||'NONE'}">${d.cvss_severity||'no score'}</span>
    <span class="score" style="font-family:var(--mono);margin-left:8px">${d.cvss_score??''}</span>
    ${d.kev?`<span class="kevbadge">KEV</span> <span style="font-size:12px;color:var(--crit);font-family:var(--mono)">added ${esc(d.kev.date_added||'')} · due ${esc(d.kev.due_date||'')}${d.kev.ransomware==='Known'?' · ransomware':''}</span>`:''}
    ${d.epss?`<div style="margin-top:6px;font-family:var(--mono);font-size:12px;color:${d.epss.score>0.1?'var(--high)':'var(--muted)'}">EPSS ${d.epss.score.toFixed(4)} (p${Math.round(d.epss.percentile*100)})</div>`:''}
    ${d.assets&&d.assets.length?`<div style="margin-top:6px;font-size:12px;color:var(--low)">◈ on your stack: ${d.assets.map(a=>esc(a.product+' '+(a.version||''))).join(' · ')}</div>`:''}
    <p class="desc">${esc(d.description)}</p>
    <dl class="kv">
      <dt>Vector</dt><dd>${esc(d.cvss_vector||'—')}</dd>
      <dt>CWE</dt><dd>${d.cwes.map(esc).join(', ')||'—'}</dd>
    </dl>
    <h3>Triage</h3>
    <div id="triage">${STATUSES.map(s=>
      `<button data-s="${s}" class="${d.review_status===s?'active':''}">${s}</button>`).join('')}
      <span id="savednote"></span></div>
    <textarea id="note" placeholder="triage note…">${esc(d.review_note||'')}</textarea>
    <h3>References (${d.reference_urls.length})</h3>
    <ul class="refs">${d.reference_urls.slice(0,25).map(u=>
      `<li><a href="${esc(u)}" target="_blank" rel="noopener">${esc(u)}</a></li>`).join('')}</ul>
    <button id="rawtoggle">show raw NVD json</button>
    <pre id="raw">${esc(JSON.stringify(d.raw,null,2))}</pre>`;
  document.querySelectorAll('#triage button[data-s]').forEach(b=>b.onclick=async()=>{
    await fetch('/api/mark',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({cve_id:d.cve_id,status:b.dataset.s,note:$('#note').value})});
    document.querySelectorAll('#triage button[data-s]').forEach(x=>x.classList.toggle('active',x===b));
    $('#savednote').textContent='saved';setTimeout(()=>$('#savednote').textContent='',1500);
    load();
  });
  $('#rawtoggle').onclick=()=>{
    const p=$('#raw');const show=p.style.display!=='block';
    p.style.display=show?'block':'none';
    $('#rawtoggle').textContent=show?'hide raw NVD json':'show raw NVD json';
  };
  $('#drawer').classList.add('open');$('#overlay').classList.add('open');
}
function closeDrawer(){$('#drawer').classList.remove('open');$('#overlay').classList.remove('open')}
$('#close').onclick=closeDrawer;$('#overlay').onclick=closeDrawer;
document.addEventListener('keydown',e=>{if(e.key==='Escape')closeDrawer()});

$('#q').oninput=e=>{clearTimeout(debounce);debounce=setTimeout(()=>{state.q=e.target.value;state.offset=0;load()},300)};
$('#sort').onchange=e=>{state.sort=e.target.value;state.offset=0;load()};
$('#since').onchange=e=>{state.since=e.target.value;state.offset=0;load()};
$('#minscore').onchange=e=>{state.min_score=e.target.value;state.offset=0;load()};
$('#prev').onclick=()=>{state.offset=Math.max(0,state.offset-state.limit);load()};
$('#next').onclick=()=>{state.offset+=state.limit;load()};

(async()=>{
  renderStatusChips();
  const s=await(await fetch('/api/stats')).json();
  $('#syncinfo').textContent=s.total.toLocaleString()+' CVEs · '+
    (s.published_7d||0).toLocaleString()+' published <7d · last sync '+
    (s.last_sync?s.last_sync.slice(0,16).replace('T',' ')+' UTC':'never');
  load();
})();
</script>
</body>
</html>"""


# ------------------------------------------------------------------ server

class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        u = urlparse(self.path)
        p = parse_qs(u.query)
        try:
            if u.path == "/":
                self._send(200, PAGE.encode(), "text/html")
            elif u.path == "/api/stats":
                self._send(200, api_stats())
            elif u.path == "/api/cves":
                self._send(200, api_cves(p))
            elif u.path.startswith("/api/cve/"):
                d = api_cve(u.path.rsplit("/", 1)[1])
                self._send(200, d) if d else self._send(404, {"error": "not found"})
            else:
                self._send(404, {"error": "not found"})
        except Exception as e:
            self._send(500, {"error": str(e)})

    def do_POST(self):
        if urlparse(self.path).path != "/api/mark":
            return self._send(404, {"error": "not found"})
        try:
            n = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(n).decode())
            self._send(200, api_mark(body))
        except Exception as e:
            self._send(400, {"error": str(e)})

    def log_message(self, fmt, *args):
        pass  # keep the console quiet


def main():
    global DB_PATH
    ap = argparse.ArgumentParser(description="Local CVE dashboard")
    ap.add_argument("--port", type=int, default=8742)
    ap.add_argument("--db", default=DB_PATH)
    a = ap.parse_args()
    DB_PATH = a.db
    if not os.path.exists(DB_PATH):
        sys.exit(f"Database not found: {os.path.abspath(DB_PATH)} "
                 f"(run vs_sync.py sync first, or pass --db)")
    conn = db()
    with conn:
        conn.execute("CREATE INDEX IF NOT EXISTS idx_cves_published ON cves (published)")
        conn.execute("CREATE TABLE IF NOT EXISTS kev (cve_id TEXT PRIMARY KEY, date_added TEXT,"
                     " due_date TEXT, ransomware TEXT, vendor TEXT, product TEXT)")
        conn.execute("CREATE TABLE IF NOT EXISTS epss (cve_id TEXT PRIMARY KEY, score REAL,"
                     " percentile REAL)")
        conn.execute("CREATE TABLE IF NOT EXISTS asset_matches (cve_id TEXT, asset_id INTEGER,"
                     " matched_on TEXT, matched_at TEXT, PRIMARY KEY (cve_id, asset_id))")
        conn.execute("CREATE TABLE IF NOT EXISTS assets (id INTEGER PRIMARY KEY, hostname TEXT,"
                     " vendor TEXT, product TEXT, version TEXT, source TEXT, norm_tokens TEXT,"
                     " scanned_at TEXT, UNIQUE (hostname, product, version, source))")
    conn.close()
    srv = ThreadingHTTPServer(("127.0.0.1", a.port), Handler)
    print(f"CVE console -> http://127.0.0.1:{a.port}   (db: {os.path.abspath(DB_PATH)})")
    print("Ctrl+C to stop.")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
