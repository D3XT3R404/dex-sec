"""Self contained HTML report.

The report is one file with inline CSS and JavaScript: it can be e-mailed,
uploaded as a CI artifact or opened in a browser without any server.  The
findings table can be sorted and filtered, and every entry shows the evidence
and the safe PoC.
"""

from __future__ import annotations

import html
import json
import os
from datetime import datetime, timezone

from ..models import AuditReport, CorrelatedFinding, VerificationStatus

CSS = """
:root{--bg:#0d1117;--panel:#161b22;--border:#30363d;--text:#e6edf3;--muted:#8b949e;
--crit:#ff7b72;--high:#ffa657;--med:#d29922;--low:#58a6ff;--ok:#3fb950;}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.6 -apple-system,Segoe UI,Roboto,sans-serif}
header{padding:28px 32px;border-bottom:1px solid var(--border);background:var(--panel)}
h1{margin:0 0 6px;font-size:22px;letter-spacing:.5px}
.sub{color:var(--muted);font-size:13px}
.cards{display:flex;flex-wrap:wrap;gap:12px;padding:20px 32px}
.card{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:14px 18px;min-width:150px}
.card .num{font-size:26px;font-weight:600}
.card .lbl{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.6px}
main{padding:0 32px 48px}
.toolbar{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin:8px 0 16px}
input,select{background:#0d1117;border:1px solid var(--border);color:var(--text);border-radius:8px;padding:8px 12px;font-size:13px}
table{width:100%;border-collapse:collapse;background:var(--panel);border-radius:10px;overflow:hidden}
th{text-align:left;padding:11px 14px;border-bottom:1px solid var(--border);color:var(--muted);
font-size:12px;text-transform:uppercase;letter-spacing:.5px;cursor:pointer;user-select:none;white-space:nowrap}
td{padding:12px 14px;border-bottom:1px solid #21262d;vertical-align:top}
tr:hover td{background:#1c2128}
.sev{font-weight:600;padding:2px 9px;border-radius:999px;font-size:12px}
.CRITICAL{color:var(--crit)}.HIGH{color:var(--high)}.MEDIUM{color:var(--med)}.LOW{color:var(--low)}
.st{font-size:12px;color:var(--muted)}
.st.confirmed{color:var(--crit);font-weight:600}
details{margin-top:8px}
summary{cursor:pointer;color:var(--muted);font-size:12px}
pre{background:#0d1117;border:1px solid var(--border);border-radius:8px;padding:12px;overflow:auto;
font-size:12px;white-space:pre-wrap;word-break:break-word}
code{background:#0d1117;border:1px solid var(--border);border-radius:5px;padding:1px 5px;font-size:12px}
.chain{background:var(--panel);border:1px solid var(--border);border-left:3px solid var(--crit);
border-radius:8px;padding:14px 18px;margin-bottom:12px}
.chain h3{margin:0 0 6px;font-size:15px}
.chain ol{margin:8px 0 0;padding-left:20px}
.badge{display:inline-block;background:#21262d;border:1px solid var(--border);border-radius:999px;
padding:2px 10px;font-size:11px;color:var(--muted);margin-right:6px}
.empty{padding:40px;text-align:center;color:var(--muted)}
footer{padding:20px 32px;color:var(--muted);font-size:12px;border-top:1px solid var(--border)}
"""

JS = """
const rows=[...document.querySelectorAll('tbody tr')];
const q=document.getElementById('q'), sev=document.getElementById('sev'), st=document.getElementById('st');
function apply(){const s=(q.value||'').toLowerCase();
 rows.forEach(r=>{const ok=(!s||r.dataset.text.includes(s))&&(sev.value==='ALL'||r.dataset.sev===sev.value)&&(st.value==='ALL'||r.dataset.status===st.value);
 r.style.display=ok?'':'none';});}
[q,sev,st].forEach(e=>e&&e.addEventListener('input',apply));
document.querySelectorAll('th[data-sort]').forEach(th=>th.addEventListener('click',()=>{
 const idx=th.dataset.sort, dir=th.dataset.dir==='asc'?-1:1;
 document.querySelectorAll('th[data-sort]').forEach(o=>o.dataset.dir='');
 th.dataset.dir=dir>0?'asc':'desc';
 const body=th.closest('table').tBodies[0];
 [...body.rows].sort((a,b)=>a.cells[idx].textContent.localeCompare(b.cells[idx].textContent)*dir)
  .forEach(r=>body.appendChild(r));}));
"""


def _esc(text: object) -> str:
    return html.escape(str(text))


def _finding_row(item: CorrelatedFinding) -> str:
    verification = item.verification
    evidence = verification.evidence if verification else ""
    poc = verification.safe_poc_curl if verification else ""
    detail = ""
    if evidence or poc:
        detail = ["<details><summary>bukti &amp; PoC</summary>"]
        if evidence:
            detail.append(f"<p>{_esc(evidence)}</p>")
        if poc:
            detail.append(f"<pre>{_esc(poc)}</pre>")
        detail.append("</details>")
    text = f"{item.finding.vuln_class.value} {item.title} {item.finding.file}".lower()
    severity = _esc(item.final_severity.value)
    status = _esc(item.status.value)
    status_class = "confirmed" if item.status == VerificationStatus.CONFIRMED_VULNERABLE else ""
    vuln = _esc(item.finding.vuln_class.value)
    location = _esc(os.path.basename(item.finding.file)) + ":" + _esc(item.finding.line)
    route_html = ""
    if item.finding.route:
        route_html = "<div class=\"st\">" + _esc(item.finding.route.method) + " " + _esc(item.finding.route.path) + "</div>"
    remediation = _esc(item.remediation_hint)
    return (
        '<tr data-sev="' + severity + '" data-status="' + status + '" data-text="' + _esc(text) + '">'
        '<td><span class="sev ' + severity + '">' + severity + '</span></td>'
        '<td><span class="st ' + status_class + '">' + status + '</span></td>'
        '<td>' + vuln + '</td>'
        '<td><code>' + location + '</code>' + route_html + '</td>'
        '<td>' + _esc(item.finding.cwe) + '</td>'
        '<td>' + remediation + "".join(detail) + '</td>'
        '</tr>'
    )


def build_html(report: AuditReport) -> str:
    confirmed = [c for c in report.correlated if c.status == VerificationStatus.CONFIRMED_VULNERABLE]
    severities = sorted({c.final_severity.value for c in report.correlated})
    statuses = sorted({c.status.value for c in report.correlated})

    cards = [
        ("Total temuan", len(report.correlated)),
        ("Terkonfirmasi", len(confirmed)),
        ("Serangan berantai", len(report.chains)),
        ("Tindak lanjut", len(report.next_steps)),
    ]
    card_html = "".join(
        f"<div class=\"card\"><div class=\"num\">{_esc(value)}</div><div class=\"lbl\">{_esc(label)}</div></div>"
        for label, value in cards
    )

    chains_html = ""
    for chain in report.chains:
        steps = "".join(f"<li>{_esc(step)}</li>" for step in chain.get("steps", []))
        chain_severity = _esc(chain.get("severity"))
        chains_html += (
            '<div class="chain"><h3><span class="sev ' + chain_severity + '">'
            + chain_severity + "</span> " + _esc(chain.get("title")) + "</h3>"
            '<p class="sub">' + _esc(chain.get("reasoning")) + "</p><ol>" + steps + "</ol></div>"
        )

    steps_html = ""
    for step in report.next_steps:
        commands = "".join("<pre>$ " + _esc(command) + "</pre>" for command in step.get("commands", []))
        steps_html += (
            '<div class="chain"><h3><span class="badge">' + _esc(step.get("priority")) + "</span>"
            + _esc(step.get("title")) + '</h3><p class="sub">' + _esc(step.get("rationale")) + "</p>"
            + commands + "</div>"
        )

    rows = "".join(_finding_row(item) for item in report.correlated)
    if not rows:
        rows = '<tr><td colspan="6" class="empty">Tidak ada temuan.</td></tr>'

    severity_options = "".join('<option value="' + _esc(s) + '">' + _esc(s) + "</option>" for s in severities)
    status_options = "".join('<option value="' + _esc(s) + '">' + _esc(s) + "</option>" for s in statuses)

    severity_text = ", ".join("{}={}".format(k, v) for k, v in report.stats.get("by_severity", {}).items()) or "n/a"
    chains_block = ""
    if chains_html:
        chains_block = (
            '<h2 style="font-size:16px;margin:28px 0 4px;">Serangan Berantai ('
            + str(len(report.chains)) + ")</h2>" + chains_html
        )
    steps_block = ""
    if steps_html:
        steps_block = (
            '<h2 style="font-size:16px;margin:28px 0 4px;">Tindak Lanjut ('
            + str(len(report.next_steps)) + ")</h2>" + steps_html
        )

    return f"""<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DEX-SEC — Laporan Audit Keamanan</title>
<style>{CSS}</style>
</head>
<body>
<header>
  <h1>DEX-SEC — Laporan Audit Keamanan</h1>
  <div class="sub">Project: {_esc(report.project_path)} &nbsp;•&nbsp; Target: {_esc(report.target_url)} &nbsp;•&nbsp;
  {_esc(report.started_at)} → {_esc(report.finished_at)}</div>
</header>

<div class="cards">{card_html}</div>

<main>
  <h2 style="font-size:16px;margin:24px 0 4px;">Ringkasan Eksekutif</h2>
  <p class="sub">{_esc(report.stats.get('confirmed', 0))} temuan terkonfirmasi exploitable dari
  {_esc(report.stats.get('total', 0))} temuan static.
  Severity: {_esc(severity_text)}</p>

  {chains_block}
  {steps_block}

  <h2 style="font-size:16px;margin:28px 0 4px;">Semua Temuan</h2>
  <div class="toolbar">
    <input id="q" type="search" placeholder="cari vuln / file / route..." style="min-width:280px">
    <select id="sev"><option value="ALL">Semua severity</option>{severity_options}</select>
    <select id="st"><option value="ALL">Semua status</option>{status_options}</select>
    <span class="sub">klik judul kolom untuk mengurutkan</span>
  </div>
  <table>
    <thead><tr>
      <th data-sort="0" data-dir="asc">Severity</th>
      <th data-sort="1" data-dir="asc">Status</th>
      <th data-sort="2" data-dir="asc">Kerentanan</th>
      <th data-sort="3" data-dir="asc">Lokasi</th>
      <th data-sort="4" data-dir="asc">CWE</th>
      <th>Perbaikan</th>
    </tr></thead>
    <tbody>{rows}</tbody>
  </table>
</main>

<footer>DEX-SEC — Inside-Out Hybrid Application Security Testing &nbsp;•&nbsp;
dihasilkan {datetime.now(timezone.utc).astimezone().isoformat(timespec='seconds')}</footer>
<script>{JS}</script>
</body>
</html>
"""


def write_html(report: AuditReport, path: str) -> str:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(build_html(report))
    return path
