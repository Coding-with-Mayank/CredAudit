"""Builds `dashboard.html` -- a single self-contained file (same
restraint as `report.py`'s HTML report: no external assets, no charting
library, plain inline SVG) summarizing an engagement at a glance:
finding counts by severity, credential/secret risk counts, correlated
findings, an attack-path list, and the most recent audit events.

This is deliberately a *summary* view, not a replacement for the full
report -- it exists so someone can check engagement status quickly
without opening the full report/audit log.
"""
from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path

SEVERITY_COLORS = {
    "Critical": "#A83B2E", "High": "#C0603F", "Medium": "#A6790A",
    "Low": "#4F7A63", "Info": "#5B6169",
}
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]


def _esc(value) -> str:
    return html.escape(str(value))


def _severity_counts(evidence_list) -> dict:
    counts = {s: 0 for s in SEVERITY_ORDER}
    for e in evidence_list:
        counts[e.severity] = counts.get(e.severity, 0) + 1
    return counts


def _tile(label: str, value, accent: str = "") -> str:
    cls = f' class="tile-num {accent}"' if accent else ' class="tile-num"'
    return f'<div class="tile"><div{cls}>{_esc(value)}</div><div class="tile-label">{_esc(label)}</div></div>'


def _severity_bar(counts: dict) -> str:
    total = sum(counts.values())
    if total <= 0:
        return '<p class="note">No findings recorded.</p>'
    width, height = 640, 26
    x = 0.0
    rects, legend = [], []
    for sev in SEVERITY_ORDER:
        count = counts.get(sev, 0)
        if count <= 0:
            continue
        w = (count / total) * width
        color = SEVERITY_COLORS[sev]
        rects.append(f'<rect x="{x:.1f}" y="0" width="{max(w, 0.5):.1f}" height="{height}" fill="{color}" />')
        legend.append(
            f'<span class="legend-item"><span class="legend-swatch" style="background:{color}"></span>'
            f'{sev}: {count}</span>'
        )
        x += w
    svg = (
        f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" role="img" '
        f'aria-label="severity distribution">'
        f'<rect x="0" y="0" width="{width}" height="{height}" rx="4" fill="#D8DBD6" opacity="0.4"/>'
        + "".join(rects) + "</svg>"
    )
    return f'<div class="chart">{svg}<div class="legend">{"".join(legend)}</div></div>'


def _correlations_html(correlations) -> str:
    if not correlations:
        return '<p class="note">No correlated finding chains identified.</p>'
    rows = []
    for c in correlations:
        rows.append(
            f'<tr><td class="mono">{_esc(c.correlation_id)}</td>'
            f'<td>{_esc(c.asset)}</td>'
            f'<td class="mono">{_esc(c.combined_risk_score)}</td>'
            f'<td>{_esc(c.status)}</td>'
            f'<td class="note-cell">{_esc(c.explanation)}</td></tr>'
        )
    return (
        '<table class="data-table"><thead><tr><th>Chain</th><th>Asset</th><th>Risk</th>'
        '<th>Status</th><th>Explanation</th></tr></thead>'
        f'<tbody>{"".join(rows)}</tbody></table>'
    )


def _attack_paths_html(attack_paths) -> str:
    if not attack_paths:
        return '<p class="note">No attack paths identified from current evidence.</p>'
    blocks = []
    for p in attack_paths:
        chain = " \u2192 ".join(n.label for n in p.nodes)
        blocks.append(
            f'<div class="path-block"><p class="path-id">{_esc(p.path_id)} '
            f'<span class="note">(risk {p.path_risk}, confidence {p.confidence:.0%}, {_esc(p.status)})</span></p>'
            f'<p class="path-chain">{_esc(chain)}</p>'
            f'<p class="note">{_esc(p.narrative)}</p></div>'
        )
    return "".join(blocks)


def _audit_events_html(entries, limit: int = 15) -> str:
    if not entries:
        return '<p class="note">No audit events recorded yet.</p>'
    recent = entries[-limit:][::-1]
    rows = []
    for e in recent:
        ts = datetime.fromtimestamp(e["ts"], tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S") if "ts" in e else ""
        rows.append(
            f'<tr><td class="mono">{_esc(ts)}</td><td>{_esc(e.get("module",""))}</td>'
            f'<td>{_esc(e.get("action",""))}</td><td class="mono">{_esc(e.get("entry_hash","")[:10])}\u2026</td></tr>'
        )
    return (
        '<table class="data-table"><thead><tr><th>Time (UTC)</th><th>Module</th>'
        '<th>Action</th><th>Hash</th></tr></thead>'
        f'<tbody>{"".join(rows)}</tbody></table>'
    )


def build_dashboard(
    scope,
    out_dir,
    evidence_list=None,
    correlations=None,
    attack_paths=None,
    audit_entries=None,
    assets_tested: int = 0,
) -> Path:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    dashboard_path = out_dir / "dashboard.html"

    evidence_list = evidence_list or []
    correlations = correlations or []
    attack_paths = attack_paths or []
    audit_entries = audit_entries or []

    counts = _severity_counts(evidence_list)
    credential_risks = sum(1 for e in evidence_list if e.category == "Credential Exposure")
    exposed_secrets = sum(1 for e in evidence_list if e.category == "Secret Exposure")

    tiles = "".join([
        _tile("Assets tested", assets_tested or len({e.asset for e in evidence_list})),
        _tile("Total findings", len(evidence_list)),
        _tile("Critical", counts.get("Critical", 0), "flag"),
        _tile("High", counts.get("High", 0), "flag"),
        _tile("Medium", counts.get("Medium", 0), "medium"),
        _tile("Low", counts.get("Low", 0), "clear"),
        _tile("Credential risks", credential_risks),
        _tile("Exposed secrets", exposed_secrets),
        _tile("Correlated findings", len(correlations)),
        _tile("Attack paths", len(attack_paths)),
    ])

    data_blob = json.dumps(
        {
            "engagement_id": scope.engagement_id,
            "generated": datetime.now(timezone.utc).isoformat(),
            "evidence": [e.to_dict() for e in evidence_list],
            "correlations": [c.__dict__ for c in correlations],
        },
        default=str,
    )

    doc = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CredAudit dashboard \u2014 {_esc(scope.engagement_id)}</title>
<style>
  :root {{
    --ink: #14171F; --paper: #F6F7F5; --rule: #D8DBD6; --soft: #5B6169;
    --clear: #2F6E51; --flag: #A83B2E; --medium: #A6790A;
    --font-sans: Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif;
    --font-mono: 'IBM Plex Mono', SFMono-Regular, Consolas, Menlo, monospace;
  }}
  * {{ box-sizing: border-box; }}
  body {{ margin: 0; background: var(--paper); color: var(--ink); font-family: var(--font-sans); line-height: 1.5; }}
  .page {{ max-width: 980px; margin: 0 auto; padding: 32px 24px 80px; }}
  h1 {{ font-size: 22px; margin: 0 0 4px; }}
  .subtitle {{ color: var(--soft); font-size: 13px; font-family: var(--font-mono); margin: 0 0 28px; }}
  .tiles {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin-bottom: 32px; }}
  .tile {{ background: #fff; border: 1px solid var(--rule); border-radius: 6px; padding: 14px; }}
  .tile-num {{ font-family: var(--font-mono); font-size: 26px; font-weight: 600; }}
  .tile-num.flag {{ color: var(--flag); }}
  .tile-num.medium {{ color: var(--medium); }}
  .tile-num.clear {{ color: var(--clear); }}
  .tile-label {{ font-size: 12px; color: var(--soft); margin-top: 4px; }}
  .section {{ padding: 22px 0; border-top: 1px solid var(--rule); }}
  .section h2 {{ font-size: 16px; margin: 0 0 12px; }}
  .note {{ font-size: 12px; color: var(--soft); }}
  .note-cell {{ font-size: 12px; color: var(--soft); }}
  .chart {{ margin-top: 6px; }}
  .legend {{ display: flex; flex-wrap: wrap; gap: 6px 16px; margin-top: 8px; font-size: 12px; color: var(--soft); }}
  .legend-item {{ display: inline-flex; align-items: center; gap: 5px; }}
  .legend-swatch {{ width: 9px; height: 9px; border-radius: 2px; display: inline-block; }}
  .data-table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  .data-table th {{ text-align: left; font-family: var(--font-mono); font-size: 10px; letter-spacing: 0.05em;
    text-transform: uppercase; color: var(--soft); border-bottom: 1px solid var(--rule); padding: 6px 8px; }}
  .data-table td {{ padding: 7px 8px; border-bottom: 1px solid var(--rule); }}
  .mono {{ font-family: var(--font-mono); font-size: 12px; }}
  .path-block {{ background: #fff; border: 1px solid var(--rule); border-radius: 6px; padding: 12px 14px; margin-bottom: 10px; }}
  .path-id {{ font-family: var(--font-mono); font-size: 12px; margin: 0 0 4px; }}
  .path-chain {{ font-size: 14px; margin: 4px 0; }}
</style>
</head>
<body>
<div class="page">
  <h1>CredAudit dashboard</h1>
  <p class="subtitle">{_esc(scope.engagement_id)} &middot; {_esc(scope.client_name)} &middot;
    generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M')} UTC</p>

  <div class="tiles">{tiles}</div>

  <section class="section">
    <h2>Risk distribution</h2>
    {_severity_bar(counts)}
  </section>

  <section class="section">
    <h2>Correlated findings</h2>
    {_correlations_html(correlations)}
  </section>

  <section class="section">
    <h2>Attack paths</h2>
    {_attack_paths_html(attack_paths)}
  </section>

  <section class="section">
    <h2>Recent audit events</h2>
    {_audit_events_html(audit_entries)}
  </section>

  <p class="note">Full detail (per-finding evidence, remediation, and the full audit trail) lives in
    report.html / report.md / audit_log.jsonl alongside this file. This dashboard is a summary view only.</p>
</div>
<script type="application/json" id="credaudit-data">{data_blob}</script>
</body>
</html>"""

    dashboard_path.write_text(doc)
    return dashboard_path
