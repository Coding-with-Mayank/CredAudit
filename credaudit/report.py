"""Builds the engagement report -- a plain Markdown version for quick
reading/diffing, and a styled, self-contained HTML version meant to be
handed to a client or auditor as the actual deliverable.

Design intent for the HTML report: this is a case file, not a dashboard.
No plaintext credentials are ever written into it. Its one signature
visual is the hash-chain audit trail, because tamper-evidence is the
actual novel thing this tool provides. The proportion charts added
alongside it follow the same restraint: plain stacked bars in the
report's own two status colors, no separate charting library, so the
file still renders identically if opened years from now with no network
access.
"""
from __future__ import annotations

import html
import json
from datetime import datetime
from pathlib import Path

from .audit_log import AuditLog
from .modules import attack_graph as attack_graph_mod
from .modules.risk_engine import RISK_ORDER
from .scope import Scope


def _esc(value) -> str:
    return html.escape(str(value))


def _read_audit_entries(audit_log_path) -> list:
    path = Path(audit_log_path)
    entries = []
    if not path.exists():
        return entries
    with path.open() as f:
        for line in f:
            if line.strip():
                entries.append(json.loads(line))
    return entries


# Nuclei findings usually carry a severity under info.severity. Anything
# in HIGH_ATTENTION gets the "flag" color in charts; everything else
# (including missing/unknown severity) is treated as informational.
HIGH_ATTENTION_SEVERITIES = {"critical", "high", "medium"}


def _finding_severity(finding: dict) -> str:
    info = finding.get("info") if isinstance(finding, dict) else None
    if isinstance(info, dict) and info.get("severity"):
        return str(info["severity"]).lower()
    return str(finding.get("severity", "unknown")).lower() if isinstance(finding, dict) else "unknown"


def recon_severity_buckets(findings: list) -> dict:
    """Collapse nuclei-style severities into two buckets for a quick
    at-a-glance chart. Full per-finding detail still lives in the raw
    recon.jsonl -- this is a summary, not a replacement for it."""
    buckets = {"needs_attention": 0, "informational": 0}
    for finding in findings:
        severity = _finding_severity(finding)
        if severity in HIGH_ATTENTION_SEVERITIES:
            buckets["needs_attention"] += 1
        else:
            buckets["informational"] += 1
    return buckets


def _stat_bar(segments, total, width=460, height=22) -> str:
    """segments: list of (count, css_color_var, label). Renders a plain
    horizontal stacked bar plus a legend line, using the report's own
    CSS variables so it always matches the surrounding page theme."""
    if total <= 0:
        return '<p class="note">No data to chart yet.</p>'

    x = 0.0
    rects = []
    legend_items = []
    for count, color, label in segments:
        w = (count / total) * width
        if w > 0.01:
            rects.append(f'<rect x="{x:.1f}" y="0" width="{w:.1f}" height="{height}" fill="{color}" />')
        pct = (count / total) * 100
        legend_items.append(
            f'<span class="legend-item"><span class="legend-swatch" style="background:{color}"></span>'
            f'{_esc(label)}: {count} ({pct:.0f}%)</span>'
        )
        x += w

    svg = (
        f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" '
        f'role="img" aria-label="proportion chart">'
        f'<rect x="0" y="0" width="{width}" height="{height}" rx="4" '
        f'fill="var(--rule)" opacity="0.35"/>'
        + "".join(rects) +
        f'</svg>'
    )
    legend = f'<div class="legend">{"".join(legend_items)}</div>'
    return f'<div class="chart">{svg}{legend}</div>'


RISK_CSS_CLASS = {
    "Critical": "flag", "High": "flag", "Medium": "medium", "Low": "clear", "Info": "clear",
}


def _risk_table_html(risk_assessments: list) -> str:
    if not risk_assessments:
        return '<p class="note">No risk-rated findings.</p>'
    rows = []
    for a in risk_assessments:
        cls = RISK_CSS_CLASS.get(a.risk_level, "clear")
        indicator_list = ", ".join(a.indicators) if a.indicators else "\u2014"
        rows.append(
            f'<tr><td class="mono">{_esc(a.service)}</td>'
            f'<td class="mono">{_esc(a.target)}</td>'
            f'<td><span class="risk-badge risk-{cls}">{_esc(a.risk_level)}</span></td>'
            f'<td>{_esc(indicator_list)}</td>'
            f'<td class="note-cell">{_esc(a.reasoning)}</td></tr>'
        )
    return f'''<table class="data-table">
      <thead><tr><th>Service</th><th>Target</th><th>Risk</th><th>Indicators</th><th>Reasoning</th></tr></thead>
      <tbody>{"".join(rows)}</tbody>
    </table>'''


def _js_intel_html(js_intel_results: list) -> str:
    if not js_intel_results:
        return '<p class="note">No JS intelligence results.</p>'

    blocks = []
    for result in js_intel_results:
        top_endpoints = result.endpoints[:10]
        endpoint_items = "".join(
            f'<span class="tag">{_esc(path)} <span class="note">({score})</span></span>'
            for path, score in top_endpoints
        ) or '<span class="note">No endpoints extracted.</span>'

        secret_rows = "".join(
            f'<tr><td class="mono">{_esc(s.kind)}</td><td class="mono flag">{_esc(s.masked)}</td></tr>'
            for s in result.secrets
        )
        secret_table = (
            f'<table class="data-table"><thead><tr><th>Kind</th><th>Value (masked)</th></tr></thead>'
            f'<tbody>{secret_rows}</tbody></table>'
            if result.secrets else '<p class="note">No secret patterns matched.</p>'
        )

        blocks.append(f'''
        <div class="js-intel-block">
          <p class="note"><strong>{_esc(result.source or "(unnamed source)")}</strong>
            {"&mdash; GraphQL endpoint detected" if result.has_graphql else ""}</p>
          <div class="tag-list" style="margin:8px 0;">{endpoint_items}</div>
          {secret_table}
        </div>''')

    return "".join(blocks)


def _attack_graph_svg(graph) -> str:
    if not graph.nodes:
        return '<p class="note">No escalation paths identified from current evidence.</p>'

    node_w, node_h, col_gap, row_h = 190, 54, 20, 90
    positions = {}
    svg_nodes = []
    y = 20
    for stage in attack_graph_mod.STAGE_ORDER:
        nodes_in_stage = [n for n in graph.nodes if n.stage == stage]
        if not nodes_in_stage:
            continue
        x = 20
        for n in nodes_in_stage:
            positions[n.id] = (x, y, x + node_w, y + node_h)
            color = "var(--clear)" if n.verified else "var(--flag)"
            dash = '' if n.verified else 'stroke-dasharray="4,3"'
            label = _esc(n.label if len(n.label) <= 34 else n.label[:31] + "\u2026")
            svg_nodes.append(
                f'<rect x="{x}" y="{y}" width="{node_w}" height="{node_h}" rx="6" '
                f'fill="var(--paper)" stroke="{color}" stroke-width="1.5" {dash}/>'
                f'<text x="{x + node_w/2}" y="{y + 16}" text-anchor="middle" '
                f'font-family="var(--font-mono)" font-size="9" fill="var(--soft)" '
                f'text-transform="uppercase">{_esc(attack_graph_mod.STAGE_LABELS[stage])}</text>'
                f'<text x="{x + node_w/2}" y="{y + 34}" text-anchor="middle" '
                f'font-size="12" fill="var(--ink)">{label}</text>'
            )
            x += node_w + col_gap
        y += row_h

    svg_edges = []
    for e in graph.edges:
        if e.source not in positions or e.target not in positions:
            continue
        sx0, sy0, sx1, sy1 = positions[e.source]
        tx0, ty0, tx1, ty1 = positions[e.target]
        x1, y1 = (sx0 + sx1) / 2, sy1
        x2, y2 = (tx0 + tx1) / 2, ty0
        svg_edges.append(
            f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" '
            f'stroke="var(--rule)" stroke-width="1.5" marker-end="url(#agarrow)"/>'
        )

    total_height = y + 10
    svg = (
        f'<svg viewBox="0 0 680 {total_height}" width="100%" role="img" aria-label="attack graph">'
        f'<defs><marker id="agarrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" '
        f'orient="auto-start-reverse"><path d="M2 1L8 5L2 9" fill="none" stroke="var(--rule)" stroke-width="1.5"/>'
        f'</marker></defs>'
        + "".join(svg_edges) + "".join(svg_nodes) +
        f'</svg>'
    )
    return (
        f'<div class="chart">{svg}<p class="note">Dashed border = hypothetical next stage, not verified. '
        f'Solid border = directly observed evidence. This graph does not test or confirm any of the '
        f'unverified stages \u2014 that requires a separate, deliberate, human decision.</p></div>'
    )


# ---------------------------------------------------------------------------
# Markdown report -- quick to read, easy to diff/version-control
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Unified evidence / correlation / attack-path / credential / secret
# sections. These render the core.evidence.Evidence, core.correlation.
# CorrelatedFinding, and attack_paths.graph.AttackPath objects the
# pipeline (core.pipeline.run_pipeline) produces, when the caller
# supplies them. Every parameter is optional and purely additive --
# callers still using only the original per-module arguments get exactly
# the report this project always produced.
# ---------------------------------------------------------------------------

EVIDENCE_SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]
_EVIDENCE_SEVERITY_COLORS = {
    "Critical": "var(--flag)", "High": "var(--flag)", "Medium": "#A6790A",
    "Low": "var(--clear)", "Info": "var(--soft)",
}


def _evidence_severity_counts(evidence_list) -> dict:
    counts = {s: 0 for s in EVIDENCE_SEVERITY_ORDER}
    for e in evidence_list or []:
        counts[e.severity] = counts.get(e.severity, 0) + 1
    return counts


def _risk_distribution_text(evidence_list) -> list:
    counts = _evidence_severity_counts(evidence_list)
    total = sum(counts.values())
    return [
        f"- {s}: {counts[s]} ({(counts[s] / total * 100 if total else 0):.0f}%)"
        for s in EVIDENCE_SEVERITY_ORDER if counts[s] > 0
    ]


def _risk_distribution_chart(evidence_list) -> str:
    counts = _evidence_severity_counts(evidence_list)
    total = sum(counts.values())
    segments = [(counts[s], _EVIDENCE_SEVERITY_COLORS[s], s) for s in EVIDENCE_SEVERITY_ORDER if counts[s] > 0]
    return _stat_bar(segments, total=total)


def _credential_findings_md(findings) -> list:
    lines = ["## Credential findings", ""]
    for f in sorted(findings, key=lambda x: x.risk.score, reverse=True):
        flags = []
        if f.default_credential:
            flags.append("default credential")
        if f.reused_with:
            flags.append(f"reused ({len(f.reused_with)} other account(s))")
        if f.breach_exposure:
            flags.append("breach-exposed")
        elif f.breach_exposure is None:
            flags.append("breach: not checked")
        if f.privileged:
            flags.append("privileged")
        lines.append(
            f"- **[{f.risk.severity}]** `{f.account}` \u2014 {f.strength} password "
            f"(risk {f.risk.score}, confidence {f.risk.confidence:.0%}): {', '.join(flags) or 'none'}"
        )
        lines.append(f"  - Remediation: {f.risk.remediation}")
    lines.append("")
    return lines


def _secret_findings_md(findings) -> list:
    lines = ["## Secret exposure", ""]
    for f in findings:
        location = f" (line {f.line_number})" if f.line_number else ""
        lines.append(f"- **[{f.display_severity}]** {f.secret_type} in `{f.source}`{location} \u2014 `{f.redacted}`")
        lines.append(f"  - Remediation: {f.remediation}")
    lines.append("")
    return lines


def _correlations_md(correlations) -> list:
    lines = ["## Correlated findings", ""]
    if not correlations:
        lines += ["No correlated finding chains identified.", ""]
        return lines
    for c in correlations:
        lines.append(f"- **{c.correlation_id}** [{c.status}] {c.explanation}")
        lines.append(f"  - Combined risk: {c.combined_risk_score}, confidence: {c.confidence:.0%}")
        lines.append(f"  - Related findings: {', '.join(c.related_finding_ids)}")
        lines.append(f"  - Remediation: {c.remediation}")
    lines.append("")
    return lines


def _attack_paths_md(attack_paths) -> list:
    lines = ["## Attack paths", ""]
    if not attack_paths:
        lines += ["No attack paths identified from current evidence.", ""]
        return lines
    for p in attack_paths:
        chain = " \u2192 ".join(n.label for n in p.nodes)
        lines.append(f"- **{p.path_id}** [{p.status}] risk {p.path_risk}, confidence {p.confidence:.0%}")
        lines.append(f"  - {chain}")
        lines.append(f"  - {p.narrative}")
        verification = getattr(p, "verification", None)
        if verification is not None:
            lines.append(f"  - Verification: {verification.summary}")
            for step in verification.outstanding_steps:
                lines.append(f"    - To confirm: {step}")
        for m in p.recommended_mitigations:
            lines.append(f"  - Mitigation: {m}")
    lines.append("")
    return lines


def _evidence_table_md(evidence_list) -> list:
    lines = [
        "## Evidence detail", "",
        "| ID | Asset | Category | Severity | Risk | Confidence | Status | Source |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for e in sorted(evidence_list, key=lambda x: x.risk_score, reverse=True):
        lines.append(
            f"| {e.finding_id} | {e.asset} | {e.category} | {e.severity} | {e.risk_score} | "
            f"{e.confidence:.0%} | {e.status} | {e.source} |"
        )
    lines.append("")
    return lines


LIMITATIONS_TEXT = [
    "Scope enforcement happens in CredAudit's own Python code before every external-tool "
    "invocation; it cannot guarantee that a third-party binary (hydra, hashcat, nuclei, ...) "
    "will never itself act outside the intended boundary due to a bug or flag misuse.",
    "Scope-file signature verification (when used) proves the file's content has not changed "
    "since a specific private key signed it. With an externally-supplied trusted key this is "
    "real assurance; with a key embedded in the scope file itself, it only proves internal "
    "self-consistency. It never proves the signer was organizationally authorized to approve "
    "the engagement.",
    "The audit log's hash chain detects edits, reordering, and deletions within the entries "
    "present. Detecting truncation from the end of the log requires comparing it against its "
    "signed manifest (`credaudit verify`) -- an unsigned manifest still detects truncation, "
    "just not who approved the final state.",
    "Correlated findings and attack paths describe co-occurrence of evidence on the same asset, "
    "not a confirmed attacker path. Status is only \u2018confirmed\u2019 when every underlying "
    "finding was itself directly observed (e.g. a live valid credential pair, or a live-validated "
    "secret) -- never from pattern-matching alone. Per-path verification detail (which specific "
    "link is still unconfirmed, and the exact authorized step that would confirm it) is available "
    "via attack_paths.verification -- see docs/attack_path_verification.md. This platform does not, "
    "and will not, automatically exploit a finding to 'prove' a path; that detail still requires a "
    "human to take the indicated, already-scoped action.",
    "Secret detection is pattern-based (regex/shape heuristics) and will still miss secrets that "
    "don't match a known pattern shape. Live validation (opt-in via --validate-secrets) can confirm "
    "whether a detected secret with a known issuing provider (GitHub, Slack, Stripe, SendGrid, "
    "Google, AWS) is currently active via a single read-only API call to that provider -- see "
    "docs/secret_validation.md for exactly what is and isn't checked this way, and why private keys "
    "and database connection strings are deliberately excluded from automatic validation.",
    "Password-strength classification defaults to a fixed, documented rule (length + "
    "character-class count); the built-in common-password list is a small hygiene sample, not a "
    "full cracking dictionary. An opt-in entropy/crack-time estimate (zxcvbn-based, via "
    "use_entropy_scoring=True) is available for a more graduated, pattern-aware assessment that "
    "catches things the fixed rule can miss, such as keyboard-walk passwords.",
    "Breach-exposure checking is opt-in and requires network access to the HIBP Pwned Passwords "
    "API; when not run, credential findings record breach exposure as \u2018not checked\u2019, "
    "never as \u2018clean\u2019.",
    "Risk scores are an explainable, documented weighted model (see docs/risk_model.md), not a "
    "guarantee of real-world exploitability -- they exist to prioritize review, not replace it.",
    "The optional persistent findings backend (credaudit.api, requires the [api] extra) adds "
    "workflow tracking (open/remediated/false_positive/accepted_risk) on top of findings; it does "
    "not change or re-score the confidence/status vocabulary produced by a scan, and it does not "
    "re-run or re-verify a finding on import.",
]


def build_report(
    scope: Scope,
    out_dir: Path,
    recon_findings=None,
    online_summary=None,
    offline_result=None,
    breach_results=None,
    risk_assessments=None,
    js_intel_results=None,
    executive_summary=None,
    evidence_list=None,
    correlations=None,
    attack_paths=None,
    credential_findings=None,
    secret_findings=None,
) -> Path:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    report_path = out_dir / "report.md"

    lines = [
        "# Credential audit report",
        "",
        f"- **Engagement:** {scope.engagement_id}",
        f"- **Client:** {scope.client_name}",
        f"- **Authorized by:** {scope.authorized_by}",
        f"- **Window:** {scope.start_date} to {scope.end_date}",
        f"- **Scope file checksum (sha256):** `{scope.source_sha256}`",
        f"- **Generated:** {datetime.utcnow().isoformat()}Z",
        "",
    ]

    if executive_summary:
        lines += [
            "## Executive summary", "",
            "*AI-generated draft \u2014 review before including in a client deliverable.*", "",
            executive_summary, "",
        ]

    lines += [
        "## Targets in scope",
        "",
        *[f"- {t}" for t in scope.targets],
        "",
    ]

    if risk_assessments:
        lines += ["## Risk assessment", ""]
        for a in sorted(risk_assessments, key=lambda x: RISK_ORDER.index(x.risk_level), reverse=True):
            indicator_list = ", ".join(a.indicators) if a.indicators else "none"
            lines.append(f"- **{a.risk_level}** \u2014 {a.service} on {a.target}: {a.reasoning} (indicators: {indicator_list})")
        lines.append("")

    if recon_findings is not None:
        buckets = recon_severity_buckets(recon_findings)
        lines += [
            "## Recon findings", "",
            f"{len(recon_findings)} findings recorded "
            f"({buckets['needs_attention']} needing attention, "
            f"{buckets['informational']} informational).",
            "",
        ]

    if js_intel_results:
        lines += ["## JavaScript intelligence", ""]
        for r in js_intel_results:
            lines.append(f"- `{r.source}`: {len(r.endpoints)} endpoint(s), {len(r.secrets)} secret pattern(s)"
                          + (", GraphQL detected" if r.has_graphql else ""))
            for s in r.secrets:
                lines.append(f"  - {s.kind}: `{s.masked}`")
        lines.append("")

    if risk_assessments or js_intel_results:
        graph = attack_graph_mod.build_attack_graph(risk_assessments, js_intel_results)
        if graph.nodes:
            lines += ["## Attack graph (hypothetical, unverified past credential leak)", ""]
            by_id = {n.id: n for n in graph.nodes}
            for e in graph.edges:
                src, tgt = by_id[e.source], by_id[e.target]
                mark = "" if tgt.verified else " *(unverified)*"
                lines.append(f"- {src.label} \u2192 {tgt.label}{mark} ({e.label})")
            lines.append("")

    if online_summary is not None:
        summaries = online_summary if isinstance(online_summary, list) else [online_summary]
        lines += ["## Online credential testing", ""]
        for s in summaries:
            lines.append(
                f"- `{s.log_path}` — {s.accounts_tested} accounts tested, "
                f"{s.valid_pairs_found} valid pair(s) found"
            )
        lines.append("")

    if offline_result is not None:
        lines += [
            "## Offline hash audit",
            "",
            f"- {offline_result.cracked_count} / {offline_result.total_hashes} hashes "
            f"cracked ({offline_result.weak_ratio * 100:.0f}%)",
            f"- Cracked-password log: `{offline_result.out_file}`",
            "- Raw plaintext is intentionally not embedded in this report; "
            "reference the log file directly and handle it per your "
            "engagement's data-handling rules.",
            "",
        ]

    if breach_results:
        breached = sum(1 for r in breach_results if r.is_breached)
        lines += [
            "## Password hygiene (breach-corpus check)",
            "",
            f"- {breached} / {len(breach_results)} tested passwords have "
            "appeared in known public breaches.",
            "",
        ]

    if credential_findings:
        lines += _credential_findings_md(credential_findings)

    if secret_findings:
        lines += _secret_findings_md(secret_findings)

    if correlations is not None:
        lines += _correlations_md(correlations)

    if attack_paths is not None:
        lines += _attack_paths_md(attack_paths)

    if evidence_list:
        lines += ["## Risk distribution", "", *_risk_distribution_text(evidence_list), ""]
        lines += _evidence_table_md(evidence_list)

    lines += [
        "## Scope & authorization",
        "",
        f"- **Cryptographically verified:** {scope.cryptographically_verified} "
        f"(trust level: {scope.verification_trust_level})",
        f"- **Signature required by scope file:** {scope.require_signature}",
        f"- **Allowed modules:** {', '.join(scope.allowed_modules)}",
        "",
    ]

    if evidence_list:
        sources = sorted({e.source for e in evidence_list})
        lines += ["## Tool / evidence sources", "", *[f"- {s}" for s in sources], ""]

    lines += [
        "## Audit trail",
        "",
        "See `audit_log.jsonl` in this engagement's output directory for the "
        "full hash-chained action log, and `audit_log_manifest.json` for the "
        "signed final checkpoint. Verify both with "
        "`python -m credaudit.cli verify --log audit_log.jsonl`.",
        "",
    ]

    lines += ["## Limitations", "", *[f"- {t}" for t in LIMITATIONS_TEXT], ""]

    report_path.write_text("\n".join(lines))
    return report_path


# ---------------------------------------------------------------------------
# HTML report -- the client/auditor-facing deliverable
# ---------------------------------------------------------------------------

def _credential_findings_html(findings) -> str:
    rows = []
    for f in sorted(findings, key=lambda x: x.risk.score, reverse=True):
        flags = []
        if f.default_credential:
            flags.append("default credential")
        if f.reused_with:
            flags.append(f"reused \u00d7{len(f.reused_with)}")
        if f.breach_exposure:
            flags.append("breach-exposed")
        elif f.breach_exposure is None:
            flags.append("breach: not checked")
        if f.privileged:
            flags.append("privileged")
        cls = "flag" if f.risk.severity in ("Critical", "High") else "clear" if f.risk.severity in ("Low", "Info") else ""
        rows.append(
            f'<tr><td class="mono">{_esc(f.account)}</td><td>{_esc(f.strength)}</td>'
            f'<td class="{cls}">{_esc(f.risk.severity)}</td><td class="mono">{f.risk.score}</td>'
            f'<td>{_esc(", ".join(flags) or "none")}</td></tr>'
        )
    return (
        '<table class="data-table"><thead><tr><th>Account</th><th>Strength</th>'
        '<th>Severity</th><th>Risk</th><th>Flags</th></tr></thead>'
        f'<tbody>{"".join(rows)}</tbody></table>'
    )


def _secret_findings_html(findings) -> str:
    rows = []
    for f in findings:
        location = f" (line {f.line_number})" if f.line_number else ""
        sev = f.display_severity
        cls = "flag" if sev in ("Critical", "High") else "clear" if sev == "Low" else ""
        rows.append(
            f'<tr><td>{_esc(f.secret_type)}</td><td class="mono">{_esc(f.source)}{_esc(location)}</td>'
            f'<td class="{cls}">{_esc(sev)}</td><td class="mono">{_esc(f.redacted)}</td></tr>'
        )
    return (
        '<table class="data-table"><thead><tr><th>Type</th><th>Source</th>'
        '<th>Severity</th><th>Redacted value</th></tr></thead>'
        f'<tbody>{"".join(rows)}</tbody></table>'
    )


def _correlations_html(correlations) -> str:
    if not correlations:
        return '<p class="note">No correlated finding chains identified.</p>'
    rows = []
    for c in correlations:
        rows.append(
            f'<tr><td class="mono">{_esc(c.correlation_id)}</td><td>{_esc(c.asset)}</td>'
            f'<td class="mono">{c.combined_risk_score}</td><td>{_esc(c.status)}</td>'
            f'<td>{_esc(c.explanation)}</td></tr>'
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
        verification = getattr(p, "verification", None)
        verification_html = ""
        if verification is not None:
            steps_html = "".join(f"<li>{_esc(step)}</li>" for step in verification.outstanding_steps)
            verification_html = (
                f'<p class="note" style="margin:4px 0;"><strong>Verification:</strong> {_esc(verification.summary)}</p>'
                + (f'<ul class="note" style="margin:0 0 4px 16px;">{steps_html}</ul>' if steps_html else "")
            )
        blocks.append(
            f'<div class="tile" style="margin-bottom:10px;">'
            f'<p class="mono" style="margin:0 0 4px;">{_esc(p.path_id)} '
            f'<span class="note">(risk {p.path_risk}, confidence {p.confidence:.0%}, {_esc(p.status)})</span></p>'
            f'<p style="margin:4px 0;">{_esc(chain)}</p>'
            f'<p class="note">{_esc(p.narrative)}</p>{verification_html}</div>'
        )
    return "".join(blocks)


def _evidence_table_html(evidence_list) -> str:
    rows = []
    for e in sorted(evidence_list, key=lambda x: x.risk_score, reverse=True):
        cls = "flag" if e.severity in ("Critical", "High") else "clear" if e.severity in ("Low", "Info") else ""
        rows.append(
            f'<tr><td class="mono">{_esc(e.finding_id)}</td><td>{_esc(e.asset)}</td>'
            f'<td>{_esc(e.category)}</td><td class="{cls}">{_esc(e.severity)}</td>'
            f'<td class="mono">{e.risk_score}</td><td class="mono">{e.confidence:.0%}</td>'
            f'<td>{_esc(e.status)}</td><td>{_esc(e.source)}</td></tr>'
        )
    return (
        '<table class="data-table"><thead><tr><th>ID</th><th>Asset</th><th>Category</th>'
        '<th>Severity</th><th>Risk</th><th>Confidence</th><th>Status</th><th>Source</th></tr></thead>'
        f'<tbody>{"".join(rows)}</tbody></table>'
    )


def _scope_authorization_html(scope: Scope) -> str:
    verified_cls = "clear" if scope.cryptographically_verified else ""
    return f"""
    <dl class="cover-facts">
      <div><dt>Cryptographically verified</dt>
        <dd class="{verified_cls}">{_esc(scope.cryptographically_verified)}
          (trust level: {_esc(scope.verification_trust_level)})</dd></div>
      <div><dt>Signature required by scope file</dt><dd>{_esc(scope.require_signature)}</dd></div>
      <div><dt>Allowed modules</dt><dd>{_esc(", ".join(scope.allowed_modules))}</dd></div>
    </dl>"""


def _limitations_html() -> str:
    items = "".join(f"<li>{_esc(t)}</li>" for t in LIMITATIONS_TEXT)
    return f'<ul class="note" style="padding-left:18px;">{items}</ul>'


def build_html_report(
    scope: Scope,
    out_dir: Path,
    audit_log_path,
    recon_findings=None,
    online_summary=None,
    offline_result=None,
    breach_results=None,
    risk_assessments=None,
    js_intel_results=None,
    executive_summary=None,
    evidence_list=None,
    correlations=None,
    attack_paths=None,
    credential_findings=None,
    secret_findings=None,
) -> Path:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    html_path = out_dir / "report.html"

    chain_valid = AuditLog(audit_log_path).verify_chain()
    entries = _read_audit_entries(audit_log_path)

    targets_html = "".join(f'<span class="tag">{_esc(t)}</span>' for t in scope.targets)

    exec_summary_html = ""
    if executive_summary:
        exec_summary_html = f"""
        <section class="section" style="border-top:none; padding-top:0;">
          <p class="eyebrow">AI-generated draft &mdash; review before sharing</p>
          <h2>Executive summary</h2>
          <p class="stat" style="font-size:15px; font-weight:400;">{_esc(executive_summary)}</p>
        </section>"""

    sections = []

    if risk_assessments:
        sections.append(f"""
        <section class="section">
          <p class="eyebrow">Interpretation</p>
          <h2>Risk assessment</h2>
          {_risk_table_html(sorted(risk_assessments, key=lambda a: RISK_ORDER.index(a.risk_level), reverse=True))}
        </section>""")

    if recon_findings is not None:
        buckets = recon_severity_buckets(recon_findings)
        chart = _stat_bar(
            [
                (buckets["needs_attention"], "var(--flag)", "Needs attention"),
                (buckets["informational"], "var(--clear)", "Informational"),
            ],
            total=len(recon_findings),
        )
        sections.append(f"""
        <section class="section">
          <p class="eyebrow">Evidence</p>
          <h2>Recon findings</h2>
          <p class="stat"><span class="stat-num">{len(recon_findings)}</span>
            findings recorded across scoped targets.</p>
          {chart}
        </section>""")

    if js_intel_results:
        sections.append(f"""
        <section class="section">
          <p class="eyebrow">Evidence</p>
          <h2>JavaScript intelligence</h2>
          {_js_intel_html(js_intel_results)}
        </section>""")

    if risk_assessments or js_intel_results:
        graph = attack_graph_mod.build_attack_graph(risk_assessments, js_intel_results)
        if graph.nodes:
            sections.append(f"""
        <section class="section">
          <p class="eyebrow">Interpretation</p>
          <h2>Attack graph</h2>
          <p class="note" style="margin-bottom:8px;">Hypothetical escalation paths built from the
            evidence above. Nothing past a credential leak is tested or confirmed by this tool.</p>
          {_attack_graph_svg(graph)}
        </section>""")

    if online_summary is not None:
        summaries = online_summary if isinstance(online_summary, list) else [online_summary]
        rows = "".join(
            f'<tr><td class="mono">{_esc(s.log_path.name)}</td>'
            f'<td>{s.accounts_tested}</td>'
            f'<td class="{"flag" if s.valid_pairs_found else "clear"}">'
            f'{s.valid_pairs_found}</td></tr>'
            for s in summaries
        )
        online_charts = "".join(
            f'<p class="note" style="margin-top:14px;">{_esc(s.log_path.name)}</p>' +
            _stat_bar(
                [
                    (s.valid_pairs_found, "var(--flag)", "Valid pairs found"),
                    (max(s.accounts_tested - s.valid_pairs_found, 0), "var(--clear)", "No match"),
                ],
                total=s.accounts_tested,
            )
            for s in summaries
        )
        sections.append(f"""
        <section class="section">
          <p class="eyebrow">Evidence</p>
          <h2>Online credential testing</h2>
          <table class="data-table">
            <thead><tr><th>Log</th><th>Accounts tested</th><th>Valid pairs found</th></tr></thead>
            <tbody>{rows}</tbody>
          </table>
          {online_charts}
        </section>""")

    if offline_result is not None:
        pct = offline_result.weak_ratio * 100
        status_class = "flag" if offline_result.cracked_count > 0 else "clear"
        chart = _stat_bar(
            [
                (offline_result.cracked_count, "var(--flag)", "Weak (cracked)"),
                (offline_result.total_hashes - offline_result.cracked_count, "var(--clear)", "Not cracked"),
            ],
            total=offline_result.total_hashes,
        )
        sections.append(f"""
        <section class="section">
          <p class="eyebrow">Evidence</p>
          <h2>Offline hash audit</h2>
          <p class="stat"><span class="stat-num {status_class}">{pct:.0f}%</span>
            of {offline_result.total_hashes} tested hashes cracked against the
            supplied wordlist ({offline_result.cracked_count} weak).</p>
          {chart}
          <p class="note">Plaintext is intentionally not included in this report.
            See <code>{_esc(offline_result.out_file.name)}</code> in the engagement
            output directory, handled per your data-handling policy.</p>
        </section>""")

    if breach_results:
        breached = sum(1 for r in breach_results if r.is_breached)
        status_class = "flag" if breached else "clear"
        chart = _stat_bar(
            [
                (breached, "var(--flag)", "Breached"),
                (len(breach_results) - breached, "var(--clear)", "Clean"),
            ],
            total=len(breach_results),
        )
        sections.append(f"""
        <section class="section">
          <p class="eyebrow">Evidence</p>
          <h2>Password hygiene &mdash; breach corpus check</h2>
          <p class="stat"><span class="stat-num {status_class}">{breached} / {len(breach_results)}</span>
            tested passwords have appeared in known public breaches
            (HIBP k-anonymity model, no plaintext transmitted).</p>
          {chart}
        </section>""")

    if credential_findings:
        sections.append(f"""
        <section class="section">
          <p class="eyebrow">Evidence</p>
          <h2>Credential findings</h2>
          {_credential_findings_html(credential_findings)}
        </section>""")

    if secret_findings:
        sections.append(f"""
        <section class="section">
          <p class="eyebrow">Evidence</p>
          <h2>Secret exposure</h2>
          {_secret_findings_html(secret_findings)}
        </section>""")

    if correlations is not None:
        sections.append(f"""
        <section class="section">
          <p class="eyebrow">Interpretation</p>
          <h2>Correlated findings</h2>
          <p class="note" style="margin-bottom:8px;">Co-occurring evidence on the same asset, grouped into a
            combined-risk chain. A chain is only marked \u2018confirmed\u2019 when every finding feeding it was
            itself directly observed -- otherwise it is a prioritization signal, not proof.</p>
          {_correlations_html(correlations)}
        </section>""")

    if attack_paths is not None:
        sections.append(f"""
        <section class="section">
          <p class="eyebrow">Interpretation</p>
          <h2>Attack paths</h2>
          <p class="note" style="margin-bottom:8px;">Built directly from the correlated findings above --
            every node traces back to a specific finding_id, and nothing here is tested or exploited.</p>
          {_attack_paths_html(attack_paths)}
        </section>""")

    if evidence_list:
        sections.append(f"""
        <section class="section">
          <p class="eyebrow">Summary</p>
          <h2>Risk distribution</h2>
          {_risk_distribution_chart(evidence_list)}
        </section>""")
        sections.append(f"""
        <section class="section">
          <p class="eyebrow">Evidence</p>
          <h2>Evidence detail</h2>
          {_evidence_table_html(evidence_list)}
        </section>""")
        sources = sorted({e.source for e in evidence_list})
        sections.append(f"""
        <section class="section">
          <p class="eyebrow">Reference</p>
          <h2>Tool / evidence sources</h2>
          <div class="tag-list">{"".join(f'<span class="tag">{_esc(s)}</span>' for s in sources)}</div>
        </section>""")

    sections.append(f"""
    <section class="section">
      <p class="eyebrow">Scope</p>
      <h2>Scope &amp; authorization</h2>
      {_scope_authorization_html(scope)}
    </section>""")

    sections.append(f"""
    <section class="section">
      <p class="eyebrow">Reference</p>
      <h2>Limitations</h2>
      {_limitations_html()}
    </section>""")

    chain_blocks = []
    for i, e in enumerate(entries):
        ts = datetime.utcfromtimestamp(e["ts"]).strftime("%H:%M:%S")
        short_hash = e["entry_hash"][:8]
        chain_blocks.append(f"""
        <div class="chain-block" tabindex="0" title="entry_hash: {_esc(e['entry_hash'])}">
          <span class="chain-index">{i:02d}</span>
          <span class="chain-action">{_esc(e['module'])}.{_esc(e['action'])}</span>
          <span class="chain-time">{ts} UTC</span>
          <span class="chain-hash">{_esc(short_hash)}&hellip;</span>
        </div>""")
    chain_html = '<div class="chain-link"></div>'.join(chain_blocks) if chain_blocks else \
        '<p class="note">No audit log entries recorded yet.</p>'

    chain_status_class = "clear" if chain_valid else "flag"
    chain_status_text = "CHAIN VERIFIED" if chain_valid else "CHAIN INTEGRITY FAILED"

    doc = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Credential audit report &mdash; {_esc(scope.engagement_id)}</title>
<style>
  :root {{
    --ink: #14171F;
    --paper: #F6F7F5;
    --rule: #D8DBD6;
    --soft: #5B6169;
    --clear: #2F6E51;
    --flag: #A83B2E;
    --medium: #A6790A;
    --font-serif: 'Iowan Old Style', 'Palatino Linotype', Palatino, Georgia, Cambria, serif;
    --font-sans: Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
    --font-mono: 'IBM Plex Mono', SFMono-Regular, Consolas, 'Liberation Mono', Menlo, monospace;
  }}

  * {{ box-sizing: border-box; }}

  body {{
    margin: 0;
    background: var(--paper);
    color: var(--ink);
    font-family: var(--font-sans);
    font-size: 16px;
    line-height: 1.55;
    -webkit-print-color-adjust: exact;
    print-color-adjust: exact;
  }}

  .page {{
    max-width: 820px;
    margin: 0 auto;
    padding: 0 24px 80px;
  }}

  .cover {{
    background: var(--ink);
    color: var(--paper);
    margin: 0 -24px 48px;
    padding: 48px 24px 40px;
  }}

  .cover-top {{
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: 16px;
    flex-wrap: wrap;
  }}

  .cover-title {{
    font-family: var(--font-serif);
    font-size: 30px;
    font-weight: 600;
    letter-spacing: 0.01em;
    margin: 0 0 4px;
  }}

  .cover-id {{
    font-family: var(--font-mono);
    font-size: 13px;
    color: #A9B0BC;
    letter-spacing: 0.04em;
  }}

  .pill {{
    font-family: var(--font-mono);
    font-size: 11px;
    letter-spacing: 0.08em;
    padding: 6px 10px;
    border-radius: 3px;
    white-space: nowrap;
    border: 1px solid currentColor;
  }}
  .pill.clear {{ color: #7FD9AE; }}
  .pill.flag {{ color: #F0A090; }}

  .cover-meta {{
    margin-top: 28px;
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 14px 32px;
    font-size: 14px;
  }}

  .cover-meta dt {{
    font-family: var(--font-mono);
    font-size: 11px;
    letter-spacing: 0.08em;
    color: #8A909C;
    margin-bottom: 2px;
  }}

  .cover-meta dd {{ margin: 0; }}

  .cover-checksum {{
    margin-top: 24px;
    padding-top: 16px;
    border-top: 1px solid #2C3140;
    font-family: var(--font-mono);
    font-size: 11px;
    color: #8A909C;
    word-break: break-all;
  }}

  .eyebrow {{
    font-family: var(--font-mono);
    font-size: 11px;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    color: var(--soft);
    margin: 0 0 6px;
  }}

  .section {{
    padding: 28px 0;
    border-top: 1px solid var(--rule);
  }}

  .section h2 {{
    font-family: var(--font-serif);
    font-weight: 600;
    font-size: 21px;
    margin: 0 0 12px;
  }}

  .stat {{ font-size: 15px; margin: 0 0 6px; }}
  .stat-num {{ font-family: var(--font-mono); font-size: 22px; font-weight: 600; }}
  .stat-num.clear {{ color: var(--clear); }}
  .stat-num.flag {{ color: var(--flag); }}

  .note {{ font-size: 13px; color: var(--soft); margin: 6px 0 0; }}

  .tag-list {{ display: flex; flex-wrap: wrap; gap: 8px; }}
  .tag {{
    font-family: var(--font-mono);
    font-size: 13px;
    background: #EAECE8;
    border: 1px solid var(--rule);
    border-radius: 3px;
    padding: 4px 8px;
  }}

  .data-table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
  .data-table th {{
    text-align: left;
    font-family: var(--font-mono);
    font-size: 11px;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    color: var(--soft);
    border-bottom: 1px solid var(--rule);
    padding: 6px 8px;
  }}
  .data-table td {{
    padding: 8px;
    border-bottom: 1px solid var(--rule);
  }}
  .data-table td.mono {{ font-family: var(--font-mono); font-size: 13px; }}
  .data-table td.clear {{ color: var(--clear); font-weight: 600; }}
  .data-table td.flag {{ color: var(--flag); font-weight: 600; }}
  .data-table td.note-cell {{ font-size: 12px; color: var(--soft); }}

  .risk-badge {{
    display: inline-block;
    font-family: var(--font-mono);
    font-size: 11px;
    letter-spacing: 0.04em;
    padding: 2px 8px;
    border-radius: 3px;
    border: 1px solid currentColor;
    white-space: nowrap;
  }}
  .risk-flag {{ color: var(--flag); }}
  .risk-medium {{ color: var(--medium); }}
  .risk-clear {{ color: var(--clear); }}

  .js-intel-block {{ margin-bottom: 18px; }}
  .js-intel-block:last-child {{ margin-bottom: 0; }}

  code {{
    font-family: var(--font-mono);
    background: #EAECE8;
    padding: 1px 5px;
    border-radius: 3px;
    font-size: 0.9em;
  }}

  .chart {{ margin-top: 14px; }}
  .legend {{
    display: flex;
    flex-wrap: wrap;
    gap: 6px 16px;
    margin-top: 8px;
    font-size: 12px;
    color: var(--soft);
  }}
  .legend-item {{ display: inline-flex; align-items: center; gap: 5px; }}
  .legend-swatch {{
    width: 9px;
    height: 9px;
    border-radius: 2px;
    display: inline-block;
    flex: none;
  }}

  .chain {{
    display: flex;
    flex-wrap: wrap;
    align-items: stretch;
    gap: 0;
    margin-top: 16px;
  }}

  .chain-block {{
    display: flex;
    flex-direction: column;
    gap: 2px;
    background: #FFFFFF;
    border: 1px solid var(--rule);
    border-radius: 4px;
    padding: 10px 12px;
    min-width: 168px;
  }}

  .chain-block:focus-visible {{
    outline: 2px solid var(--ink);
    outline-offset: 2px;
  }}

  .chain-link {{
    width: 20px;
    align-self: center;
    border-top: 1px dashed var(--rule);
  }}

  .chain-index {{
    font-family: var(--font-mono);
    font-size: 10px;
    color: var(--soft);
  }}

  .chain-action {{ font-size: 13px; font-weight: 600; }}
  .chain-time {{ font-family: var(--font-mono); font-size: 11px; color: var(--soft); }}
  .chain-hash {{ font-family: var(--font-mono); font-size: 11px; color: var(--soft); }}

  .chain-status {{
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-family: var(--font-mono);
    font-size: 12px;
    letter-spacing: 0.06em;
    margin-top: 16px;
    padding: 6px 10px;
    border-radius: 3px;
    border: 1px solid currentColor;
  }}
  .chain-status.clear {{ color: var(--clear); }}
  .chain-status.flag {{ color: var(--flag); }}

  .footer {{
    margin-top: 40px;
    padding-top: 20px;
    border-top: 1px solid var(--rule);
    font-size: 12px;
    color: var(--soft);
  }}
  .footer code {{ font-size: 0.95em; }}

  @media (max-width: 560px) {{
    .cover-meta {{ grid-template-columns: 1fr; }}
  }}

  @media print {{
    body {{ background: #fff; }}
    .chain-block:focus-visible {{ outline: none; }}
  }}

  @media (prefers-reduced-motion: reduce) {{
    * {{ transition: none !important; }}
  }}
</style>
</head>
<body>
<div class="page">

  <header class="cover">
    <div class="cover-top">
      <div>
        <p class="cover-title">Credential audit report</p>
        <p class="cover-id">{_esc(scope.engagement_id)}</p>
      </div>
      <span class="pill {chain_status_class}">{chain_status_text}</span>
    </div>

    <dl class="cover-meta">
      <div><dt>Client</dt><dd>{_esc(scope.client_name)}</dd></div>
      <div><dt>Authorized by</dt><dd>{_esc(scope.authorized_by)}</dd></div>
      <div><dt>Engagement window</dt><dd>{_esc(scope.start_date)} &ndash; {_esc(scope.end_date)}</dd></div>
      <div><dt>Generated</dt><dd>{datetime.utcnow().strftime('%Y-%m-%d %H:%M')} UTC</dd></div>
    </dl>

    <p class="cover-checksum">scope file sha256 &nbsp;{_esc(scope.source_sha256)}</p>
  </header>

  {exec_summary_html}

  <section class="section" style="border-top:none; padding-top:0;">
    <p class="eyebrow">Authorization</p>
    <h2>Targets in scope</h2>
    <div class="tag-list">{targets_html}</div>
  </section>

  {''.join(sections)}

  <section class="section">
    <p class="eyebrow">Chain of custody</p>
    <h2>Audit trail</h2>
    <div class="chain">{chain_html}</div>
    <span class="chain-status {chain_status_class}">&#9679; {chain_status_text}</span>
    <p class="note">Each entry embeds the hash of the one before it. Recompute
      independently with <code>python -m credaudit.cli verify --log audit_log.jsonl</code>.</p>
  </section>

  <footer class="footer">
    Generated by credaudit. This report references the scope file by checksum
    rather than embedding it, so scope changes after generation are detectable.
  </footer>

</div>
</body>
</html>"""

    html_path.write_text(doc)
    return html_path
