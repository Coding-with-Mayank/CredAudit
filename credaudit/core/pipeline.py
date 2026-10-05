"""Wires analyzers, integrations, correlation, and attack-path building
into one pipeline. Kept separate from `cli.py` so the whole "evidence ->
correlation -> attack path" flow is unit-testable without going through
argparse, and so anything else embedding credaudit (a notebook, a
different frontend) can call it directly.

This module does not invoke any external tool itself and does not touch
scope/authorization at all -- it strictly consumes already-collected
results (recon findings, risk assessments, credential records, secret
scan targets, online summaries) and turns them into the unified
evidence/correlation/attack-path output the reporting layer renders.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ..analyzers import credentials as credential_analyzer
from ..analyzers import secrets as secrets_analyzer
from ..analyzers import vulnerabilities as vuln_analyzer
from ..integrations import hydra as hydra_integration
from . import correlation as correlation_engine
from . import evidence as ev
from ..attack_paths import graph as attack_path_builder
from ..attack_paths import verification as path_verification


@dataclass
class PipelineResult:
    evidence: list = field(default_factory=list)
    correlations: list = field(default_factory=list)
    attack_paths: list = field(default_factory=list)
    credential_findings: list = field(default_factory=list)
    secret_findings: list = field(default_factory=list)
    live_validation_summary: dict = None  # {"verified_active": n, "verified_inactive": n, "unknown": n}, set only when validate_secrets=True


def _js_intel_secret_to_finding(secret, source: str):
    kind = secrets_analyzer.JS_INTEL_KIND_ALIASES.get(secret.kind, secret.kind)
    spec = secrets_analyzer.SECRET_TYPES.get(kind, {})
    return secrets_analyzer.SecretFinding(
        secret_type=kind,
        value=secret.value,
        source=source,
        line_number=None,
        severity=spec.get("severity", "Medium"),
        confidence=spec.get("confidence", 0.5),
        remediation=spec.get("remediation", "Confirm this is a live secret and rotate it if so."),
    )


def run_pipeline(
    scope,
    recon_findings: list = None,
    risk_assessments: list = None,
    offline_result=None,
    credential_records: list = None,
    breach_checker=None,
    secret_scan_paths: list = None,
    js_intel_results: list = None,
    online_summaries: list = None,
    internet_facing_default: bool = True,
    reset_ids: bool = True,
    validate_secrets: bool = False,
    live_validation_max_checks: int = 25,
) -> PipelineResult:
    """Run every analyzer/integration that has input available, then
    correlate and build attack paths across all of it.

    Every argument is optional -- pass whatever this engagement actually
    collected. `scope` is used only for `engagement_id`.

    `validate_secrets`, when True, makes a single opt-in pass of
    read-only, provider-side live validation (see
    `credaudit.validators`) across every secret found via
    `secret_scan_paths`/`js_intel_results` combined, before turning them
    into Evidence -- so a secret found by both sources is only ever
    checked once. Off by default: this performs real outbound network
    calls to third-party providers (GitHub, Slack, Stripe, SendGrid,
    Google, AWS) using the discovered secret values themselves, which
    callers should only enable with the same explicit, informed opt-in
    the CLI requires for `--validate-secrets` (see docs/secret_validation.md).
    """
    if reset_ids:
        ev.reset_finding_id_counter()

    engagement_id = scope.engagement_id
    result = PipelineResult()

    if risk_assessments:
        result.evidence.extend(
            vuln_analyzer.assessments_to_evidence(
                risk_assessments, engagement_id, internet_facing=internet_facing_default,
            )
        )

    if credential_records:
        asset_label = offline_result.out_file.parent.name if offline_result else "credential-analysis"
        findings = credential_analyzer.analyze_credentials(
            credential_records, breach_checker=breach_checker, internet_facing=internet_facing_default,
        )
        result.credential_findings = findings
        result.evidence.extend(
            credential_analyzer.findings_to_evidence(findings, engagement_id, asset=asset_label)
        )

    secret_scan_items = []  # list[(findings, asset, source_module)]
    all_secret_findings = []
    for path in secret_scan_paths or []:
        p = Path(path)
        findings = secrets_analyzer.scan_directory(p) if p.is_dir() else secrets_analyzer.scan_file(p)
        secret_scan_items.append((findings, str(path), "secret_analysis"))
        all_secret_findings.extend(findings)

    for r in js_intel_results or []:
        source_label = r.source or "js_intel"
        js_findings = [_js_intel_secret_to_finding(s, source_label) for s in r.secrets]
        secret_scan_items.append((js_findings, source_label, "js_intel"))
        all_secret_findings.extend(js_findings)

    live_results = None
    if validate_secrets and all_secret_findings:
        from .. import validators

        live_results = validators.validate_findings(all_secret_findings, max_checks=live_validation_max_checks)
        result.live_validation_summary = validators.summarize(live_results)

    for findings, asset, source_module in secret_scan_items:
        result.secret_findings.extend(findings)
        result.evidence.extend(
            secrets_analyzer.to_evidence(
                findings, engagement_id, asset=asset, source_module=source_module, live_results=live_results,
            )
        )

    if online_summaries:
        result.evidence.extend(
            hydra_integration.online_summaries_to_evidence(online_summaries, engagement_id)
        )

    result.correlations = correlation_engine.correlate(result.evidence)
    result.attack_paths = attack_path_builder.build_attack_paths(result.evidence, result.correlations)

    verifications = path_verification.verify_paths(result.attack_paths, result.evidence)
    for path in result.attack_paths:
        path.verification = verifications.get(path.path_id)

    return result
