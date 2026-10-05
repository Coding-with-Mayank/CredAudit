"""Bridges the existing recon rule engine (`credaudit.modules.risk_engine`,
which scores a nuclei-style finding against a service/indicator rule
table) into the unified evidence model, so recon findings sit in the
same Evidence/risk-score/correlation pipeline as credential and secret
findings instead of being a separate, disconnected code path.

The rule-based service/indicator matching itself is unchanged and lives
in `modules/risk_engine.py` -- this module's job is strictly the
conversion into `core.evidence.Evidence`, using the platform-wide
multi-factor risk engine (`core.risk`) for the final score, rather than
inventing a second scoring scheme here.
"""
from __future__ import annotations

from ..core import evidence as ev
from ..core import risk as risk_engine

# Indicators (from modules/risk_engine.py's INDICATOR_SEVERITY table)
# that represent an immediately-usable weakness rather than a
# theoretical one -- used to set the exploitability factor.
EXPLOITABLE_INDICATORS = {"default_creds", "secrets_exposed", "null_session", "legacy_protocol", "anonymous_access"}

_REMEDIATION_HINTS = {
    "default_creds": "Change default credentials immediately.",
    "old_version": "Patch/upgrade the service to a supported version.",
    "weak_crypto": "Disable weak ciphers/protocol versions.",
    "anonymous_access": "Disable anonymous/unauthenticated access.",
    "null_session": "Disable null-session access.",
    "secrets_exposed": "Remove the exposed secrets/config and rotate any credentials they contained.",
    "debug_exposed": "Disable debug mode / verbose error output in production.",
    "nla_disabled": "Enable Network Level Authentication (NLA) for RDP.",
    "legacy_protocol": "Disable legacy protocol versions (e.g. SMBv1, SSLv2/3, TLS 1.0/1.1).",
    "password_auth_enabled": "Prefer key-based authentication (and/or MFA) over password auth where possible.",
}


def _remediation_for(assessment) -> str:
    hints = [_REMEDIATION_HINTS[i] for i in assessment.indicators if i in _REMEDIATION_HINTS]
    return " ".join(hints) or "Review the finding and apply vendor-recommended hardening."


def assessment_to_evidence(
    assessment,
    engagement_id: str,
    internet_facing: bool = True,
    service_criticality: float = 0.5,
    confidence: float = 0.75,
) -> ev.Evidence:
    """assessment: a `modules.risk_engine.RiskAssessment` (from
    `assess_finding`/`assess_service`/`assess_all`)."""
    exploitable = bool(set(assessment.indicators) & EXPLOITABLE_INDICATORS)
    risk = risk_engine.score_service_finding(
        risk_level=assessment.risk_level,
        internet_facing=internet_facing,
        confidence=confidence,
        service_criticality=service_criticality,
        exploitable_indicator=exploitable,
    )
    indicator_text = ", ".join(assessment.indicators) if assessment.indicators else "none"
    return ev.Evidence(
        finding_id=ev.next_finding_id(engagement_id),
        engagement_id=engagement_id,
        asset=assessment.target,
        category="Network/Service Exposure",
        severity=risk.severity,
        risk_score=risk.score,
        confidence=confidence,
        source="recon (nuclei)",
        evidence=f"{assessment.service.upper()} \u2014 {assessment.reasoning} (indicators: {indicator_text})",
        remediation=_remediation_for(assessment),
        status="detected",
        factors={c.name: c.value for c in risk.factors},
        extra={
            "service": assessment.service,
            "indicators": assessment.indicators,
            "source_template": assessment.source_template,
            "legacy_risk_level": assessment.risk_level,
        },
    )


def assessments_to_evidence(assessments: list, engagement_id: str, **kwargs) -> list:
    return [assessment_to_evidence(a, engagement_id, **kwargs) for a in assessments]
