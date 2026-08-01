"""Risk engine: turns a raw finding into an interpreted risk assessment
-- service, indicators observed, risk level, and *why* -- instead of
just passing "SSH found" through untouched. This is pure interpretation
of evidence you already have (or manually observed, e.g. from a banner
grab you read yourself). It never decides to test or exploit anything;
it just tells you how worried to be and why.
"""
from __future__ import annotations

from dataclasses import dataclass

RISK_ORDER = ["Info", "Low", "Medium", "High", "Critical"]

INDICATOR_SEVERITY = {
    "old_version": "High",
    "weak_crypto": "High",
    "default_creds": "Critical",
    "anonymous_access": "High",
    "debug_exposed": "Medium",
    "secrets_exposed": "Critical",
    "password_auth_enabled": "Medium",
    "legacy_protocol": "Critical",
    "nla_disabled": "High",
    "null_session": "High",
}

INDICATOR_DESCRIPTIONS = {
    "old_version": "Outdated software version detected",
    "weak_crypto": "Weak cipher/algorithm in use",
    "default_creds": "Default credentials may be in use",
    "anonymous_access": "Anonymous/unauthenticated access allowed",
    "debug_exposed": "Debug mode or verbose errors exposed",
    "secrets_exposed": "Secrets or sensitive files exposed",
    "password_auth_enabled": "Password authentication enabled",
    "legacy_protocol": "Legacy/deprecated protocol version enabled",
    "nla_disabled": "Network Level Authentication disabled",
    "null_session": "Null session access allowed",
}

SERVICE_PROFILES = {
    "ssh": {
        "applicable": ["old_version", "weak_crypto", "default_creds", "password_auth_enabled"],
        "default_reasoning": "SSH is a common brute-force and credential-stuffing target.",
    },
    "ftp": {
        "applicable": ["anonymous_access", "old_version", "default_creds"],
        "default_reasoning": "Unauthenticated or outdated FTP servers are common initial-access points.",
    },
    "rdp": {
        "applicable": ["nla_disabled", "old_version", "default_creds"],
        "default_reasoning": "RDP is a frequent brute-force target and has a history of critical RCE flaws.",
    },
    "smb": {
        "applicable": ["legacy_protocol", "null_session", "default_creds"],
        "default_reasoning": "SMB misconfigurations are a common lateral-movement and RCE vector.",
    },
    "http": {
        "applicable": ["secrets_exposed", "debug_exposed", "default_creds"],
        "default_reasoning": "Web misconfigurations often expose source code, secrets, or internal details.",
    },
    "telnet": {
        "applicable": ["legacy_protocol", "default_creds"],
        "default_reasoning": "Telnet transmits credentials in cleartext and is largely obsolete.",
    },
    "mysql": {
        "applicable": ["default_creds", "anonymous_access", "old_version"],
        "default_reasoning": "Exposed database services are a direct path to data exposure if credentials are weak.",
    },
}

# Best-effort keyword hints for auto-detecting indicators from a nuclei
# template-id or tag string. Not exhaustive -- a human reviewing the raw
# finding is still the authority, this just surfaces likely candidates.
TEMPLATE_INDICATOR_HINTS = {
    "old-version": "old_version", "outdated": "old_version", "eol": "old_version",
    "weak-cipher": "weak_crypto", "weak-ssl": "weak_crypto", "sweet32": "weak_crypto",
    "default-login": "default_creds", "default-password": "default_creds", "default-creds": "default_creds",
    "anonymous": "anonymous_access",
    "debug": "debug_exposed", "verbose-error": "debug_exposed", "stack-trace": "debug_exposed",
    "exposed-panel": "secrets_exposed", "git-config": "secrets_exposed",
    "env-exposure": "secrets_exposed", "exposed-env": "secrets_exposed", "git-exposure": "secrets_exposed",
    "smbv1": "legacy_protocol", "sslv2": "legacy_protocol", "sslv3": "legacy_protocol", "tlsv1": "legacy_protocol",
    "null-session": "null_session",
    "nla": "nla_disabled",
}


@dataclass
class RiskAssessment:
    target: str
    service: str
    indicators: list
    risk_level: str
    reasoning: str
    source_template: str = ""


def _max_severity(levels: list) -> str:
    if not levels:
        return "Info"
    return max(levels, key=lambda lvl: RISK_ORDER.index(lvl) if lvl in RISK_ORDER else 0)


def assess_service(target: str, service: str, indicators: list) -> RiskAssessment:
    """Build a risk assessment from indicators you already know are true
    -- e.g. you read the SSH banner yourself and saw an old version with
    password auth enabled. This is the manual-entry path: you supply the
    facts, this just does the consistent scoring and phrasing."""
    profile = SERVICE_PROFILES.get(service, {})
    known = [i for i in indicators if i in INDICATOR_SEVERITY]

    severities = [INDICATOR_SEVERITY[i] for i in known]
    risk_level = _max_severity(severities) if severities else "Info"

    descriptions = [INDICATOR_DESCRIPTIONS[i] for i in known]
    reasoning_parts = descriptions[:]
    default_reasoning = profile.get("default_reasoning")
    if default_reasoning:
        reasoning_parts.append(default_reasoning)
    reasoning = "; ".join(reasoning_parts) if reasoning_parts else "No specific risk indicators observed."

    return RiskAssessment(
        target=target, service=service, indicators=known,
        risk_level=risk_level, reasoning=reasoning,
    )


def assess_finding(finding: dict) -> RiskAssessment | None:
    """Best-effort automatic assessment from a nuclei-style finding dict.
    Returns None if the finding doesn't map to a known service -- not
    every recon result is worth a risk assessment, and this doesn't
    force one."""
    template_id = str(finding.get("template-id") or finding.get("template", "")).lower()
    host = finding.get("host") or finding.get("ip") or finding.get("target")
    if not host or not template_id:
        return None

    service = None
    for svc in SERVICE_PROFILES:
        if svc in template_id:
            service = svc
            break
    if service is None:
        return None

    applicable = set(SERVICE_PROFILES[service]["applicable"])
    indicators = []
    for hint, indicator in TEMPLATE_INDICATOR_HINTS.items():
        if hint in template_id and indicator in applicable:
            indicators.append(indicator)

    assessment = assess_service(str(host), service, indicators)
    assessment.source_template = template_id
    return assessment


def assess_all(findings: list) -> list:
    """Run assess_finding across a batch, dropping anything that didn't
    map to a known service."""
    results = []
    for finding in findings:
        assessment = assess_finding(finding)
        if assessment is not None:
            results.append(assessment)
    return results
