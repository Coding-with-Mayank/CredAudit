"""nuclei (or scan4all) integration.

`modules/recon.py` already owns invoking the scanner itself (scope
checks, subprocess, timeout, parsing the JSONL it writes). This module's
job is strictly turning that already-collected raw output -- plus the
existing rule-based risk assessments `modules/risk_engine.py` derives
from it -- into unified Evidence, via `analyzers.vulnerabilities`.
"""
from __future__ import annotations

from ..analyzers import vulnerabilities as vuln_analyzer
from ..modules import risk_engine as legacy_risk_engine


def recon_findings_to_evidence(
    recon_findings: list,
    engagement_id: str,
    internet_facing: bool = True,
    service_criticality: float = 0.5,
) -> list:
    """Run the existing recon rule engine over raw nuclei-style findings
    and convert every resulting assessment into Evidence. Findings that
    don't map to a known service (see modules/risk_engine.SERVICE_PROFILES)
    are dropped by assess_all, same as before -- this does not force an
    assessment onto a finding that doesn't fit the rule table."""
    assessments = legacy_risk_engine.assess_all(recon_findings)
    return vuln_analyzer.assessments_to_evidence(
        assessments, engagement_id, internet_facing=internet_facing, service_criticality=service_criticality,
    )
