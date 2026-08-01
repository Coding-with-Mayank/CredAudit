"""Recon module: maps which services are actually live before any
credential testing touches them. Wraps an external scanner (nuclei by
default; point scanner_bin at scan4all or another tool you already have
installed) rather than reimplementing service discovery.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from ..scope import Scope


class ReconError(Exception):
    pass


# Nuclei template-id keywords that typically indicate an authentication
# surface worth considering for the online module. Best-effort mapping,
# not exhaustive -- always sanity-check suggestions against the real
# service before spraying it.
AUTH_KEYWORDS = {
    "ssh": "ssh", "ftp": "ftp", "rdp": "rdp", "telnet": "telnet",
    "mysql": "mysql", "postgres": "postgresql", "mssql": "mssql",
    "smb": "smb", "vnc": "vnc", "http-login": "http-post-form",
    "basic-auth": "http-get",
}


def suggest_online_targets(findings: list) -> list:
    """Turn raw recon findings into a deduplicated list of
    {"target": ..., "protocol": ..., "source_template": ...} suggestions
    for the online module, so you're not hand-typing hosts and protocols
    after every recon run. Still requires a human to review and actually
    invoke the online module -- this only removes the busywork."""
    suggestions = []
    seen = set()

    for finding in findings:
        template_id = str(finding.get("template-id") or finding.get("template", "")).lower()
        host = finding.get("host") or finding.get("ip") or finding.get("target")
        if not host:
            continue

        for keyword, protocol in AUTH_KEYWORDS.items():
            if keyword in template_id:
                key = (host, protocol)
                if key not in seen:
                    seen.add(key)
                    suggestions.append({
                        "target": host, "protocol": protocol, "source_template": template_id,
                    })
                break

    return suggestions


def suggest_online_targets_with_risk(findings: list) -> list:
    """Same idea as suggest_online_targets, but consults the risk engine
    first and only surfaces a suggestion where there's an actual reason
    to prioritize it -- e.g. an old, password-auth-enabled SSH service
    ranks above a generic SSH banner. Sorted by risk, highest first.

    This is a richer *suggestion* list, nothing more: the decision to
    run --modules online against any of these, and typing the
    confirmation, is still entirely a human action. Nothing here calls
    the online module.
    """
    from . import risk_engine

    base_suggestions = suggest_online_targets(findings)
    assessments_by_target = {}
    for finding in findings:
        assessment = risk_engine.assess_finding(finding)
        if assessment is not None:
            existing = assessments_by_target.get(assessment.target)
            if existing is None or risk_engine.RISK_ORDER.index(assessment.risk_level) > \
                    risk_engine.RISK_ORDER.index(existing.risk_level):
                assessments_by_target[assessment.target] = assessment

    enriched = []
    for suggestion in base_suggestions:
        assessment = assessments_by_target.get(suggestion["target"])
        enriched.append({
            **suggestion,
            "risk_level": assessment.risk_level if assessment else "Info",
            "reasoning": assessment.reasoning if assessment else "No specific risk indicators observed.",
        })

    enriched.sort(
        key=lambda s: risk_engine.RISK_ORDER.index(s["risk_level"]), reverse=True,
    )
    return enriched


def run_recon(scope: Scope, out_dir: Path, scanner_bin: str = "nuclei") -> list:
    scope.check_module("recon")

    if shutil.which(scanner_bin) is None:
        raise ReconError(
            f"'{scanner_bin}' not found on PATH. Install it separately, e.g. "
            f"https://github.com/projectdiscovery/nuclei (or point scanner_bin "
            f"at scan4all / another scanner you already have installed)."
        )

    for target in scope.targets:
        scope.check_target(target.split("/")[0])  # strip CIDR suffix for the check

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / "recon.jsonl"

    cmd = [scanner_bin, "-silent", "-jsonl", "-o", str(out_file)]
    for target in scope.targets:
        cmd += ["-target", target]

    subprocess.run(cmd, check=True, timeout=3600)

    findings = []
    if out_file.exists():
        with out_file.open() as f:
            for line in f:
                if line.strip():
                    findings.append(json.loads(line))
    return findings
