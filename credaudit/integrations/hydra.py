"""Hydra/Medusa/ncrack integration.

`modules/online.py` already owns invoking the chosen backend itself
(scope check, interactive confirmation, lockout-safe pacing, subprocess,
audit logging). This module's job is turning its *summary* -- never the
raw valid-pair log, which stays local on disk exactly as the tool wrote
it -- into unified Evidence.

This is the one integration that can produce a "confirmed" (rather than
"detected"/"suspected") finding: a valid credential pair actually found
by live testing is directly observed evidence, not an inference from a
pattern.
"""
from __future__ import annotations

from ..core import evidence as ev

_CONFIRMED_REMEDIATION = (
    "Reset the affected account's password immediately, review logs for unauthorized "
    "use during the exposure window, and consider MFA / an account lockout policy for this service."
)


def online_summary_to_evidence(
    summary,
    engagement_id: str,
    target: str,
    protocol: str = "",
    backend: str = "",
) -> list:
    """summary: a `modules.online.OnlineTestSummary`. Returns [] when no
    valid pair was found -- "we tested and found nothing" is not itself
    a finding worth reporting as evidence."""
    if summary.valid_pairs_found <= 0:
        return []

    protocol_label = protocol or "the tested service"
    backend_label = backend or "hydra/medusa/ncrack"
    evidence_text = (
        f"Live credential testing ({backend_label}) against {protocol_label} on '{target}' "
        f"identified {summary.valid_pairs_found} valid account/password pair(s) out of "
        f"{summary.accounts_tested} account(s) tested. Raw credentials are intentionally not "
        f"included here -- see {summary.log_path.name} in this engagement's output directory, "
        "handled per your data-handling policy."
    )
    return [
        ev.Evidence(
            finding_id=ev.next_finding_id(engagement_id),
            engagement_id=engagement_id,
            asset=target,
            category="Credential Exposure",
            severity="Critical",
            risk_score=95,
            confidence=1.0,
            source=f"online ({backend})" if backend else "online",
            evidence=evidence_text,
            remediation=_CONFIRMED_REMEDIATION,
            status="confirmed",
            factors={"asset_exposure": 1.0, "exploitability": 1.0, "credential_weakness": 1.0},
            extra={"protocol": protocol, "backend": backend, "log_path": str(summary.log_path)},
        )
    ]


def online_summaries_to_evidence(summaries: list, engagement_id: str) -> list:
    """Convenience batch form. Prefer calling `online_summary_to_evidence`
    directly with the target/protocol/backend you already have in hand
    from the CLI's own loop -- this fallback recovers them from the log
    filename (`online_<backend>_<target>.log`) on a best-effort basis
    for callers (e.g. re-processing saved summaries) that don't have
    that context anymore."""
    out = []
    for s in summaries:
        backend, target, protocol = _parse_log_stem(s.log_path.stem)
        out.extend(online_summary_to_evidence(s, engagement_id, target=target, protocol=protocol, backend=backend))
    return out


def _parse_log_stem(stem: str) -> tuple:
    # "online_<backend>_<target...>" -- target itself may contain
    # underscores (online.py replaces "/" with "_" for CIDR targets),
    # so only the first two underscore-separated fields are structural.
    parts = stem.split("_", 2)
    if len(parts) == 3 and parts[0] == "online":
        return parts[1], parts[2], ""
    return "", stem, ""
