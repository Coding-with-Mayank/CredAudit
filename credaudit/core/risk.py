"""Explainable, multi-factor risk engine.

Every risk score CredAudit produces is the weighted sum of a small,
fixed set of named factors, each normalized to 0.0-1.0. There is no
hidden fudge factor and no per-finding special-casing: the same factor
table and the same weights apply to a credential finding, a secret
finding, and a service-exposure finding alike, so two findings backed by
the same underlying facts always get the same score.

Weight rationale (weights sum to 1.0):
    asset_exposure (0.20)         An internal-only weakness and an
                                   internet-facing one are not the same
                                   risk, even with identical technical
                                   severity -- this is the single
                                   biggest lever on "how likely is this
                                   to actually be reached".
    privilege_level (0.18)        Blast radius if the finding is
                                   abused. A weak password on a
                                   low-privilege test account is not
                                   the same event as one on a domain
                                   admin account.
    exploitability (0.15)         How directly usable the finding is
                                   *today*, without further chaining
                                   (a default credential is
                                   immediately exploitable; a
                                   theoretical weak-cipher exposure
                                   less so).
    credential_weakness (0.12)    Intrinsic weakness of the credential
                                   itself (length/complexity/common
                                   password).
    breach_exposure (0.10)        Whether the exact credential/secret
                                   is already known to be public.
    vulnerability_severity (0.10) Underlying CVE/misconfiguration
                                   severity, when applicable (recon
                                   findings).
    password_reuse (0.08)         Same credential used elsewhere
                                   multiplies the blast radius of a
                                   single leak.
    service_criticality (0.05)    Business/asset importance -- kept as
                                   the smallest weight deliberately:
                                   it's usually a judgment call supplied
                                   by the person running the
                                   engagement, not something CredAudit
                                   observes directly, so it nudges the
                                   score rather than dominating it.
    secret_type_sensitivity (0.02) Small tie-breaker between e.g. a
                                   cloud admin key and a low-scope
                                   token when everything else is equal.

These weights are a judgment call, not a physical law -- see
`docs/risk_model.md` for the full reasoning and how to tune them for an
engagement with a different risk appetite. What is *not* a judgment
call: given a fixed set of factor values and a fixed confidence, the
score this module returns is 100% reproducible and its breakdown is
always shown alongside it (`RiskResult.factors` / `.explanation`).
"""
from __future__ import annotations

from dataclasses import dataclass, field

RISK_ORDER = ["Info", "Low", "Medium", "High", "Critical"]

FACTOR_WEIGHTS = {
    "asset_exposure": 0.20,
    "privilege_level": 0.18,
    "exploitability": 0.15,
    "credential_weakness": 0.12,
    "breach_exposure": 0.10,
    "vulnerability_severity": 0.10,
    "password_reuse": 0.08,
    "service_criticality": 0.05,
    "secret_type_sensitivity": 0.02,
}

_weight_total = sum(FACTOR_WEIGHTS.values())
if abs(_weight_total - 1.0) > 1e-9:
    raise AssertionError(f"FACTOR_WEIGHTS must sum to 1.0, got {_weight_total}")

FACTOR_DESCRIPTIONS = {
    "asset_exposure": "Asset is internet-facing / externally reachable",
    "privilege_level": "Associated account or access has elevated privilege",
    "exploitability": "Weakness is directly usable without further work",
    "credential_weakness": "Credential is short, common, or low-complexity",
    "breach_exposure": "Credential/secret has appeared in a known public breach",
    "vulnerability_severity": "Underlying vulnerability/misconfiguration severity",
    "password_reuse": "Same credential reused across multiple accounts/assets",
    "service_criticality": "Business/asset importance of the affected service",
    "secret_type_sensitivity": "Sensitivity of this specific secret type",
}

# Score -> severity band. Checked top-down; a score of exactly 80 is
# Critical, exactly 60 is High, etc.
SEVERITY_THRESHOLDS = [
    (80, "Critical"),
    (60, "High"),
    (40, "Medium"),
    (20, "Low"),
    (0, "Info"),
]

# Base "sensitivity" of a secret type -- used by score_secret_finding for
# both secret_type_sensitivity and part of exploitability. Documented
# here (not just in analyzers/secrets.py) because it's a risk-model
# input, not just a detection concern.
SECRET_TYPE_SENSITIVITY = {
    "private_key": 1.0,
    "aws_secret_key": 1.0,
    "azure_connection_string": 1.0,
    "stripe_api_key": 0.95,  # a Stripe secret key alone authorizes charges/refunds/payouts
    "database_connection_string": 0.95,
    "aws_access_key": 0.9,
    "github_token": 0.75,
    "gcp_api_key": 0.75,
    "sendgrid_api_key": 0.6,  # alone sufficient to send mail as the account, but not financial/infra access
    "slack_token": 0.65,
    "jwt": 0.5,
    "bearer_token": 0.45,
    "generic_api_key": 0.45,
    "generic_secret": 0.35,
}


class RiskEngineError(Exception):
    pass


@dataclass
class RiskFactorContribution:
    name: str
    weight: float
    value: float  # normalized 0.0-1.0 input actually used
    contribution: float  # points out of 100 this factor added
    description: str


@dataclass
class RiskResult:
    score: int
    severity: str
    confidence: float
    factors: list = field(default_factory=list)  # list[RiskFactorContribution]
    explanation: str = ""
    remediation: str = ""


def severity_for_score(value: float) -> str:
    for threshold, label in SEVERITY_THRESHOLDS:
        if value >= threshold:
            return label
    return "Info"  # pragma: no cover -- unreachable, SEVERITY_THRESHOLDS floors at 0


def score(
    factor_values: dict,
    confidence: float = 1.0,
    remediation: str = "",
    include_zero_factors: bool = False,
) -> RiskResult:
    """Compute a RiskResult from a mapping of factor name -> 0.0-1.0.

    Any factor not present in `factor_values` is treated as not
    applicable / not observed (0.0) -- this function never guesses a
    value you didn't supply, and never applies a factor that isn't in
    FACTOR_WEIGHTS (that raises immediately, so a typo'd factor name
    fails loudly instead of silently contributing nothing).
    """
    unknown = set(factor_values) - set(FACTOR_WEIGHTS)
    if unknown:
        raise RiskEngineError(
            f"Unknown risk factor(s): {sorted(unknown)}. Known factors: {sorted(FACTOR_WEIGHTS)}"
        )
    if not (0.0 <= confidence <= 1.0):
        raise RiskEngineError(f"confidence must be 0.0-1.0, got {confidence!r}")

    contributions = []
    raw_total = 0.0
    for name, weight in FACTOR_WEIGHTS.items():
        value = max(0.0, min(1.0, float(factor_values.get(name, 0.0))))
        contribution = weight * value * 100
        raw_total += contribution
        if value > 0 or include_zero_factors:
            contributions.append(
                RiskFactorContribution(
                    name=name,
                    weight=weight,
                    value=value,
                    contribution=round(contribution, 1),
                    description=FACTOR_DESCRIPTIONS[name],
                )
            )

    final_score = max(0, min(100, round(raw_total * confidence)))
    severity = severity_for_score(final_score)
    contributions.sort(key=lambda c: c.contribution, reverse=True)

    if contributions:
        explanation = "; ".join(
            f"{c.description} (+{c.contribution:.0f} pts)" for c in contributions
        )
    else:
        explanation = "No risk-contributing factors observed."
    if confidence < 1.0:
        explanation += f" Score discounted for evidence confidence ({confidence:.0%})."

    return RiskResult(
        score=final_score,
        severity=severity,
        confidence=confidence,
        factors=contributions,
        explanation=explanation,
        remediation=remediation,
    )


# ---------------------------------------------------------------------------
# Convenience scorers for the finding shapes CredAudit actually produces.
# Each of these is a thin, documented mapping from booleans/labels people
# actually have on hand to the normalized factor_values `score()` expects
# -- nothing here invents a number that isn't traceable to an input.
# ---------------------------------------------------------------------------

def score_credential_finding(
    *,
    weak: bool,
    reused: bool,
    breached: bool,
    privileged: bool,
    internet_facing: bool,
    default_credential: bool = False,
    confidence: float = 1.0,
    service_criticality: float = 0.5,
    weakness_score: float = None,
) -> RiskResult:
    """`weakness_score`: optional continuous 0.0-1.0 override for the
    `credential_weakness`/`exploitability` factors, e.g. derived from
    `analyzers.password_strength.estimate_strength()`'s zxcvbn-based
    guess model instead of the binary Weak/Medium/Strong classification.
    Omitted (the default, `None`) reproduces the original binary
    behavior exactly -- existing callers and their exact risk scores are
    unaffected unless they explicitly opt in to passing this.
    """
    if weakness_score is not None:
        credential_weakness = max(weakness_score, 1.0 if default_credential else 0.0)
        exploitability = (
            1.0 if default_credential else
            (credential_weakness if internet_facing else credential_weakness * 0.6)
        )
    else:
        credential_weakness = 1.0 if (weak or default_credential) else 0.0
        exploitability = (
            1.0 if default_credential else
            (1.0 if (weak and internet_facing) else (0.5 if weak else 0.0))
        )
    factor_values = {
        "credential_weakness": credential_weakness,
        "password_reuse": 1.0 if reused else 0.0,
        "breach_exposure": 1.0 if breached else 0.0,
        "privilege_level": 1.0 if privileged else 0.0,
        "asset_exposure": 1.0 if internet_facing else 0.3,
        "exploitability": exploitability,
        "service_criticality": service_criticality,
    }
    remediation = _credential_remediation(
        weak=weak, reused=reused, breached=breached,
        privileged=privileged, default_credential=default_credential,
    )
    return score(factor_values, confidence=confidence, remediation=remediation)


def _credential_remediation(*, weak, reused, breached, privileged, default_credential) -> str:
    hints = []
    if default_credential:
        hints.append("Change this default credential immediately.")
    elif weak:
        hints.append("Rotate to a longer, non-dictionary password (12+ characters, no common patterns).")
    if reused:
        hints.append("This password is reused elsewhere -- rotate all accounts sharing it, not just this one.")
    if breached:
        hints.append("This credential appears in a known public breach; treat it as compromised and rotate it.")
    if privileged:
        hints.append("This is a privileged account -- prioritize remediation and consider requiring MFA.")
    return " ".join(hints) or "No specific remediation indicated beyond standard password hygiene."


def score_secret_finding(
    *,
    secret_type: str,
    confidence: float,
    remediation: str = "",
    internet_facing: bool = True,
    service_criticality: float = 0.5,
) -> RiskResult:
    sensitivity = SECRET_TYPE_SENSITIVITY.get(secret_type, 0.4)
    # Types where possessing the secret alone is sufficient to authenticate
    # get full privilege credit. Everything else (e.g. an AWS *access key
    # ID*, which needs its paired secret key to do anything) gets partial,
    # sensitivity-scaled credit -- enough that a highly sensitive token
    # (a broad-scope GitHub/Slack token, say) isn't artificially capped at
    # the same score as a low-value one, without claiming the same
    # certainty as a secret that's independently sufficient to log in.
    high_privilege_types = {
        "private_key", "aws_secret_key", "azure_connection_string", "database_connection_string",
        "stripe_api_key",
    }
    privilege_level = sensitivity if secret_type in high_privilege_types else sensitivity * 0.5
    factor_values = {
        "secret_type_sensitivity": sensitivity,
        "exploitability": sensitivity,
        "asset_exposure": 1.0 if internet_facing else 0.4,
        "privilege_level": privilege_level,
        "service_criticality": service_criticality,
    }
    return score(factor_values, confidence=confidence, remediation=remediation)


def score_service_finding(
    *,
    risk_level: str,
    internet_facing: bool = True,
    confidence: float = 0.75,
    service_criticality: float = 0.5,
    exploitable_indicator: bool = False,
) -> RiskResult:
    severity_value = {"Critical": 1.0, "High": 0.75, "Medium": 0.5, "Low": 0.25, "Info": 0.0}.get(
        risk_level, 0.0
    )
    factor_values = {
        "vulnerability_severity": severity_value,
        "asset_exposure": 1.0 if internet_facing else 0.3,
        "exploitability": 0.8 if exploitable_indicator else severity_value * 0.6,
        "service_criticality": service_criticality,
    }
    return score(factor_values, confidence=confidence, remediation="")
