"""Native credential intelligence.

Analyzes credential material an engagement already has lawful
possession of -- an exported/cracked hash dump, or a manually supplied
account/password list -- and turns it into structured, explainable
findings: weak passwords, reuse, default credentials, breach exposure,
privileged accounts using weak credentials. This is analysis CredAudit
does itself; it goes beyond "call Hashcat and report the count".

Plaintext handling rule, followed throughout this module: a plaintext
password is only ever held in memory for the duration of a single
`analyze_credentials()` call. It is hashed immediately for
reuse/dictionary comparison, and every output object (`CredentialFinding`)
carries only a redacted/hashed representation -- never the plaintext
itself. Callers are responsible for not logging the input records
elsewhere; this module never does.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

from ..core import evidence as ev
from ..core import risk as risk_engine
from . import password_strength

# A small, unremarkable sample of very common passwords, used for the
# "common password" indicator when no external wordlist is supplied.
# This is a hygiene check, not a cracking wordlist -- point
# `common_passwords` at SecLists' 10k-most-common list (see
# wordlists/fetch_wordlists.sh) for a serious check.
_BUILTIN_COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345", "qwerty",
    "abc123", "111111", "123123", "1234567", "iloveyou", "adobe123",
    "photoshop", "letmein", "1234567890", "dragon", "monkey", "master",
    "sunshine", "princess", "welcome", "shadow", "ashley", "football",
    "jesus", "michael", "ninja", "mustang", "password1", "admin",
    "administrator", "root", "login", "starwars", "trustno1", "hello",
    "freedom", "whatever", "qazwsx", "changeme", "passw0rd", "p@ssw0rd",
    "p@ssword", "welcome1", "summer2024", "summer2025", "winter2024",
    "winter2025", "company123", "temp1234", "guest", "test123",
}

# Exact account/password pairs that are well-known vendor/OS defaults.
# Not exhaustive -- this is a hygiene net, not a substitute for checking
# the vendor's own default-credential list for a specific product.
DEFAULT_CREDENTIAL_PAIRS = {
    ("admin", "admin"), ("admin", "password"), ("admin", "admin123"),
    ("root", "root"), ("root", "toor"), ("administrator", "administrator"),
    ("guest", "guest"), ("test", "test"), ("sa", "sa"), ("postgres", "postgres"),
    ("ubnt", "ubnt"), ("pi", "raspberry"), ("admin", "1234"), ("admin", "12345"),
    ("admin", "changeme"), ("admin", "letmein"), ("cisco", "cisco"),
}

PRIVILEGED_ACCOUNT_HINTS = re.compile(
    r"\b(admin|administrator|root|domain[_ ]?admin|enterprise[_ ]?admin|sa|sysadmin|"
    r"superuser|backup[_ ]?admin|schema[_ ]?admin)\b",
    re.IGNORECASE,
)


@dataclass
class CredentialRecord:
    """One account/password pair to analyze. `password` is used only
    transiently -- see module docstring."""

    account: str
    password: str
    source: str = "manual"
    privileged: bool = None  # None => infer from account name
    default_credential_hint: bool = False


@dataclass
class CredentialFinding:
    account: str
    password_hash: str  # sha256 hex digest -- never the plaintext
    length: int
    strength: str  # "Weak" / "Medium" / "Strong"
    common_password: bool
    default_credential: bool
    reused_with: list = field(default_factory=list)  # other account names sharing this hash
    breach_exposure: bool = None  # None = not checked (never silently assumed False)
    privileged: bool = False
    source: str = "manual"
    risk: risk_engine.RiskResult = None
    strength_estimate: object = None  # analyzers.password_strength.PasswordStrengthEstimate, set only when use_entropy_scoring=True


def _hash(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def _complexity_classes(password: str) -> int:
    classes = 0
    for pattern in (r"[a-z]", r"[A-Z]", r"[0-9]", r"[^a-zA-Z0-9]"):
        if re.search(pattern, password):
            classes += 1
    return classes


def classify_strength(password: str, common: bool) -> str:
    """Weak / Medium / Strong classification. Documented, fixed rule
    (not a black-box entropy estimate):
      - any common-list match, or length < 8         -> Weak
      - only one character class (all-lower, etc.)    -> Weak
      - length >= 14 AND 3+ character classes         -> Strong
      - length >= 10 AND 3+ character classes         -> Medium
      - everything else                               -> Weak
    """
    if common or len(password) < 8:
        return "Weak"
    classes = _complexity_classes(password)
    if classes <= 1:
        return "Weak"
    if len(password) >= 14 and classes >= 3:
        return "Strong"
    if len(password) >= 10 and classes >= 3:
        return "Medium"
    return "Weak"


def _looks_privileged(account: str) -> bool:
    return bool(PRIVILEGED_ACCOUNT_HINTS.search(account))


def analyze_credentials(
    records: list,
    breach_checker=None,
    common_passwords: set = None,
    internet_facing: bool = False,
    service_criticality: float = 0.5,
    use_entropy_scoring: bool = False,
) -> list:
    """Analyze a batch of CredentialRecord and return list[CredentialFinding].

    breach_checker: optional callable(password: str) -> bool, e.g.
    `credaudit.modules.breach_check.check_password` wrapped to return a
    bool (or a mock in tests). Omit entirely to skip the breach-exposure
    factor -- this is never silently treated as "not breached"; it's
    recorded as `breach_exposure=None` ("not checked") throughout.

    internet_facing/service_criticality: applied uniformly to this whole
    batch (records from one analysis call are assumed to be about the
    same asset/context) and fed into the risk engine's asset_exposure /
    service_criticality factors.

    use_entropy_scoring: off by default so existing callers/tests keep
    their exact `strength` label and risk score. When True, also runs
    each password through `analyzers.password_strength.estimate_strength`
    (zxcvbn) and feeds its continuous weakness score into the risk
    engine instead of the binary Weak/Medium/Strong signal -- the
    estimate (entropy bits, crack-time, zxcvbn's own warning/suggestions)
    is attached to `CredentialFinding.strength_estimate` either way the
    `strength` label is computed, as long as zxcvbn is importable.
    """
    common_set = common_passwords or _BUILTIN_COMMON_PASSWORDS

    hash_to_accounts: dict = {}
    for r in records:
        hash_to_accounts.setdefault(_hash(r.password), []).append(r.account)

    findings = []
    for r in records:
        h = _hash(r.password)
        common = r.password.lower() in common_set
        default_cred = r.default_credential_hint or (
            (r.account.lower(), r.password.lower()) in DEFAULT_CREDENTIAL_PAIRS
        )
        reused_with = [a for a in hash_to_accounts[h] if a != r.account]
        privileged = r.privileged if r.privileged is not None else _looks_privileged(r.account)
        strength = classify_strength(r.password, common)

        breach = None
        if breach_checker is not None:
            try:
                breach = bool(breach_checker(r.password))
            except Exception:
                breach = None  # fail closed to "unknown", never silently "clean"

        strength_estimate = None
        weakness_score = None
        if use_entropy_scoring:
            strength_estimate = password_strength.estimate_strength(r.password, user_inputs=[r.account])
            if strength_estimate is not None:
                weakness_score = strength_estimate.weakness_score

        risk = risk_engine.score_credential_finding(
            weak=(strength == "Weak"),
            reused=bool(reused_with),
            breached=bool(breach),
            privileged=privileged,
            internet_facing=internet_facing,
            default_credential=default_cred,
            confidence=1.0 if (breach is not None or breach_checker is None) else 0.7,
            service_criticality=service_criticality,
            weakness_score=weakness_score,
        )

        findings.append(
            CredentialFinding(
                account=r.account,
                password_hash=h,
                length=len(r.password),
                strength=strength,
                common_password=common,
                default_credential=default_cred,
                reused_with=reused_with,
                breach_exposure=breach,
                privileged=privileged,
                source=r.source,
                risk=risk,
                strength_estimate=strength_estimate,
            )
        )
    return findings


def finding_to_evidence(finding: CredentialFinding, engagement_id: str, asset: str) -> ev.Evidence:
    """Convert one CredentialFinding into a redacted Evidence record. The
    `evidence` text intentionally never includes the plaintext password,
    only a short, non-reversible hash prefix for cross-referencing."""
    risk = finding.risk
    parts = [
        f"Account '{finding.account}': {finding.strength} password (length {finding.length})",
        f"common={finding.common_password}",
        f"default_credential={finding.default_credential}",
        f"reused_with={len(finding.reused_with)} other account(s)" if finding.reused_with else "reused=no",
        f"breach_exposure={'unknown (not checked)' if finding.breach_exposure is None else finding.breach_exposure}",
        f"privileged={finding.privileged}",
        f"password_hash_prefix={finding.password_hash[:12]}\u2026",
    ]
    extra = {
        "account": finding.account,
        "reused_with": finding.reused_with,
        "source": finding.source,
    }
    if finding.strength_estimate is not None:
        est = finding.strength_estimate
        parts.append(
            f"zxcvbn_score={est.zxcvbn_score}/4, ~{est.entropy_bits} bits, "
            f"offline-fast-hash crack time \u2248 {est.offline_fast_hashing_crack_time}"
        )
        extra["password_strength_estimate"] = {
            "zxcvbn_score": est.zxcvbn_score,
            "entropy_bits": est.entropy_bits,
            "crack_time_display": est.crack_time_display,
            "warning": est.warning,
            "suggestions": est.suggestions,
        }
    return ev.Evidence(
        finding_id=ev.next_finding_id(engagement_id),
        engagement_id=engagement_id,
        asset=asset,
        category="Credential Exposure",
        severity=risk.severity,
        risk_score=risk.score,
        confidence=risk.confidence,
        source="credential_analysis",
        evidence="; ".join(parts),
        remediation=risk.remediation,
        status="detected",
        related_findings=[],
        factors={c.name: c.value for c in risk.factors},
        extra=extra,
    )


def findings_to_evidence(findings: list, engagement_id: str, asset: str) -> list:
    return [finding_to_evidence(f, engagement_id, asset) for f in findings]
