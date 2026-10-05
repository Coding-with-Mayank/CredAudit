"""Native secret detection for authorized files, repositories, and
already-collected evidence (recon output, retrieved JS/config files,
etc).

Detection is pattern-based (regex + shape heuristics) -- the same
general approach tools like truffleHog/detect-secrets/gitleaks use. This
module does not attempt to validate whether a found secret is still
live; it flags patterns and leaves "rotate it / report it / confirm
it's live" as a human judgment call, exactly like the project's
existing `modules/js_intel.py` already does for JS-embedded secrets
(this module generalizes that same approach to arbitrary files).

Full secret values are only ever returned through `SecretFinding.value`
for in-process use (masking, hashing for a --unmasked triage file, deduping);
`SecretFinding.redacted` is what every report/log/evidence object uses.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from ..core.evidence import redact

SECRET_TYPES = {
    "aws_access_key": {
        "pattern": re.compile(r"AKIA[0-9A-Z]{16}"),
        "severity": "Critical", "confidence": 0.9,
        "remediation": "Rotate the AWS access key immediately and audit CloudTrail for its use.",
    },
    "aws_secret_key": {
        "pattern": re.compile(r"(?i)aws_secret_access_key[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})"),
        "severity": "Critical", "confidence": 0.75,
        "remediation": "Rotate the AWS secret key and review IAM access history.",
    },
    "gcp_api_key": {
        "pattern": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
        "severity": "High", "confidence": 0.85,
        "remediation": "Restrict or rotate the Google API key; check API usage logs for abuse.",
    },
    "azure_connection_string": {
        "pattern": re.compile(r"DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[^;]+"),
        "severity": "Critical", "confidence": 0.85,
        "remediation": "Rotate the Azure storage account key.",
    },
    "slack_token": {
        "pattern": re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,48}"),
        "severity": "High", "confidence": 0.85,
        "remediation": "Revoke and reissue the Slack token.",
    },
    "github_token": {
        "pattern": re.compile(r"gh[pousr]_[A-Za-z0-9]{36,255}"),
        "severity": "High", "confidence": 0.9,
        "remediation": "Revoke the GitHub token and audit recent API activity for it.",
    },
    "private_key": {
        "pattern": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----"),
        "severity": "Critical", "confidence": 0.95,
        "remediation": "Treat the private key as compromised: revoke/replace it and any certificates issued with it.",
    },
    "jwt": {
        "pattern": re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
        "severity": "Medium", "confidence": 0.6,
        "remediation": "Confirm whether the token is still valid; revoke/rotate signing keys if it grants meaningful access.",
    },
    "database_connection_string": {
        "pattern": re.compile(
            r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|mssql)://[^:\s\"']+:[^@\s\"']+@[^\s\"']+"
        ),
        "severity": "Critical", "confidence": 0.85,
        "remediation": "Rotate the database credential and restrict network access to the database.",
    },
    "bearer_token": {
        "pattern": re.compile(r"(?i)bearer\s+[A-Za-z0-9_\-.=]{20,}"),
        "severity": "Medium", "confidence": 0.55,
        "remediation": "Confirm token scope/expiry; revoke if it grants access beyond what's needed.",
    },
    "generic_api_key": {
        "pattern": re.compile(r"""(?i)(?:api[_-]?key|apikey)["']?\s*[:=]\s*["']([A-Za-z0-9_\-]{16,64})["']"""),
        "severity": "Medium", "confidence": 0.5,
        "remediation": "Confirm this is a live key; rotate and move it to a secrets manager if so.",
    },
    "generic_secret": {
        "pattern": re.compile(r"""(?i)(?:secret|client[_-]?secret|passwd|password)["']?\s*[:=]\s*["']([^"'\s]{8,64})["']"""),
        "severity": "Medium", "confidence": 0.4,
        "remediation": "Confirm this is a live secret; rotate and move it to a secrets manager if so.",
    },
    "stripe_api_key": {
        "pattern": re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{10,99}\b"),
        "severity": "Critical", "confidence": 0.9,
        "remediation": "Roll the Stripe API key immediately from the Stripe dashboard and review recent API activity/webhooks.",
    },
    "sendgrid_api_key": {
        "pattern": re.compile(r"\bSG\.[A-Za-z0-9_\-]{20,24}\.[A-Za-z0-9_\-]{37,45}\b"),
        "severity": "High", "confidence": 0.9,
        "remediation": "Revoke the SendGrid API key and issue a new one scoped to only the needed permissions.",
    },
}

# secret_type -> whether a live-validation provider exists for it in
# `credaudit.validators` (checked here only to build accurate CLI/report
# messaging -- the validators package is imported lazily, on demand, so
# `analyzers.secrets` itself never requires network-capable code to be
# importable just to detect patterns).
LIVE_VALIDATABLE_TYPES = {
    "github_token", "slack_token", "stripe_api_key", "sendgrid_api_key",
    "gcp_api_key", "aws_access_key", "aws_secret_key", "jwt",
}

# Maps the (differently-named) secret kinds already produced by
# modules/js_intel.py onto this module's SECRET_TYPES keys, so a
# previously-collected `analyze-js` result can be folded into the same
# evidence/correlation pipeline instead of living in its own island.
JS_INTEL_KIND_ALIASES = {
    "google_api_key": "gcp_api_key",
    "private_key_header": "private_key",
}

TEXT_EXTENSIONS = {
    ".js", ".ts", ".jsx", ".tsx", ".py", ".json", ".yml", ".yaml", ".env",
    ".config", ".txt", ".md", ".xml", ".ini", ".cfg", ".sh", ".properties",
    ".tf", ".java", ".rb", ".go", ".php", ".env.example",
}
MAX_FILE_BYTES = 5_000_000


@dataclass
class SecretFinding:
    secret_type: str
    value: str
    source: str
    line_number: int = None
    # `severity`/`confidence` here are the static, quick-lookup defaults
    # from SECRET_TYPES -- useful the moment a pattern is matched, before
    # any asset/exposure context is known. `to_evidence()` below computes
    # the *real*, context-aware severity via the platform risk engine and
    # stores it in `risk`; anything rendering a report/dashboard should
    # prefer `risk.severity` over this field once `to_evidence()` has run,
    # so the same finding never shows two different severities in two
    # different places.
    severity: str = "Medium"
    confidence: float = 0.5
    remediation: str = ""
    risk: object = None  # core.risk.RiskResult, set by to_evidence()
    live_check: object = None  # validators.base.LiveCheckResult, set by to_evidence() when available

    @property
    def redacted(self) -> str:
        return redact(self.value, keep_start=4, keep_end=4, min_len_to_partial=10)

    @property
    def display_severity(self) -> str:
        """The severity to show in any report/table: the risk-engine's
        computed value once available, falling back to the static
        per-type default for a finding that hasn't gone through
        to_evidence() yet (e.g. a raw scan_text()/scan_file() result)."""
        return self.risk.severity if self.risk is not None else self.severity


def scan_text(content: str, source: str = "") -> list:
    """Scan a block of text and return list[SecretFinding], deduplicated
    by (secret_type, value) so the same secret repeated many times in
    one file only produces one finding."""
    findings = []
    seen = set()
    for secret_type, spec in SECRET_TYPES.items():
        for match in spec["pattern"].finditer(content):
            value = match.group(1) if match.groups() else match.group(0)
            key = (secret_type, value)
            if key in seen:
                continue
            seen.add(key)
            line_no = content.count("\n", 0, match.start()) + 1
            findings.append(
                SecretFinding(
                    secret_type=secret_type, value=value, source=source, line_number=line_no,
                    severity=spec["severity"], confidence=spec["confidence"], remediation=spec["remediation"],
                )
            )
    return findings


def scan_file(path) -> list:
    """Scan one file. Silently returns [] for anything unreadable,
    too large, or binary -- this is a best-effort scan over files you
    already have, not a guarantee every byte was inspected."""
    path = Path(path)
    if not path.exists() or not path.is_file():
        return []
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return []
        content = path.read_text(errors="ignore")
    except OSError:
        return []
    return scan_text(content, source=str(path))


def scan_directory(path, extensions: set = None) -> list:
    """Recursively scan a directory for secrets in text-like files.
    Only scans an authorized local path you already have -- this
    module never fetches or clones anything itself."""
    path = Path(path)
    exts = extensions or TEXT_EXTENSIONS
    findings = []
    if not path.exists():
        return findings
    for file_path in sorted(path.rglob("*")):
        if file_path.is_file() and file_path.suffix.lower() in exts:
            findings.extend(scan_file(file_path))
    return findings


def _downgrade_for_confirmed_inactive(risk) -> "object":
    """A secret that live-validation directly confirmed is no longer
    active poses materially less *immediate* risk -- but it's not a
    false positive: the exposure still happened, and whatever rotation
    process retired this secret is worth confirming actually covers
    every place it leaked to. So: cap severity low rather than discard
    the finding."""
    from ..core.risk import RiskResult, severity_for_score

    new_score = min(risk.score, 15)
    return RiskResult(
        score=new_score,
        severity=severity_for_score(new_score),
        confidence=risk.confidence,
        factors=risk.factors,
        explanation=(
            risk.explanation
            + " Live validation directly confirmed this specific secret is no longer active, which substantially "
              "reduces immediate risk; retained as a hygiene finding because the exposure itself still occurred "
              "and the rotation/response process around it is worth reviewing."
        ),
        remediation=risk.remediation,
    )


def to_evidence(
    findings: list,
    engagement_id: str,
    asset: str,
    source_module: str = "secret_analysis",
    live_results: dict = None,
) -> list:
    """Build Evidence from SecretFinding objects.

    `live_results`, when given, is the `{(secret_type, value): LiveCheckResult}`
    mapping from `credaudit.validators.validate_findings()`. It is
    entirely optional and additive: omit it (the default) and this
    behaves exactly as before. When a finding has a matching live-check
    result:
      - verified_active   -> status becomes "confirmed" (this is the one
        other place besides `integrations.hydra` that can produce that
        status, and for the same reason: a fact was directly observed,
        not inferred from a pattern match), confidence is raised to 1.0,
        and severity is recomputed at that confidence.
      - verified_inactive -> severity is capped low (see
        `_downgrade_for_confirmed_inactive`); status stays "detected"
        because the *exposure* is still a real, detected fact.
      - unknown           -> no change to severity/status; the attempt
        and its inconclusive result are still recorded in `extra` for
        transparency (validation was tried, not skipped).
    """
    from ..core import evidence as ev
    from ..core import risk as risk_engine

    out = []
    for f in findings:
        risk = risk_engine.score_secret_finding(
            secret_type=f.secret_type, confidence=f.confidence, remediation=f.remediation,
        )
        confidence = f.confidence
        status = "detected"
        location = f" (line {f.line_number})" if f.line_number else ""
        evidence_text = f"{f.secret_type} detected in {f.source}{location} \u2014 {f.redacted}"
        extra = {"secret_type": f.secret_type, "source_file": f.source, "line_number": f.line_number}

        live = live_results.get((f.secret_type, f.value)) if live_results else None
        if live is not None:
            f.live_check = live
            extra["live_validation"] = live.to_dict()
            if live.status == "verified_active":
                status = "confirmed"
                confidence = 1.0
                risk = risk_engine.score_secret_finding(
                    secret_type=f.secret_type, confidence=1.0, remediation=f.remediation,
                )
                evidence_text += f" \u2014 LIVE-VALIDATED ACTIVE: {live.detail}"
            elif live.status == "verified_inactive":
                risk = _downgrade_for_confirmed_inactive(risk)
                evidence_text += f" \u2014 live-validated INACTIVE: {live.detail}"
            else:
                evidence_text += f" \u2014 live validation inconclusive: {live.detail}"

        f.risk = risk  # keep the finding and the evidence built from it in agreement
        out.append(
            ev.Evidence(
                finding_id=ev.next_finding_id(engagement_id),
                engagement_id=engagement_id,
                asset=asset,
                category="Secret Exposure",
                severity=risk.severity,
                risk_score=risk.score,
                confidence=confidence,
                source=source_module,
                evidence=evidence_text,
                remediation=f.remediation,
                status=status,
                factors={c.name: c.value for c in risk.factors},
                extra=extra,
            )
        )
    return out
