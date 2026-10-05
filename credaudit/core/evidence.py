"""Unified evidence schema.

Every analyzer, correlation step, and tool integration in CredAudit
emits (or consumes) findings in this one shape, so the risk engine,
correlation engine, attack-path builder, and reporting layer can all
operate on a single structure instead of each module inventing its own
dict shape.

This does not replace the tool-specific raw output (a nuclei JSONL
line, a hashcat cracked.txt, a hydra log) -- those stay on disk exactly
as the underlying tool wrote them, for anyone who needs the raw detail.
Evidence is the *interpreted*, redacted, structured layer that sits on
top of them, and it is the only thing correlation/risk/reporting code
should need to look at.

Status vocabulary (deliberately conservative -- see also
`core.correlation`):
    detected               -- a pattern/indicator was observed
    suspected              -- multiple weak signals point the same way,
                              but nothing has been directly confirmed
    potential_relationship -- this finding is part of a correlated
                              chain whose combined evidence is still
                              circumstantial
    confirmed              -- directly observed/validated fact (e.g. an
                              online module actually validated a login)

Nothing in this module (or anywhere downstream) is allowed to promote a
finding's status past what its own evidence supports.
"""
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

VALID_STATUSES = ("detected", "suspected", "potential_relationship", "confirmed")
VALID_SEVERITIES = ("Info", "Low", "Medium", "High", "Critical")


class EvidenceError(Exception):
    """Raised when a piece of evidence violates the schema's invariants."""


# Process-local sequential id counter. Deliberately simple: uniqueness
# only needs to hold within one `run`/pipeline invocation, and finding
# ids are always paired with engagement_id in reports, so cross-process
# collisions are not a correctness problem.
_counter = {"n": 0}


def next_finding_id(engagement_id: str) -> str:
    """Return the next sequential finding id, e.g. 'CA-0001'.

    The engagement_id is intentionally not embedded in the id itself
    (ids stay short and stable); every Evidence object already carries
    engagement_id as its own field, so the pair (engagement_id,
    finding_id) is what's actually unique.
    """
    _counter["n"] += 1
    return f"CA-{_counter['n']:04d}"


def reset_finding_id_counter() -> None:
    """Reset the process-local counter to 0. Called at the start of a
    fresh pipeline run so ids are stable/reproducible per run, and used
    directly by tests that need deterministic ids."""
    _counter["n"] = 0


@dataclass
class Evidence:
    """The unified finding shape. Field meanings mirror the schema in
    the project README almost exactly -- see that file for the
    at-a-glance JSON example."""

    finding_id: str
    engagement_id: str
    asset: str
    category: str
    severity: str
    risk_score: int
    confidence: float
    source: str
    evidence: str
    remediation: str = ""
    status: str = "detected"
    related_findings: list = field(default_factory=list)
    factors: dict = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    # Module-specific extra detail. Still subject to the "never put raw
    # secrets/plaintext here" rule that applies to the whole schema --
    # this is for things like {"service": "ssh", "indicators": [...]}."
    extra: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.severity not in VALID_SEVERITIES:
            raise EvidenceError(
                f"Invalid severity '{self.severity}'. Must be one of {VALID_SEVERITIES}."
            )
        if self.status not in VALID_STATUSES:
            raise EvidenceError(
                f"Invalid status '{self.status}'. Must be one of {VALID_STATUSES}."
            )
        if not isinstance(self.risk_score, int) or not (0 <= self.risk_score <= 100):
            raise EvidenceError(f"risk_score must be an int 0-100, got {self.risk_score!r}.")
        if not (0.0 <= self.confidence <= 1.0):
            raise EvidenceError(f"confidence must be 0.0-1.0, got {self.confidence!r}.")

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "Evidence":
        known = {f for f in cls.__dataclass_fields__}
        clean = {k: v for k, v in data.items() if k in known}
        return cls(**clean)


def redact(value: str, keep_start: int = 1, keep_end: int = 0, min_len_to_partial: int = 4) -> str:
    """Redact a sensitive string for safe display in a report/log.

    Short values are fully masked (there's no safe partial reveal of a
    4-character secret). Longer ones keep a few boundary characters so
    a human reviewing a report can recognize *which* secret/credential
    is being referred to without the value itself being usable.
    """
    if not value:
        return ""
    if len(value) <= min_len_to_partial:
        return "*" * len(value)
    start = value[:keep_start] if keep_start else ""
    end = value[-keep_end:] if keep_end else ""
    middle_len = max(len(value) - keep_start - keep_end, 3)
    return f"{start}{'*' * middle_len}{end}"


def write_evidence_jsonl(evidence_list, path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        for e in evidence_list:
            f.write(json.dumps(e.to_dict(), default=str) + "\n")
    return path


def read_evidence_jsonl(path) -> list:
    path = Path(path)
    if not path.exists():
        return []
    out = []
    with path.open() as f:
        for line in f:
            if line.strip():
                out.append(Evidence.from_dict(json.loads(line)))
    return out
