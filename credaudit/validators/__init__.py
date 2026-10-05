"""Opt-in, read-only live secret-validation. See docs/secret_validation.md.

    from credaudit.validators import validate_findings, summarize

    results = validate_findings(secret_findings)   # {(type, value): LiveCheckResult}
    print(summarize(results))                       # {"verified_active": 1, ...}
"""
from .base import LiveCheckResult, unknown_result
from .live_validation import summarize, validate_findings

__all__ = ["LiveCheckResult", "unknown_result", "validate_findings", "summarize"]
