"""Orchestrates live secret-validation across a batch of SecretFinding
objects collected by `analyzers.secrets`.

Opt-in, rate-limited, and auditable -- this is never run implicitly by
a scan. See `credaudit.cli`'s `--validate-secrets` flag and
docs/secret_validation.md for the full policy: what gets checked, what
deliberately doesn't, and why.

Rate limiting (`max_checks`) exists for two reasons, not one: it keeps
a scan of a large repository from silently making hundreds of outbound
requests to third-party providers (politeness/abuse-avoidance -- the
same concern `modules/online.py`'s pacing addresses for live credential
testing against a target), and it keeps a misconfigured or very noisy
pattern match from turning a secret scan into something that looks like
probing from the providers' side.
"""
from __future__ import annotations

import time

from .base import LiveCheckResult
from .jwt_local import inspect_jwt_locally
from .providers import SINGLE_VALUE_VALIDATORS, validate_aws_pair

DEFAULT_MAX_CHECKS = 25
DEFAULT_DELAY_SECONDS = 0.0  # set > 0 to pace requests across many distinct providers/hosts


def validate_findings(
    findings: list,
    timeout: float = 5.0,
    max_checks: int = DEFAULT_MAX_CHECKS,
    delay_seconds: float = DEFAULT_DELAY_SECONDS,
) -> dict:
    """Validate as many distinct (secret_type, value) pairs in `findings`
    as `max_checks` allows, returning {(secret_type, value): LiveCheckResult}.

    AWS access-key/secret-key pairs are matched by `source` (the same
    file/location they were found in) -- a heuristic, not a guarantee,
    documented in docs/secret_validation.md: if a single file legitimately
    contains more than one AWS key pair, only the first access key and
    first secret key found in it are paired and checked.

    JWT local-expiry inspection is NOT rate-limited and always runs
    (even if max_checks is 0) because it makes no network call --
    see `jwt_local.py`.
    """
    results: dict = {}
    checked = 0
    handled_ids: set = set()

    by_source: dict = {}
    for f in findings:
        by_source.setdefault(f.source, []).append(f)

    for group in by_source.values():
        if checked >= max_checks:
            break
        access_keys = [f for f in group if f.secret_type == "aws_access_key"]
        secret_keys = [f for f in group if f.secret_type == "aws_secret_key"]
        if access_keys and secret_keys:
            ak, sk = access_keys[0], secret_keys[0]
            result = validate_aws_pair(ak.value, sk.value, timeout=timeout)
            results[("aws_access_key", ak.value)] = result
            results[("aws_secret_key", sk.value)] = result
            handled_ids.add(id(ak))
            handled_ids.add(id(sk))
            checked += 1
            if delay_seconds:
                time.sleep(delay_seconds)

    for f in findings:
        key = (f.secret_type, f.value)
        if key in results or id(f) in handled_ids:
            continue
        if f.secret_type == "jwt":
            results[key] = inspect_jwt_locally(f.value)
            continue
        validator = SINGLE_VALUE_VALIDATORS.get(f.secret_type)
        if validator is None:
            continue
        if checked >= max_checks:
            continue
        try:
            results[key] = validator(f.value, timeout=timeout)
        except Exception as e:  # pragma: no cover -- defensive; validators already catch requests errors
            results[key] = LiveCheckResult(
                secret_type=f.secret_type, status="unknown", provider=f.secret_type,
                detail=f"Validation raised an unexpected error: {type(e).__name__}.",
            )
        checked += 1
        if delay_seconds:
            time.sleep(delay_seconds)

    return results


def summarize(results: dict) -> dict:
    """Small counts dict for CLI/report output: how many came back
    active/inactive/unknown."""
    counts = {"verified_active": 0, "verified_inactive": 0, "unknown": 0}
    for r in results.values():
        counts[r.status] = counts.get(r.status, 0) + 1
    return counts
