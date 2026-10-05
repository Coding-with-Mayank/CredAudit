"""Local, network-free JWT inspection.

This decodes a JWT's own (unverified) payload claims to check `exp`.
It never verifies the signature (that would need the signing key, which
by definition isn't available for a leaked token) and never makes a
network call -- so unlike everything in `providers.py`, this runs
unconditionally, with no `--validate-secrets` opt-in needed, exactly
like reading any other field already present in the matched text.

What this can and can't tell you:
  - `exp` in the past  -> verified_inactive, high confidence (any
    correctly-implemented verifier will also reject it on expiry alone,
    independent of whether the signature is still otherwise valid).
  - `exp` in the future, or missing -> unknown. A non-expired claim says
    nothing about whether the token has been revoked, whether its
    signing key has been rotated, or whether `exp` was even honest --
    none of that is checkable without the issuer's verification key.
"""
from __future__ import annotations

import base64
import json
import time
from datetime import datetime, timezone

from .base import LiveCheckResult


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def inspect_jwt_locally(value: str) -> LiveCheckResult:
    """Always returns a LiveCheckResult (never raises); malformed input
    just yields an 'unknown' result explaining why."""
    parts = value.split(".")
    if len(parts) != 3:
        return LiveCheckResult(
            secret_type="jwt", status="unknown", provider="local_jwt_inspection", network_call_made=False,
            detail="Value does not have the standard three-segment JWT structure; could not inspect claims.",
        )
    try:
        payload = json.loads(_b64url_decode(parts[1]))
    except Exception:
        return LiveCheckResult(
            secret_type="jwt", status="unknown", provider="local_jwt_inspection", network_call_made=False,
            detail="Could not decode the token's payload segment as JSON; could not inspect claims.",
        )

    exp = payload.get("exp")
    if exp is None:
        return LiveCheckResult(
            secret_type="jwt", status="unknown", provider="local_jwt_inspection", network_call_made=False,
            detail="Token has no 'exp' claim; local inspection alone can't determine expiry "
                   "(signature not verified, no network call made).",
        )

    try:
        exp = float(exp)
    except (TypeError, ValueError):
        return LiveCheckResult(
            secret_type="jwt", status="unknown", provider="local_jwt_inspection", network_call_made=False,
            detail=f"Token's 'exp' claim ({exp!r}) is not a usable timestamp.",
        )

    if exp < time.time():
        expired_at = datetime.fromtimestamp(exp, tz=timezone.utc).isoformat()
        return LiveCheckResult(
            secret_type="jwt", status="verified_inactive", provider="local_jwt_inspection", network_call_made=False,
            detail=f"Token's own 'exp' claim shows it expired at {expired_at} (checked locally from the "
                   "token's payload; signature not verified, no network call made).",
        )
    return LiveCheckResult(
        secret_type="jwt", status="unknown", provider="local_jwt_inspection", network_call_made=False,
        detail="Token's 'exp' claim has not yet passed, but the signature was not verified and revocation "
               "can't be ruled out from the token's contents alone.",
    )
