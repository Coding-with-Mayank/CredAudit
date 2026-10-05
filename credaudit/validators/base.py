"""Shared shape for secret live-validation results.

What "validation" means here, precisely: for a secret type with a known
issuing provider, make exactly one read-only, non-destructive API call
using the secret exactly as a legitimate client would -- the same
"who am I" request the provider's own SDK makes to authenticate a
session (GitHub `GET /user`, Slack `auth.test`, AWS
`sts:GetCallerIdentity`, Stripe's balance lookup, SendGrid's
`/v3/scopes`). This is the same approach TruffleHog, gitleaks, and other
mainstream secret scanners use to turn "a string that matches a pattern"
into "a credential we confirmed is still live" -- see
docs/secret_validation.md for the full rationale and explicit
boundaries (which secret types this does and does NOT attempt, and why).

This module never attempts an action the provider wouldn't classify as
a normal authentication check, never writes/modifies/deletes anything,
and never targets a system other than the API that issued the secret in
the first place. It is deliberately a *narrower* set of checks than
"does this grant access to something interesting" -- answering that
fully for, say, an AWS key would mean enumerating permissions, which
starts to look like reconnaissance against the account, not identity
verification. GetCallerIdentity-style calls stop at "is this pair
currently accepted," on purpose.

Three-way result, never two: a provider that rejects a secret (401/403
with an auth-specific error) is different from a provider that couldn't
be reached, timed out, or returned something this module doesn't
recognize. Collapsing "inactive" and "unknown" together would silently
turn "we don't know" into a false sense of safety.
"""
from __future__ import annotations

import time
from dataclasses import dataclass

STATUS_ACTIVE = "verified_active"
STATUS_INACTIVE = "verified_inactive"
STATUS_UNKNOWN = "unknown"

VALID_LIVE_STATUSES = (STATUS_ACTIVE, STATUS_INACTIVE, STATUS_UNKNOWN)


@dataclass
class LiveCheckResult:
    secret_type: str
    status: str  # one of VALID_LIVE_STATUSES
    detail: str  # human-readable, already-redacted explanation
    provider: str  # which provider/mechanism performed the check, e.g. "github", "local_jwt_inspection"
    checked: bool = True
    identity_hint: str = ""  # masked account/user identifier, never the secret itself
    http_status: int = None
    checked_at: float = None
    network_call_made: bool = True

    def __post_init__(self) -> None:
        if self.status not in VALID_LIVE_STATUSES:
            raise ValueError(f"Invalid live-check status '{self.status}'. Must be one of {VALID_LIVE_STATUSES}.")
        if self.checked_at is None:
            self.checked_at = time.time()

    def to_dict(self) -> dict:
        return {
            "secret_type": self.secret_type,
            "status": self.status,
            "detail": self.detail,
            "provider": self.provider,
            "identity_hint": self.identity_hint,
            "http_status": self.http_status,
            "checked_at": self.checked_at,
            "network_call_made": self.network_call_made,
        }


def unknown_result(secret_type: str, provider: str, detail: str, http_status: int = None) -> LiveCheckResult:
    """Convenience constructor for the common 'couldn't tell' case --
    a network error, timeout, or an HTTP status this provider's
    validator doesn't specifically interpret."""
    return LiveCheckResult(
        secret_type=secret_type, status=STATUS_UNKNOWN, detail=detail,
        provider=provider, http_status=http_status,
    )
