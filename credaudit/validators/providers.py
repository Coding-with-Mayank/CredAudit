"""Per-provider live-validation checks.

Every function here takes the secret value(s) and returns a
`LiveCheckResult` (never raises for an ordinary HTTP/network failure --
that becomes an `unknown` result, same discipline as the rest of the
platform's "fail closed to unknown, never to false-clean" rule). Each
one makes exactly one request, read-only, to the provider's own
documented API.

Deliberately NOT implemented here, and why: `private_key`,
`database_connection_string`. Both would require starting a live
session against whatever host the key/connection string points at --
that is testing a *target*, not querying an issuer's own account-level
API, and this platform already has a module for that
(`modules/online.py`) with its own scope check, target allowlist, and
mandatory interactive confirmation. Bolting a silent "quick check" onto
the secret scanner would quietly bypass that safeguard for exactly the
cases it exists to cover. See docs/secret_validation.md.
"""
from __future__ import annotations

import requests

from ..core.evidence import redact
from .aws_sigv4 import build_get_caller_identity_request
from .base import LiveCheckResult, unknown_result

USER_AGENT = "credaudit-secret-validator/1 (+read-only identity check; see docs/secret_validation.md)"


def validate_github_token(value: str, timeout: float = 5.0) -> LiveCheckResult:
    headers = {"Authorization": f"Bearer {value}", "User-Agent": USER_AGENT}
    try:
        resp = requests.get("https://api.github.com/user", headers=headers, timeout=timeout)
    except requests.RequestException as e:
        return unknown_result("github_token", "github", f"Request to GitHub failed: {type(e).__name__}.")

    if resp.status_code == 200:
        login = ""
        try:
            login = resp.json().get("login", "")
        except ValueError:
            pass
        masked = redact(login, keep_start=1, keep_end=0) if login else "(unknown login)"
        return LiveCheckResult(
            secret_type="github_token", status="verified_active", provider="github", http_status=200,
            identity_hint=masked,
            detail=f"GitHub accepted the token and identified it as user '{masked}'.",
        )
    if resp.status_code == 401:
        return LiveCheckResult(
            secret_type="github_token", status="verified_inactive", provider="github", http_status=401,
            detail="GitHub rejected the token (401 Unauthorized) -- it is revoked, expired, or malformed.",
        )
    return unknown_result("github_token", "github", f"GitHub returned HTTP {resp.status_code}; inconclusive.", resp.status_code)


def validate_slack_token(value: str, timeout: float = 5.0) -> LiveCheckResult:
    headers = {"Authorization": f"Bearer {value}", "User-Agent": USER_AGENT}
    try:
        # Slack's auth.test always replies HTTP 200; success/failure is in the body.
        resp = requests.post("https://slack.com/api/auth.test", headers=headers, timeout=timeout)
    except requests.RequestException as e:
        return unknown_result("slack_token", "slack", f"Request to Slack failed: {type(e).__name__}.")

    try:
        data = resp.json()
    except ValueError:
        return unknown_result("slack_token", "slack", f"Slack returned a non-JSON response (HTTP {resp.status_code}).", resp.status_code)

    if data.get("ok"):
        team = redact(data.get("team", ""), keep_start=1)
        user = redact(data.get("user", ""), keep_start=1)
        return LiveCheckResult(
            secret_type="slack_token", status="verified_active", provider="slack", http_status=resp.status_code,
            identity_hint=f"{user}@{team}",
            detail=f"Slack accepted the token for workspace '{team}' as user '{user}'.",
        )

    error = data.get("error", "unknown_error")
    inactive_errors = {"invalid_auth", "token_revoked", "account_inactive", "token_expired", "not_authed"}
    if error in inactive_errors:
        return LiveCheckResult(
            secret_type="slack_token", status="verified_inactive", provider="slack", http_status=resp.status_code,
            detail=f"Slack rejected the token (error: {error}).",
        )
    return unknown_result("slack_token", "slack", f"Slack returned error '{error}'; inconclusive.", resp.status_code)


def validate_stripe_key(value: str, timeout: float = 5.0) -> LiveCheckResult:
    try:
        resp = requests.get("https://api.stripe.com/v1/balance", auth=(value, ""),
                             headers={"User-Agent": USER_AGENT}, timeout=timeout)
    except requests.RequestException as e:
        return unknown_result("stripe_api_key", "stripe", f"Request to Stripe failed: {type(e).__name__}.")

    mode = "test-mode" if "_test_" in value else "live-mode" if "_live_" in value else "unknown-mode"
    if resp.status_code == 200:
        return LiveCheckResult(
            secret_type="stripe_api_key", status="verified_active", provider="stripe", http_status=200,
            detail=f"Stripe accepted the key against the balance endpoint ({mode} key).",
        )
    if resp.status_code == 401:
        return LiveCheckResult(
            secret_type="stripe_api_key", status="verified_inactive", provider="stripe", http_status=401,
            detail="Stripe rejected the key (401 Unauthorized) -- it is revoked or malformed.",
        )
    return unknown_result("stripe_api_key", "stripe", f"Stripe returned HTTP {resp.status_code}; inconclusive.", resp.status_code)


def validate_sendgrid_key(value: str, timeout: float = 5.0) -> LiveCheckResult:
    headers = {"Authorization": f"Bearer {value}", "User-Agent": USER_AGENT}
    try:
        resp = requests.get("https://api.sendgrid.com/v3/scopes", headers=headers, timeout=timeout)
    except requests.RequestException as e:
        return unknown_result("sendgrid_api_key", "sendgrid", f"Request to SendGrid failed: {type(e).__name__}.")

    if resp.status_code == 200:
        return LiveCheckResult(
            secret_type="sendgrid_api_key", status="verified_active", provider="sendgrid", http_status=200,
            detail="SendGrid accepted the key (GET /v3/scopes succeeded).",
        )
    if resp.status_code in (401, 403):
        return LiveCheckResult(
            secret_type="sendgrid_api_key", status="verified_inactive", provider="sendgrid", http_status=resp.status_code,
            detail=f"SendGrid rejected the key (HTTP {resp.status_code}) -- it is revoked or malformed.",
        )
    return unknown_result("sendgrid_api_key", "sendgrid", f"SendGrid returned HTTP {resp.status_code}; inconclusive.", resp.status_code)


def validate_gcp_api_key(value: str, timeout: float = 5.0) -> LiveCheckResult:
    """Heuristic, best-effort only: unlike GitHub/Slack/Stripe/SendGrid,
    a Google API key has no universal account-level identity endpoint --
    it's scoped to whichever specific APIs are enabled on its project.
    This probes the (near-universally-enabled, free-tier) Geocoding API
    as a proxy and is explicit in its result when that proxy can't
    distinguish 'invalid key' from 'valid key, this API just isn't
    enabled for it.'
    """
    try:
        resp = requests.get(
            "https://maps.googleapis.com/maps/api/geocode/json",
            params={"address": "1600 Amphitheatre Parkway", "key": value},
            headers={"User-Agent": USER_AGENT}, timeout=timeout,
        )
    except requests.RequestException as e:
        return unknown_result("gcp_api_key", "google_geocoding_proxy", f"Request to Google failed: {type(e).__name__}.")

    try:
        data = resp.json()
    except ValueError:
        return unknown_result("gcp_api_key", "google_geocoding_proxy", f"Non-JSON response (HTTP {resp.status_code}).", resp.status_code)

    status = data.get("status", "")
    error_message = data.get("error_message", "")
    key_invalid_phrases = ("api key not valid", "the provided api key is invalid", "invalid api key")
    if status == "REQUEST_DENIED" and any(p in error_message.lower() for p in key_invalid_phrases):
        return LiveCheckResult(
            secret_type="gcp_api_key", status="verified_inactive", provider="google_geocoding_proxy",
            http_status=resp.status_code, detail=f"Google reported the key itself is invalid: {error_message!r}",
        )
    if status in ("OK", "ZERO_RESULTS", "OVER_QUERY_LIMIT"):
        return LiveCheckResult(
            secret_type="gcp_api_key", status="verified_active", provider="google_geocoding_proxy",
            http_status=resp.status_code,
            detail="Google accepted the key for the Geocoding API (proxy check -- other APIs on this key weren't tested).",
        )
    return unknown_result(
        "gcp_api_key", "google_geocoding_proxy",
        f"Google returned status={status!r}; this proxy check can't tell whether the key is invalid or simply "
        "not enabled for the Geocoding API specifically. Inconclusive by design -- see docs/secret_validation.md.",
        resp.status_code,
    )


def validate_aws_pair(access_key_id: str, secret_access_key: str, timeout: float = 5.0) -> LiveCheckResult:
    request = build_get_caller_identity_request(access_key_id, secret_access_key)
    try:
        resp = requests.get(request["url"], headers=request["headers"], timeout=timeout)
    except requests.RequestException as e:
        return unknown_result("aws_access_key", "aws_sts", f"Request to AWS STS failed: {type(e).__name__}.")

    if resp.status_code == 200:
        import re
        arn_match = re.search(r"<Arn>([^<]+)</Arn>", resp.text)
        identity = arn_match.group(1) if arn_match else "(identity not parsed)"
        return LiveCheckResult(
            secret_type="aws_access_key", status="verified_active", provider="aws_sts", http_status=200,
            identity_hint=redact(identity, keep_start=10, keep_end=6, min_len_to_partial=20),
            detail="AWS STS GetCallerIdentity succeeded -- this access key / secret key pair is live.",
        )
    if "InvalidClientTokenId" in resp.text or "SignatureDoesNotMatch" in resp.text:
        return LiveCheckResult(
            secret_type="aws_access_key", status="verified_inactive", provider="aws_sts", http_status=resp.status_code,
            detail="AWS rejected the access key ID or the signature derived from the secret key -- the pair is invalid or revoked.",
        )
    if "AccessDenied" in resp.text:
        # The signature itself was accepted (AWS could derive a valid
        # principal from it) -- only the GetCallerIdentity call specifically
        # was denied by an attached policy. The pair is still live.
        return LiveCheckResult(
            secret_type="aws_access_key", status="verified_active", provider="aws_sts", http_status=resp.status_code,
            detail="AWS accepted the credential's signature (identity resolved) but an attached policy denied "
                   "GetCallerIdentity specifically -- the pair is live, just scoped.",
        )
    return unknown_result("aws_access_key", "aws_sts", f"AWS STS returned HTTP {resp.status_code}; inconclusive.", resp.status_code)


# secret_type -> validator(value, timeout) for types with a single-value,
# single-request check. AWS is handled separately (validate_aws_pair)
# because it needs both the access key ID and its paired secret key.
SINGLE_VALUE_VALIDATORS = {
    "github_token": validate_github_token,
    "slack_token": validate_slack_token,
    "stripe_api_key": validate_stripe_key,
    "sendgrid_api_key": validate_sendgrid_key,
    "gcp_api_key": validate_gcp_api_key,
}
