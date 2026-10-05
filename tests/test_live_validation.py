import json
import time
from unittest.mock import MagicMock, patch

from credaudit.analyzers.secrets import SecretFinding, to_evidence
from credaudit.validators import live_validation, summarize, validate_findings
from credaudit.validators.base import LiveCheckResult
from credaudit.validators.jwt_local import inspect_jwt_locally
from credaudit.validators.providers import (
    validate_aws_pair,
    validate_github_token,
    validate_gcp_api_key,
    validate_sendgrid_key,
    validate_slack_token,
    validate_stripe_key,
)


def _resp(status_code=200, json_data=None, text=""):
    r = MagicMock()
    r.status_code = status_code
    r.text = text or (json.dumps(json_data) if json_data is not None else "")
    if json_data is not None:
        r.json.return_value = json_data
    else:
        r.json.side_effect = ValueError("no json")
    return r


# ---- GitHub ----

def test_github_token_active():
    with patch("requests.get", return_value=_resp(200, {"login": "octocat"})):
        result = validate_github_token("ghp_fake")
    assert result.status == "verified_active"
    assert "octocat" not in result.detail or result.identity_hint != "octocat"  # must be redacted, not raw


def test_github_token_inactive():
    with patch("requests.get", return_value=_resp(401)):
        result = validate_github_token("ghp_fake")
    assert result.status == "verified_inactive"


def test_github_token_network_error_is_unknown():
    import requests
    with patch("requests.get", side_effect=requests.ConnectionError("boom")):
        result = validate_github_token("ghp_fake")
    assert result.status == "unknown"
    assert result.checked is True


# ---- Slack ----

def test_slack_token_active():
    with patch("requests.post", return_value=_resp(200, {"ok": True, "team": "Acme", "user": "alice"})):
        result = validate_slack_token("xoxb-fake")
    assert result.status == "verified_active"


def test_slack_token_revoked():
    with patch("requests.post", return_value=_resp(200, {"ok": False, "error": "token_revoked"})):
        result = validate_slack_token("xoxb-fake")
    assert result.status == "verified_inactive"


def test_slack_token_unrecognized_error_is_unknown():
    with patch("requests.post", return_value=_resp(200, {"ok": False, "error": "ratelimited"})):
        result = validate_slack_token("xoxb-fake")
    assert result.status == "unknown"


# ---- Stripe ----

def test_stripe_key_active():
    with patch("requests.get", return_value=_resp(200, {"object": "balance"})):
        result = validate_stripe_key("sk_test_fake")
    assert result.status == "verified_active"
    assert "test-mode" in result.detail


def test_stripe_key_inactive():
    with patch("requests.get", return_value=_resp(401)):
        result = validate_stripe_key("sk_live_fake")
    assert result.status == "verified_inactive"


# ---- SendGrid ----

def test_sendgrid_key_active():
    with patch("requests.get", return_value=_resp(200, {"scopes": ["mail.send"]})):
        result = validate_sendgrid_key("SG.fake")
    assert result.status == "verified_active"


def test_sendgrid_key_inactive():
    with patch("requests.get", return_value=_resp(401)):
        result = validate_sendgrid_key("SG.fake")
    assert result.status == "verified_inactive"


# ---- GCP (heuristic) ----

def test_gcp_key_invalid_detected():
    data = {"status": "REQUEST_DENIED", "error_message": "The provided API key is invalid."}
    with patch("requests.get", return_value=_resp(200, data)):
        result = validate_gcp_api_key("AIzaFake")
    assert result.status == "verified_inactive"


def test_gcp_key_ok_is_active():
    with patch("requests.get", return_value=_resp(200, {"status": "OK", "results": []})):
        result = validate_gcp_api_key("AIzaFake")
    assert result.status == "verified_active"


def test_gcp_key_api_not_enabled_is_unknown_not_inactive():
    data = {"status": "REQUEST_DENIED", "error_message": "This API project is not authorized to use this API."}
    with patch("requests.get", return_value=_resp(200, data)):
        result = validate_gcp_api_key("AIzaFake")
    assert result.status == "unknown"


# ---- AWS SigV4 ----

def test_aws_pair_active_via_get_caller_identity():
    body = "<GetCallerIdentityResponse><GetCallerIdentityResult><Arn>arn:aws:iam::123456789012:user/bob</Arn></GetCallerIdentityResult></GetCallerIdentityResponse>"
    with patch("requests.get", return_value=_resp(200, text=body)):
        result = validate_aws_pair("AKIAFAKE", "secretfake")
    assert result.status == "verified_active"


def test_aws_pair_invalid_access_key():
    with patch("requests.get", return_value=_resp(403, text="InvalidClientTokenId")):
        result = validate_aws_pair("AKIAFAKE", "secretfake")
    assert result.status == "verified_inactive"


def test_aws_pair_access_denied_is_still_active():
    # Signature validated (a real principal was resolved) but the
    # specific GetCallerIdentity call was denied by policy -- the pair
    # is live, just restricted.
    with patch("requests.get", return_value=_resp(403, text="AccessDenied: User is not authorized")):
        result = validate_aws_pair("AKIAFAKE", "secretfake")
    assert result.status == "verified_active"


# ---- JWT local inspection (no network) ----

def _fake_jwt(exp):
    import base64
    header = base64.urlsafe_b64encode(b'{"alg":"none"}').rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(json.dumps({"exp": exp}).encode()).rstrip(b"=").decode()
    return f"{header}.{payload}.sig"


def test_jwt_expired_detected_locally_no_network():
    token = _fake_jwt(exp=time.time() - 3600)
    with patch("requests.get") as mock_get, patch("requests.post") as mock_post:
        result = inspect_jwt_locally(token)
        mock_get.assert_not_called()
        mock_post.assert_not_called()
    assert result.status == "verified_inactive"
    assert result.network_call_made is False


def test_jwt_not_expired_is_unknown():
    token = _fake_jwt(exp=time.time() + 3600)
    result = inspect_jwt_locally(token)
    assert result.status == "unknown"


def test_jwt_malformed_is_unknown():
    result = inspect_jwt_locally("not-a-jwt")
    assert result.status == "unknown"


# ---- Orchestrator ----

def test_validate_findings_pairs_aws_by_source():
    ak = SecretFinding(secret_type="aws_access_key", value="AKIAFAKE", source="config.py")
    sk = SecretFinding(secret_type="aws_secret_key", value="secretfake", source="config.py")
    body = "<GetCallerIdentityResponse><GetCallerIdentityResult><Arn>arn:aws:iam::1:user/x</Arn></GetCallerIdentityResult></GetCallerIdentityResponse>"
    with patch("requests.get", return_value=_resp(200, text=body)):
        results = validate_findings([ak, sk])
    assert results[("aws_access_key", "AKIAFAKE")].status == "verified_active"
    assert results[("aws_secret_key", "secretfake")].status == "verified_active"


def test_validate_findings_respects_max_checks():
    findings = [
        SecretFinding(secret_type="github_token", value=f"ghp_{i}", source="f.py")
        for i in range(5)
    ]
    with patch("requests.get", return_value=_resp(200, {"login": "x"})) as mock_get:
        results = validate_findings(findings, max_checks=2)
    assert mock_get.call_count == 2
    assert len(results) == 2


def test_validate_findings_skips_non_validatable_types():
    findings = [SecretFinding(secret_type="generic_secret", value="whatever12345", source="f.py")]
    results = validate_findings(findings)
    assert results == {}


def test_summarize_counts_statuses():
    results = {
        ("a", "1"): LiveCheckResult(secret_type="a", status="verified_active", provider="p", detail="d"),
        ("b", "2"): LiveCheckResult(secret_type="b", status="verified_inactive", provider="p", detail="d"),
        ("c", "3"): LiveCheckResult(secret_type="c", status="unknown", provider="p", detail="d"),
    }
    counts = summarize(results)
    assert counts == {"verified_active": 1, "verified_inactive": 1, "unknown": 1}


# ---- Integration with to_evidence() ----

def test_to_evidence_without_live_results_is_unchanged():
    f = SecretFinding(secret_type="github_token", value="ghp_fake", source="app.py", confidence=0.9)
    evidence = to_evidence([f], "ENG-1", "repo")
    assert evidence[0].status == "detected"
    assert "live_validation" not in evidence[0].extra


def test_to_evidence_promotes_to_confirmed_when_verified_active():
    f = SecretFinding(secret_type="github_token", value="ghp_fake", source="app.py", confidence=0.6)
    live = {
        ("github_token", "ghp_fake"): LiveCheckResult(
            secret_type="github_token", status="verified_active", provider="github", detail="active",
        )
    }
    evidence = to_evidence([f], "ENG-1", "repo", live_results=live)[0]
    assert evidence.status == "confirmed"
    assert evidence.confidence == 1.0
    assert "LIVE-VALIDATED ACTIVE" in evidence.evidence


def test_to_evidence_downgrades_severity_when_verified_inactive():
    f = SecretFinding(secret_type="aws_secret_key", value="s3cr3t0123456789", source="app.py", confidence=0.9)
    baseline = to_evidence([f], "ENG-1", "repo")[0]

    f2 = SecretFinding(secret_type="aws_secret_key", value="s3cr3t0123456789", source="app.py", confidence=0.9)
    live = {
        ("aws_secret_key", "s3cr3t0123456789"): LiveCheckResult(
            secret_type="aws_secret_key", status="verified_inactive", provider="aws_sts", detail="revoked",
        )
    }
    downgraded = to_evidence([f2], "ENG-1", "repo", live_results=live)[0]

    assert downgraded.status == "detected"  # exposure is still a fact
    assert downgraded.risk_score < baseline.risk_score
    assert "live-validated INACTIVE" in downgraded.evidence


def test_to_evidence_records_inconclusive_without_changing_severity():
    f = SecretFinding(secret_type="github_token", value="ghp_fake", source="app.py", confidence=0.6)
    baseline_score = to_evidence(
        [SecretFinding(secret_type="github_token", value="ghp_fake", source="app.py", confidence=0.6)],
        "ENG-1", "repo",
    )[0].risk_score

    live = {
        ("github_token", "ghp_fake"): LiveCheckResult(
            secret_type="github_token", status="unknown", provider="github", detail="timed out",
        )
    }
    evidence = to_evidence([f], "ENG-1", "repo", live_results=live)[0]
    assert evidence.status == "detected"
    assert evidence.risk_score == baseline_score
    assert evidence.extra["live_validation"]["status"] == "unknown"
