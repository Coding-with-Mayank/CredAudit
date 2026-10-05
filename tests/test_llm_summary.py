from datetime import date
from unittest.mock import MagicMock, patch

import pytest

from credaudit.modules.llm_summary import (
    LLMSummaryError,
    _collect_facts,
    generate_executive_summary,
    generate_fallback_summary,
)
from credaudit.scope import Scope


def make_scope():
    return Scope(
        engagement_id="T", client_name="C", authorized_by="A",
        start_date=date(2020, 1, 1), end_date=date(2030, 1, 1),
        targets=["10.0.0.1"], allowed_modules=["recon"],
        max_requests_per_minute=10, confirm_online_testing=True,
        source_path="x", source_sha256="x",
    )


def test_missing_api_key_raises_without_calling_anything(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    scope = make_scope()

    # Isolate the "no key" branch specifically: fake out the anthropic
    # import so this test's result doesn't depend on whether the real
    # (optional) package happens to be installed in the environment
    # running the tests -- requirements.txt correctly leaves it out, so
    # a fresh `pip install -r requirements.txt` would otherwise hit the
    # "package isn't installed" branch first and fail this assertion.
    fake_anthropic_module = MagicMock()
    with patch.dict("sys.modules", {"anthropic": fake_anthropic_module}):
        with pytest.raises(LLMSummaryError, match="No API key"):
            generate_executive_summary(scope)


def test_missing_package_raises_when_anthropic_not_installed(monkeypatch):
    """The other half of the same check: if the package genuinely isn't
    importable, that specific error should fire -- regardless of the API
    key being set or not."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key-for-test")
    scope = make_scope()

    with patch.dict("sys.modules", {"anthropic": None}):
        with pytest.raises(LLMSummaryError, match="isn't installed"):
            generate_executive_summary(scope)


def test_collect_facts_contains_no_raw_secrets():
    scope = make_scope()
    facts = _collect_facts(scope, recon_findings=[{"a": 1}, {"b": 2}])
    assert facts["recon_finding_count"] == 2
    assert facts["engagement_id"] == "T"


def test_generate_summary_calls_api_with_facts_only(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key-for-test")
    scope = make_scope()

    fake_text_block = MagicMock()
    fake_text_block.type = "text"
    fake_text_block.text = "This engagement found no critical issues."
    fake_response = MagicMock()
    fake_response.content = [fake_text_block]

    fake_client = MagicMock()
    fake_client.messages.create.return_value = fake_response

    fake_anthropic_module = MagicMock()
    fake_anthropic_module.Anthropic.return_value = fake_client

    with patch.dict("sys.modules", {"anthropic": fake_anthropic_module}):
        summary = generate_executive_summary(scope, recon_findings=[{"a": 1}])

    assert summary == "This engagement found no critical issues."
    # confirm it only ever made ONE call -- no chained/follow-up calls
    assert fake_client.messages.create.call_count == 1


# ---- Fallback summary (no network, no dependency) ----

def test_fallback_summary_is_deterministic_and_fact_based():
    scope = make_scope()
    summary1 = generate_fallback_summary(scope, recon_findings=[{"a": 1}, {"b": 2}])
    summary2 = generate_fallback_summary(scope, recon_findings=[{"a": 1}, {"b": 2}])
    assert summary1 == summary2
    assert "2 finding(s)" in summary1
    assert scope.engagement_id in summary1
    assert "no AI model was used" in summary1


def test_fallback_summary_with_no_data_still_produces_output():
    scope = make_scope()
    summary = generate_fallback_summary(scope)
    assert scope.engagement_id in summary
    assert "No findings were supplied" in summary


def test_fallback_summary_includes_offline_and_online_results():
    scope = make_scope()

    class FakeOffline:
        total_hashes = 10
        cracked_count = 3

    class FakeOnlineSummary:
        accounts_tested = 5
        valid_pairs_found = 1

    summary = generate_fallback_summary(
        scope, offline_result=FakeOffline(), online_summary=[FakeOnlineSummary()],
    )
    assert "3 of 10 hash(es)" in summary
    assert "confirmed 1 valid credential pair(s)" in summary


def test_missing_package_with_allow_fallback_returns_fallback_not_exception():
    scope = make_scope()
    with patch.dict("sys.modules", {"anthropic": None}):
        summary = generate_executive_summary(scope, recon_findings=[{"a": 1}], allow_fallback=True)
    assert "no AI model was used" in summary


def test_missing_api_key_with_allow_fallback_returns_fallback_not_exception(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    scope = make_scope()
    fake_anthropic_module = MagicMock()
    with patch.dict("sys.modules", {"anthropic": fake_anthropic_module}):
        summary = generate_executive_summary(scope, recon_findings=[{"a": 1}], allow_fallback=True)
    assert "no AI model was used" in summary


def test_allow_fallback_false_still_raises_exactly_as_before(monkeypatch):
    # Default behavior (allow_fallback=False) must be byte-for-byte the
    # original raising behavior -- this guards against a regression that
    # would silently change existing callers' error handling.
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    scope = make_scope()
    fake_anthropic_module = MagicMock()
    with patch.dict("sys.modules", {"anthropic": fake_anthropic_module}):
        with pytest.raises(LLMSummaryError, match="No API key found"):
            generate_executive_summary(scope, recon_findings=[{"a": 1}])


def test_allow_fallback_true_does_not_affect_successful_api_path(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key-for-test")
    scope = make_scope()

    fake_text_block = MagicMock()
    fake_text_block.type = "text"
    fake_text_block.text = "Real AI summary."
    fake_response = MagicMock()
    fake_response.content = [fake_text_block]
    fake_client = MagicMock()
    fake_client.messages.create.return_value = fake_response
    fake_anthropic_module = MagicMock()
    fake_anthropic_module.Anthropic.return_value = fake_client

    with patch.dict("sys.modules", {"anthropic": fake_anthropic_module}):
        summary = generate_executive_summary(scope, recon_findings=[{"a": 1}], allow_fallback=True)

    assert summary == "Real AI summary."
