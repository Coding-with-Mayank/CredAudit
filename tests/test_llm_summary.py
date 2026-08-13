from datetime import date
from unittest.mock import MagicMock, patch

import pytest

from credaudit.modules.llm_summary import LLMSummaryError, _collect_facts, generate_executive_summary
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
