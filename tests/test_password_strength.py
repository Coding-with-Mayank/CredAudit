from credaudit.analyzers import password_strength
from credaudit.analyzers.credentials import CredentialRecord, analyze_credentials
from credaudit.core import risk as risk_engine


def test_estimate_strength_weak_password():
    est = password_strength.estimate_strength("password123")
    assert est.zxcvbn_score <= 1
    assert est.weakness_score >= 0.8
    assert est.entropy_bits > 0
    assert "offline_fast_hashing_1e10_per_second" in est.crack_time_display


def test_estimate_strength_strong_password():
    est = password_strength.estimate_strength("qK7$mP2*nX9!wZ4@")
    assert est.zxcvbn_score >= 3
    assert est.weakness_score <= 0.3


def test_estimate_strength_flags_keyboard_walk_despite_character_classes():
    # classify_strength()'s fixed rule only counts character classes and
    # length, so this would otherwise look "Strong" -- zxcvbn should
    # still recognize the keyboard-walk pattern and score it low.
    from credaudit.analyzers.credentials import classify_strength

    password = "Qwertyuiop123!"
    fixed_rule_label = classify_strength(password, common=False)
    est = password_strength.estimate_strength(password)
    assert fixed_rule_label == "Strong"
    assert est.zxcvbn_score <= 2


def test_estimate_strength_returns_none_when_zxcvbn_unavailable(monkeypatch):
    monkeypatch.setattr(password_strength, "ZXCVBN_AVAILABLE", False)
    assert password_strength.estimate_strength("whatever") is None


def test_analyze_credentials_without_entropy_scoring_is_unchanged():
    records = [CredentialRecord(account="bob", password="Qwertyuiop123!")]
    findings = analyze_credentials(records)
    assert findings[0].strength_estimate is None


def test_analyze_credentials_with_entropy_scoring_attaches_estimate():
    records = [CredentialRecord(account="bob", password="password123")]
    findings = analyze_credentials(records, use_entropy_scoring=True)
    f = findings[0]
    assert f.strength_estimate is not None
    assert f.strength_estimate.zxcvbn_score <= 1


def test_entropy_scoring_can_catch_what_fixed_rule_misses():
    # A keyboard-walk password that the fixed rule rates "Strong" should
    # score a meaningfully higher (worse) risk once entropy scoring is on,
    # because the continuous weakness_score reflects the real guessability.
    records = [CredentialRecord(account="admin", password="Qwertyuiop123!")]
    fixed = analyze_credentials(records, internet_facing=True)[0]
    entropy_scored = analyze_credentials(records, internet_facing=True, use_entropy_scoring=True)[0]

    assert fixed.strength == "Strong"
    assert fixed.risk.score < entropy_scored.risk.score


def test_score_credential_finding_default_behavior_unchanged():
    # weakness_score omitted -> must reproduce the exact legacy factor values
    a = risk_engine.score_credential_finding(
        weak=True, reused=False, breached=False, privileged=False, internet_facing=True,
    )
    b = risk_engine.score_credential_finding(
        weak=True, reused=False, breached=False, privileged=False, internet_facing=True, weakness_score=None,
    )
    assert a.score == b.score
    assert a.factors == b.factors


def test_score_credential_finding_weakness_score_overrides_binary():
    weak_binary = risk_engine.score_credential_finding(
        weak=True, reused=False, breached=False, privileged=False, internet_facing=True,
    )
    graduated_low = risk_engine.score_credential_finding(
        weak=True, reused=False, breached=False, privileged=False, internet_facing=True, weakness_score=0.2,
    )
    assert graduated_low.score < weak_binary.score
