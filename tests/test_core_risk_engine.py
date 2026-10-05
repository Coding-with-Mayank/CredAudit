import pytest

from credaudit.core import risk


def test_weights_sum_to_one():
    assert abs(sum(risk.FACTOR_WEIGHTS.values()) - 1.0) < 1e-9


def test_unknown_factor_raises():
    with pytest.raises(risk.RiskEngineError):
        risk.score({"not_a_real_factor": 1.0})


def test_invalid_confidence_raises():
    with pytest.raises(risk.RiskEngineError):
        risk.score({}, confidence=1.5)


def test_no_factors_gives_zero_score_info_severity():
    result = risk.score({})
    assert result.score == 0
    assert result.severity == "Info"
    assert result.factors == []


def test_all_factors_maxed_gives_critical():
    all_max = {name: 1.0 for name in risk.FACTOR_WEIGHTS}
    result = risk.score(all_max)
    assert result.score == 100
    assert result.severity == "Critical"


def test_confidence_discounts_score():
    factors = {"asset_exposure": 1.0}
    full = risk.score(factors, confidence=1.0)
    half = risk.score(factors, confidence=0.5)
    assert half.score == round(full.score * 0.5)
    assert "confidence" in half.explanation.lower()


def test_severity_thresholds():
    assert risk.severity_for_score(0) == "Info"
    assert risk.severity_for_score(19) == "Info"
    assert risk.severity_for_score(20) == "Low"
    assert risk.severity_for_score(39) == "Low"
    assert risk.severity_for_score(40) == "Medium"
    assert risk.severity_for_score(59) == "Medium"
    assert risk.severity_for_score(60) == "High"
    assert risk.severity_for_score(79) == "High"
    assert risk.severity_for_score(80) == "Critical"
    assert risk.severity_for_score(100) == "Critical"


def test_factors_are_clamped_to_0_1():
    result = risk.score({"asset_exposure": 5.0})
    assert result.factors[0].value == 1.0
    result2 = risk.score({"asset_exposure": -5.0})
    assert result2.score == 0


def test_score_is_reproducible():
    factors = {"asset_exposure": 0.7, "privilege_level": 0.4}
    r1 = risk.score(factors, confidence=0.9)
    r2 = risk.score(factors, confidence=0.9)
    assert r1.score == r2.score
    assert r1.severity == r2.severity


# --- the worked example from the project brief ------------------------------

def test_credential_worked_example_is_critical():
    """admin / weak / reused / breached / privileged / internet-facing
    should land Critical, matching the brief's example output."""
    result = risk.score_credential_finding(
        weak=True, reused=True, breached=True, privileged=True, internet_facing=True,
    )
    assert result.severity == "Critical"
    assert result.score >= 80
    factor_names = {f.name for f in result.factors}
    assert {"credential_weakness", "password_reuse", "breach_exposure", "privilege_level"} <= factor_names


def test_credential_strong_unique_unbreached_internal_is_low_risk():
    result = risk.score_credential_finding(
        weak=False, reused=False, breached=False, privileged=False, internet_facing=False,
    )
    assert result.severity in ("Info", "Low")


def test_credential_default_credential_boosts_exploitability():
    weak_only = risk.score_credential_finding(
        weak=True, reused=False, breached=False, privileged=False, internet_facing=False,
    )
    default_cred = risk.score_credential_finding(
        weak=True, reused=False, breached=False, privileged=False, internet_facing=False,
        default_credential=True,
    )
    assert default_cred.score > weak_only.score


def test_credential_remediation_mentions_relevant_actions():
    result = risk.score_credential_finding(
        weak=True, reused=True, breached=True, privileged=True, internet_facing=True,
    )
    text = result.remediation.lower()
    assert "rotate" in text
    assert "reused" in text or "shared" in text
    assert "breach" in text
    assert "privileged" in text or "mfa" in text


def test_secret_private_key_scores_higher_than_generic_secret():
    private_key = risk.score_secret_finding(secret_type="private_key", confidence=0.9)
    generic = risk.score_secret_finding(secret_type="generic_secret", confidence=0.9)
    assert private_key.score > generic.score


def test_secret_unknown_type_gets_conservative_default():
    result = risk.score_secret_finding(secret_type="some_unheard_of_type", confidence=0.9)
    assert 0 <= result.score <= 100  # doesn't crash, doesn't except


def test_service_finding_critical_risk_level_scores_higher_than_low():
    critical = risk.score_service_finding(risk_level="Critical", internet_facing=True)
    low = risk.score_service_finding(risk_level="Low", internet_facing=True)
    assert critical.score > low.score


def test_service_finding_internet_facing_scores_higher_than_internal():
    external = risk.score_service_finding(risk_level="High", internet_facing=True)
    internal = risk.score_service_finding(risk_level="High", internet_facing=False)
    assert external.score > internal.score
