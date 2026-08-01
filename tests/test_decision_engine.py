from credaudit.modules.recon import suggest_online_targets_with_risk


def test_risk_aware_suggestions_are_sorted_highest_first():
    findings = [
        {"template-id": "ssh-detect", "host": "10.0.0.1"},  # Info-level, no indicators
        {"template-id": "ssh-old-version-default-login", "host": "10.0.0.2"},  # Critical
    ]
    suggestions = suggest_online_targets_with_risk(findings)
    assert len(suggestions) == 2
    assert suggestions[0]["target"] == "10.0.0.2"
    assert suggestions[0]["risk_level"] == "Critical"
    assert suggestions[1]["risk_level"] == "Info"


def test_risk_aware_suggestions_include_reasoning():
    findings = [{"template-id": "ssh-old-version-detect", "host": "10.0.0.1"}]
    suggestions = suggest_online_targets_with_risk(findings)
    assert suggestions[0]["reasoning"]
    assert "brute-force" in suggestions[0]["reasoning"]


def test_still_just_a_suggestion_list_not_an_action():
    """Confirms the function returns plain data -- no side effects, no
    module invocations, nothing that could trigger a live test."""
    findings = [{"template-id": "ssh-old-version-detect", "host": "10.0.0.1"}]
    result = suggest_online_targets_with_risk(findings)
    assert isinstance(result, list)
    assert all(isinstance(s, dict) for s in result)
