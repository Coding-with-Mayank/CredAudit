from credaudit.modules.risk_engine import assess_all, assess_finding, assess_service


def test_manual_assessment_matches_the_ssh_example():
    # SSH / weak banner / old OpenSSH / password auth enabled -> High risk
    assessment = assess_service(
        "203.0.113.10", "ssh", ["old_version", "password_auth_enabled"]
    )
    assert assessment.risk_level == "High"
    assert "Outdated software version" in assessment.reasoning
    assert "Password authentication enabled" in assessment.reasoning
    assert "brute-force" in assessment.reasoning


def test_default_creds_is_critical():
    assessment = assess_service("10.0.0.1", "ftp", ["default_creds"])
    assert assessment.risk_level == "Critical"


def test_no_indicators_is_info():
    assessment = assess_service("10.0.0.1", "ssh", [])
    assert assessment.risk_level == "Info"


def test_unknown_indicators_are_ignored_not_crashed_on():
    assessment = assess_service("10.0.0.1", "ssh", ["made_up_indicator"])
    assert assessment.indicators == []
    assert assessment.risk_level == "Info"


def test_assess_finding_auto_detects_ssh_and_old_version():
    finding = {"template-id": "ssh-old-version-detect", "host": "203.0.113.10"}
    assessment = assess_finding(finding)
    assert assessment is not None
    assert assessment.service == "ssh"
    assert "old_version" in assessment.indicators
    assert assessment.risk_level == "High"


def test_assess_finding_returns_none_for_unknown_service():
    finding = {"template-id": "generic-tech-detect", "host": "203.0.113.10"}
    assert assess_finding(finding) is None


def test_assess_finding_returns_none_without_host():
    finding = {"template-id": "ssh-detect"}
    assert assess_finding(finding) is None


def test_assess_all_skips_unmapped_findings():
    findings = [
        {"template-id": "ssh-detect", "host": "10.0.0.1"},
        {"template-id": "generic-tech-detect", "host": "10.0.0.1"},
    ]
    results = assess_all(findings)
    assert len(results) == 1
    assert results[0].service == "ssh"
