from credaudit.analyzers import vulnerabilities as va
from credaudit.modules.risk_engine import assess_service


def test_assessment_to_evidence_basic_shape():
    assessment = assess_service("10.0.0.5", "ssh", ["old_version", "password_auth_enabled"])
    e = va.assessment_to_evidence(assessment, "ENG-1")
    assert e.category == "Network/Service Exposure"
    assert e.asset == "10.0.0.5"
    assert e.source == "recon (nuclei)"
    assert "patch" in e.remediation.lower() or "upgrade" in e.remediation.lower()


def test_internet_facing_increases_score():
    assessment = assess_service("10.0.0.5", "ftp", ["default_creds"])
    external = va.assessment_to_evidence(assessment, "ENG-1", internet_facing=True)
    internal = va.assessment_to_evidence(assessment, "ENG-1", internet_facing=False)
    assert external.risk_score > internal.risk_score


def test_exploitable_indicator_detected():
    assessment = assess_service("10.0.0.5", "ftp", ["default_creds"])
    e = va.assessment_to_evidence(assessment, "ENG-1")
    assert e.extra["indicators"] == ["default_creds"]


def test_batch_conversion():
    assessments = [
        assess_service("a", "ssh", ["old_version"]),
        assess_service("b", "ftp", ["default_creds"]),
    ]
    evs = va.assessments_to_evidence(assessments, "ENG-1")
    assert len(evs) == 2
    assert {e.asset for e in evs} == {"a", "b"}
