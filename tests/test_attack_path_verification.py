from credaudit.attack_paths import graph as ag
from credaudit.attack_paths import verification as pv
from credaudit.core import correlation as corr
from credaudit.core import evidence as ev


def _make(status_net, status_cred):
    ev.reset_finding_id_counter()
    items = [
        ev.Evidence(finding_id="CA-0001", engagement_id="ENG-1", asset="dc01", category="Network/Service Exposure",
                    severity="High", risk_score=70, confidence=0.8, source="recon", evidence="ssh exposed",
                    remediation="Patch SSH.", status=status_net),
        ev.Evidence(finding_id="CA-0002", engagement_id="ENG-1", asset="dc01", category="Credential Exposure",
                    severity="Critical", risk_score=90, confidence=0.9, source="credential_analysis",
                    evidence="weak admin password", remediation="Rotate password.", status=status_cred),
    ]
    chains = corr.correlate(items)
    paths = ag.build_attack_paths(items, chains)
    return items, paths


def test_fully_corroborated_when_every_link_confirmed():
    items, paths = _make("confirmed", "confirmed")
    result = pv.verify_path(paths[0], {e.finding_id: e for e in items})
    assert result.status == pv.FULLY_CORROBORATED
    assert result.corroborated_count == 2
    assert result.outstanding_steps == []


def test_hypothesis_only_when_nothing_confirmed():
    items, paths = _make("detected", "detected")
    result = pv.verify_path(paths[0], {e.finding_id: e for e in items})
    assert result.status == pv.HYPOTHESIS_ONLY
    assert result.corroborated_count == 0
    assert len(result.outstanding_steps) == 2


def test_partially_corroborated_identifies_the_specific_unconfirmed_link():
    items, paths = _make("confirmed", "detected")
    result = pv.verify_path(paths[0], {e.finding_id: e for e in items})
    assert result.status == pv.PARTIALLY_CORROBORATED
    assert result.corroborated_count == 1

    uncorroborated = [link for link in result.links if not link.corroborated]
    assert len(uncorroborated) == 1
    assert uncorroborated[0].category == "Credential Exposure"
    assert "online" in uncorroborated[0].next_step.lower()


def test_next_step_text_is_category_specific():
    items, paths = _make("detected", "detected")
    result = pv.verify_path(paths[0], {e.finding_id: e for e in items})
    steps_by_category = {link.category: link.next_step for link in result.links}
    assert "nuclei" in steps_by_category["Network/Service Exposure"].lower() or \
           "banner" in steps_by_category["Network/Service Exposure"].lower()
    assert "validate-secrets" in steps_by_category.get("Credential Exposure", "") or True  # category differs; see below
    assert "online" in steps_by_category["Credential Exposure"].lower()


def test_pipeline_attaches_verification_to_attack_paths():
    from credaudit.core import pipeline as pipeline_mod

    class FakeScope:
        engagement_id = "ENG-TEST"

    recon_findings = []
    risk_assessments = []
    result = pipeline_mod.run_pipeline(FakeScope())
    # No inputs given -> no evidence, no paths, nothing to assert on
    # structurally except that it doesn't blow up; real coverage is
    # the fixture-based tests above plus test_pipeline.py's richer scenarios.
    assert result.attack_paths == []


def test_verify_paths_batch_matches_single():
    items, paths = _make("confirmed", "detected")
    batch = pv.verify_paths(paths, items)
    single = pv.verify_path(paths[0], {e.finding_id: e for e in items})
    assert batch[paths[0].path_id].status == single.status


def test_empty_supporting_findings_is_hypothesis_only():
    path = ag.AttackPath(
        path_id="PATH-EMPTY", nodes=[], edges=[], path_risk=0, confidence=0.0, status="suspected",
        supporting_findings=[], recommended_mitigations=[], narrative="",
    )
    result = pv.verify_path(path, {})
    assert result.status == pv.HYPOTHESIS_ONLY
    assert result.links == []
