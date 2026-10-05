from credaudit.core import evidence as ev
from credaudit.core import correlation as corr
from credaudit.attack_paths import graph as ag


def build_chain():
    ev.reset_finding_id_counter()
    items = [
        ev.Evidence(finding_id="CA-0001", engagement_id="ENG-1", asset="dc01", category="Network/Service Exposure",
                     severity="High", risk_score=70, confidence=0.8, source="recon", evidence="ssh exposed",
                     remediation="Patch SSH."),
        ev.Evidence(finding_id="CA-0002", engagement_id="ENG-1", asset="dc01", category="Credential Exposure",
                     severity="Critical", risk_score=90, confidence=0.9, source="credential_analysis",
                     evidence="weak admin password", remediation="Rotate password."),
    ]
    return items, corr.correlate(items)


def test_build_attack_paths_basic_structure():
    items, chains = build_chain()
    paths = ag.build_attack_paths(items, chains)
    assert len(paths) == 1
    p = paths[0]
    assert p.nodes[0].kind == "internet"
    assert p.nodes[1].kind == "asset" and p.nodes[1].label == "dc01"
    finding_nodes = [n for n in p.nodes if n.kind == "finding"]
    assert {n.finding_id for n in finding_nodes} == {"CA-0001", "CA-0002"}


def test_path_risk_and_confidence_match_correlation():
    items, chains = build_chain()
    paths = ag.build_attack_paths(items, chains)
    assert paths[0].path_risk == chains[0].combined_risk_score
    assert paths[0].confidence == chains[0].confidence
    assert paths[0].status == chains[0].status


def test_path_ordering_is_network_before_credential():
    items, chains = build_chain()
    paths = ag.build_attack_paths(items, chains)
    finding_labels = [n.finding_id for n in paths[0].nodes if n.kind == "finding"]
    assert finding_labels == ["CA-0001", "CA-0002"]


def test_no_correlations_means_no_paths():
    items, _ = build_chain()
    assert ag.build_attack_paths(items, []) == []


def test_mitigations_come_from_correlation_remediation():
    items, chains = build_chain()
    paths = ag.build_attack_paths(items, chains)
    assert paths[0].recommended_mitigations == [chains[0].remediation]
