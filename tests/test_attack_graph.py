from credaudit.modules.risk_engine import RiskAssessment
from credaudit.modules.js_intel import JSIntelResult, SecretFinding
from credaudit.modules.attack_graph import build_attack_graph


def test_empty_inputs_produce_empty_graph():
    graph = build_attack_graph()
    assert graph.nodes == []
    assert graph.edges == []


def test_high_risk_finding_becomes_exposure_node():
    assessment = RiskAssessment(
        target="10.0.0.1", service="ssh", indicators=["old_version"],
        risk_level="High", reasoning="test",
    )
    graph = build_attack_graph(risk_assessments=[assessment])
    exposure_nodes = [n for n in graph.nodes if n.stage == "exposure"]
    assert len(exposure_nodes) == 1
    assert exposure_nodes[0].verified is True


def test_low_risk_finding_does_not_become_exposure_node():
    assessment = RiskAssessment(
        target="10.0.0.1", service="ssh", indicators=[],
        risk_level="Low", reasoning="test",
    )
    graph = build_attack_graph(risk_assessments=[assessment])
    assert graph.nodes == []


def test_secret_always_terminates_in_manual_verification():
    result = JSIntelResult(
        source="main.js",
        secrets=[SecretFinding(kind="generic_secret", value="x" * 20, masked="xx**xx")],
    )
    graph = build_attack_graph(js_intel_results=[result])
    verification_nodes = [n for n in graph.nodes if n.stage == "needs_verification"]
    assert len(verification_nodes) == 1
    assert verification_nodes[0].verified is False


def test_no_node_in_the_graph_claims_verified_access():
    """The core safety invariant: nothing past 'credential_leak' is ever
    marked verified=True, no matter what secret type is found. Detecting
    a secret is real evidence; access is never assumed."""
    result = JSIntelResult(
        source="main.js",
        secrets=[
            SecretFinding(kind="aws_access_key", value="AKIA" + "X" * 16, masked="AKIA****XXXX"),
            SecretFinding(kind="generic_secret", value="y" * 20, masked="yy**yy"),
        ],
    )
    graph = build_attack_graph(js_intel_results=[result])
    for node in graph.nodes:
        if node.stage in ("potential_access", "needs_verification"):
            assert node.verified is False, f"{node.label} must not be marked verified"


def test_aws_key_gets_potential_access_stage():
    result = JSIntelResult(
        source="main.js",
        secrets=[SecretFinding(kind="aws_access_key", value="AKIA" + "X" * 16, masked="m")],
    )
    graph = build_attack_graph(js_intel_results=[result])
    access_nodes = [n for n in graph.nodes if n.stage == "potential_access"]
    assert len(access_nodes) == 1
    assert "AWS" in access_nodes[0].label


def test_exposure_links_to_secret_only_on_target_match():
    assessment = RiskAssessment(
        target="acme.example", service="http", indicators=["secrets_exposed"],
        risk_level="High", reasoning="test",
    )
    matching = JSIntelResult(
        source="https://acme.example/main.js",
        secrets=[SecretFinding(kind="generic_secret", value="z" * 20, masked="m")],
    )
    non_matching = JSIntelResult(
        source="https://other.example/main.js",
        secrets=[SecretFinding(kind="generic_secret", value="w" * 20, masked="m")],
    )
    graph = build_attack_graph(risk_assessments=[assessment], js_intel_results=[matching, non_matching])

    exposure_id = next(n.id for n in graph.nodes if n.stage == "exposure")
    linked_targets = {e.target for e in graph.edges if e.source == exposure_id}
    assert len(linked_targets) == 1  # only the matching source got linked
