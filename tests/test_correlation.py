from credaudit.core import evidence as ev
from credaudit.core import correlation as corr


def e(category, status="detected", confidence=0.8, risk_score=50, finding_id=None, asset="host1"):
    ev.reset_finding_id_counter() if finding_id is None else None
    return ev.Evidence(
        finding_id=finding_id or ev.next_finding_id("ENG-1"), engagement_id="ENG-1", asset=asset,
        category=category, severity="High", risk_score=risk_score, confidence=confidence,
        source="test", evidence="x", status=status,
    )


def test_no_chain_below_two_categories():
    items = [e("Network/Service Exposure", finding_id="CA-1")]
    assert corr.correlate(items) == []


def test_two_category_chain_detected():
    items = [e("Network/Service Exposure", finding_id="CA-1"), e("Credential Exposure", finding_id="CA-2")]
    chains = corr.correlate(items)
    assert len(chains) == 1
    c = chains[0]
    assert c.asset == "host1"
    assert set(c.related_finding_ids) == {"CA-1", "CA-2"}
    assert "Internet-facing" in c.explanation


def test_three_category_pattern_preferred_over_subsets():
    items = [
        e("Network/Service Exposure", finding_id="CA-1"),
        e("Secret Exposure", finding_id="CA-2"),
        e("Credential Exposure", finding_id="CA-3"),
    ]
    chains = corr.correlate(items)
    assert len(chains) == 1
    assert set(chains[0].categories) == {"Network/Service Exposure", "Secret Exposure", "Credential Exposure"}


def test_different_assets_dont_merge():
    items = [
        e("Network/Service Exposure", finding_id="CA-1", asset="host1"),
        e("Credential Exposure", finding_id="CA-2", asset="host2"),
    ]
    assert corr.correlate(items) == []


def test_status_confirmed_only_when_all_confirmed():
    items = [
        e("Network/Service Exposure", finding_id="CA-1", status="confirmed"),
        e("Credential Exposure", finding_id="CA-2", status="confirmed"),
    ]
    assert corr.correlate(items)[0].status == "confirmed"


def test_status_downgrades_when_one_link_is_only_detected():
    items = [
        e("Network/Service Exposure", finding_id="CA-1", status="confirmed"),
        e("Credential Exposure", finding_id="CA-2", status="detected"),
    ]
    assert corr.correlate(items)[0].status == "potential_relationship"


def test_combined_risk_is_at_least_the_max_individual_score():
    items = [
        e("Network/Service Exposure", finding_id="CA-1", risk_score=40),
        e("Credential Exposure", finding_id="CA-2", risk_score=90),
    ]
    c = corr.correlate(items)[0]
    assert c.combined_risk_score >= 90
    assert c.combined_risk_score <= 100


def test_combined_risk_bonus_is_capped():
    items = [e("Network/Service Exposure", finding_id="CA-1", risk_score=70)] + [
        e("Credential Exposure", finding_id=f"CA-{i}", risk_score=70) for i in range(2, 10)
    ]
    c = corr.correlate(items)[0]
    assert c.combined_risk_score <= 70 + 15


def test_remediation_deduplicated():
    items = [
        ev.Evidence(finding_id="CA-1", engagement_id="ENG-1", asset="h", category="Network/Service Exposure",
                     severity="High", risk_score=60, confidence=0.8, source="t", evidence="x", remediation="Patch it."),
        ev.Evidence(finding_id="CA-2", engagement_id="ENG-1", asset="h", category="Credential Exposure",
                     severity="High", risk_score=60, confidence=0.8, source="t", evidence="x", remediation="Patch it."),
    ]
    c = corr.correlate(items)[0]
    assert c.remediation.count("Patch it.") == 1
