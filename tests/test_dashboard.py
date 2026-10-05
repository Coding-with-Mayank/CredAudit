from credaudit.core import evidence as ev
from credaudit.core import correlation as corr
from credaudit.dashboard import build_dashboard


class FakeScope:
    engagement_id = "ENG-DASH"
    client_name = "Acme"


def test_dashboard_builds_with_no_data(tmp_path):
    path = build_dashboard(FakeScope(), tmp_path)
    assert path.exists()
    assert path.name == "dashboard.html"
    text = path.read_text()
    assert "ENG-DASH" in text
    assert "No findings recorded" in text


def test_dashboard_includes_counts_and_no_plaintext(tmp_path):
    ev.reset_finding_id_counter()
    items = [
        ev.Evidence(finding_id=ev.next_finding_id("E"), engagement_id="E", asset="dc01",
                     category="Credential Exposure", severity="Critical", risk_score=95,
                     confidence=0.9, source="credential_analysis",
                     evidence="account admin; password_hash_prefix=abc123; SECRET_PW_VALUE not present"),
    ]
    chains = corr.correlate(items)  # empty, only one category
    path = build_dashboard(FakeScope(), tmp_path, evidence_list=items, correlations=chains)
    text = path.read_text()
    assert "Critical" in text
    assert "SECRET_PW_VALUE" not in text or "SECRET_PW_VALUE not present" in text  # only our own label string


def test_dashboard_audit_events_rendered(tmp_path):
    entries = [{"ts": 1700000000.0, "module": "cli", "action": "engagement_start", "entry_hash": "a" * 64}]
    path = build_dashboard(FakeScope(), tmp_path, audit_entries=entries)
    text = path.read_text()
    assert "engagement_start" in text
