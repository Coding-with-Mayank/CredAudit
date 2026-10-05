import pytest

from credaudit.core import evidence as ev


def make(**overrides):
    base = dict(
        finding_id="CA-0001", engagement_id="ENG-1", asset="10.0.0.1",
        category="Credential Exposure", severity="High", risk_score=70,
        confidence=0.8, source="test", evidence="redacted",
    )
    base.update(overrides)
    return ev.Evidence(**base)


def test_valid_evidence_constructs_with_defaults():
    e = make()
    assert e.status == "detected"
    assert e.related_findings == []
    assert e.remediation == ""


@pytest.mark.parametrize("field,value", [
    ("severity", "Catastrophic"),
    ("status", "proven"),
    ("risk_score", 101),
    ("risk_score", -1),
    ("risk_score", 50.5),
    ("confidence", 1.5),
    ("confidence", -0.1),
])
def test_invalid_values_rejected(field, value):
    with pytest.raises(ev.EvidenceError):
        make(**{field: value})


def test_all_documented_statuses_accepted():
    for status in ("detected", "suspected", "potential_relationship", "confirmed"):
        assert make(status=status).status == status


def test_dict_roundtrip_ignores_unknown_keys():
    e = make()
    data = e.to_dict()
    data["bogus"] = 1
    again = ev.Evidence.from_dict(data)
    assert again.finding_id == e.finding_id


def test_finding_id_counter_is_sequential_and_resettable():
    ev.reset_finding_id_counter()
    assert ev.next_finding_id("X") == "CA-0001"
    assert ev.next_finding_id("X") == "CA-0002"
    ev.reset_finding_id_counter()
    assert ev.next_finding_id("X") == "CA-0001"


def test_jsonl_roundtrip(tmp_path):
    items = [make(finding_id="CA-0001"), make(finding_id="CA-0002", severity="Low", risk_score=25)]
    path = ev.write_evidence_jsonl(items, tmp_path / "sub" / "e.jsonl")
    loaded = ev.read_evidence_jsonl(path)
    assert [e.finding_id for e in loaded] == ["CA-0001", "CA-0002"]


def test_read_missing_file_returns_empty(tmp_path):
    assert ev.read_evidence_jsonl(tmp_path / "nope.jsonl") == []


def test_redact_short_values_fully_masked():
    assert ev.redact("abcd") == "****"
    assert ev.redact("") == ""


def test_redact_long_value_hides_middle():
    out = ev.redact("AKIAABCDEFGHIJKLMNOP", keep_start=4, keep_end=4, min_len_to_partial=10)
    assert out.startswith("AKIA") and out.endswith("MNOP")
    assert "ABCDEFGH" not in out
