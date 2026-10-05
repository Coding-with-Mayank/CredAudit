import json

from credaudit.audit_log import AuditLog, verify_manifest
from credaudit.core import authorization


def make_log(path, engagement_id="ENG-1", n=3):
    log = AuditLog(path, engagement_id=engagement_id)
    for i in range(n):
        log.record("cli", f"action_{i}", {"i": i})
    return log


def test_unsigned_manifest_detects_ok_log(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    log = make_log(log_path)
    log.finalize()
    result = verify_manifest(log_path)
    assert result["ok"] is True
    assert result["chain_valid"] is True
    assert result["manifest_found"] is True


def test_no_manifest_present_is_reported_but_chain_still_checked(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    make_log(log_path)  # no finalize()
    result = verify_manifest(log_path)
    assert result["manifest_found"] is False
    assert result["ok"] is True  # chain itself is fine
    assert result["count_matches"] is None


def test_truncation_detected_via_manifest_even_though_chain_still_valid(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    log = make_log(log_path, n=5)
    log.finalize()

    lines = log_path.read_text().splitlines()
    log_path.write_text("\n".join(lines[:-1]) + "\n")  # drop the last entry

    truncated_log = AuditLog(log_path)
    assert truncated_log.verify_chain() is True  # chain alone doesn't notice

    result = verify_manifest(log_path)
    assert result["chain_valid"] is True
    assert result["count_matches"] is False
    assert result["hash_matches"] is False
    assert result["ok"] is False  # but the manifest does


def test_edited_entry_breaks_chain(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    log = make_log(log_path)
    log.finalize()

    lines = log_path.read_text().splitlines()
    entry = json.loads(lines[1])
    entry["detail"]["i"] = 999  # edit without recomputing hash
    lines[1] = json.dumps(entry)
    log_path.write_text("\n".join(lines) + "\n")

    assert AuditLog(log_path).verify_chain() is False
    assert verify_manifest(log_path)["ok"] is False


def test_reordered_entries_break_chain(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    make_log(log_path, n=3)
    lines = log_path.read_text().splitlines()
    lines[0], lines[1] = lines[1], lines[0]
    log_path.write_text("\n".join(lines) + "\n")
    assert AuditLog(log_path).verify_chain() is False


def test_signed_manifest_verifies_with_correct_key(tmp_path):
    priv, pub = authorization.generate_keypair()
    log_path = tmp_path / "audit.jsonl"
    log = make_log(log_path)
    log.finalize(private_key_pem=priv)

    result = verify_manifest(log_path, trusted_public_key=pub)
    assert result["signature_valid"] is True
    assert result["ok"] is True


def test_signed_manifest_fails_with_wrong_key(tmp_path):
    priv, _ = authorization.generate_keypair()
    _, wrong_pub = authorization.generate_keypair()
    log_path = tmp_path / "audit.jsonl"
    log = make_log(log_path)
    log.finalize(private_key_pem=priv)

    result = verify_manifest(log_path, trusted_public_key=wrong_pub)
    assert result["signature_valid"] is False
    assert result["ok"] is False


def test_entries_carry_engagement_id_and_actor(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    log = AuditLog(log_path, engagement_id="ENG-42")
    log.record("cli", "engagement_start", {}, target="10.0.0.1", result="ok")
    entry = json.loads(log_path.read_text().splitlines()[0])
    assert entry["engagement_id"] == "ENG-42"
    assert entry["target"] == "10.0.0.1"
    assert entry["result"] == "ok"
    assert "actor" in entry and entry["actor"]


def test_entry_count(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    log = make_log(log_path, n=4)
    assert log.entry_count() == 4
