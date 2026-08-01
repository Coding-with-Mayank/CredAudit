from credaudit.audit_log import AuditLog


def test_chain_valid_after_normal_writes(tmp_path):
    log = AuditLog(tmp_path / "audit_log.jsonl")
    log.record("cli", "engagement_start", {"scope_sha256": "abc123"})
    log.record("recon", "scan_start", {"targets": 3})
    log.record("recon", "scan_end", {"findings": 2})
    assert log.verify_chain() is True


def test_chain_detects_tampering(tmp_path):
    path = tmp_path / "audit_log.jsonl"
    log = AuditLog(path)
    log.record("cli", "engagement_start", {"scope_sha256": "abc123"})
    log.record("offline", "crack_end", {"cracked_count": 0})

    # tamper with the first line's action field after the fact
    lines = path.read_text().splitlines()
    lines[0] = lines[0].replace("engagement_start", "TAMPERED")
    path.write_text("\n".join(lines) + "\n")

    tampered_log = AuditLog(path)
    assert tampered_log.verify_chain() is False


def test_empty_log_is_valid(tmp_path):
    log = AuditLog(tmp_path / "does_not_exist_yet.jsonl")
    assert log.verify_chain() is True
