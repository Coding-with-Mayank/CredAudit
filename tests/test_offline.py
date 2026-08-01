from unittest.mock import patch

from credaudit.modules import offline


def test_count_lines(tmp_path):
    f = tmp_path / "hashes.txt"
    f.write_text("hash1\nhash2\nhash3\n\n")  # trailing blank line shouldn't count
    assert offline._count_lines(f) == 3


def test_count_lines_missing_file(tmp_path):
    assert offline._count_lines(tmp_path / "nope.txt") == 0


def test_offline_audit_result_weak_ratio():
    result = offline.OfflineAuditResult(
        out_file=None, total_hashes=100, cracked_count=25
    )
    assert result.weak_ratio == 0.25


def test_offline_audit_result_weak_ratio_zero_hashes():
    result = offline.OfflineAuditResult(out_file=None, total_hashes=0, cracked_count=0)
    assert result.weak_ratio == 0.0


def test_run_offline_audit_missing_binary_raises(tmp_path):
    from credaudit.scope import Scope
    from credaudit.audit_log import AuditLog
    from datetime import date

    scope = Scope(
        engagement_id="T", client_name="C", authorized_by="A",
        start_date=date(2020, 1, 1), end_date=date(2030, 1, 1),
        targets=["1.2.3.4"], allowed_modules=["offline"],
        max_requests_per_minute=10, confirm_online_testing=True,
        source_path=tmp_path, source_sha256="x",
    )
    audit_log = AuditLog(tmp_path / "audit_log.jsonl")

    with patch("shutil.which", return_value=None):
        try:
            offline.run_offline_audit(
                scope, tmp_path / "h.txt", tmp_path / "w.txt", "1000",
                audit_log, tmp_path / "out",
            )
            assert False, "expected OfflineAuditError"
        except offline.OfflineAuditError:
            pass
