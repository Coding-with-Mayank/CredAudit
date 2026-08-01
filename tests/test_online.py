from datetime import date
from pathlib import Path

import pytest

from credaudit.audit_log import AuditLog
from credaudit.modules import online
from credaudit.scope import Scope, ScopeViolation


def make_scope(tmp_path, **overrides):
    from datetime import timedelta
    defaults = dict(
        engagement_id="T-ONLINE", client_name="C", authorized_by="A",
        start_date=date.today() - timedelta(days=1),
        end_date=date.today() + timedelta(days=1),
        targets=["10.0.0.5"], allowed_modules=["online"],
        max_requests_per_minute=10, confirm_online_testing=True,
        source_path=tmp_path, source_sha256="x",
    )
    defaults.update(overrides)
    return Scope(**defaults)


def test_build_command_hydra(tmp_path):
    cmd = online._build_command(
        "hydra", tmp_path / "u.txt", tmp_path / "p.txt", "10.0.0.5", "ssh", 1, tmp_path / "out.log"
    )
    assert cmd[0] == "hydra"
    assert "-L" in cmd and "-P" in cmd
    assert cmd[-2:] == ["10.0.0.5", "ssh"]


def test_build_command_medusa(tmp_path):
    cmd = online._build_command(
        "medusa", tmp_path / "u.txt", tmp_path / "p.txt", "10.0.0.5", "ssh", 1, tmp_path / "out.log"
    )
    assert cmd[0] == "medusa"
    assert "-h" in cmd and "-M" in cmd


def test_build_command_ncrack(tmp_path):
    cmd = online._build_command(
        "ncrack", tmp_path / "u.txt", tmp_path / "p.txt", "10.0.0.5", "ssh", 1, tmp_path / "out.log"
    )
    assert cmd[0] == "ncrack"
    assert cmd[-1] == "ssh://10.0.0.5"


def test_build_command_unsupported_backend(tmp_path):
    with pytest.raises(online.OnlineTestError):
        online._build_command(
            "made-up-tool", tmp_path / "u.txt", tmp_path / "p.txt", "10.0.0.5", "ssh", 1, tmp_path / "out.log"
        )


def test_summarize_log_hydra_format(tmp_path):
    log = tmp_path / "hydra.log"
    log.write_text(
        "[22][ssh] host: 10.0.0.5   login: alice   password: hunter2\n"
        "some other unrelated line\n"
    )
    summary = online.summarize_log(log, accounts_tested=48, backend="hydra")
    assert summary.valid_pairs_found == 1
    assert summary.accounts_tested == 48


def test_summarize_log_medusa_format(tmp_path):
    log = tmp_path / "medusa.log"
    log.write_text("ACCOUNT FOUND: [ssh] Host: 10.0.0.5 User: bob Password: letmein [SUCCESS]\n")
    summary = online.summarize_log(log, accounts_tested=10, backend="medusa")
    assert summary.valid_pairs_found == 1


def test_summarize_log_missing_file_returns_zero(tmp_path):
    summary = online.summarize_log(tmp_path / "nope.log", accounts_tested=5, backend="hydra")
    assert summary.valid_pairs_found == 0


def test_run_spray_blocks_out_of_scope_target_before_touching_backend(tmp_path):
    scope = make_scope(tmp_path)
    audit_log = AuditLog(tmp_path / "audit_log.jsonl")
    cfg = online.SprayConfig(protocol="ssh", usernames=["alice"], passwords=["x"], backend="hydra")

    with pytest.raises(ScopeViolation):
        online.run_spray(scope, "8.8.8.8", cfg, audit_log, tmp_path / "out")


def test_run_spray_blocks_disallowed_module(tmp_path):
    scope = make_scope(tmp_path, allowed_modules=["recon"])  # online not allowed
    audit_log = AuditLog(tmp_path / "audit_log.jsonl")
    cfg = online.SprayConfig(protocol="ssh", usernames=["alice"], passwords=["x"], backend="hydra")

    with pytest.raises(ScopeViolation):
        online.run_spray(scope, "10.0.0.5", cfg, audit_log, tmp_path / "out")


def test_run_spray_unsupported_backend_rejected_before_binary_check(tmp_path):
    scope = make_scope(tmp_path)
    audit_log = AuditLog(tmp_path / "audit_log.jsonl")
    cfg = online.SprayConfig(protocol="ssh", usernames=["alice"], passwords=["x"], backend="not-a-real-tool")

    with pytest.raises(online.OnlineTestError):
        online.run_spray(scope, "10.0.0.5", cfg, audit_log, tmp_path / "out")
