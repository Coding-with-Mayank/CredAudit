from credaudit.analyzers import secrets as sa


def types(findings):
    return {f.secret_type for f in findings}


def test_detects_common_secret_types():
    text = """
    AWS=AKIAABCDEFGHIJKLMNOP
    -----BEGIN RSA PRIVATE KEY-----
    db = "postgres://admin:S3cretPass@db.internal:5432/prod"
    token = ghp_abcdefghijklmnopqrstuvwxyz0123456789
    jwt = eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456
    Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456
    slack = xoxb-1234567890-abcdefghij
    """
    found = types(sa.scan_text(text, "t"))
    assert {"aws_access_key", "private_key", "database_connection_string",
            "github_token", "jwt", "bearer_token", "slack_token"} <= found


def test_clean_text_has_no_findings():
    assert sa.scan_text("nothing to see here, just prose and numbers 12345", "t") == []


def test_duplicates_collapsed_and_line_numbers():
    text = "x\nAKIAABCDEFGHIJKLMNOP\nAKIAABCDEFGHIJKLMNOP\n"
    f = sa.scan_text(text, "t")
    assert len(f) == 1 and f[0].line_number == 2


def test_redacted_hides_value():
    f = sa.scan_text("AKIAABCDEFGHIJKLMNOP", "t")[0]
    assert "BCDEFGHIJKL" not in f.redacted
    assert f.redacted.startswith("AKIA")


def test_scan_file_and_directory(tmp_path):
    (tmp_path / "a.js").write_text('const k = "AKIAABCDEFGHIJKLMNOP";')
    (tmp_path / "b.png").write_text("AKIAABCDEFGHIJKLMNOP")  # wrong extension: skipped
    sub = tmp_path / "sub"; sub.mkdir()
    (sub / "c.env").write_text("password = 'hunter2hunter2'")
    found = sa.scan_directory(tmp_path)
    assert {"aws_access_key", "generic_secret"} <= types(found)
    assert len(found) == 2
    assert sa.scan_file(tmp_path / "missing.js") == []


def test_oversized_file_skipped(tmp_path, monkeypatch):
    p = tmp_path / "big.txt"; p.write_text("AKIAABCDEFGHIJKLMNOP")
    monkeypatch.setattr(sa, "MAX_FILE_BYTES", 5)
    assert sa.scan_file(p) == []


def test_to_evidence_redacts_and_severity_matches_risk():
    findings = sa.scan_text('db="postgres://u:Passw0rdX@h/db"', "app.py")
    evs = sa.to_evidence(findings, "ENG-1", "app")
    assert "Passw0rdX" not in evs[0].evidence
    assert evs[0].category == "Secret Exposure"
    assert findings[0].display_severity == evs[0].severity  # no contradictory severities


def test_display_severity_falls_back_before_to_evidence():
    f = sa.scan_text("AKIAABCDEFGHIJKLMNOP", "t")[0]
    assert f.display_severity == f.severity
