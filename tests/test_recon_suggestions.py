from credaudit.modules import recon


def test_suggests_ssh_target():
    findings = [{"template-id": "ssh-detect", "host": "10.0.0.5"}]
    suggestions = recon.suggest_online_targets(findings)
    assert len(suggestions) == 1
    assert suggestions[0]["target"] == "10.0.0.5"
    assert suggestions[0]["protocol"] == "ssh"


def test_ignores_findings_without_host():
    findings = [{"template-id": "ssh-detect"}]
    assert recon.suggest_online_targets(findings) == []


def test_ignores_non_auth_findings():
    findings = [{"template-id": "generic-tech-detect", "host": "10.0.0.5"}]
    assert recon.suggest_online_targets(findings) == []


def test_deduplicates_same_target_and_protocol():
    findings = [
        {"template-id": "ssh-detect", "host": "10.0.0.5"},
        {"template-id": "ssh-version", "host": "10.0.0.5"},
    ]
    suggestions = recon.suggest_online_targets(findings)
    assert len(suggestions) == 1


def test_handles_multiple_protocols_same_host():
    findings = [
        {"template-id": "ssh-detect", "host": "10.0.0.5"},
        {"template-id": "ftp-anon-login", "host": "10.0.0.5"},
    ]
    suggestions = recon.suggest_online_targets(findings)
    protocols = {s["protocol"] for s in suggestions}
    assert protocols == {"ssh", "ftp"}
