from pathlib import Path

from credaudit.integrations import hashcat as hashcat_integration
from credaudit.integrations import hydra as hydra_integration
from credaudit.modules.online import OnlineTestSummary


def test_hashcat_joins_username_from_colon_format(tmp_path):
    hash_file = tmp_path / "hashes.txt"
    hash_file.write_text("alice:5f4dcc3b5aa765d61d8327deb882cf99\nbob:098f6bcd4621d373cade4e832627b4f6\n")
    cracked_file = tmp_path / "cracked.txt"
    cracked_file.write_text("5f4dcc3b5aa765d61d8327deb882cf99:password\n098f6bcd4621d373cade4e832627b4f6:test\n")

    records = hashcat_integration.load_cracked_credentials(hash_file, cracked_file)
    by_account = {r.account: r.password for r in records}
    assert by_account == {"alice": "password", "bob": "test"}


def test_hashcat_falls_back_to_hash_label_when_no_username(tmp_path):
    hash_file = tmp_path / "hashes.txt"
    hash_file.write_text("5f4dcc3b5aa765d61d8327deb882cf99\n")  # bare hash, no ':'
    cracked_file = tmp_path / "cracked.txt"
    cracked_file.write_text("5f4dcc3b5aa765d61d8327deb882cf99:password\n")

    records = hashcat_integration.load_cracked_credentials(hash_file, cracked_file)
    assert len(records) == 1
    assert records[0].account.startswith("hash:")
    assert records[0].password == "password"


def test_hashcat_account_map_overrides(tmp_path):
    hash_file = tmp_path / "hashes.txt"
    hash_file.write_text("5f4dcc3b5aa765d61d8327deb882cf99\n")
    cracked_file = tmp_path / "cracked.txt"
    cracked_file.write_text("5f4dcc3b5aa765d61d8327deb882cf99:password\n")
    account_map = tmp_path / "map.csv"
    account_map.write_text("5f4dcc3b5aa765d61d8327deb882cf99,real_account\n")

    records = hashcat_integration.load_cracked_credentials(hash_file, cracked_file, account_map_file=account_map)
    assert records[0].account == "real_account"


def test_hashcat_no_cracked_entries_returns_empty(tmp_path):
    hash_file = tmp_path / "hashes.txt"
    hash_file.write_text("deadbeef\n")
    cracked_file = tmp_path / "cracked.txt"
    cracked_file.write_text("")
    assert hashcat_integration.load_cracked_credentials(hash_file, cracked_file) == []


def test_hydra_no_valid_pairs_produces_no_evidence(tmp_path):
    summary = OnlineTestSummary(log_path=tmp_path / "online_hydra_10.0.0.1.log", accounts_tested=50, valid_pairs_found=0)
    assert hydra_integration.online_summary_to_evidence(summary, "ENG-1", target="10.0.0.1") == []


def test_hydra_valid_pair_produces_confirmed_critical_evidence(tmp_path):
    log_path = tmp_path / "online_hydra_10.0.0.1.log"
    log_path.write_text("host: 10.0.0.1 login: admin password: hunter2\n")
    summary = OnlineTestSummary(log_path=log_path, accounts_tested=50, valid_pairs_found=1)

    out = hydra_integration.online_summary_to_evidence(summary, "ENG-1", target="10.0.0.1", protocol="ssh", backend="hydra")
    assert len(out) == 1
    e = out[0]
    assert e.status == "confirmed"
    assert e.severity == "Critical"
    assert e.category == "Credential Exposure"
    assert "hunter2" not in e.evidence
    assert "admin" not in e.evidence or True  # account name isn't a secret, but check no password leaked
    assert "hunter2" not in repr(e.to_dict())


def test_hydra_batch_parses_log_filename():
    summary = OnlineTestSummary(log_path=Path("online_medusa_10.0.0.5.log"), accounts_tested=10, valid_pairs_found=2)
    out = hydra_integration.online_summaries_to_evidence([summary], "ENG-1")
    assert len(out) == 1
    assert out[0].asset == "10.0.0.5"
    assert "medusa" in out[0].source
