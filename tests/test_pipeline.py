from datetime import date, timedelta

import yaml

from credaudit.analyzers.credentials import CredentialRecord
from credaudit.core import pipeline
from credaudit.modules.risk_engine import assess_service
from credaudit.scope import Scope


def make_scope(tmp_path, engagement_id="ENG-PIPE"):
    data = {
        "engagement_id": engagement_id,
        "client_name": "Acme",
        "authorized_by": "Tester",
        "start_date": date.today() - timedelta(days=1),
        "end_date": date.today() + timedelta(days=1),
        "targets": ["dc01"],
        "allowed_modules": ["recon"],
    }
    path = tmp_path / "scope.yaml"
    path.write_text(yaml.dump(data))
    return Scope.load(path)


def test_pipeline_with_only_credentials(tmp_path):
    scope = make_scope(tmp_path)
    result = pipeline.run_pipeline(
        scope, credential_records=[CredentialRecord(account="admin", password="admin")],
    )
    assert len(result.evidence) == 1
    assert result.evidence[0].category == "Credential Exposure"
    assert result.credential_findings[0].default_credential is True


def test_pipeline_correlates_across_vuln_and_credential_on_same_asset(tmp_path):
    scope = make_scope(tmp_path)
    assessment = assess_service("dc01", "ssh", ["default_creds"])
    result = pipeline.run_pipeline(
        scope,
        risk_assessments=[assessment],
        credential_records=[CredentialRecord(account="admin", password="admin")],
    )
    # vuln evidence asset is assessment.target ("dc01"); credential
    # evidence asset defaults to "credential-analysis" unless an
    # offline_result is supplied -- so without that, they land on
    # different assets and should NOT correlate.
    assets = {e.asset for e in result.evidence}
    assert "dc01" in assets
    assert len(result.correlations) == 0  # different assets, no false correlation


def test_pipeline_secret_scan(tmp_path):
    scope = make_scope(tmp_path)
    f = tmp_path / "config.js"
    f.write_text('const k = "AKIAABCDEFGHIJKLMNOP";')
    result = pipeline.run_pipeline(scope, secret_scan_paths=[str(f)])
    assert len(result.evidence) == 1
    assert result.evidence[0].category == "Secret Exposure"
    assert len(result.secret_findings) == 1


def test_pipeline_resets_ids_by_default(tmp_path):
    scope = make_scope(tmp_path)
    r1 = pipeline.run_pipeline(scope, credential_records=[CredentialRecord(account="a", password="pw1")])
    r2 = pipeline.run_pipeline(scope, credential_records=[CredentialRecord(account="b", password="pw2")])
    assert r1.evidence[0].finding_id == r2.evidence[0].finding_id == "CA-0001"


def test_pipeline_empty_input_produces_empty_result(tmp_path):
    scope = make_scope(tmp_path)
    result = pipeline.run_pipeline(scope)
    assert result.evidence == []
    assert result.correlations == []
    assert result.attack_paths == []


def test_pipeline_no_plaintext_leakage(tmp_path):
    scope = make_scope(tmp_path)
    result = pipeline.run_pipeline(
        scope, credential_records=[CredentialRecord(account="jdoe", password="S3cretPlaintext!")],
    )
    dump = repr([e.to_dict() for e in result.evidence])
    assert "S3cretPlaintext!" not in dump
