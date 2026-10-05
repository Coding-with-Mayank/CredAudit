"""Tests for the optional persistent findings API (`pip install credaudit[api]`).

Skipped entirely (not failed) when fastapi isn't installed, exactly
like test_llm_summary.py's handling of the optional `anthropic`
package -- the base `pip install .` + `pytest` workflow never needs
these dependencies and must never fail because of their absence.
"""
import os

import pytest

fastapi = pytest.importorskip("fastapi")

os.environ.setdefault("CREDAUDIT_JWT_SECRET", "test-only-secret-at-least-32-bytes-long!!")

from fastapi.testclient import TestClient  # noqa: E402
from sqlmodel import Session, SQLModel, create_engine  # noqa: E402

from credaudit.api.app import create_app  # noqa: E402
from credaudit.api.db import Role, User, get_session, init_db  # noqa: E402
from credaudit.api.security import hash_password  # noqa: E402


@pytest.fixture
def engine():
    # In-memory SQLite, shared across connections within one test via
    # StaticPool -- a fresh, fully isolated database per test.
    from sqlalchemy.pool import StaticPool

    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(eng)
    return eng


@pytest.fixture
def client(engine):
    app = create_app()

    def _get_session_override():
        with Session(engine) as session:
            yield session

    app.dependency_overrides[get_session] = _get_session_override
    return TestClient(app)


@pytest.fixture
def admin_headers(engine, client):
    with Session(engine) as session:
        session.add(User(username="admin", hashed_password=hash_password("adminpass123"), role=Role.admin))
        session.commit()
    token = client.post("/auth/token", data={"username": "admin", "password": "adminpass123"}).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def viewer_headers(engine, client, admin_headers):
    client.post("/users", headers=admin_headers, json={"username": "viewer1", "password": "viewerpass123", "role": "viewer"})
    token = client.post("/auth/token", data={"username": "viewer1", "password": "viewerpass123"}).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


SAMPLE_EVIDENCE = [{
    "finding_id": "ENG-0001", "engagement_id": "TEST", "asset": "repo", "category": "Secret Exposure",
    "severity": "Critical", "risk_score": 90, "confidence": 1.0, "source": "secret_analysis",
    "evidence": "github_token detected", "remediation": "rotate", "status": "confirmed",
}]


def test_health_needs_no_auth(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_login_rejects_wrong_password(client, admin_headers):
    r = client.post("/auth/token", data={"username": "admin", "password": "wrong"})
    assert r.status_code == 401


def test_unauthenticated_request_is_rejected(client):
    assert client.get("/engagements").status_code == 401


def test_admin_can_create_user(client, admin_headers):
    r = client.post("/users", headers=admin_headers, json={"username": "x", "password": "pw12345678", "role": "analyst"})
    assert r.status_code == 201
    assert r.json()["role"] == "analyst"


def test_viewer_cannot_create_user(client, viewer_headers):
    r = client.post("/users", headers=viewer_headers, json={"username": "y", "password": "pw12345678"})
    assert r.status_code == 403


def test_duplicate_username_rejected(client, admin_headers):
    client.post("/users", headers=admin_headers, json={"username": "dup", "password": "pw12345678"})
    r = client.post("/users", headers=admin_headers, json={"username": "dup", "password": "pw12345678"})
    assert r.status_code == 409


def test_admin_can_import_findings(client, admin_headers):
    r = client.post("/engagements/TEST/import", headers=admin_headers, json={"evidence": SAMPLE_EVIDENCE})
    assert r.status_code == 200
    assert r.json() == {"imported": 1, "skipped_existing": 0}


def test_viewer_cannot_import_findings(client, viewer_headers):
    r = client.post("/engagements/TEST/import", headers=viewer_headers, json={"evidence": SAMPLE_EVIDENCE})
    assert r.status_code == 403


def test_viewer_can_read_findings(client, admin_headers, viewer_headers):
    client.post("/engagements/TEST/import", headers=admin_headers, json={"evidence": SAMPLE_EVIDENCE})
    r = client.get("/engagements/TEST/findings", headers=viewer_headers)
    assert r.status_code == 200
    assert len(r.json()) == 1
    assert r.json()[0]["severity"] == "Critical"


def test_import_is_idempotent_and_does_not_clobber_workflow_status(client, admin_headers):
    client.post("/engagements/TEST/import", headers=admin_headers, json={"evidence": SAMPLE_EVIDENCE})
    finding_id = client.get("/engagements/TEST/findings", headers=admin_headers).json()[0]["id"]
    client.patch(f"/findings/{finding_id}", headers=admin_headers, json={"workflow_status": "remediated"})

    r = client.post("/engagements/TEST/import", headers=admin_headers, json={"evidence": SAMPLE_EVIDENCE})
    assert r.json() == {"imported": 0, "skipped_existing": 1}

    row = client.get(f"/findings/{finding_id}", headers=admin_headers).json()
    assert row["workflow_status"] == "remediated"  # NOT reset to "open" by the re-import


def test_viewer_cannot_patch_finding(client, admin_headers, viewer_headers):
    client.post("/engagements/TEST/import", headers=admin_headers, json={"evidence": SAMPLE_EVIDENCE})
    finding_id = client.get("/engagements/TEST/findings", headers=admin_headers).json()[0]["id"]
    r = client.patch(f"/findings/{finding_id}", headers=viewer_headers, json={"workflow_status": "remediated"})
    assert r.status_code == 403


def test_patch_records_who_and_when(client, admin_headers):
    client.post("/engagements/TEST/import", headers=admin_headers, json={"evidence": SAMPLE_EVIDENCE})
    finding_id = client.get("/engagements/TEST/findings", headers=admin_headers).json()[0]["id"]
    r = client.patch(
        f"/findings/{finding_id}", headers=admin_headers,
        json={"workflow_status": "accepted_risk", "workflow_note": "compensating control in place"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["updated_by"] == "admin"
    assert body["updated_at"] is not None
    assert body["workflow_note"] == "compensating control in place"


def test_patch_rejects_invalid_workflow_status(client, admin_headers):
    client.post("/engagements/TEST/import", headers=admin_headers, json={"evidence": SAMPLE_EVIDENCE})
    finding_id = client.get("/engagements/TEST/findings", headers=admin_headers).json()[0]["id"]
    r = client.patch(f"/findings/{finding_id}", headers=admin_headers, json={"workflow_status": "not_a_real_status"})
    assert r.status_code == 422


def test_findings_filterable_by_severity(client, admin_headers):
    evidence = SAMPLE_EVIDENCE + [{
        "finding_id": "ENG-0002", "engagement_id": "TEST", "asset": "repo", "category": "Credential Exposure",
        "severity": "Low", "risk_score": 10, "confidence": 0.5, "source": "credential_analysis",
        "evidence": "weak password", "remediation": "rotate", "status": "detected",
    }]
    client.post("/engagements/TEST/import", headers=admin_headers, json={"evidence": evidence})
    r = client.get("/engagements/TEST/findings", headers=admin_headers, params={"severity": "Low"})
    assert len(r.json()) == 1
    assert r.json()[0]["finding_id"] == "ENG-0002"


def test_summary_counts_by_severity_and_workflow_status(client, admin_headers):
    client.post("/engagements/TEST/import", headers=admin_headers, json={"evidence": SAMPLE_EVIDENCE})
    r = client.get("/engagements/TEST/summary", headers=admin_headers)
    assert r.json() == {"total": 1, "by_severity": {"Critical": 1}, "by_workflow_status": {"open": 1}}


def test_unknown_engagement_is_404(client, admin_headers):
    r = client.get("/engagements/NOPE/findings", headers=admin_headers)
    assert r.status_code == 404


def test_invalid_evidence_object_is_422(client, admin_headers):
    bad = [{"finding_id": "X", "severity": "NOT_A_SEVERITY"}]
    r = client.post("/engagements/TEST/import", headers=admin_headers, json={"evidence": bad})
    assert r.status_code == 422


def test_users_me_returns_the_authenticated_user(client, viewer_headers):
    r = client.get("/users/me", headers=viewer_headers)
    assert r.status_code == 200
    assert r.json()["username"] == "viewer1"
    assert r.json()["role"] == "viewer"
