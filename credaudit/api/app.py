"""Persistent findings REST API: auth, RBAC, engagements, and
long-term findings management on top of `credaudit.api.db`.

This is additive to the CLI, not a replacement for it -- every scan
still runs exactly as before and still produces evidence.jsonl with
zero dependency on this module or a running server. What this adds is
a place for findings to live *after* a scan, across multiple scans and
multiple analysts, with a remediation-workflow status
(open/remediated/false_positive/accepted_risk) layered on top of the
scan's own confidence status, which stays untouched.

Bootstrapping the first admin user is deliberately a CLI action
(`credaudit create-user --role admin`), not an open HTTP registration
endpoint -- see `cli.py`. Opening unauthenticated self-registration on
a findings database is the kind of default that's convenient in a demo
and a real problem in production; requiring local/CLI access for the
first account (and admin-only `/users` thereafter) avoids that trade-off
entirely rather than trying to make the unauthenticated path "safe
enough."
"""
from __future__ import annotations

import json
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Query, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel import Session, select

from . import ingest, schemas
from .db import Engagement, Role, StoredFinding, WORKFLOW_STATUSES, get_session, init_db
from .security import authenticate_user, create_access_token, get_current_user, require_role


@asynccontextmanager
async def _lifespan(app: FastAPI):
    init_db()
    yield


def create_app() -> FastAPI:
    app = FastAPI(
        title="CredAudit Findings API",
        description="Persistent, multi-user findings storage for authorized CredAudit engagements.",
        version="1.0",
        lifespan=_lifespan,
    )

    @app.get("/health", tags=["meta"])
    def health():
        return {"status": "ok"}

    @app.post("/auth/token", response_model=schemas.Token, tags=["auth"])
    def login(form_data: OAuth2PasswordRequestForm = Depends(), session: Session = Depends(get_session)):
        user = authenticate_user(session, form_data.username, form_data.password)
        token = create_access_token(user.username, user.role.value)
        return schemas.Token(access_token=token)

    @app.get("/users/me", response_model=schemas.UserOut, tags=["users"])
    def read_current_user(current=Depends(get_current_user)):
        return current

    @app.post("/users", response_model=schemas.UserOut, status_code=status.HTTP_201_CREATED, tags=["users"])
    def create_user(
        payload: schemas.UserCreate,
        session: Session = Depends(get_session),
        _admin=Depends(require_role(Role.admin)),
    ):
        from .db import User
        from .security import hash_password

        if session.exec(select(User).where(User.username == payload.username)).first():
            raise HTTPException(status_code=409, detail="Username already exists")
        user = User(username=payload.username, hashed_password=hash_password(payload.password), role=payload.role)
        session.add(user)
        session.commit()
        session.refresh(user)
        return user

    @app.get("/users", response_model=list[schemas.UserOut], tags=["users"])
    def list_users(session: Session = Depends(get_session), _admin=Depends(require_role(Role.admin))):
        from .db import User

        return session.exec(select(User)).all()

    @app.get("/engagements", response_model=list[schemas.EngagementOut], tags=["engagements"])
    def list_engagements(session: Session = Depends(get_session), _user=Depends(get_current_user)):
        return session.exec(select(Engagement)).all()

    @app.get("/engagements/{engagement_id}", response_model=schemas.EngagementOut, tags=["engagements"])
    def get_engagement(engagement_id: str, session: Session = Depends(get_session), _user=Depends(get_current_user)):
        eng = session.exec(select(Engagement).where(Engagement.engagement_id == engagement_id)).first()
        if eng is None:
            raise HTTPException(status_code=404, detail="Engagement not found")
        return eng

    @app.post(
        "/engagements/{engagement_id}/import", response_model=schemas.ImportResult, tags=["findings"],
    )
    def import_findings(
        engagement_id: str,
        payload: schemas.ImportRequest,
        session: Session = Depends(get_session),
        _analyst=Depends(require_role(Role.admin, Role.analyst)),
    ):
        from ..core import evidence as ev

        try:
            evidence_objs = [ev.Evidence.from_dict(item) for item in payload.evidence]
        except (ev.EvidenceError, TypeError) as e:
            raise HTTPException(status_code=422, detail=f"Invalid evidence object: {e}")
        result = ingest.import_evidence(session, engagement_id, evidence_objs, payload.client_name)
        return schemas.ImportResult(imported=result["imported"], skipped_existing=result["skipped_existing"])

    def _finding_out(row: StoredFinding) -> schemas.FindingOut:
        return schemas.FindingOut(
            id=row.id, finding_id=row.finding_id, asset=row.asset, category=row.category,
            severity=row.severity, risk_score=row.risk_score, confidence=row.confidence,
            source=row.source, evidence=row.evidence, remediation=row.remediation,
            status=row.status, workflow_status=row.workflow_status, workflow_note=row.workflow_note,
            extra=json.loads(row.extra_json or "{}"), imported_at=row.imported_at,
            updated_by=row.updated_by, updated_at=row.updated_at,
        )

    @app.get(
        "/engagements/{engagement_id}/findings", response_model=list[schemas.FindingOut], tags=["findings"],
    )
    def list_findings(
        engagement_id: str,
        severity: Optional[str] = None,
        category: Optional[str] = None,
        status_filter: Optional[str] = Query(default=None, alias="status"),
        workflow_status: Optional[str] = None,
        asset: Optional[str] = None,
        limit: int = Query(default=100, le=1000),
        offset: int = 0,
        session: Session = Depends(get_session),
        _user=Depends(get_current_user),
    ):
        eng = session.exec(select(Engagement).where(Engagement.engagement_id == engagement_id)).first()
        if eng is None:
            raise HTTPException(status_code=404, detail="Engagement not found")

        query = select(StoredFinding).where(StoredFinding.engagement_db_id == eng.id)
        if severity:
            query = query.where(StoredFinding.severity == severity)
        if category:
            query = query.where(StoredFinding.category == category)
        if status_filter:
            query = query.where(StoredFinding.status == status_filter)
        if workflow_status:
            query = query.where(StoredFinding.workflow_status == workflow_status)
        if asset:
            query = query.where(StoredFinding.asset == asset)
        query = query.offset(offset).limit(limit)

        rows = session.exec(query).all()
        return [_finding_out(r) for r in rows]

    @app.get("/engagements/{engagement_id}/summary", response_model=schemas.SummaryOut, tags=["findings"])
    def engagement_summary(
        engagement_id: str, session: Session = Depends(get_session), _user=Depends(get_current_user),
    ):
        eng = session.exec(select(Engagement).where(Engagement.engagement_id == engagement_id)).first()
        if eng is None:
            raise HTTPException(status_code=404, detail="Engagement not found")
        rows = session.exec(select(StoredFinding).where(StoredFinding.engagement_db_id == eng.id)).all()
        by_severity: dict = {}
        by_workflow: dict = {}
        for r in rows:
            by_severity[r.severity] = by_severity.get(r.severity, 0) + 1
            by_workflow[r.workflow_status] = by_workflow.get(r.workflow_status, 0) + 1
        return schemas.SummaryOut(total=len(rows), by_severity=by_severity, by_workflow_status=by_workflow)

    @app.get("/findings/{finding_db_id}", response_model=schemas.FindingOut, tags=["findings"])
    def get_finding(finding_db_id: int, session: Session = Depends(get_session), _user=Depends(get_current_user)):
        row = session.get(StoredFinding, finding_db_id)
        if row is None:
            raise HTTPException(status_code=404, detail="Finding not found")
        return _finding_out(row)

    @app.patch("/findings/{finding_db_id}", response_model=schemas.FindingOut, tags=["findings"])
    def update_finding(
        finding_db_id: int,
        payload: schemas.FindingUpdate,
        session: Session = Depends(get_session),
        analyst=Depends(require_role(Role.admin, Role.analyst)),
    ):
        from .db import utcnow

        row = session.get(StoredFinding, finding_db_id)
        if row is None:
            raise HTTPException(status_code=404, detail="Finding not found")
        if payload.workflow_status is not None:
            if payload.workflow_status not in WORKFLOW_STATUSES:
                raise HTTPException(
                    status_code=422, detail=f"workflow_status must be one of {WORKFLOW_STATUSES}",
                )
            row.workflow_status = payload.workflow_status
        if payload.workflow_note is not None:
            row.workflow_note = payload.workflow_note
        row.updated_by = analyst.username
        row.updated_at = utcnow()
        session.add(row)
        session.commit()
        session.refresh(row)
        return _finding_out(row)

    return app
