"""Persistent storage for the findings backend: SQLModel models + engine
management. SQLite by default (zero setup); point `CREDAUDIT_DATABASE_URL`
at Postgres/MySQL for multi-user production use -- SQLModel/SQLAlchemy
don't care which, and nothing else in this package assumes SQLite.

This is an optional extra (`pip install credaudit[api]`) layered on top
of the core CLI, not a replacement for it: every CLI workflow (`run`,
`analyze-secrets`, etc.) still works, writing evidence.jsonl exactly as
before, with zero dependency on this package or a running database. The
API is for teams that want findings to persist across runs, be queried
by multiple analysts, and carry a remediation-workflow status over time
-- `credaudit import-findings` (or the `/engagements/{id}/import`
endpoint) is the bridge from one to the other.

`StoredFinding.status` mirrors `core.evidence.Evidence.status` exactly
(detected/suspected/potential_relationship/confirmed) -- the same
confidence vocabulary, unchanged on import. `workflow_status` is a
separate, new concept: where this finding stands in *this team's*
remediation process (open/remediated/false_positive/accepted_risk).
Conflating the two would blur "how sure are we this is real" with "have
we dealt with it," which are genuinely different questions answered by
different people at different times.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from sqlmodel import Field, Session, SQLModel, create_engine


class Role(str, Enum):
    admin = "admin"  # manage users and engagements
    analyst = "analyst"  # import findings, update workflow status
    viewer = "viewer"  # read-only


WORKFLOW_STATUSES = ("open", "remediated", "false_positive", "accepted_risk")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(SQLModel, table=True):
    __tablename__ = "users"

    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(index=True, unique=True)
    hashed_password: str
    role: Role = Role.viewer
    disabled: bool = False
    created_at: datetime = Field(default_factory=utcnow)


class Engagement(SQLModel, table=True):
    __tablename__ = "engagements"

    id: Optional[int] = Field(default=None, primary_key=True)
    engagement_id: str = Field(index=True, unique=True)  # matches scope.Scope.engagement_id
    client_name: str = ""
    created_at: datetime = Field(default_factory=utcnow)


class StoredFinding(SQLModel, table=True):
    __tablename__ = "stored_findings"

    id: Optional[int] = Field(default=None, primary_key=True)
    engagement_db_id: int = Field(foreign_key="engagements.id", index=True)
    finding_id: str = Field(index=True)  # original Evidence.finding_id, e.g. "ENG-0001"

    asset: str = Field(index=True)
    category: str = Field(index=True)
    severity: str = Field(index=True)
    risk_score: int
    confidence: float
    source: str
    evidence: str
    remediation: str = ""
    status: str = "detected"  # Evidence's own confidence/confirmation vocabulary, unchanged on import
    extra_json: str = "{}"  # json.dumps(Evidence.extra)

    workflow_status: str = Field(default="open", index=True)  # see module docstring
    workflow_note: str = ""
    updated_by: Optional[str] = None
    updated_at: Optional[datetime] = None

    imported_at: datetime = Field(default_factory=utcnow)


class AuditEntry(SQLModel, table=True):
    __tablename__ = "api_audit_entries"

    id: Optional[int] = Field(default=None, primary_key=True)
    actor: str
    action: str
    detail_json: str = "{}"
    at: datetime = Field(default_factory=utcnow)


_engine = None


def get_engine(database_url: str = None):
    """Build (but don't cache) a SQLAlchemy engine for `database_url`,
    or `CREDAUDIT_DATABASE_URL`, or a local SQLite file as a last
    resort. Kept separate from `get_default_engine()` so tests can build
    an isolated engine (e.g. `sqlite://` in-memory) without touching the
    process-wide default."""
    url = database_url or os.environ.get("CREDAUDIT_DATABASE_URL", "sqlite:///./credaudit.db")
    connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
    return create_engine(url, connect_args=connect_args)


def get_default_engine():
    global _engine
    if _engine is None:
        _engine = get_engine()
    return _engine


def set_default_engine(engine) -> None:
    """Used by tests and by `credaudit serve --db-url` to point the
    process-wide default at a specific engine instead of re-reading
    CREDAUDIT_DATABASE_URL."""
    global _engine
    _engine = engine


def init_db(engine=None) -> None:
    SQLModel.metadata.create_all(engine or get_default_engine())


def get_session():
    """FastAPI dependency. Tests override this via
    `app.dependency_overrides[get_session]` to point at an isolated
    engine -- see tests/test_api.py."""
    with Session(get_default_engine()) as session:
        yield session
