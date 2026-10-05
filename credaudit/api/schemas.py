from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field

from .db import WORKFLOW_STATUSES, Role


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserCreate(BaseModel):
    username: str
    password: str
    role: Role = Role.viewer


class UserOut(BaseModel):
    id: int
    username: str
    role: Role
    disabled: bool


class EngagementOut(BaseModel):
    id: int
    engagement_id: str
    client_name: str
    created_at: datetime


class FindingOut(BaseModel):
    id: int
    finding_id: str
    asset: str
    category: str
    severity: str
    risk_score: int
    confidence: float
    source: str
    evidence: str
    remediation: str
    status: str
    workflow_status: str
    workflow_note: str
    extra: dict
    imported_at: datetime
    updated_by: Optional[str] = None
    updated_at: Optional[datetime] = None


class FindingUpdate(BaseModel):
    workflow_status: Optional[str] = Field(default=None, description=f"One of {WORKFLOW_STATUSES}")
    workflow_note: Optional[str] = None


class ImportRequest(BaseModel):
    """Inline evidence objects for a direct HTTP import -- each dict
    should be a JSON-serialized `core.evidence.Evidence` (i.e. exactly
    what one line of evidence.jsonl deserializes to). For importing a
    local evidence.jsonl file, use the CLI's `credaudit import-findings`
    instead, which reads the file directly rather than requiring a
    client to read and re-upload it."""
    client_name: str = ""
    evidence: list = Field(default_factory=list)


class ImportResult(BaseModel):
    imported: int
    skipped_existing: int


class SummaryOut(BaseModel):
    total: int
    by_severity: dict
    by_workflow_status: dict
