"""Bridges `core.evidence.Evidence` objects (from a CLI run's
evidence.jsonl, or any in-memory `PipelineResult.evidence`) into the
persisted findings database.

Import is idempotent by design: re-importing the same evidence.jsonl
(e.g. because a scan was re-run) never overwrites a finding that's
already stored, specifically so it can never clobber an analyst's
`workflow_status` update with a freshly-reimported "open." A finding_id
already present for that engagement is left untouched; only genuinely
new finding_ids are inserted. If the underlying scan logic changes
enough that a finding_id's meaning changes, that's a new engagement_id
or a deliberate admin action, not a side effect of re-running `import`.
"""
from __future__ import annotations

import json
from pathlib import Path

from sqlmodel import Session, select

from ..core import evidence as ev
from .db import Engagement, StoredFinding


def get_or_create_engagement(session: Session, engagement_id: str, client_name: str = "") -> Engagement:
    eng = session.exec(select(Engagement).where(Engagement.engagement_id == engagement_id)).first()
    if eng is None:
        eng = Engagement(engagement_id=engagement_id, client_name=client_name)
        session.add(eng)
        session.commit()
        session.refresh(eng)
    return eng


def import_evidence(session: Session, engagement_id: str, evidence_list: list, client_name: str = "") -> dict:
    """Returns {"imported": n, "skipped_existing": n}."""
    eng = get_or_create_engagement(session, engagement_id, client_name)

    existing_ids = set(
        session.exec(
            select(StoredFinding.finding_id).where(StoredFinding.engagement_db_id == eng.id)
        ).all()
    )

    imported = 0
    skipped = 0
    for e in evidence_list:
        if e.finding_id in existing_ids:
            skipped += 1
            continue
        row = StoredFinding(
            engagement_db_id=eng.id,
            finding_id=e.finding_id,
            asset=e.asset,
            category=e.category,
            severity=e.severity,
            risk_score=e.risk_score,
            confidence=e.confidence,
            source=e.source,
            evidence=e.evidence,
            remediation=e.remediation,
            status=e.status,
            extra_json=json.dumps(e.extra or {}, default=str),
        )
        session.add(row)
        existing_ids.add(e.finding_id)
        imported += 1
    session.commit()
    return {"imported": imported, "skipped_existing": skipped, "engagement_db_id": eng.id}


def import_evidence_jsonl(session: Session, engagement_id: str, path, client_name: str = "") -> dict:
    evidence_list = ev.read_evidence_jsonl(Path(path))
    return import_evidence(session, engagement_id, evidence_list, client_name)
