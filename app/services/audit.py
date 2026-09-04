from __future__ import annotations

import logging
from typing import Sequence

from sqlalchemy import desc, select

from app.db.models import AuditEvent
from app.db.session import get_session
from app.services.textutil import mask_secrets

logger = logging.getLogger(__name__)


def write_event(
    user_id: int,
    action: str,
    scan_type: str = "",
    target: str = "",
    scan_id: int | None = None,
    detail: str = "",
) -> int:
    event = AuditEvent(
        user_id=int(user_id),
        action=action[:64],
        scan_type=(scan_type or "")[:32],
        target=mask_secrets((target or "")[:500]),
        scan_id=scan_id,
        detail=mask_secrets((detail or "")[:4000]),
    )
    with get_session() as session:
        session.add(event)
        session.commit()
        session.refresh(event)
        logger.info(
            "audit user=%s action=%s type=%s target=%s scan_id=%s",
            user_id,
            action,
            scan_type,
            event.target[:80],
            scan_id,
        )
        return event.id


def recent(user_id: int | None = None, limit: int = 50) -> Sequence[AuditEvent]:
    with get_session() as session:
        stmt = select(AuditEvent).order_by(desc(AuditEvent.created_at)).limit(limit)
        if user_id is not None:
            stmt = stmt.where(AuditEvent.user_id == user_id)
        rows = session.execute(stmt).scalars().all()
        session.expunge_all()
        return rows
