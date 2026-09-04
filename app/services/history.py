from __future__ import annotations

from datetime import datetime, timezone
from typing import Sequence

from sqlalchemy import desc, func, select

from app.db.models import ScanHistory
from app.db.session import get_session


def create_scan(user_id: int, scan_type: str, target: str) -> int:
    with get_session() as session:
        record = ScanHistory(
            user_id=user_id,
            scan_type=scan_type,
            target=target[:500],
            status="running",
        )
        session.add(record)
        session.commit()
        session.refresh(record)
        return record.id


def finish_scan(
    scan_id: int,
    status: str,
    raw_report: str | None = None,
    summary: str | None = None,
) -> bool:
    with get_session() as session:
        record = session.get(ScanHistory, scan_id)
        if not record:
            return False
        record.status = status
        record.raw_report = (raw_report or "")[:50_000]
        record.summary = (summary or "")[:10_000]
        record.finished_at = datetime.now(timezone.utc)
        session.commit()
        return True


def get_user_history(user_id: int, limit: int = 10) -> Sequence[ScanHistory]:
    with get_session() as session:
        result = session.execute(
            select(ScanHistory)
            .where(ScanHistory.user_id == user_id)
            .order_by(desc(ScanHistory.created_at))
            .limit(limit)
        )
        rows = result.scalars().all()
        session.expunge_all()
        return rows


def get_scan(scan_id: int) -> ScanHistory | None:
    with get_session() as session:
        record = session.get(ScanHistory, scan_id)
        if record:
            session.expunge(record)
        return record


def count_running(user_id: int) -> int:
    with get_session() as session:
        result = session.execute(
            select(func.count())
            .select_from(ScanHistory)
            .where(ScanHistory.user_id == user_id, ScanHistory.status == "running")
        )
        return int(result.scalar_one())
