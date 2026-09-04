from __future__ import annotations

from datetime import datetime, timezone
from typing import Sequence

from sqlalchemy import select, desc

from app.db.models import ScanHistory
from app.db.session import async_session


async def create_scan(
    user_id: int,
    scan_type: str,
    target: str,
) -> int:
    async with async_session() as session:
        record = ScanHistory(
            user_id=user_id,
            scan_type=scan_type,
            target=target[:500],
            status="running",
        )
        session.add(record)
        await session.commit()
        await session.refresh(record)
        return record.id


async def finish_scan(
    scan_id: int,
    status: str,
    raw_report: str | None = None,
    summary: str | None = None,
) -> None:
    async with async_session() as session:
        result = await session.execute(select(ScanHistory).where(ScanHistory.id == scan_id))
        record = result.scalar_one_or_none()
        if not record:
            return
        record.status = status
        record.raw_report = (raw_report or "")[:50000]
        record.summary = (summary or "")[:10000]
        record.finished_at = datetime.now(timezone.utc)
        await session.commit()


async def get_user_history(user_id: int, limit: int = 10) -> Sequence[ScanHistory]:
    async with async_session() as session:
        result = await session.execute(
            select(ScanHistory)
            .where(ScanHistory.user_id == user_id)
            .order_by(desc(ScanHistory.created_at))
            .limit(limit)
        )
        return result.scalars().all()
