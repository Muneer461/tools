"""Repository for :class:`AuditLog` records."""

from __future__ import annotations

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from zorksec.db.models import AuditLog
from zorksec.repositories.base import BaseRepository


class AuditRepository(BaseRepository[AuditLog]):
    model = AuditLog

    def __init__(self, session: Session) -> None:
        super().__init__(session)

    def record(
        self,
        event: str,
        *,
        username: str | None = None,
        detail: str = "",
        success: bool = True,
        ip_address: str | None = None,
    ) -> AuditLog:
        entry = AuditLog(
            event=event,
            username=username,
            detail=detail,
            success=success,
            ip_address=ip_address,
        )
        return self.add(entry)

    def recent(self, limit: int = 50) -> list[AuditLog]:
        stmt = select(AuditLog).order_by(desc(AuditLog.created_at)).limit(limit)
        return list(self.session.execute(stmt).scalars().all())
