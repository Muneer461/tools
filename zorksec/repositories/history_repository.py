"""Repository for tool install/run history."""

from __future__ import annotations

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from zorksec.db.models import InstallHistory
from zorksec.repositories.base import BaseRepository


class HistoryRepository(BaseRepository[InstallHistory]):
    model = InstallHistory

    def __init__(self, session: Session) -> None:
        super().__init__(session)

    def record(
        self,
        tool_slug: str,
        action: str,
        *,
        success: bool,
        exit_code: int | None = None,
        detail: str = "",
    ) -> InstallHistory:
        entry = InstallHistory(
            tool_slug=tool_slug,
            action=action,
            success=success,
            exit_code=exit_code,
            detail=detail,
        )
        return self.add(entry)

    def recent(self, limit: int = 20) -> list[InstallHistory]:
        stmt = select(InstallHistory).order_by(desc(InstallHistory.created_at)).limit(limit)
        return list(self.session.execute(stmt).scalars().all())
