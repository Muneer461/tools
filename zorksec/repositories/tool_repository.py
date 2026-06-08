"""Repository for the tool catalog (registry + status + health)."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from zorksec.db.models import ToolHealth, ToolRegistry, ToolStatus
from zorksec.repositories.base import BaseRepository


class ToolRepository(BaseRepository[ToolRegistry]):
    model = ToolRegistry

    def __init__(self, session: Session) -> None:
        super().__init__(session)

    def get_by_slug(self, slug: str) -> ToolRegistry | None:
        stmt = select(ToolRegistry).where(ToolRegistry.slug == slug)
        return self.session.execute(stmt).scalar_one_or_none()

    def list_by_team(self, team: str) -> list[ToolRegistry]:
        if team == "both":
            stmt = select(ToolRegistry).order_by(ToolRegistry.category, ToolRegistry.name)
        else:
            stmt = (
                select(ToolRegistry)
                .where(ToolRegistry.team.in_([team, "both"]))
                .order_by(ToolRegistry.category, ToolRegistry.name)
            )
        return list(self.session.execute(stmt).scalars().all())

    def list_by_category(self, category: str) -> list[ToolRegistry]:
        stmt = (
            select(ToolRegistry)
            .where(ToolRegistry.category == category)
            .order_by(ToolRegistry.name)
        )
        return list(self.session.execute(stmt).scalars().all())

    def ensure_status(self, tool: ToolRegistry) -> ToolStatus:
        if tool.status is None:
            status = ToolStatus(tool_id=tool.id, installed=False)
            self.session.add(status)
            self.session.flush()
            tool.status = status
        return tool.status

    def ensure_health(self, tool: ToolRegistry) -> ToolHealth:
        if tool.health is None:
            health = ToolHealth(tool_id=tool.id)
            self.session.add(health)
            self.session.flush()
            tool.health = health
        return tool.health

    def count(self) -> int:
        return len(list(self.list()))
