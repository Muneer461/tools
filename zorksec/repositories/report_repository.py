"""Repository for generated reports."""

from __future__ import annotations

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from zorksec.db.models import Report
from zorksec.repositories.base import BaseRepository


class ReportRepository(BaseRepository[Report]):
    model = Report

    def __init__(self, session: Session) -> None:
        super().__init__(session)

    def create(self, title: str, report_type: str, body: str, fmt: str = "markdown") -> Report:
        report = Report(title=title, report_type=report_type, body=body, fmt=fmt)
        return self.add(report)

    def recent(self, limit: int = 25) -> list[Report]:
        stmt = select(Report).order_by(desc(Report.created_at)).limit(limit)
        return list(self.session.execute(stmt).scalars().all())
