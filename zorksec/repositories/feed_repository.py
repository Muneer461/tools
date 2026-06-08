"""Repository for threat-intelligence feed entries (IOCs)."""

from __future__ import annotations

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from zorksec.db.models import ThreatFeed
from zorksec.repositories.base import BaseRepository


class FeedRepository(BaseRepository[ThreatFeed]):
    model = ThreatFeed

    def __init__(self, session: Session) -> None:
        super().__init__(session)

    def add_indicator(self, source: str, feed_type: str, indicator: str,
                      description: str = "") -> ThreatFeed:
        entry = ThreatFeed(
            source=source,
            feed_type=feed_type,
            indicator=indicator,
            description=description,
        )
        return self.add(entry)

    def exists(self, indicator: str) -> bool:
        stmt = select(ThreatFeed.id).where(ThreatFeed.indicator == indicator).limit(1)
        return self.session.execute(stmt).first() is not None

    def by_type(self, feed_type: str, limit: int = 100) -> list[ThreatFeed]:
        stmt = (
            select(ThreatFeed)
            .where(ThreatFeed.feed_type == feed_type)
            .order_by(desc(ThreatFeed.fetched_at))
            .limit(limit)
        )
        return list(self.session.execute(stmt).scalars().all())

    def recent(self, limit: int = 100) -> list[ThreatFeed]:
        stmt = select(ThreatFeed).order_by(desc(ThreatFeed.fetched_at)).limit(limit)
        return list(self.session.execute(stmt).scalars().all())

    def search(self, term: str, limit: int = 50) -> list[ThreatFeed]:
        like = f"%{term}%"
        stmt = (
            select(ThreatFeed)
            .where(ThreatFeed.indicator.like(like))
            .order_by(desc(ThreatFeed.fetched_at))
            .limit(limit)
        )
        return list(self.session.execute(stmt).scalars().all())

    def counts_by_type(self) -> dict[str, int]:
        stmt = select(ThreatFeed.feed_type, func.count(ThreatFeed.id)).group_by(
            ThreatFeed.feed_type
        )
        return {row[0]: row[1] for row in self.session.execute(stmt).all()}
