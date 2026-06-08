"""Repository for :class:`User` records."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from zorksec.db.models import User
from zorksec.repositories.base import BaseRepository


class UserRepository(BaseRepository[User]):
    model = User

    def __init__(self, session: Session) -> None:
        super().__init__(session)

    def get_by_username(self, username: str) -> User | None:
        stmt = select(User).where(User.username == username)
        return self.session.execute(stmt).scalar_one_or_none()

    def count(self) -> int:
        return len(list(self.list()))
