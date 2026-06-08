"""Generic repository base class.

Repositories receive a SQLAlchemy ``Session`` (dependency injection) and expose
typed CRUD helpers. Services compose repositories; they never touch the session
directly. This is the reference pattern every other repository follows.
"""

from __future__ import annotations

from typing import Generic, Sequence, Type, TypeVar

from sqlalchemy import select
from sqlalchemy.orm import Session

from zorksec.db.models import Base

ModelT = TypeVar("ModelT", bound=Base)


class BaseRepository(Generic[ModelT]):
    """CRUD helpers shared by all repositories."""

    model: Type[ModelT]

    def __init__(self, session: Session) -> None:
        self.session = session

    def add(self, entity: ModelT) -> ModelT:
        self.session.add(entity)
        self.session.flush()  # populate primary key without committing
        return entity

    def get(self, entity_id: int) -> ModelT | None:
        return self.session.get(self.model, entity_id)

    def list(self) -> Sequence[ModelT]:
        return self.session.execute(select(self.model)).scalars().all()

    def delete(self, entity: ModelT) -> None:
        self.session.delete(entity)
        self.session.flush()
