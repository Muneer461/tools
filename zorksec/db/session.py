"""Database engine and session management.

Uses SQLite in WAL mode for safer concurrent reads during installs, with a
busy timeout to reduce ``database is locked`` errors. A single configured
sessionmaker is exposed via :func:`get_sessionmaker`.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from zorksec.config import Settings, ensure_directories, get_settings
from zorksec.db.models import Base

_engine: Engine | None = None
_Session: sessionmaker[Session] | None = None
_engine_url: str | None = None


def _configure_sqlite(dbapi_connection, _connection_record) -> None:
    """Apply pragmas on every new SQLite connection (WAL + busy timeout)."""
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL;")
    cursor.execute("PRAGMA busy_timeout=5000;")
    cursor.execute("PRAGMA foreign_keys=ON;")
    cursor.close()


def get_engine(settings: Settings | None = None) -> Engine:
    """Return a process-wide engine, rebuilding it if the DB URL changed."""
    global _engine, _Session, _engine_url
    settings = settings or get_settings()
    if _engine is None or _engine_url != settings.database_url:
        ensure_directories(settings)
        _engine = create_engine(
            settings.database_url,
            future=True,
            connect_args={"check_same_thread": False},
        )
        event.listen(_engine, "connect", _configure_sqlite)
        _Session = sessionmaker(bind=_engine, expire_on_commit=False, future=True)
        _engine_url = settings.database_url
    return _engine


def get_sessionmaker(settings: Settings | None = None) -> sessionmaker[Session]:
    """Return the configured sessionmaker (initialising the engine if needed)."""
    get_engine(settings)
    assert _Session is not None  # set by get_engine
    return _Session


def init_db(settings: Settings | None = None) -> None:
    """Create all tables if they do not exist (idempotent)."""
    engine = get_engine(settings)
    Base.metadata.create_all(engine)


@contextmanager
def session_scope(settings: Settings | None = None) -> Iterator[Session]:
    """Provide a transactional scope around a series of operations."""
    factory = get_sessionmaker(settings)
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
