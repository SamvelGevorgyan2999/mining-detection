from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from .config import settings
from .models import Base

_engine: Engine | None = None
_SessionFactory: sessionmaker[Session] | None = None


def _build_engine(database_url: str) -> Engine:
    if database_url.startswith("sqlite"):
        engine = create_engine(
            database_url,
            future=True,
            connect_args={"check_same_thread": False},
        )

        @event.listens_for(engine, "connect")
        def _enable_sqlite_fks(dbapi_connection, _record) -> None:
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

        return engine

    return create_engine(database_url, future=True, pool_pre_ping=True, pool_size=5, max_overflow=10)


def get_engine() -> Engine:
    global _engine, _SessionFactory
    if _engine is None:
        _engine = _build_engine(settings.database_url)
        _SessionFactory = sessionmaker(bind=_engine, expire_on_commit=False, future=True)
    return _engine


def init_db() -> None:
    Base.metadata.create_all(get_engine())


def get_session() -> Session:
    get_engine()
    assert _SessionFactory is not None
    return _SessionFactory()


@contextmanager
def session_scope() -> Iterator[Session]:
    session = get_session()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def session_dependency() -> Iterator[Session]:
    """FastAPI dependency that yields a request-scoped session."""
    session = get_session()
    try:
        yield session
    finally:
        session.close()


def configure(database_url: str) -> None:
    """Point the process at a different database. Used by tests."""
    global _engine, _SessionFactory
    if _engine is not None:
        _engine.dispose()
    _engine = _build_engine(database_url)
    _SessionFactory = sessionmaker(bind=_engine, expire_on_commit=False, future=True)
    Base.metadata.create_all(_engine)


