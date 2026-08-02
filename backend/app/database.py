"""SQLAlchemy engine, session factory, and declarative base."""
from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import settings

engine = create_engine(
    settings.database_url,
    pool_pre_ping=True,
    future=True,
)

# autoflush is ON so "get-or-create" checks inside a single run see rows added
# earlier in the same transaction — prevents duplicate-key errors when a tool
# emits the same subdomain / port / endpoint more than once in one run
# (e.g. naabu reporting a port twice, katana re-emitting the same URL).
SessionLocal = sessionmaker(bind=engine, autoflush=True, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency: yields a session, always closed afterwards."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def session_scope() -> Session:
    """Plain session for use inside Celery tasks (caller manages lifecycle)."""
    return SessionLocal()
