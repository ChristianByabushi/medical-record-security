"""
SQLAlchemy 2.x async base: DeclarativeBase, engine, session factory, and get_db dependency.
Engine creation is lazy — the engine is only created when first accessed.
"""
from __future__ import annotations

from collections.abc import AsyncGenerator
from typing import TYPE_CHECKING

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Shared declarative base for all ORM models."""
    pass


# ---------------------------------------------------------------------------
# Lazy engine / session factory
# ---------------------------------------------------------------------------
# These are module-level singletons but are only initialised on first access
# so that importing this module at test-collection time does not attempt a DB
# connection (settings may not be configured yet).

_engine = None
_AsyncSessionLocal: async_sessionmaker[AsyncSession] | None = None


def _get_engine():
    global _engine
    if _engine is None:
        from app.core.config import settings
        _engine = create_async_engine(
            settings.DATABASE_URL,
            echo=False,
            future=True,
        )
    return _engine


def _get_session_factory() -> async_sessionmaker[AsyncSession]:
    global _AsyncSessionLocal
    if _AsyncSessionLocal is None:
        _AsyncSessionLocal = async_sessionmaker(
            bind=_get_engine(),
            class_=AsyncSession,
            expire_on_commit=False,
        )
    return _AsyncSessionLocal


# Convenience aliases used by other modules
@property  # type: ignore[misc]
def engine():  # noqa: D401
    return _get_engine()


@property  # type: ignore[misc]
def AsyncSessionLocal():  # noqa: D401
    return _get_session_factory()


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency that yields an async DB session."""
    factory = _get_session_factory()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
