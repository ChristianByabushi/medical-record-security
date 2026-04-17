"""Shared fixtures for unit tests that need an in-memory async DB and KeyManager."""
from __future__ import annotations

import os
import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

# Set env vars before any app imports
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-for-unit-tests-only")
os.environ.setdefault("RECORD_ENCRYPTION_KEY", "a" * 64)
os.environ.setdefault("TOTP_ENCRYPTION_KEY", "b" * 64)
os.environ.setdefault("SETTINGS_ENV_FILE", "/nonexistent/.env.test")
os.environ.setdefault("DEV_MODE", "true")

from app.models.base import Base
import app.core.key_manager as _km_module
from app.core.key_manager import KeyManager


@pytest.fixture(scope="session", autouse=True)
def init_key_manager():
    """Initialise the KeyManager singleton once per test session."""
    km = KeyManager.from_env()
    _km_module._instance = km
    yield
    _km_module._instance = None


@pytest_asyncio.fixture
async def db_session():
    """Provide a fresh in-memory SQLite async session for each test."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session:
        yield session

    await engine.dispose()
