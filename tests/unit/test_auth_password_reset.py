# Feature: secure-medical-records-backend, Property 24: Password Reset Tokens Are Unique and Single-Use
# Feature: secure-medical-records-backend, Property 25: Password Reset Revokes All Active Sessions
"""
Property 24: Password Reset Tokens Are Unique and Single-Use
Validates: Requirements 13.1, 13.3

Property 25: Password Reset Revokes All Active Sessions
Validates: Requirements 13.5
"""
from __future__ import annotations

import hashlib
import pytest
import pytest_asyncio
from hypothesis import given, settings as h_settings
from hypothesis import strategies as st
from sqlalchemy import select

from app.models.password_reset_token import PasswordResetToken
from app.models.refresh_token import RefreshToken
from app.schemas.auth import TokenPair
from app.services.auth_service import AuthService

_service = AuthService()


async def _register_user(db, email="reset@example.com", password="TestPassword123!", role="Patient"):
    user_out = await _service.register(db, email, password, role)
    return str(user_out.id), email, password


# ---------------------------------------------------------------------------
# Property 24: Password Reset Tokens Are Unique and Single-Use
# ---------------------------------------------------------------------------


@given(st.integers(min_value=2, max_value=5))
@h_settings(max_examples=10, deadline=None)
def test_password_reset_tokens_unique_and_single_use(n: int):
    """
    Property 24: Password Reset Tokens Are Unique and Single-Use
    Validates: Requirements 13.1, 13.3

    Generate N reset tokens for the same user; assert N distinct hashes in DB;
    use one token (200); use same token again (400); assert used=True.
    """
    import asyncio
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
    from app.models.base import Base

    async def _run():
        engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        async with factory() as db:
            _, email, _ = await _register_user(db)

            # Generate N reset tokens
            raw_tokens = []
            for _ in range(n):
                result = await _service.request_password_reset(db, email)
                assert "dev_token" in result  # DEV_MODE=true
                raw_token = result["dev_token"].split(" ")[0]
                raw_tokens.append(raw_token)

            # Assert N distinct hashes in DB
            hashes = [hashlib.sha256(t.encode()).hexdigest() for t in raw_tokens]
            assert len(set(hashes)) == n, "Token hashes must all be distinct"

            db_result = await db.execute(select(PasswordResetToken))
            db_tokens = db_result.scalars().all()
            db_hashes = {t.token_hash for t in db_tokens}
            for h in hashes:
                assert h in db_hashes

            # Use the first token — should succeed
            first_token = raw_tokens[0]
            resp = await _service.complete_password_reset(
                db, first_token, "NewPassword456!", None
            )
            assert "Password updated" in resp["message"]

            # Use the same token again — must fail with 400
            from fastapi import HTTPException
            with pytest.raises(HTTPException) as exc_info:
                await _service.complete_password_reset(
                    db, first_token, "AnotherPassword789!", None
                )
            assert exc_info.value.status_code == 400
            assert exc_info.value.headers.get("X-Error-Code") == "TOKEN_EXPIRED_OR_USED"

            # Assert used=True in DB
            first_hash = hashlib.sha256(first_token.encode()).hexdigest()
            db_result2 = await db.execute(
                select(PasswordResetToken).where(PasswordResetToken.token_hash == first_hash)
            )
            used_token = db_result2.scalar_one()
            assert used_token.used is True

        await engine.dispose()

    asyncio.get_event_loop().run_until_complete(_run())


# ---------------------------------------------------------------------------
# Property 25: Password Reset Revokes All Active Sessions
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_password_reset_revokes_all_sessions(db_session):
    """
    Property 25: Password Reset Revokes All Active Sessions
    Validates: Requirements 13.5

    Create a user with an active refresh token; complete password reset;
    attempt to use the old refresh token (401).
    """
    _, email, password = await _register_user(db_session, email="revoke@example.com")

    # Login to get a refresh token
    login_result = await _service.login(db_session, email, password)
    assert isinstance(login_result, TokenPair)
    old_refresh_token = login_result.refresh_token

    # Verify the refresh token works before reset
    new_pair = await _service.refresh_tokens(db_session, old_refresh_token)
    assert isinstance(new_pair, TokenPair)
    active_refresh = new_pair.refresh_token

    # Request and complete password reset
    reset_result = await _service.request_password_reset(db_session, email)
    assert "dev_token" in reset_result
    raw_token = reset_result["dev_token"].split(" ")[0]

    resp = await _service.complete_password_reset(
        db_session, raw_token, "BrandNewPassword999!", None
    )
    assert "Password updated" in resp["message"]

    # The active refresh token must now be revoked
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc_info:
        await _service.refresh_tokens(db_session, active_refresh)
    assert exc_info.value.status_code == 401

    # Confirm all refresh tokens for this user are revoked in DB
    from sqlalchemy import select as sa_select
    from app.models.user import User
    user_result = await db_session.execute(sa_select(User).where(User.email == email))
    user = user_result.scalar_one()

    rt_result = await db_session.execute(
        sa_select(RefreshToken).where(RefreshToken.user_id == user.id)
    )
    all_tokens = rt_result.scalars().all()
    assert all(t.revoked for t in all_tokens), "All refresh tokens must be revoked after password reset"
