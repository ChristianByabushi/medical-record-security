# Feature: secure-medical-records-backend, Property 7: Refresh Token Rotation Invalidates Consumed Tokens
# Feature: secure-medical-records-backend, Property 5: MFA-Enabled Login Never Issues Full Tokens Without TOTP
# Feature: secure-medical-records-backend, Property 8: Invalid TOTP Codes Are Always Rejected
"""
Property 7: Refresh Token Rotation Invalidates Consumed Tokens
Validates: Requirements 3.3

Property 5: MFA-Enabled Login Never Issues Full Tokens Without TOTP
Validates: Requirements 2.2

Property 8: Invalid TOTP Codes Are Always Rejected
Validates: Requirements 4.3, 4.5
"""
from __future__ import annotations

import pytest
import pytest_asyncio
import pyotp
from hypothesis import given, settings as h_settings
from hypothesis import strategies as st
from sqlalchemy import select

from app.models.refresh_token import RefreshToken
from app.schemas.auth import PartialAuthResponse, TokenPair
from app.services.auth_service import AuthService


_service = AuthService()


# ---------------------------------------------------------------------------
# Helper: register a user and return (user_id, email, password)
# ---------------------------------------------------------------------------

async def _register_user(db, email="test@example.com", password="TestPassword123!", role="Patient"):
    user_out = await _service.register(db, email, password, role)
    return str(user_out.id), email, password


# ---------------------------------------------------------------------------
# Property 7: Refresh Token Rotation Invalidates Consumed Tokens
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_refresh_token_rotation_invalidates_old_token(db_session):
    """
    Property 7: Refresh Token Rotation Invalidates Consumed Tokens
    Validates: Requirements 3.3

    Use a valid refresh token; call refresh once (200, new token pair);
    call refresh again with same token (401); assert original token revoked=True in DB.
    """
    _, email, password = await _register_user(db_session)
    login_result = await _service.login(db_session, email, password)
    assert isinstance(login_result, TokenPair)
    original_refresh = login_result.refresh_token

    # First refresh — should succeed and return a new token pair
    new_pair = await _service.refresh_tokens(db_session, original_refresh)
    assert isinstance(new_pair, TokenPair)
    assert new_pair.refresh_token != original_refresh

    # Second refresh with the same original token — must fail
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc_info:
        await _service.refresh_tokens(db_session, original_refresh)
    assert exc_info.value.status_code == 401

    # Verify the original token is marked revoked in the DB
    import hashlib
    token_hash = hashlib.sha256(original_refresh.encode()).hexdigest()
    result = await db_session.execute(
        select(RefreshToken).where(RefreshToken.token_hash == token_hash)
    )
    db_token = result.scalar_one_or_none()
    assert db_token is not None
    assert db_token.revoked is True


# ---------------------------------------------------------------------------
# Property 5: MFA-Enabled Login Never Issues Full Tokens Without TOTP
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mfa_enabled_login_returns_partial_token(db_session):
    """
    Property 5: MFA-Enabled Login Never Issues Full Tokens Without TOTP
    Validates: Requirements 2.2

    Enable MFA for a user; login with correct credentials; assert response
    contains mfa_required=True and partial_token (not a full TokenPair).
    """
    user_id, email, password = await _register_user(db_session, email="mfa@example.com")

    # Enroll and confirm MFA
    enroll_resp = await _service.enroll_mfa(db_session, user_id)
    valid_code = pyotp.TOTP(enroll_resp.secret).now()
    await _service.confirm_mfa(db_session, user_id, valid_code)

    # Login should now return a partial token, not a full TokenPair
    login_result = await _service.login(db_session, email, password)
    assert isinstance(login_result, PartialAuthResponse)
    assert login_result.mfa_required is True
    assert login_result.partial_token is not None
    assert len(login_result.partial_token) > 0

    # Using the partial token directly on verify_totp with wrong code must fail
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc_info:
        await _service.verify_totp(db_session, login_result.partial_token, "000000")
    assert exc_info.value.status_code == 401


# ---------------------------------------------------------------------------
# Property 8: Invalid TOTP Codes Are Always Rejected
# ---------------------------------------------------------------------------


@given(
    st.from_regex(r"\d{6}", fullmatch=True)
)
@h_settings(max_examples=50, deadline=None)
def test_invalid_totp_rejected_on_confirm(totp_code: str):
    """
    Property 8: Invalid TOTP Codes Are Always Rejected (confirm_mfa)
    Validates: Requirements 4.3, 4.5

    Uses hypothesis to generate 6-digit codes; filters out the valid one at runtime.
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
            user_id, _, _ = await _register_user(db, email="totp_test@example.com")
            enroll_resp = await _service.enroll_mfa(db, user_id)
            valid_code = pyotp.TOTP(enroll_resp.secret).now()

            if totp_code == valid_code:
                # Skip — this is the valid code, not testing rejection
                return

            from fastapi import HTTPException
            with pytest.raises(HTTPException) as exc_info:
                await _service.confirm_mfa(db, user_id, totp_code)
            assert exc_info.value.status_code == 400
            assert exc_info.value.headers.get("X-Error-Code") == "INVALID_TOTP"

        await engine.dispose()

    asyncio.get_event_loop().run_until_complete(_run())


@given(
    st.from_regex(r"\d{6}", fullmatch=True)
)
@h_settings(max_examples=50, deadline=None)
def test_invalid_totp_rejected_on_verify_totp(totp_code: str):
    """
    Property 8: Invalid TOTP Codes Are Always Rejected (verify_totp)
    Validates: Requirements 4.3, 4.5

    Uses hypothesis to generate 6-digit codes; filters out the valid one at runtime.
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
            user_id, email, password = await _register_user(
                db, email="totp_verify@example.com"
            )
            enroll_resp = await _service.enroll_mfa(db, user_id)
            valid_code = pyotp.TOTP(enroll_resp.secret).now()
            await _service.confirm_mfa(db, user_id, valid_code)

            # Login to get partial token
            login_result = await _service.login(db, email, password)
            assert isinstance(login_result, PartialAuthResponse)
            partial_token = login_result.partial_token

            if totp_code == valid_code:
                return

            from fastapi import HTTPException
            with pytest.raises(HTTPException) as exc_info:
                await _service.verify_totp(db, partial_token, totp_code)
            assert exc_info.value.status_code == 401

        await engine.dispose()

    asyncio.get_event_loop().run_until_complete(_run())
