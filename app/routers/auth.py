"""Auth router: registration, login, token refresh, MFA, and password reset endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.middleware.rbac import TokenClaims, get_current_user
from app.middleware.replay_guard import ReplayGuard
from app.models.base import get_db
from app.schemas.auth import (
    LoginRequest,
    MFAConfirmRequest,
    MFAEnrollResponse,
    MFALoginVerifyRequest,
    MFAVerifyRequest,
    PartialAuthResponse,
    PasswordResetComplete,
    PasswordResetRequest,
    RefreshRequest,
    RegisterRequest,
    TokenPair,
    UserOut,
)
from app.services.auth_service import AuthService

router = APIRouter(tags=["auth"])

_auth_service = AuthService()


# ---------------------------------------------------------------------------
# Registration & Login
# ---------------------------------------------------------------------------


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def register(body: RegisterRequest, db: AsyncSession = Depends(get_db)) -> UserOut:
    return await _auth_service.register(db, body.email, body.password, body.role)


@router.post(
    "/login",
    response_model=TokenPair | PartialAuthResponse,
    status_code=status.HTTP_200_OK,
)
async def login(
    body: LoginRequest,
    db: AsyncSession = Depends(get_db),
    _replay: None = Depends(ReplayGuard.validate),
) -> TokenPair | PartialAuthResponse:
    return await _auth_service.login(db, body.email, body.password)


# ---------------------------------------------------------------------------
# Token refresh
# ---------------------------------------------------------------------------


@router.post("/token/refresh", response_model=TokenPair, status_code=status.HTTP_200_OK)
async def refresh_token(
    body: RefreshRequest, db: AsyncSession = Depends(get_db)
) -> TokenPair:
    return await _auth_service.refresh_tokens(db, body.refresh_token)


# ---------------------------------------------------------------------------
# MFA endpoints
# ---------------------------------------------------------------------------


@router.post("/mfa/enroll", response_model=MFAEnrollResponse, status_code=status.HTTP_200_OK)
async def mfa_enroll(
    db: AsyncSession = Depends(get_db),
    claims: TokenClaims = Depends(get_current_user),
) -> MFAEnrollResponse:
    return await _auth_service.enroll_mfa(db, claims.user_id)


@router.post("/mfa/confirm", status_code=status.HTTP_200_OK)
async def mfa_confirm(
    body: MFAConfirmRequest,
    db: AsyncSession = Depends(get_db),
    claims: TokenClaims = Depends(get_current_user),
) -> dict:
    return await _auth_service.confirm_mfa(db, claims.user_id, body.totp_code)


@router.post("/mfa/verify", response_model=TokenPair, status_code=status.HTTP_200_OK)
async def mfa_verify(
    body: MFALoginVerifyRequest,
    db: AsyncSession = Depends(get_db),
    _replay: None = Depends(ReplayGuard.validate),
) -> TokenPair:
    return await _auth_service.verify_totp(db, body.partial_token, body.totp_code)


# ---------------------------------------------------------------------------
# Password reset
# ---------------------------------------------------------------------------


@router.post(
    "/password-reset/request", status_code=status.HTTP_200_OK
)
async def password_reset_request(
    body: PasswordResetRequest,
    db: AsyncSession = Depends(get_db),
    _replay: None = Depends(ReplayGuard.validate),
) -> dict:
    return await _auth_service.request_password_reset(db, body.email)


@router.post(
    "/password-reset/complete", status_code=status.HTTP_200_OK
)
async def password_reset_complete(
    body: PasswordResetComplete,
    db: AsyncSession = Depends(get_db),
    _replay: None = Depends(ReplayGuard.validate),
) -> dict:
    return await _auth_service.complete_password_reset(
        db, body.token, body.new_password, body.totp_code
    )
