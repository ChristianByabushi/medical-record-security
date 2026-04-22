"""Authentication service: registration, login, JWT issuance, refresh tokens."""
from __future__ import annotations

import hashlib
import secrets
import uuid as _uuid_module
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
from fastapi import HTTPException
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.base import _get_session_factory
from app.core.crypto import encrypt, decrypt
from app.core.key_manager import get_key_manager
from app.core.totp import generate_secret, verify_totp as totp_verify, build_provisioning_uri
from app.models.mfa_secret import MFASecret
from app.models.password_reset_token import PasswordResetToken
from app.models.refresh_token import RefreshToken
from app.models.user import User
from app.schemas.auth import MFAEnrollResponse, PartialAuthResponse, TokenPair, UserOut


def _to_uuid(value: str | _uuid_module.UUID) -> _uuid_module.UUID:
    """Coerce a string or UUID to a UUID object."""
    if isinstance(value, _uuid_module.UUID):
        return value
    return _uuid_module.UUID(value)


def _hash_password(password: str) -> str:
    """Hash a password with bcrypt, returning a UTF-8 string."""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def _verify_password(password: str, hashed: str) -> bool:
    """Constant-time bcrypt verification."""
    return bcrypt.checkpw(password.encode(), hashed.encode())


# Dummy hash for constant-time comparison when user is not found (prevents timing attacks).
_DUMMY_HASH = _hash_password("dummy-timing-safe-x9k2")


async def _audit_login_failed(
    actor_id: _uuid_module.UUID,
    resource_id: _uuid_module.UUID,
    client_ip: str,
    reason: str,
    subject_user_id: str | None = None,
) -> None:
    """Write a LOGIN_FAILED audit entry in its own committed session.

    Uses a separate session so the entry is persisted even when the calling
    request session is rolled back (which happens when HTTPException is raised).
    """
    from app.services.audit_service import AuditService
    extra: dict = {"reason": reason}
    if subject_user_id:
        extra["subject_user_id"] = subject_user_id
    try:
        factory = _get_session_factory()
        async with factory() as session:
            async with session.begin():
                await AuditService().append(
                    session,
                    event_type="LOGIN_FAILED",
                    actor_id=actor_id,
                    resource_id=resource_id,
                    resource_type="user",
                    client_ip=client_ip,
                    extra=extra,
                )
    except Exception:
        pass  # audit failure must never block the auth response


class AuthService:
    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    async def register(self, db: AsyncSession, email: str, password: str, role: str, full_name: str = "") -> UserOut:
        """Register a new user. Raises HTTP 409 if email already exists."""
        result = await db.execute(select(User).where(User.email == email))
        existing = result.scalar_one_or_none()
        if existing is not None:
            raise HTTPException(
                status_code=409,
                detail="Email already registered",
                headers={"X-Error-Code": "EMAIL_ALREADY_EXISTS"},
            )

        password_hash = _hash_password(password)
        user = User(email=email, password_hash=password_hash, role=role, full_name=full_name)
        db.add(user)
        await db.flush()  # populate user.id without committing
        await db.refresh(user)
        return UserOut.model_validate(user)

    # ------------------------------------------------------------------
    # Login
    # ------------------------------------------------------------------

    async def login(
        self, db: AsyncSession, email: str, password: str, client_ip: str = "0.0.0.0"
    ) -> TokenPair | PartialAuthResponse:
        """Authenticate user. Returns TokenPair or PartialAuthResponse (MFA required)."""
        result = await db.execute(select(User).where(User.email == email))
        user = result.scalar_one_or_none()

        if user is None:
            # Constant-time: verify against dummy hash to prevent timing attacks
            _verify_password(password, _DUMMY_HASH)
            # Audit failed login in its own session so the rollback from HTTPException
            # does not discard the audit entry.
            await _audit_login_failed(
                actor_id=_uuid_module.UUID(int=0),
                resource_id=_uuid_module.UUID(int=0),
                client_ip=client_ip,
                reason="unknown_email",
            )
            raise HTTPException(
                status_code=401,
                detail="Invalid credentials",
                headers={"X-Error-Code": "INVALID_CREDENTIALS"},
            )

        if not _verify_password(password, user.password_hash):
            await _audit_login_failed(
                actor_id=user.id,
                resource_id=user.id,
                client_ip=client_ip,
                reason="wrong_password",
                subject_user_id=str(user.id),
            )
            raise HTTPException(
                status_code=401,
                detail="Invalid credentials",
                headers={"X-Error-Code": "INVALID_CREDENTIALS"},
            )

        if user.mfa_enabled:
            partial_token = self._issue_partial_token(user)
            return PartialAuthResponse(partial_token=partial_token)

        token_pair = await self._issue_token_pair(db, user)

        # Audit login event
        from app.services.audit_service import AuditService
        await AuditService().append(
            db,
            event_type="USER_LOGIN",
            actor_id=user.id,
            resource_id=user.id,
            resource_type="user",
            client_ip=client_ip,
        )

        return token_pair

    # ------------------------------------------------------------------
    # Token helpers
    # ------------------------------------------------------------------

    def _issue_partial_token(self, user: User) -> str:
        now = datetime.now(timezone.utc)
        payload = {
            "sub": str(user.id),
            "partial": True,
            "exp": now + timedelta(minutes=5),
        }
        return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)

    async def _issue_token_pair(self, db: AsyncSession, user: User) -> TokenPair:
        now = datetime.now(timezone.utc)
        expire_minutes = settings.ACCESS_TOKEN_EXPIRE_MINUTES
        access_payload = {
            "sub": str(user.id),
            "role": user.role,
            "exp": now + timedelta(minutes=expire_minutes),
        }
        access_token = jwt.encode(
            access_payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM
        )

        raw_refresh = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_refresh.encode()).hexdigest()
        refresh_expires = now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

        db_token = RefreshToken(
            user_id=user.id,
            token_hash=token_hash,
            expires_at=refresh_expires,
        )
        db.add(db_token)
        await db.flush()

        return TokenPair(
            access_token=access_token,
            refresh_token=raw_refresh,
            expires_in=expire_minutes * 60,
        )

    # ------------------------------------------------------------------
    # Token refresh (rotation)
    # ------------------------------------------------------------------

    async def refresh_tokens(self, db: AsyncSession, refresh_token: str) -> TokenPair:
        """Rotate a refresh token. Raises HTTP 401 if invalid/expired/revoked."""
        token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
        result = await db.execute(
            select(RefreshToken).where(RefreshToken.token_hash == token_hash)
        )
        db_token = result.scalar_one_or_none()

        now = datetime.now(timezone.utc)
        if (
            db_token is None
            or db_token.revoked
            or db_token.expires_at.replace(tzinfo=timezone.utc) < now
        ):
            raise HTTPException(
                status_code=401,
                detail="Invalid or expired refresh token",
                headers={"X-Error-Code": "REFRESH_TOKEN_INVALID"},
            )

        # Revoke old token
        db_token.revoked = True
        await db.flush()

        # Issue new token pair
        user_result = await db.execute(select(User).where(User.id == db_token.user_id))
        user = user_result.scalar_one()
        return await self._issue_token_pair(db, user)

    # ------------------------------------------------------------------
    # MFA enrollment
    # ------------------------------------------------------------------

    async def enroll_mfa(self, db: AsyncSession, user_id: str) -> MFAEnrollResponse:
        """Generate and store an encrypted TOTP secret. Returns provisioning URI."""
        uid = _to_uuid(user_id)
        user_result = await db.execute(select(User).where(User.id == uid))
        user = user_result.scalar_one()

        secret = generate_secret()
        totp_key = get_key_manager().get_totp_key()
        ciphertext, iv, tag = encrypt(secret.encode(), totp_key)

        # Upsert: remove existing secret if present
        existing = await db.execute(select(MFASecret).where(MFASecret.user_id == uid))
        existing_secret = existing.scalar_one_or_none()
        if existing_secret is not None:
            await db.delete(existing_secret)
            await db.flush()

        mfa_secret = MFASecret(
            user_id=uid,
            encrypted_secret=ciphertext,
            iv=iv,
            tag=tag,
        )
        db.add(mfa_secret)
        await db.flush()

        provisioning_uri = build_provisioning_uri(secret, user.email)
        return MFAEnrollResponse(provisioning_uri=provisioning_uri, secret=secret)

    # ------------------------------------------------------------------
    # MFA confirmation
    # ------------------------------------------------------------------

    async def confirm_mfa(self, db: AsyncSession, user_id: str, totp_code: str) -> dict:
        """Verify TOTP code and enable MFA for the user."""
        uid = _to_uuid(user_id)
        secret = await self._decrypt_totp_secret(db, uid)

        if not totp_verify(secret, totp_code):
            raise HTTPException(
                status_code=400,
                detail="Invalid TOTP code",
                headers={"X-Error-Code": "INVALID_TOTP"},
            )

        user_result = await db.execute(select(User).where(User.id == uid))
        user = user_result.scalar_one()
        user.mfa_enabled = True
        await db.flush()
        return {"mfa_enabled": True}

    # ------------------------------------------------------------------
    # MFA verification (partial token → full token pair)
    # ------------------------------------------------------------------

    async def verify_totp(
        self, db: AsyncSession, partial_token: str, totp_code: str
    ) -> TokenPair:
        """Exchange a partial JWT + valid TOTP code for a full TokenPair."""
        try:
            payload = jwt.decode(
                partial_token,
                settings.JWT_SECRET_KEY,
                algorithms=[settings.JWT_ALGORITHM],
            )
        except jwt.PyJWTError:
            raise HTTPException(status_code=401, detail="Invalid or expired partial token")

        if not payload.get("partial"):
            raise HTTPException(status_code=401, detail="Not a partial token")

        user_id = payload["sub"]
        uid = _to_uuid(user_id)
        user_result = await db.execute(select(User).where(User.id == uid))
        user = user_result.scalar_one_or_none()
        if user is None:
            raise HTTPException(status_code=401, detail="User not found")

        secret = await self._decrypt_totp_secret(db, uid)
        if not totp_verify(secret, totp_code):
            raise HTTPException(status_code=401, detail="Invalid TOTP code")

        return await self._issue_token_pair(db, user)

    # ------------------------------------------------------------------
    # Password reset — request
    # ------------------------------------------------------------------

    async def request_password_reset(self, db: AsyncSession, email: str) -> dict:
        """Generate a password reset token. Returns generic message to avoid email enumeration."""
        result = await db.execute(select(User).where(User.email == email))
        user = result.scalar_one_or_none()

        generic_msg = {"message": "If that email exists, a reset link has been sent."}
        if user is None:
            return generic_msg

        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(minutes=30)

        reset_token = PasswordResetToken(
            user_id=user.id,
            token_hash=token_hash,
            expires_at=expires_at,
            used=False,
        )
        db.add(reset_token)
        await db.flush()

        if settings.DEV_MODE:
            return {
                "message": generic_msg["message"],
                "dev_token": f"{token} [DEV ONLY - remove in production]",
            }
        return generic_msg

    # ------------------------------------------------------------------
    # Password reset — complete
    # ------------------------------------------------------------------

    async def complete_password_reset(
        self,
        db: AsyncSession,
        token: str,
        new_password: str,
        totp_code: str | None,
    ) -> dict:
        """Validate reset token, update password, revoke all sessions."""
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        result = await db.execute(
            select(PasswordResetToken).where(PasswordResetToken.token_hash == token_hash)
        )
        reset_token = result.scalar_one_or_none()

        now = datetime.now(timezone.utc)
        if (
            reset_token is None
            or reset_token.used
            or reset_token.expires_at.replace(tzinfo=timezone.utc) < now
        ):
            raise HTTPException(
                status_code=400,
                detail="Invalid or expired reset token",
                headers={"X-Error-Code": "TOKEN_EXPIRED_OR_USED"},
            )

        # Double-check password length (Pydantic enforces this, but belt-and-suspenders)
        if len(new_password) < 12:
            raise HTTPException(status_code=422, detail="Password must be at least 12 characters")

        user_result = await db.execute(select(User).where(User.id == reset_token.user_id))
        user = user_result.scalar_one()

        if user.mfa_enabled and totp_code is None:
            raise HTTPException(
                status_code=400,
                detail="TOTP code required for MFA-enabled accounts",
            )

        if user.mfa_enabled:
            secret = await self._decrypt_totp_secret(db, str(user.id))
            if not totp_verify(secret, totp_code):
                raise HTTPException(status_code=400, detail="Invalid TOTP code")

        user.password_hash = _hash_password(new_password)
        reset_token.used = True

        # Revoke ALL refresh tokens for this user
        await db.execute(
            update(RefreshToken)
            .where(RefreshToken.user_id == user.id)
            .values(revoked=True)
        )

        await db.flush()

        # TODO: Log audit event (audit module not built yet)

        return {"message": "Password updated. All sessions have been revoked."}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _decrypt_totp_secret(self, db: AsyncSession, user_id) -> str:
        """Fetch and decrypt the TOTP secret for a user."""
        uid = _to_uuid(user_id)
        result = await db.execute(select(MFASecret).where(MFASecret.user_id == uid))
        mfa_secret = result.scalar_one_or_none()
        if mfa_secret is None:
            raise HTTPException(status_code=400, detail="MFA not enrolled for this user")

        totp_key = get_key_manager().get_totp_key()
        secret_bytes = decrypt(mfa_secret.encrypted_secret, mfa_secret.iv, mfa_secret.tag, totp_key)
        return secret_bytes.decode()
