"""
Email OTP service — alternative MFA via email-delivered one-time codes.

Flow:
  1. User logs in with email/password
  2. If email OTP is their MFA method, system generates a 6-digit code
  3. Code is hashed (SHA-256) and stored in DB with 5-minute expiry
  4. Plaintext code is emailed to the user
  5. User enters the code to complete authentication
"""
from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.email_otp import EmailOTP
from app.services.email_service import send_email

OTP_EXPIRY_MINUTES = 5
OTP_LENGTH = 6


def _generate_otp() -> str:
    """Generate a cryptographically random 6-digit OTP code."""
    # Use secrets.randbelow for uniform distribution
    code = secrets.randbelow(10 ** OTP_LENGTH)
    return str(code).zfill(OTP_LENGTH)


def _hash_code(code: str) -> str:
    """SHA-256 hash of the OTP code (we never store plaintext)."""
    return hashlib.sha256(code.encode()).hexdigest()


class OTPService:

    async def send_otp(self, db: AsyncSession, user_id: uuid.UUID, email: str) -> dict:
        """Generate an OTP, store the hash, and email the code to the user."""
        # Invalidate any existing unused OTPs for this user
        await db.execute(
            update(EmailOTP)
            .where(EmailOTP.user_id == user_id, EmailOTP.used == False)  # noqa: E712
            .values(used=True)
        )

        code = _generate_otp()
        code_hash = _hash_code(code)
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=OTP_EXPIRY_MINUTES)

        otp_record = EmailOTP(
            user_id=user_id,
            code_hash=code_hash,
            expires_at=expires_at,
        )
        db.add(otp_record)
        await db.flush()

        # Send the code via email
        from app.core.config import settings as _settings
        app_name = _settings.APP_NAME
        html = f"""
        <div style="font-family:sans-serif;max-width:400px;margin:0 auto">
          <h2 style="color:#1e3a5f">{app_name} — Verification Code</h2>
          <p>Your one-time verification code is:</p>
          <div style="font-size:2rem;font-weight:700;letter-spacing:0.3em;text-align:center;
                      background:#f0f0f0;padding:16px;border-radius:8px;margin:1rem 0">
            {code}
          </div>
          <p style="color:#666;font-size:12px">This code expires in {OTP_EXPIRY_MINUTES} minutes.
          If you did not request this, ignore this email.</p>
          <hr style="border:none;border-top:1px solid #eee;margin:1.5rem 0" />
          <p style="color:#999;font-size:11px">{app_name} — Secure Medical Records Platform</p>
        </div>
        """
        send_email(email, f"{app_name} — Your Verification Code", html)

        return {"message": "Verification code sent to your email."}

    async def verify_otp(self, db: AsyncSession, user_id: uuid.UUID, code: str) -> bool:
        """Verify an OTP code. Returns True if valid, raises HTTPException if not."""
        code_hash = _hash_code(code)
        now = datetime.now(timezone.utc)

        result = await db.execute(
            select(EmailOTP).where(
                EmailOTP.user_id == user_id,
                EmailOTP.code_hash == code_hash,
                EmailOTP.used == False,  # noqa: E712
                EmailOTP.expires_at > now,
            )
        )
        otp_record = result.scalar_one_or_none()

        if otp_record is None:
            raise HTTPException(
                status_code=401,
                detail="Invalid or expired verification code",
            )

        # Mark as used
        otp_record.used = True
        await db.flush()
        return True
