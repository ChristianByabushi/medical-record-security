"""Replay attack prevention: nonce + timestamp validation."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.base import get_db
from app.models.nonce_store import NonceStore


class ReplayGuard:

    @staticmethod
    async def validate(
        x_nonce: str = Header(..., alias="X-Nonce"),
        x_timestamp: str = Header(..., alias="X-Timestamp"),
        db: AsyncSession = Depends(get_db),
    ) -> None:
        # 1. Parse X-Timestamp as ISO-8601 UTC
        try:
            ts = datetime.fromisoformat(x_timestamp)
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            else:
                ts = ts.astimezone(timezone.utc)
        except (ValueError, TypeError):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid timestamp format",
                headers={"X-Error-Code": "REPLAY_TIMESTAMP_SKEW"},
            )

        # 2. Reject if |now - timestamp| > 300 seconds
        now = datetime.now(timezone.utc)
        skew = abs((now - ts).total_seconds())
        if skew > 300:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Timestamp outside acceptable window",
                headers={"X-Error-Code": "REPLAY_TIMESTAMP_SKEW"},
            )

        # 3. Check nonce_store for X-Nonce where expires_at > now
        result = await db.execute(
            select(NonceStore).where(
                NonceStore.nonce == x_nonce,
                NonceStore.expires_at > now,
            )
        )
        existing = result.scalar_one_or_none()
        if existing is not None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Nonce already used",
                headers={"X-Error-Code": "REPLAY_NONCE_SEEN"},
            )

        # 4. Insert nonce with expires_at = now + 5 minutes
        nonce_entry = NonceStore(
            nonce=x_nonce,
            expires_at=now + timedelta(minutes=5),
        )
        db.add(nonce_entry)
        await db.flush()
