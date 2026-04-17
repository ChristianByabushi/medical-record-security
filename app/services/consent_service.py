"""Consent service: manage consent grants between doctors and patients."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.consent_grant import ConsentGrant
from app.schemas.consent import ConsentGrantOut


class ConsentService:

    async def request_consent(
        self,
        db: AsyncSession,
        doctor_id: uuid.UUID,
        patient_id: uuid.UUID,
        duration_days: int,
    ) -> ConsentGrantOut:
        """Insert a pending consent grant. RBAC middleware ensures caller is a Doctor."""
        grant = ConsentGrant(
            doctor_id=doctor_id,
            patient_id=patient_id,
            status="pending",
            requested_duration_days=duration_days,
        )
        db.add(grant)
        await db.flush()
        await db.refresh(grant)

        from app.services.audit_service import AuditService
        await AuditService().append(
            db,
            event_type="CONSENT_REQUESTED",
            actor_id=doctor_id,
            resource_id=grant.id,
            resource_type="consent_grant",
            client_ip="0.0.0.0",
        )

        return ConsentGrantOut.model_validate(grant)

    async def approve_consent(
        self,
        db: AsyncSession,
        patient_id: uuid.UUID,
        grant_id: uuid.UUID,
    ) -> ConsentGrantOut:
        """Approve a pending grant. Only the owning patient may approve."""
        grant = await self._fetch_grant(db, grant_id)
        self._verify_ownership(grant, patient_id)

        if grant.status != "pending":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Grant is not in pending state",
            )

        now = datetime.now(timezone.utc)
        grant.status = "active"
        grant.expires_at = now + timedelta(seconds=grant.requested_duration_days * 86400)
        grant.updated_at = now
        await db.flush()
        await db.refresh(grant)

        from app.services.audit_service import AuditService
        await AuditService().append(
            db,
            event_type="CONSENT_APPROVED",
            actor_id=patient_id,
            resource_id=grant.id,
            resource_type="consent_grant",
            client_ip="0.0.0.0",
        )

        return ConsentGrantOut.model_validate(grant)

    async def reject_consent(
        self,
        db: AsyncSession,
        patient_id: uuid.UUID,
        grant_id: uuid.UUID,
    ) -> ConsentGrantOut:
        """Reject a pending grant."""
        grant = await self._fetch_grant(db, grant_id)
        self._verify_ownership(grant, patient_id)

        now = datetime.now(timezone.utc)
        grant.status = "rejected"
        grant.updated_at = now
        await db.flush()
        await db.refresh(grant)
        return ConsentGrantOut.model_validate(grant)

    async def revoke_consent(
        self,
        db: AsyncSession,
        patient_id: uuid.UUID,
        grant_id: uuid.UUID,
    ) -> ConsentGrantOut:
        """Revoke an active grant."""
        grant = await self._fetch_grant(db, grant_id)
        self._verify_ownership(grant, patient_id)

        if grant.status != "active":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Only active grants can be revoked",
            )

        now = datetime.now(timezone.utc)
        grant.status = "revoked"
        grant.updated_at = now
        await db.flush()
        await db.refresh(grant)

        from app.services.audit_service import AuditService
        await AuditService().append(
            db,
            event_type="CONSENT_REVOKED",
            actor_id=patient_id,
            resource_id=grant.id,
            resource_type="consent_grant",
            client_ip="0.0.0.0",
        )

        return ConsentGrantOut.model_validate(grant)

    async def list_grants(
        self,
        db: AsyncSession,
        patient_id: uuid.UUID,
    ) -> list[ConsentGrantOut]:
        """Return all grants where patient_id matches."""
        result = await db.execute(
            select(ConsentGrant).where(ConsentGrant.patient_id == patient_id)
        )
        grants = result.scalars().all()
        return [ConsentGrantOut.model_validate(g) for g in grants]

    async def check_active_grant(
        self,
        db: AsyncSession,
        doctor_id: uuid.UUID,
        patient_id: uuid.UUID,
    ) -> bool:
        """Return True if an active, non-expired grant exists for this doctor/patient pair."""
        now = datetime.now(timezone.utc)
        result = await db.execute(
            select(ConsentGrant).where(
                ConsentGrant.doctor_id == doctor_id,
                ConsentGrant.patient_id == patient_id,
                ConsentGrant.status == "active",
                ConsentGrant.expires_at > now,
            )
        )
        return result.scalar_one_or_none() is not None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _fetch_grant(self, db: AsyncSession, grant_id: uuid.UUID) -> ConsentGrant:
        result = await db.execute(
            select(ConsentGrant).where(ConsentGrant.id == grant_id)
        )
        grant = result.scalar_one_or_none()
        if grant is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Consent grant not found",
            )
        return grant

    def _verify_ownership(self, grant: ConsentGrant, patient_id: uuid.UUID) -> None:
        if grant.patient_id != patient_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not own this consent grant",
            )
