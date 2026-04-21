"""Consent service: manage consent grants between doctors and patients."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.consent_grant import ConsentGrant
from app.models.user import User
from app.schemas.consent import ConsentGrantOut


class ConsentService:

    async def _enrich_grant(self, db: AsyncSession, grant: ConsentGrant) -> ConsentGrantOut:
        """Add doctor/patient email and name to the grant output."""
        out = ConsentGrantOut.model_validate(grant)
        # Resolve doctor
        doc = await db.execute(select(User).where(User.id == grant.doctor_id))
        doctor = doc.scalar_one_or_none()
        if doctor:
            out.doctor_email = doctor.email
            out.doctor_name = doctor.full_name
        # Resolve patient
        pat = await db.execute(select(User).where(User.id == grant.patient_id))
        patient = pat.scalar_one_or_none()
        if patient:
            out.patient_email = patient.email
            out.patient_name = patient.full_name
        return out

    async def request_consent(
        self,
        db: AsyncSession,
        doctor_id: uuid.UUID,
        patient_email: str,
        duration_hours: int,
    ) -> ConsentGrantOut:
        """Insert a pending consent grant. Resolves patient by email."""
        # Find patient by email
        result = await db.execute(select(User).where(User.email == patient_email, User.role == "Patient"))
        patient = result.scalar_one_or_none()
        if patient is None:
            raise HTTPException(status_code=404, detail="Patient not found with that email")

        grant = ConsentGrant(
            doctor_id=doctor_id,
            patient_id=patient.id,
            status="pending",
            requested_duration_hours=duration_hours,
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
            extra={
                "patient_id": str(patient.id),
                "doctor_id": str(doctor_id),
                "subject_user_id": str(patient.id),
            },
        )

        # Send email notification to patient
        try:
            from app.services.email_service import send_email
            from app.core.config import settings
            doc_result = await db.execute(select(User).where(User.id == doctor_id))
            doctor = doc_result.scalar_one_or_none()
            doc_name = doctor.full_name or doctor.email if doctor else "A clinician"
            duration_str = f"{duration_hours} hours" if duration_hours < 24 else f"{duration_hours // 24} day(s)"
            send_email(
                patient.email,
                f"{settings.APP_NAME} — Access Request from {doc_name}",
                f"""<div style="font-family:sans-serif;max-width:500px;margin:0 auto">
                  <h2 style="color:#1e3a5f">{settings.APP_NAME} — Access Request</h2>
                  <p><strong>{doc_name}</strong> ({doctor.email if doctor else 'unknown'}) is requesting access to your medical records for <strong>{duration_str}</strong>.</p>
                  <p>Please log in to approve or reject this request.</p>
                  <a href="{settings.APP_URL}" style="display:inline-block;background:#2563eb;color:#ffffff;padding:10px 24px;border-radius:6px;text-decoration:none;font-weight:500;margin:1rem 0">Review Request</a>
                  <p style="color:#666;font-size:12px">If you did not expect this, contact your administrator.</p>
                </div>""",
            )
        except Exception:
            pass  # Don't fail the request if email fails

        return await self._enrich_grant(db, grant)

    async def approve_consent(
        self,
        db: AsyncSession,
        patient_id: uuid.UUID,
        grant_id: uuid.UUID,
    ) -> ConsentGrantOut:
        grant = await self._fetch_grant(db, grant_id)
        self._verify_ownership(grant, patient_id)

        if grant.status != "pending":
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Grant is not in pending state")

        now = datetime.now(timezone.utc)
        grant.status = "active"
        grant.expires_at = now + timedelta(hours=grant.requested_duration_hours)
        grant.updated_at = now
        await db.flush()
        await db.refresh(grant)

        from app.services.audit_service import AuditService
        await AuditService().append(
            db, event_type="CONSENT_APPROVED", actor_id=patient_id,
            resource_id=grant.id, resource_type="consent_grant", client_ip="0.0.0.0",
            extra={
                "patient_id": str(patient_id),
                "doctor_id": str(grant.doctor_id),
                "subject_user_id": str(patient_id),
            },
        )
        return await self._enrich_grant(db, grant)

    async def reject_consent(
        self,
        db: AsyncSession,
        patient_id: uuid.UUID,
        grant_id: uuid.UUID,
    ) -> ConsentGrantOut:
        grant = await self._fetch_grant(db, grant_id)
        self._verify_ownership(grant, patient_id)

        now = datetime.now(timezone.utc)
        grant.status = "rejected"
        grant.updated_at = now
        await db.flush()
        await db.refresh(grant)
        from app.services.audit_service import AuditService
        await AuditService().append(
            db, event_type="CONSENT_REJECTED", actor_id=patient_id,
            resource_id=grant.id, resource_type="consent_grant", client_ip="0.0.0.0",
            extra={
                "patient_id": str(patient_id),
                "doctor_id": str(grant.doctor_id),
                "subject_user_id": str(patient_id),
            },
        )
        return await self._enrich_grant(db, grant)

    async def revoke_consent(
        self,
        db: AsyncSession,
        patient_id: uuid.UUID,
        grant_id: uuid.UUID,
    ) -> ConsentGrantOut:
        grant = await self._fetch_grant(db, grant_id)
        self._verify_ownership(grant, patient_id)

        if grant.status != "active":
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Only active grants can be revoked")

        now = datetime.now(timezone.utc)
        grant.status = "revoked"
        grant.updated_at = now
        await db.flush()
        await db.refresh(grant)

        from app.services.audit_service import AuditService
        await AuditService().append(
            db, event_type="CONSENT_REVOKED", actor_id=patient_id,
            resource_id=grant.id, resource_type="consent_grant", client_ip="0.0.0.0",
            extra={
                "patient_id": str(patient_id),
                "doctor_id": str(grant.doctor_id),
                "subject_user_id": str(patient_id),
            },
        )
        return await self._enrich_grant(db, grant)

    async def release_consent(
        self,
        db: AsyncSession,
        doctor_id: uuid.UUID,
        grant_id: uuid.UUID,
    ) -> ConsentGrantOut:
        grant = await self._fetch_grant(db, grant_id)
        if grant.doctor_id != doctor_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You do not own this consent grant")
        if grant.status != "active":
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Only active grants can be released")

        now = datetime.now(timezone.utc)
        grant.status = "revoked"
        grant.updated_at = now
        await db.flush()
        await db.refresh(grant)

        from app.services.audit_service import AuditService
        await AuditService().append(
            db, event_type="CONSENT_RELEASED", actor_id=doctor_id,
            resource_id=grant.id, resource_type="consent_grant", client_ip="0.0.0.0",
            extra={
                "patient_id": str(grant.patient_id),
                "doctor_id": str(doctor_id),
                "subject_user_id": str(grant.patient_id),
            },
        )
        return await self._enrich_grant(db, grant)

    async def list_grants(self, db: AsyncSession, patient_id: uuid.UUID) -> list[ConsentGrantOut]:
        result = await db.execute(select(ConsentGrant).where(ConsentGrant.patient_id == patient_id))
        grants = result.scalars().all()
        return [await self._enrich_grant(db, g) for g in grants]

    async def list_doctor_grants(self, db: AsyncSession, doctor_id: uuid.UUID) -> list[ConsentGrantOut]:
        """List all grants where this doctor requested access."""
        result = await db.execute(select(ConsentGrant).where(ConsentGrant.doctor_id == doctor_id))
        grants = result.scalars().all()
        return [await self._enrich_grant(db, g) for g in grants]

    async def check_active_grant(self, db: AsyncSession, doctor_id: uuid.UUID, patient_id: uuid.UUID) -> bool:
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

    async def _fetch_grant(self, db: AsyncSession, grant_id: uuid.UUID) -> ConsentGrant:
        result = await db.execute(select(ConsentGrant).where(ConsentGrant.id == grant_id))
        grant = result.scalar_one_or_none()
        if grant is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Consent grant not found")
        return grant

    def _verify_ownership(self, grant: ConsentGrant, patient_id: uuid.UUID) -> None:
        if grant.patient_id != patient_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You do not own this consent grant")
