"""Records service: create, read, update, publish, delete medical records.

Access rules:
- Doctor: sees records they CREATED (any status) + published records of patients
  who granted them active consent.
- Nurse: sees published records of patients who granted them active consent (read-only).
- Lab_Technician: sees only records they created.
- Patient: sees only their own PUBLISHED records.
- Draft records are visible ONLY to the creator until published.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import decrypt, encrypt
from app.core.key_manager import get_key_manager
from app.middleware.rbac import TokenClaims
from app.models.medical_record import MedicalRecord
from app.models.user import User
from app.schemas.records import RecordOut


def _decrypt_record(record: MedicalRecord) -> dict:
    key = get_key_manager().get_record_key()
    plaintext = decrypt(record.encrypted_data, record.iv, record.tag, key)
    return json.loads(plaintext.decode("utf-8"))


def _record_to_out(
    record: MedicalRecord,
    data: dict | None = None,
    creator: User | None = None,
) -> RecordOut:
    return RecordOut(
        id=record.id,
        patient_id=record.patient_id,
        record_type=record.record_type,
        created_by=record.created_by,
        creator_email=creator.email if creator else None,
        creator_name=creator.full_name if creator else None,
        status=record.status,
        data=data,
        published_at=record.published_at,
        created_at=record.created_at,
        updated_at=record.updated_at,
    )


def _can_read(actor: TokenClaims, record: MedicalRecord, has_consent: bool) -> bool:
    """Return True if actor may read this record (no exception raised)."""
    role = actor.role
    actor_uuid = uuid.UUID(actor.user_id)

    # Creator always sees their own records (draft or published)
    if record.created_by == actor_uuid:
        return True

    if role == "Patient":
        # Patient sees only their own published records
        return record.patient_id == actor_uuid and record.status == "published"

    if role in ("Doctor", "Nurse"):
        # Must have active consent AND record must be published
        return has_consent and record.status == "published"

    if role == "Lab_Technician":
        # Only records they created (handled above)
        return False

    return False


class RecordsService:

    async def _get_creator(self, db: AsyncSession, creator_id: uuid.UUID) -> User | None:
        result = await db.execute(select(User).where(User.id == creator_id))
        return result.scalar_one_or_none()

    async def _check_consent(
        self, db: AsyncSession, actor: TokenClaims, patient_id: uuid.UUID
    ) -> bool:
        if actor.role not in ("Doctor", "Nurse"):
            return False
        from app.services.consent_service import ConsentService
        return await ConsentService().check_active_grant(
            db,
            doctor_id=uuid.UUID(actor.user_id),
            patient_id=patient_id,
        )

    async def _audit(
        self, db: AsyncSession, event_type: str, actor_id: uuid.UUID,
        resource_id: uuid.UUID, patient_id: uuid.UUID, client_ip: str,
    ) -> None:
        from app.services.audit_service import AuditService
        await AuditService().append(
            db, event_type=event_type, actor_id=actor_id,
            resource_id=resource_id, resource_type="medical_record",
            client_ip=client_ip,
            extra={"patient_id": str(patient_id), "subject_user_id": str(patient_id)},
        )

    # ── Create ─────────────────────────────────────────────────────────

    async def create_record(
        self,
        db: AsyncSession,
        actor: TokenClaims,
        patient_id: uuid.UUID,
        record_type: str,
        data: dict,
        record_status: str = "draft",
        client_ip: str = "0.0.0.0",
    ) -> RecordOut:
        # Nurses can only create vitals records
        if actor.role == "Nurse" and record_type not in ("vitals", "medication_log", "triage"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Nurses may only create vitals, medication_log, or triage records",
            )

        # Validate status
        if record_status not in ("draft", "published"):
            record_status = "draft"

        plaintext = json.dumps(data).encode("utf-8")
        key = get_key_manager().get_record_key()
        ciphertext, iv, tag = encrypt(plaintext, key)

        now = datetime.now(timezone.utc)
        record = MedicalRecord(
            patient_id=patient_id,
            record_type=record_type,
            created_by=uuid.UUID(actor.user_id),
            encrypted_data=ciphertext,
            iv=iv,
            tag=tag,
            status=record_status,
            published_at=now if record_status == "published" else None,
        )
        db.add(record)
        await db.flush()
        await db.refresh(record)

        event = "RECORD_CREATED" if record_status == "draft" else "RECORD_PUBLISHED"
        await self._audit(db, event, uuid.UUID(actor.user_id), record.id, patient_id, client_ip)

        # Notify patient by email if published immediately
        if record_status == "published":
            await self._notify_patient_published(db, record)

        creator = await self._get_creator(db, record.created_by)
        return _record_to_out(record, creator=creator)

    # ── Publish draft ──────────────────────────────────────────────────

    async def publish_record(
        self,
        db: AsyncSession,
        actor: TokenClaims,
        record_id: uuid.UUID,
        client_ip: str = "0.0.0.0",
    ) -> RecordOut:
        result = await db.execute(
            select(MedicalRecord).where(
                MedicalRecord.id == record_id,
                MedicalRecord.is_deleted == False,  # noqa: E712
            )
        )
        record = result.scalar_one_or_none()
        if record is None:
            raise HTTPException(status_code=404, detail="Record not found")

        # Only the creator can publish
        if record.created_by != uuid.UUID(actor.user_id):
            raise HTTPException(status_code=403, detail="Only the creator can publish this record")

        if record.status == "published":
            raise HTTPException(status_code=400, detail="Record is already published")

        record.status = "published"
        record.published_at = datetime.now(timezone.utc)
        await db.flush()
        await db.refresh(record)

        await self._audit(db, "RECORD_PUBLISHED", uuid.UUID(actor.user_id), record.id, record.patient_id, client_ip)
        await self._notify_patient_published(db, record)

        creator = await self._get_creator(db, record.created_by)
        data = _decrypt_record(record)
        return _record_to_out(record, data, creator)

    # ── Get single record ──────────────────────────────────────────────

    async def get_record(
        self,
        db: AsyncSession,
        actor: TokenClaims,
        record_id: uuid.UUID,
        client_ip: str = "0.0.0.0",
    ) -> RecordOut:
        result = await db.execute(
            select(MedicalRecord).where(
                MedicalRecord.id == record_id,
                MedicalRecord.is_deleted == False,  # noqa: E712
            )
        )
        record = result.scalar_one_or_none()
        if record is None:
            raise HTTPException(status_code=404, detail="Record not found")

        has_consent = await self._check_consent(db, actor, record.patient_id)
        if not _can_read(actor, record, has_consent):
            await self._audit_denied(db, actor, record_id, client_ip)
            raise HTTPException(status_code=403, detail="Access denied")

        data = _decrypt_record(record)
        await self._audit(db, "RECORD_READ", uuid.UUID(actor.user_id), record.id, record.patient_id, client_ip)

        creator = await self._get_creator(db, record.created_by)
        return _record_to_out(record, data, creator)

    # ── Update ─────────────────────────────────────────────────────────

    async def update_record(
        self,
        db: AsyncSession,
        actor: TokenClaims,
        record_id: uuid.UUID,
        data: dict,
        client_ip: str = "0.0.0.0",
    ) -> RecordOut:
        result = await db.execute(
            select(MedicalRecord).where(
                MedicalRecord.id == record_id,
                MedicalRecord.is_deleted == False,  # noqa: E712
            )
        )
        record = result.scalar_one_or_none()
        if record is None:
            raise HTTPException(status_code=404, detail="Record not found")

        actor_uuid = uuid.UUID(actor.user_id)

        # Creator can always edit their own records (draft or published)
        if record.created_by == actor_uuid:
            pass  # allowed
        elif actor.role == "Doctor":
            has_consent = await self._check_consent(db, actor, record.patient_id)
            if not has_consent or record.status != "published":
                await self._audit_denied(db, actor, record_id, client_ip)
                raise HTTPException(status_code=403, detail="Active consent required to edit published records")
        else:
            await self._audit_denied(db, actor, record_id, client_ip)
            raise HTTPException(status_code=403, detail="Access denied")

        plaintext = json.dumps(data).encode("utf-8")
        key = get_key_manager().get_record_key()
        ciphertext, iv, tag = encrypt(plaintext, key)

        record.encrypted_data = ciphertext
        record.iv = iv
        record.tag = tag
        record.updated_at = datetime.now(timezone.utc)
        await db.flush()
        await db.refresh(record)

        await self._audit(db, "RECORD_UPDATED", actor_uuid, record.id, record.patient_id, client_ip)

        creator = await self._get_creator(db, record.created_by)
        return _record_to_out(record, data, creator)

    # ── Delete ─────────────────────────────────────────────────────────

    async def delete_record(
        self,
        db: AsyncSession,
        actor: TokenClaims,
        record_id: uuid.UUID,
        client_ip: str = "0.0.0.0",
    ) -> dict:
        result = await db.execute(
            select(MedicalRecord).where(
                MedicalRecord.id == record_id,
                MedicalRecord.is_deleted == False,  # noqa: E712
            )
        )
        record = result.scalar_one_or_none()
        if record is None:
            raise HTTPException(status_code=404, detail="Record not found")

        if actor.role != "Doctor":
            raise HTTPException(status_code=403, detail="Access denied")

        has_consent = await self._check_consent(db, actor, record.patient_id)
        actor_uuid = uuid.UUID(actor.user_id)
        # Creator can delete their own; others need consent
        if record.created_by != actor_uuid and not has_consent:
            await self._audit_denied(db, actor, record_id, client_ip)
            raise HTTPException(status_code=403, detail="Active consent required")

        record.is_deleted = True
        record.updated_at = datetime.now(timezone.utc)
        await db.flush()

        await self._audit(db, "RECORD_DELETED", actor_uuid, record_id, record.patient_id, client_ip)
        return {"message": "Record deleted."}

    # ── List ───────────────────────────────────────────────────────────

    async def list_records(
        self,
        db: AsyncSession,
        actor: TokenClaims,
        patient_id: uuid.UUID,
        client_ip: str = "0.0.0.0",
        include_drafts: bool = False,
    ) -> list[RecordOut]:
        actor_uuid = uuid.UUID(actor.user_id)
        has_consent = await self._check_consent(db, actor, patient_id)

        query = select(MedicalRecord).where(
            MedicalRecord.patient_id == patient_id,
            MedicalRecord.is_deleted == False,  # noqa: E712
        )
        result = await db.execute(query)
        records = result.scalars().all()

        out = []
        for record in records:
            if not _can_read(actor, record, has_consent):
                continue
            # Optionally filter out drafts for non-creators
            if record.status == "draft" and record.created_by != actor_uuid and not include_drafts:
                continue
            data = _decrypt_record(record)
            creator = await self._get_creator(db, record.created_by)
            out.append(_record_to_out(record, data, creator))

        # Sort newest first
        out.sort(key=lambda r: r.created_at, reverse=True)
        return out

    # ── Helpers ────────────────────────────────────────────────────────

    async def _audit_denied(
        self, db: AsyncSession, actor: TokenClaims,
        resource_id: uuid.UUID, client_ip: str,
    ) -> None:
        """Log a failed/denied access attempt."""
        from app.services.audit_service import AuditService
        await AuditService().append(
            db, event_type="ACCESS_DENIED",
            actor_id=uuid.UUID(actor.user_id),
            resource_id=resource_id,
            resource_type="medical_record",
            client_ip=client_ip,
            extra={"role": actor.role, "subject_user_id": None},
        )

    async def _notify_patient_published(
        self, db: AsyncSession, record: MedicalRecord
    ) -> None:
        """Send email to patient when a record is published."""
        try:
            result = await db.execute(select(User).where(User.id == record.patient_id))
            patient = result.scalar_one_or_none()
            creator_result = await db.execute(select(User).where(User.id == record.created_by))
            creator = creator_result.scalar_one_or_none()
            if not patient:
                return
            from app.services.email_service import send_email
            from app.core.config import settings
            creator_label = f"{creator.full_name} ({creator.email})" if creator else "Your clinician"
            send_email(
                patient.email,
                f"{settings.APP_NAME} — New Medical Record Available",
                f"""<div style="font-family:sans-serif;max-width:500px;margin:0 auto">
                  <h2 style="color:#1e3a5f">{settings.APP_NAME}</h2>
                  <p>A new <strong>{record.record_type}</strong> record has been added to your medical file by <strong>{creator_label}</strong>.</p>
                  <p>You can view it by logging into your account.</p>
                  <a href="{settings.APP_URL}" style="display:inline-block;background:#2563eb;color:#fff;padding:10px 24px;border-radius:6px;text-decoration:none;font-weight:500;margin:1rem 0">View My Records</a>
                  <p style="color:#666;font-size:12px">If you have questions, contact your healthcare provider.</p>
                </div>""",
            )
        except Exception:
            pass  # Never fail the main operation due to email
