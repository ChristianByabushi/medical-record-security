"""Records service: create, read, update, delete, and list medical records."""
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
from app.schemas.records import RecordOut


def _check_read_access(actor: TokenClaims, record: MedicalRecord, has_consent: bool) -> None:
    """Raise HTTP 403 if actor cannot read this record."""
    role = actor.role
    actor_uuid = uuid.UUID(actor.user_id)

    if role == "Patient":
        if record.patient_id != actor_uuid:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    elif role in ("Doctor", "Nurse"):
        if not has_consent:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Active consent required",
            )
    elif role == "Lab_Technician":
        if record.created_by != actor_uuid:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    else:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")


def _check_write_access(actor: TokenClaims, record: MedicalRecord, has_consent: bool) -> None:
    """Raise HTTP 403 if actor cannot write this record."""
    role = actor.role
    actor_uuid = uuid.UUID(actor.user_id)

    if role == "Doctor":
        if not has_consent:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Active consent required",
            )
    elif role == "Lab_Technician":
        if record.created_by != actor_uuid:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    elif role == "Nurse":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Nurses have read-only access",
        )
    else:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")


def _decrypt_record(record: MedicalRecord) -> dict:
    key = get_key_manager().get_record_key()
    plaintext = decrypt(record.encrypted_data, record.iv, record.tag, key)
    return json.loads(plaintext.decode("utf-8"))


def _record_to_out(record: MedicalRecord, data: dict | None = None) -> RecordOut:
    return RecordOut(
        id=record.id,
        patient_id=record.patient_id,
        record_type=record.record_type,
        created_by=record.created_by,
        data=data,
        created_at=record.created_at,
        updated_at=record.updated_at,
    )


class RecordsService:

    async def create_record(
        self,
        db: AsyncSession,
        actor: TokenClaims,
        patient_id: uuid.UUID,
        record_type: str,
        data: dict,
        client_ip: str = "0.0.0.0",
    ) -> RecordOut:
        plaintext = json.dumps(data).encode("utf-8")
        key = get_key_manager().get_record_key()
        ciphertext, iv, tag = encrypt(plaintext, key)

        record = MedicalRecord(
            patient_id=patient_id,
            record_type=record_type,
            created_by=uuid.UUID(actor.user_id),
            encrypted_data=ciphertext,
            iv=iv,
            tag=tag,
        )
        db.add(record)
        await db.flush()
        await db.refresh(record)

        # Audit
        from app.services.audit_service import AuditService
        await AuditService().append(
            db,
            event_type="RECORD_CREATE",
            actor_id=uuid.UUID(actor.user_id),
            resource_id=record.id,
            resource_type="medical_record",
            client_ip=client_ip,
        )

        return _record_to_out(record)

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
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Record not found")

        has_consent = await self._check_consent(db, actor, record.patient_id)
        _check_read_access(actor, record, has_consent)

        data = _decrypt_record(record)

        # Audit
        from app.services.audit_service import AuditService
        await AuditService().append(
            db,
            event_type="RECORD_READ",
            actor_id=uuid.UUID(actor.user_id),
            resource_id=record.id,
            resource_type="medical_record",
            client_ip=client_ip,
        )

        return _record_to_out(record, data)

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
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Record not found")

        has_consent = await self._check_consent(db, actor, record.patient_id)
        _check_write_access(actor, record, has_consent)

        plaintext = json.dumps(data).encode("utf-8")
        key = get_key_manager().get_record_key()
        ciphertext, iv, tag = encrypt(plaintext, key)

        record.encrypted_data = ciphertext
        record.iv = iv
        record.tag = tag
        record.updated_at = datetime.now(timezone.utc)
        await db.flush()
        await db.refresh(record)

        # Audit
        from app.services.audit_service import AuditService
        await AuditService().append(
            db,
            event_type="RECORD_UPDATE",
            actor_id=uuid.UUID(actor.user_id),
            resource_id=record.id,
            resource_type="medical_record",
            client_ip=client_ip,
        )

        return _record_to_out(record, data)

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
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Record not found")

        # Only Doctor with active consent can delete
        if actor.role != "Doctor":
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")

        has_consent = await self._check_consent(db, actor, record.patient_id)
        if not has_consent:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Active consent required",
            )

        record.is_deleted = True
        record.updated_at = datetime.now(timezone.utc)
        await db.flush()

        # Audit
        from app.services.audit_service import AuditService
        await AuditService().append(
            db,
            event_type="RECORD_DELETE",
            actor_id=uuid.UUID(actor.user_id),
            resource_id=record_id,
            resource_type="medical_record",
            client_ip=client_ip,
        )

        return {"message": "Record soft-deleted."}

    async def list_records(
        self,
        db: AsyncSession,
        actor: TokenClaims,
        patient_id: uuid.UUID,
        client_ip: str = "0.0.0.0",
    ) -> list[RecordOut]:
        result = await db.execute(
            select(MedicalRecord).where(
                MedicalRecord.patient_id == patient_id,
                MedicalRecord.is_deleted == False,  # noqa: E712
            )
        )
        records = result.scalars().all()

        has_consent = await self._check_consent(db, actor, patient_id)

        out = []
        for record in records:
            try:
                _check_read_access(actor, record, has_consent)
            except HTTPException:
                continue
            data = _decrypt_record(record)
            out.append(_record_to_out(record, data))

        return out

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _check_consent(
        self, db: AsyncSession, actor: TokenClaims, patient_id: uuid.UUID
    ) -> bool:
        """Return True if actor is a Doctor/Nurse with active consent for patient."""
        if actor.role not in ("Doctor", "Nurse"):
            return False
        from app.services.consent_service import ConsentService
        return await ConsentService().check_active_grant(
            db,
            doctor_id=uuid.UUID(actor.user_id),
            patient_id=patient_id,
        )
