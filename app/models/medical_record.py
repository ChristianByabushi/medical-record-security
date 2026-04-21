"""MedicalRecord ORM model — stores AES-256-GCM encrypted PHI."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Index, LargeBinary, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class MedicalRecord(Base):
    __tablename__ = "medical_records"

    __table_args__ = (
        CheckConstraint(
            "status IN ('draft','published')",
            name="ck_medical_records_status",
        ),
        Index("idx_mr_patient_id", "patient_id"),
        Index("idx_mr_created_by", "created_by"),
        Index("idx_mr_record_type", "record_type"),
        Index("idx_mr_status", "status"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    patient_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    record_type: Mapped[str] = mapped_column(String(50), nullable=False)
    created_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    encrypted_data: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    iv: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    tag: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    # draft = only creator can see; published = patient + consented clinicians can see
    status: Mapped[str] = mapped_column(String(10), nullable=False, default="draft")
    is_deleted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    published_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=datetime.utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow
    )
