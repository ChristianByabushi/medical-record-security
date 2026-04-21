"""PatientProfile ORM model — stores demographic and sensitive patient data."""
from __future__ import annotations

import uuid
from datetime import date, datetime

from sqlalchemy import Date, DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class PatientProfile(Base):
    __tablename__ = "patient_profiles"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    # Identity / Demographics
    date_of_birth: Mapped[date | None] = mapped_column(Date, nullable=True)
    sex: Mapped[str | None] = mapped_column(String(20), nullable=True)
    nationality: Mapped[str | None] = mapped_column(String(100), nullable=True)
    phone_number: Mapped[str | None] = mapped_column(String(30), nullable=True)
    insurance_provider: Mapped[str | None] = mapped_column(String(100), nullable=True)
    # Emergency & medical summary (high sensitivity)
    blood_type: Mapped[str | None] = mapped_column(String(10), nullable=True)
    known_allergies: Mapped[str | None] = mapped_column(Text, nullable=True)
    known_conditions: Mapped[str | None] = mapped_column(Text, nullable=True)
    dnr_status: Mapped[bool | None] = mapped_column(nullable=True, default=False)
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=datetime.utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow
    )
