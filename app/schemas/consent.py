"""Consent-related Pydantic schemas."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class ConsentRequestIn(BaseModel):
    patient_email: str = Field(description="Patient email address")
    duration_hours: int = Field(ge=1, le=8760, description="Duration in hours (max 365 days)")


class ConsentGrantOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    doctor_id: uuid.UUID
    patient_id: uuid.UUID
    doctor_email: Optional[str] = None
    doctor_name: Optional[str] = None
    patient_email: Optional[str] = None
    patient_name: Optional[str] = None
    status: str
    requested_duration_hours: int
    expires_at: Optional[datetime]
    created_at: datetime
    updated_at: datetime
