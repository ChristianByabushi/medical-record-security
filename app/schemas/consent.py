"""Consent-related Pydantic schemas."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class ConsentRequestIn(BaseModel):
    patient_id: uuid.UUID
    duration_days: int = Field(ge=1, le=365)


class ConsentGrantOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    doctor_id: uuid.UUID
    patient_id: uuid.UUID
    status: str
    requested_duration_days: int
    expires_at: Optional[datetime]
    created_at: datetime
    updated_at: datetime
