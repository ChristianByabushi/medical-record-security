"""PatientProfile Pydantic schemas."""
from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict


class PatientProfileIn(BaseModel):
    date_of_birth: Optional[date] = None
    sex: Optional[str] = None
    nationality: Optional[str] = None
    phone_number: Optional[str] = None
    insurance_provider: Optional[str] = None
    blood_type: Optional[str] = None
    known_allergies: Optional[str] = None
    known_conditions: Optional[str] = None
    dnr_status: Optional[bool] = None


class PatientProfileOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    user_id: uuid.UUID
    date_of_birth: Optional[date] = None
    sex: Optional[str] = None
    nationality: Optional[str] = None
    phone_number: Optional[str] = None
    insurance_provider: Optional[str] = None
    blood_type: Optional[str] = None
    known_allergies: Optional[str] = None
    known_conditions: Optional[str] = None
    dnr_status: Optional[bool] = None
    updated_at: datetime


class EmergencyContactLinkOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    patient_id: uuid.UUID
    contact_user_id: uuid.UUID
    contact_email: Optional[str] = None
    contact_name: Optional[str] = None
    relationship: Optional[str] = None
    created_at: datetime


class EmergencyContactLinkIn(BaseModel):
    contact_email: str  # resolve by email
    relationship: Optional[str] = None


# Limited summary for Emergency_Contact role
class EmergencySummaryOut(BaseModel):
    full_name: str
    blood_type: Optional[str] = None
    known_allergies: Optional[str] = None
    known_conditions: Optional[str] = None
    dnr_status: Optional[bool] = None
