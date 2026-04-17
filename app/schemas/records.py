"""Medical records Pydantic schemas."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict


class RecordIn(BaseModel):
    patient_id: uuid.UUID
    record_type: str
    data: dict


class RecordUpdate(BaseModel):
    data: dict


class RecordOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    patient_id: uuid.UUID
    record_type: str
    created_by: uuid.UUID
    data: Optional[dict] = None
    created_at: datetime
    updated_at: datetime
