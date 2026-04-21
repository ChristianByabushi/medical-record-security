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
    status: str = "draft"  # doctor chooses draft or published on create


class RecordUpdate(BaseModel):
    data: dict


class RecordPublish(BaseModel):
    """Publish a draft record."""
    pass


class RecordOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    patient_id: uuid.UUID
    record_type: str
    created_by: uuid.UUID
    creator_email: Optional[str] = None
    creator_name: Optional[str] = None
    status: str = "published"
    data: Optional[dict] = None
    published_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime
