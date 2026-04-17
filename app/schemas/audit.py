"""Audit-related Pydantic schemas."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class AuditEntryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    event_type: str
    actor_id: uuid.UUID
    resource_id: uuid.UUID
    resource_type: str
    client_ip: str
    occurred_at: datetime
    chain_hash: str
    extra: Optional[dict] = None


class AuditFilter(BaseModel):
    actor_id: Optional[uuid.UUID] = None
    resource_id: Optional[uuid.UUID] = None
    from_dt: Optional[datetime] = Field(default=None, alias="from")
    to_dt: Optional[datetime] = Field(default=None, alias="to")
    limit: int = Field(default=50, le=200)
    offset: int = 0


class ChainVerificationResult(BaseModel):
    chain_intact: bool
    entries_checked: int
    first_broken_at_id: Optional[int] = None
    first_entry_id: Optional[int] = None
    last_entry_id: Optional[int] = None
