"""Audit-related Pydantic schemas."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class FailedLoginSummary(BaseModel):
    """Per-account failed login summary."""
    actor_id: uuid.UUID
    actor_email: Optional[str] = None
    actor_name: Optional[str] = None
    failure_count: int
    last_attempt: datetime
    client_ips: list[str]


class SecurityAlertSummary(BaseModel):
    """Admin-only security alert dashboard payload."""
    generated_at: datetime
    window_hours: int
    failed_logins: list[FailedLoginSummary]
    access_denied_count: int
    replay_blocked_count: int
    top_offending_ips: list[dict]  # [{"ip": str, "count": int}]


class AuditEntryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    event_type: str
    actor_id: uuid.UUID
    actor_email: Optional[str] = None
    actor_name: Optional[str] = None
    resource_id: uuid.UUID
    resource_type: str
    client_ip: str
    occurred_at: datetime
    chain_hash: str
    extra: Optional[dict] = None


class AuditFilter(BaseModel):
    actor_id: Optional[uuid.UUID] = None
    resource_id: Optional[uuid.UUID] = None
    subject_user_id: Optional[uuid.UUID] = None
    event_type: Optional[str] = None
    from_dt: Optional[datetime] = Field(default=None, alias="from")
    to_dt: Optional[datetime] = Field(default=None, alias="to")
    limit: int = Field(default=50, le=200)
    offset: int = 0


class ChainVerificationResult(BaseModel):
    chain_intact: bool
    entries_checked: int
    first_broken_at_id: Optional[int] = None
    broken_entry_event: Optional[str] = None
    broken_entry_occurred_at: Optional[datetime] = None
    broken_entry_actor_id: Optional[uuid.UUID] = None
