"""AuditLog ORM model — append-only, hash-chained audit trail.

NOTE: The application DB role must be granted INSERT + SELECT only on this
table (no UPDATE or DELETE). This is enforced at the PostgreSQL privilege
level, not in application code.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import BigInteger, DateTime, ForeignKey, Index, Integer, JSON, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class AuditLog(Base):
    __tablename__ = "audit_log"

    __table_args__ = (
        Index("idx_al_actor_id", "actor_id"),
        Index("idx_al_resource_id", "resource_id"),
        Index("idx_al_occurred_at", "occurred_at"),
    )

    # Use Integer for SQLite compatibility (BigInteger maps to INTEGER on SQLite anyway)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_type: Mapped[str] = mapped_column(String(50), nullable=False)
    # No FK constraint — actor may be nil UUID for unauthenticated events (replay blocks, unknown-email logins)
    actor_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    resource_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(30), nullable=False)
    # Stored as VARCHAR(45) for SQLAlchemy compatibility (INET not portable)
    client_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    chain_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    extra: Mapped[dict | None] = mapped_column(JSON, nullable=True)
