"""NonceStore ORM model — replay-attack prevention via nonce tracking."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Index, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class NonceStore(Base):
    __tablename__ = "nonce_store"

    __table_args__ = (
        Index("idx_ns_expires_at", "expires_at"),
    )

    nonce: Mapped[str] = mapped_column(String(128), primary_key=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
