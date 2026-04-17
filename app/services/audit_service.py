"""Audit service: append-only, hash-chained audit log."""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditLog
from app.schemas.audit import AuditEntryOut, AuditFilter, ChainVerificationResult


class AuditService:

    async def append(
        self,
        db: AsyncSession,
        event_type: str,
        actor_id: uuid.UUID,
        resource_id: uuid.UUID,
        resource_type: str,
        client_ip: str,
        extra: dict | None = None,
    ) -> AuditLog:
        """Append a new audit entry with hash chaining."""
        occurred_at = datetime.now(timezone.utc)

        # Fetch previous chain hash
        result = await db.execute(
            select(AuditLog.chain_hash).order_by(AuditLog.id.desc()).limit(1)
        )
        row = result.scalar_one_or_none()
        prev_hash: str = row if row is not None else "0" * 64

        # Deterministic serialisation
        entry_data = {
            "event_type": event_type,
            "actor_id": str(actor_id),
            "resource_id": str(resource_id),
            "resource_type": resource_type,
            "client_ip": client_ip,
            "occurred_at": occurred_at.isoformat(),
            "extra": extra,
        }
        serialized = json.dumps(entry_data, sort_keys=True, separators=(",", ":"))
        chain_hash = hashlib.sha256((serialized + prev_hash).encode()).hexdigest()

        log_entry = AuditLog(
            event_type=event_type,
            actor_id=actor_id,
            resource_id=resource_id,
            resource_type=resource_type,
            client_ip=client_ip,
            occurred_at=occurred_at,
            chain_hash=chain_hash,
            extra=extra,
        )
        db.add(log_entry)
        await db.flush()
        await db.refresh(log_entry)
        return log_entry

    async def verify_chain(self, db: AsyncSession) -> ChainVerificationResult:
        """Recompute all chain hashes and verify integrity."""
        result = await db.execute(select(AuditLog).order_by(AuditLog.id.asc()))
        entries = result.scalars().all()

        prev_hash = "0" * 64
        for entry in entries:
            entry_data = {
                "event_type": entry.event_type,
                "actor_id": str(entry.actor_id),
                "resource_id": str(entry.resource_id),
                "resource_type": entry.resource_type,
                "client_ip": entry.client_ip,
                "occurred_at": entry.occurred_at.isoformat(),
                "extra": entry.extra,
            }
            serialized = json.dumps(entry_data, sort_keys=True, separators=(",", ":"))
            expected = hashlib.sha256((serialized + prev_hash).encode()).hexdigest()

            if expected != entry.chain_hash:
                return ChainVerificationResult(
                    chain_intact=False,
                    entries_checked=len(entries),
                    first_broken_at_id=entry.id,
                )
            prev_hash = entry.chain_hash

        return ChainVerificationResult(chain_intact=True, entries_checked=len(entries))

    async def list_entries(
        self, db: AsyncSession, filters: AuditFilter
    ) -> list[AuditEntryOut]:
        """Query audit log with optional filters."""
        query = select(AuditLog)

        if filters.actor_id is not None:
            query = query.where(AuditLog.actor_id == filters.actor_id)
        if filters.resource_id is not None:
            query = query.where(AuditLog.resource_id == filters.resource_id)
        if filters.from_dt is not None:
            query = query.where(AuditLog.occurred_at >= filters.from_dt)
        if filters.to_dt is not None:
            query = query.where(AuditLog.occurred_at <= filters.to_dt)

        query = query.order_by(AuditLog.id.asc()).offset(filters.offset).limit(filters.limit)

        result = await db.execute(query)
        entries = result.scalars().all()
        return [AuditEntryOut.model_validate(e) for e in entries]
