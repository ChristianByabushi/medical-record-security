"""Audit service: append-only, hash-chained audit log."""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditLog
from app.models.user import User
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
                    broken_entry_event=entry.event_type,
                    broken_entry_occurred_at=entry.occurred_at,
                    broken_entry_actor_id=entry.actor_id,
                )
            prev_hash = entry.chain_hash

        return ChainVerificationResult(chain_intact=True, entries_checked=len(entries))

    async def verify_my_entries(
        self, db: AsyncSession, subject_user_id: uuid.UUID
    ) -> ChainVerificationResult:
        """Verify content integrity of audit entries belonging to a specific user.

        Fetches the full chain in order, then for each entry that belongs to this
        user it recomputes the hash from the raw data and checks it matches the
        stored hash.  This detects whether any individual entry was silently edited
        in the database — even though the patient cannot verify ordering or
        deletions (that requires the full chain).
        """
        # Load the full chain in insertion order so we can recompute hashes
        result = await db.execute(select(AuditLog).order_by(AuditLog.id.asc()))
        all_entries = result.scalars().all()

        subject_str = str(subject_user_id)
        my_entries = [
            e for e in all_entries
            if (
                str(e.actor_id) == subject_str
                or str(e.resource_id) == subject_str
                or str((e.extra or {}).get("subject_user_id", "")) == subject_str
                or str((e.extra or {}).get("patient_id", "")) == subject_str
            )
        ]

        if not my_entries:
            return ChainVerificationResult(chain_intact=True, entries_checked=0)

        # Walk the full chain to build a map of id → expected_hash
        prev_hash = "0" * 64
        hash_map: dict[int, str] = {}
        for entry in all_entries:
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
            hash_map[entry.id] = expected
            prev_hash = entry.chain_hash  # use stored hash to continue chain

        # Now check only the patient's entries
        for entry in my_entries:
            if hash_map.get(entry.id) != entry.chain_hash:
                return ChainVerificationResult(
                    chain_intact=False,
                    entries_checked=len(my_entries),
                    first_broken_at_id=entry.id,
                    broken_entry_event=entry.event_type,
                    broken_entry_occurred_at=entry.occurred_at,
                    broken_entry_actor_id=entry.actor_id,
                )

        return ChainVerificationResult(chain_intact=True, entries_checked=len(my_entries))

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

        query = query.order_by(AuditLog.id.desc())

        result = await db.execute(query)
        entries = result.scalars().all()

        if filters.subject_user_id is not None:
            subject_user_id = str(filters.subject_user_id)
            filtered_entries = []
            for entry in entries:
                extra = entry.extra or {}
                if (
                    str(entry.actor_id) == subject_user_id
                    or str(entry.resource_id) == subject_user_id
                    or str(extra.get("subject_user_id", "")) == subject_user_id
                    or str(extra.get("patient_id", "")) == subject_user_id
                ):
                    filtered_entries.append(entry)
            entries = filtered_entries

        entries = entries[filters.offset : filters.offset + filters.limit]

        actor_ids = list({entry.actor_id for entry in entries})
        actor_map: dict[uuid.UUID, User] = {}
        if actor_ids:
            actor_result = await db.execute(select(User).where(User.id.in_(actor_ids)))
            actor_map = {user.id: user for user in actor_result.scalars().all()}

        return [
            AuditEntryOut(
                id=entry.id,
                event_type=entry.event_type,
                actor_id=entry.actor_id,
                actor_email=actor_map.get(entry.actor_id).email if actor_map.get(entry.actor_id) else None,
                actor_name=actor_map.get(entry.actor_id).full_name if actor_map.get(entry.actor_id) else None,
                resource_id=entry.resource_id,
                resource_type=entry.resource_type,
                client_ip=entry.client_ip,
                occurred_at=entry.occurred_at,
                chain_hash=entry.chain_hash,
                extra=entry.extra,
            )
            for entry in entries
        ]
