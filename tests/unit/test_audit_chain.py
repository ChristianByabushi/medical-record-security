"""
Audit chain integrity tests.

Tests verify:
- Hash chain is intact after normal appends
- Tampering with any entry breaks the chain at that entry
- Patient-scoped verify detects tampering on their entries
- Patient-scoped verify passes when chain is clean
- Chain is broken at the correct entry (not before, not after)
"""
from __future__ import annotations

import hashlib
import json
import uuid

import pytest

from app.models.audit_log import AuditLog
from app.schemas.audit import AuditFilter
from app.services.audit_service import AuditService

_service = AuditService()

_ACTOR = uuid.uuid4()
_RESOURCE = uuid.uuid4()
_PATIENT = uuid.uuid4()


async def _append(db, event_type: str, actor_id=None, resource_id=None, extra=None):
    return await _service.append(
        db,
        event_type=event_type,
        actor_id=actor_id or _ACTOR,
        resource_id=resource_id or _RESOURCE,
        resource_type="test",
        client_ip="127.0.0.1",
        extra=extra,
    )


# ── Basic chain integrity ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_empty_chain_is_intact(db_session):
    """An empty audit log must report chain_intact=True with 0 entries."""
    result = await _service.verify_chain(db_session)
    assert result.chain_intact is True
    assert result.entries_checked == 0


@pytest.mark.asyncio
async def test_single_entry_chain_intact(db_session):
    """A single audit entry must produce an intact chain."""
    await _append(db_session, "USER_LOGIN")
    result = await _service.verify_chain(db_session)
    assert result.chain_intact is True
    assert result.entries_checked == 1


@pytest.mark.asyncio
async def test_multiple_entries_chain_intact(db_session):
    """Multiple sequential entries must produce an intact chain."""
    for i in range(10):
        await _append(db_session, f"EVENT_{i}")
    result = await _service.verify_chain(db_session)
    assert result.chain_intact is True
    assert result.entries_checked == 10


@pytest.mark.asyncio
async def test_chain_hash_depends_on_previous(db_session):
    """Each entry's hash must differ from the previous (chain linkage)."""
    e1 = await _append(db_session, "EVENT_A")
    e2 = await _append(db_session, "EVENT_B")
    assert e1.chain_hash != e2.chain_hash


# ── Tamper detection ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_tamper_first_entry_detected(db_session):
    """Modifying the first entry must break the chain at entry 1."""
    e1 = await _append(db_session, "USER_LOGIN")
    await _append(db_session, "RECORD_READ")
    await _append(db_session, "CONSENT_APPROVED")

    # Tamper: change the event_type of the first entry directly in DB
    e1.event_type = "TAMPERED_EVENT"
    await db_session.flush()

    result = await _service.verify_chain(db_session)
    assert result.chain_intact is False
    assert result.first_broken_at_id == e1.id
    assert result.entries_checked == 3


@pytest.mark.asyncio
async def test_tamper_middle_entry_detected(db_session):
    """Modifying a middle entry must break the chain at that entry."""
    await _append(db_session, "EVENT_1")
    e2 = await _append(db_session, "EVENT_2")
    await _append(db_session, "EVENT_3")
    await _append(db_session, "EVENT_4")

    # Tamper: change client_ip of the middle entry
    e2.client_ip = "10.0.0.1"
    await db_session.flush()

    result = await _service.verify_chain(db_session)
    assert result.chain_intact is False
    assert result.first_broken_at_id == e2.id


@pytest.mark.asyncio
async def test_tamper_last_entry_detected(db_session):
    """Modifying the last entry must break the chain at that entry."""
    await _append(db_session, "EVENT_1")
    await _append(db_session, "EVENT_2")
    e3 = await _append(db_session, "EVENT_3")

    # Tamper: change the stored chain_hash directly
    e3.chain_hash = "0" * 64
    await db_session.flush()

    result = await _service.verify_chain(db_session)
    assert result.chain_intact is False
    assert result.first_broken_at_id == e3.id


@pytest.mark.asyncio
async def test_tamper_reports_correct_event_type(db_session):
    """The broken entry result must include the tampered entry's event_type."""
    await _append(db_session, "NORMAL_EVENT")
    e2 = await _append(db_session, "SENSITIVE_EVENT")
    await _append(db_session, "ANOTHER_EVENT")

    e2.client_ip = "evil.attacker.com"
    await db_session.flush()

    result = await _service.verify_chain(db_session)
    assert result.chain_intact is False
    # The broken entry is e2 — its event_type should be reported
    assert result.broken_entry_event == "SENSITIVE_EVENT"
    assert result.broken_entry_occurred_at is not None


# ── Patient-scoped verify ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_patient_verify_clean_chain(db_session):
    """Patient verify must pass when their entries are untampered."""
    patient_id = uuid.uuid4()
    other_id = uuid.uuid4()

    # Mix patient and other entries
    await _append(db_session, "OTHER_LOGIN", actor_id=other_id)
    await _append(db_session, "PATIENT_LOGIN", actor_id=patient_id,
                  extra={"subject_user_id": str(patient_id)})
    await _append(db_session, "RECORD_READ", actor_id=other_id,
                  extra={"subject_user_id": str(patient_id)})
    await _append(db_session, "OTHER_EVENT", actor_id=other_id)

    result = await _service.verify_my_entries(db_session, patient_id)
    assert result.chain_intact is True
    assert result.entries_checked == 2  # only the 2 patient entries


@pytest.mark.asyncio
async def test_patient_verify_no_entries(db_session):
    """Patient verify with no entries must return intact with 0 checked."""
    patient_id = uuid.uuid4()
    await _append(db_session, "UNRELATED_EVENT")

    result = await _service.verify_my_entries(db_session, patient_id)
    assert result.chain_intact is True
    assert result.entries_checked == 0


@pytest.mark.asyncio
async def test_patient_verify_detects_tampered_own_entry(db_session):
    """Patient verify must detect tampering on their own entries."""
    patient_id = uuid.uuid4()

    await _append(db_session, "UNRELATED", actor_id=uuid.uuid4())
    patient_entry = await _append(
        db_session, "RECORD_READ",
        actor_id=patient_id,
        extra={"subject_user_id": str(patient_id)},
    )
    await _append(db_session, "ANOTHER_UNRELATED", actor_id=uuid.uuid4())

    # Tamper with the patient's entry
    patient_entry.event_type = "RECORD_DELETED"
    await db_session.flush()

    result = await _service.verify_my_entries(db_session, patient_id)
    assert result.chain_intact is False
    assert result.first_broken_at_id == patient_entry.id


@pytest.mark.asyncio
async def test_patient_verify_ignores_other_users_tampering(db_session):
    """
    Patient verify must pass even if another user's entry is tampered.
    The patient can only verify their own entries — not the full chain.
    """
    patient_id = uuid.uuid4()
    other_id = uuid.uuid4()

    other_entry = await _append(db_session, "OTHER_EVENT", actor_id=other_id)
    await _append(db_session, "PATIENT_EVENT", actor_id=patient_id,
                  extra={"subject_user_id": str(patient_id)})

    # Tamper with the OTHER user's entry — patient verify should not catch this
    other_entry.event_type = "TAMPERED"
    await db_session.flush()

    # Patient's own entries are still intact
    result = await _service.verify_my_entries(db_session, patient_id)
    assert result.chain_intact is True


# ── Audit log listing ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_list_entries_subject_filter(db_session):
    """list_entries with subject_user_id must return only that user's entries."""
    patient_id = uuid.uuid4()
    other_id = uuid.uuid4()

    await _append(db_session, "OTHER_LOGIN", actor_id=other_id)
    await _append(db_session, "PATIENT_LOGIN", actor_id=patient_id,
                  extra={"subject_user_id": str(patient_id)})
    await _append(db_session, "RECORD_READ", actor_id=other_id,
                  extra={"patient_id": str(patient_id)})

    filters = AuditFilter(subject_user_id=patient_id, limit=50, offset=0)
    entries = await _service.list_entries(db_session, filters)

    # Should return the 2 entries related to patient_id
    assert len(entries) == 2
    for e in entries:
        related = (
            str(e.actor_id) == str(patient_id)
            or str(e.resource_id) == str(patient_id)
            or str((e.extra or {}).get("subject_user_id", "")) == str(patient_id)
            or str((e.extra or {}).get("patient_id", "")) == str(patient_id)
        )
        assert related, f"Entry {e.id} not related to patient"


@pytest.mark.asyncio
async def test_list_entries_no_filter_returns_all(db_session):
    """list_entries with no filter must return all entries."""
    for i in range(5):
        await _append(db_session, f"EVENT_{i}")

    filters = AuditFilter(limit=50, offset=0)
    entries = await _service.list_entries(db_session, filters)
    assert len(entries) == 5
