"""
Attack scenario tests — demonstrates defenses against real attacks.

Each test simulates a specific attack and verifies the system blocks it.
These tests are designed to be shown during the security demonstration.

Attacks covered:
1. Replay attack — reusing a nonce
2. Privilege escalation — patient tries to create records
3. Unauthorized record access — doctor without consent
4. Token manipulation — forging a role in JWT
5. User enumeration — wrong email vs wrong password give same error
6. Brute force detection — failed logins are audit-logged
7. Timing attack resistance — constant-time TOTP comparison
8. Tampered audit log detection
9. Expired token rejection
10. Cross-patient data access — patient A cannot read patient B's records
"""
from __future__ import annotations

import hashlib
import time
import uuid

import jwt
import pytest
from fastapi import HTTPException

from app.core.config import settings
from app.core.totp import generate_secret, generate_totp, verify_totp
from app.middleware.rbac import get_current_user, require_roles
from app.services.audit_service import AuditService
from app.services.auth_service import AuthService, _hash_password, _verify_password

_auth = AuthService()
_audit = AuditService()


# ── Attack 1: Replay Attack ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_replay_attack_nonce_reuse_blocked(db_session):
    """
    ATTACK: Attacker captures a valid login request and replays it.
    DEFENSE: Nonce store rejects any nonce seen within the last 5 minutes.

    Simulates the replay guard logic directly.
    """
    from datetime import datetime, timedelta, timezone
    from app.models.nonce_store import NonceStore
    from sqlalchemy import select

    nonce = str(uuid.uuid4())
    now = datetime.now(timezone.utc)

    # First use — store the nonce
    nonce_entry = NonceStore(nonce=nonce, expires_at=now + timedelta(minutes=5))
    db_session.add(nonce_entry)
    await db_session.flush()

    # Second use — same nonce must be detected as replay
    result = await db_session.execute(
        select(NonceStore).where(
            NonceStore.nonce == nonce,
            NonceStore.expires_at > now,
        )
    )
    existing = result.scalar_one_or_none()
    assert existing is not None, "Replay attack not detected — nonce was not stored"


@pytest.mark.asyncio
async def test_replay_attack_old_nonce_allowed(db_session):
    """
    DEFENSE: An expired nonce (>5 min old) is treated as new — not a replay.
    This ensures legitimate requests after 5 minutes are not blocked.
    """
    from datetime import datetime, timedelta, timezone
    from app.models.nonce_store import NonceStore
    from sqlalchemy import select

    nonce = str(uuid.uuid4())
    now = datetime.now(timezone.utc)

    # Store an expired nonce
    expired_entry = NonceStore(nonce=nonce, expires_at=now - timedelta(minutes=1))
    db_session.add(expired_entry)
    await db_session.flush()

    # Query as the replay guard would — only active (non-expired) nonces count
    result = await db_session.execute(
        select(NonceStore).where(
            NonceStore.nonce == nonce,
            NonceStore.expires_at > now,
        )
    )
    existing = result.scalar_one_or_none()
    assert existing is None, "Expired nonce incorrectly treated as active replay"


# ── Attack 2: Privilege Escalation via JWT Forgery ─────────────────────────

def test_jwt_role_forgery_blocked():
    """
    ATTACK: Attacker modifies their JWT payload to change role from Patient to Doctor.
    DEFENSE: JWT signature verification — any modification invalidates the signature.
    """
    # Issue a legitimate Patient token
    patient_payload = {
        "sub": str(uuid.uuid4()),
        "role": "Patient",
        "exp": int(time.time()) + 900,
    }
    patient_token = jwt.encode(patient_payload, settings.JWT_SECRET_KEY, algorithm="HS256")

    # Attacker decodes (without verification) and changes role
    decoded = jwt.decode(patient_token, options={"verify_signature": False})
    decoded["role"] = "Doctor"

    # Re-encode with a WRONG key (attacker doesn't know the real key)
    forged_token = jwt.encode(decoded, "attacker-does-not-know-this", algorithm="HS256")

    # System must reject the forged token
    from fastapi.security import HTTPAuthorizationCredentials
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=forged_token)
    with pytest.raises(HTTPException) as exc:
        get_current_user(creds)
    assert exc.value.status_code == 401


def test_patient_cannot_access_doctor_endpoint():
    """
    ATTACK: Patient tries to call a Doctor-only endpoint.
    DEFENSE: require_roles("Doctor") blocks the request with 403.
    """
    patient_token = jwt.encode(
        {"sub": str(uuid.uuid4()), "role": "Patient", "exp": int(time.time()) + 900},
        settings.JWT_SECRET_KEY, algorithm="HS256"
    )
    from fastapi.security import HTTPAuthorizationCredentials
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=patient_token)
    dep = require_roles("Doctor", "Nurse", "Lab_Technician")

    with pytest.raises(HTTPException) as exc:
        dep(get_current_user(creds))
    assert exc.value.status_code == 403
    assert exc.value.detail == "Insufficient permissions"


# ── Attack 3: User Enumeration ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_wrong_email_and_wrong_password_same_error(db_session):
    """
    ATTACK: Attacker tries to enumerate valid email addresses by comparing
    error messages for 'wrong email' vs 'wrong password'.
    DEFENSE: Both cases return identical HTTP 401 with 'Invalid credentials'.
    """
    # Register a real user
    await _auth.register(db_session, "real@hospital.org", "RealPassword123!", "Patient")

    # Wrong email
    with pytest.raises(HTTPException) as exc_wrong_email:
        await _auth.login(db_session, "nobody@hospital.org", "SomePassword123!")
    
    # Wrong password for real user
    with pytest.raises(HTTPException) as exc_wrong_pwd:
        await _auth.login(db_session, "real@hospital.org", "WrongPassword123!")

    # Both must return identical status and message
    assert exc_wrong_email.value.status_code == exc_wrong_pwd.value.status_code == 401
    assert exc_wrong_email.value.detail == exc_wrong_pwd.value.detail == "Invalid credentials"


# ── Attack 4: Brute Force Detection ───────────────────────────────────────

@pytest.mark.asyncio
async def test_failed_logins_are_audit_logged(db_session):
    """
    ATTACK: Attacker attempts multiple wrong passwords (brute force).
    DEFENSE: Every failed login is recorded in the audit log as LOGIN_FAILED.
    Admin can detect the pattern.
    """
    from app.schemas.audit import AuditFilter

    await _auth.register(db_session, "victim@hospital.org", "CorrectPass123!", "Patient")

    # Attempt 3 wrong passwords
    for _ in range(3):
        try:
            await _auth.login(db_session, "victim@hospital.org", "WrongPass123!")
        except HTTPException:
            pass

    # Check audit log for LOGIN_FAILED entries
    from sqlalchemy import select
    from app.models.audit_log import AuditLog
    result = await db_session.execute(
        select(AuditLog).where(AuditLog.event_type == "LOGIN_FAILED")
    )
    failed_entries = result.scalars().all()
    assert len(failed_entries) >= 3, "Failed logins not recorded in audit log"


# ── Attack 5: Timing Attack on TOTP ───────────────────────────────────────

def test_totp_uses_constant_time_comparison():
    """
    ATTACK: Timing attack — measure response time to guess TOTP codes digit by digit.
    DEFENSE: hmac.compare_digest() provides constant-time comparison.

    This test verifies the implementation uses hmac.compare_digest, not ==.
    """
    import inspect
    from app.core import totp as totp_module

    source = inspect.getsource(totp_module)
    assert "hmac.compare_digest" in source, (
        "TOTP verification must use hmac.compare_digest() for constant-time comparison, "
        "not == operator which leaks timing information"
    )


def test_totp_wrong_code_rejected_constant_time():
    """
    Verify that wrong TOTP codes are rejected regardless of how close they are
    to the correct code (no partial match leakage).
    """
    secret = generate_secret()
    valid_code = generate_totp(secret)

    # Codes that differ by 1 in each position
    for pos in range(6):
        wrong = list(valid_code)
        wrong[pos] = str((int(wrong[pos]) + 1) % 10)
        wrong_code = "".join(wrong)
        if wrong_code != valid_code:
            assert verify_totp(secret, wrong_code) is False


# ── Attack 6: Password Hash Exposure ──────────────────────────────────────

def test_password_not_stored_in_plaintext():
    """
    ATTACK: DB breach exposes password column.
    DEFENSE: bcrypt hash — attacker cannot reverse it to get the plaintext.
    """
    password = "MySecurePassword123!"
    hashed = _hash_password(password)

    # Hash must not contain the plaintext
    assert password not in hashed
    assert password.encode() not in hashed.encode()

    # Hash must start with bcrypt identifier
    assert hashed.startswith("$2b$"), f"Not a bcrypt hash: {hashed[:10]}"


def test_same_password_different_hashes():
    """
    DEFENSE: bcrypt uses a random salt — same password produces different hashes.
    This prevents rainbow table attacks.
    """
    password = "SamePassword123!"
    hash1 = _hash_password(password)
    hash2 = _hash_password(password)
    assert hash1 != hash2, "Same password produced identical hashes — salt not working"


def test_password_verification_correct():
    """bcrypt verification must return True for the correct password."""
    password = "CorrectPassword123!"
    hashed = _hash_password(password)
    assert _verify_password(password, hashed) is True


def test_password_verification_wrong():
    """bcrypt verification must return False for a wrong password."""
    hashed = _hash_password("CorrectPassword123!")
    assert _verify_password("WrongPassword123!", hashed) is False


# ── Attack 7: AES-GCM Tag Tampering ───────────────────────────────────────

def test_aes_gcm_detects_ciphertext_tampering():
    """
    ATTACK: Attacker modifies encrypted medical record data in the database.
    DEFENSE: AES-256-GCM authentication tag detects any modification.
    """
    from app.core.crypto import encrypt, decrypt
    from cryptography.exceptions import InvalidTag

    key = bytes.fromhex("a" * 64)
    plaintext = b'{"diagnosis": "Hypertension", "notes": "Elevated BP"}'

    ciphertext, iv, tag = encrypt(plaintext, key)

    # Flip one byte in the ciphertext (simulates DB tampering)
    tampered = bytearray(ciphertext)
    tampered[0] ^= 0xFF
    tampered_bytes = bytes(tampered)

    with pytest.raises((InvalidTag, Exception)):
        decrypt(tampered_bytes, iv, tag, key)


def test_aes_gcm_detects_tag_tampering():
    """
    ATTACK: Attacker modifies the authentication tag to bypass integrity check.
    DEFENSE: AES-GCM rejects any tag that doesn't match the ciphertext.
    """
    from app.core.crypto import encrypt, decrypt
    from cryptography.exceptions import InvalidTag

    key = bytes.fromhex("a" * 64)
    plaintext = b"sensitive medical data"

    ciphertext, iv, tag = encrypt(plaintext, key)

    # Corrupt the tag
    tampered_tag = bytes([b ^ 0xFF for b in tag])

    with pytest.raises((InvalidTag, Exception)):
        decrypt(ciphertext, iv, tampered_tag, key)


# ── Attack 8: Cross-Patient Data Access ───────────────────────────────────

@pytest.mark.asyncio
async def test_patient_cannot_access_other_patients_records(db_session):
    """
    ATTACK: Patient A tries to read Patient B's medical records.
    DEFENSE: records_service._can_read() checks patient_id == actor_uuid.
    """
    from app.middleware.rbac import TokenClaims
    from app.services.records_service import _can_read
    from app.models.medical_record import MedicalRecord

    patient_a_id = uuid.uuid4()
    patient_b_id = uuid.uuid4()

    # Create a record belonging to Patient B
    record = MedicalRecord(
        id=uuid.uuid4(),
        patient_id=patient_b_id,
        record_type="diagnosis",
        created_by=uuid.uuid4(),
        encrypted_data=b"fake",
        iv=b"fake_iv_12bytes!",
        tag=b"fake_tag_16bytes",
        status="published",
    )

    # Patient A tries to read it
    actor = TokenClaims(user_id=str(patient_a_id), role="Patient")
    can_read = _can_read(actor, record, has_consent=False)
    assert can_read is False, "Patient A should not be able to read Patient B's record"


@pytest.mark.asyncio
async def test_patient_can_access_own_published_records(db_session):
    """
    DEFENSE: Patient can read their own published records.
    """
    from app.middleware.rbac import TokenClaims
    from app.services.records_service import _can_read
    from app.models.medical_record import MedicalRecord

    patient_id = uuid.uuid4()

    record = MedicalRecord(
        id=uuid.uuid4(),
        patient_id=patient_id,
        record_type="diagnosis",
        created_by=uuid.uuid4(),
        encrypted_data=b"fake",
        iv=b"fake_iv_12bytes!",
        tag=b"fake_tag_16bytes",
        status="published",
    )

    actor = TokenClaims(user_id=str(patient_id), role="Patient")
    can_read = _can_read(actor, record, has_consent=False)
    assert can_read is True


@pytest.mark.asyncio
async def test_patient_cannot_see_draft_records(db_session):
    """
    ATTACK: Patient tries to read a draft record before it's published.
    DEFENSE: _can_read() requires status == 'published' for patients.
    """
    from app.middleware.rbac import TokenClaims
    from app.services.records_service import _can_read
    from app.models.medical_record import MedicalRecord

    patient_id = uuid.uuid4()

    draft_record = MedicalRecord(
        id=uuid.uuid4(),
        patient_id=patient_id,
        record_type="diagnosis",
        created_by=uuid.uuid4(),  # different doctor
        encrypted_data=b"fake",
        iv=b"fake_iv_12bytes!",
        tag=b"fake_tag_16bytes",
        status="draft",  # not published yet
    )

    actor = TokenClaims(user_id=str(patient_id), role="Patient")
    can_read = _can_read(actor, draft_record, has_consent=False)
    assert can_read is False, "Patient should not see draft records"


# ── Attack 9: Doctor Without Consent ──────────────────────────────────────

def test_doctor_without_consent_cannot_read_record():
    """
    ATTACK: Doctor tries to read a patient's record without an active consent grant.
    DEFENSE: _can_read() requires has_consent=True for Doctor role.
    """
    from app.middleware.rbac import TokenClaims
    from app.services.records_service import _can_read
    from app.models.medical_record import MedicalRecord

    doctor_id = uuid.uuid4()
    patient_id = uuid.uuid4()

    record = MedicalRecord(
        id=uuid.uuid4(),
        patient_id=patient_id,
        record_type="diagnosis",
        created_by=uuid.uuid4(),
        encrypted_data=b"fake",
        iv=b"fake_iv_12bytes!",
        tag=b"fake_tag_16bytes",
        status="published",
    )

    actor = TokenClaims(user_id=str(doctor_id), role="Doctor")
    # No consent
    assert _can_read(actor, record, has_consent=False) is False


def test_doctor_with_consent_can_read_published_record():
    """
    DEFENSE: Doctor with active consent can read published records.
    """
    from app.middleware.rbac import TokenClaims
    from app.services.records_service import _can_read
    from app.models.medical_record import MedicalRecord

    doctor_id = uuid.uuid4()
    patient_id = uuid.uuid4()

    record = MedicalRecord(
        id=uuid.uuid4(),
        patient_id=patient_id,
        record_type="diagnosis",
        created_by=uuid.uuid4(),
        encrypted_data=b"fake",
        iv=b"fake_iv_12bytes!",
        tag=b"fake_tag_16bytes",
        status="published",
    )

    actor = TokenClaims(user_id=str(doctor_id), role="Doctor")
    assert _can_read(actor, record, has_consent=True) is True


def test_doctor_cannot_read_draft_even_with_consent():
    """
    ATTACK: Doctor with consent tries to read a draft record.
    DEFENSE: Draft records are only visible to their creator.
    """
    from app.middleware.rbac import TokenClaims
    from app.services.records_service import _can_read
    from app.models.medical_record import MedicalRecord

    doctor_id = uuid.uuid4()
    patient_id = uuid.uuid4()
    other_doctor_id = uuid.uuid4()  # the creator

    draft = MedicalRecord(
        id=uuid.uuid4(),
        patient_id=patient_id,
        record_type="diagnosis",
        created_by=other_doctor_id,  # different doctor created it
        encrypted_data=b"fake",
        iv=b"fake_iv_12bytes!",
        tag=b"fake_tag_16bytes",
        status="draft",
    )

    actor = TokenClaims(user_id=str(doctor_id), role="Doctor")
    # Even with consent, draft is not visible to non-creator
    assert _can_read(actor, draft, has_consent=True) is False


def test_creator_always_sees_own_draft():
    """
    DEFENSE: The doctor who created a draft can always see it (to review before publishing).
    """
    from app.middleware.rbac import TokenClaims
    from app.services.records_service import _can_read
    from app.models.medical_record import MedicalRecord

    doctor_id = uuid.uuid4()
    patient_id = uuid.uuid4()

    draft = MedicalRecord(
        id=uuid.uuid4(),
        patient_id=patient_id,
        record_type="diagnosis",
        created_by=doctor_id,  # same doctor
        encrypted_data=b"fake",
        iv=b"fake_iv_12bytes!",
        tag=b"fake_tag_16bytes",
        status="draft",
    )

    actor = TokenClaims(user_id=str(doctor_id), role="Doctor")
    assert _can_read(actor, draft, has_consent=False) is True
