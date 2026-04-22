"""
RBAC and access control tests.

Tests verify:
- JWT decoding and role extraction
- require_roles blocks wrong roles with 403
- Partial tokens are rejected on protected endpoints
- Expired tokens are rejected with 401
- Missing tokens are rejected with 401
- Each role can only perform its permitted actions
"""
from __future__ import annotations

import time
import uuid

import jwt
import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from app.core.config import settings
from app.middleware.rbac import TokenClaims, get_current_user, require_roles


# ── Helpers ────────────────────────────────────────────────────────────────

def _make_token(role: str, user_id: str | None = None, extra: dict | None = None) -> str:
    """Issue a valid JWT with the given role."""
    payload = {
        "sub": user_id or str(uuid.uuid4()),
        "role": role,
        "exp": int(time.time()) + 900,
    }
    if extra:
        payload.update(extra)
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def _make_partial_token(user_id: str | None = None) -> str:
    """Issue a partial JWT (MFA not yet completed)."""
    payload = {
        "sub": user_id or str(uuid.uuid4()),
        "partial": True,
        "exp": int(time.time()) + 300,
    }
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def _make_expired_token(role: str) -> str:
    """Issue an already-expired JWT."""
    payload = {
        "sub": str(uuid.uuid4()),
        "role": role,
        "exp": int(time.time()) - 60,  # expired 60 seconds ago
    }
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def _creds(token: str) -> HTTPAuthorizationCredentials:
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)


# ── get_current_user ───────────────────────────────────────────────────────

def test_valid_token_returns_claims():
    """A valid JWT must return correct TokenClaims."""
    uid = str(uuid.uuid4())
    token = _make_token("Doctor", user_id=uid)
    claims = get_current_user(_creds(token))
    assert claims.user_id == uid
    assert claims.role == "Doctor"


def test_expired_token_raises_401():
    """An expired JWT must raise HTTP 401."""
    token = _make_expired_token("Patient")
    with pytest.raises(HTTPException) as exc:
        get_current_user(_creds(token))
    assert exc.value.status_code == 401
    assert exc.value.headers["X-Error-Code"] == "TOKEN_EXPIRED"


def test_invalid_token_raises_401():
    """A malformed JWT must raise HTTP 401."""
    with pytest.raises(HTTPException) as exc:
        get_current_user(_creds("not.a.valid.token"))
    assert exc.value.status_code == 401
    assert exc.value.headers["X-Error-Code"] == "TOKEN_INVALID"


def test_wrong_signature_raises_401():
    """A JWT signed with a different key must raise HTTP 401."""
    payload = {"sub": str(uuid.uuid4()), "role": "Patient", "exp": int(time.time()) + 900}
    token = jwt.encode(payload, "wrong-secret-key", algorithm="HS256")
    with pytest.raises(HTTPException) as exc:
        get_current_user(_creds(token))
    assert exc.value.status_code == 401


def test_partial_token_raises_401():
    """A partial token (MFA not completed) must be rejected on protected endpoints."""
    token = _make_partial_token()
    with pytest.raises(HTTPException) as exc:
        get_current_user(_creds(token))
    assert exc.value.status_code == 401
    assert exc.value.headers["X-Error-Code"] == "TOKEN_INVALID"


# ── require_roles ──────────────────────────────────────────────────────────

def test_require_roles_allows_correct_role():
    """require_roles must pass when the token role is in the allowed list."""
    token = _make_token("Doctor")
    dep = require_roles("Doctor", "Nurse")
    claims = dep(get_current_user(_creds(token)))
    assert claims.role == "Doctor"


def test_require_roles_blocks_wrong_role():
    """require_roles must raise HTTP 403 when the role is not allowed."""
    token = _make_token("Patient")
    dep = require_roles("Doctor", "Nurse")
    with pytest.raises(HTTPException) as exc:
        dep(get_current_user(_creds(token)))
    assert exc.value.status_code == 403
    assert exc.value.headers["X-Error-Code"] == "FORBIDDEN"
    assert exc.value.detail == "Insufficient permissions"


def test_require_roles_single_role():
    """require_roles with a single role must block all others."""
    allowed_token = _make_token("SuperAdmin")
    blocked_token = _make_token("Admin")

    dep = require_roles("SuperAdmin")
    # SuperAdmin passes
    claims = dep(get_current_user(_creds(allowed_token)))
    assert claims.role == "SuperAdmin"

    # Admin is blocked
    with pytest.raises(HTTPException) as exc:
        dep(get_current_user(_creds(blocked_token)))
    assert exc.value.status_code == 403


# ── Role permission matrix ─────────────────────────────────────────────────

ALL_ROLES = ["Patient", "Doctor", "Nurse", "Lab_Technician",
             "Front_Desk", "Emergency_Contact", "Admin", "SuperAdmin"]

CLINICIAN_ROLES = ["Doctor", "Nurse", "Lab_Technician"]
ADMIN_ROLES = ["Admin", "SuperAdmin"]


@pytest.mark.parametrize("role", ALL_ROLES)
def test_all_roles_produce_valid_claims(role):
    """Every role must produce valid TokenClaims from a JWT."""
    token = _make_token(role)
    claims = get_current_user(_creds(token))
    assert claims.role == role


@pytest.mark.parametrize("role", [r for r in ALL_ROLES if r not in CLINICIAN_ROLES])
def test_non_clinician_blocked_from_clinician_endpoint(role):
    """Non-clinician roles must be blocked from Doctor/Nurse/Lab_Tech endpoints."""
    token = _make_token(role)
    dep = require_roles("Doctor", "Nurse", "Lab_Technician")
    with pytest.raises(HTTPException) as exc:
        dep(get_current_user(_creds(token)))
    assert exc.value.status_code == 403


@pytest.mark.parametrize("role", [r for r in ALL_ROLES if r not in ADMIN_ROLES])
def test_non_admin_blocked_from_admin_endpoint(role):
    """Non-admin roles must be blocked from Admin/SuperAdmin endpoints."""
    token = _make_token(role)
    dep = require_roles("Admin", "SuperAdmin")
    with pytest.raises(HTTPException) as exc:
        dep(get_current_user(_creds(token)))
    assert exc.value.status_code == 403


@pytest.mark.parametrize("role", ADMIN_ROLES)
def test_admin_roles_allowed_on_admin_endpoint(role):
    """Admin and SuperAdmin must be allowed on admin endpoints."""
    token = _make_token(role)
    dep = require_roles("Admin", "SuperAdmin")
    claims = dep(get_current_user(_creds(token)))
    assert claims.role == role


def test_patient_allowed_on_patient_endpoint():
    """Patient role must be allowed on patient-only endpoints."""
    token = _make_token("Patient")
    dep = require_roles("Patient")
    claims = dep(get_current_user(_creds(token)))
    assert claims.role == "Patient"


def test_doctor_blocked_from_patient_only_endpoint():
    """Doctor must be blocked from Patient-only endpoints."""
    token = _make_token("Doctor")
    dep = require_roles("Patient")
    with pytest.raises(HTTPException) as exc:
        dep(get_current_user(_creds(token)))
    assert exc.value.status_code == 403
