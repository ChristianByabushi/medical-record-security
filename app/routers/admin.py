"""Admin endpoints: user management for SuperAdmin/Admin roles."""
from __future__ import annotations

import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, EmailStr
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.middleware.rbac import TokenClaims, require_roles
from app.models.base import get_db
from app.models.user import User
from app.models.refresh_token import RefreshToken
from app.schemas.auth import UserOut
from app.services.audit_service import AuditService

router = APIRouter(tags=["admin"])

# Only SuperAdmin and Admin can access these endpoints
_admin_dep = require_roles("SuperAdmin", "Admin")


class UserListOut(BaseModel):
    items: list[UserOut]
    total: int


class UserCreateIn(BaseModel):
    email: EmailStr
    full_name: str = ""
    password: str
    role: str


class UserUpdateIn(BaseModel):
    email: Optional[EmailStr] = None
    full_name: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None


# ── List all users ──────────────────────────────────────
@router.get("/users", response_model=UserListOut)
async def list_users(
    role: Optional[str] = Query(None),
    is_active: Optional[bool] = Query(None),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    claims: TokenClaims = Depends(_admin_dep),
):
    query = select(User)
    count_query = select(func.count(User.id))

    if role:
        query = query.where(User.role == role)
        count_query = count_query.where(User.role == role)
    if is_active is not None:
        query = query.where(User.is_active == is_active)
        count_query = count_query.where(User.is_active == is_active)

    query = query.order_by(User.created_at.desc()).offset(offset).limit(limit)

    result = await db.execute(query)
    users = result.scalars().all()
    total_result = await db.execute(count_query)
    total = total_result.scalar()

    return UserListOut(
        items=[UserOut.model_validate(u) for u in users],
        total=total,
    )


# ── Get single user ─────────────────────────────────────
@router.get("/users/{user_id}", response_model=UserOut)
async def get_user(
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    claims: TokenClaims = Depends(_admin_dep),
):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return UserOut.model_validate(user)


# ── Create user (admin-created accounts) ────────────────
@router.post("/users", response_model=UserOut, status_code=201)
async def create_user(
    body: UserCreateIn,
    db: AsyncSession = Depends(get_db),
    claims: TokenClaims = Depends(_admin_dep),
):
    from app.services.auth_service import _hash_password
    from app.services.email_service import send_welcome_email

    # Only SuperAdmin can create Admin/SuperAdmin accounts
    if body.role in ("Admin", "SuperAdmin") and claims.role != "SuperAdmin":
        raise HTTPException(
            status_code=403,
            detail="Only SuperAdmin can create Admin or SuperAdmin accounts",
        )

    # Check email uniqueness
    existing = await db.execute(select(User).where(User.email == body.email))
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(status_code=409, detail="Email already registered")

    valid_roles = {"Patient", "Doctor", "Nurse", "Lab_Technician", "Admin", "SuperAdmin", "Front_Desk", "Emergency_Contact"}
    if body.role not in valid_roles:
        raise HTTPException(status_code=422, detail=f"Invalid role. Must be one of: {valid_roles}")

    user = User(
        email=body.email,
        full_name=body.full_name,
        password_hash=_hash_password(body.password),
        role=body.role,
        must_change_password=True,
    )
    db.add(user)
    await db.flush()
    await db.refresh(user)

    # Send welcome email with the password
    send_welcome_email(body.email, body.password, body.role)

    # Audit
    await AuditService().append(
        db, event_type="USER_CREATED_BY_ADMIN",
        actor_id=uuid.UUID(claims.user_id),
        resource_id=user.id, resource_type="user",
        client_ip="0.0.0.0",
        extra={"created_role": body.role},
    )

    return UserOut.model_validate(user)


# ── Update user (change role, deactivate, etc.) ─────────
@router.patch("/users/{user_id}", response_model=UserOut)
async def update_user(
    user_id: uuid.UUID,
    body: UserUpdateIn,
    db: AsyncSession = Depends(get_db),
    claims: TokenClaims = Depends(_admin_dep),
):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    # Prevent non-SuperAdmin from modifying SuperAdmin accounts
    if user.role == "SuperAdmin" and claims.role != "SuperAdmin":
        raise HTTPException(status_code=403, detail="Cannot modify SuperAdmin accounts")

    # Prevent role escalation by non-SuperAdmin
    if body.role in ("Admin", "SuperAdmin") and claims.role != "SuperAdmin":
        raise HTTPException(status_code=403, detail="Only SuperAdmin can assign Admin/SuperAdmin roles")

    if body.email is not None:
        existing = await db.execute(select(User).where(User.email == body.email, User.id != user.id))
        if existing.scalar_one_or_none() is not None:
            raise HTTPException(status_code=409, detail="Email already in use")
        user.email = body.email

    if body.full_name is not None:
        user.full_name = body.full_name.strip()

    if body.role is not None:
        valid_roles = {"Patient", "Doctor", "Nurse", "Lab_Technician", "Admin", "SuperAdmin", "Front_Desk", "Emergency_Contact"}
        if body.role not in valid_roles:
            raise HTTPException(status_code=422, detail=f"Invalid role")
        user.role = body.role

    if body.is_active is not None:
        user.is_active = body.is_active

    await db.flush()
    await db.refresh(user)

    # Audit
    await AuditService().append(
        db, event_type="USER_UPDATED_BY_ADMIN",
        actor_id=uuid.UUID(claims.user_id),
        resource_id=user.id, resource_type="user",
        client_ip="0.0.0.0",
    )

    return UserOut.model_validate(user)


# ── Deactivate user (soft ban) ──────────────────────────
@router.post("/users/{user_id}/deactivate", response_model=dict)
async def deactivate_user(
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    claims: TokenClaims = Depends(_admin_dep),
):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    if user.role == "SuperAdmin" and claims.role != "SuperAdmin":
        raise HTTPException(status_code=403, detail="Cannot deactivate SuperAdmin accounts")

    user.is_active = False

    # Revoke all their refresh tokens
    await db.execute(
        update(RefreshToken)
        .where(RefreshToken.user_id == user_id)
        .values(revoked=True)
    )
    await db.flush()

    # Audit
    await AuditService().append(
        db, event_type="USER_DEACTIVATED",
        actor_id=uuid.UUID(claims.user_id),
        resource_id=user.id, resource_type="user",
        client_ip="0.0.0.0",
    )

    return {"message": f"User {user.email} deactivated and all sessions revoked."}


# ── Reactivate user ────────────────────────────────────
@router.post("/users/{user_id}/reactivate", response_model=dict)
async def reactivate_user(
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    claims: TokenClaims = Depends(_admin_dep),
):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    user.is_active = True
    await db.flush()

    await AuditService().append(
        db, event_type="USER_REACTIVATED",
        actor_id=uuid.UUID(claims.user_id),
        resource_id=user.id, resource_type="user",
        client_ip="0.0.0.0",
    )

    return {"message": f"User {user.email} reactivated."}


class AdminResetPasswordIn(BaseModel):
    new_password: str


# ── Reset user password (admin) ─────────────────────────
@router.post("/users/{user_id}/reset-password", response_model=dict)
async def admin_reset_password(
    user_id: uuid.UUID,
    body: AdminResetPasswordIn,
    db: AsyncSession = Depends(get_db),
    claims: TokenClaims = Depends(_admin_dep),
):
    """Admin resets a user's password, revokes all sessions, flags for change."""
    from app.services.auth_service import _hash_password
    from app.services.email_service import send_email
    from app.core.config import settings

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    if user.role == "SuperAdmin" and claims.role != "SuperAdmin":
        raise HTTPException(status_code=403, detail="Cannot reset SuperAdmin passwords")

    if len(body.new_password) < 12:
        raise HTTPException(status_code=422, detail="Password must be at least 12 characters")

    user.password_hash = _hash_password(body.new_password)
    user.must_change_password = True

    # Revoke all refresh tokens
    await db.execute(
        update(RefreshToken)
        .where(RefreshToken.user_id == user_id)
        .values(revoked=True)
    )
    await db.flush()

    # Email the user their new password
    app_name = settings.APP_NAME
    app_url = settings.APP_URL
    send_email(
        user.email,
        f"{app_name} — Your Password Has Been Reset",
        f"""
        <div style="font-family:sans-serif;max-width:500px;margin:0 auto">
          <h2 style="color:#1e3a5f">{app_name} — Password Reset</h2>
          <p>An administrator has reset your password.</p>
          <table style="margin:1rem 0;font-size:14px">
            <tr><td style="padding:4px 12px 4px 0;color:#666">New Password:</td>
                <td><code style="background:#f0f0f0;padding:2px 6px;border-radius:3px">{body.new_password}</code></td></tr>
          </table>
          <p style="color:#dc2626;font-weight:600">⚠️ You must change this password on your next login.</p>
          <a href="{app_url}" style="display:inline-block;background:#2563eb;color:white;padding:10px 24px;
             border-radius:6px;text-decoration:none;font-weight:500;margin:1rem 0">Log In to {app_name}</a>
          <p style="color:#666;font-size:12px">Or copy this link: {app_url}</p>
          <hr style="border:none;border-top:1px solid #eee;margin:1.5rem 0" />
          <p style="color:#999;font-size:11px">{app_name} — Secure Medical Records Platform</p>
        </div>
        """,
    )

    # Audit
    await AuditService().append(
        db, event_type="PASSWORD_RESET_BY_ADMIN",
        actor_id=uuid.UUID(claims.user_id),
        resource_id=user.id, resource_type="user",
        client_ip="0.0.0.0",
    )

    return {"message": f"Password reset for {user.email}. New password emailed. All sessions revoked."}


# ── Disable MFA for a user (admin recovery) ─────────────
@router.post("/users/{user_id}/disable-mfa", response_model=dict)
async def admin_disable_mfa(
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    claims: TokenClaims = Depends(_admin_dep),
):
    """Admin disables MFA for a locked-out user so they can log in again."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    if not user.mfa_enabled:
        return {"message": f"MFA is already disabled for {user.email}"}

    user.mfa_enabled = False
    await db.flush()

    await AuditService().append(
        db, event_type="MFA_DISABLED_BY_ADMIN",
        actor_id=uuid.UUID(claims.user_id),
        resource_id=user.id, resource_type="user",
        client_ip="0.0.0.0",
    )

    return {"message": f"MFA disabled for {user.email}. They can now log in with just their password."}


# ── Front Desk: register patients only ──────────────────
_frontdesk_dep = require_roles("Front_Desk", "Admin", "SuperAdmin")


class FrontDeskCreatePatient(BaseModel):
    email: EmailStr
    full_name: str
    password: str


@router.post("/register-patient", response_model=UserOut, status_code=201)
async def frontdesk_register_patient(
    body: FrontDeskCreatePatient,
    db: AsyncSession = Depends(get_db),
    claims: TokenClaims = Depends(_frontdesk_dep),
):
    """Front Desk can register new patients only."""
    from app.services.auth_service import _hash_password
    from app.services.email_service import send_welcome_email

    existing = await db.execute(select(User).where(User.email == body.email))
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(status_code=409, detail="Email already registered")

    user = User(
        email=body.email,
        full_name=body.full_name,
        password_hash=_hash_password(body.password),
        role="Patient",
        must_change_password=True,
    )
    db.add(user)
    await db.flush()
    await db.refresh(user)

    send_welcome_email(body.email, body.password, "Patient")

    await AuditService().append(
        db, event_type="PATIENT_REGISTERED_BY_FRONTDESK",
        actor_id=uuid.UUID(claims.user_id),
        resource_id=user.id, resource_type="user",
        client_ip="0.0.0.0",
    )

    return UserOut.model_validate(user)
