"""User profile endpoints."""
from __future__ import annotations

import uuid
from typing import Optional

from fastapi import Depends, HTTPException, Query, status
from fastapi import APIRouter
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.middleware.rbac import TokenClaims, get_current_user, require_roles
from app.models.base import get_db
from app.models.user import User
from app.schemas.auth import UserOut

router = APIRouter(tags=["users"])


class UserUpdateIn(BaseModel):
    email: Optional[str] = None
    full_name: Optional[str] = None


class ChangePasswordIn(BaseModel):
    current_password: str
    new_password: str


class RecoveryEmailIn(BaseModel):
    recovery_email: str


@router.get("/me", response_model=UserOut)
async def get_me(
    db: AsyncSession = Depends(get_db),
    claims: TokenClaims = Depends(get_current_user),
) -> UserOut:
    result = await db.execute(select(User).where(User.id == uuid.UUID(claims.user_id)))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return UserOut.model_validate(user)


@router.patch("/me", response_model=UserOut)
async def update_me(
    body: UserUpdateIn,
    db: AsyncSession = Depends(get_db),
    claims: TokenClaims = Depends(get_current_user),
) -> UserOut:
    result = await db.execute(select(User).where(User.id == uuid.UUID(claims.user_id)))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if body.email:
        existing = await db.execute(select(User).where(User.email == body.email))
        if existing.scalar_one_or_none() is not None and body.email != user.email:
            raise HTTPException(status_code=409, detail="Email already in use")
        user.email = body.email
    if body.full_name:
        user.full_name = body.full_name
    await db.flush()
    await db.refresh(user)
    return UserOut.model_validate(user)


@router.post("/me/change-password", response_model=dict)
async def change_password(
    body: ChangePasswordIn,
    db: AsyncSession = Depends(get_db),
    claims: TokenClaims = Depends(get_current_user),
) -> dict:
    """Change password using current password. No reset token needed."""
    from app.services.auth_service import _verify_password, _hash_password

    result = await db.execute(select(User).where(User.id == uuid.UUID(claims.user_id)))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    if not _verify_password(body.current_password, user.password_hash):
        raise HTTPException(status_code=401, detail="Current password is incorrect")

    if len(body.new_password) < 12:
        raise HTTPException(status_code=422, detail="New password must be at least 12 characters")

    user.password_hash = _hash_password(body.new_password)
    user.must_change_password = False
    await db.flush()

    return {"message": "Password changed successfully."}


@router.get("/search", response_model=list[UserOut])
async def search_users(
    email: str = Query(""),
    role: str = Query("Patient"),
    db: AsyncSession = Depends(get_db),
    claims: TokenClaims = Depends(get_current_user),
) -> list[UserOut]:
    """Search users by email prefix. Doctors use this to find patients."""
    if not email or len(email) < 3:
        return []
    result = await db.execute(
        select(User)
        .where(User.email.ilike(f"%{email}%"), User.role == role)
        .limit(10)
    )
    users = result.scalars().all()
    return [UserOut.model_validate(u) for u in users]


@router.post("/me/recovery-email", response_model=dict)
async def set_recovery_email(
    body: RecoveryEmailIn,
    db: AsyncSession = Depends(get_db),
    claims: TokenClaims = Depends(get_current_user),
) -> dict:
    """Set a recovery email for account recovery."""
    result = await db.execute(select(User).where(User.id == uuid.UUID(claims.user_id)))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    user.recovery_email = body.recovery_email
    await db.flush()
    return {"message": f"Recovery email set to {body.recovery_email}"}
