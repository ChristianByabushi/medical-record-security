"""User profile endpoints."""
from __future__ import annotations

import uuid
from typing import Optional

from fastapi import Depends, HTTPException, status
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
    claims: TokenClaims = Depends(require_roles("Patient")),
) -> UserOut:
    result = await db.execute(select(User).where(User.id == uuid.UUID(claims.user_id)))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if body.email is not None:
        # Check uniqueness
        existing = await db.execute(
            select(User).where(User.email == body.email, User.id != user.id)
        )
        if existing.scalar_one_or_none() is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Email already in use",
            )
        user.email = body.email

    await db.flush()
    await db.refresh(user)
    return UserOut.model_validate(user)
