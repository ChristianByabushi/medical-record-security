"""Audit router: list entries and verify chain integrity."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.middleware.rbac import TokenClaims, get_current_user
from app.models.base import get_db
from app.schemas.audit import AuditEntryOut, AuditFilter, ChainVerificationResult
from app.services.audit_service import AuditService

router = APIRouter(tags=["audit"])

_audit_service = AuditService()


@router.get("", response_model=list[AuditEntryOut])
async def list_audit_entries(
    actor_id: Optional[uuid.UUID] = Query(default=None),
    resource_id: Optional[uuid.UUID] = Query(default=None),
    from_dt: Optional[datetime] = Query(default=None, alias="from"),
    to_dt: Optional[datetime] = Query(default=None, alias="to"),
    limit: int = Query(default=50, le=200),
    offset: int = Query(default=0),
    db: AsyncSession = Depends(get_db),
    claims: TokenClaims = Depends(get_current_user),
) -> list[AuditEntryOut]:
    # Admin/SuperAdmin see everything; all other roles see only their own activity
    subject_user_id = None
    if claims.role not in ("Admin", "SuperAdmin"):
        subject_user_id = uuid.UUID(claims.user_id)
        actor_id = None
        resource_id = None

    filters = AuditFilter(
        actor_id=actor_id,
        resource_id=resource_id,
        subject_user_id=subject_user_id,
        from_dt=from_dt,
        to_dt=to_dt,
        limit=limit,
        offset=offset,
    )
    return await _audit_service.list_entries(db, filters)


@router.get("/verify", response_model=ChainVerificationResult)
async def verify_chain(
    db: AsyncSession = Depends(get_db),
    claims: TokenClaims = Depends(get_current_user),
) -> ChainVerificationResult:
    # Only admins can verify the full chain
    if claims.role not in ("Admin", "SuperAdmin"):
        from fastapi import HTTPException
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    return await _audit_service.verify_chain(db)
