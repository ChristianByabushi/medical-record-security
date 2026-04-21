"""Consent router: request, list, approve, reject, and revoke consent grants."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.middleware.rbac import TokenClaims, require_roles
from app.models.base import get_db
from app.schemas.consent import ConsentGrantOut, ConsentRequestIn
from app.services.consent_service import ConsentService

router = APIRouter(tags=["consent"])

_consent_service = ConsentService()


@router.post("", response_model=ConsentGrantOut, status_code=status.HTTP_201_CREATED)
async def request_consent(
    body: ConsentRequestIn,
    db: AsyncSession = Depends(get_db),
    claims: TokenClaims = Depends(require_roles("Doctor")),
) -> ConsentGrantOut:
    return await _consent_service.request_consent(
        db,
        doctor_id=uuid.UUID(claims.user_id),
        patient_email=body.patient_email,
        duration_hours=body.duration_hours,
    )


@router.get("", response_model=list[ConsentGrantOut], status_code=status.HTTP_200_OK)
async def list_grants(
    db: AsyncSession = Depends(get_db),
    claims: TokenClaims = Depends(require_roles("Patient", "Emergency_Contact")),
) -> list[ConsentGrantOut]:
    return await _consent_service.list_grants(db, patient_id=uuid.UUID(claims.user_id))


@router.post(
    "/{grant_id}/approve",
    response_model=ConsentGrantOut,
    status_code=status.HTTP_200_OK,
)
async def approve_consent(
    grant_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    claims: TokenClaims = Depends(require_roles("Patient", "Emergency_Contact")),
) -> ConsentGrantOut:
    return await _consent_service.approve_consent(
        db, patient_id=uuid.UUID(claims.user_id), grant_id=grant_id
    )


@router.post(
    "/{grant_id}/reject",
    response_model=ConsentGrantOut,
    status_code=status.HTTP_200_OK,
)
async def reject_consent(
    grant_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    claims: TokenClaims = Depends(require_roles("Patient", "Emergency_Contact")),
) -> ConsentGrantOut:
    return await _consent_service.reject_consent(
        db, patient_id=uuid.UUID(claims.user_id), grant_id=grant_id
    )


@router.post(
    "/{grant_id}/revoke",
    response_model=ConsentGrantOut,
    status_code=status.HTTP_200_OK,
)
async def revoke_consent(
    grant_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    claims: TokenClaims = Depends(require_roles("Patient", "Emergency_Contact")),
) -> ConsentGrantOut:
    return await _consent_service.revoke_consent(
        db, patient_id=uuid.UUID(claims.user_id), grant_id=grant_id
    )


@router.post(
    "/{grant_id}/release",
    response_model=ConsentGrantOut,
    status_code=status.HTTP_200_OK,
)
async def release_consent(
    grant_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    claims: TokenClaims = Depends(require_roles("Doctor")),
) -> ConsentGrantOut:
    return await _consent_service.release_consent(
        db, doctor_id=uuid.UUID(claims.user_id), grant_id=grant_id
    )


@router.get("/my-requests", response_model=list[ConsentGrantOut], status_code=status.HTTP_200_OK)
async def list_doctor_grants(
    db: AsyncSession = Depends(get_db),
    claims: TokenClaims = Depends(require_roles("Doctor")),
) -> list[ConsentGrantOut]:
    """List all consent requests made by this doctor."""
    return await _consent_service.list_doctor_grants(db, doctor_id=uuid.UUID(claims.user_id))
