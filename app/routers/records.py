"""Records router: CRUD endpoints for medical records."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.middleware.rbac import TokenClaims, get_current_user, require_roles
from app.middleware.replay_guard import ReplayGuard
from app.models.base import get_db
from app.schemas.records import RecordIn, RecordOut, RecordUpdate
from app.services.records_service import RecordsService

router = APIRouter(tags=["records"])

_records_service = RecordsService()


@router.post("", response_model=RecordOut, status_code=status.HTTP_201_CREATED)
async def create_record(
    request: Request,
    body: RecordIn,
    db: AsyncSession = Depends(get_db),
    claims: TokenClaims = Depends(require_roles("Doctor", "Nurse", "Lab_Technician")),
    _replay: None = Depends(ReplayGuard.validate),
) -> RecordOut:
    client_ip = request.client.host if request.client else "0.0.0.0"
    return await _records_service.create_record(
        db,
        actor=claims,
        patient_id=body.patient_id,
        record_type=body.record_type,
        data=body.data,
        client_ip=client_ip,
    )


@router.get("/{record_id}", response_model=RecordOut, status_code=status.HTTP_200_OK)
async def get_record(
    record_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    claims: TokenClaims = Depends(get_current_user),
) -> RecordOut:
    client_ip = request.client.host if request.client else "0.0.0.0"
    return await _records_service.get_record(db, actor=claims, record_id=record_id, client_ip=client_ip)


@router.get("", response_model=list[RecordOut], status_code=status.HTTP_200_OK)
async def list_records(
    patient_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    claims: TokenClaims = Depends(get_current_user),
) -> list[RecordOut]:
    client_ip = request.client.host if request.client else "0.0.0.0"
    return await _records_service.list_records(db, actor=claims, patient_id=patient_id, client_ip=client_ip)


@router.patch("/{record_id}", response_model=RecordOut, status_code=status.HTTP_200_OK)
async def update_record(
    record_id: uuid.UUID,
    request: Request,
    body: RecordUpdate,
    db: AsyncSession = Depends(get_db),
    claims: TokenClaims = Depends(require_roles("Doctor", "Lab_Technician")),
    _replay: None = Depends(ReplayGuard.validate),
) -> RecordOut:
    client_ip = request.client.host if request.client else "0.0.0.0"
    return await _records_service.update_record(
        db, actor=claims, record_id=record_id, data=body.data, client_ip=client_ip
    )


@router.delete("/{record_id}", status_code=status.HTTP_200_OK)
async def delete_record(
    record_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    claims: TokenClaims = Depends(require_roles("Doctor")),
    _replay: None = Depends(ReplayGuard.validate),
) -> dict:
    client_ip = request.client.host if request.client else "0.0.0.0"
    return await _records_service.delete_record(db, actor=claims, record_id=record_id, client_ip=client_ip)
