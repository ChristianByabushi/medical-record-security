"""Patient profile and emergency contact endpoints."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.middleware.rbac import TokenClaims, get_current_user, require_roles
from app.middleware.replay_guard import ReplayGuard
from app.models.base import get_db
from app.models.emergency_contact import EmergencyContactLink
from app.models.patient_profile import PatientProfile
from app.models.user import User
from app.schemas.patient_profile import (
    EmergencyContactLinkIn,
    EmergencyContactLinkOut,
    EmergencySummaryOut,
    PatientProfileIn,
    PatientProfileOut,
)

router = APIRouter(tags=["patient-profile"])


# ── Get / upsert own profile ────────────────────────────────────────────────

@router.get("/me/profile", response_model=PatientProfileOut)
async def get_my_profile(
    db: AsyncSession = Depends(get_db),
    claims: TokenClaims = Depends(require_roles("Patient")),
) -> PatientProfileOut:
    result = await db.execute(
        select(PatientProfile).where(PatientProfile.user_id == uuid.UUID(claims.user_id))
    )
    profile = result.scalar_one_or_none()
    if profile is None:
        # Auto-create empty profile
        profile = PatientProfile(user_id=uuid.UUID(claims.user_id))
        db.add(profile)
        await db.flush()
        await db.refresh(profile)
    return PatientProfileOut.model_validate(profile)


@router.patch("/me/profile", response_model=PatientProfileOut)
async def update_my_profile(
    body: PatientProfileIn,
    db: AsyncSession = Depends(get_db),
    claims: TokenClaims = Depends(require_roles("Patient")),
    _replay: None = Depends(ReplayGuard.validate),
) -> PatientProfileOut:
    result = await db.execute(
        select(PatientProfile).where(PatientProfile.user_id == uuid.UUID(claims.user_id))
    )
    profile = result.scalar_one_or_none()
    if profile is None:
        profile = PatientProfile(user_id=uuid.UUID(claims.user_id))
        db.add(profile)

    for field, value in body.model_dump(exclude_unset=True).items():
        setattr(profile, field, value)

    await db.flush()
    await db.refresh(profile)
    return PatientProfileOut.model_validate(profile)


# ── Profile edit for all users (name, email) ───────────────────────────────

@router.patch("/me", response_model=dict)
async def update_identity(
    body: dict,
    db: AsyncSession = Depends(get_db),
    claims: TokenClaims = Depends(get_current_user),
    _replay: None = Depends(ReplayGuard.validate),
) -> dict:
    """Update full_name and/or email for any user."""
    result = await db.execute(select(User).where(User.id == uuid.UUID(claims.user_id)))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    if "full_name" in body and body["full_name"]:
        user.full_name = str(body["full_name"])[:255]
    if "email" in body and body["email"]:
        # Check uniqueness
        existing = await db.execute(select(User).where(User.email == body["email"]))
        if existing.scalar_one_or_none() is not None and body["email"] != user.email:
            raise HTTPException(status_code=409, detail="Email already in use")
        user.email = body["email"]

    await db.flush()
    return {"message": "Profile updated", "full_name": user.full_name, "email": user.email}


# ── Emergency contacts ──────────────────────────────────────────────────────

@router.get("/me/emergency-contacts", response_model=list[EmergencyContactLinkOut])
async def list_emergency_contacts(
    db: AsyncSession = Depends(get_db),
    claims: TokenClaims = Depends(require_roles("Patient")),
) -> list[EmergencyContactLinkOut]:
    result = await db.execute(
        select(EmergencyContactLink).where(
            EmergencyContactLink.patient_id == uuid.UUID(claims.user_id)
        )
    )
    links = result.scalars().all()
    out = []
    for link in links:
        contact_result = await db.execute(select(User).where(User.id == link.contact_user_id))
        contact = contact_result.scalar_one_or_none()
        out.append(EmergencyContactLinkOut(
            id=link.id,
            patient_id=link.patient_id,
            contact_user_id=link.contact_user_id,
            contact_email=contact.email if contact else None,
            contact_name=contact.full_name if contact else None,
            relationship=link.relationship,
            created_at=link.created_at,
        ))
    return out


@router.post("/me/emergency-contacts", response_model=EmergencyContactLinkOut, status_code=201)
async def add_emergency_contact(
    body: EmergencyContactLinkIn,
    db: AsyncSession = Depends(get_db),
    claims: TokenClaims = Depends(require_roles("Patient")),
    _replay: None = Depends(ReplayGuard.validate),
) -> EmergencyContactLinkOut:
    patient_id = uuid.UUID(claims.user_id)

    # Max 2 emergency contacts
    count_result = await db.execute(
        select(EmergencyContactLink).where(EmergencyContactLink.patient_id == patient_id)
    )
    if len(count_result.scalars().all()) >= 2:
        raise HTTPException(status_code=400, detail="Maximum 2 emergency contacts allowed")

    # Resolve contact by email — must be Emergency_Contact role
    contact_result = await db.execute(
        select(User).where(User.email == body.contact_email, User.role == "Emergency_Contact")
    )
    contact = contact_result.scalar_one_or_none()
    if contact is None:
        raise HTTPException(status_code=404, detail="No Emergency_Contact user found with that email")

    # Check not already linked
    existing = await db.execute(
        select(EmergencyContactLink).where(
            EmergencyContactLink.patient_id == patient_id,
            EmergencyContactLink.contact_user_id == contact.id,
        )
    )
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(status_code=409, detail="Already linked as emergency contact")

    link = EmergencyContactLink(
        patient_id=patient_id,
        contact_user_id=contact.id,
        relationship=body.relationship,
    )
    db.add(link)
    await db.flush()
    await db.refresh(link)

    return EmergencyContactLinkOut(
        id=link.id,
        patient_id=link.patient_id,
        contact_user_id=link.contact_user_id,
        contact_email=contact.email,
        contact_name=contact.full_name,
        relationship=link.relationship,
        created_at=link.created_at,
    )


@router.delete("/me/emergency-contacts/{link_id}", status_code=200)
async def remove_emergency_contact(
    link_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    claims: TokenClaims = Depends(require_roles("Patient")),
    _replay: None = Depends(ReplayGuard.validate),
) -> dict:
    result = await db.execute(
        select(EmergencyContactLink).where(
            EmergencyContactLink.id == link_id,
            EmergencyContactLink.patient_id == uuid.UUID(claims.user_id),
        )
    )
    link = result.scalar_one_or_none()
    if link is None:
        raise HTTPException(status_code=404, detail="Emergency contact not found")
    await db.delete(link)
    await db.flush()
    return {"message": "Emergency contact removed"}


# ── Emergency summary (for Emergency_Contact role) ─────────────────────────

@router.get("/patients/{patient_id}/emergency-summary", response_model=EmergencySummaryOut)
async def get_emergency_summary(
    patient_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    claims: TokenClaims = Depends(require_roles("Emergency_Contact")),
) -> EmergencySummaryOut:
    """Emergency contacts can view limited patient summary: allergies, blood type, conditions, DNR."""
    # Verify this emergency contact is linked to the patient
    link_result = await db.execute(
        select(EmergencyContactLink).where(
            EmergencyContactLink.patient_id == patient_id,
            EmergencyContactLink.contact_user_id == uuid.UUID(claims.user_id),
        )
    )
    if link_result.scalar_one_or_none() is None:
        raise HTTPException(status_code=403, detail="Not linked as emergency contact for this patient")

    user_result = await db.execute(select(User).where(User.id == patient_id))
    patient = user_result.scalar_one_or_none()
    if patient is None:
        raise HTTPException(status_code=404, detail="Patient not found")

    profile_result = await db.execute(
        select(PatientProfile).where(PatientProfile.user_id == patient_id)
    )
    profile = profile_result.scalar_one_or_none()

    return EmergencySummaryOut(
        full_name=patient.full_name,
        blood_type=profile.blood_type if profile else None,
        known_allergies=profile.known_allergies if profile else None,
        known_conditions=profile.known_conditions if profile else None,
        dnr_status=profile.dnr_status if profile else None,
    )
