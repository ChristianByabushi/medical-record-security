"""Auth-related Pydantic schemas."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class RegisterRequest(BaseModel):
    email: EmailStr
    full_name: str = Field(min_length=2, max_length=255)
    password: str = Field(min_length=12)
    role: Literal["Patient"] = "Patient"


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenPair(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = 900


class PartialAuthResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    partial_token: str
    mfa_required: bool = True


class MFAVerifyRequest(BaseModel):
    totp_code: str = Field(pattern=r"^\d{6}$")


class MFALoginVerifyRequest(BaseModel):
    partial_token: str
    totp_code: str


class MFAEnrollResponse(BaseModel):
    provisioning_uri: str
    secret: str


class MFAConfirmRequest(BaseModel):
    totp_code: str


class RefreshRequest(BaseModel):
    refresh_token: str


class PasswordResetRequest(BaseModel):
    email: EmailStr


class PasswordResetComplete(BaseModel):
    token: str
    new_password: str = Field(min_length=12)
    totp_code: Optional[str] = None


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: str
    full_name: str = ""
    role: str
    mfa_enabled: bool
    must_change_password: bool = False
    recovery_email: Optional[str] = None
    created_at: datetime
