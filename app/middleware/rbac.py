"""RBAC middleware: JWT decoding, TokenClaims, and role-based access control."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.config import settings

_bearer = HTTPBearer()


@dataclass
class TokenClaims:
    user_id: str
    role: str


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(_bearer),
) -> TokenClaims:
    """Decode JWT and return TokenClaims. Raises HTTP 401 on any failure."""
    token = credentials.credentials
    try:
        payload = jwt.decode(
            token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM]
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired",
            headers={"X-Error-Code": "TOKEN_EXPIRED"},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"X-Error-Code": "TOKEN_INVALID"},
        )

    # Reject partial tokens (issued during MFA flow)
    if payload.get("partial") is True:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Full authentication required",
            headers={"X-Error-Code": "TOKEN_INVALID"},
        )

    return TokenClaims(user_id=payload["sub"], role=payload["role"])


def require_roles(*roles: str) -> Callable:
    """Factory that returns a FastAPI dependency enforcing role membership."""

    def _dependency(claims: TokenClaims = Depends(get_current_user)) -> TokenClaims:
        if claims.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
                headers={"X-Error-Code": "FORBIDDEN"},
            )
        return claims

    return _dependency
