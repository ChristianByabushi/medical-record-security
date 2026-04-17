"""Common Pydantic schemas."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class ErrorResponse(BaseModel):
    detail: str
    error_code: str
    timestamp: datetime
