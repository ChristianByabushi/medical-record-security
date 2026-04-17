"""Custom exception classes and FastAPI exception handlers."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.schemas.common import ErrorResponse


class AppError(HTTPException):
    """HTTPException with an additional machine-readable error_code field."""

    def __init__(self, status_code: int, detail: str, error_code: str, headers: dict | None = None):
        super().__init__(status_code=status_code, detail=detail, headers=headers)
        self.error_code = error_code


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def register_exception_handlers(app: FastAPI) -> None:
    """Register global exception handlers on the FastAPI app."""

    @app.exception_handler(AppError)
    async def app_error_handler(request: Request, exc: AppError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content=ErrorResponse(
                detail=exc.detail,
                error_code=exc.error_code,
                timestamp=datetime.now(timezone.utc),
            ).model_dump(mode="json"),
            headers=exc.headers,
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content=ErrorResponse(
                detail="Request validation failed",
                error_code="VALIDATION_ERROR",
                timestamp=datetime.now(timezone.utc),
            ).model_dump(mode="json"),
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        # Log server-side without leaking stack trace to client
        import logging
        logging.getLogger(__name__).exception("Unhandled exception: %s", exc)
        return JSONResponse(
            status_code=500,
            content=ErrorResponse(
                detail="Internal server error",
                error_code="INTERNAL_ERROR",
                timestamp=datetime.now(timezone.utc),
            ).model_dump(mode="json"),
        )
