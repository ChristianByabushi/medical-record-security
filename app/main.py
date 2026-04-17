"""FastAPI application entry point."""
from contextlib import asynccontextmanager

from fastapi import FastAPI

import app.core.key_manager as _km_module
from app.core.exceptions import register_exception_handlers
from app.core.key_manager import KeyManager


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: initialise KeyManager singleton
    key_manager = KeyManager.from_env()
    app.state.key_manager = key_manager
    _km_module._instance = key_manager
    yield
    # Shutdown: cleanup here in later tasks


app = FastAPI(title="Secure Medical Records API", lifespan=lifespan)

# Register global exception handlers
register_exception_handlers(app)

# Routers
from app.routers.auth import router as auth_router  # noqa: E402
from app.routers.consent import router as consent_router  # noqa: E402
from app.routers.records import router as records_router  # noqa: E402
from app.routers.audit import router as audit_router  # noqa: E402
from app.routers.users import router as users_router  # noqa: E402
from app.routers.health import router as health_router  # noqa: E402

app.include_router(auth_router, prefix="/auth")
app.include_router(consent_router, prefix="/consent")
app.include_router(records_router, prefix="/records")
app.include_router(audit_router, prefix="/audit")
app.include_router(users_router, prefix="/users")
app.include_router(health_router)
