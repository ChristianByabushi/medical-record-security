"""Import all models so Alembic (and any metadata inspection) can discover them."""
from app.models.base import Base  # noqa: F401
from app.models.user import User  # noqa: F401
from app.models.mfa_secret import MFASecret  # noqa: F401
from app.models.refresh_token import RefreshToken  # noqa: F401
from app.models.password_reset_token import PasswordResetToken  # noqa: F401
from app.models.consent_grant import ConsentGrant  # noqa: F401
from app.models.medical_record import MedicalRecord  # noqa: F401
from app.models.audit_log import AuditLog  # noqa: F401
from app.models.nonce_store import NonceStore  # noqa: F401
from app.models.email_otp import EmailOTP  # noqa: F401
from app.models.patient_profile import PatientProfile  # noqa: F401
from app.models.emergency_contact import EmergencyContactLink  # noqa: F401

__all__ = [
    "Base", "User", "MFASecret", "RefreshToken", "PasswordResetToken",
    "ConsentGrant", "MedicalRecord", "AuditLog", "NonceStore", "EmailOTP",
    "PatientProfile", "EmergencyContactLink",
]
