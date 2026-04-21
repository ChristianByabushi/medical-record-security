"""
Application configuration loaded from environment variables.
All required variables are validated at import time.
"""
import os
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


REQUIRED_VARS = [
    "DATABASE_URL",
    "JWT_SECRET_KEY",
    "RECORD_ENCRYPTION_KEY",
    "TOTP_ENCRYPTION_KEY",
]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=os.environ.get("SETTINGS_ENV_FILE", ".env"),
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    DATABASE_URL: str = Field(default="")
    JWT_SECRET_KEY: str = Field(default="")
    JWT_ALGORITHM: str = Field(default="HS256")
    RECORD_ENCRYPTION_KEY: str = Field(default="")
    TOTP_ENCRYPTION_KEY: str = Field(default="")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=15)
    REFRESH_TOKEN_EXPIRE_DAYS: int = Field(default=7)
    DEV_MODE: bool = Field(default=False)
    TLS_CERT_FILE: str = Field(default="cert.pem")
    TLS_KEY_FILE: str = Field(default="key.pem")

    # Application settings
    APP_NAME: str = Field(default="MedVault")
    APP_URL: str = Field(default="http://localhost:3000")

    # SMTP settings for sending emails
    SMTP_HOST: str = Field(default="")
    SMTP_PORT: int = Field(default=465)
    SMTP_USERNAME: str = Field(default="")
    SMTP_PASSWORD: str = Field(default="")
    SMTP_FROM_EMAIL: str = Field(default="")


def _validate_required(s: Settings) -> None:
    """Raise RuntimeError naming the first missing required variable."""
    for var in REQUIRED_VARS:
        if not getattr(s, var, None):
            raise RuntimeError(var)


settings = Settings()
_validate_required(settings)
