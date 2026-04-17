# Feature: secure-medical-records-backend, Property 23: Missing Required Environment Variables Cause Descriptive Startup Failure
"""
Property 23: Missing Required Environment Variables Cause Descriptive Startup Failure
Validates: Requirements 11.2

For each required env var, unset it and assert RuntimeError message contains the variable name.
"""
import importlib
import sys
import os
import pytest
from hypothesis import given, settings as h_settings
from hypothesis import strategies as st


REQUIRED_VARS = [
    "DATABASE_URL",
    "JWT_SECRET_KEY",
    "RECORD_ENCRYPTION_KEY",
    "TOTP_ENCRYPTION_KEY",
]

# Full set of valid env vars used as a baseline
_VALID_ENV = {
    "DATABASE_URL": "postgresql+asyncpg://user:pass@localhost/db",
    "JWT_SECRET_KEY": "supersecretkey1234567890abcdef",
    "JWT_ALGORITHM": "HS256",
    "RECORD_ENCRYPTION_KEY": "a" * 64,
    "TOTP_ENCRYPTION_KEY": "b" * 64,
    "ACCESS_TOKEN_EXPIRE_MINUTES": "15",
    "REFRESH_TOKEN_EXPIRE_DAYS": "7",
    "DEV_MODE": "false",
    "TLS_CERT_FILE": "cert.pem",
    "TLS_KEY_FILE": "key.pem",
}

_ALL_MANAGED_KEYS = set(REQUIRED_VARS) | set(_VALID_ENV.keys())


def _reload_config_with_env(env: dict) -> None:
    """Reload app.core.config with the given environment, isolated from real env."""
    # Remove cached module so module-level code re-executes
    for mod in list(sys.modules.keys()):
        if mod == "app.core.config" or mod.startswith("app.core.config."):
            del sys.modules[mod]

    # Snapshot and clear managed keys from real env
    saved = {k: os.environ[k] for k in _ALL_MANAGED_KEYS if k in os.environ}
    for k in _ALL_MANAGED_KEYS:
        os.environ.pop(k, None)

    # Prevent pydantic-settings from loading the real .env file
    os.environ["SETTINGS_ENV_FILE"] = "/nonexistent/.env.test"
    os.environ.update(env)
    try:
        importlib.import_module("app.core.config")
    finally:
        # Restore
        for k in _ALL_MANAGED_KEYS:
            os.environ.pop(k, None)
        os.environ.pop("SETTINGS_ENV_FILE", None)
        os.environ.update(saved)
        # Remove the module again so subsequent tests start fresh
        for mod in list(sys.modules.keys()):
            if mod == "app.core.config" or mod.startswith("app.core.config."):
                del sys.modules[mod]


@given(st.sampled_from(REQUIRED_VARS))
@h_settings(max_examples=100, deadline=None)
def test_missing_required_var_raises_runtime_error_with_var_name(missing_var: str):
    """
    Property 23: For each required env var, removing it causes RuntimeError
    whose message contains the variable name.
    """
    env = {k: v for k, v in _VALID_ENV.items() if k != missing_var}

    with pytest.raises(RuntimeError) as exc_info:
        _reload_config_with_env(env)

    assert missing_var in str(exc_info.value), (
        f"RuntimeError message '{exc_info.value}' does not contain '{missing_var}'"
    )


def test_all_vars_present_does_not_raise():
    """Sanity check: providing all required vars should not raise."""
    _reload_config_with_env(_VALID_ENV)
