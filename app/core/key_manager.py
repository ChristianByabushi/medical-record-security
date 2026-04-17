"""
Key_Manager: loads and validates AES-256 encryption keys from environment variables.
Keys are validated at startup; the singleton is stored on app.state.key_manager.
"""
from __future__ import annotations

from app.core.config import settings

_instance: "KeyManager | None" = None


class KeyManager:
    def __init__(self, record_key: bytes, totp_key: bytes) -> None:
        self._record_key = record_key
        self._totp_key = totp_key

    @classmethod
    def from_env(cls) -> "KeyManager":
        """Read keys from settings, decode hex, validate 32-byte length."""
        record_key = cls._decode_key("RECORD_ENCRYPTION_KEY", settings.RECORD_ENCRYPTION_KEY)
        totp_key = cls._decode_key("TOTP_ENCRYPTION_KEY", settings.TOTP_ENCRYPTION_KEY)
        return cls(record_key, totp_key)

    @staticmethod
    def _decode_key(name: str, hex_value: str) -> bytes:
        try:
            key = bytes.fromhex(hex_value)
        except ValueError:
            raise RuntimeError(
                f"{name} must be a 64-character hex string (32 bytes), got invalid hex"
            )
        if len(key) != 32:
            raise RuntimeError(
                f"{name} must be a 64-character hex string (32 bytes), got {len(key)} bytes"
            )
        return key

    def get_record_key(self) -> bytes:
        return self._record_key

    def get_totp_key(self) -> bytes:
        return self._totp_key


def get_key_manager() -> KeyManager:
    """Return the module-level singleton. Raises RuntimeError if not initialised."""
    if _instance is None:
        raise RuntimeError(
            "KeyManager has not been initialised. "
            "Call KeyManager.from_env() during application startup."
        )
    return _instance
