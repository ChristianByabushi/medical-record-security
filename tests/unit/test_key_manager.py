# Feature: secure-medical-records-backend, Property 18: Key Manager Rejects Invalid Key Lengths
"""
Property 18: Key Manager Rejects Invalid Key Lengths
Validates: Requirements 8.4

For any byte sequence whose length is not exactly 32, KeyManager._decode_key
must raise RuntimeError. Only 32-byte inputs are valid AES-256 keys.
"""
import pytest
from hypothesis import given, settings as h_settings
from hypothesis import strategies as st

from app.core.key_manager import KeyManager


@given(st.binary(min_size=0, max_size=256).filter(lambda b: len(b) != 32))
@h_settings(max_examples=100)
def test_key_manager_rejects_non_32_byte_keys(raw_key: bytes):
    """
    Property 18: Key Manager Rejects Invalid Key Lengths
    Validates: Requirements 8.4

    Any hex-encoded key that does not decode to exactly 32 bytes must raise RuntimeError.
    """
    hex_key = raw_key.hex()
    with pytest.raises(RuntimeError):
        KeyManager._decode_key("TEST_KEY", hex_key)


def test_key_manager_accepts_32_byte_key():
    """Valid 32-byte key (64 hex chars) must not raise."""
    valid_hex = "a" * 64
    key = KeyManager._decode_key("TEST_KEY", valid_hex)
    assert len(key) == 32


def test_key_manager_rejects_invalid_hex():
    """Non-hex string must raise RuntimeError."""
    with pytest.raises(RuntimeError):
        KeyManager._decode_key("TEST_KEY", "not-valid-hex!!")


def test_get_key_manager_raises_when_not_initialised(monkeypatch):
    """get_key_manager() raises RuntimeError when _instance is None."""
    import app.core.key_manager as km_module
    original = km_module._instance
    km_module._instance = None
    try:
        from app.core.key_manager import get_key_manager
        with pytest.raises(RuntimeError, match="not been initialised"):
            get_key_manager()
    finally:
        km_module._instance = original
