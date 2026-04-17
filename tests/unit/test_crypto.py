# Feature: secure-medical-records-backend, Property 17: AES-256-GCM Encryption Round-Trip Is Lossless
"""
Property 17: AES-256-GCM Encryption Round-Trip Is Lossless
Validates: Requirements 8.1, 8.2, 8.6

For any plaintext bytes (including empty), encrypting then decrypting with the
same 32-byte key must return the original plaintext unchanged.
"""
import pytest
from hypothesis import given, settings as h_settings
from hypothesis import strategies as st

from app.core.crypto import encrypt, decrypt

# Fixed 32-byte test key (64 hex chars of 'a')
_TEST_KEY = bytes.fromhex("a" * 64)


@given(st.binary())
@h_settings(max_examples=100)
def test_aes_gcm_round_trip(plaintext: bytes):
    """
    Property 17: AES-256-GCM Encryption Round-Trip Is Lossless
    Validates: Requirements 8.6

    decrypt(*encrypt(pt, key), key) == pt for all inputs including empty bytes.
    """
    ciphertext, iv, tag = encrypt(plaintext, _TEST_KEY)
    recovered = decrypt(ciphertext, iv, tag, _TEST_KEY)
    assert recovered == plaintext
