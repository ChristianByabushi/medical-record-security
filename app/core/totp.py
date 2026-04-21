"""
Custom TOTP implementation — RFC 6238 / RFC 4226 compliant.

built from scratch using only
Python's standard library (hmac, hashlib, struct, time, os, base64).

Algorithm:
  1. Generate a shared secret (random 20 bytes, base32-encoded)
  2. Compute counter = floor(current_unix_time / time_step)
  3. HMAC-SHA1(secret_bytes, counter_as_8_byte_big_endian)
  4. Dynamic truncation → extract 4 bytes → mod 10^digits → zero-pad
  5. Compare user input against computed code (allow ±1 window for clock drift)
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import struct
import time
import urllib.parse

# ── Configuration ───────────────────────────────────────
DIGITS = 6           # Length of the OTP code
TIME_STEP = 30       # Seconds per time window
DRIFT_WINDOWS = 1    # Allow ±1 window for clock skew
SECRET_BYTES = 20    # 160-bit secret (standard for TOTP)


def generate_secret() -> str:
    """Generate a random base32-encoded secret (160 bits / 20 bytes)."""
    raw = os.urandom(SECRET_BYTES)
    return base64.b32encode(raw).decode("ascii")


def _decode_secret(secret_b32: str) -> bytes:
    """Decode a base32 secret string to raw bytes."""
    # Pad to multiple of 8 if needed
    padded = secret_b32.upper() + "=" * (-len(secret_b32) % 8)
    return base64.b32decode(padded)


def _compute_hotp(secret_bytes: bytes, counter: int) -> str:
    """
    HOTP algorithm (RFC 4226):
      1. HMAC-SHA1(secret, counter as 8-byte big-endian)
      2. Dynamic truncation: take 4 bytes at offset determined by last nibble
      3. Mask to 31 bits, mod 10^digits, zero-pad
    """
    # Step 1: HMAC-SHA1
    counter_bytes = struct.pack(">Q", counter)  # 8-byte big-endian
    hmac_digest = hmac.new(secret_bytes, counter_bytes, hashlib.sha1).digest()

    # Step 2: Dynamic truncation
    offset = hmac_digest[-1] & 0x0F
    truncated = struct.unpack(">I", hmac_digest[offset:offset + 4])[0]
    truncated &= 0x7FFFFFFF  # Mask to 31 bits (remove sign bit)

    # Step 3: Modulo and zero-pad
    code = truncated % (10 ** DIGITS)
    return str(code).zfill(DIGITS)


def generate_totp(secret_b32: str, timestamp: float | None = None) -> str:
    """
    Generate a TOTP code for the given secret at the current time.

    Args:
        secret_b32: Base32-encoded shared secret
        timestamp: Unix timestamp (defaults to current time)

    Returns:
        6-digit TOTP code as a string
    """
    if timestamp is None:
        timestamp = time.time()
    counter = int(timestamp) // TIME_STEP
    secret_bytes = _decode_secret(secret_b32)
    return _compute_hotp(secret_bytes, counter)


def verify_totp(secret_b32: str, code: str, timestamp: float | None = None) -> bool:
    """
    Verify a TOTP code against the shared secret.

    Checks the current time window plus ±DRIFT_WINDOWS to account
    for clock skew between server and authenticator app.

    Args:
        secret_b32: Base32-encoded shared secret
        code: 6-digit code entered by the user
        timestamp: Unix timestamp (defaults to current time)

    Returns:
        True if the code is valid in any allowed window
    """
    if timestamp is None:
        timestamp = time.time()

    current_counter = int(timestamp) // TIME_STEP
    secret_bytes = _decode_secret(secret_b32)

    # Check current window and ±drift windows
    for offset in range(-DRIFT_WINDOWS, DRIFT_WINDOWS + 1):
        expected = _compute_hotp(secret_bytes, current_counter + offset)
        if hmac.compare_digest(expected, code):
            return True

    return False


def build_provisioning_uri(secret_b32: str, email: str, issuer: str = "MedVault") -> str:
    """
    Build an otpauth:// URI for QR code scanning.

    Format: otpauth://totp/{issuer}:{email}?secret={secret}&issuer={issuer}&digits=6&period=30
    """
    label = f"{issuer}:{email}"
    params = urllib.parse.urlencode({
        "secret": secret_b32,
        "issuer": issuer,
        "digits": DIGITS,
        "period": TIME_STEP,
        "algorithm": "SHA1",
    })
    return f"otpauth://totp/{urllib.parse.quote(label)}?{params}"
