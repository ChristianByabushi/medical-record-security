"""
Attack 04 — JWT Forgery
========================
Attacker decodes their Patient JWT, changes role to SuperAdmin,
and re-signs with a guessed key.

Defense: HMAC-SHA256 signature — any modification invalidates the token.
"""
import sys
import os
import base64
import json
import hmac
import hashlib
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from attacks.shared import (
    header, step, ok, fail, info, warn,
    get, setup_accounts, assert_blocked, assert_allowed,
)

def _b64url_decode(s):
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)

def _b64url_encode(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def forge_token(original_token, new_role, fake_key=b"attacker-guessed-key"):
    """Decode JWT, change role, re-sign with a wrong key."""
    parts = original_token.split(".")
    payload = json.loads(_b64url_decode(parts[1]))
    info(f"Original role in JWT: {payload.get('role')}")

    payload["role"] = new_role
    new_payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{parts[0]}.{new_payload_b64}".encode()

    fake_sig = hmac.new(fake_key, signing_input, hashlib.sha256).digest()
    fake_sig_b64 = _b64url_encode(fake_sig)

    forged = f"{parts[0]}.{new_payload_b64}.{fake_sig_b64}"
    info(f"Forged role in JWT:   {new_role}")
    return forged

def run():
    header("Attack 04 — JWT Forgery")

    info("Setting up accounts...")
    patient_token, patient_id, _ = setup_accounts()

    step(1, "Decode the patient's JWT (no verification needed)")
    parts = patient_token.split(".")
    payload = json.loads(_b64url_decode(parts[1]))
    info(f"JWT payload: {json.dumps(payload, indent=2)}")

    step(2, "Forge token: change role from Patient → SuperAdmin")
    forged_token = forge_token(patient_token, "SuperAdmin")
    info(f"Forged token (first 60): {forged_token[:60]}...")

    step(3, "Use forged token on /users/me — must be rejected")
    status, data = get("/users/me", token=forged_token)
    assert_blocked(status, data, expected_status=401)
    info(f"Error code: {data.get('error_code','')}")
    info(f"Detail: {data.get('detail','')}")

    step(4, "Use forged token on admin endpoint — must also be rejected")
    status, data = get("/admin/users", token=forged_token)
    assert_blocked(status, data, expected_status=401)
    info("Admin endpoint also rejects the forged token")

    step(5, "Real token still works")
    status, data = get("/users/me", token=patient_token)
    assert_allowed(status, data, expected_status=200)
    info(f"Real token: role={data.get('role')}, email={data.get('email')}")

    print("\n✅ Attack 04 complete — JWT signature verification confirmed.\n")

if __name__ == "__main__":
    run()
