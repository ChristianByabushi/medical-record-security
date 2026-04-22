"""
Attack 11 — AES-GCM Ciphertext Tampering
==========================================
Attacker with DB access flips a byte in the encrypted_data column.

Defense: AES-256-GCM authentication tag detects any modification to ciphertext.

This script demonstrates the detection using the crypto module directly,
then shows what happens when a tampered record is read via the API.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from attacks.shared import (
    header, step, ok, fail, info, warn,
    get, post, setup_accounts,
)

def run():
    header("Attack 11 — AES-GCM Ciphertext Tampering")

    # ── Part A: Direct crypto demonstration ───────────────
    step(1, "Demonstrate AES-GCM tamper detection directly")

    # Import the crypto module
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
    from app.core.crypto import encrypt, decrypt

    key       = bytes.fromhex("a" * 64)
    plaintext = b'{"diagnosis": "Hypertension", "severity": "Moderate"}'

    ciphertext, iv, tag = encrypt(plaintext, key)
    info(f"Original plaintext: {plaintext.decode()}")
    info(f"Ciphertext (hex):   {ciphertext.hex()[:40]}...")
    info(f"Auth tag (hex):     {tag.hex()}")

    # Verify round-trip works
    recovered = decrypt(ciphertext, iv, tag, key)
    ok(f"Normal decrypt: '{recovered.decode()}'")

    # Tamper: flip one byte in the ciphertext
    tampered = bytearray(ciphertext)
    tampered[0] ^= 0xFF
    info(f"\nAttacker flips byte 0: {ciphertext[0]:02x} → {tampered[0]:02x}")

    try:
        decrypt(bytes(tampered), iv, tag, key)
        fail("VULNERABLE — tampered ciphertext was decrypted!")
        sys.exit(1)
    except Exception as e:
        ok(f"BLOCKED — decryption failed: {type(e).__name__}")
        ok("AES-GCM authentication tag detected the modification")

    # Tamper: corrupt the tag itself
    bad_tag = bytes([b ^ 0xFF for b in tag])
    info(f"\nAttacker corrupts the auth tag")
    try:
        decrypt(ciphertext, bad_tag, tag, key)
        fail("VULNERABLE — corrupted tag was accepted!")
        sys.exit(1)
    except Exception as e:
        ok(f"BLOCKED — bad tag rejected: {type(e).__name__}")

    # ── Part B: API demonstration ──────────────────────────
    step(2, "Create a record via the API")
    patient_token, patient_id, doctor_token = setup_accounts()

    _, grant = post("/consent",
                    {"patient_email": "patient@demo.com", "duration_hours": 12},
                    token=doctor_token)
    if grant.get("id"):
        post(f"/consent/{grant['id']}/approve", token=patient_token)

    _, rec = post("/records",
                  {"patient_id": patient_id, "record_type": "diagnosis",
                   "data": {"diagnosis": "Hypertension"}, "status": "published"},
                  token=doctor_token, replay=True)
    record_id = rec.get("id")
    info(f"Record created: {record_id}")

    step(3, "Read the record normally — works")
    status, data = get(f"/records/{record_id}", token=patient_token)
    if status == 200:
        ok(f"Normal read: {data.get('data')}")
    else:
        warn(f"Read returned {status}: {data}")

    step(4, "Instructions — tamper with the database")
    print(f"""
  To complete this demonstration, run in psql:

  ┌─────────────────────────────────────────────────────────────────┐
  │  psql -U postgres -d medrecords                                 │
  │                                                                 │
  │  -- Flip one byte in the encrypted_data column                  │
  │  UPDATE medical_records                                         │
  │  SET encrypted_data = set_byte(encrypted_data, 0,               │
  │                        get_byte(encrypted_data, 0) # 255)       │
  │  WHERE id = '{record_id}';                                      │
  └─────────────────────────────────────────────────────────────────┘
""")
    input("  Press Enter after running the SQL to continue...")

    step(5, "Try to read the tampered record — must fail")
    status, data = get(f"/records/{record_id}", token=patient_token)
    if status == 500:
        ok(f"BLOCKED — server returned 500 (decryption failed)")
        ok("AES-GCM tag verification detected the DB tampering")
    elif status == 200:
        fail("VULNERABLE — tampered record was decrypted and returned!")
        sys.exit(1)
    else:
        info(f"Got {status}: {data}")

    print("\n✅ Attack 11 complete — AES-GCM tamper detection confirmed.\n")
    print("   AES-CBC would NOT detect this — it only provides confidentiality.")
    print("   AES-GCM provides confidentiality + integrity (authenticated encryption).\n")

if __name__ == "__main__":
    run()