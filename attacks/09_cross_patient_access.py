"""
Attack 09 — Cross-Patient Data Access
=======================================
Patient A tries to read Patient B's medical records by guessing their UUID.

Defense: patient_id ownership check — patients can only see their own records.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from attacks.shared import (
    header, step, ok, fail, info, warn,
    get, post, register, login, get_my_id,
    setup_accounts, assert_allowed,
)

def run():
    header("Attack 09 — Cross-Patient Data Access")

    info("Setting up accounts...")
    patient_a_token, patient_a_id, doctor_token = setup_accounts()

    # Register Patient B
    register("patientB@demo.com", "Bob Patient", "DemoPass123!", "Patient")
    patient_b_token = login("patientB@demo.com", "DemoPass123!")
    patient_b_id    = get_my_id(patient_b_token)
    info(f"Patient A ID: {patient_a_id}")
    info(f"Patient B ID: {patient_b_id}")

    step(1, "Patient A tries to list Patient B's records (ATTACK)")
    status, data = get(f"/records?patient_id={patient_b_id}", token=patient_a_token)
    if status == 200 and isinstance(data, list) and len(data) == 0:
        ok("BLOCKED — empty list (ownership check enforced, no records visible)")
    elif status == 403:
        ok(f"BLOCKED — 403 Forbidden")
        info(f"Detail: {data.get('detail','')}")
    else:
        fail(f"VULNERABLE — Patient A got {status}: {data}")
        sys.exit(1)

    step(2, "Patient A reads their own records (legitimate)")
    status, data = get(f"/records?patient_id={patient_a_id}", token=patient_a_token)
    assert_allowed(status, data, expected_status=200)
    ok(f"Patient A sees {len(data)} of their own record(s)")

    step(3, "Patient B reads their own records (legitimate)")
    status, data = get(f"/records?patient_id={patient_b_id}", token=patient_b_token)
    assert_allowed(status, data, expected_status=200)
    ok(f"Patient B sees {len(data)} of their own record(s)")

    step(4, "Patient A tries to read a specific record belonging to Patient B")
    # Create a record for Patient B first (via doctor with consent)
    _, grant = post("/consent",
                    {"patient_email": "patientB@demo.com", "duration_hours": 12},
                    token=doctor_token)
    if grant.get("id"):
        post(f"/consent/{grant['id']}/approve", token=patient_b_token)
        _, rec = post("/records",
                      {"patient_id": patient_b_id, "record_type": "vitals",
                       "data": {"blood_pressure": "120/80"}, "status": "published"},
                      token=doctor_token, replay=True)
        b_record_id = rec.get("id")
        info(f"Patient B's record ID: {b_record_id}")

        # Patient A tries to read it directly
        status, data = get(f"/records/{b_record_id}", token=patient_a_token)
        if status == 403:
            ok(f"BLOCKED — 403 on direct record access")
        elif status == 200:
            fail("VULNERABLE — Patient A read Patient B's record!")
            sys.exit(1)
        else:
            info(f"Got {status}: {data}")

    print("\n✅ Attack 09 complete — cross-patient access prevented.\n")

if __name__ == "__main__":
    run()