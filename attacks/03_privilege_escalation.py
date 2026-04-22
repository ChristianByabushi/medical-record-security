"""
Attack 03 — Privilege Escalation
==================================
A Patient tries to call Doctor-only endpoints (create/delete records).

Defense: require_roles() checks the JWT role and returns 403 for wrong roles.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from attacks.shared import (
    header, step, ok, fail, info, warn,
    post, delete, get, setup_accounts, request_and_approve_consent,
    assert_blocked, assert_allowed,
)

def run():
    header("Attack 03 — Privilege Escalation")

    info("Setting up accounts...")
    patient_token, patient_id, doctor_token = setup_accounts()

    step(1, "Patient tries to CREATE a medical record (Doctor-only)")
    status, data = post(
        "/records",
        {
            "patient_id": patient_id,
            "record_type": "diagnosis",
            "data": {"diagnosis": "Fake diagnosis by patient"},
            "status": "published",
        },
        token=patient_token,
        replay=True,
    )
    assert_blocked(status, data, expected_status=403)
    info(f"Detail: {data.get('detail','')}")

    step(2, "Doctor creates a record (legitimate)")
    # First need consent — request and approve
    grant_id = request_and_approve_consent(patient_token, doctor_token)
    if grant_id:
        info(f"Consent grant active: {grant_id}")
    else:
        warn("Could not establish consent grant — doctor record creation may fail")

    status, data = post(
        "/records",
        {
            "patient_id": patient_id,
            "record_type": "diagnosis",
            "data": {"diagnosis": "Hypertension", "severity": "Moderate"},
            "status": "published",
        },
        token=doctor_token,
        replay=True,
    )
    assert_allowed(status, data, expected_status=201)
    record_id = data.get("id")
    info(f"Record created: {record_id}")

    step(3, "Patient tries to DELETE the record (Doctor-only)")
    if not record_id:
        fail("No record_id — cannot test delete")
        return
    status, data = delete(f"/records/{record_id}", token=patient_token, replay=True)
    assert_blocked(status, data, expected_status=403)
    info(f"Detail: {data.get('detail','')}")

    step(4, "Patient tries to access Admin endpoint")
    status, data = post(
        "/admin/users",
        {"email": "hacker@evil.com", "full_name": "Hacker", "password": "Hack123456!", "role": "Doctor"},
        token=patient_token,
    )
    assert_blocked(status, data, expected_status=403)
    info("Admin endpoint blocked for Patient role")

    print("\n✅ Attack 03 complete — privilege escalation blocked.\n")

if __name__ == "__main__":
    run()
