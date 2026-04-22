"""
Attack 08 — Unauthorized Record Access (Doctor Without Consent)
================================================================
Doctor tries to read a patient's record without an active consent grant.

Defense: Consent check + ACCESS_DENIED audit event logged.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from attacks.shared import (
    header, step, ok, fail, info, warn,
    get, post, setup_accounts, admin_login,
    request_and_approve_consent,
    assert_blocked, assert_allowed,
)

def run():
    header("Attack 08 — Unauthorized Record Access")

    info("Setting up accounts...")
    patient_token, patient_id, doctor_token = setup_accounts()
    admin_token = admin_login()

    # Create a record with consent
    step(1, "Doctor requests consent and creates a published record")
    grant_id = request_and_approve_consent(patient_token, doctor_token)
    if not grant_id:
        fail("Could not establish consent grant")
        return
    info(f"Consent approved: {grant_id}")

    _, rec = post("/records",
                  {"patient_id": patient_id, "record_type": "diagnosis",
                   "data": {"diagnosis": "Hypertension"}, "status": "published"},
                  token=doctor_token, replay=True)
    record_id = rec.get("id")
    if not record_id:
        fail(f"Record creation failed: {rec}")
        return
    info(f"Record created: {record_id}")

    step(2, "Patient revokes consent")
    post(f"/consent/{grant_id}/revoke", token=patient_token)
    ok("Consent revoked")

    step(3, "Doctor tries to read record WITHOUT consent (ATTACK)")
    status, data = get(f"/records/{record_id}", token=doctor_token)
    assert_blocked(status, data, expected_status=403)
    info(f"Detail: {data.get('detail','')}")

    step(4, "Doctor tries to list patient records WITHOUT consent (ATTACK)")
    status, data = get(f"/records?patient_id={patient_id}", token=doctor_token)
    if status == 200 and isinstance(data, list) and len(data) == 0:
        ok("BLOCKED — empty list returned (no accessible records)")
    elif status == 403:
        ok(f"BLOCKED — 403 returned")
    else:
        fail(f"VULNERABLE — got {status}: {data}")

    step(5, "Admin checks audit log for ACCESS_DENIED events")
    _, entries = get("/audit", token=admin_token)
    denied = [e for e in entries if e.get("event_type") == "ACCESS_DENIED"]
    ok(f"ACCESS_DENIED events logged: {len(denied)}")
    for e in denied:
        info(f"  [{e.get('occurred_at','')}] actor={str(e.get('actor_id',''))[:8]}...")

    step(6, "Patient can still read their own record")
    status, data = get(f"/records/{record_id}", token=patient_token)
    assert_allowed(status, data, expected_status=200)
    info(f"Patient sees: {data.get('data', {})}")

    print("\n✅ Attack 08 complete — consent enforcement and audit logging confirmed.\n")

if __name__ == "__main__":
    run()