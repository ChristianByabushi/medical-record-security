"""
Attack 10 — Draft Record Leakage
==================================
Patient tries to read a medical record that the doctor saved as a draft
(not yet published/reviewed).

Defense: status == 'published' gate — drafts are only visible to their creator.

"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from attacks.shared import (
    header, step, ok, fail, info, warn,
    get, post, setup_accounts, request_and_approve_consent,
    assert_blocked, assert_allowed,
)

def run():
    header("Attack 10 — Draft Record Leakage")

    info("Setting up accounts...")
    patient_token, patient_id, doctor_token = setup_accounts()

    step(1, "Doctor creates a DRAFT record (not yet reviewed)")
    grant_id = request_and_approve_consent(patient_token, doctor_token)
    if not grant_id:
        fail("Could not establish consent grant")
        return

    _, draft = post("/records",
                    {"patient_id": patient_id, "record_type": "diagnosis",
                     "data": {"diagnosis": "Preliminary — under review", "severity": "Unknown"},
                     "status": "draft"},
                    token=doctor_token, replay=True)
    draft_id = draft.get("id")
    if not draft_id:
        fail(f"Draft record creation failed: {draft}")
        return
    info(f"Draft record created: {draft_id}, status={draft.get('status')}")

    step(2, "Patient tries to read the DRAFT record (ATTACK)")
    status, data = get(f"/records/{draft_id}", token=patient_token)
    assert_blocked(status, data, expected_status=403)
    info("Patient cannot see the draft — doctor is still reviewing it")

    step(3, "Patient lists their records — draft is not visible")
    status, records = get(f"/records?patient_id={patient_id}", token=patient_token)
    assert_allowed(status, records, expected_status=200)
    draft_visible = any(r.get("id") == draft_id for r in records)
    if not draft_visible:
        ok("Draft does NOT appear in patient's record list")
    else:
        fail("VULNERABLE — draft appears in patient's record list!")
        sys.exit(1)

    step(4, "Doctor can see their own draft (to review before publishing)")
    status, data = get(f"/records/{draft_id}", token=doctor_token)
    assert_allowed(status, data, expected_status=200)
    ok(f"Doctor sees draft: status={data.get('status')}, data={data.get('data')}")

    step(5, "Doctor publishes the record")
    status, pub = post(f"/records/{draft_id}/publish", token=doctor_token, replay=True)
    assert_allowed(status, pub, expected_status=200)
    ok(f"Published: status={pub.get('status')}, published_at={pub.get('published_at')}")
    info("Patient received an email notification")

    step(6, "Patient can now read the published record")
    status, data = get(f"/records/{draft_id}", token=patient_token)
    assert_allowed(status, data, expected_status=200)
    ok(f"Patient sees: status={data.get('status')}, data={data.get('data')}")

    print("\n✅ Attack 10 complete — draft/publish workflow confirmed.\n")

if __name__ == "__main__":
    run()