"""
Attack 07 — Audit Log Tampering
=================================
Attacker with DB access modifies an audit entry to hide their actions.

Defense: SHA-256 hash chain — any modification breaks the chain at that entry.

NOTE: This script demonstrates the detection side.
      The actual DB modification must be done manually in psql (instructions printed).
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from attacks.shared import (
    header, step, ok, fail, info, warn,
    get, post, setup_accounts, admin_login,
)

def run():
    header("Attack 07 — Audit Log Tampering")

    info("Setting up accounts...")
    setup_accounts()
    admin_token = admin_login()
    if not admin_token:
        fail("Could not login as admin — run create_superadmin.py first")
        sys.exit(1)

    # Generate some audit entries
    info("Generating audit entries (login events)...")
    for _ in range(3):
        post("/auth/login",
             {"email": "patient@demo.com", "password": "DemoPass123!"},
             replay=True)

    step(1, "Verify audit chain BEFORE tampering")
    status, result = get("/audit/verify", token=admin_token)
    if status != 200:
        fail(f"Verify failed: {status} — {result}")
        sys.exit(1)

    ok(f"chain_intact: {result.get('chain_intact')}")
    ok(f"entries_checked: {result.get('entries_checked')}")

    step(2, "Fetch first few audit entries")
    status, entries = get("/audit", token=admin_token)
    if status != 200 or not entries:
        fail("Could not fetch audit entries")
        sys.exit(1)

    # Show the first entry
    first = entries[-1]  # entries are newest-first, so last = oldest
    info(f"First entry ID:    {first.get('id')}")
    info(f"First entry event: {first.get('event_type')}")
    info(f"First entry hash:  {first.get('chain_hash','')[:32]}...")

    step(3, "Instructions — tamper with the database")
    print(f"""
  Run this in psql to simulate an attacker modifying the audit log:

  ┌─────────────────────────────────────────────────────────────────┐
  │  psql -U postgres -d medrecords                                 │
  │                                                                 │
  │  -- See the entry                                               │
  │  SELECT id, event_type, chain_hash FROM audit_log               │
  │  ORDER BY id LIMIT 3;                                           │
  │                                                                 │
  │  -- Tamper: change event_type of the first entry                │
  │  UPDATE audit_log                                               │
  │  SET event_type = 'TAMPERED_BY_ATTACKER'                        │
  │  WHERE id = (SELECT MIN(id) FROM audit_log);                    │
  └─────────────────────────────────────────────────────────────────┘
""")
    input("  Press Enter after running the SQL to continue...")

    step(4, "Verify audit chain AFTER tampering")
    status, result = get("/audit/verify", token=admin_token)
    if status != 200:
        fail(f"Verify request failed: {status}")
        sys.exit(1)

    if not result.get("chain_intact"):
        ok(f"TAMPERING DETECTED!")
        ok(f"  chain_intact:       {result.get('chain_intact')}")
        ok(f"  first_broken_at_id: {result.get('first_broken_at_id')}")
        ok(f"  broken_entry_event: {result.get('broken_entry_event')}")
        ok(f"  occurred_at:        {result.get('broken_entry_occurred_at')}")
        info("All entries from this point forward are unreliable.")
    else:
        warn("Chain still intact — did you run the SQL?")

    step(5, "Patient verifies their own entries")
    patient_token = post(
        "/auth/login",
        {"email": "patient@demo.com", "password": "DemoPass123!"},
        replay=True,
    )[1].get("access_token")

    status, result = get("/audit/verify", token=patient_token)
    info(f"Patient verify — chain_intact: {result.get('chain_intact')}")
    info(f"Patient verify — entries_checked: {result.get('entries_checked')}")
    if not result.get("chain_intact"):
        warn("Patient's entries also affected — they should contact the administrator")

    print("\n✅ Attack 07 complete — audit chain tamper detection confirmed.\n")

if __name__ == "__main__":
    run()
