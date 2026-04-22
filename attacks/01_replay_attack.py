"""
Attack 01 — Replay Attack
=========================
An attacker captures a valid login request and sends it again
with the same nonce to obtain a fresh token.

Defense: Nonce store rejects any nonce seen within the last 5 minutes.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from attacks.shared import (
    header, step, ok, fail, info, warn,
    post, setup_accounts, assert_blocked, assert_allowed,
)

def run():
    header("Attack 01 — Replay Attack")

    info("Setting up accounts...")
    setup_accounts()

    # Use a fixed nonce but a live timestamp to simulate a captured request
    # Include a timestamp in the nonce so it's unique per run but still "fixed" for the demo
    import uuid as _uuid
    from datetime import datetime, timezone
    FIXED_NONCE = f"replay-demo-{_uuid.uuid4().hex[:8]}"
    CURRENT_TS  = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    info(f"Using fixed nonce: {FIXED_NONCE} (unique per run)")

    step(1, "Legitimate request — first use of nonce")
    status, data = post(
        "/auth/login",
        {"email": "patient@demo.com", "password": "DemoPass123!"},
        replay=True,
        nonce=FIXED_NONCE,
        timestamp=CURRENT_TS,
    )

    assert_allowed(status, data, expected_status=200)
    info(f"Token issued: {data.get('access_token','')[:30]}...")

    step(2, "Replay attack — same nonce sent again")
    status, data = post(
        "/auth/login",
        {"email": "patient@demo.com", "password": "DemoPass123!"},
        replay=True,
        nonce=FIXED_NONCE,
        timestamp=CURRENT_TS,
    )
    assert_blocked(status, data, expected_status=400)
    info(f"Error code: {data.get('error_code','')}")
    info(f"Detail: {data.get('detail','')}")

    step(3, "New unique nonce — request succeeds again")
    status, data = post(
        "/auth/login",
        {"email": "patient@demo.com", "password": "DemoPass123!"},
        replay=True,
    )
    assert_allowed(status, data, expected_status=200)
    info("Fresh nonce accepted — legitimate request goes through")

    print("\n✅ Attack 01 complete — replay protection confirmed.\n")

if __name__ == "__main__":
    run()
