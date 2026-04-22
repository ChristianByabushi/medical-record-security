"""
Attack 02 — Stale Timestamp
============================
Attacker replays a request with an old timestamp (e.g., captured yesterday).

Defense: Timestamp must be within ±5 minutes of server time.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from attacks.shared import (
    header, step, ok, fail, info, warn,
    post, setup_accounts, assert_blocked, assert_allowed,
)

def run():
    header("Attack 02 — Stale Timestamp")

    info("Setting up accounts...")
    setup_accounts()

    body = {"email": "patient@demo.com", "password": "DemoPass123!"}

    step(1, "Timestamp from 2020 — clearly old")
    status, data = post(
        "/auth/login", body,
        replay=True,
        nonce="stale-ts-test-001",
        timestamp="2020-01-01T00:00:00Z",
    )
    assert_blocked(status, data, expected_status=400)
    info(f"Error code: {data.get('error_code','')}")

    step(2, "Timestamp 10 minutes in the future")
    from datetime import datetime, timezone, timedelta
    future_ts = (datetime.now(timezone.utc) + timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    status, data = post(
        "/auth/login", body,
        replay=True,
        nonce="stale-ts-test-002",
        timestamp=future_ts,
    )
    assert_blocked(status, data, expected_status=400)
    info(f"Future timestamp '{future_ts}' rejected")

    step(3, "Timestamp 6 minutes ago — just outside the 5-min window")
    old_ts = (datetime.now(timezone.utc) - timedelta(minutes=6)).strftime("%Y-%m-%dT%H:%M:%SZ")
    status, data = post(
        "/auth/login", body,
        replay=True,
        nonce="stale-ts-test-003",
        timestamp=old_ts,
    )
    assert_blocked(status, data, expected_status=400)
    info(f"Timestamp 6 min ago rejected")

    step(4, "Valid timestamp (now) — request succeeds")
    status, data = post("/auth/login", body, replay=True)
    assert_allowed(status, data, expected_status=200)
    info("Current timestamp accepted")

    print("\n✅ Attack 02 complete — timestamp validation confirmed.\n")

if __name__ == "__main__":
    run()
