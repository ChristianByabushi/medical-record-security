"""
Attack 06 — Brute Force Detection
===================================
Attacker tries multiple wrong passwords against a known account.

Defense: Every failed attempt is logged as LOGIN_FAILED in the audit trail.
Admins can detect the pattern and take action.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from attacks.shared import (
    header, step, ok, fail, info, warn,
    post, get, setup_accounts, admin_login,
)

def run():
    header("Attack 06 — Brute Force Detection")

    info("Setting up accounts...")
    setup_accounts()
    admin_token = admin_login()
    if not admin_token:
        fail("Could not login as admin — run create_superadmin.py first")
        sys.exit(1)

    step(1, "Attacker tries 5 wrong passwords")
    wrong_passwords = ["wrong1!", "wrong2!", "wrong3!", "wrong4!", "wrong5!"]
    for pwd in wrong_passwords:
        status, data = post(
            "/auth/login",
            {"email": "patient@demo.com", "password": pwd},
            replay=True,
        )
        info(f"  '{pwd}' → {status} {data.get('detail','')}")

    step(2, "Admin queries audit log for LOGIN_FAILED events")
    status, entries = get("/audit", token=admin_token)
    if status != 200:
        fail(f"Could not fetch audit log: {status}")
        sys.exit(1)

    failed = [e for e in entries if e.get("event_type") == "LOGIN_FAILED"]
    ok(f"LOGIN_FAILED events recorded: {len(failed)}")
    for e in failed:
        reason = (e.get("extra") or {}).get("reason", "unknown")
        ts     = e.get("occurred_at", "")
        info(f"  [{ts}] reason={reason}")

    if len(failed) >= 5:
        ok("All 5 brute-force attempts are in the audit log")
    else:
        warn(f"Only {len(failed)} events found — some may have been from previous runs")

    step(3, "Correct password still works after failed attempts")
    status, data = post(
        "/auth/login",
        {"email": "patient@demo.com", "password": "DemoPass123!"},
        replay=True,
    )
    if status == 200 and "access_token" in data:
        ok("Correct credentials accepted — no lockout (rate limiting is a proxy concern)")
    else:
        fail(f"Login failed: {status} — {data}")

    print("\n✅ Attack 06 complete — brute force attempts are audit-logged.\n")
    print("   In production: add rate limiting at the reverse proxy (nginx/Cloudflare)")
    print("   to block IPs after N failed attempts.\n")

if __name__ == "__main__":
    run()
