"""
Attack 05 — User Enumeration
==============================
Attacker tries to discover valid email addresses by comparing
error messages for wrong email vs wrong password.

Defense: Both cases return identical HTTP 401 "Invalid credentials".
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from attacks.shared import (
    header, step, ok, fail, info, warn,
    post, setup_accounts,
)

def run():
    header("Attack 05 — User Enumeration")

    info("Setting up accounts...")
    setup_accounts()

    step(1, "Wrong email — account does not exist")
    status1, data1 = post(
        "/auth/login",
        {"email": "nobody@nowhere.com", "password": "DemoPass123!"},
        replay=True,
    )
    info(f"Status:  {status1}")
    info(f"Detail:  {data1.get('detail','')}")
    info(f"ErrCode: {data1.get('error_code','')}")

    step(2, "Wrong password — account exists")
    status2, data2 = post(
        "/auth/login",
        {"email": "patient@demo.com", "password": "WrongPassword!"},
        replay=True,
    )
    info(f"Status:  {status2}")
    info(f"Detail:  {data2.get('detail','')}")
    info(f"ErrCode: {data2.get('error_code','')}")

    step(3, "Compare responses")
    same_status  = status1 == status2
    same_detail  = data1.get("detail") == data2.get("detail")
    same_errcode = data1.get("error_code") == data2.get("error_code")

    if same_status and same_detail and same_errcode:
        ok(f"Responses are IDENTICAL — no enumeration possible")
        ok(f"  Status:    {status1} == {status2}")
        ok(f"  Detail:    '{data1.get('detail')}' == '{data2.get('detail')}'")
        ok(f"  ErrorCode: '{data1.get('error_code')}' == '{data2.get('error_code')}'")
    else:
        fail("VULNERABLE — responses differ!")
        fail(f"  Wrong email: {status1} — {data1.get('detail')}")
        fail(f"  Wrong pwd:   {status2} — {data2.get('detail')}")
        sys.exit(1)

    step(4, "Correct credentials — login succeeds")
    status3, data3 = post(
        "/auth/login",
        {"email": "patient@demo.com", "password": "DemoPass123!"},
        replay=True,
    )
    if status3 == 200 and "access_token" in data3:
        ok(f"Correct credentials accepted (200)")
    else:
        fail(f"Login failed unexpectedly: {status3} — {data3}")

    print("\n✅ Attack 05 complete — user enumeration prevented.\n")

if __name__ == "__main__":
    run()
