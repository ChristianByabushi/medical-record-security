"""
run_all.py — Run all attack demonstrations in sequence.

Usage:
    python attacks/run_all.py

Skips attacks that require manual DB interaction (07, 11).
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from attacks.shared import header, ok, fail, warn, info, BOLD, RESET, GREEN, RED

ATTACKS = [
    ("01", "Replay Attack",                  "attacks.01_replay_attack"),
    ("02", "Stale Timestamp",                "attacks.02_stale_timestamp"),
    ("03", "Privilege Escalation",           "attacks.03_privilege_escalation"),
    ("04", "JWT Forgery",                    "attacks.04_jwt_forgery"),
    ("05", "User Enumeration",               "attacks.05_user_enumeration"),
    ("06", "Brute Force Detection",          "attacks.06_brute_force"),
    ("08", "Unauthorized Record Access",     "attacks.08_unauthorized_record_access"),
    ("09", "Cross-Patient Access",           "attacks.09_cross_patient_access"),
    ("10", "Draft Record Leakage",           "attacks.10_draft_record_leakage"),
    ("11", "AES-GCM Tampering (crypto only)","attacks.11_aes_gcm_tampering"),
]

SKIPPED = ["07", "11_db"]  # require manual DB interaction

def run():
    print(f"\n{BOLD}{'='*55}")
    print("  MedVault — Attack Demonstration Suite")
    print(f"{'='*55}{RESET}\n")
    print("  Running all automated attack demonstrations...")
    print("  (Attacks 07 and 11 DB-part require manual psql steps)\n")

    results = []
    for num, name, module in ATTACKS:
        print(f"\n{BOLD}{'─'*55}{RESET}")
        print(f"{BOLD}  [{num}] {name}{RESET}")
        print(f"{'─'*55}")
        try:
            import importlib
            mod = importlib.import_module(module)
            mod.run()
            results.append((num, name, True))
        except SystemExit:
            results.append((num, name, False))
        except Exception as e:
            print(f"{RED}  ERROR: {e}{RESET}")
            results.append((num, name, False))

    # Summary
    print(f"\n{BOLD}{'='*55}")
    print("  RESULTS SUMMARY")
    print(f"{'='*55}{RESET}")
    passed = sum(1 for _, _, r in results if r)
    for num, name, result in results:
        status = f"{GREEN}PASS{RESET}" if result else f"{RED}FAIL{RESET}"
        print(f"  [{num}] {name:<35} {status}")

    print(f"\n  {passed}/{len(results)} attacks demonstrated successfully")
    print(f"\n  Skipped (require manual DB steps):")
    print(f"    [07] Audit Tampering — run: python attacks/07_audit_tampering.py")
    print(f"    [11] AES-GCM DB part — run: python attacks/11_aes_gcm_tampering.py\n")

if __name__ == "__main__":
    run()