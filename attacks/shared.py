"""

Shared utilities for all attack demonstration scripts.
Handles HTTP requests, colored output, and token management.

"""
import json
import sys
import uuid
from datetime import datetime, timezone

import urllib.request
import urllib.error
import ssl

# ── Config ─────────────────────────────────────────────
BASE_URL = "https://localhost:8000"
SSL_CTX  = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode    = ssl.CERT_NONE   # self-signed cert

# ── ANSI colors ────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def ok(msg):    print(f"{GREEN}  ✅ {msg}{RESET}")
def fail(msg):  print(f"{RED}  ❌ {msg}{RESET}")
def warn(msg):  print(f"{YELLOW}  ⚠️  {msg}{RESET}")
def info(msg):  print(f"{CYAN}  ℹ  {msg}{RESET}")
def header(msg):print(f"\n{BOLD}{CYAN}{'─'*55}{RESET}\n{BOLD}  {msg}{RESET}\n{'─'*55}")
def step(n, msg):print(f"\n{BOLD}[Step {n}]{RESET} {msg}")


# ── HTTP helpers ───────────────────────────────────────

def _replay_headers():
    return {
        "X-Nonce":     str(uuid.uuid4()),
        "X-Timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def request(method, path, body=None, token=None, replay=False, nonce=None, timestamp=None):
    """
    Make an HTTPS request to the backend.
    Returns (status_code, response_dict).
    """
    url = BASE_URL + path
    headers = {"Content-Type": "application/json"}

    if token:
        headers["Authorization"] = f"Bearer {token}"

    if replay:
        rh = _replay_headers()
        headers["X-Nonce"]     = nonce or rh["X-Nonce"]
        headers["X-Timestamp"] = timestamp or rh["X-Timestamp"]

    data = json.dumps(body).encode() if body else None
    req  = urllib.request.Request(url, data=data, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req, context=SSL_CTX) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read())
        except Exception:
            body = {"detail": str(e)}
        return e.code, body


def get(path, token=None):
    return request("GET", path, token=token)

def post(path, body=None, token=None, replay=False, nonce=None, timestamp=None):
    return request("POST", path, body=body, token=token,
                   replay=replay, nonce=nonce, timestamp=timestamp)

def patch(path, body=None, token=None, replay=False):
    return request("PATCH", path, body=body, token=token, replay=replay)

def delete(path, token=None, replay=False):
    return request("DELETE", path, token=token, replay=replay)


# ── Account helpers ────────────────────────────────────
def register(email, full_name, password, role="Patient"):
    status, data = post("/auth/register", {
        "email": email, "full_name": full_name,
        "password": password, "role": role,
    })
    return status, data


def login(email, password):
    status, data = post("/auth/login", {"email": email, "password": password}, replay=True)
    if status == 200 and "access_token" in data:
        return data["access_token"]
    return None


def get_my_id(token):
    _, data = get("/users/me", token=token)
    return data.get("id")


def setup_accounts():
    """
    Register and login patient + doctor. Returns (patient_token, patient_id, doctor_token).
    Idempotent — safe to call multiple times.
    """
    for email, name, role in [
        ("patient@demo.com", "Alice Patient", "Patient"),
        ("doctor@demo.com",  "Dr. Demo",      "Doctor"),
    ]:
        register(email, name, "DemoPass123!", role)

    pt = login("patient@demo.com", "DemoPass123!")
    dt = login("doctor@demo.com",  "DemoPass123!")
    pid = get_my_id(pt)
    return pt, pid, dt


def request_and_approve_consent(patient_token: str, doctor_token: str,
                                 patient_email: str = "patient@demo.com",
                                 duration_hours: int = 12) -> str | None:
    """
    Request a consent grant as doctor and approve it as patient.
    Returns the grant_id, or None if it could not be created.
    Handles the case where a grant already exists (409) by fetching existing grants.
    """
    status, data = post(
        "/consent",
        {"patient_email": patient_email, "duration_hours": duration_hours},
        token=doctor_token,
    )
    if status in (200, 201) and data.get("id"):
        grant_id = data["id"]
        # Approve it as patient
        post(f"/consent/{grant_id}/approve", token=patient_token)
        return grant_id

    # If a grant already exists and is active, find it
    _, grants = get("/consent", token=patient_token)
    if isinstance(grants, list):
        for g in grants:
            if g.get("status") == "active":
                return g.get("id")
        # Try to approve any pending grant
        for g in grants:
            if g.get("status") == "pending":
                gid = g.get("id")
                post(f"/consent/{gid}/approve", token=patient_token)
                return gid
    return None


def admin_login():
    return login("superadmin@hospital.org", "SuperAdmin123!")


def assert_blocked(status, data, expected_status=403, label="attack"):
    if status == expected_status:
        ok(f"BLOCKED ({status}) — {data.get('detail','')}")
    else:
        fail(f"VULNERABLE — expected {expected_status}, got {status}: {data}")
        sys.exit(1)


def assert_allowed(status, data, expected_status=200, label="request"):
    if status == expected_status:
        ok(f"ALLOWED ({status})")
    else:
        fail(f"FAILED — expected {expected_status}, got {status}: {data}")
        sys.exit(1)
