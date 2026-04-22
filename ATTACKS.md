# Attack & Defense Demonstration

This document shows how to manually demonstrate each attack scenario against MedVault.
Each section shows the attack, the expected defense, and the exact command to run.

**Prerequisites:**
- Backend running: `uvicorn app.main:app --ssl-certfile cert.pem --ssl-keyfile key.pem --host 0.0.0.0 --port 8000`
- PowerShell with variables set (run the Setup block first)

---

## Setup — Register test accounts and get tokens

```powershell
# Helper function for replay headers
function Get-ReplayHeaders {
    return @{
        "X-Nonce"     = [System.Guid]::NewGuid().ToString()
        "X-Timestamp" = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    }
}

# Register a patient
$body = '{"email":"patient@demo.com","full_name":"Alice Patient","password":"DemoPass123!","role":"Patient"}'
Invoke-RestMethod -Method POST -Uri "https://localhost:8000/auth/register" `
    -ContentType "application/json" -Body $body -SkipCertificateCheck

# Login as patient — save token
$headers = Get-ReplayHeaders
$body = '{"email":"patient@demo.com","password":"DemoPass123!"}'
$r = Invoke-RestMethod -Method POST -Uri "https://localhost:8000/auth/login" `
    -ContentType "application/json" -Headers $headers -Body $body -SkipCertificateCheck
$PATIENT_TOKEN = $r.access_token
$PATIENT_ID = (Invoke-RestMethod -Uri "https://localhost:8000/users/me" `
    -Headers @{"Authorization"="Bearer $PATIENT_TOKEN"} -SkipCertificateCheck).id

Write-Host "Patient token: $($PATIENT_TOKEN.Substring(0,30))..."
Write-Host "Patient ID: $PATIENT_ID"
```

---

## Attack 1 — Replay Attack

**What:** Attacker captures a valid login request and sends it again.  
**Defense:** Nonce store rejects any nonce seen within the last 5 minutes.

```powershell
# Step 1: Set a FIXED nonce (simulating a captured request)
$FIXED_NONCE = "replay-attack-demo-nonce-12345"
$FIXED_TS = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

$headers = @{
    "Content-Type" = "application/json"
    "X-Nonce"      = $FIXED_NONCE
    "X-Timestamp"  = $FIXED_TS
}
$body = '{"email":"patient@demo.com","password":"DemoPass123!"}'

# First request — succeeds
Write-Host "=== First request (legitimate) ==="
$r1 = Invoke-RestMethod -Method POST -Uri "https://localhost:8000/auth/login" `
    -Headers $headers -Body $body -SkipCertificateCheck
Write-Host "Result: 200 OK — token issued"

# Second request — SAME nonce, same timestamp
Write-Host "`n=== Second request (REPLAY ATTACK) ==="
try {
    $r2 = Invoke-RestMethod -Method POST -Uri "https://localhost:8000/auth/login" `
        -Headers $headers -Body $body -SkipCertificateCheck
    Write-Host "FAIL: Replay was not blocked!"
} catch {
    Write-Host "BLOCKED: $($_.Exception.Response.StatusCode) — $($_.ErrorDetails.Message)"
    # Expected: 400 Bad Request — REPLAY_NONCE_SEEN
}
```

**Expected output:**
```
=== First request (legitimate) ===
Result: 200 OK — token issued

=== Second request (REPLAY ATTACK) ===
BLOCKED: 400 — {"detail":"Nonce already used","error_code":"REPLAY_NONCE_SEEN"}
```

---

## Attack 2 — Stale Timestamp Rejection

**What:** Attacker replays a request with an old timestamp (e.g., captured yesterday).  
**Defense:** Timestamp must be within ±5 minutes of server time.

```powershell
$headers = @{
    "Content-Type" = "application/json"
    "X-Nonce"      = [System.Guid]::NewGuid().ToString()
    "X-Timestamp"  = "2020-01-01T00:00:00Z"   # 6 years ago
}

$body = '{"email":"patient@demo.com","password":"DemoPass123!"}'

try {
    Invoke-RestMethod -Method POST -Uri "https://localhost:8000/auth/login" `
        -Headers $headers -Body $body -SkipCertificateCheck
} catch {
    Write-Host "BLOCKED: $($_.ErrorDetails.Message)"
    # Expected: 400 — REPLAY_TIMESTAMP_SKEW
}
```

---

## Attack 3 — Privilege Escalation (Patient → Doctor)

**What:** Patient tries to create a medical record (Doctor-only action).  
**Defense:** `require_roles("Doctor","Nurse","Lab_Technician")` returns 403.

```powershell
$headers = @{
    "Authorization" = "Bearer $PATIENT_TOKEN"
    "Content-Type"  = "application/json"
    "X-Nonce"       = [System.Guid]::NewGuid().ToString()
    "X-Timestamp"   = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
}
$body = "{`"patient_id`":`"$PATIENT_ID`",`"record_type`":`"diagnosis`",`"data`":{`"diagnosis`":`"Fake`"}}"

try {
    Invoke-RestMethod -Method POST -Uri "https://localhost:8000/records" `
        -Headers $headers -Body $body -SkipCertificateCheck
    Write-Host "FAIL: Patient was allowed to create a record!"
} catch {
    Write-Host "BLOCKED: $($_.Exception.Response.StatusCode)"
    Write-Host $_.ErrorDetails.Message
    # Expected: 403 — Insufficient permissions
}
```

---

## Attack 4 — User Enumeration

**What:** Attacker tries to discover valid email addresses by comparing error messages.  
**Defense:** Both "wrong email" and "wrong password" return identical 401 responses.

```powershell
$headers = Get-ReplayHeaders

# Wrong email (account doesn't exist)
try {
    $h = Get-ReplayHeaders
    Invoke-RestMethod -Method POST -Uri "https://localhost:8000/auth/login" `
        -ContentType "application/json" -Headers $h `
        -Body '{"email":"nobody@nowhere.com","password":"DemoPass123!"}' -SkipCertificateCheck
} catch {
    $wrongEmail = $_.ErrorDetails.Message
    Write-Host "Wrong email response:    $wrongEmail"
}

# Wrong password (account exists)
try {
    $h = Get-ReplayHeaders
    Invoke-RestMethod -Method POST -Uri "https://localhost:8000/auth/login" `
        -ContentType "application/json" -Headers $h `
        -Body '{"email":"patient@demo.com","password":"WrongPassword!"}' -SkipCertificateCheck
} catch {
    $wrongPwd = $_.ErrorDetails.Message
    Write-Host "Wrong password response: $wrongPwd"
}

# Both must be identical
if ($wrongEmail -eq $wrongPwd) {
    Write-Host "`nDEFENSE CONFIRMED: Responses are identical — no enumeration possible"
} else {
    Write-Host "`nVULNERABLE: Responses differ — email enumeration possible!"
}
```

**Expected output:**
```
Wrong email response:    {"detail":"Invalid credentials","error_code":"INVALID_CREDENTIALS"}
Wrong password response: {"detail":"Invalid credentials","error_code":"INVALID_CREDENTIALS"}

DEFENSE CONFIRMED: Responses are identical — no enumeration possible
```

---

## Attack 5 — Brute Force Detection

**What:** Attacker tries multiple passwords against a known account.  
**Defense:** Every failed attempt is logged as `LOGIN_FAILED` in the audit trail.

```powershell
# Attempt 5 wrong passwords
$passwords = @("wrong1!", "wrong2!", "wrong3!", "wrong4!", "wrong5!")
foreach ($pwd in $passwords) {
    try {
        $h = Get-ReplayHeaders
        Invoke-RestMethod -Method POST -Uri "https://localhost:8000/auth/login" `
            -ContentType "application/json" -Headers $h `
            -Body "{`"email`":`"patient@demo.com`",`"password`":`"$pwd`"}" -SkipCertificateCheck
    } catch { }
}

# Admin checks the audit log — login as admin first
$h = Get-ReplayHeaders
$r = Invoke-RestMethod -Method POST -Uri "https://localhost:8000/auth/login" `
    -ContentType "application/json" -Headers $h `
    -Body '{"email":"superadmin@hospital.org","password":"SuperAdmin123!"}' -SkipCertificateCheck
$ADMIN_TOKEN = $r.access_token

# Query audit log for LOGIN_FAILED events
$entries = Invoke-RestMethod -Uri "https://localhost:8000/audit" `
    -Headers @{"Authorization"="Bearer $ADMIN_TOKEN"} -SkipCertificateCheck

$failed = $entries | Where-Object { $_.event_type -eq "LOGIN_FAILED" }
Write-Host "Failed login attempts recorded: $($failed.Count)"
$failed | ForEach-Object { Write-Host "  - $($_.occurred_at): $($_.extra | ConvertTo-Json -Compress)" }
```

---

## Attack 6 — Audit Log Tampering

**What:** Attacker with DB access modifies an audit entry to hide their actions.  
**Defense:** SHA-256 hash chain — any modification breaks the chain.

```powershell
# Step 1: Verify chain is intact
$result = Invoke-RestMethod -Uri "https://localhost:8000/audit/verify" `
    -Headers @{"Authorization"="Bearer $ADMIN_TOKEN"} -SkipCertificateCheck
Write-Host "Before tampering: chain_intact=$($result.chain_intact), entries=$($result.entries_checked)"

# Step 2: Manually tamper with an audit entry in PostgreSQL
Write-Host "`nSimulate DB tampering (run in psql):"
Write-Host "  UPDATE audit_log SET event_type = 'TAMPERED' WHERE id = 1;"
Write-Host "  (Then re-run the verify endpoint)"

# Step 3: After tampering, verify detects it
# (Run this after manually editing the DB)
# $result2 = Invoke-RestMethod -Uri "https://localhost:8000/audit/verify" ...
# Expected: chain_intact=false, first_broken_at_id=1
```

**What to show in psql:**
```sql
-- Before: chain is intact
SELECT id, event_type, chain_hash FROM audit_log ORDER BY id LIMIT 3;

-- Tamper: change the event_type of entry 1
UPDATE audit_log SET event_type = 'TAMPERED_BY_ATTACKER' WHERE id = 1;

-- Now verify via API — it will report chain broken at id=1
```

---

## Attack 7 — Unauthorized Record Access (Doctor Without Consent)

**What:** Doctor tries to read a patient's record without an active consent grant.  
**Defense:** `_can_read()` requires `has_consent=True` for Doctor role.

```powershell
# Register and login as a doctor
$body = '{"email":"doctor@demo.com","full_name":"Dr. Demo","password":"DemoPass123!","role":"Doctor"}'
Invoke-RestMethod -Method POST -Uri "https://localhost:8000/auth/register" `
    -ContentType "application/json" -Body $body -SkipCertificateCheck

$h = Get-ReplayHeaders
$r = Invoke-RestMethod -Method POST -Uri "https://localhost:8000/auth/login" `
    -ContentType "application/json" -Headers $h `
    -Body '{"email":"doctor@demo.com","password":"DemoPass123!"}' -SkipCertificateCheck
$DOCTOR_TOKEN = $r.access_token

# Doctor tries to list patient's records WITHOUT consent
try {
    Invoke-RestMethod -Uri "https://localhost:8000/records?patient_id=$PATIENT_ID" `
        -Headers @{"Authorization"="Bearer $DOCTOR_TOKEN"} -SkipCertificateCheck
    Write-Host "FAIL: Doctor accessed records without consent!"
} catch {
    Write-Host "BLOCKED: $($_.Exception.Response.StatusCode)"
    # Expected: 403 or empty list
}

# Check audit log — ACCESS_DENIED should be recorded
$entries = Invoke-RestMethod -Uri "https://localhost:8000/audit" `
    -Headers @{"Authorization"="Bearer $ADMIN_TOKEN"} -SkipCertificateCheck
$denied = $entries | Where-Object { $_.event_type -eq "ACCESS_DENIED" }
Write-Host "ACCESS_DENIED events logged: $($denied.Count)"
```

---

## Attack 8 — Patient Verifies Their Own Audit Integrity

**What:** Patient checks whether their own audit entries have been tampered with.  
**Defense:** `/audit/verify` runs a scoped hash check on the patient's entries only.

```powershell
# Patient verifies their own audit entries
$result = Invoke-RestMethod -Uri "https://localhost:8000/audit/verify" `
    -Headers @{"Authorization"="Bearer $PATIENT_TOKEN"} -SkipCertificateCheck

Write-Host "chain_intact: $($result.chain_intact)"
Write-Host "entries_checked: $($result.entries_checked)"

if ($result.chain_intact) {
    Write-Host "Your audit records have not been tampered with."
} else {
    Write-Host "WARNING: Tampering detected at entry $($result.first_broken_at_id)!"
    Write-Host "Affected event: $($result.broken_entry_event)"
    Write-Host "Contact your administrator immediately."
}
```

---

## Attack 9 — Expired Token Rejection

**What:** Attacker uses a stolen access token after it has expired.  
**Defense:** JWT `exp` claim — tokens expire after 15 minutes.

```powershell
# Forge an expired token (for demonstration — attacker can't do this without the key)
# In a real scenario, just wait 15 minutes after stealing a token

# Show the token expiry from the JWT payload
$tokenParts = $PATIENT_TOKEN.Split(".")
$payload = [System.Text.Encoding]::UTF8.GetString(
    [System.Convert]::FromBase64String($tokenParts[1].PadRight($tokenParts[1].Length + (4 - $tokenParts[1].Length % 4) % 4, '='))
)
$exp = ($payload | ConvertFrom-Json).exp
$expTime = [DateTimeOffset]::FromUnixTimeSeconds($exp).LocalDateTime
Write-Host "Token expires at: $expTime"
Write-Host "Current time:     $(Get-Date)"
Write-Host "Token valid for:  $([math]::Round(($expTime - (Get-Date)).TotalMinutes, 1)) more minutes"
```

---

## Running the Automated Tests

```powershell
$env:PYTHONPATH = "D:\Courses-CMU\Information Security\FinalProject"

# All unit tests
pytest tests/unit/ -v --tb=short

# Just the attack scenario tests
pytest tests/unit/test_attack_scenarios.py -v --tb=short

# Just the TOTP tests (shows RFC 6238 compliance)
pytest tests/unit/test_totp.py -v --tb=short

# Just the audit chain tests
pytest tests/unit/test_audit_chain.py -v --tb=short

# Just the RBAC tests
pytest tests/unit/test_rbac.py -v --tb=short
```

---

## Summary of Defenses

| Attack | Defense | Where in Code |
|--------|---------|---------------|
| Replay attack | Nonce + timestamp validation | `app/middleware/replay_guard.py` |
| JWT forgery | HMAC-SHA256 signature verification | `app/middleware/rbac.py` |
| Privilege escalation | `require_roles()` on every endpoint | `app/middleware/rbac.py` |
| User enumeration | Identical error for wrong email/password | `app/services/auth_service.py` |
| Brute force | `LOGIN_FAILED` audit events | `app/services/auth_service.py` |
| DB breach (records) | AES-256-GCM encryption at rest | `app/core/crypto.py` |
| DB breach (passwords) | bcrypt with random salt | `app/services/auth_service.py` |
| Audit tampering | SHA-256 hash chain | `app/services/audit_service.py` |
| Timing attack (TOTP) | `hmac.compare_digest()` | `app/core/totp.py` |
| Cross-patient access | `patient_id` ownership check | `app/services/records_service.py` |
| Draft record leakage | `status == 'published'` check | `app/services/records_service.py` |
| Token theft | 15-min expiry + refresh rotation | `app/services/auth_service.py` |
