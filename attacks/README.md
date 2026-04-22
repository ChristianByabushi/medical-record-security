# Attack Demonstrations

Each file in this folder documents one attack scenario — what the attack is,
how it works, the defense implemented, and the exact commands to reproduce it.

| # | File | Attack | Defense |
|---|------|--------|---------|
| 0 | `00_SETUP.md` | — | Setup script for all attacks |
| 1 | `01_replay_attack.md` | Replay captured request with same nonce | Nonce store + timestamp window |
| 2 | `02_stale_timestamp.md` | Replay with old timestamp | ±5 min timestamp validation |
| 3 | `03_privilege_escalation.md` | Patient calls Doctor-only endpoint | `require_roles()` → 403 |
| 4 | `04_jwt_forgery.md` | Modify JWT payload to change role | HMAC-SHA256 signature |
| 5 | `05_user_enumeration.md` | Distinguish valid vs invalid emails | Identical error messages |
| 6 | `06_brute_force.md` | Multiple wrong password attempts | `LOGIN_FAILED` audit logging |
| 7 | `07_audit_tampering.md` | Edit audit entry in database | SHA-256 hash chain |
| 8 | `08_unauthorized_record_access.md` | Doctor reads record without consent | Consent check + ACCESS_DENIED log |
| 9 | `09_cross_patient_access.md` | Patient reads another patient's record | `patient_id` ownership check |
| 10 | `10_draft_record_leakage.md` | Patient reads unpublished draft | `status == published` gate |
| 11 | `11_aes_gcm_tampering.md` | Modify encrypted record in database | AES-256-GCM authentication tag |

## Setup (run once before any attack)

```powershell
# Start the backend
uvicorn app.main:app --ssl-certfile cert.pem --ssl-keyfile key.pem --host 0.0.0.0 --port 8000

# Helper — generates fresh replay headers
function Get-ReplayHeaders {
    return @{
        "X-Nonce"     = [System.Guid]::NewGuid().ToString()
        "X-Timestamp" = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    }
}

# Register patient
Invoke-RestMethod -Method POST -Uri "https://localhost:8000/auth/register" `
    -ContentType "application/json" -SkipCertificateCheck `
    -Body '{"email":"patient@demo.com","full_name":"Alice Patient","password":"DemoPass123!","role":"Patient"}'

# Login patient — save token
$h = Get-ReplayHeaders
$r = Invoke-RestMethod -Method POST -Uri "https://localhost:8000/auth/login" `
    -ContentType "application/json" -Headers $h -SkipCertificateCheck `
    -Body '{"email":"patient@demo.com","password":"DemoPass123!"}'
$PATIENT_TOKEN = $r.access_token
$PATIENT_ID = (Invoke-RestMethod -Uri "https://localhost:8000/users/me" `
    -Headers @{"Authorization"="Bearer $PATIENT_TOKEN"} -SkipCertificateCheck).id

# Register doctor
Invoke-RestMethod -Method POST -Uri "https://localhost:8000/auth/register" `
    -ContentType "application/json" -SkipCertificateCheck `
    -Body '{"email":"doctor@demo.com","full_name":"Dr. Demo","password":"DemoPass123!","role":"Doctor"}'

$h = Get-ReplayHeaders
$r = Invoke-RestMethod -Method POST -Uri "https://localhost:8000/auth/login" `
    -ContentType "application/json" -Headers $h -SkipCertificateCheck `
    -Body '{"email":"doctor@demo.com","password":"DemoPass123!"}'
$DOCTOR_TOKEN = $r.access_token

# Login as SuperAdmin
$h = Get-ReplayHeaders
$r = Invoke-RestMethod -Method POST -Uri "https://localhost:8000/auth/login" `
    -ContentType "application/json" -Headers $h -SkipCertificateCheck `
    -Body '{"email":"superadmin@hospital.org","password":"SuperAdmin123!"}'
$ADMIN_TOKEN = $r.access_token

Write-Host "Setup complete."
Write-Host "PATIENT_TOKEN = $($PATIENT_TOKEN.Substring(0,20))..."
Write-Host "DOCTOR_TOKEN  = $($DOCTOR_TOKEN.Substring(0,20))..."
Write-Host "PATIENT_ID    = $PATIENT_ID"
```
