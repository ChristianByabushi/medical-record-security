# Attack Demonstration Setup

Run this script once before demonstrating any attack. It creates test accounts
and saves their tokens to PowerShell variables.

## Prerequisites

- Backend running: `uvicorn app.main:app --ssl-certfile cert.pem --ssl-keyfile key.pem --host 0.0.0.0 --port 8000`
- Database migrated: `alembic upgrade head`
- SuperAdmin account created: `python create_superadmin.py`

## Setup script

```powershell
# ── Helper function ────────────────────────────────────
function Get-ReplayHeaders {
    return @{
        "X-Nonce"     = [System.Guid]::NewGuid().ToString()
        "X-Timestamp" = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    }
}

# ── Register Patient ───────────────────────────────────
Write-Host "Registering patient@demo.com..."
try {
    Invoke-RestMethod -Method POST -Uri "https://localhost:8000/auth/register" `
        -ContentType "application/json" -SkipCertificateCheck `
        -Body '{"email":"patient@demo.com","full_name":"Alice Patient","password":"DemoPass123!","role":"Patient"}' | Out-Null
} catch {
    Write-Host "  (Already exists — skipping)"
}

$h = Get-ReplayHeaders
$r = Invoke-RestMethod -Method POST -Uri "https://localhost:8000/auth/login" `
    -ContentType "application/json" -Headers $h -SkipCertificateCheck `
    -Body '{"email":"patient@demo.com","password":"DemoPass123!"}'
$PATIENT_TOKEN = $r.access_token
$PATIENT_ID = (Invoke-RestMethod -Uri "https://localhost:8000/users/me" `
    -Headers @{"Authorization"="Bearer $PATIENT_TOKEN"} -SkipCertificateCheck).id
Write-Host "  Token: $($PATIENT_TOKEN.Substring(0,25))..."
Write-Host "  ID:    $PATIENT_ID"

# ── Register Doctor ────────────────────────────────────
Write-Host "`nRegistering doctor@demo.com..."
try {
    Invoke-RestMethod -Method POST -Uri "https://localhost:8000/auth/register" `
        -ContentType "application/json" -SkipCertificateCheck `
        -Body '{"email":"doctor@demo.com","full_name":"Dr. Demo","password":"DemoPass123!","role":"Doctor"}' | Out-Null
} catch {
    Write-Host "  (Already exists — skipping)"
}

$h = Get-ReplayHeaders
$r = Invoke-RestMethod -Method POST -Uri "https://localhost:8000/auth/login" `
    -ContentType "application/json" -Headers $h -SkipCertificateCheck `
    -Body '{"email":"doctor@demo.com","password":"DemoPass123!"}'
$DOCTOR_TOKEN = $r.access_token
$DOCTOR_ID = (Invoke-RestMethod -Uri "https://localhost:8000/users/me" `
    -Headers @{"Authorization"="Bearer $DOCTOR_TOKEN"} -SkipCertificateCheck).id
Write-Host "  Token: $($DOCTOR_TOKEN.Substring(0,25))..."
Write-Host "  ID:    $DOCTOR_ID"

# ── Login as SuperAdmin ────────────────────────────────
Write-Host "`nLogging in as superadmin@hospital.org..."
$h = Get-ReplayHeaders
$r = Invoke-RestMethod -Method POST -Uri "https://localhost:8000/auth/login" `
    -ContentType "application/json" -Headers $h -SkipCertificateCheck `
    -Body '{"email":"superadmin@hospital.org","password":"SuperAdmin123!"}'
$ADMIN_TOKEN = $r.access_token
Write-Host "  Token: $($ADMIN_TOKEN.Substring(0,25))..."

# ── Summary ────────────────────────────────────────────
Write-Host "`n=== Setup complete ==="
Write-Host "Variables set:"
Write-Host "  `$PATIENT_TOKEN"
Write-Host "  `$PATIENT_ID"
Write-Host "  `$DOCTOR_TOKEN"
Write-Host "  `$DOCTOR_ID"
Write-Host "  `$ADMIN_TOKEN"
Write-Host ""
Write-Host "You can now run any attack demonstration."
```

## Verify setup

```powershell
# Check all tokens work
Write-Host "Patient profile:"
Invoke-RestMethod -Uri "https://localhost:8000/users/me" `
    -Headers @{"Authorization"="Bearer $PATIENT_TOKEN"} -SkipCertificateCheck | ConvertTo-Json

Write-Host "`nDoctor profile:"
Invoke-RestMethod -Uri "https://localhost:8000/users/me" `
    -Headers @{"Authorization"="Bearer $DOCTOR_TOKEN"} -SkipCertificateCheck | ConvertTo-Json

Write-Host "`nAdmin can list users:"
$users = Invoke-RestMethod -Uri "https://localhost:8000/admin/users" `
    -Headers @{"Authorization"="Bearer $ADMIN_TOKEN"} -SkipCertificateCheck
Write-Host "Total users: $($users.total)"
```
