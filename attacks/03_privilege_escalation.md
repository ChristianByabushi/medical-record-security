# Attack 03 — Privilege Escalation

## What is it?

A lower-privileged user (Patient) attempts to call an endpoint that requires
a higher role (Doctor/Nurse/Lab_Technician) to create or modify medical records.

## How it works without defense

Without role enforcement, any authenticated user could POST to `/records`
and create records for any patient — bypassing the clinical workflow entirely.

## Defense implemented

Every endpoint uses `require_roles()` which reads the role from the JWT and
rejects any role not in the allowed list with HTTP 403.

**Code:** `app/middleware/rbac.py`

```python
def require_roles(*roles: str) -> Callable:
    def _dependency(claims: TokenClaims = Depends(get_current_user)) -> TokenClaims:
        if claims.role not in roles:
            raise HTTPException(
                status_code=403,
                detail="Insufficient permissions",
                headers={"X-Error-Code": "FORBIDDEN"},
            )
        return claims
    return _dependency
```

Applied on the records endpoint:
```python
# app/routers/records.py
@router.post("", ...)
async def create_record(
    claims: TokenClaims = Depends(require_roles("Doctor", "Nurse", "Lab_Technician")),
    ...
```

## Demonstration

```powershell
# ── Patient tries to create a medical record ──────────
Write-Host "=== Patient attempts to create a record (ATTACK) ==="
$headers = @{
    "Authorization" = "Bearer $PATIENT_TOKEN"
    "Content-Type"  = "application/json"
    "X-Nonce"       = [System.Guid]::NewGuid().ToString()
    "X-Timestamp"   = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
}
$body = "{`"patient_id`":`"$PATIENT_ID`",`"record_type`":`"diagnosis`",`"data`":{`"diagnosis`":`"Fake diagnosis`"}}"

try {
    Invoke-RestMethod -Method POST -Uri "https://localhost:8000/records" `
        -Headers $headers -Body $body -SkipCertificateCheck
    Write-Host "VULNERABLE: Patient was allowed to create a record!"
} catch {
    Write-Host "BLOCKED: HTTP $($_.Exception.Response.StatusCode.value__)"
    Write-Host $_.ErrorDetails.Message
}

# ── Doctor (correct role) creates a record ────────────
Write-Host "`n=== Doctor creates a record (legitimate) ==="
$headers["Authorization"] = "Bearer $DOCTOR_TOKEN"
$r = Invoke-RestMethod -Method POST -Uri "https://localhost:8000/records" `
    -Headers $headers -Body $body -SkipCertificateCheck
Write-Host "ALLOWED: HTTP 201 — record ID: $($r.id)"

# ── Patient tries to delete a record ──────────────────
Write-Host "`n=== Patient attempts to delete a record (ATTACK) ==="
$headers["Authorization"] = "Bearer $PATIENT_TOKEN"
$headers["X-Nonce"]       = [System.Guid]::NewGuid().ToString()
try {
    Invoke-RestMethod -Method DELETE -Uri "https://localhost:8000/records/$($r.id)" `
        -Headers $headers -SkipCertificateCheck
    Write-Host "VULNERABLE: Patient deleted a record!"
} catch {
    Write-Host "BLOCKED: HTTP $($_.Exception.Response.StatusCode.value__)"
    Write-Host $_.ErrorDetails.Message
}
```

## Expected output

```
=== Patient attempts to create a record (ATTACK) ===
BLOCKED: HTTP 403
{"detail":"Insufficient permissions","error_code":"FORBIDDEN"}

=== Doctor creates a record (legitimate) ===
ALLOWED: HTTP 201 — record ID: <uuid>

=== Patient attempts to delete a record (ATTACK) ===
BLOCKED: HTTP 403
{"detail":"Insufficient permissions","error_code":"FORBIDDEN"}
```

## Automated tests

```powershell
$env:PYTHONPATH = "."
pytest tests/unit/test_attack_scenarios.py::test_patient_cannot_access_doctor_endpoint -v
pytest tests/unit/test_rbac.py::test_require_roles_blocks_wrong_role -v
pytest tests/unit/test_rbac.py -k "non_clinician_blocked" -v
```
