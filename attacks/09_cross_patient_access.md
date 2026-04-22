# Attack 09 — Cross-Patient Data Access

## What is it?

Patient A tries to read Patient B's medical records by guessing or obtaining
Patient B's UUID and querying the records endpoint directly.

## How it works without defense

Without ownership checks, any authenticated patient could query:
```
GET /records?patient_id=<any-other-patient-uuid>
```
And read another patient's complete medical history.

## Defense implemented

The records service checks that the requesting patient's ID matches the
record's `patient_id`. No consent mechanism applies — patients can only
ever see their own records.

**Code:** `app/services/records_service.py`

```python
def _can_read(actor, record, has_consent):
    if role == "Patient":
        # Patient sees only their own published records
        return record.patient_id == actor_uuid and record.status == "published"
```

## Demonstration

```powershell
# ── Setup: register a second patient ──────────────────
Write-Host "=== Setup: Register Patient B ==="
Invoke-RestMethod -Method POST -Uri "https://localhost:8000/auth/register" `
    -ContentType "application/json" -SkipCertificateCheck `
    -Body '{"email":"patientB@demo.com","full_name":"Bob Patient","password":"DemoPass123!","role":"Patient"}'

$h = Get-ReplayHeaders
$r = Invoke-RestMethod -Method POST -Uri "https://localhost:8000/auth/login" `
    -ContentType "application/json" -Headers $h -SkipCertificateCheck `
    -Body '{"email":"patientB@demo.com","password":"DemoPass123!"}'
$PATIENT_B_TOKEN = $r.access_token
$PATIENT_B_ID = (Invoke-RestMethod -Uri "https://localhost:8000/users/me" `
    -Headers @{"Authorization"="Bearer $PATIENT_B_TOKEN"} -SkipCertificateCheck).id
Write-Host "Patient B ID: $PATIENT_B_ID"

# ── Attack: Patient A tries to read Patient B's records ─
Write-Host "`n=== Patient A tries to read Patient B's records (ATTACK) ==="
try {
    $records = Invoke-RestMethod `
        -Uri "https://localhost:8000/records?patient_id=$PATIENT_B_ID" `
        -Headers @{"Authorization"="Bearer $PATIENT_TOKEN"} -SkipCertificateCheck
    if ($records.Count -gt 0) {
        Write-Host "VULNERABLE: Patient A read $($records.Count) of Patient B's records!"
    } else {
        Write-Host "BLOCKED: No records returned (ownership check enforced)"
    }
} catch {
    Write-Host "BLOCKED: HTTP $($_.Exception.Response.StatusCode.value__)"
    Write-Host $_.ErrorDetails.Message
}

# ── Confirm: Patient A can read their own records ─────
Write-Host "`n=== Patient A reads their own records (legitimate) ==="
$myRecords = Invoke-RestMethod `
    -Uri "https://localhost:8000/records?patient_id=$PATIENT_ID" `
    -Headers @{"Authorization"="Bearer $PATIENT_TOKEN"} -SkipCertificateCheck
Write-Host "ALLOWED: $($myRecords.Count) own record(s) returned"

# ── Confirm: Patient B can read their own records ─────
Write-Host "`n=== Patient B reads their own records (legitimate) ==="
$bRecords = Invoke-RestMethod `
    -Uri "https://localhost:8000/records?patient_id=$PATIENT_B_ID" `
    -Headers @{"Authorization"="Bearer $PATIENT_B_TOKEN"} -SkipCertificateCheck
Write-Host "ALLOWED: $($bRecords.Count) own record(s) returned"
```

## Expected output

```
=== Setup: Register Patient B ===
Patient B ID: <uuid-b>

=== Patient A tries to read Patient B's records (ATTACK) ===
BLOCKED: No records returned (ownership check enforced)

=== Patient A reads their own records (legitimate) ===
ALLOWED: 1 own record(s) returned

=== Patient B reads their own records (legitimate) ===
ALLOWED: 0 own record(s) returned
```

## Automated tests

```powershell
$env:PYTHONPATH = "."
pytest tests/unit/test_attack_scenarios.py::test_patient_cannot_access_other_patients_records -v
pytest tests/unit/test_attack_scenarios.py::test_patient_can_access_own_published_records -v
```
