# Attack 08 — Unauthorized Record Access (Doctor Without Consent)

## What is it?

A doctor tries to read a patient's medical records without having an active
consent grant from that patient.

## How it works without defense

Without consent enforcement, any doctor could query:
```
GET /records?patient_id=<any-patient-uuid>
```
And read all records for any patient in the system.

## Defense implemented

Two layers:

1. **Consent check** — `records_service._check_consent()` queries the
   `consent_grants` table for an active, non-expired grant between this
   doctor and this patient.

2. **Audit logging** — denied access attempts are logged as `ACCESS_DENIED`
   events, visible to admins.

**Code:** `app/services/records_service.py`

```python
def _can_read(actor, record, has_consent):
    if role in ("Doctor", "Nurse"):
        # Must have active consent AND record must be published
        return has_consent and record.status == "published"
```

```python
if not _can_read(actor, record, has_consent):
    await self._audit_denied(db, actor, record_id, client_ip)
    raise HTTPException(status_code=403, detail="Access denied")
```

## Demonstration

```powershell
# ── Setup: doctor creates a record for the patient ────
Write-Host "=== Setup: Doctor requests consent and creates a record ==="

# Doctor requests consent
$h = Get-ReplayHeaders
$h["Authorization"] = "Bearer $DOCTOR_TOKEN"
$h["Content-Type"]  = "application/json"
$grant = Invoke-RestMethod -Method POST -Uri "https://localhost:8000/consent" `
    -Headers $h -SkipCertificateCheck `
    -Body "{`"patient_email`":`"patient@demo.com`",`"duration_hours`":12}"
$GRANT_ID = $grant.id
Write-Host "Consent requested: grant_id=$GRANT_ID, status=$($grant.status)"

# Patient approves
$r = Invoke-RestMethod -Method POST `
    -Uri "https://localhost:8000/consent/$GRANT_ID/approve" `
    -Headers @{"Authorization"="Bearer $PATIENT_TOKEN"} -SkipCertificateCheck
Write-Host "Consent approved: status=$($r.status)"

# Doctor creates a record
$h = Get-ReplayHeaders
$h["Authorization"] = "Bearer $DOCTOR_TOKEN"
$h["Content-Type"]  = "application/json"
$rec = Invoke-RestMethod -Method POST -Uri "https://localhost:8000/records" `
    -Headers $h -SkipCertificateCheck `
    -Body "{`"patient_id`":`"$PATIENT_ID`",`"record_type`":`"diagnosis`",`"data`":{`"diagnosis`":`"Hypertension`"},`"status`":`"published`"}"
$RECORD_ID = $rec.id
Write-Host "Record created: id=$RECORD_ID"

# ── Attack: revoke consent, then try to access ────────
Write-Host "`n=== Patient revokes consent ==="
Invoke-RestMethod -Method POST `
    -Uri "https://localhost:8000/consent/$GRANT_ID/revoke" `
    -Headers @{"Authorization"="Bearer $PATIENT_TOKEN"} -SkipCertificateCheck | Out-Null
Write-Host "Consent revoked."

Write-Host "`n=== Doctor tries to read record WITHOUT consent (ATTACK) ==="
try {
    Invoke-RestMethod -Uri "https://localhost:8000/records/$RECORD_ID" `
        -Headers @{"Authorization"="Bearer $DOCTOR_TOKEN"} -SkipCertificateCheck
    Write-Host "VULNERABLE: Doctor accessed record without consent!"
} catch {
    Write-Host "BLOCKED: HTTP $($_.Exception.Response.StatusCode.value__)"
    Write-Host $_.ErrorDetails.Message
}

# ── Check audit log for ACCESS_DENIED ─────────────────
Write-Host "`n=== Admin checks audit log for ACCESS_DENIED ==="
$entries = Invoke-RestMethod -Uri "https://localhost:8000/audit" `
    -Headers @{"Authorization"="Bearer $ADMIN_TOKEN"} -SkipCertificateCheck
$denied = $entries | Where-Object { $_.event_type -eq "ACCESS_DENIED" }
Write-Host "ACCESS_DENIED events: $($denied.Count)"
$denied | ForEach-Object {
    Write-Host "  [$($_.occurred_at)] actor=$($_.actor_id) resource=$($_.resource_id)"
}
```

## Expected output

```
=== Setup: Doctor requests consent and creates a record ===
Consent requested: grant_id=<uuid>, status=pending
Consent approved: status=active
Record created: id=<uuid>

=== Patient revokes consent ===
Consent revoked.

=== Doctor tries to read record WITHOUT consent (ATTACK) ===
BLOCKED: HTTP 403
{"detail":"Access denied"}

=== Admin checks audit log for ACCESS_DENIED ===
ACCESS_DENIED events: 1
  [2026-04-22T10:05:00] actor=<doctor-uuid> resource=<record-uuid>
```

## Automated tests

```powershell
$env:PYTHONPATH = "."
pytest tests/unit/test_attack_scenarios.py::test_doctor_without_consent_cannot_read_record -v
pytest tests/unit/test_attack_scenarios.py::test_doctor_with_consent_can_read_published_record -v
```
