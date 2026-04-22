# Attack 10 — Draft Record Leakage

## What is it?

A patient tries to read a medical record that a doctor has created but not
yet published. The doctor may still be reviewing or correcting the record
before making it official.

## How it works without defense

Without a draft/publish workflow, every record is immediately visible to the
patient the moment it is created — even if the doctor made an error and
hasn't reviewed it yet.

## Defense implemented

Records have a `status` field: `draft` or `published`.

- **Draft** — visible only to the creator (the doctor who wrote it)
- **Published** — visible to the patient and consented clinicians; patient
  receives an email notification

**Code:** `app/services/records_service.py`

```python
def _can_read(actor, record, has_consent):
    if role == "Patient":
        # Patient sees only their own PUBLISHED records
        return record.patient_id == actor_uuid and record.status == "published"

    if role in ("Doctor", "Nurse"):
        # Must have active consent AND record must be published
        return has_consent and record.status == "published"

    # Creator always sees their own records (draft or published)
    if record.created_by == actor_uuid:
        return True
```

## Demonstration

```powershell
# ── Setup: doctor creates a DRAFT record ──────────────
Write-Host "=== Doctor creates a DRAFT record ==="

# Ensure doctor has consent
$h = Get-ReplayHeaders
$h["Authorization"] = "Bearer $DOCTOR_TOKEN"
$h["Content-Type"]  = "application/json"
$grant = Invoke-RestMethod -Method POST -Uri "https://localhost:8000/consent" `
    -Headers $h -SkipCertificateCheck `
    -Body "{`"patient_email`":`"patient@demo.com`",`"duration_hours`":12}"
Invoke-RestMethod -Method POST `
    -Uri "https://localhost:8000/consent/$($grant.id)/approve" `
    -Headers @{"Authorization"="Bearer $PATIENT_TOKEN"} -SkipCertificateCheck | Out-Null

# Create a DRAFT record (default status)
$h = Get-ReplayHeaders
$h["Authorization"] = "Bearer $DOCTOR_TOKEN"
$h["Content-Type"]  = "application/json"
$draft = Invoke-RestMethod -Method POST -Uri "https://localhost:8000/records" `
    -Headers $h -SkipCertificateCheck `
    -Body "{`"patient_id`":`"$PATIENT_ID`",`"record_type`":`"diagnosis`",`"data`":{`"diagnosis`":`"Preliminary — under review`"},`"status`":`"draft`"}"
$DRAFT_ID = $draft.id
Write-Host "Draft record created: id=$DRAFT_ID, status=$($draft.status)"

# ── Attack: patient tries to read the draft ───────────
Write-Host "`n=== Patient tries to read the DRAFT record (ATTACK) ==="
try {
    $r = Invoke-RestMethod -Uri "https://localhost:8000/records/$DRAFT_ID" `
        -Headers @{"Authorization"="Bearer $PATIENT_TOKEN"} -SkipCertificateCheck
    Write-Host "VULNERABLE: Patient read draft record!"
    Write-Host "Data: $($r.data | ConvertTo-Json -Compress)"
} catch {
    Write-Host "BLOCKED: HTTP $($_.Exception.Response.StatusCode.value__)"
    Write-Host $_.ErrorDetails.Message
}

# ── Doctor can still see their own draft ──────────────
Write-Host "`n=== Doctor reads their own draft (legitimate) ==="
$r = Invoke-RestMethod -Uri "https://localhost:8000/records/$DRAFT_ID" `
    -Headers @{"Authorization"="Bearer $DOCTOR_TOKEN"} -SkipCertificateCheck
Write-Host "ALLOWED: status=$($r.status), data=$($r.data | ConvertTo-Json -Compress)"

# ── Doctor publishes the record ───────────────────────
Write-Host "`n=== Doctor publishes the record ==="
$h = Get-ReplayHeaders
$h["Authorization"] = "Bearer $DOCTOR_TOKEN"
$pub = Invoke-RestMethod -Method POST `
    -Uri "https://localhost:8000/records/$DRAFT_ID/publish" `
    -Headers $h -SkipCertificateCheck
Write-Host "Published: status=$($pub.status), published_at=$($pub.published_at)"

# ── Patient can now read the published record ─────────
Write-Host "`n=== Patient reads the PUBLISHED record (now allowed) ==="
$r = Invoke-RestMethod -Uri "https://localhost:8000/records/$DRAFT_ID" `
    -Headers @{"Authorization"="Bearer $PATIENT_TOKEN"} -SkipCertificateCheck
Write-Host "ALLOWED: status=$($r.status)"
Write-Host "Data: $($r.data | ConvertTo-Json -Compress)"
Write-Host "(Patient also received an email notification)"
```

## Expected output

```
=== Doctor creates a DRAFT record ===
Draft record created: id=<uuid>, status=draft

=== Patient tries to read the DRAFT record (ATTACK) ===
BLOCKED: HTTP 403
{"detail":"Access denied"}

=== Doctor reads their own draft (legitimate) ===
ALLOWED: status=draft, data={"diagnosis":"Preliminary — under review"}

=== Doctor publishes the record ===
Published: status=published, published_at=2026-04-22T10:10:00

=== Patient reads the PUBLISHED record (now allowed) ===
ALLOWED: status=published
Data: {"diagnosis":"Preliminary — under review"}
(Patient also received an email notification)
```

## Automated tests

```powershell
$env:PYTHONPATH = "."
pytest tests/unit/test_attack_scenarios.py::test_patient_cannot_see_draft_records -v
pytest tests/unit/test_attack_scenarios.py::test_doctor_cannot_read_draft_even_with_consent -v
pytest tests/unit/test_attack_scenarios.py::test_creator_always_sees_own_draft -v
```
