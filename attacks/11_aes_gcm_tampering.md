# Attack 11 — AES-GCM Ciphertext Tampering

## What is it?

An attacker with database access modifies the encrypted medical record data
directly in the `medical_records` table, hoping to alter the patient's
diagnosis or treatment plan.

## How it works without defense

If the system used AES-CBC (encryption only, no authentication), an attacker
could flip bits in the ciphertext and the system would decrypt it to garbage
or partially altered plaintext — with no detection.

## Defense implemented

AES-256-GCM provides **authenticated encryption** — the `tag` field is a
cryptographic checksum of the ciphertext. Any modification to the ciphertext
causes the tag verification to fail during decryption.

**Code:** `app/core/crypto.py`

```python
def decrypt(ciphertext: bytes, iv: bytes, tag: bytes, key: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    # If tag doesn't match → InvalidTag exception raised
    return plaintext
```

## Demonstration (requires psql access)

```powershell
# ── Step 1: Doctor creates a record ───────────────────
Write-Host "=== Step 1: Doctor creates a record ==="
$h = Get-ReplayHeaders
$h["Authorization"] = "Bearer $DOCTOR_TOKEN"
$h["Content-Type"]  = "application/json"

# Ensure consent exists
$grant = Invoke-RestMethod -Method POST -Uri "https://localhost:8000/consent" `
    -Headers $h -SkipCertificateCheck `
    -Body "{`"patient_email`":`"patient@demo.com`",`"duration_hours`":12}"
Invoke-RestMethod -Method POST `
    -Uri "https://localhost:8000/consent/$($grant.id)/approve" `
    -Headers @{"Authorization"="Bearer $PATIENT_TOKEN"} -SkipCertificateCheck | Out-Null

$rec = Invoke-RestMethod -Method POST -Uri "https://localhost:8000/records" `
    -Headers $h -SkipCertificateCheck `
    -Body "{`"patient_id`":`"$PATIENT_ID`",`"record_type`":`"diagnosis`",`"data`":{`"diagnosis`":`"Hypertension`",`"severity`":`"Moderate`"},`"status`":`"published`"}"
$RECORD_ID = $rec.id
Write-Host "Record created: id=$RECORD_ID"

# ── Step 2: Read the record (works) ───────────────────
Write-Host "`n=== Step 2: Patient reads the record (before tampering) ==="
$r = Invoke-RestMethod -Uri "https://localhost:8000/records/$RECORD_ID" `
    -Headers @{"Authorization"="Bearer $PATIENT_TOKEN"} -SkipCertificateCheck
Write-Host "Data: $($r.data | ConvertTo-Json -Compress)"

# ── Step 3: Tamper with ciphertext in PostgreSQL ──────
Write-Host "`n=== Step 3: Tamper with encrypted_data in database ==="
Write-Host "Run this in psql:"
Write-Host ""
Write-Host "  -- Find the record"
Write-Host "  SELECT id, record_type, length(encrypted_data) FROM medical_records WHERE id = '$RECORD_ID';"
Write-Host ""
Write-Host "  -- Flip one byte in the ciphertext (simulates attacker modifying DB)"
Write-Host "  UPDATE medical_records"
Write-Host "  SET encrypted_data = set_byte(encrypted_data, 0, get_byte(encrypted_data, 0) # 255)"
Write-Host "  WHERE id = '$RECORD_ID';"
Write-Host ""
Write-Host "(Press Enter after running the SQL to continue...)"
Read-Host

# ── Step 4: Try to read the tampered record ───────────
Write-Host "=== Step 4: Patient tries to read tampered record ==="
try {
    $r = Invoke-RestMethod -Uri "https://localhost:8000/records/$RECORD_ID" `
        -Headers @{"Authorization"="Bearer $PATIENT_TOKEN"} -SkipCertificateCheck
    Write-Host "VULNERABLE: Tampered data was decrypted!"
    Write-Host "Data: $($r.data | ConvertTo-Json -Compress)"
} catch {
    Write-Host "BLOCKED: HTTP $($_.Exception.Response.StatusCode.value__)"
    Write-Host "Decryption failed — AES-GCM tag verification detected tampering"
    Write-Host $_.ErrorDetails.Message
}
```

## Expected output

```
=== Step 1: Doctor creates a record ===
Record created: id=<uuid>

=== Step 2: Patient reads the record (before tampering) ===
Data: {"diagnosis":"Hypertension","severity":"Moderate"}

=== Step 3: Tamper with encrypted_data in database ===
[... SQL instructions ...]

=== Step 4: Patient tries to read tampered record ===
BLOCKED: HTTP 500
Decryption failed — AES-GCM tag verification detected tampering
{"detail":"Internal server error"}
```

> **Note:** The 500 error is expected — the decryption failure is caught by
> the global exception handler. In production, this would trigger an alert.

## Automated tests

```powershell
$env:PYTHONPATH = "."
pytest tests/unit/test_attack_scenarios.py::test_aes_gcm_detects_ciphertext_tampering -v
pytest tests/unit/test_attack_scenarios.py::test_aes_gcm_detects_tag_tampering -v
pytest tests/unit/test_crypto.py -v
```
