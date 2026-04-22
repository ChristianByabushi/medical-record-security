# Attack 04 — JWT Forgery

## What is it?

An attacker decodes their own JWT (which is base64, not encrypted), modifies
the `role` field from `Patient` to `Doctor` or `SuperAdmin`, and re-signs it
with a guessed or brute-forced key.

## How it works without defense

A JWT has three parts: `header.payload.signature`

The payload is just base64-encoded JSON — anyone can decode and read it:
```json
{"sub": "abc-123", "role": "Patient", "exp": 1745000000}
```

Without signature verification, an attacker could change `"role": "Patient"`
to `"role": "SuperAdmin"` and the server would accept it.

## Defense implemented

The JWT is signed with HMAC-SHA256 using a 32-byte secret key stored only
on the server. Any modification to the payload invalidates the signature.

**Code:** `app/middleware/rbac.py`

```python
payload = jwt.decode(
    token,
    settings.JWT_SECRET_KEY,   # server-side secret — attacker doesn't know this
    algorithms=[settings.JWT_ALGORITHM],
)
```

If the signature doesn't match → `jwt.InvalidTokenError` → HTTP 401.

## Demonstration

```powershell
# ── Step 1: Decode the patient token (no verification) ─
$parts   = $PATIENT_TOKEN.Split(".")
$padding = "=" * ((4 - $parts[1].Length % 4) % 4)
$payload = [System.Text.Encoding]::UTF8.GetString(
    [System.Convert]::FromBase64String($parts[1] + $padding)
)
Write-Host "=== Original JWT payload ==="
Write-Host $payload
# Shows: {"sub":"...","role":"Patient","exp":...}

# ── Step 2: Attacker modifies role and re-signs with wrong key ─
Write-Host "`n=== Attacker forges token with role=SuperAdmin ==="
$forgedPayload = $payload | ConvertFrom-Json
$forgedPayload.role = "SuperAdmin"

# Attacker re-encodes with a GUESSED key (not the real one)
$header  = $parts[0]
$newBody = [System.Convert]::ToBase64String(
    [System.Text.Encoding]::UTF8.GetBytes(($forgedPayload | ConvertTo-Json -Compress))
).TrimEnd("=").Replace("+","-").Replace("/","_")

$fakeKey  = [System.Text.Encoding]::UTF8.GetBytes("attacker-guessed-key")
$hmac     = New-Object System.Security.Cryptography.HMACSHA256
$hmac.Key = $fakeKey
$sigBytes = $hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("$header.$newBody"))
$fakeSig  = [System.Convert]::ToBase64String($sigBytes).TrimEnd("=").Replace("+","-").Replace("/","_")
$FORGED_TOKEN = "$header.$newBody.$fakeSig"

Write-Host "Forged token (first 60 chars): $($FORGED_TOKEN.Substring(0,60))..."

# ── Step 3: Use forged token — must be rejected ────────
Write-Host "`n=== Using forged token on /users/me ==="
try {
    Invoke-RestMethod -Uri "https://localhost:8000/users/me" `
        -Headers @{"Authorization"="Bearer $FORGED_TOKEN"} -SkipCertificateCheck
    Write-Host "VULNERABLE: Forged token was accepted!"
} catch {
    Write-Host "BLOCKED: HTTP $($_.Exception.Response.StatusCode.value__)"
    Write-Host $_.ErrorDetails.Message
}

# ── Step 4: Real token still works ────────────────────
Write-Host "`n=== Real token still works ==="
$me = Invoke-RestMethod -Uri "https://localhost:8000/users/me" `
    -Headers @{"Authorization"="Bearer $PATIENT_TOKEN"} -SkipCertificateCheck
Write-Host "ALLOWED: role=$($me.role), email=$($me.email)"
```

## Expected output

```
=== Original JWT payload ===
{"sub":"abc-123","role":"Patient","exp":1745000000}

=== Attacker forges token with role=SuperAdmin ===
Forged token (first 60 chars): eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMt...

=== Using forged token on /users/me ===
BLOCKED: HTTP 401
{"detail":"Invalid token","error_code":"TOKEN_INVALID"}

=== Real token still works ===
ALLOWED: role=Patient, email=patient@demo.com
```

## Automated tests

```powershell
$env:PYTHONPATH = "."
pytest tests/unit/test_attack_scenarios.py::test_jwt_role_forgery_blocked -v
pytest tests/unit/test_rbac.py::test_wrong_signature_raises_401 -v
pytest tests/unit/test_rbac.py::test_invalid_token_raises_401 -v
```
