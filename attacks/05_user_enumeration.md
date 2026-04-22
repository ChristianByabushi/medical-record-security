# Attack 05 — User Enumeration

## What is it?

An attacker tries to discover which email addresses have accounts by comparing
the error messages for "wrong email" vs "wrong password".

## How it works without defense

If the system returns different errors:
- `"User not found"` → email doesn't exist
- `"Invalid password"` → email exists, password is wrong

The attacker can build a list of valid emails to target for brute force.

## Defense implemented

Both cases return **identical** HTTP 401 responses with the message
`"Invalid credentials"` — no distinction between wrong email and wrong password.

**Code:** `app/services/auth_service.py`

```python
# Case 1: email not found
if user is None:
    _verify_password(password, _DUMMY_HASH)  # constant-time delay
    raise HTTPException(status_code=401, detail="Invalid credentials", ...)

# Case 2: wrong password
if not _verify_password(password, user.password_hash):
    raise HTTPException(status_code=401, detail="Invalid credentials", ...)
```

The `_DUMMY_HASH` verification ensures both paths take the same time (prevents timing attacks).

## Demonstration

```powershell
# ── Attempt 1: wrong email (account doesn't exist) ────
Write-Host "=== Attempt 1: wrong email ==="
$h = Get-ReplayHeaders
try {
    Invoke-RestMethod -Method POST -Uri "https://localhost:8000/auth/login" `
        -ContentType "application/json" -Headers $h -SkipCertificateCheck `
        -Body '{"email":"nobody@nowhere.com","password":"DemoPass123!"}'
} catch {
    $wrongEmailCode = $_.Exception.Response.StatusCode.value__
    $wrongEmailMsg  = ($_.ErrorDetails.Message | ConvertFrom-Json).detail
    Write-Host "Status: $wrongEmailCode"
    Write-Host "Message: $wrongEmailMsg"
}

# ── Attempt 2: wrong password (account exists) ────────
Write-Host "`n=== Attempt 2: wrong password ==="
$h = Get-ReplayHeaders
try {
    Invoke-RestMethod -Method POST -Uri "https://localhost:8000/auth/login" `
        -ContentType "application/json" -Headers $h -SkipCertificateCheck `
        -Body '{"email":"patient@demo.com","password":"WrongPassword!"}'
} catch {
    $wrongPwdCode = $_.Exception.Response.StatusCode.value__
    $wrongPwdMsg  = ($_.ErrorDetails.Message | ConvertFrom-Json).detail
    Write-Host "Status: $wrongPwdCode"
    Write-Host "Message: $wrongPwdMsg"
}

# ── Compare responses ──────────────────────────────────
Write-Host "`n=== Comparison ==="
if ($wrongEmailCode -eq $wrongPwdCode -and $wrongEmailMsg -eq $wrongPwdMsg) {
    Write-Host "DEFENSE CONFIRMED: Responses are identical"
    Write-Host "  Status: $wrongEmailCode"
    Write-Host "  Message: $wrongEmailMsg"
    Write-Host "Attacker cannot distinguish valid from invalid emails."
} else {
    Write-Host "VULNERABLE: Responses differ!"
    Write-Host "  Wrong email: $wrongEmailCode - $wrongEmailMsg"
    Write-Host "  Wrong pwd:   $wrongPwdCode - $wrongPwdMsg"
}
```

## Expected output

```
=== Attempt 1: wrong email ===
Status: 401
Message: Invalid credentials

=== Attempt 2: wrong password ===
Status: 401
Message: Invalid credentials

=== Comparison ===
DEFENSE CONFIRMED: Responses are identical
  Status: 401
  Message: Invalid credentials
Attacker cannot distinguish valid from invalid emails.
```

## Automated test

```powershell
$env:PYTHONPATH = "."
pytest tests/unit/test_attack_scenarios.py::test_wrong_email_and_wrong_password_same_error -v
```
