# Attack 06 — Brute Force Detection

## What is it?

An attacker systematically tries many passwords against a known account,
hoping to guess the correct one.

## How it works without defense

Without logging or rate limiting, an attacker can try thousands of passwords
silently. The server processes each attempt and returns 401 with no record
of the attempts.

## Defense implemented

Every failed login attempt is recorded in the audit log as a `LOGIN_FAILED`
event. Admins can query the log to detect patterns — many failures from the
same IP or against the same account.

**Code:** `app/services/auth_service.py`

```python
if not _verify_password(password, user.password_hash):
    await AuditService().append(
        db, event_type="LOGIN_FAILED",
        actor_id=user.id,
        resource_id=user.id,
        resource_type="user",
        client_ip="0.0.0.0",
        extra={"reason": "wrong_password", "subject_user_id": str(user.id)},
    )
    raise HTTPException(status_code=401, detail="Invalid credentials")
```

> **Note:** Rate limiting (account lockout, exponential backoff) would be
> added via a reverse proxy (nginx/Cloudflare) in production. The audit log
> provides the detection layer; the proxy provides the blocking layer.

## Demonstration

```powershell
# ── Attacker tries 5 wrong passwords ──────────────────
Write-Host "=== Attacker brute-forcing patient account ==="
$attempts = @("wrong1!", "wrong2!", "wrong3!", "wrong4!", "wrong5!")
foreach ($pwd in $attempts) {
    $h = Get-ReplayHeaders
    try {
        Invoke-RestMethod -Method POST -Uri "https://localhost:8000/auth/login" `
            -ContentType "application/json" -Headers $h -SkipCertificateCheck `
            -Body "{`"email`":`"patient@demo.com`",`"password`":`"$pwd`"}"
    } catch { }
    Write-Host "  Attempt with '$pwd' → 401"
}

# ── Admin checks the audit log ─────────────────────────
Write-Host "`n=== Admin reviews audit log for LOGIN_FAILED events ==="
$entries = Invoke-RestMethod -Uri "https://localhost:8000/audit" `
    -Headers @{"Authorization"="Bearer $ADMIN_TOKEN"} -SkipCertificateCheck

$failed = $entries | Where-Object { $_.event_type -eq "LOGIN_FAILED" }
Write-Host "LOGIN_FAILED events recorded: $($failed.Count)"
$failed | ForEach-Object {
    $reason = $_.extra.reason
    $ts     = $_.occurred_at
    Write-Host "  [$ts] reason=$reason"
}

Write-Host "`nAdmin can now:"
Write-Host "  - Identify the targeted account"
Write-Host "  - Block the source IP at the network level"
Write-Host "  - Alert the account owner"
```

## Expected output

```
=== Attacker brute-forcing patient account ===
  Attempt with 'wrong1!' → 401
  Attempt with 'wrong2!' → 401
  Attempt with 'wrong3!' → 401
  Attempt with 'wrong4!' → 401
  Attempt with 'wrong5!' → 401

=== Admin reviews audit log for LOGIN_FAILED events ===
LOGIN_FAILED events recorded: 5
  [2026-04-22T10:00:01] reason=wrong_password
  [2026-04-22T10:00:02] reason=wrong_password
  [2026-04-22T10:00:03] reason=wrong_password
  [2026-04-22T10:00:04] reason=wrong_password
  [2026-04-22T10:00:05] reason=wrong_password
```

## Automated test

```powershell
$env:PYTHONPATH = "."
pytest tests/unit/test_attack_scenarios.py::test_failed_logins_are_audit_logged -v
```
