# Attack 02 — Stale Timestamp

## What is it?

A variant of the replay attack where the attacker replays a request with an
old timestamp — for example, a request captured yesterday or from a log file.

## How it works without defense

If only the nonce is checked (not the timestamp), an attacker could:
1. Capture a request with a unique nonce
2. Wait until the nonce expires (>5 min)
3. Replay the request with the old timestamp — the nonce is now "fresh" again

## Defense implemented

The timestamp must be within **±5 minutes** of the server's current time.
This limits the replay window to 10 minutes maximum, even if the nonce expires.

**Code:** `app/middleware/replay_guard.py`

```python
skew = abs((now - ts).total_seconds())
if skew > 300:  # 300 seconds = 5 minutes
    raise HTTPException(
        status_code=400,
        detail="Timestamp outside acceptable window",
        headers={"X-Error-Code": "REPLAY_TIMESTAMP_SKEW"},
    )
```

## Demonstration

```powershell
# ── Scenario A: timestamp from 2020 (clearly old) ─────
Write-Host "=== Scenario A: 6-year-old timestamp ==="
$headers = @{
    "Content-Type" = "application/json"
    "X-Nonce"      = [System.Guid]::NewGuid().ToString()
    "X-Timestamp"  = "2020-01-01T00:00:00Z"
}
try {
    Invoke-RestMethod -Method POST -Uri "https://localhost:8000/auth/login" `
        -Headers $headers -Body '{"email":"patient@demo.com","password":"DemoPass123!"}' `
        -SkipCertificateCheck
    Write-Host "VULNERABLE: Old timestamp accepted!"
} catch {
    Write-Host "BLOCKED: HTTP $($_.Exception.Response.StatusCode.value__)"
    Write-Host $_.ErrorDetails.Message
}

# ── Scenario B: timestamp 10 minutes in the future ────
Write-Host "`n=== Scenario B: timestamp 10 minutes ahead ==="
$futureTS = (Get-Date).AddMinutes(10).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$headers["X-Nonce"]     = [System.Guid]::NewGuid().ToString()
$headers["X-Timestamp"] = $futureTS
try {
    Invoke-RestMethod -Method POST -Uri "https://localhost:8000/auth/login" `
        -Headers $headers -Body '{"email":"patient@demo.com","password":"DemoPass123!"}' `
        -SkipCertificateCheck
    Write-Host "VULNERABLE: Future timestamp accepted!"
} catch {
    Write-Host "BLOCKED: HTTP $($_.Exception.Response.StatusCode.value__)"
    Write-Host $_.ErrorDetails.Message
}

# ── Scenario C: valid timestamp (within 5 min) ────────
Write-Host "`n=== Scenario C: valid timestamp (now) ==="
$headers["X-Nonce"]     = [System.Guid]::NewGuid().ToString()
$headers["X-Timestamp"] = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$r = Invoke-RestMethod -Method POST -Uri "https://localhost:8000/auth/login" `
    -Headers $headers -Body '{"email":"patient@demo.com","password":"DemoPass123!"}' `
    -SkipCertificateCheck
Write-Host "ALLOWED: HTTP 200 — token issued"
```

## Expected output

```
=== Scenario A: 6-year-old timestamp ===
BLOCKED: HTTP 400
{"detail":"Timestamp outside acceptable window","error_code":"REPLAY_TIMESTAMP_SKEW"}

=== Scenario B: timestamp 10 minutes ahead ===
BLOCKED: HTTP 400
{"detail":"Timestamp outside acceptable window","error_code":"REPLAY_TIMESTAMP_SKEW"}

=== Scenario C: valid timestamp (now) ===
ALLOWED: HTTP 200 — token issued
```

## Automated test

```powershell
$env:PYTHONPATH = "."
pytest tests/unit/test_attack_scenarios.py::test_replay_attack_old_nonce_allowed -v
```
