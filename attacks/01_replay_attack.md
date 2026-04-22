# Attack 01 — Replay Attack

## What is it?

An attacker intercepts a valid HTTP request (e.g., a login) and sends it again
later to gain unauthorized access or repeat an action.

## How it works without defense

Without replay protection, the attacker captures:
```
POST /auth/login
Content-Type: application/json
{"email":"patient@demo.com","password":"DemoPass123!"}
```
And replays it seconds or hours later to obtain a fresh token.

## Defense implemented

Every sensitive endpoint requires two extra headers:

| Header | Purpose |
|--------|---------|
| `X-Nonce` | Unique string — stored in DB for 5 minutes, rejected if seen again |
| `X-Timestamp` | ISO-8601 UTC — rejected if more than ±5 minutes from server time |

**Code:** `app/middleware/replay_guard.py`

```python
# Nonce is stored on first use
nonce_entry = NonceStore(nonce=x_nonce, expires_at=now + timedelta(minutes=5))

# Second use of same nonce → 400
if existing is not None:
    raise HTTPException(status_code=400, detail="Nonce already used",
                        headers={"X-Error-Code": "REPLAY_NONCE_SEEN"})
```

## Demonstration

```powershell
# Fix a single nonce (simulates a captured request)
$FIXED_NONCE = "replay-demo-fixed-nonce-001"
$FIXED_TS    = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

$headers = @{
    "Content-Type" = "application/json"
    "X-Nonce"      = $FIXED_NONCE
    "X-Timestamp"  = $FIXED_TS
}
$body = '{"email":"patient@demo.com","password":"DemoPass123!"}'

# ── Request 1: legitimate ──────────────────────────────
Write-Host "=== Request 1 (legitimate) ==="
$r1 = Invoke-RestMethod -Method POST -Uri "https://localhost:8000/auth/login" `
    -Headers $headers -Body $body -SkipCertificateCheck
Write-Host "Status: 200 OK"
Write-Host "Token issued: $($r1.access_token.Substring(0,30))..."

# ── Request 2: replay with same nonce ─────────────────
Write-Host "`n=== Request 2 (REPLAY — same nonce) ==="
try {
    Invoke-RestMethod -Method POST -Uri "https://localhost:8000/auth/login" `
        -Headers $headers -Body $body -SkipCertificateCheck
    Write-Host "VULNERABLE: Replay was not blocked!"
} catch {
    $code = $_.Exception.Response.StatusCode.value__
    $msg  = $_.ErrorDetails.Message
    Write-Host "BLOCKED: HTTP $code"
    Write-Host "Response: $msg"
}
```

## Expected output

```
=== Request 1 (legitimate) ===
Status: 200 OK
Token issued: eyJhbGciOiJIUzI1NiIsInR5cCI6...

=== Request 2 (REPLAY — same nonce) ===
BLOCKED: HTTP 400
Response: {"detail":"Nonce already used","error_code":"REPLAY_NONCE_SEEN"}
```

## Automated test

```powershell
$env:PYTHONPATH = "."
pytest tests/unit/test_attack_scenarios.py::test_replay_attack_nonce_reuse_blocked -v
```
