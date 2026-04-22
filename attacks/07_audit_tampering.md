# Attack 07 — Audit Log Tampering

## What is it?

An attacker with database access (e.g., a rogue DBA or after a DB breach)
modifies audit log entries to hide their actions — changing who did what,
or deleting incriminating entries.

## How it works without defense

Without integrity protection, an attacker can run:
```sql
UPDATE audit_log SET actor_id = 'innocent-user-uuid' WHERE id = 42;
DELETE FROM audit_log WHERE event_type = 'RECORD_DELETED';
```
And the tampering is undetectable.

## Defense implemented

Every audit entry includes a `chain_hash`:

```
hash_n = SHA256(entry_data_n + hash_{n-1})
```

Each entry's hash depends on its own data AND the previous entry's hash.
Modifying any entry changes its hash, which breaks the chain for all
subsequent entries.

**Code:** `app/services/audit_service.py`

```python
serialized = json.dumps(entry_data, sort_keys=True, separators=(",", ":"))
chain_hash = hashlib.sha256((serialized + prev_hash).encode()).hexdigest()
```

The `/audit/verify` endpoint recomputes all hashes and reports the first mismatch.

## Demonstration

```powershell
# ── Step 1: Verify chain is intact ────────────────────
Write-Host "=== Step 1: Verify chain before tampering ==="
$result = Invoke-RestMethod -Uri "https://localhost:8000/audit/verify" `
    -Headers @{"Authorization"="Bearer $ADMIN_TOKEN"} -SkipCertificateCheck
Write-Host "chain_intact: $($result.chain_intact)"
Write-Host "entries_checked: $($result.entries_checked)"

# ── Step 2: Tamper with an entry in PostgreSQL ─────────
Write-Host "`n=== Step 2: Tamper with audit entry in database ==="
Write-Host "Run this in psql:"
Write-Host ""
Write-Host "  -- See the first few entries"
Write-Host "  SELECT id, event_type, actor_id FROM audit_log ORDER BY id LIMIT 5;"
Write-Host ""
Write-Host "  -- Tamper: change event_type of entry 1"
Write-Host "  UPDATE audit_log SET event_type = 'TAMPERED_BY_ATTACKER' WHERE id = 1;"
Write-Host ""
Write-Host "  -- Confirm the change"
Write-Host "  SELECT id, event_type FROM audit_log WHERE id = 1;"
Write-Host ""
Write-Host "(Press Enter after running the SQL to continue...)"
Read-Host

# ── Step 3: Verify chain detects tampering ────────────
Write-Host "=== Step 3: Verify chain after tampering ==="
$result2 = Invoke-RestMethod -Uri "https://localhost:8000/audit/verify" `
    -Headers @{"Authorization"="Bearer $ADMIN_TOKEN"} -SkipCertificateCheck
Write-Host "chain_intact: $($result2.chain_intact)"
if (-not $result2.chain_intact) {
    Write-Host "TAMPERING DETECTED at entry: $($result2.first_broken_at_id)"
    Write-Host "Tampered event: $($result2.broken_entry_event)"
    Write-Host "Occurred at: $($result2.broken_entry_occurred_at)"
    Write-Host "Actor: $($result2.broken_entry_actor_id)"
    Write-Host "`nAll entries from #$($result2.first_broken_at_id) onward are unreliable."
}
```

## Expected output

```
=== Step 1: Verify chain before tampering ===
chain_intact: True
entries_checked: 15

=== Step 2: Tamper with audit entry in database ===
[... SQL instructions ...]

=== Step 3: Verify chain after tampering ===
chain_intact: False
TAMPERING DETECTED at entry: 1
Tampered event: TAMPERED_BY_ATTACKER
Occurred at: 2026-04-22T10:00:00
Actor: 00000000-0000-0000-0000-000000000000

All entries from #1 onward are unreliable.
```

## Patient can also verify their own entries

```powershell
# Patient verifies their own audit entries
$result = Invoke-RestMethod -Uri "https://localhost:8000/audit/verify" `
    -Headers @{"Authorization"="Bearer $PATIENT_TOKEN"} -SkipCertificateCheck
Write-Host "Patient verify — chain_intact: $($result.chain_intact)"
Write-Host "Entries checked (patient's only): $($result.entries_checked)"
```

## Automated tests

```powershell
$env:PYTHONPATH = "."
pytest tests/unit/test_audit_chain.py -v
pytest tests/unit/test_audit_chain.py::test_tamper_first_entry_detected -v
pytest tests/unit/test_audit_chain.py::test_tamper_middle_entry_detected -v
pytest tests/unit/test_audit_chain.py::test_patient_verify_detects_tampered_own_entry -v
```
