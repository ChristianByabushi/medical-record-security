# Manual Test Plan — Secure Medical Records API

## Setup

**Base URL:** `https://localhost:8000`
**SSL verification:** OFF in Postman (Settings → General → SSL certificate verification → OFF)
**Environment:** `Test_Med_Records` (already created)

---

## Collection-Level Pre-request Script
Right-click `My Collection` → Edit → Scripts → Pre-req tab:
```javascript
pm.request.headers.add({ key: 'X-Nonce', value: pm.variables.replaceIn('{{$guid}}') });
pm.request.headers.add({ key: 'X-Timestamp', value: new Date().toISOString() });
```
This runs automatically on every request. Safe to have globally — ignored by endpoints that don't check replay headers.

---

## F1 — Health Check

### F1.1 Server is running
- Method: GET
- URL: `https://localhost:8000/health`
- Auth: none
- Pre-req: none
- Post-res: none
- Expected: `200` → `{"status": "ok", "timestamp": "..."}`

---

## F2 — Registration

### F2.1 Register Patient
- Method: POST
- URL: `https://localhost:8000/auth/register`
- Body (raw JSON):
```json
{"email": "patient@test.com", "password": "SecurePass123!", "role": "Patient"}
```
- Pre-req: none needed
- Post-res: none
- Expected: `201` → `{id, email, role: "Patient", mfa_enabled: false}`

### F2.2 Register Doctor
- Method: POST
- URL: `https://localhost:8000/auth/register`
- Body:
```json
{"email": "doctor@test.com", "password": "SecurePass123!", "role": "Doctor"}
```
- Expected: `201`

### F2.3 Register Nurse
- Body: `{"email": "nurse@test.com", "password": "SecurePass123!", "role": "Nurse"}`
- Expected: `201`

### F2.4 Register Lab Technician
- Body: `{"email": "lab@test.com", "password": "SecurePass123!", "role": "Lab_Technician"}`
- Expected: `201`

### F2.5 Duplicate email rejected
- Same body as F2.1
- Expected: `409` → `{"error_code": "EMAIL_ALREADY_EXISTS"}`

### F2.6 Short password rejected
- Body: `{"email": "x@test.com", "password": "short", "role": "Patient"}`
- Expected: `422`

### F2.7 Invalid role rejected
- Body: `{"email": "x@test.com", "password": "SecurePass123!", "role": "Admin"}`
- Expected: `422`

---

## F3 — Login & Token Issuance

> Replay headers are injected automatically by the collection pre-request script.

### F3.1 Login Patient
- Method: POST
- URL: `https://localhost:8000/auth/login`
- Body:
```json
{"email": "patient@test.com", "password": "SecurePass123!"}
```
- Pre-req: (collection script handles it)
- Post-res tab:
```javascript
var r = pm.response.json();
pm.collectionVariables.set("patient_token", r.access_token);
pm.collectionVariables.set("patient_refresh", r.refresh_token);
```
- Expected: `200` → `{access_token, refresh_token, expires_in: 900}`

### F3.2 Login Doctor
- Same as F3.1 with doctor credentials
- Post-res tab:
```javascript
var r = pm.response.json();
pm.collectionVariables.set("doctor_token", r.access_token);
pm.collectionVariables.set("doctor_refresh", r.refresh_token);
```
- Expected: `200`

### F3.3 Login Nurse
- Post-res tab:
```javascript
var r = pm.response.json();
pm.collectionVariables.set("nurse_token", r.access_token);
pm.collectionVariables.set("nurse_refresh", r.refresh_token);
```
- Expected: `200`

### F3.4 Login Lab Tech
- Post-res tab:
```javascript
var r = pm.response.json();
pm.collectionVariables.set("lab_token", r.access_token);
```
- Expected: `200`

### F3.5 Wrong password rejected
- Body: `{"email": "patient@test.com", "password": "WrongPassword!"}`
- Expected: `401` → `{"detail": "Invalid credentials"}`

### F3.6 Non-existent email — same response as wrong password
- Body: `{"email": "nobody@test.com", "password": "SecurePass123!"}`
- Expected: `401` → same message as F3.5 (no email enumeration)

### F3.7 Replay attack — reuse same nonce
- Send F3.1 twice with the same `X-Nonce` header value (manually set a fixed nonce in Headers tab)
- Expected: second request returns `400` → `REPLAY_NONCE_SEEN`

### F3.8 Old timestamp rejected
- Add header manually: `X-Timestamp: 2020-01-01T00:00:00Z`
- Expected: `400` → `REPLAY_TIMESTAMP_SKEW`

---

## F4 — Token Refresh

### F4.1 Valid refresh token rotates
- Method: POST
- URL: `https://localhost:8000/auth/token/refresh`
- Body:
```json
{"refresh_token": "{{patient_refresh}}"}
```
- Pre-req: none
- Post-res tab:
```javascript
var r = pm.response.json();
pm.collectionVariables.set("patient_token", r.access_token);
pm.collectionVariables.set("patient_refresh", r.refresh_token);
```
- Expected: `200` → new `access_token` and new `refresh_token`

### F4.2 Old refresh token rejected after rotation
- Use the OLD `patient_refresh` value (before F4.1 ran)
- Body: `{"refresh_token": "<old_token>"}`
- Expected: `401`

### F4.3 Invalid token rejected
- Body: `{"refresh_token": "fakeinvalidtoken"}`
- Expected: `401`

---

## F5 — User Profile

### F5.1 Get own profile (Patient)
- Method: GET
- URL: `https://localhost:8000/users/me`
- Authorization tab → Bearer Token → `{{patient_token}}`
- Pre-req: none
- Post-res tab:
```javascript
var r = pm.response.json();
pm.collectionVariables.set("patient_id", r.id);
```
- Expected: `200` → `{id, email, role: "Patient"}`

### F5.2 Get own profile (Doctor)
- Same as F5.1 with `{{doctor_token}}`
- Post-res tab:
```javascript
pm.collectionVariables.set("doctor_id", pm.response.json().id);
```
- Expected: `200`

### F5.3 No token rejected
- GET `/users/me` with no Authorization header
- Expected: `401`


### F5.4 Patient updates own email
- Method: PATCH
- URL: `https://localhost:8000/users/me`
- Authorization: Bearer `{{patient_token}}`
- Body: `{"email": "patient_updated@test.com"}`
- Pre-req: none
- Post-res: none
- Expected: `200` → updated email in response

### F5.5 Doctor cannot use PATCH /users/me
- Same as F5.4 but Authorization: Bearer `{{doctor_token}}`
- Expected: `403`

---

## F6 — Consent Management

### F6.1 Doctor requests consent
- Method: POST
- URL: `https://localhost:8000/consent`
- Authorization: Bearer `{{doctor_token}}`
- Body:
```json
{"patient_id": "{{patient_id}}", "duration_days": 1}
```
- Pre-req: none
- Post-res tab:
```javascript
pm.collectionVariables.set("grant_id", pm.response.json().id);
```
- Expected: `201` → `{status: "pending"}`

### F6.2 Patient cannot request consent
- Same as F6.1 but Authorization: Bearer `{{patient_token}}`
- Expected: `403`

### F6.3 Patient lists grants
- Method: GET
- URL: `https://localhost:8000/consent`
- Authorization: Bearer `{{patient_token}}`
- Pre-req: none
- Post-res: none
- Expected: `200` → array containing the pending grant from F6.1

### F6.4 Doctor cannot list grants
- Same as F6.3 but Authorization: Bearer `{{doctor_token}}`
- Expected: `403`

### F6.5 Patient approves consent
- Method: POST
- URL: `https://localhost:8000/consent/{{grant_id}}/approve`
- Authorization: Bearer `{{patient_token}}`
- Body: none
- Pre-req: none
- Post-res: none
- Expected: `200` → `{status: "active", expires_at: <timestamp>}`

### F6.6 Patient rejects a consent
- First create a new grant (repeat F6.1 — saves new `grant_id`)
- Method: POST
- URL: `https://localhost:8000/consent/{{grant_id}}/reject`
- Authorization: Bearer `{{patient_token}}`
- Expected: `200` → `{status: "rejected"}`

### F6.7 Patient revokes active consent
- Re-approve a grant first (F6.1 + F6.5)
- Method: POST
- URL: `https://localhost:8000/consent/{{grant_id}}/revoke`
- Authorization: Bearer `{{patient_token}}`
- Expected: `200` → `{status: "revoked"}`

> NOTE: After F6.7, create and approve a fresh grant before running F7.

---


## F7 — Medical Records

> Prerequisite: active consent grant must exist between doctor and patient.
> Run F6.1 + F6.5 to create one before starting F7.

### F7.1 Doctor creates a record
- Method: POST
- URL: `https://localhost:8000/records`
- Authorization: Bearer `{{doctor_token}}`
- Body:
```json
{
  "patient_id": "{{patient_id}}",
  "record_type": "diagnosis",
  "data": {"diagnosis": "Hypertension", "notes": "Elevated BP", "bp": "140/90"}
}
```
- Pre-req: (collection script handles replay headers)
- Post-res tab:
```javascript
pm.collectionVariables.set("record_id", pm.response.json().id);
```
- Expected: `201` → `{id, patient_id, record_type}` (no `data` field — by design)

### F7.2 Doctor reads the record (decrypted)
- Method: GET
- URL: `https://localhost:8000/records/{{record_id}}`
- Authorization: Bearer `{{doctor_token}}`
- Pre-req: none
- Post-res: none
- Expected: `200` → `{data: {diagnosis: "Hypertension", ...}}`

### F7.3 Patient reads own record
- Same as F7.2 but Authorization: Bearer `{{patient_token}}`
- Expected: `200` → same decrypted data

### F7.4 Patient lists own records
- Method: GET
- URL: `https://localhost:8000/records?patient_id={{patient_id}}`
- Authorization: Bearer `{{patient_token}}`
- Expected: `200` → array with at least one record

### F7.5 Doctor without consent cannot read record
- Revoke consent (F6.7), then:
- GET `https://localhost:8000/records/{{record_id}}`
- Authorization: Bearer `{{doctor_token}}`
- Expected: `403`
- Re-approve consent after this test.

### F7.6 Doctor updates a record
- Method: PATCH
- URL: `https://localhost:8000/records/{{record_id}}`
- Authorization: Bearer `{{doctor_token}}`
- Body: `{"data": {"diagnosis": "Hypertension Stage 2", "notes": "Updated after follow-up"}}`
- Pre-req: (collection script handles replay headers)
- Post-res: none
- Expected: `200` → updated `data`

### F7.7 Read back confirms update
- GET `https://localhost:8000/records/{{record_id}}`
- Authorization: Bearer `{{doctor_token}}`
- Expected: `data.diagnosis` = "Hypertension Stage 2"

### F7.8 Nurse cannot update record
- PATCH `https://localhost:8000/records/{{record_id}}`
- Authorization: Bearer `{{nurse_token}}`
- Expected: `403`

### F7.9 Lab Tech creates a lab result
- Method: POST
- URL: `https://localhost:8000/records`
- Authorization: Bearer `{{lab_token}}`
- Body:
```json
{
  "patient_id": "{{patient_id}}",
  "record_type": "lab_result",
  "data": {"test": "Blood glucose", "result": "5.4 mmol/L", "status": "normal"}
}
```
- Pre-req: (collection script handles replay headers)
- Expected: `201`

### F7.10 Doctor soft-deletes a record
- Method: DELETE
- URL: `https://localhost:8000/records/{{record_id}}`
- Authorization: Bearer `{{doctor_token}}`
- Pre-req: (collection script handles replay headers)
- Post-res: none
- Expected: `200` → `{"message": "Record soft-deleted."}`

### F7.11 Deleted record returns 404
- GET `https://localhost:8000/records/{{record_id}}`
- Authorization: Bearer `{{doctor_token}}`
- Expected: `404`

### F7.12 Non-existent record returns 404
- GET `https://localhost:8000/records/00000000-0000-0000-0000-000000000000`
- Authorization: Bearer `{{patient_token}}`
- Expected: `404`

---

## F8 — MFA

### F8.1 Enroll MFA
- Method: POST
- URL: `https://localhost:8000/auth/mfa/enroll`
- Authorization: Bearer `{{nurse_token}}`
- Pre-req: none
- Post-res tab:
```javascript
pm.collectionVariables.set("mfa_secret", pm.response.json().secret);
```
- Expected: `200` → `{provisioning_uri, secret}`

### F8.2 Confirm MFA enrollment
- Generate a TOTP code from the secret:
```bash
python -c "import pyotp; print(pyotp.TOTP('YOUR_SECRET').now())"
```
- Method: POST
- URL: `https://localhost:8000/auth/mfa/confirm`
- Authorization: Bearer `{{nurse_token}}`
- Body: `{"totp_code": "<6-digit code>"}`
- Pre-req: none
- Post-res: none
- Expected: `200` → `{"mfa_enabled": true}`

### F8.3 Login with MFA returns partial token
- Method: POST
- URL: `https://localhost:8000/auth/login`
- Body: `{"email": "nurse@test.com", "password": "SecurePass123!"}`
- Pre-req: (collection script handles replay headers)
- Post-res tab:
```javascript
pm.collectionVariables.set("partial_token", pm.response.json().partial_token);
```
- Expected: `200` → `{partial_token, mfa_required: true}` (NOT a full token pair)

### F8.4 Partial token rejected on protected endpoints
- GET `https://localhost:8000/users/me`
- Authorization: Bearer `{{partial_token}}`
- Expected: `401`

### F8.5 Complete MFA login
- Generate fresh TOTP code (same command as F8.2)
- Method: POST
- URL: `https://localhost:8000/auth/mfa/verify`
- Body:
```json
{"partial_token": "{{partial_token}}", "totp_code": "<current code>"}
```
- Pre-req: (collection script handles replay headers)
- Post-res tab:
```javascript
var r = pm.response.json();
pm.collectionVariables.set("nurse_token", r.access_token);
pm.collectionVariables.set("nurse_refresh", r.refresh_token);
```
- Expected: `200` → full `{access_token, refresh_token}`

### F8.6 Wrong TOTP code rejected
- Same as F8.5 but `"totp_code": "000000"`
- Expected: `401`

---

## F9 — Password Reset

### F9.1 Request reset
- Method: POST
- URL: `https://localhost:8000/auth/password-reset/request`
- Body: `{"email": "nurse@test.com"}`
- Pre-req: (collection script handles replay headers)
- Post-res tab:
```javascript
// Copy dev_token from response manually into collection variable
var r = pm.response.json();
if (r.dev_token) {
    var token = r.dev_token.replace(" [DEV ONLY - remove in production]", "");
    pm.collectionVariables.set("reset_token", token);
}
```
- Expected: `200` → `{message, dev_token: "<token> [DEV ONLY...]"}`

### F9.2 Non-existent email — same response
- Body: `{"email": "nobody@nowhere.com"}`
- Expected: `200` → same generic message (no leak)

### F9.3 Complete password reset
- Method: POST
- URL: `https://localhost:8000/auth/password-reset/complete`
- Body:
```json
{
  "token": "{{reset_token}}",
  "new_password": "NewSecurePass456!",
  "totp_code": null
}
```
- Pre-req: (collection script handles replay headers)
- Post-res: none
- Expected: `200` → `{"message": "Password updated. All sessions have been revoked."}`

### F9.4 Old refresh token revoked after reset
- Method: POST
- URL: `https://localhost:8000/auth/token/refresh`
- Body: `{"refresh_token": "{{nurse_refresh}}"}`
- Expected: `401`

### F9.5 Login with new password works
- POST `/auth/login` with `"password": "NewSecurePass456!"`
- Expected: `200` → new token pair

### F9.6 Used reset token rejected
- Repeat F9.3 with same `{{reset_token}}`
- Expected: `400` → `TOKEN_EXPIRED_OR_USED`

---

## F10 — Audit Log

### F10.1 List audit entries
- Method: GET
- URL: `https://localhost:8000/audit`
- Authorization: Bearer `{{patient_token}}`
- Pre-req: none
- Post-res: none
- Expected: `200` → array of audit entries

### F10.2 Filter by actor
- URL: `https://localhost:8000/audit?actor_id={{patient_id}}`
- Authorization: Bearer `{{patient_token}}`
- Expected: `200` → only entries where patient was the actor

### F10.3 Verify chain integrity
- Method: GET
- URL: `https://localhost:8000/audit/verify`
- Authorization: Bearer `{{patient_token}}`
- Pre-req: none
- Post-res: none
- Expected: `200` → `{"chain_intact": true, "entries_checked": N}`

### F10.4 No auth rejected
- GET `https://localhost:8000/audit/verify` with no token
- Expected: `401`

---

## Open Questions

1. **Nurse consent**: Nurses use the same consent check as Doctors. Does a Nurse need a formal consent grant, or should they be assigned to patients differently?
2. **Record create response**: POST /records returns no `data` field. Frontend must GET the record to read content — is this acceptable?
3. **Patient notifications**: No push/email when a doctor requests consent. Frontend must poll GET /consent to see pending requests.
4. **Lab Tech scope**: Lab Techs can only read records they created — not diagnosis records from Doctors. Confirm this is correct.
