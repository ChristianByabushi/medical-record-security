# Design Document: Secure Medical Records Backend

## Overview

The Secure Patient Medical Records System is a RESTful API backend built for Rwandan healthcare institutions. It provides authenticated, role-gated, consent-controlled access to encrypted patient medical records, with a tamper-evident audit trail on every sensitive operation.

### Technology Stack

| Layer | Technology |
|---|---|
| API Framework | Python 3.11 + FastAPI |
| Database | PostgreSQL 15 |
| ORM / Migrations | SQLAlchemy 2.x (async) + Alembic |
| Authentication | JWT (PyJWT), bcrypt (passlib), TOTP (pyotp) |
| Encryption | AES-256-GCM (cryptography library) |
| Transport | HTTPS with self-signed TLS (local dev) |
| Config | python-dotenv, Pydantic Settings |

### Design Goals

1. **Defence in depth** — every layer (transport, auth, RBAC, encryption, audit) independently enforces security.
2. **Zero trust on data at rest** — sensitive fields are encrypted before hitting the database; a DB dump reveals no plaintext PHI.
3. **Non-repudiation** — every sensitive action is recorded in a hash-chained, append-only audit log.
4. **Least privilege** — roles carry the minimum permissions needed; consent gates cross-role access.
5. **No hardcoded secrets** — all keys and credentials come from environment variables validated at startup.

---

## Architecture

### Layer Diagram

```
+-----------------------------------------------------------------+
¦                        HTTPS (TLS 1.2+)                         ¦
¦                    (self-signed cert, local)                     ¦
+-----------------------------------------------------------------+
                            ¦
+---------------------------?-------------------------------------+
¦                      FastAPI Application                         ¦
¦  +--------------+  +--------------+  +------------------------+ ¦
¦  ¦ Replay_Guard ¦  ¦RBAC_Middleware¦  ¦   Request Validation   ¦ ¦
¦  ¦  (nonce +    ¦  ¦ (JWT verify + ¦  ¦   (Pydantic schemas)   ¦ ¦
¦  ¦  timestamp)  ¦  ¦  role check)  ¦  ¦                        ¦ ¦
¦  +--------------+  +--------------+  +------------------------+ ¦
¦         ¦                 ¦                      ¦               ¦
¦  +------?-----------------?----------------------?------------+ ¦
¦  ¦                    Route Handlers                           ¦ ¦
¦  ¦  /auth  ¦  /users  ¦  /consent  ¦  /records  ¦  /audit     ¦ ¦
¦  +------------------------------------------------------------+ ¦
¦         ¦                                              ¦         ¦
¦  +------?----------------------------------------------?------+ ¦
¦  ¦                    Service Layer                            ¦ ¦
¦  ¦  Auth_Module ¦ Consent_Module ¦ Records_Module ¦ Audit_Module¦ ¦
¦  +------------------------------------------------------------+ ¦
¦         ¦                                              ¦         ¦
¦  +------?----------------------------------------------?------+ ¦
¦  ¦              Key_Manager  (singleton, startup-validated)    ¦ ¦
¦  +------------------------------------------------------------+ ¦
+---------+----------------------------------------------+--------+
          ¦                                              ¦
+---------?----------------------------------------------?--------+
¦                     PostgreSQL Database                          ¦
¦  users ¦ refresh_tokens ¦ mfa_secrets ¦ password_reset_tokens   ¦
¦  consent_grants ¦ medical_records ¦ audit_log ¦ nonce_store      ¦
+-----------------------------------------------------------------+
```

### Trust Boundaries

| Boundary | Enforcement |
|---|---|
| Internet ? API | TLS termination; all plaintext HTTP rejected |
| Request ? Handler | Replay_Guard (nonce + timestamp) on sensitive endpoints |
| Handler ? Business Logic | RBAC_Middleware (JWT signature + role check) |
| Business Logic ? DB | SQLAlchemy parameterised queries (no raw SQL); field-level AES-256-GCM encryption on PHI columns |
| DB ? Disk | PostgreSQL at-rest encryption (OS/volume level, out of scope) |

### Module Interaction Summary

```
Client
  ¦
  +-? Replay_Guard.validate(nonce, timestamp)          [sensitive endpoints only]
  ¦
  +-? RBAC_Middleware.authenticate(bearer_token)
  ¦       +-? JWT.decode() ? {user_id, role}
  ¦
  +-? Route Handler
  ¦       +-? Auth_Module      (registration, login, MFA, refresh, password reset)
  ¦       +-? Consent_Module   (request, approve, reject, revoke, list)
  ¦       +-? Records_Module   (CRUD)
  ¦       ¦       +-? Key_Manager.get_key() ? AES key
  ¦       +-? Audit_Module.append(event)               [called by every module]
  ¦
  +-? Response
```

---

## Components and Interfaces

### Auth_Module

Responsibilities: user registration, login, JWT issuance, TOTP enrollment/verification, token refresh, password reset.

```python
class AuthService:
    def register(email: str, password: str, role: Role) -> UserOut
    def login(email: str, password: str) -> LoginResult          # LoginResult is full tokens OR partial-auth token
    def verify_totp(partial_token: str, totp_code: str) -> TokenPair
    def refresh_tokens(refresh_token: str) -> TokenPair
    def enroll_mfa(user_id: UUID) -> MFAEnrollmentOut            # returns provisioning URI
    def confirm_mfa(user_id: UUID, totp_code: str) -> None
    def request_password_reset(email: str) -> PasswordResetOut   # dev mode returns token
    def complete_password_reset(token: str, new_password: str, totp_code: str | None) -> None
```

### RBAC_Middleware

FastAPI dependency injected into every protected route. Decodes and validates the JWT, extracts `user_id` and `role`, and checks the role against the endpoint's allowed-roles set. For record-access endpoints it additionally calls `ConsentService.check_active_grant()`.

```python
def require_roles(*roles: Role) -> Callable:
    """Returns a FastAPI dependency that enforces role membership."""

def get_current_user(token: str = Depends(oauth2_scheme)) -> TokenClaims:
    """Decodes JWT, raises HTTP 401/403 on failure."""
```

### Consent_Module

```python
class ConsentService:
    def request_consent(doctor_id: UUID, patient_id: UUID, duration_days: int) -> ConsentGrant
    def approve_consent(patient_id: UUID, grant_id: UUID) -> ConsentGrant
    def reject_consent(patient_id: UUID, grant_id: UUID) -> ConsentGrant
    def revoke_consent(patient_id: UUID, grant_id: UUID) -> ConsentGrant
    def list_grants(patient_id: UUID) -> list[ConsentGrant]
    def check_active_grant(doctor_id: UUID, patient_id: UUID) -> bool
```

### Records_Module

```python
class RecordsService:
    def create_record(actor: TokenClaims, patient_id: UUID, data: RecordIn) -> RecordOut
    def get_record(actor: TokenClaims, record_id: UUID) -> RecordOut
    def update_record(actor: TokenClaims, record_id: UUID, data: RecordUpdate) -> RecordOut
    def delete_record(actor: TokenClaims, record_id: UUID) -> None          # soft delete
    def list_records(actor: TokenClaims, patient_id: UUID) -> list[RecordOut]
```

All sensitive fields are encrypted via `Key_Manager` before persistence and decrypted on retrieval.

### Audit_Module

```python
class AuditService:
    def append(event_type: AuditEvent, actor_id: UUID, resource_id: UUID,
               client_ip: str, extra: dict | None = None) -> AuditEntry
    def verify_chain() -> ChainVerificationResult
    def list_entries(filters: AuditFilter) -> list[AuditEntry]
```

`append()` is called inside a database transaction alongside the triggering operation so that the audit entry and the business-logic change are committed atomically.

### Replay_Guard

Implemented as a FastAPI dependency applied to sensitive endpoints.

```python
class ReplayGuard:
    def validate(nonce: str = Header(...), x_timestamp: str = Header(...)) -> None:
        """
        1. Parse x_timestamp as ISO-8601 UTC.
        2. Reject if |now - timestamp| > 5 minutes.
        3. Check nonce_store for nonce; reject HTTP 400 if found.
        4. Insert nonce with TTL = 5 minutes.
        """
```

Nonce storage uses the `nonce_store` table with a `expires_at` column; a background task (or DB-level TTL via pg_cron) purges expired rows.

### Key_Manager

Singleton loaded at application startup.

```python
class KeyManager:
    _record_key: bytes      # 32 bytes, AES-256
    _totp_key: bytes        # 32 bytes, for encrypting TOTP secrets

    @classmethod
    def from_env(cls) -> "KeyManager":
        """Reads RECORD_ENCRYPTION_KEY and TOTP_ENCRYPTION_KEY from env.
           Raises RuntimeError with descriptive message if absent or wrong length."""

    def get_record_key(self) -> bytes: ...
    def get_totp_key(self) -> bytes: ...
```

---

## Data Models

### Entity-Relationship Overview

```
users --< refresh_tokens
users --< mfa_secrets (0..1)
users --< password_reset_tokens
users (patient) --< medical_records
users (doctor)  --< consent_grants (as requester)
users (patient) --< consent_grants (as subject)
medical_records --< audit_log (as target)
users           --< audit_log (as actor)
```

### Table Definitions

#### `users`

| Column | Type | Constraints |
|---|---|---|
| id | UUID | PK, default gen_random_uuid() |
| email | VARCHAR(255) | UNIQUE, NOT NULL |
| password_hash | VARCHAR(72) | NOT NULL (bcrypt output) |
| role | VARCHAR(20) | NOT NULL, CHECK IN ('Patient','Doctor','Nurse','Lab_Technician') |
| is_active | BOOLEAN | NOT NULL, DEFAULT TRUE |
| mfa_enabled | BOOLEAN | NOT NULL, DEFAULT FALSE |
| created_at | TIMESTAMPTZ | NOT NULL, DEFAULT now() |
| updated_at | TIMESTAMPTZ | NOT NULL, DEFAULT now() |

Indexes: `idx_users_email` (UNIQUE), `idx_users_role`.

#### `mfa_secrets`

| Column | Type | Constraints |
|---|---|---|
| id | UUID | PK |
| user_id | UUID | FK ? users.id, UNIQUE, NOT NULL |
| encrypted_secret | BYTEA | NOT NULL (AES-256-GCM ciphertext) |
| iv | BYTEA | NOT NULL (12-byte GCM nonce) |
| tag | BYTEA | NOT NULL (16-byte GCM auth tag) |
| created_at | TIMESTAMPTZ | NOT NULL, DEFAULT now() |

#### `refresh_tokens`

| Column | Type | Constraints |
|---|---|---|
| id | UUID | PK |
| user_id | UUID | FK ? users.id, NOT NULL |
| token_hash | VARCHAR(64) | NOT NULL (SHA-256 hex of raw token) |
| expires_at | TIMESTAMPTZ | NOT NULL |
| revoked | BOOLEAN | NOT NULL, DEFAULT FALSE |
| created_at | TIMESTAMPTZ | NOT NULL, DEFAULT now() |

Indexes: `idx_refresh_tokens_user_id`, `idx_refresh_tokens_token_hash` (UNIQUE).

The raw refresh token is a 256-bit random value encoded as a URL-safe base64 string. Only its SHA-256 hash is stored.

#### `password_reset_tokens`

| Column | Type | Constraints |
|---|---|---|
| id | UUID | PK |
| user_id | UUID | FK ? users.id, NOT NULL |
| token_hash | VARCHAR(64) | NOT NULL (SHA-256 hex) |
| expires_at | TIMESTAMPTZ | NOT NULL |
| used | BOOLEAN | NOT NULL, DEFAULT FALSE |
| created_at | TIMESTAMPTZ | NOT NULL, DEFAULT now() |

Indexes: `idx_prt_token_hash` (UNIQUE), `idx_prt_user_id`.

#### `consent_grants`

| Column | Type | Constraints |
|---|---|---|
| id | UUID | PK |
| doctor_id | UUID | FK ? users.id, NOT NULL |
| patient_id | UUID | FK ? users.id, NOT NULL |
| status | VARCHAR(10) | NOT NULL, CHECK IN ('pending','active','rejected','revoked','expired') |
| requested_duration_days | INTEGER | NOT NULL |
| expires_at | TIMESTAMPTZ | NULL (set on approval) |
| created_at | TIMESTAMPTZ | NOT NULL, DEFAULT now() |
| updated_at | TIMESTAMPTZ | NOT NULL, DEFAULT now() |

Indexes: `idx_cg_doctor_patient` (doctor_id, patient_id), `idx_cg_patient_status` (patient_id, status).

#### `medical_records`

| Column | Type | Constraints |
|---|---|---|
| id | UUID | PK |
| patient_id | UUID | FK ? users.id, NOT NULL |
| record_type | VARCHAR(50) | NOT NULL (e.g. 'lab_result', 'diagnosis', 'prescription') |
| created_by | UUID | FK ? users.id, NOT NULL |
| encrypted_data | BYTEA | NOT NULL (AES-256-GCM ciphertext of JSON payload) |
| iv | BYTEA | NOT NULL (12-byte GCM nonce) |
| tag | BYTEA | NOT NULL (16-byte GCM auth tag) |
| is_deleted | BOOLEAN | NOT NULL, DEFAULT FALSE |
| created_at | TIMESTAMPTZ | NOT NULL, DEFAULT now() |
| updated_at | TIMESTAMPTZ | NOT NULL, DEFAULT now() |

Indexes: `idx_mr_patient_id`, `idx_mr_created_by`, `idx_mr_record_type`.

The entire record payload (diagnosis, notes, lab values, etc.) is serialised to JSON and encrypted as a single blob. This avoids partial-encryption mistakes and simplifies the encryption boundary.

#### `audit_log`

| Column | Type | Constraints |
|---|---|---|
| id | BIGSERIAL | PK (sequential for ordering) |
| event_type | VARCHAR(30) | NOT NULL |
| actor_id | UUID | FK ? users.id, NOT NULL |
| resource_id | UUID | NOT NULL |
| resource_type | VARCHAR(30) | NOT NULL |
| client_ip | INET | NOT NULL |
| occurred_at | TIMESTAMPTZ | NOT NULL, DEFAULT now() |
| chain_hash | CHAR(64) | NOT NULL (SHA-256 hex) |
| extra | JSONB | NULL (additional context) |

Indexes: `idx_al_actor_id`, `idx_al_resource_id`, `idx_al_occurred_at`.

No UPDATE or DELETE privileges are granted to the application DB user on this table. The application role has INSERT + SELECT only.

#### `nonce_store`

| Column | Type | Constraints |
|---|---|---|
| nonce | VARCHAR(128) | PK |
| expires_at | TIMESTAMPTZ | NOT NULL |

A partial index `idx_ns_expires_at` on `expires_at` supports efficient cleanup of expired nonces.


---

## API Endpoint Contracts

All endpoints are served over HTTPS. Protected endpoints require `Authorization: Bearer <access_token>`. Replay-protected endpoints additionally require `X-Nonce: <uuid>` and `X-Timestamp: <ISO-8601 UTC>` headers.

### Auth Endpoints

#### `POST /auth/register`
- Auth: None
- Replay protection: No
- Request body:
```json
{ "email": "string", "password": "string (min 12 chars)", "role": "Patient|Doctor|Nurse|Lab_Technician" }
```
- Response 201:
```json
{ "id": "uuid", "email": "string", "role": "string", "created_at": "datetime" }
```
- Errors: 409 (duplicate email), 422 (validation)

#### `POST /auth/login`
- Auth: None
- Replay protection: Yes
- Request body:
```json
{ "email": "string", "password": "string" }
```
- Response 200 (MFA disabled):
```json
{ "access_token": "string", "refresh_token": "string", "token_type": "bearer", "expires_in": 900 }
```
- Response 200 (MFA enabled):
```json
{ "partial_token": "string", "mfa_required": true }
```
- Errors: 401 (invalid credentials)

#### `POST /auth/mfa/verify`
- Auth: Partial token (Bearer)
- Replay protection: Yes
- Request body:
```json
{ "totp_code": "string (6 digits)" }
```
- Response 200:
```json
{ "access_token": "string", "refresh_token": "string", "token_type": "bearer", "expires_in": 900 }
```
- Errors: 401 (invalid TOTP)

#### `POST /auth/mfa/enroll`
- Auth: Access token (any role)
- Replay protection: No
- Response 200:
```json
{ "provisioning_uri": "otpauth://totp/...", "secret": "string (base32, shown once)" }
```

#### `POST /auth/mfa/confirm`
- Auth: Access token (any role)
- Replay protection: No
- Request body:
```json
{ "totp_code": "string" }
```
- Response 200: `{ "mfa_enabled": true }`
- Errors: 400 (invalid TOTP code)

#### `POST /auth/token/refresh`
- Auth: None (refresh token in body)
- Replay protection: No
- Request body:
```json
{ "refresh_token": "string" }
```
- Response 200:
```json
{ "access_token": "string", "refresh_token": "string", "token_type": "bearer", "expires_in": 900 }
```
- Errors: 401 (expired/revoked token)

#### `POST /auth/password-reset/request`
- Auth: None
- Replay protection: Yes
- Request body:
```json
{ "email": "string" }
```
- Response 200: `{ "message": "If that email exists, a reset link has been sent." }`
- Dev mode response 200: `{ "message": "...", "dev_token": "string [DEV ONLY - remove in production]" }`

#### `POST /auth/password-reset/complete`
- Auth: None
- Replay protection: Yes
- Request body:
```json
{ "token": "string", "new_password": "string (min 12 chars)", "totp_code": "string|null" }
```
- Response 200: `{ "message": "Password updated. All sessions have been revoked." }`
- Errors: 400 (expired/used token), 422 (weak password)

### User Endpoints

#### `GET /users/me`
- Auth: Any role
- Response 200:
```json
{ "id": "uuid", "email": "string", "role": "string", "mfa_enabled": "bool", "created_at": "datetime" }
```

#### `PATCH /users/me`
- Auth: Patient only (own profile)
- Request body: `{ "email": "string|null" }`
- Response 200: Updated user object

### Consent Endpoints

#### `POST /consent/request`
- Auth: Doctor
- Replay protection: No
- Request body:
```json
{ "patient_id": "uuid", "duration_days": "integer (1-365)" }
```
- Response 201:
```json
{ "id": "uuid", "doctor_id": "uuid", "patient_id": "uuid", "status": "pending", "created_at": "datetime" }
```

#### `GET /consent`
- Auth: Patient (own grants)
- Response 200: `[ { "id": "uuid", "doctor_id": "uuid", "status": "string", "expires_at": "datetime|null", ... } ]`

#### `POST /consent/{grant_id}/approve`
- Auth: Patient (must own the grant)
- Response 200: Updated grant object with `status: "active"` and `expires_at`

#### `POST /consent/{grant_id}/reject`
- Auth: Patient (must own the grant)
- Response 200: Updated grant object with `status: "rejected"`

#### `POST /consent/{grant_id}/revoke`
- Auth: Patient (must own the grant)
- Response 200: Updated grant object with `status: "revoked"`

### Medical Records Endpoints

#### `POST /records`
- Auth: Doctor (with active consent), Nurse (assigned patients), Lab_Technician
- Replay protection: Yes
- Request body:
```json
{ "patient_id": "uuid", "record_type": "string", "data": { "...": "any PHI fields" } }
```
- Response 201: `{ "id": "uuid", "patient_id": "uuid", "record_type": "string", "created_at": "datetime" }`

#### `GET /records/{record_id}`
- Auth: Patient (own), Doctor (active consent), Nurse (assigned), Lab_Technician (own lab results)
- Response 200:
```json
{ "id": "uuid", "patient_id": "uuid", "record_type": "string", "data": { "...": "decrypted PHI" }, "created_at": "datetime" }
```
- Errors: 404 (not found), 403 (no permission)

#### `GET /records?patient_id={uuid}`
- Auth: Patient (own), Doctor (active consent), Nurse (assigned)
- Response 200: Array of record objects (data field included, decrypted)

#### `PATCH /records/{record_id}`
- Auth: Doctor (active consent), Nurse (assigned, read-only — 403), Lab_Technician (own lab results)
- Replay protection: Yes
- Request body: `{ "data": { "...": "updated fields" } }`
- Response 200: Updated record object

#### `DELETE /records/{record_id}`
- Auth: Doctor (active consent)
- Replay protection: Yes
- Response 200: `{ "message": "Record soft-deleted." }`

### Audit Endpoints

#### `GET /audit`
- Auth: Doctor, Nurse (read-only, own actions only) — in practice, compliance officer role would be added; for now Doctor can view
- Query params: `actor_id`, `resource_id`, `from`, `to`, `limit`, `offset`
- Response 200: Array of audit entry objects

#### `GET /audit/verify`
- Auth: Any authenticated user
- Response 200:
```json
{ "chain_intact": true, "entries_checked": 1042, "first_entry_id": 1, "last_entry_id": 1042 }
```
- Response 200 (tampered):
```json
{ "chain_intact": false, "first_broken_at_id": 517, "entries_checked": 1042 }
```

### Health Check

#### `GET /health`
- Auth: None
- Response 200: `{ "status": "ok", "timestamp": "datetime" }`


---

## Encryption Design

### AES-256-GCM Overview

AES-256-GCM is an authenticated encryption scheme. It provides:
- **Confidentiality** via AES in counter mode (256-bit key).
- **Integrity and authenticity** via the GCM authentication tag (128-bit).

This means a tampered ciphertext is detected at decryption time — no separate HMAC is needed.

### Key Derivation and Storage

```
Environment variable: RECORD_ENCRYPTION_KEY (hex-encoded, 64 hex chars = 32 bytes)
                                ¦
                    KeyManager.from_env()
                                ¦
                    Validated at startup (length check)
                                ¦
                    Held in memory as bytes
                    Never written to DB, logs, or files
```

A separate key `TOTP_ENCRYPTION_KEY` is used for TOTP secrets to limit blast radius if one key is compromised.

### IV/Nonce Handling

- A fresh 12-byte (96-bit) random IV is generated for **every encryption operation** using `os.urandom(12)`.
- The IV is stored alongside the ciphertext in dedicated columns (`iv BYTEA`).
- IVs are never reused — each record write generates a new IV even for updates.
- **Security justification**: GCM security collapses catastrophically if an IV is reused with the same key. Per-operation random IVs with a 96-bit space make collision probability negligible (birthday bound: ~2^48 operations before 50% collision probability — far beyond any realistic usage).

### Storage Format

Each encrypted field is stored as three separate columns:

| Column | Content | Size |
|---|---|---|
| `encrypted_data` | AES-256-GCM ciphertext | variable |
| `iv` | 12-byte random nonce | 12 bytes |
| `tag` | 16-byte GCM authentication tag | 16 bytes |

### Encryption / Decryption Flow

```python
# Encryption
def encrypt(plaintext: bytes, key: bytes) -> tuple[bytes, bytes, bytes]:
    iv = os.urandom(12)
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag          # 16 bytes
    return ciphertext, iv, tag

# Decryption
def decrypt(ciphertext: bytes, iv: bytes, tag: bytes, key: bytes) -> bytes:
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()
    # Raises InvalidTag if ciphertext or tag has been tampered with
```

The medical record `data` dict is serialised to UTF-8 JSON before encryption and deserialised after decryption.

### Key Rotation Consideration

Key rotation is out of scope for the initial implementation but the design supports it: each record stores its own IV and tag, so a rotation job can re-encrypt records one at a time using the old key to decrypt and the new key to encrypt, without downtime.

---

## Audit Chain Design

### Hash Chaining Algorithm

The audit log forms a linked list of SHA-256 hashes. Each entry's `chain_hash` commits to both the entry's own content and all prior entries.

```
Entry 0 (sentinel):  chain_hash = "0" * 64

Entry 1:  chain_hash = SHA256( serialize(entry_1) + "0" * 64 )
Entry 2:  chain_hash = SHA256( serialize(entry_2) + chain_hash_of_entry_1 )
Entry N:  chain_hash = SHA256( serialize(entry_N) + chain_hash_of_entry_(N-1) )
```

### Serialisation for Hashing

The entry is serialised deterministically before hashing:

```python
def serialize_for_hash(entry: AuditEntry) -> str:
    return json.dumps({
        "id": entry.id,
        "event_type": entry.event_type,
        "actor_id": str(entry.actor_id),
        "resource_id": str(entry.resource_id),
        "resource_type": entry.resource_type,
        "client_ip": str(entry.client_ip),
        "occurred_at": entry.occurred_at.isoformat(),
        "extra": entry.extra,
    }, sort_keys=True, separators=(',', ':'))
```

`sort_keys=True` and no extra whitespace ensure deterministic output regardless of insertion order.

### Sentinel Value

The chain hash preceding the first real entry is defined as `"0" * 64` (64 ASCII zero characters). This is a fixed, well-known value that anchors the chain without requiring a dummy database row.

### Verification Flow

```
GET /audit/verify
    ¦
    +- Load all entries ordered by id ASC
    ¦
    +- prev_hash = "0" * 64
    ¦
    +- FOR each entry in order:
    ¦       expected = SHA256(serialize(entry) + prev_hash)
    ¦       IF expected != entry.chain_hash:
    ¦           return { chain_intact: false, first_broken_at_id: entry.id }
    ¦       prev_hash = entry.chain_hash
    ¦
    +- return { chain_intact: true, entries_checked: N }
```

### Tamper Detection

Any modification to a stored entry (changing event_type, actor_id, timestamp, etc.) will cause its `chain_hash` to no longer match the recomputed value. Because each entry's hash depends on all prior hashes, modifying entry N also invalidates entries N+1 through the end of the chain — making silent tampering computationally infeasible.

### Append-Only Enforcement

- The application DB user is granted `INSERT` and `SELECT` on `audit_log` only — no `UPDATE` or `DELETE`.
- This is enforced at the PostgreSQL privilege level, not just application logic.

---

## Data Flow Diagrams

### Flow 1: Doctor Accessing a Patient Record (Full Consent Flow)

```
Doctor Client
    ¦
    ¦  POST /consent/request  { patient_id, duration_days }
    ¦  Headers: Authorization: Bearer <doctor_access_token>
    ?
RBAC_Middleware
    ¦  Decode JWT ? { user_id: doctor_id, role: "Doctor" }
    ¦  Check role == Doctor ?
    ?
ConsentService.request_consent(doctor_id, patient_id, duration_days)
    ¦  INSERT consent_grants (status='pending')
    ?
AuditService.append(CONSENT_REQUESTED, actor=doctor_id, resource=grant_id)
    ¦
    ¦  [Out-of-band: Patient is notified — email/in-app, out of scope for API]
    ¦
    ?
Response 201 ? { grant_id, status: "pending" }

---------------------------------------------------------------------

Patient Client
    ¦
    ¦  POST /consent/{grant_id}/approve
    ¦  Headers: Authorization: Bearer <patient_access_token>
    ?
RBAC_Middleware
    ¦  Decode JWT ? { user_id: patient_id, role: "Patient" }
    ¦  Verify patient owns grant ?
    ?
ConsentService.approve_consent(patient_id, grant_id)
    ¦  UPDATE consent_grants SET status='active', expires_at=now()+duration
    ?
AuditService.append(CONSENT_APPROVED, actor=patient_id, resource=grant_id)
    ¦
    ?
Response 200 ? { grant_id, status: "active", expires_at }

---------------------------------------------------------------------

Doctor Client
    ¦
    ¦  GET /records/{record_id}
    ¦  Headers: Authorization: Bearer <doctor_access_token>
    ?
Replay_Guard  [not applied to GET — read endpoints are not replay-protected]
    ¦
RBAC_Middleware
    ¦  Decode JWT ? { user_id: doctor_id, role: "Doctor" }
    ¦  role == Doctor ? must check consent
    ¦
    +-? ConsentService.check_active_grant(doctor_id, patient_id)
    ¦       SELECT consent_grants WHERE doctor_id=? AND patient_id=?
    ¦                               AND status='active' AND expires_at > now()
    ¦       Returns True ?
    ¦
    ?
RecordsService.get_record(actor, record_id)
    ¦  SELECT medical_records WHERE id=? AND is_deleted=FALSE
    ¦
    +-? KeyManager.get_record_key() ? 32-byte AES key
    ¦
    +-? decrypt(encrypted_data, iv, tag, key) ? plaintext JSON
    ¦
    ?
AuditService.append(RECORD_READ, actor=doctor_id, resource=record_id)
    ¦
    ?
Response 200 ? { id, patient_id, record_type, data: { decrypted PHI } }
```

### Flow 2: Password Reset Flow

```
User Client
    ¦
    ¦  POST /auth/password-reset/request  { email }
    ¦  Headers: X-Nonce: <uuid>, X-Timestamp: <ISO UTC>
    ?
Replay_Guard
    ¦  Parse X-Timestamp ? check |now - ts| = 5 min ?
    ¦  Check nonce_store for X-Nonce ? not found ?
    ¦  INSERT nonce_store (nonce, expires_at=now()+5min)
    ?
AuthService.request_password_reset(email)
    ¦
    +- Lookup user by email
    ¦   IF not found ? return generic 200 (no leak)
    ¦
    +- Generate reset_token = secrets.token_urlsafe(32)   [256-bit entropy]
    ¦   token_hash = SHA256(reset_token)
    ¦
    +- INSERT password_reset_tokens (user_id, token_hash, expires_at=now()+30min)
    ¦
    +- [PROD] Send email via SMTP with reset link containing raw token
    ¦   [DEV]  Return token in response body, clearly marked dev-only
    ¦
    ?
Response 200 ? { message: "If that email exists, a reset link has been sent." }
              [DEV: + "dev_token": "<token> [DEV ONLY]" ]

---------------------------------------------------------------------

User Client
    ¦
    ¦  POST /auth/password-reset/complete
    ¦  { token, new_password, totp_code (if MFA enabled) }
    ¦  Headers: X-Nonce: <uuid>, X-Timestamp: <ISO UTC>
    ?
Replay_Guard
    ¦  Validate nonce + timestamp ?
    ?
AuthService.complete_password_reset(token, new_password, totp_code)
    ¦
    +- token_hash = SHA256(token)
    ¦   SELECT password_reset_tokens WHERE token_hash=? AND used=FALSE
    ¦   IF not found OR expires_at < now() ? HTTP 400
    ¦
    +- Validate new_password length = 12 chars
    ¦
    +- IF user.mfa_enabled AND totp_code is None ? HTTP 400
    ¦   IF user.mfa_enabled ? verify TOTP code via pyotp ?
    ¦
    +- new_hash = bcrypt.hash(new_password)
    ¦   UPDATE users SET password_hash=new_hash
    ¦
    +- UPDATE password_reset_tokens SET used=TRUE
    ¦
    +- UPDATE refresh_tokens SET revoked=TRUE WHERE user_id=?
    ¦   (invalidates ALL existing sessions)
    ¦
    ?
AuditService.append(PASSWORD_RESET, actor=user_id, resource=user_id)
    ¦
    ?
Response 200 ? { message: "Password updated. All sessions have been revoked." }
```

---

## Error Handling

### Error Response Format

All errors follow a consistent envelope:

```json
{
  "detail": "Human-readable error message",
  "error_code": "MACHINE_READABLE_CODE",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

FastAPI's default 422 validation errors are wrapped by a custom exception handler to match this format.

### Error Code Catalogue

| HTTP Status | error_code | Trigger |
|---|---|---|
| 400 | REPLAY_NONCE_SEEN | Nonce already used |
| 400 | REPLAY_TIMESTAMP_SKEW | Timestamp outside 5-min window |
| 400 | INVALID_TOTP | TOTP code rejected |
| 400 | TOKEN_EXPIRED_OR_USED | Reset token expired or already used |
| 401 | INVALID_CREDENTIALS | Wrong email/password |
| 401 | TOKEN_EXPIRED | Access token expired |
| 401 | TOKEN_INVALID | Malformed or tampered JWT |
| 401 | REFRESH_TOKEN_INVALID | Refresh token expired/revoked |
| 403 | INSUFFICIENT_ROLE | Role not permitted for endpoint |
| 403 | NO_ACTIVE_CONSENT | Doctor lacks active consent grant |
| 404 | RECORD_NOT_FOUND | Record ID does not exist or is soft-deleted |
| 409 | EMAIL_ALREADY_EXISTS | Duplicate registration email |
| 422 | VALIDATION_ERROR | Request body fails schema validation |
| 500 | INTERNAL_ERROR | Unexpected server error (details not leaked) |

### Security-Sensitive Error Handling Rules

1. **No information leakage on 401**: Login and password-reset-request endpoints always return the same message regardless of whether the email exists.
2. **No stack traces in responses**: A global exception handler catches unhandled exceptions, logs them server-side, and returns a generic 500 with no internal details.
3. **Decryption failures**: If `InvalidTag` is raised during decryption (tampered ciphertext), the error is logged as a security event and HTTP 500 is returned — not 400 — to avoid oracle attacks.

---

## Testing Strategy

### Dual Testing Approach

Unit tests cover specific examples, edge cases, and error conditions. Property-based tests verify universal correctness properties across randomised inputs. Both are required for comprehensive coverage.

### Property-Based Testing

The project uses **Hypothesis** (Python) as the property-based testing library. Each property test is configured with `@settings(max_examples=100)` minimum.

Each property test is tagged with a comment in the format:
`# Feature: secure-medical-records-backend, Property N: <property_text>`

### Unit Testing

Unit tests use **pytest** with **pytest-asyncio** for async FastAPI routes. External dependencies (DB, SMTP) are mocked with `unittest.mock` or `pytest-mock`.

Focus areas:
- Specific login/registration examples
- Consent state machine transitions (pending ? active ? revoked)
- Role permission matrix (each role × each endpoint)
- Error response format consistency
- Nonce/timestamp boundary conditions (exactly 5 minutes, 5 minutes + 1 second)

### Integration Testing

Integration tests run against a real PostgreSQL instance (Docker Compose in CI):
- Full auth flow (register ? login ? refresh ? logout)
- Full consent flow (request ? approve ? access ? revoke ? deny)
- Audit chain verification after a sequence of operations
- Password reset end-to-end

### Test Coverage Targets

| Module | Unit | Property | Integration |
|---|---|---|---|
| Auth_Module | ? | ? (encryption round-trip, token claims) | ? |
| RBAC_Middleware | ? | ? (role permission properties) | ? |
| Consent_Module | ? | ? (consent state properties) | ? |
| Records_Module | ? | ? (encryption round-trip) | ? |
| Audit_Module | ? | ? (chain integrity) | ? |
| Replay_Guard | ? | ? (nonce uniqueness) | ? |
| Key_Manager | ? | — | — |


---

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system — essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

The project uses **Hypothesis** (Python) for property-based testing. Each property test runs a minimum of 100 iterations (`@settings(max_examples=100)`).

Tag format for each test: `# Feature: secure-medical-records-backend, Property N: <property_text>`

---

### Property 1: Password Storage Is Never Plaintext

*For any* valid registration input (email, password, role), the value stored in `users.password_hash` must not equal the plaintext password, and `bcrypt.checkpw(plaintext, stored_hash)` must return True.

**Validates: Requirements 1.1, 1.5**

---

### Property 2: Duplicate Email Registration Is Always Rejected

*For any* email address, registering it a second time must return HTTP 409 and the total number of user accounts with that email must remain exactly 1.

**Validates: Requirements 1.2**

---

### Property 3: Invalid Registration Inputs Are Always Rejected

*For any* password of length 0–11 characters, registration must return HTTP 422. *For any* role string not in {Patient, Doctor, Nurse, Lab_Technician}, registration must return HTTP 422.

**Validates: Requirements 1.3, 1.4**

---

### Property 4: Access Token Claims Are Always Present and Correct

*For any* registered user of any role, the Access_Token issued on successful login must contain `role` and `user_id` claims that exactly match the registered user's role and ID, and the `exp - iat` claim difference must equal 900 seconds (15 minutes).

**Validates: Requirements 2.1, 2.4**

---

### Property 5: MFA-Enabled Login Never Issues Full Tokens Without TOTP

*For any* user with MFA enabled, a login request with correct credentials must return `mfa_required: true` and a partial token, and the partial token must be rejected with HTTP 401 on any protected endpoint.

**Validates: Requirements 2.2**

---

### Property 6: Authentication Failure Responses Are Indistinguishable

*For any* (email, wrong_password) pair — whether the email exists in the system or not — the HTTP status code and response body structure must be identical (HTTP 401, same generic message). The same holds for password-reset-request responses regardless of whether the email is registered.

**Validates: Requirements 2.3, 13.2**

---

### Property 7: Refresh Token Rotation Invalidates Consumed Tokens

*For any* valid refresh token, using it once must succeed and issue a new token pair. Using the same token a second time must return HTTP 401. The original token must be marked revoked in the database.

**Validates: Requirements 3.3**

---

### Property 8: Invalid TOTP Codes Are Always Rejected

*For any* 6-digit code that does not match the current TOTP window for a given secret, submitting it during MFA enrollment confirmation must return HTTP 400 and leave `mfa_enabled = False`. Submitting it during MFA login must return HTTP 401 and issue no tokens.

**Validates: Requirements 4.3, 4.5**

---

### Property 9: Tampered JWTs Are Always Rejected

*For any* valid Access_Token, modifying any byte of the signature or any claim in the payload must cause the RBAC_Middleware to return HTTP 401.

**Validates: Requirements 5.1**

---

### Property 10: Role Permission Matrix Is Universally Enforced

*For any* (user, endpoint) pair where the user's role is not in the endpoint's permitted-roles set, the request must return HTTP 403 regardless of the request body or path parameters.

**Validates: Requirements 5.3, 5.4**

---

### Property 11: Consent Gate Is a Complete Access Control Invariant

*For any* Doctor and any Patient record, the Doctor must receive HTTP 403 unless there exists a consent grant with `status = 'active'` and `expires_at > now()` linking that Doctor to that Patient. This invariant must hold after: no grant exists, grant is pending, grant is rejected, grant is revoked, and grant is expired.

**Validates: Requirements 5.5, 6.3, 6.4, 6.5**

---

### Property 12: Consent Approval Sets Correct Expiry

*For any* pending consent grant with `requested_duration_days = D`, approving it must set `expires_at` to a timestamp within ±5 seconds of `now() + D * 86400 seconds`.

**Validates: Requirements 6.2**

---

### Property 13: Patient Consent List Is Complete

*For any* patient with N consent grants (of any status), the `GET /consent` endpoint must return exactly N grant objects, each containing the correct `status` and `expires_at` fields.

**Validates: Requirements 6.6**

---

### Property 14: Medical Record Round-Trip Preserves Data

*For any* record data dictionary, creating a record and then reading it back must return a data dictionary that is deeply equal to the original. The raw bytes stored in `medical_records.encrypted_data` must not equal the UTF-8 JSON encoding of the original data.

**Validates: Requirements 7.2, 8.1, 8.2**

---

### Property 15: Record Update Round-Trip Preserves New Data

*For any* existing record and any new data dictionary, updating the record and then reading it back must return a data dictionary deeply equal to the new data, not the original.

**Validates: Requirements 7.3**

---

### Property 16: Soft-Deleted Records Are Inaccessible

*For any* record that has been soft-deleted, any subsequent read request for that record ID must return HTTP 404.

**Validates: Requirements 7.4**

---

### Property 17: AES-256-GCM Encryption Round-Trip Is Lossless

*For any* byte string (representing serialised record data), encrypting it with a 32-byte key and then decrypting the resulting (ciphertext, iv, tag) tuple must produce a byte string identical to the original. This must hold for all valid inputs including empty bytes, single bytes, and large payloads.

**Validates: Requirements 8.6**

---

### Property 18: Key Manager Rejects Invalid Key Lengths

*For any* byte string of length ? 32, `KeyManager.from_env()` must raise a `RuntimeError` with a descriptive message. This must hold for lengths 0 through 31 and 33 through at least 256.

**Validates: Requirements 8.4**

---

### Property 19: Nonce Reuse Is Always Rejected

*For any* nonce string, submitting it to a replay-protected endpoint a second time within the 5-minute window must return HTTP 400, regardless of the nonce value or the endpoint.

**Validates: Requirements 9.2**

---

### Property 20: Out-of-Window Timestamps Are Always Rejected

*For any* timestamp that differs from the server's current UTC time by more than 300 seconds (in either direction), the Replay_Guard must return HTTP 400. Timestamps within the 300-second window must be accepted.

**Validates: Requirements 9.3**

---

### Property 21: Every Sensitive Event Produces a Complete Audit Entry

*For any* triggering event (login, record create/read/update/delete, consent request/approval/revocation), the Audit_Module must append exactly one entry containing non-null values for `event_type`, `actor_id`, `resource_id`, `occurred_at`, and `client_ip`.

**Validates: Requirements 10.1**

---

### Property 22: Audit Chain Integrity Is Self-Consistent

*For any* sequence of N audit entries produced by the system, calling `GET /audit/verify` must return `chain_intact: true` and `entries_checked: N`. If any single entry's stored fields are modified (simulated tampering), `verify` must return `chain_intact: false` with `first_broken_at_id` pointing to the tampered entry or any subsequent entry.

**Validates: Requirements 10.2, 10.4, 10.6**

---

### Property 23: Missing Required Environment Variables Cause Descriptive Startup Failure

*For any* required environment variable (JWT_SECRET_KEY, RECORD_ENCRYPTION_KEY, TOTP_ENCRYPTION_KEY, DATABASE_URL, etc.), starting the application with that variable absent must raise a startup error whose message contains the name of the missing variable.

**Validates: Requirements 11.2**

---

### Property 24: Password Reset Tokens Are Unique and Single-Use

*For any* user, generating N password reset tokens must produce N distinct token hashes in the database. Using any one token to complete a reset must mark it as `used = True`, and any subsequent attempt to use the same token must return HTTP 400.

**Validates: Requirements 13.1, 13.3**

---

### Property 25: Password Reset Revokes All Active Sessions

*For any* user with N active refresh tokens (N = 1), completing a password reset must cause all N refresh tokens to return HTTP 401 when used for token refresh.

**Validates: Requirements 13.5**


---

## Security Justifications

### JWT Design Decisions

| Decision | Justification |
|---|---|
| 15-minute access token expiry | Short-lived tokens limit the window of exploitation if a token is stolen. An attacker who captures a token has at most 15 minutes before it expires. |
| 7-day refresh token with rotation | Balances usability (users don't re-authenticate daily) with security (rotation means a stolen refresh token can only be used once before the legitimate user's next refresh invalidates it). |
| Refresh token stored as SHA-256 hash | The raw token is never stored. If the DB is breached, the attacker gets hashes that cannot be reversed to valid tokens. |
| Partial-auth token for MFA | Prevents issuing a full access token before the second factor is verified. The partial token has no privileges on protected endpoints. |
| Role + user_id embedded in JWT | Eliminates a DB lookup on every request for role checking. The JWT signature guarantees the claims haven't been tampered with. |

### Password Security

| Decision | Justification |
|---|---|
| bcrypt with default cost factor | bcrypt is intentionally slow (adaptive cost), making brute-force attacks computationally expensive. The cost factor can be increased as hardware improves. |
| Minimum 12-character password | NIST SP 800-63B recommends at least 8 characters; 12 provides additional entropy margin. |
| Generic error messages on login failure | Prevents user enumeration attacks. An attacker cannot determine whether an email is registered by observing the error response. |

### Encryption Design

| Decision | Justification |
|---|---|
| AES-256-GCM over AES-256-CBC | GCM provides authenticated encryption — it detects ciphertext tampering without a separate HMAC. CBC requires a separate MAC and is vulnerable to padding oracle attacks if not implemented carefully. |
| Per-operation random 12-byte IV | GCM security requires IV uniqueness per (key, IV) pair. Random 96-bit IVs make collision probability negligible (~2^-32 after 2^32 operations). Reusing an IV with GCM leaks the authentication key. |
| Separate keys for records and TOTP secrets | Key separation limits blast radius. Compromising the record encryption key does not expose TOTP secrets, and vice versa. |
| Encrypt entire JSON payload as one blob | Avoids partial-encryption mistakes where a developer forgets to encrypt a new field. The encryption boundary is the entire record payload. |
| Keys from env vars only, validated at startup | Prevents accidental key exposure in source code or config files. Startup validation ensures the system never runs with a missing or malformed key. |

### Audit Log Design

| Decision | Justification |
|---|---|
| Hash chaining (SHA-256) | Any modification to a historical entry invalidates all subsequent chain hashes, making silent tampering detectable. An attacker cannot modify entry N without recomputing all hashes from N to the end. |
| BIGSERIAL primary key (not UUID) | Sequential integer IDs provide a natural, unambiguous ordering for chain verification. UUID ordering is non-deterministic without an additional timestamp column. |
| INSERT/SELECT only DB privileges | Even if the application is fully compromised, the attacker cannot issue UPDATE or DELETE on the audit log through the application's DB connection. |
| Atomic audit + business logic commit | The audit entry and the triggering operation are committed in the same transaction. This prevents a scenario where the operation succeeds but the audit entry is lost. |
| Sentinel value "0"*64 | A well-known, fixed anchor for the chain avoids the need for a dummy row and makes the chain verification algorithm simple and deterministic. |

### Replay Attack Protection

| Decision | Justification |
|---|---|
| Nonce + timestamp (dual check) | Nonce alone requires storing all nonces forever. Timestamp alone is insufficient (attacker can replay within the window). Together: the timestamp bounds the nonce storage window to 5 minutes, and the nonce prevents replay within that window. |
| 5-minute window | Balances clock skew tolerance (NTP-synced servers typically have <1 second skew) with replay window. A 5-minute window is standard practice (AWS Signature V4 uses the same). |
| Applied to write endpoints and auth endpoints | Read endpoints are idempotent — replaying a GET has no side effects. Write endpoints and auth endpoints can cause state changes or token issuance, making replay harmful. |
| Nonce stored with TTL | Nonces older than 5 minutes are automatically expired, keeping the nonce_store table bounded in size. |

### Consent Model

| Decision | Justification |
|---|---|
| Doctor requests, Patient approves | Inverts the traditional "doctor pulls records" model. The patient retains control and must explicitly grant access. This aligns with GDPR and Rwanda's data protection principles. |
| Time-limited grants | Prevents indefinite access. A doctor treating a patient for a specific episode does not retain access after the grant expires. |
| Revocation takes effect immediately | The consent check happens on every request (not cached). Revocation is effective within the same request cycle, not on the next token refresh. |
| Status field (pending/active/rejected/revoked/expired) | Provides a complete audit trail of consent lifecycle. Rejected and revoked grants are preserved for compliance review rather than deleted. |

### Transport Security

| Decision | Justification |
|---|---|
| HTTPS only, no HTTP | Prevents credential and token interception in transit. Even on localhost, TLS protects against local network sniffing. |
| Self-signed cert for local dev | Allows local HTTPS without a CA. The cert path is configurable via env var so production can use a CA-signed cert without code changes. |

### Configuration Security

| Decision | Justification |
|---|---|
| .env excluded from version control | Prevents accidental secret commit. The .env.example file documents required variables without exposing values. |
| Startup validation of all required vars | Fails fast with a clear error rather than running in a degraded/insecure state with missing configuration. |
| No hardcoded secrets anywhere | Eliminates the most common source of credential leakage in open-source and shared codebases. |

