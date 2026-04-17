# Implementation Plan: Secure Medical Records Backend

## Overview

Sequential implementation of a FastAPI + PostgreSQL backend for secure patient medical records. Each task builds on the previous, starting from project scaffolding and progressing through Key_Manager, Auth, RBAC, Consent, Records, Audit, and Replay_Guard modules, finishing with TLS configuration and integration wiring.

## Tasks

- [x] 1. Project scaffolding and configuration
  - Create directory structure: `app/`, `app/core/`, `app/models/`, `app/schemas/`, `app/services/`, `app/routers/`, `app/middleware/`, `tests/unit/`, `tests/integration/`
  - Create `pyproject.toml` (or `requirements.txt`) listing all dependencies: fastapi, uvicorn[standard], sqlalchemy[asyncio], asyncpg, alembic, pyjwt, passlib[bcrypt], pyotp, cryptography, python-dotenv, pydantic-settings, pytest, pytest-asyncio, hypothesis, httpx, pytest-mock
  - Create `app/core/config.py` using Pydantic `BaseSettings` to load and validate all required env vars: `DATABASE_URL`, `JWT_SECRET_KEY`, `JWT_ALGORITHM`, `RECORD_ENCRYPTION_KEY`, `TOTP_ENCRYPTION_KEY`, `ACCESS_TOKEN_EXPIRE_MINUTES`, `REFRESH_TOKEN_EXPIRE_DAYS`, `DEV_MODE`, `TLS_CERT_FILE`, `TLS_KEY_FILE`
  - Implement startup validation: raise `RuntimeError` with the missing variable name if any required env var is absent
  - Create `.env.example` with all required variable names, placeholder values, and inline descriptions
  - Create `.gitignore` excluding `.env`, `*.pem`, `*.key`, `__pycache__/`, `.pytest_cache/`
  - _Requirements: 11.1, 11.2, 11.3, 11.4_

  - [ ]* 1.1 Write property test for startup validation (Property 23)
    - **Property 23: Missing Required Environment Variables Cause Descriptive Startup Failure**
    - **Validates: Requirements 11.2**
    - Use `hypothesis.strategies.sampled_from` over the list of required env var names; for each, unset it and assert `RuntimeError` message contains the variable name

- [x] 2. Database models and Alembic migrations
  - Create `app/models/base.py` with SQLAlchemy `DeclarativeBase` and async engine setup
  - Create `app/models/user.py` — `User` model with all columns from the `users` table spec, including `idx_users_email` and `idx_users_role` indexes
  - Create `app/models/mfa_secret.py` — `MFASecret` model with `encrypted_secret`, `iv`, `tag` BYTEA columns
  - Create `app/models/refresh_token.py` — `RefreshToken` model with `token_hash`, `expires_at`, `revoked` columns and indexes
  - Create `app/models/password_reset_token.py` — `PasswordResetToken` model with `token_hash`, `expires_at`, `used` columns
  - Create `app/models/consent_grant.py` — `ConsentGrant` model with status CHECK constraint and composite indexes
  - Create `app/models/medical_record.py` — `MedicalRecord` model with `encrypted_data`, `iv`, `tag` BYTEA columns and `is_deleted` flag
  - Create `app/models/audit_log.py` — `AuditLog` model with `BIGSERIAL` PK, `chain_hash CHAR(64)`, `extra JSONB`
  - Create `app/models/nonce_store.py` — `NonceStore` model with `nonce` PK and `expires_at`
  - Initialise Alembic (`alembic init alembic`), configure `env.py` to use async engine and import all models
  - Generate and review initial migration: `alembic revision --autogenerate -m "initial_schema"`
  - Add a second migration that grants `INSERT, SELECT` only on `audit_log` to the application DB role
  - _Requirements: 8.1, 8.2, 10.5_

- [ ] 3. Key_Manager implementation
  - Create `app/core/key_manager.py` implementing `KeyManager` as a module-level singleton
  - Implement `KeyManager.from_env()`: read `RECORD_ENCRYPTION_KEY` and `TOTP_ENCRYPTION_KEY` as hex strings, decode to bytes, validate length == 32, raise `RuntimeError` with descriptive message on failure
  - Expose `get_record_key() -> bytes` and `get_totp_key() -> bytes` methods
  - Wire `KeyManager.from_env()` into the FastAPI `lifespan` startup event so the app fails to start if keys are invalid
  - _Requirements: 8.3, 8.4, 8.5_

  - [ ]* 3.1 Write property test for Key_Manager key length validation (Property 18)
    - **Property 18: Key Manager Rejects Invalid Key Lengths**
    - **Validates: Requirements 8.4**
    - Use `hypothesis.strategies.binary(min_size=0, max_size=256).filter(lambda b: len(b) != 32)`; assert `RuntimeError` is raised for every non-32-byte input

- [ ] 4. Encryption utilities
  - Create `app/core/crypto.py` with `encrypt(plaintext: bytes, key: bytes) -> tuple[bytes, bytes, bytes]` and `decrypt(ciphertext: bytes, iv: bytes, tag: bytes, key: bytes) -> bytes` using AES-256-GCM from the `cryptography` library
  - Generate a fresh `os.urandom(12)` IV on every `encrypt` call
  - Raise `InvalidTag` (re-raised as HTTP 500 in the error handler) on decryption failure
  - _Requirements: 8.1, 8.2, 8.6_

  - [ ]* 4.1 Write property test for AES-256-GCM round-trip (Property 17)
    - **Property 17: AES-256-GCM Encryption Round-Trip Is Lossless**
    - **Validates: Requirements 8.6**
    - Use `hypothesis.strategies.binary()` for plaintext and a fixed 32-byte test key; assert `decrypt(*encrypt(pt, key), key) == pt` for all inputs including empty bytes

- [ ] 5. Pydantic schemas
  - Create `app/schemas/auth.py`: `RegisterRequest`, `LoginRequest`, `TokenPair`, `PartialAuthResponse`, `MFAVerifyRequest`, `MFAEnrollResponse`, `MFAConfirmRequest`, `RefreshRequest`, `PasswordResetRequest`, `PasswordResetComplete`, `UserOut`
  - Create `app/schemas/consent.py`: `ConsentRequestIn`, `ConsentGrantOut`
  - Create `app/schemas/records.py`: `RecordIn`, `RecordUpdate`, `RecordOut`
  - Create `app/schemas/audit.py`: `AuditEntryOut`, `AuditFilter`, `ChainVerificationResult`
  - Create `app/schemas/common.py`: `ErrorResponse` with `detail`, `error_code`, `timestamp` fields
  - Enforce `password` min-length 12 via `Annotated[str, Field(min_length=12)]` in `RegisterRequest` and `PasswordResetComplete`
  - Enforce `role` as a `Literal["Patient", "Doctor", "Nurse", "Lab_Technician"]` enum in `RegisterRequest`
  - _Requirements: 1.3, 1.4, 7.1_

- [ ] 6. Auth_Module — registration and login
  - Create `app/services/auth_service.py` with `AuthService` class
  - Implement `register(email, password, role)`: check for duplicate email (raise HTTP 409), hash password with `passlib.hash.bcrypt`, insert `User`, return `UserOut`
  - Implement `login(email, password)`: look up user, verify bcrypt hash (constant-time), if MFA disabled issue `TokenPair`, if MFA enabled issue partial-auth JWT with `{"sub": user_id, "partial": true, "exp": now+5min}`
  - JWT access tokens: sign with `JWT_SECRET_KEY`, embed `user_id` and `role` claims, set `exp = now + 900s`
  - Refresh tokens: generate `secrets.token_urlsafe(32)`, store SHA-256 hash in `refresh_tokens`, return raw token to client
  - Create `app/routers/auth.py` with `POST /auth/register` (201) and `POST /auth/login` (200)
  - Register router in `app/main.py`
  - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 2.1, 2.2, 2.3, 2.4_

  - [ ]* 6.1 Write property test for password storage (Property 1)
    - **Property 1: Password Storage Is Never Plaintext**
    - **Validates: Requirements 1.1, 1.5**
    - Use `hypothesis.strategies.text(min_size=12)` for passwords; after registration assert `stored_hash != password` and `bcrypt.checkpw(password, stored_hash)` is True

  - [ ]* 6.2 Write property test for duplicate email rejection (Property 2)
    - **Property 2: Duplicate Email Registration Is Always Rejected**
    - **Validates: Requirements 1.2**
    - Use `hypothesis.strategies.emails()`; register once (201), register again (409), assert user count for that email == 1

  - [ ]* 6.3 Write property test for invalid registration inputs (Property 3)
    - **Property 3: Invalid Registration Inputs Are Always Rejected**
    - **Validates: Requirements 1.3, 1.4**
    - Use `hypothesis.strategies.text(max_size=11)` for short passwords (expect 422); use `hypothesis.strategies.text().filter(lambda r: r not in valid_roles)` for invalid roles (expect 422)

  - [ ]* 6.4 Write property test for access token claims (Property 4)
    - **Property 4: Access Token Claims Are Always Present and Correct**
    - **Validates: Requirements 2.1, 2.4**
    - For each role, register and login; decode JWT (without verification for claim inspection); assert `role` and `user_id` match registration data and `exp - iat == 900`

  - [ ]* 6.5 Write property test for authentication failure indistinguishability (Property 6)
    - **Property 6: Authentication Failure Responses Are Indistinguishable**
    - **Validates: Requirements 2.3, 13.2**
    - Use `hypothesis.strategies.emails()` for non-existent emails and wrong passwords; assert HTTP 401 with identical body structure for both cases

- [ ] 7. Checkpoint — Auth registration and login tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 8. Auth_Module — token refresh and MFA
  - Implement `refresh_tokens(refresh_token)`: hash the raw token, look up in DB, check `revoked=False` and `expires_at > now()`, mark old token revoked, issue new `TokenPair` (token rotation)
  - Implement `enroll_mfa(user_id)`: generate TOTP secret via `pyotp.random_base32()`, encrypt with `KeyManager.get_totp_key()`, store in `mfa_secrets`, return provisioning URI and plaintext secret (shown once)
  - Implement `confirm_mfa(user_id, totp_code)`: decrypt stored secret, verify TOTP code via `pyotp.TOTP(secret).verify(code)`, set `users.mfa_enabled = True`
  - Implement `verify_totp(partial_token, totp_code)`: decode partial JWT, verify `partial=True` claim, decrypt TOTP secret, verify code, issue full `TokenPair`
  - Create routes: `POST /auth/token/refresh`, `POST /auth/mfa/enroll`, `POST /auth/mfa/confirm`, `POST /auth/mfa/verify`
  - _Requirements: 3.1, 3.2, 3.3, 4.1, 4.2, 4.3, 4.4, 4.5_

  - [ ]* 8.1 Write property test for refresh token rotation (Property 7)
    - **Property 7: Refresh Token Rotation Invalidates Consumed Tokens**
    - **Validates: Requirements 3.3**
    - Use a valid refresh token; call refresh once (200, new token pair); call refresh again with same token (401); assert original token `revoked=True` in DB

  - [ ]* 8.2 Write property test for MFA-enabled login (Property 5)
    - **Property 5: MFA-Enabled Login Never Issues Full Tokens Without TOTP**
    - **Validates: Requirements 2.2**
    - Enable MFA for a user; login with correct credentials; assert response contains `mfa_required: true` and `partial_token`; use partial token on a protected endpoint and assert HTTP 401

  - [ ]* 8.3 Write property test for invalid TOTP rejection (Property 8)
    - **Property 8: Invalid TOTP Codes Are Always Rejected**
    - **Validates: Requirements 4.3, 4.5**
    - Use `hypothesis.strategies.from_regex(r'\d{6}').filter(lambda c: c != valid_code)`; assert HTTP 400 on `confirm_mfa` and HTTP 401 on `verify_totp`

- [ ] 9. Auth_Module — password reset
  - Implement `request_password_reset(email)`: look up user (return generic 200 if not found), generate `secrets.token_urlsafe(32)`, store SHA-256 hash in `password_reset_tokens` with 30-min expiry; in `DEV_MODE` return raw token in response body
  - Implement `complete_password_reset(token, new_password, totp_code)`: hash token, look up in DB (HTTP 400 if not found, expired, or used), validate password length, verify TOTP if `mfa_enabled`, update `password_hash`, mark token `used=True`, revoke all refresh tokens for user
  - Create routes: `POST /auth/password-reset/request`, `POST /auth/password-reset/complete`
  - _Requirements: 13.1, 13.2, 13.3, 13.4, 13.5, 13.6, 13.7_

  - [ ]* 9.1 Write property test for password reset token uniqueness and single-use (Property 24)
    - **Property 24: Password Reset Tokens Are Unique and Single-Use**
    - **Validates: Requirements 13.1, 13.3**
    - Generate N reset tokens for the same user; assert N distinct hashes in DB; use one token (200); use same token again (400); assert `used=True`

  - [ ]* 9.2 Write property test for password reset session revocation (Property 25)
    - **Property 25: Password Reset Revokes All Active Sessions**
    - **Validates: Requirements 13.5**
    - Create a user with an active refresh token; complete password reset; attempt to use the old refresh token (401)

- [ ] 10. RBAC_Middleware
  - Create `app/middleware/rbac.py` with `get_current_user(token) -> TokenClaims` dependency: decode JWT with `PyJWT`, raise HTTP 401 on `ExpiredSignatureError` or `InvalidTokenError`, return `TokenClaims(user_id, role)`
  - Implement `require_roles(*roles) -> Callable`: returns a FastAPI dependency that calls `get_current_user` and raises HTTP 403 if `claims.role not in roles`
  - Apply `require_roles` to all protected routes
  - _Requirements: 5.1, 5.2, 5.3, 5.4_

  - [ ]* 10.1 Write property test for tampered JWT rejection (Property 9)
    - **Property 9: Tampered JWTs Are Always Rejected**
    - **Validates: Requirements 5.1**
    - Use `hypothesis.strategies.binary(min_size=1)` to generate byte mutations; apply each mutation to the signature segment of a valid JWT; assert HTTP 401 on any protected endpoint

  - [ ]* 10.2 Write property test for role permission matrix (Property 10)
    - **Property 10: Role Permission Matrix Is Universally Enforced**
    - **Validates: Requirements 5.3, 5.4**
    - For each (role, endpoint) pair where the role is not permitted, assert HTTP 403 regardless of request body

- [ ] 11. Consent_Module
  - Create `app/services/consent_service.py` with `ConsentService`
  - Implement `request_consent(doctor_id, patient_id, duration_days)`: insert `ConsentGrant` with `status='pending'`
  - Implement `approve_consent(patient_id, grant_id)`: verify patient owns grant, set `status='active'`, set `expires_at = now() + duration_days * 86400s`
  - Implement `reject_consent(patient_id, grant_id)`: verify ownership, set `status='rejected'`
  - Implement `revoke_consent(patient_id, grant_id)`: verify ownership, set `status='revoked'`
  - Implement `list_grants(patient_id)`: return all grants for patient
  - Implement `check_active_grant(doctor_id, patient_id) -> bool`: query for `status='active'` and `expires_at > now()`
  - Create `app/routers/consent.py` with all five consent endpoints
  - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6_

  - [ ]* 11.1 Write property test for consent gate invariant (Property 11)
    - **Property 11: Consent Gate Is a Complete Access Control Invariant**
    - **Validates: Requirements 5.5, 6.3, 6.4, 6.5**
    - For each consent state (no grant, pending, rejected, revoked, expired), assert Doctor receives HTTP 403 on `GET /records/{id}`; only `status='active'` with future `expires_at` permits access

  - [ ]* 11.2 Write property test for consent approval expiry (Property 12)
    - **Property 12: Consent Approval Sets Correct Expiry**
    - **Validates: Requirements 6.2**
    - Use `hypothesis.strategies.integers(min_value=1, max_value=365)` for `duration_days`; approve grant; assert `|expires_at - (now + D*86400)| <= 5 seconds`

  - [ ]* 11.3 Write property test for patient consent list completeness (Property 13)
    - **Property 13: Patient Consent List Is Complete**
    - **Validates: Requirements 6.6**
    - Use `hypothesis.strategies.integers(min_value=1, max_value=10)` for N grants; create N grants; assert `GET /consent` returns exactly N objects with correct `status` and `expires_at`

- [ ] 12. Checkpoint — Consent and RBAC tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 13. Records_Module
  - Create `app/services/records_service.py` with `RecordsService`
  - Implement `create_record(actor, patient_id, data)`: serialize `data` to UTF-8 JSON, encrypt with `KeyManager.get_record_key()`, insert `MedicalRecord`, return `RecordOut` (no `data` field in 201 response per spec)
  - Implement `get_record(actor, record_id)`: fetch record (HTTP 404 if not found or `is_deleted=True`), decrypt `encrypted_data`, deserialize JSON, return `RecordOut` with `data`
  - Implement `update_record(actor, record_id, data)`: fetch record, re-encrypt new data with fresh IV, update row
  - Implement `delete_record(actor, record_id)`: set `is_deleted=True` (soft delete)
  - Implement `list_records(actor, patient_id)`: fetch all non-deleted records for patient, decrypt each
  - Enforce access control in each method: Patient can only access own records; Doctor requires `check_active_grant`; Nurse read-only; Lab_Technician own lab results only
  - Create `app/routers/records.py` with all five record endpoints; apply `Replay_Guard` to `POST`, `PATCH`, `DELETE`
  - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6, 8.1, 8.2_

  - [ ]* 13.1 Write property test for medical record round-trip (Property 14)
    - **Property 14: Medical Record Round-Trip Preserves Data**
    - **Validates: Requirements 7.2, 8.1, 8.2**
    - Use `hypothesis.strategies.dictionaries(keys=st.text(min_size=1), values=st.text())` for record data; create record, read it back; assert returned `data` deeply equals original; assert `encrypted_data != json.dumps(data).encode()`

  - [ ]* 13.2 Write property test for record update round-trip (Property 15)
    - **Property 15: Record Update Round-Trip Preserves New Data**
    - **Validates: Requirements 7.3**
    - Create a record with data A; update with data B; read back; assert returned `data` deeply equals B, not A

  - [ ]* 13.3 Write property test for soft-deleted record inaccessibility (Property 16)
    - **Property 16: Soft-Deleted Records Are Inaccessible**
    - **Validates: Requirements 7.4**
    - Create a record; delete it; assert `GET /records/{id}` returns HTTP 404

- [ ] 14. Audit_Module
  - Create `app/services/audit_service.py` with `AuditService`
  - Implement `append(event_type, actor_id, resource_id, client_ip, extra)`: fetch the `chain_hash` of the last entry (or `"0"*64` if none), serialize the new entry deterministically with `json.dumps(..., sort_keys=True, separators=(',',':'))`, compute `SHA256(serialized + prev_hash)`, insert `AuditLog` row — all within the same DB transaction as the triggering operation
  - Implement `verify_chain() -> ChainVerificationResult`: load all entries ordered by `id ASC`, recompute each `chain_hash`, return `chain_intact=False` with `first_broken_at_id` on first mismatch
  - Implement `list_entries(filters)`: query with optional `actor_id`, `resource_id`, `from`, `to`, `limit`, `offset`
  - Wire `AuditService.append()` calls into every service method that triggers an auditable event (login, record CRUD, consent lifecycle, password reset)
  - Create `app/routers/audit.py` with `GET /audit` and `GET /audit/verify`
  - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.5, 10.6_

  - [ ]* 14.1 Write property test for audit entry completeness (Property 21)
    - **Property 21: Every Sensitive Event Produces a Complete Audit Entry**
    - **Validates: Requirements 10.1**
    - For each auditable event type, trigger the event and assert exactly one new `AuditLog` row with non-null `event_type`, `actor_id`, `resource_id`, `occurred_at`, `client_ip`

  - [ ]* 14.2 Write property test for audit chain integrity (Property 22)
    - **Property 22: Audit Chain Integrity Is Self-Consistent**
    - **Validates: Requirements 10.2, 10.4, 10.6**
    - Use `hypothesis.strategies.integers(min_value=1, max_value=20)` for N events; produce N audit entries; call `verify_chain()` and assert `chain_intact=True` and `entries_checked=N`; mutate one entry's `event_type` in DB directly; assert `verify_chain()` returns `chain_intact=False` with correct `first_broken_at_id`

- [ ] 15. Replay_Guard
  - Create `app/middleware/replay_guard.py` implementing `ReplayGuard` as a FastAPI dependency
  - Parse `X-Timestamp` header as ISO-8601 UTC; reject with HTTP 400 (`REPLAY_TIMESTAMP_SKEW`) if `|now - timestamp| > 300 seconds`
  - Query `nonce_store` for `X-Nonce`; reject with HTTP 400 (`REPLAY_NONCE_SEEN`) if found and `expires_at > now()`
  - Insert nonce with `expires_at = now() + 5 minutes` on acceptance
  - Apply `Depends(ReplayGuard.validate)` to: `POST /auth/login`, `POST /auth/mfa/verify`, `POST /auth/password-reset/request`, `POST /auth/password-reset/complete`, `POST /records`, `PATCH /records/{id}`, `DELETE /records/{id}`
  - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.5, 13.7_

  - [ ]* 15.1 Write property test for nonce reuse rejection (Property 19)
    - **Property 19: Nonce Reuse Is Always Rejected**
    - **Validates: Requirements 9.2**
    - Use `hypothesis.strategies.uuids()` for nonces; submit a valid request with nonce N (200); submit again with same nonce N within 5 minutes (400, `REPLAY_NONCE_SEEN`)

  - [ ]* 15.2 Write property test for out-of-window timestamp rejection (Property 20)
    - **Property 20: Out-of-Window Timestamps Are Always Rejected**
    - **Validates: Requirements 9.3**
    - Use `hypothesis.strategies.integers(min_value=301, max_value=3600)` for skew seconds; generate timestamps `now + skew` and `now - skew`; assert HTTP 400 (`REPLAY_TIMESTAMP_SKEW`); assert timestamps within 300s are accepted

- [ ] 16. Checkpoint — All module tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 17. Error handling and health check
  - Create `app/core/exceptions.py` defining `AppError(HTTPException)` with `error_code` field
  - Register a global exception handler in `app/main.py` that catches unhandled exceptions, logs them server-side, and returns HTTP 500 with `{"detail": "Internal server error", "error_code": "INTERNAL_ERROR", "timestamp": "..."}` — no stack trace in response
  - Override FastAPI's default 422 handler to wrap validation errors in the `ErrorResponse` schema
  - Implement `GET /health` returning `{"status": "ok", "timestamp": "<ISO UTC>"}` with no auth required
  - _Requirements: 12.3_

- [ ] 18. User profile endpoints
  - Create `app/routers/users.py`
  - Implement `GET /users/me`: return `UserOut` for the authenticated user (any role)
  - Implement `PATCH /users/me`: allow Patient to update own email; validate uniqueness; return updated `UserOut`; restrict to `require_roles("Patient")`
  - _Requirements: 5.4_

- [ ] 19. TLS configuration and HTTPS-only enforcement
  - Generate a self-signed TLS certificate and key: `openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost"`
  - Configure `uvicorn` startup in `app/main.py` (or a `run.py` entry point) to read `TLS_CERT_FILE` and `TLS_KEY_FILE` from env and pass them to `uvicorn.run(..., ssl_certfile=..., ssl_keyfile=...)`
  - Document in `.env.example` that `TLS_CERT_FILE` and `TLS_KEY_FILE` must point to a CA-signed cert for production
  - _Requirements: 12.1, 12.2_

- [ ] 20. Integration wiring and end-to-end validation
  - Verify all routers are registered in `app/main.py` under correct prefixes: `/auth`, `/users`, `/consent`, `/records`, `/audit`, `/health`
  - Confirm `Replay_Guard` dependency is applied to all seven replay-protected endpoints
  - Confirm `AuditService.append()` is called in every service method listed in Requirement 10.1
  - Confirm `KeyManager` singleton is initialised in the `lifespan` startup event before any request is served
  - Write a `conftest.py` for integration tests that spins up an async test client (`httpx.AsyncClient`) against the FastAPI app with a test database URL
  - _Requirements: 9.5, 10.1, 11.1, 12.1_

  - [ ]* 20.1 Write integration test for full auth flow
    - Register → login (no MFA) → access protected endpoint → refresh token → use old refresh token (401)
    - _Requirements: 2.1, 3.1, 3.3_

  - [ ]* 20.2 Write integration test for full consent and record access flow
    - Register Doctor + Patient → Doctor requests consent → Patient approves → Doctor reads record → Patient revokes → Doctor denied (403)
    - _Requirements: 6.1, 6.2, 6.4, 7.2_

  - [ ]* 20.3 Write integration test for audit chain after a sequence of operations
    - Perform login + record create + record read; call `GET /audit/verify`; assert `chain_intact: true`
    - _Requirements: 10.2, 10.4_

- [ ] 21. Final checkpoint — All tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for a faster MVP
- Property tests use `@settings(max_examples=100)` and the tag comment `# Feature: secure-medical-records-backend, Property N: <text>`
- Each property test is a sub-task under the implementation task it validates, so errors surface early
- Checkpoints at tasks 7, 12, 16, and 21 ensure incremental validation before moving to the next module
- The `.env` file must never be committed; use `.env.example` as the reference
- Run tests with `pytest --asyncio-mode=auto tests/` (single-run, not watch mode)
