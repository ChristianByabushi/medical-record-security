# MedVault — Final Technical Report
## Secure Medical Records Backend
**CMU Information Security — Spring 2026**

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Theoretical Foundations](#2-theoretical-foundations)
   - 2.1 [Symmetric Encryption — AES-256-GCM](#21-symmetric-encryption--aes-256-gcm)
   - 2.2 [Password Hashing — bcrypt](#22-password-hashing--bcrypt)
   - 2.3 [HMAC-Based One-Time Passwords — TOTP (RFC 6238)](#23-hmac-based-one-time-passwords--totp-rfc-6238)
   - 2.4 [JSON Web Tokens — JWT (RFC 7519)](#24-json-web-tokens--jwt-rfc-7519)
   - 2.5 [Hash-Chained Audit Logs](#25-hash-chained-audit-logs)
   - 2.6 [Replay Attack Prevention](#26-replay-attack-prevention)
   - 2.7 [Role-Based Access Control — RBAC](#27-role-based-access-control--rbac)
   - 2.8 [Consent-Based Access Delegation](#28-consent-based-access-delegation)
   - 2.9 [Transport Security — TLS](#29-transport-security--tls)
   - 2.10 [Timing Attack Resistance](#210-timing-attack-resistance)
3. [System Architecture](#3-system-architecture)
   - 3.1 [Layered Defence Model](#31-layered-defence-model)
   - 3.2 [Trust Boundaries](#32-trust-boundaries)
   - 3.3 [Module Responsibilities](#33-module-responsibilities)
4. [Threat Model — STRIDE Analysis](#4-threat-model--stride-analysis)
   - 4.1 [Assets](#41-assets)
   - 4.2 [Adversary Profiles](#42-adversary-profiles)
   - 4.3 [STRIDE Mapping](#43-stride-mapping)
   - 4.4 [Risk Register](#44-risk-register)
5. [Secure Protocol Design](#5-secure-protocol-design)
   - 5.1 [Authentication Protocol](#51-authentication-protocol)
   - 5.2 [Token Lifecycle](#52-token-lifecycle)
   - 5.3 [Encryption Protocol](#53-encryption-protocol)
   - 5.4 [Audit Chain Protocol](#54-audit-chain-protocol)
   - 5.5 [Consent Protocol](#55-consent-protocol)
6. [Security Aspects Demonstrated](#6-security-aspects-demonstrated)
   - 6.1 [Attack 1 — Replay Attack](#61-attack-1--replay-attack)
   - 6.2 [Attack 2 — Stale Timestamp](#62-attack-2--stale-timestamp)
   - 6.3 [Attack 3 — Privilege Escalation](#63-attack-3--privilege-escalation)
   - 6.4 [Attack 4 — User Enumeration](#64-attack-4--user-enumeration)
   - 6.5 [Attack 5 — Brute Force Detection](#65-attack-5--brute-force-detection)
   - 6.6 [Attack 6 — Audit Log Tampering](#66-attack-6--audit-log-tampering)
   - 6.7 [Attack 7 — Unauthorised Record Access](#67-attack-7--unauthorised-record-access)
   - 6.8 [Attack 8 — Cross-Patient Access](#68-attack-8--cross-patient-access)
   - 6.9 [Attack 9 — Draft Record Leakage](#69-attack-9--draft-record-leakage)
   - 6.10 [Attack 10 — AES-GCM Ciphertext Tampering](#610-attack-10--aes-gcm-ciphertext-tampering)
   - 6.11 [Attack 11 — Token Theft](#611-attack-11--token-theft)
7. [Security Design Decisions](#7-security-design-decisions)
8. [Demo Plan](#8-demo-plan)

---

## 1. Project Overview

**MedVault** is a production-grade secure medical records backend built for Rwandan healthcare institutions. It exposes a REST API (FastAPI + PostgreSQL) that provides:

- Authenticated, role-gated access to encrypted patient records
- Consent-controlled data sharing between patients and clinicians
- A tamper-evident, hash-chained audit trail on every sensitive operation
- Multi-factor authentication (password + TOTP)
- Replay attack prevention on all state-changing endpoints

The system was designed and implemented as a final project for the CMU Information Security course (Spring 2026), demonstrating the full security engineering lifecycle: requirements analysis → threat modelling → secure protocol design → implementation → adversarial testing.

**Tech stack:** Python 3.11+, FastAPI, PostgreSQL 15+, SQLAlchemy 2.x (async), PyJWT, bcrypt, custom RFC 6238 TOTP, AES-256-GCM, TLS 1.2+.

---

## 2. Theoretical Foundations

### 2.1 Symmetric Encryption — AES-256-GCM

**Theory.**
The Advanced Encryption Standard (AES) is a symmetric block cipher standardised by NIST (FIPS 197, 2001). It operates on 128-bit blocks with key sizes of 128, 192, or 256 bits. MedVault uses the 256-bit variant for maximum security margin.

Galois/Counter Mode (GCM) is an authenticated encryption with associated data (AEAD) mode of operation. It combines:

- **CTR mode** for confidentiality — the block cipher is used as a keystream generator; plaintext is XOR'd with the keystream, so no padding is needed.
- **GHASH** for integrity — a Galois field multiplication-based MAC produces a 128-bit authentication tag over the ciphertext (and optionally associated data).

The result is that a single primitive provides both **confidentiality** and **integrity/authenticity** — properties that AES-CBC alone cannot provide.

**Key properties:**
- Nonce (IV): 96 bits (12 bytes) is the recommended size for GCM; it must be unique per (key, message) pair. Reusing an IV with the same key catastrophically breaks both confidentiality and integrity.
- Authentication tag: 128 bits. Any modification to the ciphertext causes tag verification to fail.
- No padding: CTR mode is a stream cipher construction, so ciphertext length equals plaintext length.

**Implementation in MedVault.**
Every medical record and TOTP secret is encrypted with AES-256-GCM before storage. A fresh 12-byte random IV is generated for every encryption operation using `os.urandom(12)`, ensuring IV uniqueness even under concurrent writes. The ciphertext, IV, and tag are stored as separate columns (`encrypted_data`, `iv`, `tag`) in the database.

```
encrypt(plaintext, key) → (ciphertext, iv=os.urandom(12), tag)
decrypt(ciphertext, iv, tag, key) → plaintext  [raises InvalidTag on tampering]
```

Source: `app/core/crypto.py`

---

### 2.2 Password Hashing — bcrypt

**Theory.**
Passwords must never be stored in plaintext or with fast hash functions (MD5, SHA-256) because offline dictionary attacks become trivial if the database is breached. bcrypt (Niels Provos & David Mazières, 1999) is a password-hashing function designed to be computationally expensive and memory-hard.

Key properties:
- **Work factor (cost):** An integer parameter that controls the number of iterations (2^cost). Increasing it by 1 doubles the computation time, allowing the system to stay ahead of hardware improvements.
- **Random salt:** A 128-bit random salt is embedded in the output hash, preventing precomputed rainbow table attacks. Each password produces a unique hash even if two users share the same password.
- **Output format:** `$2b$<cost>$<22-char-salt><31-char-hash>` — the salt and cost are self-contained in the stored string.

**Implementation in MedVault.**
`bcrypt.hashpw(password.encode(), bcrypt.gensalt())` is called at registration. Verification uses `bcrypt.checkpw()`, which is constant-time by design. A dummy hash is pre-computed at startup and used when a login attempt targets a non-existent email, ensuring the response time is identical whether the email exists or not (preventing timing-based user enumeration).

Source: `app/services/auth_service.py`

---

### 2.3 HMAC-Based One-Time Passwords — TOTP (RFC 6238)

**Theory.**
TOTP (Time-based One-Time Password) is a two-factor authentication mechanism standardised in RFC 6238 (2011), built on top of HOTP (RFC 4226). It generates a short-lived numeric code from a shared secret and the current time.

**Algorithm (step by step):**

1. **Shared secret:** A 160-bit (20-byte) random value, base32-encoded for human readability and QR code compatibility.
2. **Time counter:** `T = floor(unix_time / 30)` — the counter advances every 30 seconds.
3. **HMAC-SHA1:** `H = HMAC-SHA1(secret_bytes, T_as_8_byte_big_endian)`
4. **Dynamic truncation:** Extract 4 bytes starting at offset `H[-1] & 0x0F`.
5. **Modulo:** `code = (truncated_int & 0x7FFFFFFF) mod 10^6` — produces a 6-digit code.
6. **Clock drift tolerance:** The verifier checks the current window ±1 (i.e., three consecutive 30-second windows) to account for clock skew between the authenticator and server.

**Security properties:**
- Codes are valid for at most 90 seconds (±1 window).
- An attacker who intercepts a code cannot reuse it after the window expires.
- The shared secret is never transmitted after enrollment; only the derived code is sent.
- Timing attacks are prevented by using `hmac.compare_digest()` for constant-time string comparison.

**Implementation in MedVault.**
The entire TOTP module (`app/core/totp.py`) is implemented from scratch using only Python's standard library (`hmac`, `hashlib`, `struct`, `time`, `os`, `base64`) — no third-party `pyotp` dependency. TOTP secrets are stored encrypted with AES-256-GCM under a dedicated `TOTP_ENCRYPTION_KEY` (separate from the record encryption key).

Source: `app/core/totp.py`

---

### 2.4 JSON Web Tokens — JWT (RFC 7519)

**Theory.**
A JWT is a compact, URL-safe token format for transmitting claims between parties. It consists of three base64url-encoded parts separated by dots:

```
header.payload.signature
```

- **Header:** `{"alg": "HS256", "typ": "JWT"}`
- **Payload:** JSON claims — `sub` (subject/user ID), `role`, `exp` (expiry), etc.
- **Signature:** `HMAC-SHA256(base64url(header) + "." + base64url(payload), secret_key)`

The signature binds the header and payload to the server's secret key. Any modification to the payload invalidates the signature, making the token tamper-evident. The server verifies the signature on every request — no database lookup is needed for stateless authentication.

**Security considerations:**
- The `exp` claim enforces token expiry. Expired tokens are rejected by the `jwt.decode()` call.
- Short expiry (15 minutes) limits the damage from token theft.
- The `partial` claim is used for tokens issued after password verification but before TOTP confirmation, preventing partial-auth tokens from accessing protected resources.

**Implementation in MedVault.**
Access tokens use HS256 with a 15-minute expiry. The RBAC middleware decodes and validates the token on every protected request. A `partial=True` claim is set on tokens issued mid-MFA-flow; the middleware rejects these with `401 Full authentication required`.

Source: `app/middleware/rbac.py`, `app/services/auth_service.py`

---

### 2.5 Hash-Chained Audit Logs

**Theory.**
A hash chain (also called a linked hash list) is a data structure where each entry contains the cryptographic hash of the previous entry. This creates a tamper-evident sequence: modifying any entry changes its hash, which breaks the chain from that point forward.

The construction used in MedVault:

```
chain_hash[0] = SHA-256(serialize(entry[0]) + "0"*64)
chain_hash[i] = SHA-256(serialize(entry[i]) + chain_hash[i-1])
```

Where `serialize()` produces a deterministic JSON string (sorted keys, no whitespace) of the entry's fields: `event_type`, `actor_id`, `resource_id`, `resource_type`, `client_ip`, `occurred_at`, `extra`.

**Security properties:**
- **Tamper detection:** Any modification to entry `i` changes `chain_hash[i]`, which then causes `chain_hash[i+1]` to be wrong, and so on. The verifier detects the first broken link.
- **Append-only enforcement:** The database application role has `INSERT + SELECT` only on `audit_log` — no `UPDATE` or `DELETE`. This prevents application-layer bypass.
- **Non-repudiation:** Every sensitive action is logged with actor ID, resource ID, client IP, and timestamp before the response is returned.

**Limitation:** A hash chain alone does not prevent deletion of the most recent entries (truncation). In production, this would be addressed by periodically publishing the latest chain hash to an external notary or blockchain anchor.

Source: `app/services/audit_service.py`

---

### 2.6 Replay Attack Prevention

**Theory.**
A replay attack occurs when an adversary captures a valid request and re-submits it to achieve an unintended effect (e.g., re-authenticating, re-submitting a transaction). Even over TLS, a captured request can be replayed if the server has no mechanism to detect duplicates.

The standard defence combines two controls:

1. **Nonce (number used once):** A unique random value included in every request. The server stores seen nonces and rejects any request whose nonce has been seen before.
2. **Timestamp:** The request includes the current UTC time. The server rejects requests whose timestamp is outside a configurable window (±5 minutes), preventing indefinite replay.

Together, these controls ensure that a captured request can only be replayed within a 5-minute window, and only once.

**Implementation in MedVault.**
The `ReplayGuard` middleware (`app/middleware/replay_guard.py`) is injected as a FastAPI dependency on all state-changing endpoints. It:
1. Parses `X-Timestamp` as ISO-8601 UTC and rejects if `|now - ts| > 300s`.
2. Queries `nonce_store` for the `X-Nonce` value; rejects if found.
3. Inserts the nonce with `expires_at = now + 5 minutes`.

The nonce store TTL matches the timestamp window, so the store never grows unboundedly.

Source: `app/middleware/replay_guard.py`

---

### 2.7 Role-Based Access Control — RBAC

**Theory.**
RBAC (NIST SP 800-207) assigns permissions to roles rather than individual users. Users are assigned roles; roles are assigned permissions. This simplifies administration and enforces the principle of least privilege.

MedVault defines seven roles:

| Role | Permissions |
|------|-------------|
| `Patient` | Read own published records; manage consent grants |
| `Doctor` | Create/read/update/delete records (with consent); request consent |
| `Nurse` | Create vitals/medication/triage records; read with consent |
| `Lab_Technician` | Create and read own records only |
| `Front_Desk` | Administrative tasks (no PHI access) |
| `Admin` | Read audit log; manage users |
| `SuperAdmin` | Full system access |

**Implementation in MedVault.**
The `require_roles(*roles)` factory in `app/middleware/rbac.py` returns a FastAPI dependency that decodes the JWT, extracts the `role` claim, and raises `403 Forbidden` if the role is not in the allowed set. Every protected endpoint is decorated with this dependency.

Source: `app/middleware/rbac.py`

---

### 2.8 Consent-Based Access Delegation

**Theory.**
In healthcare systems, patients have a legal and ethical right to control who accesses their medical records (HIPAA, GDPR Article 9). A consent management system implements this by requiring explicit patient approval before a clinician can access their data.

MedVault implements a time-limited consent grant model:

```
States: PENDING → ACTIVE → REVOKED
                         → EXPIRED
        PENDING → REJECTED
```

A doctor initiates a consent request; the patient approves or rejects it. Active grants have a configurable TTL (in hours). Patients can revoke active grants at any time. The records service checks for an active, non-expired grant before allowing a doctor to read a patient's record.

**Security properties:**
- Consent is checked at the data layer (inside `_can_read()`), not just at the API layer — a compromised route handler cannot bypass it.
- Every access attempt (granted or denied) is logged in the audit trail.
- Expired grants are not automatically deleted — they remain as an audit record.

Source: `app/services/consent_service.py`, `app/services/records_service.py`

---

### 2.9 Transport Security — TLS

**Theory.**

Transport Layer Security (TLS) is the cryptographic protocol that secures all data in transit between the client and the server. It operates in two phases:

1. **Handshake phase** — asymmetric cryptography (RSA or ECDSA) is used to authenticate the server and negotiate a shared session key. The server presents its X.509 certificate; the client verifies it against a trusted Certificate Authority (CA).
2. **Record phase** — all subsequent data is encrypted with a symmetric cipher (AES-128-GCM or AES-256-GCM in TLS 1.3, or negotiated in TLS 1.2) using the session key established in the handshake.

Without TLS, an attacker on the network can:
- **Passively eavesdrop** — read plaintext credentials, JWT tokens, and PHI in transit
- **Actively MITM** — intercept and modify requests or responses without either party knowing
- **Inject malicious content** — insert fake API responses or redirect authentication flows

**X.509 Certificate Structure.**

An X.509 certificate binds a public key to an identity. The key fields are:

| Field | Purpose |
|-------|---------|
| `Subject` | Who the certificate belongs to (CN, O, C) |
| `Issuer` | Who signed it (CA name, or itself for self-signed) |
| `Public Key` | The RSA/ECDSA public key clients use to verify the server |
| `Validity` | `Not Before` / `Not After` — the certificate's lifetime |
| `Subject Alternative Names (SAN)` | DNS names and IP addresses the cert is valid for |
| `Signature` | CA's digital signature over all the above fields |

**How MedVault's certificate was generated.**

For development and demonstration, a self-signed certificate was generated using OpenSSL:

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem \
  -days 365 -nodes \
  -subj "/C=RW/ST=Kigali/L=Kigali/O=MedVault/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
```

What each flag does:

| Flag | Meaning |
|------|---------|
| `req -x509` | Generate a self-signed certificate (skip the CSR/CA step) |
| `-newkey rsa:4096` | Generate a new 4096-bit RSA key pair alongside the certificate |
| `-keyout key.pem` | Write the private key to `key.pem` |
| `-out cert.pem` | Write the certificate to `cert.pem` |
| `-days 365` | Certificate is valid for one year |
| `-nodes` | Do not encrypt the private key with a passphrase (needed for unattended server startup) |
| `-subj "..."` | Set the Subject field: Country=RW, State/City=Kigali, Org=MedVault, CN=localhost |
| `-addext "subjectAltName=..."` | Add SAN extension for `localhost` and `127.0.0.1` — required by modern browsers |

The resulting files:
- `cert.pem` — the public certificate (safe to share, sent to every client during the TLS handshake)
- `key.pem` — the private key (must be kept secret; anyone with this file can impersonate the server)

**How the server uses them.**

Uvicorn (the ASGI server) is started with:

```bash
uvicorn app.main:app \
  --ssl-certfile cert.pem \
  --ssl-keyfile key.pem \
  --host 0.0.0.0 \
  --port 8000
```

This tells Uvicorn to wrap every TCP connection in a TLS session before passing it to FastAPI. The application code never sees unencrypted bytes — TLS termination happens at the transport layer.

**Self-signed vs CA-signed — trust model.**

| Property | Self-signed (dev) | CA-signed (production) |
|----------|-------------------|----------------------|
| Who signs it | The server itself | A trusted Certificate Authority (e.g., Let's Encrypt, DigiCert) |
| Browser trust | ❌ Browser shows "Not Secure" warning | ✅ Trusted automatically |
| Cost | Free | Free (Let's Encrypt) or paid |
| Revocation | Not possible | CRL / OCSP supported |
| MITM protection | Partial — client must manually accept the cert | Full — CA chain verified automatically |

For the demo, clients must either accept the browser warning or pass `-SkipCertificateCheck` in PowerShell. This is acceptable for a controlled demo environment but would be unacceptable in production.

**Security properties provided by TLS in MedVault.**

- **Confidentiality** — JWT tokens, passwords, TOTP codes, and PHI are encrypted in transit. A network attacker sees only ciphertext.
- **Integrity** — the TLS record MAC detects any modification of data in transit. An attacker cannot flip bits in a request without the connection being torn down.
- **Server authentication** — the certificate proves the client is talking to the real MedVault server, not an impostor. (Client authentication is not used — identity is established via JWT after the TLS handshake.)
- **Forward secrecy** — TLS 1.3 (and TLS 1.2 with ECDHE cipher suites) uses ephemeral key exchange. Compromising the server's private key later does not decrypt previously recorded sessions.

**Why TLS alone is not sufficient.**

TLS protects data in transit but does nothing for:
- Data at rest (handled by AES-256-GCM field encryption)
- Replay attacks (handled by nonce + timestamp)
- Authorisation (handled by RBAC + consent)
- Audit trail integrity (handled by SHA-256 hash chain)

This is why MedVault uses defence in depth — TLS is the outermost layer, not the only layer.

---

### 2.10 Timing Attack Resistance

**Theory.**
A timing attack exploits measurable differences in execution time to infer secret information. For example, a naive string comparison `a == b` returns early on the first mismatched character — an attacker can measure response times to determine how many characters of a guess are correct.

The defence is **constant-time comparison**: the comparison always takes the same amount of time regardless of where the strings differ. Python's `hmac.compare_digest(a, b)` implements this.

**Implementation in MedVault.**
- TOTP verification uses `hmac.compare_digest(expected, code)` — an attacker cannot determine how close their guess is by measuring response time.
- Password verification uses `bcrypt.checkpw()`, which is constant-time by design.
- Login with a non-existent email runs `_verify_password(password, _DUMMY_HASH)` to ensure the response time is identical to a failed login with a real email.

Source: `app/core/totp.py`, `app/services/auth_service.py`

---
## 3. System Architecture

### 3.1 Layered Defence Model

MedVault applies **defence in depth** — every request passes through multiple independent security layers before reaching business logic or data. A bypass at one layer does not grant access to the next.

```
┌─────────────────────────────────────────────────────┐  ← UNTRUSTED ZONE
│  Client (Browser / Mobile / API Consumer)           │
└──────────────────────┬──────────────────────────────┘
                       │ HTTPS only
┌──────────────────────▼──────────────────────────────┐
│  TLS 1.2+ Transport Layer                           │
│  Encrypts all traffic; prevents eavesdropping/MITM  │
└──────────────────────┬──────────────────────────────┘
                       │                                ← TRUST BOUNDARY
┌──────────────────────▼──────────────────────────────┐  ← TRUSTED ZONE
│  Replay Guard Middleware                            │
│  Validates X-Nonce (unique) + X-Timestamp (±5 min) │
└──────────────────────┬──────────────────────────────┘
┌──────────────────────▼──────────────────────────────┐
│  RBAC Middleware                                    │
│  Decodes JWT, verifies signature, checks role       │
└──────────────────────┬──────────────────────────────┘
┌──────────────────────▼──────────────────────────────┐
│  FastAPI Routers                                    │
│  Auth / Records / Consent / Audit / Users           │
└──────────────────────┬──────────────────────────────┘
┌──────────────────────▼──────────────────────────────┐
│  Service Layer                                      │
│  Business logic, consent checks, encryption calls  │
└──────────────────────┬──────────────────────────────┘
┌──────────────────────▼──────────────────────────────┐
│  PostgreSQL                                         │
│  Encrypted PHI · Hash-chained audit log             │
│  App role: INSERT+SELECT only on audit_log          │
└─────────────────────────────────────────────────────┘
```

### 3.2 Trust Boundaries

| Zone | Components | Assumption |
|------|-----------|------------|
| **Untrusted** | Browsers, mobile apps, third-party clients | All input is hostile; all traffic may be intercepted |
| **Trusted** | FastAPI process, service layer, PostgreSQL | Same private network; asyncpg pool over Unix socket or private LAN |
| **DB privilege boundary** | `audit_log` table | Application role has `INSERT + SELECT` only — no `UPDATE` or `DELETE` even if the app process is compromised |

### 3.3 Module Responsibilities

| Module | File | Responsibility |
|--------|------|----------------|
| Key Manager | `app/core/key_manager.py` | Load and validate `RECORD_ENCRYPTION_KEY` and `TOTP_ENCRYPTION_KEY` at startup |
| Crypto | `app/core/crypto.py` | AES-256-GCM encrypt / decrypt |
| TOTP | `app/core/totp.py` | RFC 6238 code generation and verification |
| Replay Guard | `app/middleware/replay_guard.py` | Nonce + timestamp validation |
| RBAC | `app/middleware/rbac.py` | JWT decode, role enforcement |
| Auth Service | `app/services/auth_service.py` | Registration, login, MFA, token refresh, password reset |
| Records Service | `app/services/records_service.py` | CRUD with encryption, consent gate, audit calls |
| Consent Service | `app/services/consent_service.py` | Grant lifecycle management |
| Audit Service | `app/services/audit_service.py` | Append entries, verify chain, list with filters |

---

## 4. Threat Model — STRIDE Analysis

### 4.1 Assets

| # | Asset | Location | Sensitivity |
|---|-------|----------|-------------|
| 1 | Protected Health Information (PHI) | `medical_records.encrypted_data` | Critical |
| 2 | Authentication credentials | `users.password_hash`, `mfa_secrets` | Critical |
| 3 | JWT signing key | Environment variable `JWT_SECRET_KEY` | Critical |
| 4 | Encryption keys | `RECORD_ENCRYPTION_KEY`, `TOTP_ENCRYPTION_KEY` | Critical |
| 5 | Audit trail | `audit_log` table | High |
| 6 | Consent grants | `consent_grants` table | High |
| 7 | Refresh tokens | `refresh_tokens.token_hash` | High |

### 4.2 Adversary Profiles

| Adversary | Capabilities | Goals |
|-----------|-------------|-------|
| External attacker | Network access, captured HTTP traffic | Steal PHI, forge tokens, replay requests |
| Malicious insider (staff) | Valid credentials, DB read access | Escalate privileges, access unauthorised records |
| Compromised DB admin | Direct PostgreSQL access | Modify audit log, read encrypted data |
| Rogue doctor | Valid JWT, no consent grant | Access patient records without consent |
| Passive eavesdropper | Network tap | Intercept credentials or tokens in transit |

### 4.3 STRIDE Mapping

| Threat | Category | Attack Vector | Mitigation |
|--------|----------|--------------|------------|
| Credential theft | **S**poofing | Phishing, keylogger | TOTP MFA; 15-min token expiry |
| JWT forgery | **S**poofing | Crafted token | HMAC-SHA256 signature; `exp` claim |
| Ciphertext tampering | **T**ampering | Direct DB write | AES-GCM authentication tag |
| Audit log modification | **T**ampering | Direct DB write | SHA-256 hash chain; INSERT-only role |
| Hiding malicious actions | **R**epudiation | DB modification | Hash chain detects any edit |
| PHI exposure (DB breach) | **I**nformation Disclosure | DB dump | AES-256-GCM field encryption |
| Token interception | **I**nformation Disclosure | Network tap | TLS; short token expiry |
| Replay attack | **D**enial of Service / Spoofing | Captured request | Nonce + timestamp window |
| Privilege escalation | **E**levation of Privilege | Role manipulation | `require_roles()` on every endpoint |
| Cross-patient access | **E**levation of Privilege | Modified `patient_id` | Ownership check in `_can_read()` |

### 4.4 Risk Register

| Threat | Likelihood | Impact | Risk Level | Mitigation |
|--------|-----------|--------|-----------|------------|
| Credential theft / phishing | High | Critical | 🔴 Critical | TOTP MFA; 15-min token expiry |
| DB breach — PHI exposure | Medium | Critical | 🔴 High | AES-256-GCM field encryption |
| Replay attack | Medium | High | 🟠 High | Nonce + 5-min timestamp window |
| Unauthorised record access | Medium | High | 🟠 High | Consent grant check |
| Privilege escalation | Low | High | 🟠 Medium | RBAC on every endpoint |
| Audit log tampering | Low | Critical | 🟠 Medium | SHA-256 hash chain; DB INSERT-only |
| JWT forgery | Low | Critical | 🟠 Medium | HMAC-SHA256 sig; short expiry |
| Timing attack on TOTP | Low | Medium | 🟢 Low | `hmac.compare_digest()` |

---

## 5. Secure Protocol Design

### 5.1 Authentication Protocol

The full login flow is a two-step protocol: password verification followed by TOTP confirmation.

```
Client                    MedVault API                  PostgreSQL
  │                            │                             │
  │── POST /auth/login ────────►│                             │
  │   X-Nonce: <uuid>           │── validate nonce+timestamp ─►│
  │   X-Timestamp: <iso>        │◄─ OK ───────────────────────│
  │   {email, password}         │── SELECT user WHERE email=? ►│
  │                             │◄─ user row ─────────────────│
  │                             │── bcrypt.verify() ──────────│
  │◄── 200 {mfa_required:true} ─│                             │
  │    partial_token            │                             │
  │                             │                             │
  │── POST /auth/mfa-verify ───►│                             │
  │   {partial_token, code}     │── SELECT mfa_secret ────────►│
  │                             │◄─ encrypted_secret,iv,tag ──│
  │                             │── AES-GCM decrypt ──────────│
  │                             │── TOTP.verify(code) ────────│
  │                             │── INSERT refresh_token hash ►│
  │◄── 200 {access_token,       │                             │
  │         refresh_token} ─────│                             │
  │                             │                             │
  │── GET /records ────────────►│                             │
  │   Authorization: Bearer ... │── JWT.verify() ─────────────│
  │                             │── RBAC check ───────────────│
  │                             │── consent check ────────────│
  │◄── 200 {decrypted record} ──│                             │
```

### 5.2 Token Lifecycle

```
Registration
    │
    ▼
Login (password ✓)
    │
    ▼
Partial JWT issued (partial=true, exp=5min)
    │
    ▼
TOTP verification (code ✓)
    │
    ▼
Full JWT issued (exp=15min) + Refresh token (exp=7d, stored as SHA-256 hash)
    │
    ├── Access token used for API calls (stateless, verified by signature)
    │
    └── Refresh token used to rotate:
            old token → revoked=true
            new token → issued (rotation)
```

**Key properties:**
- Access tokens are stateless — no DB lookup on every request.
- Refresh tokens are stored as SHA-256 hashes — the plaintext is never persisted.
- Token rotation means a stolen refresh token can only be used once.
- Password reset revokes **all** refresh tokens for the user.

### 5.3 Encryption Protocol

```
Write path (create/update record):
  plaintext (JSON) → AES-256-GCM(key, iv=os.urandom(12)) → (ciphertext, iv, tag)
  Store: encrypted_data=ciphertext, iv=iv, tag=tag

Read path (get record):
  Fetch: ciphertext, iv, tag from DB
  AES-256-GCM-decrypt(ciphertext, iv, tag, key) → plaintext
  [raises InvalidTag if any byte was modified]
```

Two separate keys are used:
- `RECORD_ENCRYPTION_KEY` — encrypts PHI in `medical_records`
- `TOTP_ENCRYPTION_KEY` — encrypts TOTP secrets in `mfa_secrets`

This limits blast radius: compromising one key does not expose data protected by the other.

### 5.4 Audit Chain Protocol

```
On every sensitive action:

  prev_hash = SELECT chain_hash FROM audit_log ORDER BY id DESC LIMIT 1
              (or "0"*64 if table is empty)

  entry_data = JSON.serialize({
    event_type, actor_id, resource_id, resource_type,
    client_ip, occurred_at, extra
  }, sort_keys=True)

  chain_hash = SHA-256(entry_data + prev_hash)

  INSERT INTO audit_log (..., chain_hash=chain_hash)

Verification (GET /audit/verify):
  For each entry in order:
    expected = SHA-256(serialize(entry) + prev_hash)
    if expected != entry.chain_hash → BROKEN at this entry
    prev_hash = entry.chain_hash
```

### 5.5 Consent Protocol

```
Doctor                    API                       Patient
  │                        │                           │
  │── POST /consent ───────►│                           │
  │   {patient_email,       │── INSERT consent_grant ───►│
  │    duration_hours}      │   status=PENDING           │
  │◄── 201 {grant_id} ──────│                           │
  │                         │                           │
  │                         │◄── POST /consent/{id}/approve
  │                         │    (patient approves)      │
  │                         │── UPDATE status=ACTIVE ────│
  │                         │── expires_at = now+hours ──│
  │                         │                           │
  │── GET /records ─────────►│                           │
  │   (with active grant)   │── _can_read() → True ──────│
  │◄── 200 {record} ─────────│                           │
  │                         │                           │
  │                         │◄── POST /consent/{id}/revoke
  │                         │── UPDATE status=REVOKED ───│
  │── GET /records ─────────►│                           │
  │   (grant revoked)       │── _can_read() → False ─────│
  │◄── 403 Access denied ───│                           │
```

---
## 6. Security Aspects Demonstrated

Each attack is implemented as a runnable Python script in `attacks/` and documented in `ATTACKS.md`. The table below maps each attack to its script, the defence mechanism, and the exact code location.

| # | Attack | Script | Defence | Code |
|---|--------|--------|---------|------|
| 1 | Replay Attack | `attacks/01_replay_attack.py` | Nonce + timestamp | `middleware/replay_guard.py` |
| 2 | Stale Timestamp | `attacks/02_stale_timestamp.py` | ±5-min window | `middleware/replay_guard.py` |
| 3 | Privilege Escalation | `attacks/03_privilege_escalation.py` | `require_roles()` | `middleware/rbac.py` |
| 4 | User Enumeration | `attacks/04_jwt_forgery.py` | Identical error | `services/auth_service.py` |
| 5 | Brute Force | `attacks/05_user_enumeration.py` | `LOGIN_FAILED` audit | `services/auth_service.py` |
| 6 | Audit Tampering | `attacks/07_audit_tampering.py` | SHA-256 hash chain | `services/audit_service.py` |
| 7 | Unauthorised Access | `attacks/08_unauthorized_record_access.py` | Consent gate | `services/records_service.py` |
| 8 | Cross-Patient Access | `attacks/09_cross_patient_access.py` | Ownership check | `services/records_service.py` |
| 9 | Draft Record Leakage | `attacks/10_draft_record_leakage.py` | Status filter | `services/records_service.py` |
| 10 | AES-GCM Tampering | `attacks/11_aes_gcm_tampering.py` | GCM auth tag | `core/crypto.py` |
| 11 | Token Theft | (implicit in auth flow) | 15-min expiry + rotation | `services/auth_service.py` |

---

### 6.1 Attack 1 — Replay Attack

**Threat:** An attacker captures a valid `POST /auth/login` request (including `X-Nonce` and `X-Timestamp` headers) and re-submits it verbatim to obtain a second authentication token.

**Why it works without defence:** HTTP is stateless. Without a uniqueness check, the server cannot distinguish a legitimate request from a captured replay.

**Defence — Nonce store:**
The `ReplayGuard` middleware stores every `X-Nonce` value in `nonce_store` with a 5-minute TTL. On the second submission, the nonce is found in the store and the request is rejected before any authentication logic runs.

```text
First request  → nonce not in store → INSERT nonce → process → 200 OK
Second request → nonce found in store → 400 REPLAY_NONCE_SEEN
```text

**Expected demo output:**
```text
=== First request (legitimate) ===
200 OK — token issued

=== Second request (REPLAY ATTACK) ===
BLOCKED: 400 {"detail":"Nonce already used","error_code":"REPLAY_NONCE_SEEN"}
```text

---

### 6.2 Attack 2 — Stale Timestamp

**Threat:** An attacker replays a request with a timestamp from the distant past (e.g., `2020-01-01T00:00:00Z`), hoping the server will still process it.

**Defence — Timestamp window:**
The middleware computes `|now - X-Timestamp|` in seconds. If the skew exceeds 300 seconds (5 minutes), the request is rejected with `400 REPLAY_TIMESTAMP_SKEW`.

**Why both controls are needed:** Nonce alone is insufficient — an attacker could generate a fresh nonce for an old request body. Timestamp alone is insufficient — within the 5-minute window, the same request could be replayed multiple times. Together they guarantee: **at most once, within 5 minutes**.

---

### 6.3 Attack 3 — Privilege Escalation (Patient → Doctor)

**Threat:** A `Patient`-role user sends `POST /records` (a Doctor-only action) using their own valid JWT, attempting to create a medical record.

**Why it matters:** Without role enforcement, any authenticated user could perform any action. A patient could create fake diagnoses or access other patients' records.

**Defence — `require_roles()` decorator:**
The dependency decodes the JWT, checks `claims.role` against the allowed set, and raises `403 Forbidden` before the handler body executes. The patient's valid JWT is not enough — the role claim embedded in it must match.

```text
BLOCKED: 403 {"detail":"Insufficient permissions","error_code":"FORBIDDEN"}
```text

---

### 6.4 Attack 4 — User Enumeration

**Threat:** An attacker probes `POST /auth/login` with different email addresses, comparing error messages to build a list of valid accounts.

**Defence — Identical error responses:**
Both "email does not exist" and "wrong password" return the exact same HTTP status and body: `{"detail": "Invalid credentials", "error_code": "INVALID_CREDENTIALS"}`. Additionally, when the email does not exist, the server still runs `bcrypt.checkpw(password, _DUMMY_HASH)` so the response time is identical. This defeats both message-based and timing-based enumeration.

---

### 6.5 Attack 5 — Brute Force Detection

**Threat:** An attacker submits many password guesses against a known account in rapid succession.

**Defence — Audit trail logging:**
Every failed login attempt is appended to the audit log as a `LOGIN_FAILED` event, recording the actor ID, client IP, and reason (`wrong_password` or `unknown_email`). Administrators query `GET /audit` to detect accounts with many consecutive failures.

> **Note:** Rate limiting and automatic lockout are not yet implemented — the audit trail provides the detection signal; response is currently manual. This is a known gap for production hardening.

---

### 6.6 Attack 6 — Audit Log Tampering

**Threat:** An attacker with direct PostgreSQL access modifies an audit entry to hide their actions:
```sql
UPDATE audit_log SET event_type = 'TAMPERED_BY_ATTACKER' WHERE id = 1;
```sql

**Why it matters:** Without tamper detection, a malicious insider could erase evidence of unauthorised access, making forensic investigation impossible.

**Defence — SHA-256 hash chain:**
The `GET /audit/verify` endpoint recomputes every chain hash from scratch. Modifying entry 1 changes its expected hash, which no longer matches the stored value. This mismatch propagates forward — every subsequent entry's hash is now wrong. The verifier reports the first broken link.

**DB-level enforcement:** The application database role has `INSERT + SELECT` only on `audit_log`. Even if the application is fully compromised, the attacker cannot issue `UPDATE` or `DELETE` through the application connection.

**Expected output after tampering:**
```json
{"chain_intact": false, "entries_checked": 42, "first_broken_at_id": 1, "broken_entry_event": "TAMPERED_BY_ATTACKER"}
```json

---

### 6.7 Attack 7 — Unauthorised Record Access (No Consent)

**Threat:** A `Doctor`-role user with a valid JWT but no active consent grant attempts to read a patient's medical records.

**Defence — Consent gate in `_can_read()`:**
`has_consent` is resolved by querying `consent_grants` for an active, non-expired grant between this doctor and this patient. Without one, `_can_read()` returns `False` and the service raises `403 Forbidden`. The denied attempt is logged as `ACCESS_DENIED` in the audit trail.

**Why this is checked at the service layer, not just the route:** A compromised or buggy route handler cannot bypass the consent check — it is enforced inside the business logic function that actually retrieves and decrypts the record.

---

### 6.8 Attack 8 — Cross-Patient Access

**Threat:** A `Patient`-role user supplies a different `patient_id` in `GET /records?patient_id=<other_uuid>`, attempting to read another patient's records.

**Defence — Ownership check:**
The patient's own UUID (extracted from the JWT `sub` claim, which they cannot forge) is compared against the record's `patient_id`. A mismatch returns `False` regardless of what `patient_id` was supplied in the query parameter.

---

### 6.9 Attack 9 — Draft Record Leakage

**Threat:** A patient attempts to read a record that a clinician has saved as a draft (not yet published), potentially seeing incomplete or unreviewed clinical notes.

**Defence — Status filter:**
The `status == "published"` condition means draft records are invisible to patients. Only the record's creator can see their own drafts. This is enforced in both `get_record()` and `list_records()`.

**Demo script:** `attacks/10_draft_record_leakage.py` creates a draft record, attempts to read it as the patient (`403`), publishes it, then confirms the patient can read it (`200`).

---

### 6.10 Attack 10 — AES-GCM Ciphertext Tampering

**Threat:** An attacker with database access flips a byte in the `encrypted_data` column of `medical_records`, hoping to alter a patient's diagnosis without detection. This attack would succeed against AES-CBC.

**Why AES-CBC is vulnerable:** In CBC mode, a bit flip in ciphertext block `i` corrupts block `i` during decryption but produces a predictable, controlled modification in block `i+1`. An attacker can use this to alter specific bytes of plaintext.

**Defence — GCM authentication tag:**
AES-256-GCM computes a 128-bit authentication tag over the entire ciphertext during encryption. During decryption, the tag is recomputed and compared. Any modification — even a single bit flip — causes `cryptography.exceptions.InvalidTag` to be raised before any plaintext is returned.

**Demo steps:**
1. Doctor creates a record: `{"diagnosis": "Hypertension", "severity": "Moderate"}`  
2. Patient reads it successfully  
3. Attacker runs in psql: `UPDATE medical_records SET encrypted_data = set_byte(encrypted_data, 0, get_byte(encrypted_data, 0) # 255) WHERE id = '<uuid>';`  
4. Patient tries to read → server returns `500` (InvalidTag caught by global handler)

See full documentation: `attacks/11_aes_gcm_tampering.md`  
Source: `app/core/crypto.py`  

---

### 6.11 Attack 11 — Token Theft

**Threat:** An attacker steals a JWT access token (from browser localStorage, a network capture, or a server log) and uses it to impersonate the victim after the legitimate session ends.

**Defence — Short expiry + refresh token rotation:**

- **Access tokens** expire after 15 minutes. A stolen token becomes useless after expiry.
- **Refresh tokens** are rotated on every use. If an attacker steals a refresh token and uses it, the legitimate user's next refresh attempt will fail (the old token is revoked), alerting them to the compromise.
- **Refresh tokens are stored as SHA-256 hashes.** Even if the database is breached, the attacker cannot use the stored hashes directly.
- **Password reset revokes all sessions.** A user who suspects compromise can reset their password, which sets `revoked=True` on all their refresh tokens.

---

## 7. Security Design Decisions

The table below documents every significant security design choice, the alternative considered, and the justification.

| Decision | Alternative Considered | Justification |
|----------|----------------------|---------------|
| **AES-256-GCM** for PHI | AES-256-CBC + HMAC | GCM provides authenticated encryption in a single primitive. CBC requires a separate MAC and is vulnerable to padding oracle attacks (POODLE, BEAST). |
| **Random 12-byte IV per operation** | Counter-based or deterministic IV | IV reuse in GCM is catastrophic — it reveals the keystream XOR of two plaintexts and breaks the authentication tag. `os.urandom(12)` guarantees uniqueness. |
| **Custom TOTP (stdlib only)** | `pyotp` library | Eliminates a supply-chain dependency. Demonstrates RFC 6238 compliance from first principles. The implementation is ~100 lines and fully auditable. |
| **`hmac.compare_digest()` for TOTP** | `expected == code` | Python's `==` on strings short-circuits on the first mismatch, leaking timing information. `hmac.compare_digest()` always takes the same time. |
| **SHA-256 hash-chained audit** | Append-only table only | A plain append-only table can be silently truncated by a DB admin. The hash chain makes any modification detectable, even by the patient (scoped verify). |
| **DB-level INSERT+SELECT on `audit_log`** | Application-level enforcement | A compromised application process cannot issue `UPDATE`/`DELETE` through its own DB connection. Defence in depth. |
| **Separate `RECORD_ENCRYPTION_KEY` and `TOTP_ENCRYPTION_KEY`** | Single master key | Limits blast radius. A compromised record key does not expose TOTP secrets, and vice versa. |
| **15-minute JWT access token expiry** | Long-lived tokens (hours/days) | Limits the window of opportunity for a stolen token. Stateless verification means there is no server-side revocation for access tokens — short expiry is the only mitigation. |
| **Refresh token rotation** | Static refresh tokens | A stolen refresh token can only be used once before it is invalidated. The legitimate user's next refresh will fail, signalling the compromise. |
| **Identical error for wrong email/password** | Distinct error messages | Distinct messages allow an attacker to enumerate valid email addresses. Identical messages + dummy bcrypt check prevent both message-based and timing-based enumeration. |
| **`partial=True` JWT claim for MFA flow** | Session state or separate endpoint | Allows stateless MFA flow without server-side session storage. The partial token cannot access protected resources — the RBAC middleware rejects it explicitly. |
| **Consent checked at service layer** | Route-level guard only | A buggy or compromised route handler cannot bypass the consent check. The data is never decrypted unless `_can_read()` returns `True`. |
| **Soft delete (`is_deleted` flag)** | Hard `DELETE` | Preserves the audit trail. A hard delete would remove the record but leave orphaned audit entries. Soft delete keeps the record row for forensic purposes. |

---

## 8. Demo Plan

The demo is a live walkthrough of the running system, progressing from normal operation through escalating attack scenarios. Total estimated time: **25–30 minutes**.

### Prerequisites (set up before the demo)

```bash
# 1. Start the server
uvicorn app.main:app --ssl-certfile cert.pem --ssl-keyfile key.pem --host 0.0.0.0 --port 8000

# 2. Open a second terminal for psql (DB-level attacks)
psql -U medvault_user -d medical_records

# 3. Open ATTACKS.md for reference commands
# 4. Load the PowerShell helper function Get-ReplayHeaders from ATTACKS.md
```bash

---

### Phase 1 — Normal Operation (5 min)

**Goal:** Show the system working correctly before any attacks.

| Step | Action | What to show |
|------|--------|-------------|
| 1.1 | Register `patient@demo.com` | `201 Created`, role stored |
| 1.2 | Register `doctor@demo.com` | `201 Created` |
| 1.3 | Login as patient | `200 OK`, token pair issued |
| 1.4 | Doctor requests consent for patient | `201 PENDING` grant |
| 1.5 | Patient approves consent | `200 ACTIVE` grant |
| 1.6 | Doctor creates a medical record | `201`, ciphertext visible in DB |
| 1.7 | Patient reads the record | `200`, decrypted JSON returned |
| 1.8 | Show `GET /audit` | Hash-chained entries for all above actions |

**Talking point:** Every action is logged. The audit trail already has 8+ entries from normal use. Show the `chain_hash` column in the DB — it looks like random hex, but it links every entry to the previous one.

---

### Phase 2 — Authentication Attacks (8 min)

**Goal:** Show that the authentication layer is hardened against common attacks.

#### Demo 2.1 — Replay Attack (`attacks/01_replay_attack.py`)
1. Send a login request with a fixed nonce → `200 OK`  
2. Resend the identical request → `400 REPLAY_NONCE_SEEN`  
3. **Explain:** The nonce is stored for 5 minutes. The second request is blocked before bcrypt even runs.

#### Demo 2.2 — Stale Timestamp
1. Send a login request with `X-Timestamp: 2020-01-01T00:00:00Z` → `400 REPLAY_TIMESTAMP_SKEW`  
2. **Explain:** The ±5-minute window prevents indefinite replay even with a fresh nonce.

#### Demo 2.3 — User Enumeration (`attacks/04_jwt_forgery.py`)
1. Login with `nobody@nowhere.com` / any password → `401 INVALID_CREDENTIALS`  
2. Login with `patient@demo.com` / wrong password → `401 INVALID_CREDENTIALS`  
3. **Show:** Both responses are byte-for-byte identical. Response times are also equal (dummy bcrypt).  
4. **Explain:** An attacker cannot determine which emails are registered.

#### Demo 2.4 — Brute Force Visibility
1. Run 5 failed logins against `patient@demo.com`  
2. Login as admin, query `GET /audit`  
3. **Show:** 5 `LOGIN_FAILED` entries with client IP and reason.  
4. **Explain:** The audit trail is the detection signal for brute force.

---

### Phase 3 — Authorisation Attacks (7 min)

**Goal:** Show that role and consent enforcement cannot be bypassed.

#### Demo 3.1 — Privilege Escalation (`attacks/03_privilege_escalation.py`)
1. Use the patient's JWT to call `POST /records` → `403 FORBIDDEN`  
2. **Show:** The patient's token is valid, but the role claim is `Patient`, not `Doctor`.  
3. **Explain:** `require_roles()` checks the role embedded in the JWT signature — the patient cannot forge a different role without the server's secret key.

#### Demo 3.2 — Unauthorised Record Access (`attacks/08_unauthorized_record_access.py`)
1. Register `doctor2@demo.com` with no consent grant  
2. Doctor2 tries `GET /records/<id>` → `403 Access denied`  
3. **Show:** `ACCESS_DENIED` event in audit log  
4. **Explain:** The consent check is inside `_can_read()` at the service layer — not just a route guard.

#### Demo 3.3 — Draft Record Leakage (`attacks/10_draft_record_leakage.py`)
1. Doctor creates a draft record  
2. Patient tries to read it → `403`  
3. Doctor publishes it  
4. Patient reads it → `200`  
5. **Explain:** `status == "published"` is a hard requirement for patient access.

---

### Phase 4 — Data Integrity Attacks (7 min)

**Goal:** Show that encrypted data and the audit trail cannot be silently modified.

#### Demo 4.1 — AES-GCM Ciphertext Tampering (`attacks/11_aes_gcm_tampering.py`)
1. Doctor creates a record: `{"diagnosis": "Hypertension"}`  
2. Patient reads it → `200 {"diagnosis": "Hypertension"}`  
3. In psql, flip one byte:  
```sql
UPDATE medical_records
SET encrypted_data = set_byte(encrypted_data, 0, get_byte(encrypted_data, 0) # 255)
WHERE id = '<uuid>';
```sql
4. Patient tries to read → `500` (InvalidTag)  
5. **Explain:** AES-GCM's authentication tag covers every byte of ciphertext. A single bit flip is detected. Compare with AES-CBC where bit flips produce controlled plaintext changes.

#### Demo 4.2 — Audit Log Tampering (`attacks/07_audit_tampering.py`)
1. Run `GET /audit/verify` → `{"chain_intact": true, "entries_checked": N}`  
2. In psql: `UPDATE audit_log SET event_type = 'TAMPERED' WHERE id = 1;`  
3. Run `GET /audit/verify` → `{"chain_intact": false, "first_broken_at_id": 1}`  
4. **Explain:** SHA-256 hash chain. Modifying entry 1 breaks the hash at entry 2, and every entry after it.  
5. **Show:** Even the patient can run `GET /audit/verify` on their own entries.

---

### Phase 5 — Wrap-Up (3 min)

**Goal:** Summarise the defence-in-depth model.

```text
Client
  │  TLS — encrypts the channel
  ▼
Replay Guard — blocks duplicate/stale requests
  ▼
RBAC Middleware — verifies JWT, enforces roles
  ▼
Service Layer — enforces consent, ownership, status
  ▼
AES-256-GCM — encrypts PHI at rest
  ▼
PostgreSQL — append-only audit log (INSERT+SELECT only)
```text

**Key message:** No single control is relied upon exclusively. An attacker who bypasses TLS still faces JWT verification. An attacker with a valid JWT still faces RBAC and consent checks. An attacker with DB access still faces AES-GCM encryption and hash-chain tamper detection.

**Questions to anticipate:**
- *"Why not use a library for TOTP?"* — Supply-chain risk; the stdlib implementation is ~100 lines and fully auditable.
- *"What about rate limiting?"* — Currently relies on audit trail for detection; automatic lockout is a production hardening item.
- *"What if the encryption key is compromised?"* — Separate keys for records vs TOTP limit blast radius. Key rotation would require re-encrypting all records — a planned but not yet implemented feature.
- *"Can the hash chain be anchored externally?"* — Yes; publishing the latest `chain_hash` to a public ledger or notary would prevent truncation attacks. Not implemented in this prototype.

---

*End of Final Technical Report*

