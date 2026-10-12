# IBM Confidential Computing Contract Generator
## Technical Presentation

**Audience:** Engineering, Security, Architecture, DevOps
**Duration:** 30-40 minutes
**Date:** April 23, 2026
**Version:** 0.7 (aligned with codebase — post session fixes)

---

## Slide 1: Scope
- V2 architecture evolution: backend-native contract cryptography with HashiCorp Vault integration
- Trust boundaries and cryptographic key custody model
- Security control model across backend and desktop app
- Build workflow, authorization, and verification behavior (including post-finalization attestation evidence)
- Deployment topology and production hardening baseline
- Outstanding hardening opportunities

---

## Slide 2: End-to-End Architecture (V2)
- **Electron desktop app**: Persona UX, local identity-key signing (RSA-4096), request orchestration
- **Go backend**: Auth, setup restrictions, RBAC + assignment checks, workflow state transitions, **backend-native contract cryptography via `contract-go` v2 engine**
- **PostgreSQL**: Encrypted section artifacts, workflow metadata, audit chain events, build key references (AES-256-CBC encrypted PEM blobs)
- **Key Provider (DB)**: Build-scoped signing/attestation keys stored as encrypted PEM in PostgreSQL via `keymgmt/db` provider — no HashiCorp Vault dependency in current deployment
- **nginx reverse proxy**: TLS termination, rate limiting, security headers in production

---

## Slide 3: Trust Boundaries and Key Custody Model
**Identity Keys (Client-Side):**
- RSA-4096 identity keys generated and stored locally on user machines
- Private keys never transmitted to backend
- Used for request signing and audit event signatures
- 90-day expiration with forced rotation

**Build Keys (DB Key Provider):**
- Signing keys: RSA-4096, stored as AES-256-CBC encrypted PEM blobs in PostgreSQL (`keymgmt/db` provider)
- Attestation keys: RSA-4096, same encrypted PEM storage or uploaded public key
- Private key material retrieved just-in-time for `HpcrContractSign(...)` and `HpcrGetAttestationRecords(...)`
- Private keys never exposed via APIs or persisted to files/logs
- `KeyProvider` interface allows switching to Vault backend without service layer changes

**Network Trust:**
- TLS termination at nginx reverse proxy
- `db_net` internal network isolates postgres from external access
- Backend is the only service with database credentials

---

## Slide 4: Build Lifecycle (V2 Workflow)
**Linear State Progression:**
```
CREATED → SIGNING_KEY_REGISTERED → WORKLOAD_SUBMITTED →
ENVIRONMENT_STAGED → ATTESTATION_KEY_REGISTERED →
FINALIZED → CONTRACT_DOWNLOADED
```

**Key Workflow Changes (V2):**
- Auditor registers signing key **before** SP/DO submit sections
- Solution Provider submits plaintext workload; backend encrypts via `contract-go`
- Data Owner submits plaintext environment; backend encrypts via `contract-go`
- Auditor triggers backend-native finalization (no local `contract-cli` needed)
- Env Operator downloads and acknowledges (one-time, immutable)

**Post-Finalization Attestation:**
- Separate state machine: `PENDING_UPLOAD → UPLOADED → VERIFIED | REJECTED`
- Desktop unlocks upload at `CONTRACT_DOWNLOADED`
- Auditor verification includes optional attestation key passphrase support

---

## Slide 5: Two-Layer Authorization Model
**Layer 1: Global RBAC**
- `ADMIN`: User/build management, system operations
- `SOLUTION_PROVIDER`: Workload section submission
- `DATA_OWNER`: Environment section submission, attestation evidence upload
- `AUDITOR`: Key registration, finalization, attestation verification
- `ENV_OPERATOR`: Contract export/download, attestation evidence upload
- `VIEWER`: Read-only access to builds and audit logs

**Layer 2: Per-Build Assignment**
- Build participation requires **both** global role **and** explicit assignment
- Admin assigns specific users to each role per build
- Assignment validation: user must hold target global role and be setup-complete

**Build Visibility:**
- `GET /builds`: Admin sees all; non-admin sees only assigned builds
- `/builds/{id}/*`: Build-access middleware enforces admin or assignment check

**Attestation Evidence Authorization:**
- Upload: Assigned `DATA_OWNER` or `ENV_OPERATOR`
- Verify: Assigned `AUDITOR`

---

## Slide 6: Request Signing and Anti-Replay
**Required Headers (Mutating Requests):**
- `X-Signature`: RSA-PSS signature of canonical hash
- `X-Signature-Hash`: SHA-256 hash of (method + path + body + timestamp)
- `X-Timestamp`: ISO 8601 timestamp
- `X-Key-Fingerprint`: Optional, for key identification

**Validation Pipeline:**
1. Timestamp freshness check (±5 minutes tolerance)
2. Retrieve user's registered public key
3. Recompute canonical hash from request
4. Verify RSA-PSS signature against registered public key

**Signature Exemptions:**
- `POST /auth/logout`
- `PATCH /users/{id}/password` (own account)
- `PUT /users/{id}/public-key` (own account)

**Security Properties:**
- Non-repudiation: Signatures bound to registered identity keys
- Replay protection: Timestamp window enforcement
- Integrity: Canonical hash covers method, path, body, timestamp

---

## Slide 7: Setup Guard and Credential Rotation
**First-Login Enforcement:**
- All new users (including seeded admin) must complete setup before accessing functionality
- Mandatory steps: change initial password, generate RSA-4096 key pair, register public key
- Setup-incomplete users restricted to: logout, password change, public key registration

**Credential Rotation Policy (90-Day):**
| Credential | Rotation Mechanism |
|---|---|
| Password | Backend marks expired; user forced into setup flow on next login |
| Public Key | Backend checks `public_key_expires_at`; expired keys block build participation |

**Setup Guard Behavior:**
- Middleware intercepts all authenticated requests
- Returns `403 ACCOUNT_SETUP_REQUIRED` with setup requirements
- Previous signatures remain valid for audit verification (fingerprint references key used at time)

---

## Slide 8: V2 Stage Data Flow (Backend-Native Cryptography)
**Phase 1: Auditor - Signing Key Registration**
- `POST /builds/{id}/keys/signing` with mode `generate` (DB key provider) or `upload_public`
- Backend generates RSA-4096 key pair; stores encrypted private PEM in `build_keys_private`, public key in `build_keys`
- Private key storage happens **after** the parent `build_keys` row is inserted (FK ordering fix)
- Transitions build to `SIGNING_KEY_REGISTERED`

**Phase 2: Solution Provider - Workload Submission**
- `POST /builds/{id}/v2/sections/workload` with plaintext YAML + HPCR cert
- Backend encrypts via `contract-go` v2: `HpcrTextEncrypted(plaintext, "", "", certPEM)` — positional args: `(plainText, os, certVersion, encryptionCertificate)`
- Stores encrypted payload, section hash, signature metadata
- Transitions to `WORKLOAD_SUBMITTED`

**Phase 3: Data Owner - Environment Submission**
- `POST /builds/{id}/v2/sections/environment` with plaintext environment + HPCR cert
- Backend encrypts via `contract-go`
- Transitions to `ENVIRONMENT_STAGED`

**Phase 4: Auditor - Attestation Key + Finalization**
- `POST /builds/{id}/keys/attestation` (Vault-managed or uploaded public key)
- `POST /builds/{id}/v2/finalize` with signing/attestation key IDs
- Backend assembles contract, signs via `HpcrContractSign(...)`, stores immutable YAML
- Transitions to `FINALIZED`

**Phase 5: Env Operator - Download Acknowledgment**
- Downloads contract, verifies hash locally, signs acknowledgment
- `POST /builds/{id}/acknowledge-download` with signed hash
- Transitions to `CONTRACT_DOWNLOADED` (terminal, one-time)

---

## Slide 9: Post-Finalization Attestation Evidence
**Upload Flow (Data Owner / Env Operator):**
- `POST /builds/{id}/attestation/evidence` with records + signature files
- Supports signed JSON (desktop-preferred) or `multipart/form-data`
- Desktop unlock condition: build status `CONTRACT_DOWNLOADED`
- Backend guardrails: `attestation_state` must be `PENDING_UPLOAD` or `REJECTED`
- Updates state to `UPLOADED`, emits `ATTESTATION_EVIDENCE_UPLOADED` audit event

**Verification Flow (Auditor):**
- `POST /builds/{id}/attestation/evidence/{evidence_id}/verify`
- Optional `attestation_key_passphrase` in request body for encrypted attestation keys
- Backend retrieves attestation private key from Vault just-in-time
- Decrypts records via `HpcrGetAttestationRecords(...)`
- Verifies signature via `HpcrVerifySignatureAttestationRecords(...)`
- Returns verdict: `VERIFIED` or `REJECTED` with contract-go error details
- Updates `attestation_state`, emits `ATTESTATION_VERIFIED` audit event

**State Machine:**
```
PENDING_UPLOAD → UPLOADED → VERIFIED
                         ↓
                      REJECTED → (re-upload) → UPLOADED
```

---

## Slide 10: Audit Hash Chain and Non-Repudiation
**Chain Structure:**
- Genesis: `SHA256("IBM_CC:" + build_id)` (deterministic seed)
- Each event: `event_hash = SHA256(canonical_json(event_data) + previous_event_hash)`
- Tamper detection: Any modification breaks chain from that point forward

**Signed Event Types (Required for Verification):**
| Event | Persona | Signature Source |
|---|---|---|
| `BUILD_CREATED` | Admin | Identity private key |
| `SIGNING_KEY_CREATED` | Auditor | Identity private key |
| `WORKLOAD_SUBMITTED` | Solution Provider | Identity private key |
| `ENVIRONMENT_STAGED` | Data Owner | Identity private key |
| `ATTESTATION_KEY_REGISTERED` | Auditor | Identity private key |
| `BUILD_FINALIZED` | Auditor | Identity private key |
| `CONTRACT_DOWNLOADED` | Env Operator | Identity private key |
| `ATTESTATION_EVIDENCE_UPLOADED` | DO/EO | Identity private key |
| `ATTESTATION_VERIFIED` | Auditor | Identity private key |

**Verification Properties:**
- Hash chain continuity validation
- Signature verification against registered public keys (via `actor_key_fingerprint`)
- Contract hash consistency check between `BUILD_FINALIZED` event and stored contract
- No loose ends: Every persona contribution is cryptographically bound

---

## Slide 11: Verification API Surface
**Audit Chain Verification:**
- `GET /builds/{id}/verify`
  - Recomputes genesis seed from build ID
  - Walks events in sequence, recomputing hashes
  - Verifies each event hash matches stored hash
  - Verifies signatures against registered public keys (via fingerprint lookup)
  - Validates contract hash in `BUILD_FINALIZED` event matches stored contract
  - Returns pass/fail report with broken link details

**Contract Integrity Verification:**
- `GET /builds/{id}/verify-contract`
  - Validates finalized contract structure and signature semantics
  - Checks HPCR signature validity using build signing key

**Attestation Verification:**
- `POST /builds/{id}/attestation/evidence/{evidence_id}/verify`
  - Cryptographic verification via `contract-go` engine
  - Returns verdict + decryption/signature validation details
  - Rejected results include `details.reason` for diagnosis

**Attestation Status:**
- `GET /builds/{id}/attestation/status`
  - Current attestation state, verdict, evidence summary
  - Latest evidence ID from audit events

**Desktop UI Support:**
- Manual verification guide with copyable command snippets
- Persona-specific stage verification help cards
- Hash chain visualization in audit viewer

---

## Slide 12: Backend Runtime Hardening
**Middleware Pipeline (Ordered):**
1. Panic recoverer
2. Request ID injection
3. Security headers (`X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, HSTS)
4. Structured request logging (method, path, status, duration, request-id, IP)
5. CORS enforcement (explicit allowlist or `CORS_ALLOW_ALL` for dev)
6. Max body size (default 50MB, configurable)
7. Request timeout (default 30s)
8. Rate limiting (global + endpoint-specific) — **`/health` is registered before the rate-limited group and is never throttled**

**Authenticated Route Additions:**
- Auth middleware (bearer token validation)
- Setup guard (restricts incomplete accounts)
- Request signature enforcement (mutating operations)

**Rate Limiting:**
- Global: 10 req/sec, burst 20
- Login: 5 req/min, burst 3
- `/health`: exempt — registered outside rate-limited group

**Container Hardening:**
- Read-only root filesystems with `tmpfs` for writable paths
- `no-new-privileges` security option
- Dropped Linux capabilities (minimal add-back for nginx bind)
- Resource limits: memory, CPU, PID limits

---

## Slide 13: Desktop Application Security
**Electron Process Isolation:**
- `contextIsolation: true` - Preload scripts isolated from renderer
- `nodeIntegration: false` - No Node.js APIs in renderer
- `sandbox: true` - Renderer runs in OS-level sandbox
- `webSecurity: true` - Same-origin policy enforced
- `allowRunningInsecureContent: false` - No mixed content
- `webviewTag: false` - No embedded webviews

**IPC Security:**
- All IPC handlers wrapped with sender URL validation
- Trusted origin allowlist (dev: `localhost:5173`, prod: `file://` under packaged `dist/`)
- Untrusted sender requests rejected with explicit errors

**Navigation Controls:**
- `setWindowOpenHandler` denies all child windows
- `will-navigate` blocks unexpected in-app navigation
- `will-attach-webview` always blocked
- External URLs opened via shell with protocol allowlist (`https`, `http`, `mailto`)

**Session Security:**
- Deny-all permission handlers (media, device, location)
- Certificate error rejection (`callback(false)`)
- Session storage cleanup on window close and app shutdown

**CSP (Content Security Policy):**
- `default-src 'self'`
- `object-src 'none'`
- Restrictive script/style/font/image/connect directives

**Key Storage:**
- Identity private keys encrypted and stored under app user data path
- Current: Local machine-derived key strategy
- Recommended: OS keychain integration for production hardening

---

## Slide 14: Deployment Topology
**Container Services:**
```
Client → reverse_proxy (nginx:1.27-alpine) → backend (contract-manager:local) → postgres (postgres:16-alpine)
                                                      ↓
                                               migrate (contract-manager:local)
                                               pgadmin (dpage/pgadmin4:9)
```

**Network Segmentation:**
- `app_net`: reverse_proxy ↔ backend
- `db_net` (internal): backend/migrate ↔ postgres
- No external Vault dependency in current deployment; key ops handled by `keymgmt/db` provider

**TLS Configuration (Production):**
- `docker-compose.prod.yaml` overlay (removed from repo; apply as environment-specific override)
- nginx `tls.conf` with HTTPS listener (port 443, mapped to 8443)
- HTTP-to-HTTPS redirect
- Certificate/key mounted read-only
- HSTS header enforcement

**Container Hardening:**
- Read-only root filesystems with `tmpfs` mounts for writable paths
- `no-new-privileges` security option on all services
- Dropped Linux capabilities
- Resource limits: memory, CPU, PID limits per service

**Operational Endpoints:**
- Health: `GET /health` (never rate-limited, responds `{"status":"ok"}`)
- About/Version: `GET /about`
- Swagger: `GET /swagger`
- System logs: `GET /system-logs` (Admin/Auditor only)

---

## Slide 15: Documentation Alignment Status
**Design Documentation (v0.6 Synchronized):**
- `1-high-level-design.md` - Architecture, personas, workflows, v2 changes
- `2-low-level-design.md` - Implementation details, service layer, routes
- `3-desktop-app-design.md` - Electron security, UI architecture, IPC contracts
- `4-api-documentation.md` - Complete API reference with v2 endpoints
- `5-security-design.md` - Threat model, controls, key custody
- `6-deployment-guide.md` - Operations runbook, upgrade procedures

**Key V2 Documentation Updates:**
- HashiCorp Vault integration and key custody model
- Backend-native contract cryptography via `contract-go`
- V2 API endpoints (9 new endpoints for keys, sections, finalize, attestation)
- Post-finalization attestation evidence workflows
- Updated domain model with `build_keys`, `attestation_evidence`, `attestation_verifications` tables
- Credential rotation policy and setup guard behavior
- Desktop app security controls and IPC trust boundary

**Documentation Maintenance:**
- Legacy UI/UX phase planning docs removed
- All docs aligned to current codebase as source of truth
- If documentation conflicts with code, code is authoritative

---

## Slide 16: Technical Next Steps and Hardening Opportunities
**Fixes Delivered This Session:**
- `HpcrTextEncrypted` argument order corrected: `certPEM` now passed as `encryptionCertificate` (position 4), not as `confidentialComputingOs` (position 2)
- FK ordering bug fixed: `build_keys_private` row now inserted only after parent `build_keys` row exists
- `/health` exempted from global rate limiter — no more 429 on frontend polling
- 5 routes corrected to `/v2/` prefix: `contract-template`, `encryption-certificates/versions`, `workload`, `environment`, `finalize`
- Migration 020 fixed: enum `ALTER COLUMN` now drops default before ALTER and restores after

**Testing and Validation:**
- Expand automated negative-path tests for signature/replay/access edge cases
- Add integration tests for DB key provider key lifecycle and failure scenarios
- Implement staged release gates for desktop/backend version compatibility
- Add production operations validation pipeline (health, verify, verify-contract checks)

**Security Hardening:**
- Migrate desktop identity key storage to OS keychain (macOS Keychain, Windows Credential Manager, Linux Secret Service)
- Implement mTLS between reverse proxy and backend
- Evaluate HashiCorp Vault migration path for `KeyProvider` interface
- Tighten CSP directives (remove `'unsafe-inline'` for styles if feasible)
- Restrict `connect-src` to configured backend domains in production

**Operational Improvements:**
- Automated backup and restore procedures for PostgreSQL
- Monitoring and alerting for credential rotation events
- Performance optimization for assignment-filtered build queries
- OpenAPI spec generation from code to prevent drift

**Architecture Evolution:**
- Evaluate HSM / Vault integration path for highest-security deployments via `KeyProvider` interface swap
- Consider build-level encryption key rotation mechanisms
- Explore audit log immutability guarantees (append-only storage)
