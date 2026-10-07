# Plan: Sync Design Documents to PostgreSQL-Backed Key Management

## Overview

**Goal:** All five design documents — HLD, LLD, API docs, Security Design, and Deployment Guide — must accurately reflect the current codebase, which uses PostgreSQL as the sole key management provider. HashiCorp Vault has already been removed from the code (`internal/config/config.go`, `cmd/server/main.go`, migration 019). The documents still describe Vault as the active provider.

**Scope:**
- Remove all Vault references from all five design documents.
- Fix stale file paths and provider references in the LLD.
- Perform a comprehensive audit of the API documentation against the live router.
- Update the Security Design threat model to accurately describe private-key at-rest protection.
- Update the Deployment Guide to match the current `compose/docker-compose.yaml` topology and add s390x image build notes.
- Bump all document version numbers and dates.

**Out of Scope:**
- No code changes. This plan is documentation-only.
- No encryption algorithm upgrade (AES-256-CBC → AES-256-GCM is deferred; document current state accurately).
- No changes to `Design/3-desktop-app-design.md`.

**Key facts established from code review:**
- `internal/keymgmt/db/provider.go` is the active production key provider (not Vault).
- Private keys are stored as AES-256-CBC PEM blobs in `build_keys_private` table.
- `KEY_PROVIDER`, `VAULT_ADDR`, and all other Vault env vars are absent from `internal/config/config.go`.
- `compose/docker-compose.yaml` has no Vault service (5 containers: nginx, postgres, pgadmin, backend, migrate).
- Router in `cmd/server/main.go` has two undocumented routes: `GET /about` and `GET /v2/encryption-certificates/versions`.
- LLD references wrong codebase root (`backend/internal/...` instead of `internal/...`) and wrong key provider path (`keymgmt/vault/provider.go` instead of `keymgmt/db/provider.go`).
- **Confirmed role corrections:** `POST /builds`, `POST /builds/{id}/cancel`, `GET /users`, `POST /builds/{id}/assignments` are all `ADMIN or AUDITOR` in the router — API docs must be corrected from ADMIN-only.
- **s390x context:** The `Dockerfile` already handles s390x by building `golang-migrate` from source (no pre-built s390x binary available). The `go build` uses `TARGETOS`/`TARGETARCH` build args, making the image multi-arch buildable via `docker buildx`. The `compose/docker-compose.yaml` references a hardcoded digest from `ghcr.io/ibm-hyper-protect/contract-manager` — for s390x deployments, users build the image locally from the `Dockerfile` using `docker buildx build --platform linux/s390x`.

---

## Sub-Tasks

---

### Sub-Task 1: Update High-Level Design (1-high-level-design.md)

**Intent:** Remove all Vault references from the HLD. Update the system context diagram, architectural principles, key management description, cryptographic standards table, security design table, deployment topology, and v0.6 change summary to reflect PostgreSQL-backed key storage.

**Expected Outcomes:**
- No mention of HashiCorp Vault anywhere in the document.
- System context diagram shows `[ Go Backend ] → [ PostgreSQL ]` only (no Vault box).
- Deployment topology section reflects 5-container stack without Vault.
- Cryptographic standards table: `Key Management` row updated to describe AES-256-CBC passphrase-encrypted PEM blobs in PostgreSQL.
- Security Design table: `Build Key Isolation` row updated to reflect encrypted at-rest model with passphrase protection.
- `13. Summary of Changes` section gets a new `v0.7` entry describing the Vault removal and PostgreSQL key storage adoption.
- Version bumped to `0.7`, date updated to today.

**Todo List:**
1. Update document header: version `0.7`, today's date.
2. Section 1 (Introduction): Replace "Build-scoped signing and attestation keys are managed by HashiCorp Vault" with the PostgreSQL storage model.
3. Section 3 (System Context): Rewrite the customer environment diagram to remove Vault. Update Key Points to remove Vault references.
4. Section 3 (Desktop Application Architecture): No changes needed.
5. Section 7 (Cryptographic Standards): Update the `Key Management` row to: "PostgreSQL-backed encrypted key storage. Private keys stored as AES-256-CBC passphrase-encrypted PEM blobs in `build_keys_private`. Passphrases are caller-supplied at runtime and never persisted."
6. Section 10 (System Architecture): Remove HashiCorp Vault subsection. Update Backend components list to remove `KeyProvider` Vault reference.
7. Section 11 (Security Design): Update `Build Key Isolation` row to reflect encrypted at-rest model. Update `Data at Rest` row to mention `build_keys_private` table.
8. Section 12 (Deployment Topology): Update diagram and text to remove Vault. Update `KEY_PROVIDER` reference.
9. Section 13: Add `v0.7` change summary entry describing the Vault removal.

**Relevant Context:**
- File: `Design/1-high-level-design.md`
- Lines 17-19 (architectural principles), lines 53-80 (system context), lines 607-619 (crypto standards), lines 841-879 (system architecture), lines 882-900 (security design), lines 902-935 (deployment topology/changes)

**Status:** [ ] pending

---

### Sub-Task 2: Update Low-Level Design (2-low-level-design.md)

**Intent:** Fix all stale codebase paths, replace the Vault provider reference with the DB provider (`keymgmt/db/`), remove Vault configuration variables from Section 11, and update service behavior descriptions to reflect the current implementation.

**Expected Outcomes:**
- Section 2 (Codebase Structure): All paths use `internal/...` root (not `backend/internal/...`). The `keymgmt/` subtree shows `db/provider.go` and `mock/provider.go` (not `vault/provider.go`).
- Section 7 (Service-Level Behavior): `7.8 KeyService` and `7.9 ContractService` descriptions updated to mention PostgreSQL private key retrieval (not Vault).
- Section 11 (Configuration): All `KEY_PROVIDER`, `VAULT_*` variables removed. Configuration table matches current `internal/config/config.go` exactly.
- Section 12 (Known Constraints): Add note about AES-256-CBC as current encryption algo (not GCM), flagged as a known constraint.
- Version bumped to `0.5`, date updated.

**Todo List:**
1. Update document header: version `0.5`, today's date.
2. Section 2.1 Backend: Fix all `backend/internal/...` → `internal/...` paths. Replace `keymgmt/vault/provider.go` with `keymgmt/db/provider.go`. Add `keymgmt/db/provider.go` description.
3. Section 7.8 KeyService: Update description to remove Vault references. Note that private keys are retrieved from `build_keys_private` table via `GetPrivateKey()`.
4. Section 7.9 ContractService: Update to remove "resolves keys from Vault refs" language. Describe private key retrieval from PostgreSQL.
5. Section 11 Configuration: Remove `KEY_PROVIDER` variable and entire `### V2: Key Provider Configuration` and `### V2: Vault Configuration` subsections. The config table should only contain variables that exist in `internal/config/config.go`.
6. Section 12 Known Constraints: Add item: "Private keys are stored with AES-256-CBC PEM encryption (OpenSSL format). AES-256-GCM (authenticated encryption) is recommended as a future hardening step."
7. Remove any remaining inline Vault references across all other sections.

**Relevant Context:**
- File: `Design/2-low-level-design.md`
- Section 2.1 (lines ~23-92), Section 7 (lines ~441-543), Section 11 (lines ~693-733), Section 12 (lines ~734-745)
- Reference: `internal/config/config.go` for exact env vars

**Status:** [ ] pending

---

### Sub-Task 3: Comprehensive API Documentation Audit (4-api-documentation.md)

**Intent:** Perform a full audit of the API documentation against `cmd/server/main.go` (the router). Fix every discrepancy, add missing routes, remove Vault config variables, and update the env vars section to match `internal/config/config.go` exactly.

**Expected Outcomes:**
- `GET /about` is documented in Section 7.1 (Public / Documentation).
- `GET /v2/encryption-certificates/versions` is documented in an appropriate section (V2 contract operations).
- Section 9 (Configuration Environment Variables): All `KEY_PROVIDER`, `VAULT_ADDR`, `VAULT_NAMESPACE`, `VAULT_AUTH_METHOD`, `VAULT_ROLE_ID`, `VAULT_SECRET_ID`, `VAULT_TOKEN`, `VAULT_TRANSIT_MOUNT`, `VAULT_KV_MOUNT`, `VAULT_REQUEST_TIMEOUT` entries are removed. The V2 key provider subsection is removed or replaced with the DB provider description.
- Any other discrepancies found during the router audit are corrected.
- Version bumped to `1.4`, date updated.

**Todo List:**
1. Update document header: version `1.4`, today's date.
2. Walk every route in `cmd/server/main.go` `buildRouter()` against Section 7 endpoint reference. Log any discrepancies.
3. Add `GET /about` entry to Section 7.1 (Public / Documentation).
4. Add `GET /v2/encryption-certificates/versions` entry — determine correct section (likely Section 7.13 V2: Backend-Native Contract Operations).
5. Note: `POST /builds` is currently `ADMIN or AUDITOR` (`RequireRole("ADMIN", "AUDITOR")`) but the API doc says ADMIN only — correct this.
6. Note: `POST /builds/{id}/cancel` is currently `ADMIN or AUDITOR` (`RequireRole("ADMIN", "AUDITOR")`) but the API doc says ADMIN only — correct this.
7. Note: `GET /users` is currently accessible to ADMIN or AUDITOR (`RequireRole("ADMIN", "AUDITOR")`) but the API doc says ADMIN only — correct this.
8. Note: `POST /builds/{id}/assignments` is currently ADMIN or AUDITOR — correct the API doc.
9. Section 9: Remove all Vault/KEY_PROVIDER variables. Replace with accurate table of only the variables in `internal/config/config.go`.
10. Section 10 (Operational Notes): Update any references to `KEY_PROVIDER=vault` or Vault-related notes.

**Relevant Context:**
- File: `Design/4-api-documentation.md`
- Reference: `cmd/server/main.go` lines 190-319 (full router)
- Reference: `internal/config/config.go` for exact env vars
- Section 9 (lines ~1589-1632), Section 10 (lines ~1633-1669)

**Status:** [ ] pending

---

### Sub-Task 4: Update Security Design (5-security-design.md)

**Intent:** Rework the threat model to remove Vault as a trust boundary, update the key management security model to accurately describe PostgreSQL-backed encrypted key storage, add a private key at-rest protection section, and update the data-at-rest section.

**Expected Outcomes:**
- Section 3.1 (Trust Boundaries): Vault boundary removed. Backend now described as handling both contract cryptography AND encrypted private key storage (with passphrase protection).
- Section 3.2 (Out-of-Scope Risks): "Vault unsealing and disaster recovery" removed.
- Section 8.2 (Key Ownership): Updated to describe private key storage as AES-256-CBC PEM blobs in `build_keys_private` table, protected by operator-supplied passphrases. The "never persisted" guarantee from Vault is explicitly replaced.
- Section 8.3: Renamed from "Build Key Security (Vault-Managed)" to "Build Key Security (PostgreSQL-Backed)". Updated to describe: keys stored encrypted at rest, passphrase-protected, `build_keys_private` table, AES-256-CBC format, operational compensating controls.
- New subsection added: "Build Key At-Rest Protection": documents the trade-off (no hardware-sealed storage), recommends disk-level encryption and strict DB access controls as compensating controls.
- Section 8.4 (Data Classification): Add `build_keys_private` (AES-256-CBC encrypted private key PEM blobs) to stored data list.
- Version bumped to `1.2`, date updated.

**Todo List:**
1. Update document header: version `1.2`, today's date. Update source of truth reference (remove `backend/` prefix).
2. Section 3.1: Remove Vault trust boundary. Adjust Network boundary description to remove Vault network reference. Adjust Database boundary to note it now stores encrypted private key material.
3. Section 3.2: Remove "Vault unsealing and disaster recovery" from out-of-scope.
4. Section 8.2: Replace the two Vault-referencing bullet points with accurate PostgreSQL private key storage description.
5. Section 8.3: Rename to "Build Key Security (PostgreSQL-Backed)". Replace Vault-specific operations (AppRole, Transit mount, etc.) with description of: `createKey()` generates RSA-4096, encrypts private key with caller passphrase (AES-256-CBC), stores in `build_keys_private`. Runtime: `GetPrivateKey()` retrieves encrypted bytes, contract-go decrypts with passphrase, private key material is in-process only.
6. After Section 8.3, add new Section 8.4: "Build Key At-Rest Protection (Compensating Controls)": documents that private keys are always passphrase-encrypted, passphrase is never persisted, disk-level encryption is recommended, DB access should be restricted to backend service account only.
7. Renumber existing Section 8.4 → 8.5.
8. Remove all remaining `vault`, `Vault`, `VAULT_*`, `KEY_PROVIDER`, AppRole, Transit references.

**Relevant Context:**
- File: `Design/5-security-design.md`
- Lines 38-57 (Trust Boundaries), lines 220-246 (Key Ownership + Build Key Security)
- Reference: `internal/keymgmt/db/provider.go` for accurate implementation details

**Status:** [ ] pending

---

### Sub-Task 5: Update Deployment Guide (6-deployment-guide.md)

**Intent:** Update the deployment guide to match the actual `compose/docker-compose.yaml` (5-container topology with no Vault), remove all Vault-specific setup steps, remove Vault config variables from the configuration section, update the validation checklist and operations runbook, update the security checklist, and add s390x image build instructions.

**Expected Outcomes:**
- Section 2 (Runtime Topology): Vault container removed. Topology shows 5 containers: `reverse_proxy`, `postgres`, `pgadmin`, `backend`, `migrate`. No Vault in traffic flow diagram. Network layout updated: `app_net` is now reverse proxy ↔ backend only.
- Section 4 (Configuration Inputs): `KEY_PROVIDER` and all `VAULT_*` variables removed. Config table reflects only variables in `internal/config/config.go` and `compose/.env.example`.
- Section 5 (Local/Dev Deployment): Vault health check step removed.
- Section 8 (Database Migration Lifecycle): Path updated from `backend/migrations` to `/migrations` (as used in the compose `migrate` service entrypoint).
- Section 9 (Post-Deploy Validation Checklist): Item 8 ("If `KEY_PROVIDER=vault`...") removed and replaced with DB key provider validation note.
- Section 10 (Operations Runbook): Vault log/health commands and entire "10.3 Vault Operations" subsection removed.
- Section 13 (Backup and Recovery): "Vault data/storage" removed from minimum coverage. Passphrase inventory added.
- Section 15 (Security-Focused Deployment Checklist): All Vault items replaced with PostgreSQL security items (DB access control, encrypted backups including `build_keys_private`, host disk encryption recommendation).
- New section added: "s390x Image Build" — explains how to build the image for s390x using `docker buildx`, documents that `golang-migrate` is compiled from source (no pre-built s390x binary), and shows how to reference the locally built image in the compose stack.
- Version bumped to `1.2`, date updated.

**Todo List:**
1. Update document header: version `1.2`, today's date. Fix source of truth reference (remove `backend/` prefix, update compose paths).
2. Section 2: Remove `vault` from container list and traffic flow diagram. Update network layout: `app_net` = `reverse_proxy ↔ backend` only; `db_net` = `backend/migrate ↔ postgres` only.
3. Section 4: Remove `### V2: Key Provider and Vault Configuration` subsection and all its variables. The config table should only list variables present in `compose/.env.example`.
4. Section 5 (Local/Dev Deployment): Remove Vault health check step from 5.3 Validate.
5. Section 6 (Production Deployment): Remove `KEY_PROVIDER=vault` and Vault-related setup steps from 6.1 Prepare `.env`.
6. Section 8: Fix migration path from `backend/migrations` to `/migrations` (matches compose `migrate` service entrypoint `-path=/migrations`).
7. Section 9: Remove item 8 (Vault-specific). Add: "Key management: create a signing key and attestation key for a test build; confirm `build_keys_private` table contains a row."
8. Section 10.1 (Logs): Remove `docker compose logs -f vault` command.
9. Section 10.2 (Health and Status): Remove Vault health check command (`localhost:8200`). Remove entire "10.3 Vault Operations" subsection; renumber subsequent subsections.
10. Section 13 (Backup and Recovery): Remove "Vault data/storage" from minimum coverage. Add: "Passphrase inventory: all signing/attestation key passphrases must be recorded in a secure credential store external to the database."
11. Section 15 (Security Checklist): Remove all Vault items. Replace with: "PostgreSQL access restricted to backend service account only", "Encrypted backups include `build_keys_private` table", "Host disk encryption enabled on server".
12. Add new section before Related Documents: "s390x Image Build". Content: (a) Vault dependency is eliminated — no s390x blocker. (b) `Dockerfile` uses `TARGETOS`/`TARGETARCH` build args and builds `golang-migrate` from source because no pre-built s390x binary is available. (c) Build command: `docker buildx build --platform linux/s390x -t contract-manager:local .` run from repo root. (d) To use locally built image in compose, update `backend` and `migrate` service `image:` fields in `docker-compose.yaml` to `contract-manager:local` (or whatever tag was used). (e) All other images (`nginx`, `postgres`, `pgadmin4`) must be verified for s390x availability from their respective source registries before deployment.

**Relevant Context:**
- File: `Design/6-deployment-guide.md`
- Reference: `compose/docker-compose.yaml` for actual topology
- Reference: `compose/.env.example` for actual env vars

**Status:** [ ] pending

---

## Document Version Summary

| Document | Current Version | Target Version |
|---|---|---|
| `1-high-level-design.md` | v0.6 | v0.7 |
| `2-low-level-design.md` | v0.4 | v0.5 |
| `4-api-documentation.md` | v1.3 | v1.4 |
| `5-security-design.md` | v1.1 | v1.2 |
| `6-deployment-guide.md` | v1.1 | v1.2 |

---

## Notes for Implementation

- Each sub-task should be executed independently, one document at a time.
- Before editing each document, re-read the full current content to avoid missing sections.
- The API doc audit (Sub-Task 3) requires cross-referencing `cmd/server/main.go` router with every documented endpoint — do this systematically.
- The role discrepancies in the API docs (ADMIN-only claims that are actually ADMIN+AUDITOR in the router) must be verified by reading the middleware annotations in `cmd/server/main.go` before updating.
- Do not change `Design/3-desktop-app-design.md`.
- AES-256-CBC is to be documented accurately as the current implementation — not upgraded in this plan.
