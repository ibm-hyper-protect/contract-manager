# AGENTS.md — Ask (Documentation) Mode

This file provides guidance to agents when working with code in this repository.

- No `backend/` directory: Go source is at repo root (`cmd/`, `internal/`, `migrations/`). `migrations/README.md` still says `backend/migrations` and stops at 013 — treat as stale (latest is 021).
- `README.md`/`DEPLOYMENT.md` may mention Vault; **Vault was removed**. Keys are passphrase-encrypted PEM in PostgreSQL (`internal/config/config.go` note, `internal/keymgmt/db/provider.go`).
- Tokens are opaque (SHA-256 hash in `api_tokens`), not JWT. Mutating requests also need RSA request signatures (`internal/middleware/signature.go`). New users are confined by `middleware.SetupGuard` to password change + public-key registration.
- DB access truth: `internal/repository/queries/*.sql` (generated `*.sql.go` are outputs); attestation/build_keys tables are raw SQL in `internal/service/v2_store.go`.
- Build lifecycle: `internal/model/build.go` — CREATED → SIGNING_KEY_REGISTERED → WORKLOAD_SUBMITTED → ENVIRONMENT_STAGED → ATTESTATION_KEY_REGISTERED → FINALIZED → CONTRACT_DOWNLOADED (CANCELLED allowed before FINALIZED).
- `internal/contract/engine.go` is the interface; sole implementation `contractgo/` wraps `contract-go/v3`. Validation lives in `internal/contract/validation/`.
- User identity keys: `user_public_keys` table (multi-key); `users.public_key*` columns are deprecated.
- Tests exist (`*_test.go`); DB integration tests need `TEST_DATABASE_URL`.
- API docs are embedded in `internal/handler/swagger_handler.go` (inline JSON), not a separate spec file.
