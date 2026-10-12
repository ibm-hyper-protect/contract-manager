# AGENTS.md — Ask (Documentation) Mode

This file provides guidance to agents when working with code in this repository.

## Key Context for Answering Questions

### Project structure gotchas
- There is **no `backend/` directory** — Go source lives directly at repo root (`cmd/`, `internal/`, `migrations/`).
- The `compose/` directory holds Docker Compose files; the repo root `Dockerfile` is for the Go server only.
- `internal/repository/*.sql.go` are **generated** — when explaining database access, always refer to `internal/repository/queries/*.sql` as the source of truth and `internal/repository/querier.go` for the interface.

### Vault is absent
- Despite `README.md` and `DEPLOYMENT.md` mentioning Vault, **Vault has been removed**. Private keys are stored as AES-256-CBC encrypted PEM blobs in PostgreSQL. The authoritative comment is in `internal/config/config.go` line 12.

### Authentication flow
- Tokens are **not JWT** — they are opaque random tokens stored as SHA-256 hashes in the `api_tokens` table.
- Every non-GET authenticated request also requires an RSA request signature (see `internal/middleware/signature.go`).
- New users are blocked from all endpoints except password-change and public-key-upload until setup is complete (`middleware.SetupGuard`).

### Build lifecycle
- The strict state machine is defined in `internal/model/build.go:ValidTransitions`. The sequence is: CREATED → SIGNING_KEY_REGISTERED → WORKLOAD_SUBMITTED → ENVIRONMENT_STAGED → ATTESTATION_KEY_REGISTERED → FINALIZED → CONTRACT_DOWNLOADED.

### Contract engine
- `internal/contract/engine.go` defines the `Engine` interface; the only implementation is `internal/contract/contractgo/engine.go` which wraps `github.com/ibm-hyper-protect/contract-go/v2`.

### No tests yet
- There are no `*_test.go` files in the repository as of initial commit.
