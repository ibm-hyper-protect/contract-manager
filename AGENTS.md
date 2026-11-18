# AGENTS.md

This file provides guidance to agents when working with code in this repository.

## Commands (run from repo root; no Makefile)
```bash
go build -o server ./cmd/server
go test ./...
go test ./internal/service -run TestLogin        # single test (add -v for output)
go vet ./... && gofmt -l .
./scripts/generate-repository.sh                 # sqlc generate + license-header carry-over (use this, not bare `sqlc generate`)
```
- DB-backed tests skip unless `TEST_DATABASE_URL` is set (`internal/service/user_key_service_test.go`, `internal/handler/*integration_test.go`). Some contract tests skip without `openssl`.
- Schema migrations are NOT applied by the server. They are applied by the `migrate` service in `compose/docker-compose.yaml` (golang-migrate, `migrations/NNN_*.{up,down}.sql`). SQLC reads `migrations/` as its schema. `migrations/README.md` is stale (mentions `backend/` paths, stops at 013).

## Stack
Go 1.27 (`go.mod`), chi v5, pgx/v5, SQLC, `contract-go/v3`. Standard `testing` only. Single binary: `cmd/server/main.go` (`buildRouter()` registers all routes; `seedAdmin` runs on startup from `ADMIN_EMAIL/ADMIN_PASSWORD/ADMIN_NAME`).

## Non-obvious patterns
- **SQLC**: never edit `internal/repository/*.sql.go`. Edit `internal/repository/queries/*.sql`, regenerate. DB enums (`build_status`, `persona_role`, `audit_event_type`) map to plain Go `string` (`sqlc.yaml`); use typed aliases from `internal/model/`.
- **Raw SQL exception**: `build_keys`, `attestation_evidence`, `attestation_verifications` and attestation columns on `builds` are queried with raw pgx in `internal/service/v2_store.go`.
- **Errors**: handlers use `writeError(w, model.ErrXxx(...))` (`internal/handler/response.go`), never `http.Error()`. Services return `*model.AppError` for domain errors, `fmt.Errorf("ctx: %w", err)` otherwise.
- **Body parsing**: `readJSON` (1 MB, rejects unknown fields), `readJSONLarge(r,&v,max)` (encrypted payloads), `drainBody(r)` on early exits.
- **Auth**: opaque Bearer tokens (SHA-256 hash looked up in `api_tokens`, `service.HashToken`) — not JWT. Middleware chain in `buildRouter`: `Auth` → `SetupGuard` → `RequireRequestSignature`. Role checks via `middleware.RequireRole(...)` on the route, not in handlers. `RequireBuildAccess` hits the DB per request.
- **Request signatures**: POST/PUT/PATCH/DELETE need `X-Signature`, `X-Signature-Hash`, `X-Timestamp` (signed payload `{"method","path","data","timestamp"}`). Exempt: `POST /auth/logout`, `PATCH /users/*/password`, and `PUT /users/*/public-key` only when caller has zero active keys (`isSignatureExempt`). `X-Key-Fingerprint` picks the key when several are active.
- **User keys**: use `UserKeyService` / `user_public_keys` table only; the `users.public_key*` columns are deprecated. Max 5 active keys; password confirmation required after any key history (app-level, not DB constraints).
- **Build state machine**: `model.BuildStatus.CanTransitionTo()` / `ValidTransitions` in `internal/model/build.go`; return `model.ErrInvalidStateTransition`. Never compare status strings.
- **Keys**: no Vault. Private keys are passphrase-encrypted PEM (AES-256-CBC) in PostgreSQL via `keymgmt.KeyProvider` (`keymgmt/db`; `keymgmt/mock` for tests). No mock `contract.Engine` exists.
- **Logging**: `log/slog` only; also `SystemLogService.LogEvent(...)` for security/business events.

## Style
gofmt; import groups: stdlib / third-party / `github.com/ibm-hyper-protect/contract-manager/internal/...`. `XxxHandler`/`NewXxxHandler`, `XxxService`/`NewXxxService`.

## Runtime env
`DATABASE_URL` (required), `TOKEN_EXPIRY` (24h), `BCRYPT_COST` (12), `LOG_FORMAT` (json|text), `MAX_PAYLOAD_SIZE` (50MB), `REQUEST_TIMEOUT` (30s), `CORS_*`, `APPID_*` (SSO off if any empty). Full list: `internal/config/config.go`.
