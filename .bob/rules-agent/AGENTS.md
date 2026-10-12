# AGENTS.md — Agent (Coding) Mode

This file provides guidance to agents when working with code in this repository.

## Non-Negotiable Coding Rules

### Repository layer
- NEVER edit `internal/repository/*.sql.go` — they are SQLC-generated.
- Add/modify queries only in `internal/repository/queries/*.sql`, then run `sqlc generate`.
- For tables outside SQLC scope (attestation, build_keys), use raw `pgx` SQL inside `service/v2_store.go`.

### Error handling
- HTTP error responses MUST use `model.AppError` constructors from `internal/model/errors.go`.
- In handlers: `writeError(w, model.ErrXxx(...))` — never `http.Error()` or `json.NewEncoder(w).Encode(...)` directly for errors.
- In services: domain errors → return `*model.AppError` directly; unexpected errors → `fmt.Errorf("context: %w", err)`.

### Request body
- Normal JSON: `readJSON(r, &req)` — enforces 1 MB + disallows unknown fields.
- Large payloads (encrypted data): `readJSONLarge(r, &req, customSize)`.
- On early returns where body was partially read, call `drainBody(r)`.

### Signature enforcement
- Every POST/PUT/PATCH/DELETE on authenticated routes requires `X-Signature`, `X-Signature-Hash`, `X-Timestamp`.
- Three exemptions (no signature needed): `POST /auth/logout`, `PATCH .../password`, `PUT .../public-key`.

### State machine
- Always use `BuildStatus.CanTransitionTo(next)` — never compare build status strings directly.
- Return `model.ErrInvalidStateTransition(current, expected)` on failure.

### Logging
- `log/slog` only. Also call `service.SystemLogService.LogEvent(...)` for all security/business events.

### Import order (enforced by gofmt)
1. stdlib → 2. third-party → 3. `github.com/ibm-hyper-protect/contract-manager/internal/...`

### Adding a new endpoint
1. Add SQL query to `internal/repository/queries/`, run `sqlc generate`.
2. Add method to `internal/service/`.
3. Add handler method to `internal/handler/`; use `writeJSON` / `writeError`.
4. Register route in `cmd/server/main.go:buildRouter()`; apply `middleware.RequireRole(...)` as needed.
5. No Vault calls — key ops go through `keymgmt.KeyProvider` interface.
