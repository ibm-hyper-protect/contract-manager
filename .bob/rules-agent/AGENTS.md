# AGENTS.md — Agent (Coding) Mode

This file provides guidance to agents when working with code in this repository.

(General rules are in the root `AGENTS.md`; only coding-specific checklists here.)

## Adding a new endpoint
1. SQL in `internal/repository/queries/*.sql` → `./scripts/generate-repository.sh` (tables outside SQLC: raw pgx in `service/v2_store.go`).
2. Service method in `internal/service/` (call `CanTransitionTo` for build mutations; `SystemLogService.LogEvent` for events).
3. Handler in `internal/handler/` using `readJSON`/`writeJSON`/`writeError(w, model.ErrXxx(...))`.
4. Route in `cmd/server/main.go:buildRouter()` with `middleware.RequireRole(...)` as needed. Mutating routes inherit signature enforcement automatically.
5. Key operations go through `keymgmt.KeyProvider`; no Vault.

## Gotchas
- Handlers never import `repository` directly; go through services.
- Convert `pgtype.Timestamptz` to `*time.Time` in the service layer (pattern in `auth_service.go`).
- A schema change needs a new numbered `migrations/NNN_*.up.sql` + `.down.sql` before regenerating SQLC.
