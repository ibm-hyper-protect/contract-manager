# AGENTS.md — Plan Mode

This file provides guidance to agents when working with code in this repository.

## Architectural Constraints

### Layering (strict)
```
handler → service → repository.Querier (interface)
                  → keymgmt.KeyProvider (interface)
                  → contract.Engine (interface)
```
- Handlers never import `repository` directly (only via service).
- Services never import `handler` or `middleware`.
- All cross-cutting concerns (auth, RBAC, rate-limiting, signature) are in `middleware`, not services.

### Key management
- No Vault. `keymgmt.KeyProvider` abstracts DB-backed encrypted key storage. Any future key backend must implement this interface.
- Private keys are decrypted only in memory at usage time — never returned over the wire unless explicitly marked `OneTimePrivateExport`.

### Database
- SQLC owns `internal/repository/` — generated from `internal/repository/queries/*.sql` + `migrations/`.
- Tables added for v2 features (build_keys, attestation_evidence, attestation_verifications) use raw SQL in `service/v2_store.go` because they were added after SQLC setup. Plan to migrate these into queries/ over time.
- DB enum types (`build_status`, `persona_role`, `audit_event_type`) are mapped to Go `string` in `sqlc.yaml` — use typed string aliases in `internal/model/` for safety.

### Contract engine is a single implementation
- `internal/contract/Engine` interface has only one real implementation (`contractgo`), which wraps the `contract-go` v2 SDK. Tests should use the mock key provider (`keymgmt/mock`) but there is no mock `Engine` yet.

### HTTP server
- Single binary, no microservices. Router is built in `cmd/server/main.go:buildRouter()` — all route registration happens there.
- No external service discovery or messaging; everything is synchronous HTTP + PostgreSQL.

### State machine coupling
- `model.ValidTransitions` is the single source for build lifecycle. Services (`build_service.go`, `contract_service.go`, `key_service.go`) all call `CanTransitionTo()` before any mutation — do not add status checks elsewhere.

### Signature requirement
- The request signature scheme (`middleware/signature.go`) ties every mutating request to a user's registered RSA public key. This means users **must** complete setup (register public key) before they can submit any business data. Plan features accordingly.
