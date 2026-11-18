# AGENTS.md — Plan Mode

This file provides guidance to agents when working with code in this repository.

- Layering: `handler → service → repository.Querier | keymgmt.KeyProvider | contract.Engine`. Cross-cutting concerns (auth, RBAC, signature, rate-limit, setup guard) live in `middleware`, not services.
- Single synchronous binary + PostgreSQL; all routes in `cmd/server/main.go:buildRouter()`. Migrations are applied externally (compose `migrate` service), never by the server.
- Build state machine is centralized in `model.ValidTransitions`; services call `CanTransitionTo()` — don't add status checks elsewhere.
- Every mutating authenticated request is bound to a user's registered RSA key (`X-Signature*` headers), so users must finish setup (password change + key registration) before any business action. Features must respect `SetupGuard` allow-list.
- Identity keys are multi-key (`user_public_keys`, max 5 active, 90-day expiry, enforced in `UserKeyService`, not DB). Key registration/revocation lock the user row.
- Key backend is DB-only (passphrase-encrypted PEM); new backends implement `keymgmt.KeyProvider`. Private keys are decrypted in memory only at use time.
- Tables added post-SQLC setup (`build_keys`, `attestation_*`) use raw pgx in `service/v2_store.go`; migrating them into `queries/` is the preferred direction.
- Only one `contract.Engine` implementation (`contractgo`, SDK v3) and no mock engine; `keymgmt/mock` exists.
