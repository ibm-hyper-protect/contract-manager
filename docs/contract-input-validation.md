<!--
Copyright (c) 2026 IBM Corp.
All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->

# Contract input validation and encryption

This change is separate from the multiple-device-key feature. It builds on the server entrypoint in PR #7; the feature diff is relative to that branch. The paired UI branch is `fix/contract-input-validation`. The paired UI can be deployed independently: it uses full schema validation when the endpoint is available and shows an explicit local syntax/section-only review on older servers returning 404. Non-404 failures still block review.

## Inputs

The UI accepts raw `type: workload` / `type: env` YAML and complete plaintext contracts containing both sections. A complete input is validated as a pair before selecting the current persona's section. Starter templates select a single workload format and a single logging provider. Placeholder image names, archives and logging credentials must be configured for the deployment. The UI no longer offers fabricated built-in production certificates; upload the real runtime certificate. For Podman play, upload one or more `v1` Pod/ConfigMap documents, use the Podman template, or supply workload YAML with `play.archive`, `play.resources`, or `play.templates`. Pod and ConfigMap imports are wrapped as `type: workload` with `play.resources`.

Validation uses the full embedded CCRT schema from the pinned contract-go dependency for both individual and combined checks. It rejects malformed YAML, duplicate keys, multiple contract documents, wrong section types, empty Podman play input, simultaneous compose/play, invalid logging and inconsistent paired volume declarations. It does not unpack or inspect TGZ archive contents, run the workload or prove that an image or external registry is available. Plaintext comparisons across different personas are possible only when both plaintext sections are provided together; previous ciphertext is not decrypted by the backend to perform such checks.

## Encryption

Schema validation is repeated on submission. A build pins the runtime encryption certificate; subsequent sections and the attestation key must use that certificate. The environment's signing key is inserted from the registered build key, and conflicting supplied keys are rejected. Finalization requires properly framed encrypted envelopes for workload, env and the attestation key. Existing unpinned builds cannot retrospectively prove the recipient of sections encrypted before this change.

A regression test reproduced intermittent failures in the previous library path. Its raw random passwords can include line terminators, and its text-file helper trims binary ciphertext during decryption. The new adapter uses a printable encoding of 32 random bytes, binary-safe OpenSSL input/output, RSA PKCS#1 v1.5 wrapping and the established AES-256-CBC/PBKDF2 format. CCRT exports use the upstream `contract-basic` wire identifier; legacy `hyper-protect-basic` decryption and upstream `Hpcr*` API names stay compatible. Runtime encryption certificates are validated for PEM structure, dates, RSA strength and key-encipherment usage; choosing the correct trusted runtime certificate remains the operator's responsibility.

Plaintext is sent to the backend for encryption; use HTTPS for production transport. The final signature authenticates the workload/env pair. This verification does not include booting a protected guest on IBM Z.

## Checks

```sh
sqlc generate
go test -race ./...
go vet ./...
go build ./...
```

The UI has focused Node checks (`node --test tests/contractInput.test.mjs`) and `npm run build`. Local HTTP verification creates a disposable database, runs a complete Podman workload build, exports the contract, independently decrypts all three encrypted fields with OpenSSL, and verifies the final signature with Node crypto. A changed pair fails signature verification. Test credentials and private keys are excluded from source control.

Real Electron verification exercised IPC request signing, raw Pod YAML conversion, backend preflight, custom certificate upload, encrypted submission and refreshed state without renderer errors. A local API check also rejected different runtime certificates for both environment and attestation. Independent Node AES/PBKDF2 decoding confirmed the exported wire parameters (SHA-256, 10,000 iterations and an 8-byte salt) for all three encrypted fields.
