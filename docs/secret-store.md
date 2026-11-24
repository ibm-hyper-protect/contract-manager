# Personal catalog and runtime flow

For the complete implemented build flow, target profiles, owner approvals, worker configuration and supported runtime limits, see [secret-flow.md](secret-flow.md).

# Personal Secret Store

The catalog stores encrypted values, immutable versions and groups of pinned
versions. Entries stay neutral: Association versus Retrievable is selected later
when the build declares requirements and the assigned Auditor prepares approved runtime requests.

The complete [runtime secret flow](secret-flow.md) turns approved versions into
real pvsecret requests and public UV IDs for an explicitly selected destination.
Catalog UUIDs remain separate from UV IDs. Unapproved or incomplete sources block
workload submission with `SECRET_REQUESTS_PENDING`; the existing secret-free flow
continues when no sources or requirements are selected.

## Permissions

| Actor | Personal catalog | Build preparation |
|---|---|---|
| Administrator / Auditor / Solution Provider / Data Owner / Environment Operator | Create and manage their own encrypted secrets, immutable versions and groups. | Add, replace or remove their own references only when assigned to the build in a contributing role, before workload submission. |
| Viewer | No catalog access or secret creation. | No source editing and no access to personal source metadata. |

Ownership is based on the authenticated user ID, not the selected persona. A person
with multiple roles uses the same personal store. Administrators have no override
for another person's catalog. Knowing an object/version/group UUID, sharing a build,
or holding historical grants does not authorize access. Hidden entries return 404.
There is no sharing API or recipient directory and no plaintext reveal endpoint.

Groups bundle 1–64 exact versions from the same owner's store, with one version per
secret. Revisions are immutable; rotating a secret never changes an existing group
revision or build reference. The UI selects the newest complete group revision by
default and allows choosing an older revision explicitly.

The UI places personal references under **Build → Assignments → Runtime secrets**.
Each person sees and edits only their own contributions. Replacing an empty or
partial personal selection never clears another person's references. Legacy source preparation is limited to 64 sources; the complete runtime flow
is limited to eight requests after group expansion and uses a shared `expected_revision` check, so
concurrent changes fail with a refreshable conflict rather than overwrite updates.
All pending sources count toward the workload-submission guard, even when hidden
from the submitting person. A build assignment alone never shares a secret value,
its catalog entry or its group.

Migration `024_personal_secret_store` retires historical sharing grants while
preserving encrypted values, versions, groups, audit history and pinned build
references. Existing grants are ignored by the application even before that
migration runs. Its rollback recreates an empty legacy grant table; it never
restores removed permissions. Legacy mixed-owner groups omit foreign members from
responses and cannot be re-used to attach someone else's sources; save a new
personal revision instead.

## Value and key protection

The Electron main process seals each value with a fresh AES-256-GCM key and random
12-byte nonce, then wraps that key with the worker's RSA-4096 public key using
OAEP-SHA-256. The authenticated context is the ASCII string
`contract-secret-import-v1\n<secret UUID>\n<version UUID>\n`.
The payload has format `1`, `secret_id`, `version_id`, `key_id`, and canonical
Base64 `wrapped_key`, `nonce`, `ciphertext`, `tag`. The tag is 16 bytes. Values may
contain 0–65536 bytes; binary content and whitespace are preserved.

The Manager receives and stores only the encrypted package. A separate Unix-socket
worker holds the RSA private key and verifies incoming packages. Its import API returns only public key metadata or the validated byte count;
its preparation API returns only encrypted requests and public UV IDs. There is no reveal endpoint.
The database, API responses and audit records do not contain plaintext values or
the worker private key. Public metadata includes aliases, versions and byte counts;
do not put credentials in aliases or descriptions.

The Manager pins the SHA-256 fingerprint of the worker's SPKI DER public key using
`SECRET_STORE_IMPORT_KEY_FINGERPRINT`. The desktop separately pins that fingerprint
per server after explicit confirmation. Verify the fingerprint using a trusted
operator channel. A key change fails closed. Use HTTPS or a loopback SSH tunnel;
the desktop rejects catalog operations over remote plaintext HTTP.

The worker necessarily holds plaintext briefly in memory to authenticate imports.
Buffers are cleared where supported; JavaScript strings and Go runtime allocations
cannot promise complete memory erasure. File import avoids putting plaintext file
contents in the renderer. Protect the desktop and worker hosts, disable core dumps,
and provision encrypted storage/swap as required by your deployment. This is
application encryption, not an HSM or Ultravisor-backed store. Compromise of both
the wrapping key and database can expose stored values.

## Run the isolated import worker

1. Apply migrations through `025_secret_preparation_flow` using the normal migration process.
2. Provision a dedicated RSA-4096 private key **outside the repository and image
   build context**. Use a regular PEM file readable only by the worker (`0600`).
   Back it up encrypted and separately from database backups; losing it makes
   existing versions unusable. Automatic key rotation/re-wrapping is not provided.
3. Create a private socket directory (`0700`) accessible only to the worker and
   Manager service identity.
4. Run `go build -o secret-store-worker ./cmd/secret-store-worker`, then start with
   `SECRET_STORE_PRIVATE_KEY_FILE` and `SECRET_STORE_WORKER_SOCKET`. The startup log
   reports the public fingerprint. Do not print the private key.
5. Configure the Manager with the same socket path and
   `SECRET_STORE_IMPORT_KEY_FINGERPRINT=<64 lowercase hex characters>`.

Without worker configuration, catalog metadata/preparation works but encrypted
value import returns `503 SECRET_STORE_UNAVAILABLE`.

`Dockerfile.secret-store-worker` and `compose/secret-store.yaml` provide an optional
deployment profile. Build the normal Manager image, then run Compose with both
`compose/docker-compose.yaml` and `compose/secret-store.yaml`. Set the absolute
`SECRET_STORE_PRIVATE_KEY_FILE` path and fingerprint in `compose/.env`. The Linux
key file must be owned by UID/GID `10001:10001`, with mode `0600`. This overlay runs
the Manager and worker as that service identity. The Manager mounts only the socket
volume, never the private key. The worker has no network, database credentials or
capabilities; its root filesystem is read only and core dumps are disabled.

Stop both services before replacing a key. Never auto-generate a replacement on
restart. A leftover socket after an unclean exit causes startup to fail; only
remove that socket after confirming its worker has stopped. Host root and the
Docker daemon remain trusted. Validate volume ownership and the overlay on the
target container runtime before deployment.

## API

All routes use existing authentication and role checks; every mutation requires
the existing request signature headers. JSON bodies reject unknown fields.

| Method | Path | Purpose / body |
|---|---|---|
| GET | `/secret-store/import-key` | Public import key and fingerprint. |
| GET / POST | `/secret-store/objects` | List / create `{kind: SECRET or GROUP, alias, description}`. Lists only the authenticated owner; accepts `kind`, `search`, `limit` (1–100), `offset`. Legacy `scope` parameters cannot broaden access. |
| GET / PATCH | `/secret-store/objects/{objectID}` | Public detail / edit `{expected_revision, alias, description, archived}`. |
| POST | `/secret-store/objects/{objectID}/versions` | Reserve immutable version context; body `{}`. |
| PUT | `/secret-store/objects/{objectID}/versions/{versionID}/payload` | Authenticate and seal encrypted package. Identical retries succeed; replacement is rejected. |
| POST | `/secret-store/objects/{objectID}/revisions` | Pin group `{expected_revision, version_ids}`. |
| GET / PUT | `/builds/{id}/secret-sources` | Legacy preparation only, before selecting a target. After selecting a target, use signed owner approvals in the [runtime flow API](secret-flow.md#api). |

Build preparation locks the build and assignment before committing. Workload
submission checks pending sources under the same build lock, so concurrent source
changes cannot bypass the submission guard. A stale revision returns `409
SECRET_REVISION_CONFLICT`; preparation after workload submission returns `409
SECRET_PREPARATION_FROZEN`. Unknown or hidden catalog entries return `404`.

## Validation

Run `go test ./...`, `go vet ./...`, and build both commands. Set
`SECRET_STORE_TEST_DATABASE_URL` to an expendable PostgreSQL database to run
`go test -race ./internal/service -run TestSecret -count=1`; each test creates and
drops only its own random schema. Tests cover all five contributing roles, Viewer rejection, owner isolation including
administrators, personal group revisions, migration of old grants, immutable values, concurrent
updates and the existing secret-free submission path. Crypto tests authenticate
binary/whitespace/empty/maximum-size envelopes and reject tampering.
