# Personal secrets to a runtime contract

The Manager's machine is not the deployment target. Public target artifacts are
supplied explicitly for the protected runtime image and permitted IBM Z hosts.
This feature prepares contracts; it does not deploy VMs or claim that a remote
Ultravisor accepted a request.

## Roles and sequence

| Step | Assigned role | Action and visible information |
|---|---|---|
| Personal catalog | All roles except Viewer | Create only their own neutral secrets and groups. Encrypted values cannot be read back; no sharing or Administrator override. |
| Target | Environment Operator | Select the destination CCRV runtime version, runtime-image source/SHA-256, public SE header and independently obtained header SHA-256, permitted HKDs, and matching runtime encryption certificate. Personal profiles can be reused. |
| Review | Auditor | Verify image/header provenance, destination identity and public artifacts. Worker validates the HKD trust chain with pvsecret; approve this exact revision. |
| Requirements | Solution Provider | Declare logical names, intended workload consumers, and required retrievable or Association type. |
| Owner consent | Each assigned source owner | Select own fixed versions individually or from an immutable personal group revision; map to requirements; sign approval of target digest, versions, type and consumer. No catalog aliases are shared. |
| Preparation | Auditor | Trigger the trusted worker. It checks purpose-bound signatures, authenticates sealed values, creates and verifies pvsecret requests, and publishes actual UV IDs atomically. Repeating an unchanged successful preparation reuses identical stored requests. |
| Workload | Solution Provider | Define the application using the CCRV Podman Play template. Public IDs are already available for the consumer's integration; submitting freezes the manifest and target. Generated configuration belongs to Environment. |
| Environment | Data Owner | Submit logging, environment variables, registry credentials and volumes. Manager inserts public `<LOGICAL_NAME>_SECRET_ID` variables, the registered signing key and exact prepared `uv-secrets`/`host-attestation` blocks; conflicting IDs or hand-written request blocks are rejected. Secret plaintext is never exported as an environment variable. |
| Finalize | Auditor | Register the attestation key and sign the final contract. The same pinned runtime certificate protects both sections and the attestation public key. |
| Download/run | Environment Operator | Download through the existing signed receipt workflow and deploy to the approved destination using the existing runtime process. Runtime imports requests and locks its guest's store by default. |
| Consume | Named workload | Use its pinned ID with a restricted in-guest consumer helper; values can be delivered over a private Unix socket directly into application memory. |

An Administrator may maintain their own catalog but needs a held, assigned
workflow role to contribute to a build. Several people may hold the same workflow role on a build. Each owner still
approves only their own secret versions; any assigned Auditor may perform the next
Auditor step. This is collaboration, not an approval quorum. A logical consumer name documents intent; enforce container isolation
by mounting only its private socket into that consumer. The UV store itself is
per guest, not per container. IDs are identifiers, not access credentials.
Association secrets are 32-byte external-resource bindings; they are not a way
to retrieve arbitrary plaintext. Device-specific AP/crypto-domain provisioning
is outside this change.

## Artifacts and trust

- **SE header**: public header of the protected boot/runtime image, not an OCI
  workload image. Its digest is confirmed against an independently trusted source.
- **HKD**: public destination-machine host key document; one classical certificate
  or a complete two-certificate hybrid HKD. Several explicitly allowed hosts can
  be included. The Manager's host HKD is never chosen automatically.
- **Runtime certificate**: RSA contract-encryption certificate supplied by that
  runtime. It is different from an HKD, worker signing certificate and logging mTLS certificate.
- **Catalog envelope**: RSA-4096 OAEP SHA-256 wrapping of an AES-256-GCM key, with
  catalog/version IDs authenticated as context. Only the isolated worker has its
  private key. Raw secret bytes are never trimmed, logged or returned by the API.
- **Worker request signature**: separate RSA-2048/3072 or supported EC key as
  accepted by `pvsecret`; do not reuse the RSA-4096 catalog wrapping key.
- **Owner proof**: original signed HTTP bytes, including method, path and
  timestamp, retained as Base64 bytes so JSONB cannot reorder the signed content.
  Worker independently checks signature, purpose, build, target, version and
  consumer. Manager remains trusted for the identity-to-key directory and current
  authorization; this is not independent attestation of the Manager.

HKDs bind permitted machines and the SE header binds an image. This combination
does not claim a unique VM-instance binding: optional CUID/CCK/extension-secret
policies require their own trusted provisioning and are not synthesized here.

## Native support and simulation

The contract profile currently supports prepared requests only for **CCRV**.
CCRV uses `play` or confidential-containers workloads; a CCRT Compose contract
cannot simply be relabeled. The runtime handles up to **eight** requests after
group expansion. Personal groups can remain larger; choose a smaller group for
a build.

`NATIVE` preparation validates currently valid HKDs and the configured IBM trust
chain/CRLs using `pvsecret create --offline`, then `pvsecret verify`. No Add,
Retrieve or Lock operation is issued by the worker. Current local CRLs must be
provisioned out of band; network access is disabled. A failed verification never
falls back to `--no-verify`.

An optional target capability JSON report contains `add`, `list`, `lock`,
`retrieve`, `secret_types`, `recorded_at` (RFC3339), and an `evidence` source string.
A known missing operation/type or report older than seven days blocks native
preparation. Missing report means **offline preparation only**, and every result
keeps `hardware_status: NOT_TESTED_ON_TARGET`. A supplied report is operator
input, not a cryptographically attested measurement.

`SIMULATION` requires both an explicit target mode and worker
`SECRET_STORE_ALLOW_SIMULATION=true`. It still creates real pvsecret encrypted
requests, but permits development HKDs without native trust verification.
It is visibly labeled and is never hardware verification or production approval.
The tested Z16 supports Association Add/List/Lock but rejects retrievable secrets
and reports no Retrieve support. A newer CLI, alias or software helper cannot add
missing firmware support. Full native Add/Retrieve needs a supported guest
kernel, Ultravisor and runtime on the actual target (for example a suitably
configured Z17); model name alone is insufficient evidence.

## Worker deployment

Apply migration 022 for multiple assignees, then migrations 023, 024 and 025 for secrets. Keep database backups and the worker wrapping
private key separately protected; losing the key makes old catalog values
unusable. Provision the key outside the source tree/image, mode 0600 and readable
only by the worker UID. Unix socket directory is 0700, socket 0600, no host ports.

`compose/secret-store.yaml` provides catalog import only. Add
`compose/secret-preparation.yaml` for preparation. Its Dockerfile requires an
explicit immutable `PVSECRET_TOOLS_IMAGE` for the target architecture, containing
`/usr/local/bin/pvsecret` and the matching runtime libraries. The worker is
non-root, network isolated, read-only, without capabilities, with core dumps
disabled; temporary public inputs and encrypted requests live in private tmpfs
workspaces. Plaintext values are passed to pvsecret stdin and cleared afterward.
Go and external tools may make internal memory copies; protect the trusted
worker process/host and prevent swap or use encrypted swap.

Worker environment:

| Variable | Purpose |
|---|---|
| `SECRET_STORE_PVSECRET_BIN` | Explicit trusted pvsecret executable |
| `SECRET_STORE_HOST_CERTIFICATES` | Space-separated IBM signing/intermediate cert paths |
| `SECRET_STORE_HOST_CRLS` | Space-separated current CRL paths |
| `SECRET_STORE_ROOT_CA` | Trusted root CA path |
| `SECRET_STORE_REQUEST_SIGNING_KEY` | External private request signing key, 0600 |
| `SECRET_STORE_REQUEST_SIGNING_CERTIFICATE` | Matching public certificate |
| `SECRET_STORE_ALLOW_SIMULATION` | Default false; explicit development opt-in |
| `SECRET_STORE_ALLOW_GUEST_CREATION` | Default false; pvsecret `--force` only for a deliberately trusted SE worker |

Preparation is bounded, one worker job at a time, all-or-nothing. Set Manager
`REQUEST_TIMEOUT=4m` for up to eight verified requests. No database lock is held
while pvsecret executes. Concurrent target/approval changes produce a stale job
and publish no requests. Source/target/type/consumer changes invalidate requests;
after workload submission use a new build. Active accounts, held roles, build
assignments, unarchived sources and non-revoked approval keys are rechecked during
preparation, section submission and finalization.

## In-memory workload consumption

Build `go build ./cmd/secret-consumer` for the guest architecture. Provision one
private socket directory and one helper per consumer binding:

```sh
secret-consumer --id 0xACTUAL_64_HEX_UV_ID \
  --socket /run/my-consumer/secret.sock --pvsecret /usr/local/bin/pvsecret
```

The placeholder must be replaced with the published ID. The helper refuses to
start outside a Linux/s390x SE guest or if `/dev/uv` reports Retrieve absent in
either kernel or UV. Grant `/dev/uv` only to this helper, not to untrusted workload
containers. Mount only that consumer socket directory into its intended app.
`GET /secret` on the Unix socket returns binary bytes with `Cache-Control:
no-store`. Read the HTTP response directly into application memory; no secret
file or environment-variable export is required. It accepts no ID parameter and
exposes no List/Add/Lock endpoint. Only code with that private socket can read it.
There is no automatic simulation fallback or remote secret-return endpoint.

## API

All mutations retain the existing signed HTTP middleware. The existing `GET /builds/{id}` response includes the non-sensitive `secret_flow_required` flag. Older/ordinary builds do not need catalog metadata requests; required secret flows retain strict transport and never treat network or authorization errors as an absent feature. On a build:

- `GET /builds/{id}/secret-flow`: role-redacted snapshot, revision, own approvals,
  target metadata, readiness and published public IDs. Contributors also receive
  `approval_details[logical_name]` with `approved_by: {id, name}` and `approved_at`.
  These come from the stored owner's signed approval and server timestamp, never
  a client-supplied display name. Viewer and unassigned accounts receive no such
  metadata; private catalog aliases, version/group references and values remain
  owner-only.
- `PUT .../target`: `{expected_revision,target}` or an owned `target_revision_id`.
- `PUT .../requirements`: `{expected_revision,requirements:[{name,consumer,kind,type}]}`.
- `PUT .../target-approval`: `{expected_revision,target_revision_id,target_digest,header_provenance_confirmed:true}`.
- `PUT .../approvals`: `{expected_revision,source_revision,target_revision_id,target_digest,sources:[{version_id,group_revision_id?,name,consumer,kind,type}]}`.
  An empty sources list revokes that owner's pre-submission contributions.
- `POST .../prepare`: `{expected_revision}`.
- `GET /secret-store/targets`: Environment Operator's own public target profiles.

Typical errors: `SECRET_TARGET_UNSUPPORTED`,
`RETRIEVABLE_SECRETS_UNSUPPORTED_PLATFORM`, `SECRET_HKD_EXPIRED`,
`SECRET_TARGET_DIGEST_MISMATCH`, `PVSECRET_REQUEST_REJECTED`,
`SECRET_REVISION_CONFLICT`, `SECRET_APPROVALS_PENDING`,
`SECRET_APPROVAL_KEY_REVOKED`, `SECRET_RUNTIME_CERT_MISMATCH`,
`SECRET_REQUESTS_PENDING`, `SECRET_PREPARATION_FROZEN`,
`SECRET_ENVIRONMENT_INVALID`, `SECRET_ENVIRONMENT_BINDING_MISMATCH`.
Errors contain no stored values or raw tool diagnostics.

## Verification

```sh
go test ./...
# Use a disposable PostgreSQL database and real pvsecret tool for integration tests:
SECRET_STORE_TEST_DATABASE_URL='postgresql://...' \
PVSECRET_TEST_BINARY='/trusted/path/pvsecret' \
go test -race ./internal/service ./internal/secretflow ./internal/secretconsumer
```

Fixtures contain only public development artifacts and are never native trust
anchors. The complete test performs personal import/group approval, real pvsecret
request creation, immutable UV IDs, workload freeze, environment injection,
outer encryption/decryption and final signing. It does not report simulated or
offline tests as native UV acceptance.

Prepared-contract APIs are pinned to contract-go PR 344 (including PR 343) until
IBM releases them upstream; the Go module replacement names an immutable public
fork pseudo-version, not a local checkout. Remove it when the upstream release
contains these APIs.

References: [IBM retrievable secrets](https://www.ibm.com/docs/en/ccrv/1.1.x?topic=solutions-retrievable-secret),
[IBM s390-tools pvsecret](https://github.com/ibm-s390-linux/s390-tools/tree/master/rust/pvsecret),
[Linux UV device interface](https://github.com/torvalds/linux/blob/master/arch/s390/include/uapi/asm/uvdevice.h).
