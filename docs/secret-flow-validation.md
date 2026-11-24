# Secret Flow — verification record

Verified locally on 21 November 2026 and repeated with multiple assignees on
23 November 2026. The full regression suite was repeated on 24 November 2026
before publication. Native deployment limits below remain unchanged.

## Results

| Check | Result |
|---|---|
| Go regression suite, race detector, real PostgreSQL, all database fixtures enabled | 335 passing test cases; no skipped cases |
| Electron-main encrypted-import interoperability with Go worker | Passed with binary bytes, preserved whitespace and the real import module |
| Genuine IBM pvsecret | Plain (including empty/8190-byte limit), Association, AES 128/192/256, AES-XTS 128/256, HMAC-SHA 256/512, EC P-256/P-384/P-521 and Ed25519 request creation passed; invalid sizes rejected |
| Signed HTTP workflow against running Manager + separate Unix worker | Personal import → target → Auditor review → owner approval → preparation → stable UV IDs → workload freeze → environment → attestation key → finalization → export → signed receipt → userdata passed |
| Carbon forms against the real backend | Target/header/HKD/certificate uploads, requirements, personal group revision selection, signed owner approval, Auditor review and real request preparation passed; the real section forms also exercised pinned certificates, CCRV template/schema review, workload/environment receipts and attestation registration |
| UI automated suite | 33 passing tests |
| UI display | Dark/light themes and 768px tablet width checked; no horizontal page overflow or uncaught browser errors |
| Builds | UI production build and Manager/worker/consumer Linux/s390x compilation passed |
| Static checks | go vet and git diff --check passed |
| Real Electron desktop with multiple assignees | Two private source owners, two auditors, three prepared IDs, pinned group approval, workload/environment submission, finalization and native Save with signed acknowledgement passed; downloaded sections were independently decrypted and checked |

Manager PR 40 (`f675f1148f5ae1d386a06e5a900fe36d0d544358`) and UI PR 180
(`207abae056e666eabd19a289a499eb802d1d496d`) are integrated locally. Their
published migration 022 is preserved; unpublished secret migrations follow as
023–025. Added integration coverage checks same-persona catalog isolation,
independent owner consent, an unassigned auditor's rejection, idempotent handoff
between auditors, and invalidation after an owner or target reviewer loses their
assignment. Multiple assignees do not create an approval quorum.

The UI also provides per-field target help for all ten inputs plus the optional
personal profile selector. Mouse hover, keyboard focus, Escape dismissal, unchanged
form values and file-picker isolation were checked in the running Electron UI.

Ordinary and older builds avoid catalog queries; a secret build advertises its requirement in the existing build response and keeps strict metadata transport. A failed required lookup never falls back to a secret-free UI.

The tests cover wrong persona, foreign catalog IDs including Administrator access,
Viewer denial, signed proof tampering, target/consumer/type changes, unknown
platforms, expired native HKDs, missing Retrieve capability, group request limits,
partial worker failure, stale publication during a requirements change, idempotent
retries, revoked approval keys and immutable manifests. Existing logging,
environment variables, registry auths and volumes survive request injection.

Actual native retrieval is gated by the guest's `/dev/uv` kernel and UV operation
masks. The consumer test checks the observed unsupported Z16 masks and confirms
that neither a missing kernel operation nor a missing UV operation is accepted.
Its socket test preserves binary bytes, exposes only one pinned binding, rejects
ID parameters and store management routes, and clears the temporary response.

## Boundaries

- Request creation used real IBM tooling with public development HKDs in explicit
  **SIMULATION**. No result claims native UV Add/Retrieve acceptance. The Z16's
  missing retrievable-secret support remains a hardware/firmware limitation.
- Browser component checks use a Node-side signing bridge. The separate real
  Electron acceptance run and physical desktop recording retain actual local
  authentication, OS-protected device identities, main-process crypto and native
  file/Save dialogs. Demo identities and import-key trust were provisioned before
  recording. The appended, clearly labelled deployment excerpt is an earlier Z16
  recording of a separate contract, not deployment of the simulated secret flow.
- The upstream multiple-assignee PR documents remaining concurrency limits in
  legacy key registration and finalization. Sequential collaboration and consent
  checks here do not establish atomicity for those separate legacy operations.
- A current production IBM HKD chain/CRL set and native target runtime are still
  needed for a native deployment acceptance test. A model name alone is not a
  capability check. Container deployment of the supplied optional Docker/Compose
  recipe was not executed here; a trusted architecture-matching pvsecret tools
  image must be provisioned explicitly.
- Compatible transitive npm updates removed all high/critical audit findings.
  Six moderate findings remain in the existing electron-builder packaging chain;
  npm proposes a breaking change for those, which was not applied.
- Prepared-contract APIs currently use the explicitly pinned immutable contract-go
  fork revision corresponding to PR 344, including the validation fixes of PR 343.

Reproduction prerequisites and commands are in [secret-flow.md](secret-flow.md).
No test account credentials, private keys or secret values are included in this
record or its screenshots.
