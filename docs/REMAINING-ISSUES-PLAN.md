# Remaining security work

This plan tracks acceptance evidence, not merely implementation status.

1. **Transport (#13):** exercise conflicting request framing, incomplete/slow
   uploads, and two exchanges on a verified single TCP connection. Assert both
   client bytes and backend admissions. Keep response-stage double-write failure
   separate from successful body mutation and gateway timeout evidence.
2. **Composition (#23):** provide a single coordinating policy with immutable
   original-body detection, terminal decisions before request mutation, required
   response redaction before optional seeding, and final output validation.
   Add regressions for overlapping markers, seed-created tokens, forged headers,
   and failed writes. Require native tests and actual Flex wire evidence.
3. **Monitoring (#6):** use a designated disposable Connected Mode Sandbox target;
   establish clean/monitor/block windows and observe exported violation metrics.
   A property assertion or gateway log is not Monitoring evidence. Dedicated
   target creation/test asset publication is awaiting the owner's answer.
4. **Lifecycle:** resolve exact disposable registrations by recorded names,
   confirm remote deletion/revocation when possible, and remove local identities
   after runtime checks. Never delete an unrelated gateway or claim local removal
   proves remote revocation.
5. **Delivery:** independent review, strict Clippy, library and integration checks,
   release WASM and asset/provenance hygiene, passing CI, then merge. Keep any
   platform-blocked acceptance item open with its exact remaining prerequisite.

No arbitrary ordering of the existing independent filters is considered a
composition implementation. No policy-level total-process-memory or failed-write
termination guarantee is inferred from per-stream buffering tests.

## Implementation and evidence

- **#23 implemented:** `decoy-coordinator` supplies a single coordinating extension
  for the documented bounded single-envelope JSON-RPC contract. Independent review
  approved it after regressions exposed and fixed protocol-field mutation, missing
  response monitor detection, protected IDs in local denials, and oversized denial
  envelopes. It deliberately retains the separately documented PDK termination gap.
- **#13 advanced:** `raw_framing_idle_upload_and_same_socket_reuse` returns 400 for
  Content-Length/Transfer-Encoding conflicts and inconsistent duplicate lengths,
  returns 408 for an incomplete idle upload, and proves clean → denied → clean
  exchanges on one TCP stream. A catch-all unexpected backend asserts zero hits.
  The stream idle timer is not an absolute deadline for a continuously active
  slow upload. Process-wide resource ceilings and response double-write termination
  still require an outer/runtime capability and remain open acceptance items.
- **Local verification:** 100 library tests (42 Honeytoken, 25 Sentinel,
  14 Breadcrumb, 19 Coordinator); all four strict all-target Clippy and format checks;
  11 Python tests, including four Makefile subcases; four release WASM bundles.
- **Final runtime verification:** Honeytoken **5/5, 61.49 seconds**; Coordinator
  **2/2, 22.54 seconds**. These are Local Mode wire tests, not Monitoring export.
  One parallel attempt failed; the serial run passed. The PDK harness cleanup
  selects a shared Docker label, so run different policy suites serially on the
  same Docker daemon to avoid interference. CI only compiles these runtime suites.
- **#6 blocked:** no target choice/authorization has been received for the proposed
  disposable Connected Mode API/gateway and test-only Sentinel publication.
  The existing standalone Sentinel violation implementation is unchanged. Its
  25 native tests pass; actual exported metrics remain unverified.

## Registration lifecycle

`flexctl registration delete --help` confirms that Local Mode registration deletion
requires a gateway ID or the registration file; deletion by name is unsupported.
The two fresh registrations used for this round are deleted remotely using the
supported `registration delete --file` operation before local file removal.
Only nonsecret lifecycle records remain in ignored target directories.

The **three older registrations** remain unverified. Their local files were removed
before remote deletion in the previous round, and the records retained names but
not gateway IDs. The Sandbox inventory returned no records. Recover their IDs
from platform-side registration/audit records with the platform administrator,
then perform supported deletion. Do not treat deletion of newer registrations as
revocation of those older identities, and do not guess IDs or delete shared assets.
