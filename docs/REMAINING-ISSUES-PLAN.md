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

## Resource preflight follow-up

[Gateway resource preflight](GATEWAY-RESOURCE-PREFLIGHT.md) supplies an opt-in
Docker memory/swap profile and a checker that confirms live cgroup-v2 limits.
A real isolated container without a memory cap was rejected; a 256 MiB hard cap
with no swap passed. This is kernel/configuration evidence, not a Flex load test.
The expanded Honeytoken suite passed **5/5, 62.80 seconds**, including an active
two-second upload accepted under a one-second stream idle timer. This confirms
that the idle timer is not an absolute upload deadline. The newest disposable
Honeytoken registration was remotely deleted before its local file was removed.
Deployment load/recovery, absolute upload deadlines, and double-write termination
remain open under #13. #6 still needs the designated Connected Mode target.

## Outer upload-gate follow-up

The [optional HAProxy gate](../deployment/upload-gate/README.md) now supplies a
verified two-second body collection deadline with a complete-body check before
forwarding. Credential-free Docker tests cover active and concurrent uploads,
buffer saturation, framing rejection, a 64 KiB clean control, live cgroup limits,
a kernel OOM kill, and explicit restart/recovery. CI runs this outer-component
suite. The Compose profile removes the direct Flex host port.

The optional `--flex` suite also passed through edge → Flex 1.14.0 → synthetic
backend, including sixteen concurrent 64 KiB clean exchanges, Honeytoken denial,
a kernel OOM kill in Flex’s 1 GiB cgroup and explicit restart/recovery. The test
registration was remotely deleted before local removal. These are bounded local
results; production ingress isolation and sizing remain deployment responsibilities.
The missing PDK response-stage termination capability remains open under #13.
#6 still awaits the requested authorization for a dedicated Connected Mode test
target and test-only Sentinel publication, or designation of an existing target.

## Registration lifecycle

`flexctl registration delete --help` confirms that Local Mode registration deletion
requires a gateway ID or the registration file; deletion by name is unsupported.
The two fresh registrations used for this round are deleted remotely using the
supported `registration delete --file` operation before local file removal.
Only nonsecret lifecycle records remain in ignored target directories.

The **three older registrations are also deleted remotely**. Their local files
had been removed before remote deletion, leaving names without gateway IDs.
A narrowly scoped, read-only Audit Log Query recovered the three successful
Flex Gateway creation records. Each exact registration name, object ID, and
Sandbox environment ID was checked before supported
`flexctl registration delete --gateway-id` was run. All three operations
returned success. No shared gateway was selected, and no identity file was
recreated. Nonsecret deletion evidence remains outside the repository.

All five disposable registrations used through PR #25 have now
received successful remote deletion responses. Local fixture removal alone
was not treated as evidence of remote deletion.
