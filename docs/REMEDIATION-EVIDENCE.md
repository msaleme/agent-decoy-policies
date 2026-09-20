# Local remediation evidence

Historical review record. Issue states and action items below reflect that review date.
For current acceptance, see [current status](REMAINING-ISSUES-PLAN.md): the reviewer
subsequently closed #6 and #13 on 2026-09-20.

Worktree: `/tmp/agent-decoy-policies-honeytoken-streaming`.
Branch: `fix/honeytoken-streaming-contract`.
Base/HEAD: `03a5bf8b477e9bd7cf12f808013f17608349ae01`.
Validation was recorded before Git publication. The user subsequently authorized commit,
push and merge subject to repository checks. This current checklist supersedes the historical
snapshots below. The live GitHub issue list and owner acceptance comments were read on
2026-09-19; all 11 issues remain open on GitHub. No issue comments or state were changed.

## Current review status

The four [independent-review findings](INDEPENDENT-REVIEW.md) are fixed, tested and independently
re-reviewed. Honeytoken now fails closed on bounded JSON parser failures; Sentinel accepts valid
client responses and validates envelope types; standard Makefile names match runtime fixtures.
The separate reviewer approved all three fixes. The scoped remediation is ready for merge
consideration, keeping #6 and #13 open and preserving the platform limitations below.

Latest suites: **Honeytoken 42/42, Sentinel 25/25, Breadcrumb 14/14** (81 total).
New Flex runs: **Honeytoken 2/2 in 22.92s; Sentinel 2/2 in 22.65s**. Breadcrumb source/runtime
fixtures are unchanged and retain the earlier 3/3 Flex pass. All three release bundles pass
freshness checks. All-target strict Clippy, formatting and affected release builds pass.

`python3 scripts/test_build_contract.py`: PASS, one test exercising all three Makefile/generator
contracts; both Sentinel/Breadcrumb subcases failed with their old names before the fix.
`python3 scripts/test_flex_runtime_gate.py`: 8/8 PASS. New parser-limit cases are run in Flex
for explicit JSON; missing-content-type variants have library coverage only. Monitor and
plain-text limits are documented, not advertised as complete decoded inspection.

Final hygiene: 75 nonignored files scanned, zero credential filenames or PEM blocks; all three
registrations ignored with 0640 permissions; no staged files; base/branch unchanged;
`git diff --check` PASS. This is a scoped check, not a general secret audit.

This follow-up changed Honeytoken and Sentinel source/tests/READMEs, all three Makefiles,
Sentinel/Breadcrumb playground image pins, added `scripts/test_build_contract.py`, and updated
review/evidence/handoff/runbook documents. No GitHub issue updates, commits, pushes or publication.

## Issue recommendations (subject to the current support boundaries)

| Issue | Implementation and evidence | Recommendation |
| --- | --- | --- |
| [#1](https://github.com/msaleme/agent-decoy-policies/issues/1) Breadcrumb response state | Flex 1.14.0 returns seeded discovery responses in all three modes within the test timeout; current combined state is verified on this runtime | Ready for review of the supported buffered contract; do not change state solely by convention |
| [#2](https://github.com/msaleme/agent-decoy-policies/issues/2) Breadcrumb SSE | Public exclusion documented; finite SSE and encoded responses remain unchanged in Flex; enforcing requests refuse SSE | Ready for review under the owner's explicit tested-exclusion option; actual SSE seeding is unsupported |
| [#3](https://github.com/msaleme/agent-decoy-policies/issues/3) Breadcrumb framing | Remove stale framing only after successful mutation; failed-write regressions; exact upstream sanitized body and received seeded-response length tested | Ready for review |
| [#4](https://github.com/msaleme/agent-decoy-policies/issues/4) Breadcrumb scaffold | Real observe/sanitize/block fixtures, discovery/follow/clean/exclusion controls; empty-marker and disabled-seeding unit controls; usable playground | Ready for review |
| [#5](https://github.com/msaleme/agent-decoy-policies/issues/5) Breadcrumb byte safety | Strict UTF-8 and transport eligibility, decoded JSON matching, invalid/over-limit controls; observe does not rewrite unsupported bytes | Ready for review of documented whole-document marker scope |
| [#6](https://github.com/msaleme/agent-decoy-policies/issues/6) Sentinel violation | Every detected hit now emits PDK violation in monitor and block; local property assertion and replacement precedence tested | Keep open for independent Anypoint Monitoring/export evidence; HTTP success is not that evidence |
| [#9](https://github.com/msaleme/agent-decoy-policies/issues/9) Sentinel scaffold | Real block/monitor tests include clean/discovery, alerts, mixed batches, duplicate/malformed/non-JSON and notifications; exact upstream body/count assertions; configured playground | Ready for review |
| [#11](https://github.com/msaleme/agent-decoy-policies/issues/11) Honeytoken SSE | Explicit exclusion: finite SSE preserved in monitor, withheld in block; tested in Flex | Ready for review under the owner's tested-exclusion option; no live-stream containment guarantee |
| [#12](https://github.com/msaleme/agent-decoy-policies/issues/12) Honeytoken framing/state | Flex returns exact redacted JSON/text bytes with consistent framing, supported state does not hang | Ready for review for successful rewrites; write-failure termination remains a separate platform gap |
| [#13](https://github.com/msaleme/agent-decoy-policies/issues/13) Honeytoken buffering | Headers-first admission; declared length, encoding/type and invalid UTF-8 controls; oversized requests refused without upstream execution | Keep open: block responses still buffer to withhold; no pre-buffer actual-byte cap or indefinite-stream termination proof |
| [#16](https://github.com/msaleme/agent-decoy-policies/issues/16) Honeytoken scaffold/category | Real request and response tests in both modes, exact bytes/framing and transport controls; Security category retained | Ready for review |

## Latest implementation and validation

The Sentinel monitor-violation regression first failed against the previous block-only call.
After moving `generate_policy_violation()` to the common detected-hit path, it passes at the
forwarded-request property boundary. PDK unit responses from a synthetic backend do not carry
request properties, so the monitor assertion deliberately inspects the backend request.
Clean traffic preserves an earlier violation; a decoy hit replaces it, matching PDK's single
active violation slot. A later policy can replace this signal again.

Pre-review local suites: **Honeytoken 37/37, Sentinel 21/21, Breadcrumb 14/14**; superseded by the current review-status counts above.
All three pass formatting, strict all-target Clippy, and release WASM generation.
The runtime asset gate passes all three bundles; its 8 regression tests pass.

Runtime fixtures run serially with cached Flex **1.14.0**, PDK **1.10.0**, and the cached
HTTP mock image. Each policy uses a distinct, authorized disposable Sandbox registration.
Source/schema/fixture fingerprints and the exact embedded release WASM are verified by the
asset gate before execution. Fixture requests have a 15-second timeout.

Pre-review real runtime results (affected-policy reruns are recorded above):

| Policy | Flex integration result | Runtime duration |
| --- | --- | --- |
| Honeytoken | 2 passed, 0 failed | 22.61 seconds |
| Sentinel | 2 passed, 0 failed | 22.70 seconds |
| Breadcrumb | 3 passed, 0 failed | 33.95 seconds |

These seven tests contain multiple behavior scenarios. Honeytoken asserts exact JSON/text
redaction and received framing, response monitor bytes, finite SSE/encoded/oversized response
exclusions, invalid UTF-8 and oversized request admission, and zero blocked upstream execution.
Sentinel asserts both modes, clean discovery/calls, single and mixed-batch decoys, notifications,
malformed/duplicate/non-JSON input, and monitor alert headers on exact forwarded bodies.
Breadcrumb asserts all three modes, exact original/sanitized upstream bodies and follow headers,
correlated seeded-response JSON and framing, finite SSE/encoding exclusion, invalid UTF-8 and
oversized request controls. Marker-disabled and failed-write behavior are local-library evidence.
Encoding fixtures deliberately use opaque bytes tagged as encoded: they prove header-based
exclusion, not decompression. No claim is made about indefinite SSE streams or analytics export.

Final hygiene: `git diff --check` PASS; asset fingerprints PASS for all three projects;
73 tracked/untracked nonignored files scanned, zero credential filenames and zero PEM
certificate/private-key blocks; all three local registrations ignored with `0640` permissions;
zero staged files; HEAD and branch unchanged. This is a scoped scan, not a general secret audit.

Files changed in this final follow-up: Sentinel `src/lib.rs`, `tests/requests.rs`, `README.md`,
and playground configuration; Breadcrumb `src/lib.rs`, `tests/requests.rs` and playground
configuration; Honeytoken `tests/requests.rs`; root `README.md`; all three policy `AGENTS.md`
runtime instructions; `docs/CODEX-HANDOFF.md`, `docs/REMEDIATION-EVIDENCE.md`,
`docs/FLEX-RUNTIME-RUNBOOK.md` and `docs/flex-runtime-verification-boundary.md`.
Earlier remediation changes remain intact. Ignored build assets, per-policy private registration
helpers/runners and nonsecret lifecycle records are local runtime artifacts, not source changes.

Commands (run separately in each policy directory):

```bash
cargo +1.89.0 fmt --check
cargo +1.89.0 test --lib --locked --offline
cargo +1.89.0 clippy --all-targets --locked --offline -- -D warnings
cargo +1.89.0 build --target wasm32-wasip1 --release --locked --offline
cargo +1.89.0 test --test requests --locked --offline -- --test-threads=1
```

Root asset and hygiene commands:

```bash
python3 scripts/test_flex_runtime_gate.py
python3 scripts/flex_runtime_gate.py --prepare
python3 scripts/flex_runtime_gate.py
git diff --check
```

No commits, pushes, PRs, issue updates, Exchange publication, or messages to people occurred.
Registrations stay in ignored local fixture files with owner access and container-group read
only. Their nonsecret lifecycle records are in each policy's ignored
`target/disposable-registration-record.json`; revoke the corresponding disposable Sandbox
registrations and remove local fixtures when follow-up runtime verification is finished.
No identity contents were displayed or copied between projects.

Remaining platform work: independently observe Sentinel's event in Anypoint Monitoring;
obtain a gateway-enforced actual-byte buffer cap and response abort/termination capability;
then test adversarial framing, indefinite streams and write failures at that boundary.
`COMPOSITION.md` remains a design boundary, not an executable cross-policy coordinator.
Do not present these bounded passes as production certification or whole-chain containment.

## Historical evidence

The sections below preserve earlier results and restrictions; they are chronological snapshots,
not current runtime status. Later explicit user authorization enabled the Sandbox registrations.

## Baseline

`cargo +1.89.0 test --lib --locked --offline --quiet`: Honeytoken 32/32, Sentinel 14/14, Breadcrumb 6/6.
`git diff --check`: passed.

## Evidence boundaries

No Docker/Flex behavior run is authorized without a valid locally supplied disposable registration.
No credentials are read, created, copied, or displayed. No commits, pushes, PRs, issue updates, publication, or external contact.
Composition remains a gateway-owned contract, not an implemented cross-filter coordinator.

## Test-first evidence

Focused regressions were added before the relevant production fixes:

| Regression | Observed RED | GREEN behavior |
| --- | --- | --- |
| Honeytoken `mixed_string_and_primitive_response_is_fully_contained` | Numeric token survived string replacement | Mixed numeric/string and boolean/string responses withheld |
| Sentinel `ambiguous_or_mixed_invalid_json_never_reaches_upstream_in_block_mode` | Ambiguous request returned upstream HTTP 200 | Duplicate method/id/name (including escaped member names) and mixed-invalid batches receive 400, zero upstream calls |
| Breadcrumb `failed_required_sanitize_never_forwards_original_body` | Failed write forwarded original bytes, HTTP 200 | HTTP 500, zero upstream calls |
| Breadcrumb `failed_optional_seeding_preserves_original_bytes_and_framing` | Original 63-byte body retained replacement Content-Length 129 | Original bytes and original Content-Length preserved |
| Sentinel `blocked_decoy_sets_policy_violation_without_upstream_execution` | No policy-violation property | Actual PDK violation property present, zero upstream calls; clean/monitor controls absent |
| Breadcrumb `escaped_marker_is_blocked_or_sanitized_as_decoded_json` | Escaped name passed block and remained unsanitized | Decoded match blocks or removes marker while preserving other fields |
| Breadcrumb enforcing-mode admission tests | Unsupported/invalid bodies forwarded | Enforcing modes refuse, observe preserves bytes |
| Breadcrumb response correlation/unsupported-media tests | Unrelated or unsupported responses seeded | Only matching, eligible tools/list response seeded |
| Honeytoken `misleading_json_and_sse_media_types_are_uninspectable` | `application/notjson` admitted | Exact media-type admission rejects deceptive/SSE media types |
| Sentinel `block_rejects_uninspectable_transport_before_upstream` | Encoded input entered JSON parsing | Transport admission rejects before parsing/forwarding |

The PDK test builder appends headers rather than replacing them. New transport tests construct
one value per header so they exercise the intended media type/framing. Breadcrumb's test-only
`pdk-unit` experimental feature enables buffer-limit injection; the production PDK feature set
is unchanged.

## Final local verification

Run separately from each policy directory with Rust 1.89.0 and committed dependency locks:

```bash
cargo +1.89.0 fmt --check
cargo +1.89.0 test --lib --locked --offline --quiet
cargo +1.89.0 clippy --all-targets --locked --offline -- -D warnings
cargo +1.89.0 build --target wasm32-wasip1 --release --locked --offline
cargo +1.89.0 test --test requests --no-run --locked --offline
```

| Policy | Library tests | Format | Strict Clippy, all targets | Release WASM | Integration executable |
| --- | --- | --- | --- | --- | --- |
| Honeytoken | 37 passed, 0 failed | PASS | PASS | PASS | Compiled; not executed |
| Sentinel | 19 passed, 0 failed | PASS | PASS | PASS | Compiled; not executed |
| Breadcrumb | 13 passed, 0 failed | PASS | PASS | PASS | Compiled; not executed |

A first integration compile exposed disabled reqwest JSON convenience methods; fixtures now
parse response bytes with the existing serde_json dependency. Final compilation succeeds.
No Docker/Flex test was executed and no authenticated CLI command was run.
Local test bundles have now been regenerated and verified as described below; Exchange
publication metadata has not been regenerated.
Schema/generated Rust field names and types match for all three policies; this check is not
canonical PDK asset-generation evidence.

## Hygiene

- `git diff --check`: PASS.
- Schema and generated Rust property/type correspondence: PASS for all three policies.
- Tracked and untracked nonignored file scan: 69 files; zero registration/certificate/private-key
  filenames and zero private-key/certificate blocks or inline `tls.key` values. This scoped scan
  does not claim to be a general secret detector or inspect ignored local credential files.
- Registration/certificate ignore rules: PASS in all three test fixture directories.
- Parse-error diagnostics no longer echo raw configuration. Developer guidance agrees.
- No credentials handled; no staged changes, commits, pushes, PRs, publication, or external contact.

## Files changed during this continuation

Earlier Hermes modifications remain intact. This continuation edited:

- `README.md` and all three policy `README.md` / `AGENTS.md` files.
- All three `src/lib.rs` files (production fixes and focused tests).
- `breadcrumb-misdirection/Cargo.toml` (test-only feature), `definition/gcl.yaml` (descriptions),
  and `tests/requests.rs` (mode-specific runtime fixtures).
- `decoy-tool-sentinel/tests/requests.rs` (behavior and upstream-count runtime fixture).
- `docs/flex-runtime-verification-boundary.md` (identity is sensitive, not non-secret).
- `docs/CODEX-HANDOFF.md` and this new evidence checklist.

Generated Rust configuration was not manually edited in this continuation; pre-existing Hermes
configuration changes remain part of the uncommitted worktree.

## Remaining issue gates

Do not close the GitHub issues from these local results alone. Issue numbers/acceptance criteria
are from the local Hermes plan; live issue status/comments were not fetched.

1. All post-remediation Flex behavior, including the policy-violation analytics/export boundary,
   still needs a valid disposable operator-managed registration and fresh generated assets.
2. PDK response-stage replacement plus empty-body double failure still has no supported
   downstream termination guarantee. See `mcp-honeytoken-tripwire/docs/pdk-response-termination-gap.md`.
3. The 64 KiB checks are declared-length admission and post-buffer validation, not a proven
   actual-byte buffering cap. This needs gateway enforcement.
4. SSE seeding (#2) is not implemented. The safe boundary is explicit refusal for enforcing
   requests and no optional seeding of unsupported responses. If #2 requires actual SSE
   transformation, it remains open pending a bounded streaming-capable implementation.
5. `COMPOSITION.md` is not executable composition. Required original-body inspection,
   action arbitration and final-chain rescan need a coordinating policy/gateway capability.
6. A separate reviewer and real runtime evidence remain necessary before publication; this
   continuation performed local code review, not an independent-agent review.

## Runtime-gate preparation follow-up

The next-step inspection found stale generated resources, including a Honeytoken definition
missing `decoyIds` and a Breadcrumb definition missing its fixture name. Added:

- `scripts/flex_runtime_gate.py`: offline build and local test bundle preparation; schema,
  extension-reference, embedded-WASM and source fingerprint verification. Registration is
  checked only for existence, never read. No Docker or authenticated CLI calls.
- `scripts/test_flex_runtime_gate.py`: 8 passing tests for valid assets, stale schema/WASM,
  missing/wrong names, malformed assets/provenance, and changed-source provenance.
- `scripts/.gitignore`: excludes Python cache artifacts.
- `docs/FLEX-RUNTIME-RUNBOOK.md`: exact preparation/runtime commands and operator prerequisites.

Refreshing the schema also exposed a configuration bug: Flex pre-fills `decoyIds: []`, but
Honeytoken rejected that default with nonempty `honeytokens`. The focused
`gateway_default_empty_decoy_ids_uses_opaque_fallback_labels` regression first failed with
`decoyIds must contain one ID for each honeytoken`. Empty/omitted IDs now select the existing
opaque positional labels. A nonempty explicit list still requires complete, unique, nonblank
IDs, verified by a nearby control test. Honeytoken's README and schema description now agree.
The generated Rust field schema was unchanged.

Latest verification:

- Honeytoken: 37/37 library tests; format, strict all-target Clippy, release WASM, and integration
  executable compilation pass. Sentinel 19/19 and Breadcrumb 13/13 source/results unchanged.
- `python3 scripts/test_flex_runtime_gate.py`: 8/8 PASS.
- `python3 scripts/flex_runtime_gate.py --prepare`: all three asset checks PASS; exit 2 solely
  because all three registration fixtures are absent. The command rebuilt WASM offline and
  regenerated implementation YAML via installed `cargo anypoint gcl-gen`.
- Local definition resources are produced from the current source schema with fixture identity
  metadata added. These are explicitly local-mode test resources, not canonical Exchange assets.
- `runtime-bundle.json` fingerprints remain ignored under each release target directory.
- No Docker runtime executed, registration material handled, external contact, or Git write action.

Proceed with operator-managed registration and the bounded runbook. Registration alone does
not settle response termination, streaming, buffering or composition limitations.

## Authorized registration and first real Flex pass

The user subsequently authorized obtaining the disposable registration. The existing Anypoint
CLI login was verified, and a new local-mode Honeytoken gateway was registered in the existing
Sandbox environment. No production environment or pre-existing gateway was changed. Its identity
is stored only in the ignored Honeytoken fixture and was not displayed or copied between projects.
The non-secret gateway name is recorded locally in ignored
`mcp-honeytoken-tripwire/target/disposable-registration-record.json` for later lifecycle cleanup.

The initial runtime attempt failed before assertions because the default Flex container user
could not read the owner-only credential file. Per-user ACLs are unavailable on this filesystem;
permissions were narrowed to owner write/read and container-group read (`0640`, no other-user
access). A subsequent run succeeded:

```bash
cd mcp-honeytoken-tripwire
cargo +1.89.0 test --test requests --locked --offline -- --test-threads=1
```

**PASS: 1 passed, 0 failed, 11.58 seconds**, using cached Flex 1.14.0 and HTTP mock images.
`mcp_honeytoken_blocking_is_in_band_and_does_not_reach_upstream` verifies a clean upstream call,
an HTTP 200 JSON-RPC `-32008` honeytoken denial with the request ID preserved, and an unchanged
upstream hit count after denial. This is current request-path Flex evidence. It does not prove
response containment, streaming behavior, violation analytics export, or other policies.

Sentinel and Breadcrumb runtime verification remain outstanding and have no registration in
their fixtures. Honeytoken response-body Flex scenarios still need behavior-specific tests.
PDK double-write termination, actual-byte limits, SSE seeding and composition remain unresolved.
The disposable registration is retained privately for those remaining bounded Honeytoken runs;
no commits, pushes, PRs or publication occurred.
