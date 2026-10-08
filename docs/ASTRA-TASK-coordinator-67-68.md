# Astra task: declare the Flex runtime minimum (#67) and fix the Coordinator polish items (#68)

**Context.** On 2026-10-08 Tommaso re-reviewed `main` at `5ae2a43` and filed two issues:

- **#67** (Medium, blocks approval): the Coordinator uses a combined headers-and-body state
  but declares a minimum Flex runtime that is too old.
- **#68** (Low): wording, telemetry and Makefile polish.

We checked every item against the code on this Mac. All are confirmed. Two corrections and
one extension are noted below. **This is a source change task.** Change only the listed
runtime behaviour (two telemetry events and one ordering fix). Keep request and response
handling, enums and schemas as they are.

Read these first, in order:

1. Issues #67 and #68 (the full text).
2. `mcp-honeytoken-tripwire/Makefile:75-78` and `mcp-honeytoken-tripwire/scripts/set_min_flex_runtime.py`.
   This is the existing fix for the same bug (#12).
3. `docs/COORDINATOR-CONNECTED-CHAIN-EVIDENCE.md:272`. It already records "declared 1.6.1,
   tested 1.14.0".
4. `docs/CODEX-HANDOFF.md` for branch, authorization and test conventions.

## #67: pin the runtime to 1.14.0 (all four policies, not just the Coordinator)

**Correction to the issue's option 2.** The issue suggests splitting the state "as in the
Tripwire". The Tripwire does **not** split. It still calls `into_headers_body_state()` on
both legs (`mcp-honeytoken-tripwire/src/lib.rs:493, 605, 619`). The #12 fix was **only** the
1.14.0 pin. Use the pin (option 1). That fix has field evidence behind it. A split would be
an unverified behaviour change on 1.12.x, so **do not** split the state.

**Extension.** The same combined state appears in two policies that have no runtime pin:

- `decoy-tool-sentinel/src/lib.rs:251` (request leg).
- `breadcrumb-misdirection/src/lib.rs:293` (request leg).
- `breadcrumb-misdirection/src/lib.rs:390` (response leg, the path that hung on 1.12.1).

Their `build-asset-files` targets have no pin either.

Do this:

1. Move `set_min_flex_runtime.py` to the repo-root `scripts/` directory. Keep it
   parameterless and keep it at `1.14.0`. Run it from all four policies' `build-asset-files`,
   from inside each policy directory, the way the Tripwire does today. Keep the Tripwire
   working. Its existing unit tests (`scripts/test_*.py`) must still pass.
2. Make the runtime gate fail when any policy's built `target/implementation/metadata.yaml`
   or `implementation-dev/metadata.yaml` declares anything other than `minRuntimeVersion: 1.14.0`.
   Use `scripts/flex_runtime_gate.py`, or a small new test it calls. Add a unit test for
   that check.
3. State **"Requires Flex Gateway / Omni Gateway ≥ 1.14.0"** in each policy README and in
   `decoy-coordinator/docs/P4A-SUBMISSION.md` (Overview and Configuration text). Give the
   reason in one line: on 1.12.1 the combined response state can hang the response leg
   (Envoy 504, #12/#67).
4. **Do not publish.** Sentinel, Breadcrumb and the Tripwire are live on P4A. Raising
   their minimum is a new asset version, and that publish needs a human decision. Leave a
   note in the PR body listing which published assets would need a version bump.

## #68: Coordinator polish

1. **Chunked-upload wording** (`src/lib.rs:20-29`, `:134-137`; `README.md:20-39`;
   `docs/P4A-SUBMISSION.md` at the lines cited in the issue). The 1.14 caveat is there, but
   it comes after an unqualified "chunked = uninspectable" claim. Reorder so the 1.14
   behaviour comes first:
   - The host de-chunks and strips `Transfer-Encoding`, so the upload is buffered up to the
     host limit and then inspected against 64 KiB.
   - The `transfer-encoding` guard (`lib.rs:148`) only applies on hosts that keep the header.
   - Name `FLEX_DOWNSTREAM_CONNECTION_BUFFER_LIMIT_BYTES` and the request timeout in the
     README's undeclared-length section.
   - Mark the chunked 415 tests (`src/adapter_tests.rs:112`, `:169`) as host-dependent in
     their comments. Keep the assertions as they are.
2. **Response-side detection event.** A response honeytoken hit (`lib.rs:251-260`) emits
   only `agent_decoy_composition`. Also emit `agent_decoy_detection` with
   `stage:"response"` and the boolean fields. Never include lure values. Update the README
   event table (`:96`), which currently describes the event as request-only. Add a unit test.
3. **Telemetry labels:**
   - (a) A block-mode response whose body length doesn't match its declared
     `Content-Length` is withheld, but it logs `final-output-validated` (`:263` then `:304`).
     Log a distinct reason instead, e.g. `declared-length-mismatch`.
   - (b) In monitor mode with seeding enabled, a length mismatch is logged as
     `seed_skipped_no_capacity` (`:271-275`). Check `bounded` before `seed_applicable`, and
     log a mismatch-specific skip.
   - (c) Replace the free-text `logger::error!` at `:299` with a named structured event, or
     drop it, since the preceding `alert(..., "pdk-response-termination-unavailable")`
     already covers it.
   - Add the new reason strings to the README event table, and add a unit test for each of
     (a) and (b).
4. **`make test`** (`decoy-coordinator/Makefile:59`). Split it into a `--lib` run and a
   `--test requests -- --test-threads=1` run, matching README `:194`. Check whether the
   other three Makefiles have the same issue, and fix the ones that do.
5. **`edition = "2018"`.** Leave it, and say so in the PR. An edition bump can change lint
   and closure-capture behaviour, which is out of scope here.

## Boundaries (load-bearing)

- Make no change to admission, redaction, seeding output or request handling beyond the
  telemetry and ordering fixes above. All existing tests must pass unchanged, apart from
  comment edits.
- Use the PUBLIC repo hygiene. Don't commit any org, environment or client IDs, hosts,
  registration material or secrets. Run the redaction grep before committing. Preserve the
  `v0.1.0-rc.1` tag. Don't publish to Exchange or P4A.
- Tests: `cargo +1.89.0 test --lib --locked --offline` and
  `cargo +1.89.0 clippy --all-targets --locked --offline -- -D warnings` in each touched
  policy, plus `python3 -m unittest discover -s scripts -p 'test_*.py'`.

## Definition of done

- CI is green (policies, upload-gate, GitGuardian).
- All four built metadata files declare `minRuntimeVersion: 1.14.0`, and the gate enforces it.
- The runtime minimum is stated in every README and in the P4A submission text.
- Each #68 item is fixed or explicitly deferred with a reason.
- There are new unit tests for the response detection event and for the two telemetry labels.
- One PR referencing #67 and #68, with the reply to Tommaso's option-2 suggestion (pinned,
  not split) in the PR body.
