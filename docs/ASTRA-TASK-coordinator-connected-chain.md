# Astra task — re-run the Decoy Coordinator connected chain (confirm #48, close #49/#50)

**Context.** The first connected run (PR #47, merged) executed the 7-case matrix on
a real gateway and surfaced three real interoperability findings: #48 (Tool Mapping
→ Coordinator 415 before decoy matching), #49 (cached discovery / seeding / SSE test
expectations don't match the included chain), #50 (unchanged pinned schemas trigger
`RemoveTool` drift). This follow-up **re-runs the corrected contract** and confirms
the code fix for #48. It is a verification task — **do not change runtime behavior,
enums or schemas**; if a new defect surfaces, file an issue with evidence.

Read first, in order:
1. `decoy-coordinator/docs/MANAGED-CHAIN-VERIFICATION.md` → the **"Live-run
   corrections (#48 / #49 / #50)"** section. Those corrected expectations, not the
   original matrix rows, are the contract to satisfy.
2. `docs/COORDINATOR-CONNECTED-CHAIN-EVIDENCE.md` + `docs/evidence/coordinator-connected-chain-2026-09-25.json`
   — the prior run's evidence and artifact-identity/cleanup discipline; mirror it.
3. `docs/CODEX-HANDOFF.md` — working-state / branch / authorization conventions.

## The #48 fix already landed in source

A runtime change was made **here** on branch `fix/coordinator-48-inter-policy-framing`
(will merge to `main` before you start — fetch `origin/main` and confirm it is
present): the Coordinator now inspects a JSON body whose `Content-Length` is
**absent** (bounded against the 64 KiB ceiling) instead of rejecting it 415, because
Tool Mapping drops `Content-Length` after rewriting the body. SSE, compressed, and
present-but-oversized/malformed lengths still fail closed. Local Mode covers this
(`a_json_body_with_a_dropped_content_length_is_still_inspected`,
`an_undeclared_body_over_the_limit_still_fails_closed`). Your job is the interop
evidence Local Mode cannot produce.

## What to do

1. Fetch `origin/main`, confirm the #48 fix is present, create a fresh topic branch.
   Verify `git rev-parse --show-toplevel` is this repo before staging.
2. Stand up a **disposable, explicitly authorized** Connected-Mode gateway (Flex/Omni
   ≥ 1.14) with a disposable registration identity, one inert JSON-RPC backend and a
   dedicated Docker network — same isolation and cleanup rigor as the prior run.
3. **#48 — instrument, then verify.** With MCP Tool Mapping ahead of the Coordinator
   (same chain and mapping as issue #48), **capture the actual request representation
   the Coordinator receives** for the mapped `tools/call`: `content-type`,
   `content-length` (present/absent), `transfer-encoding`, and body bytes. Record it
   in the evidence — this confirms or refutes the dropped-`Content-Length`
   hypothesis. Then assert the mapped case now returns **200 / JSON-RPC `-32008`,
   backend NOT reached**, with the decoy configured on the **mapped** name; keep the
   un-mapped original-name control. If it still 415s, the root cause is something
   other than a dropped length — file a new issue with the captured framing rather
   than adjusting the matrix to pass.
4. **#49 — corrected cases.** (a) Add a case that forces a **backend** `tools/list`
   (discovery not asset-served) so the Coordinator response leg is actually
   exercised, separate from the cached-discovery 200. (b) State the event-stream case
   as **whole-chain fail-closed** (`-32600` from MCP Support, 0 backend calls), not a
   Coordinator 415.
5. **#50 → seeding beat.** First isolate the descriptor representation an intermediate
   policy emits vs. the pinned asset (why unchanged schemas read as `inputSchema`
   drift). Then demonstrate the seeding conflict **only** as the incremental
   `description` drift that appears when `seeding: enabled` adds a breadcrumb to a
   tool that lacked one — never as bare tool removal. Confirm the recommended
   `seeding: disabled` + asset-planted breadcrumb avoids it. Give the response enough
   whitespace capacity for the non-growing seed edit.
6. Record results as an updated `docs/COORDINATOR-CONNECTED-CHAIN-EVIDENCE.md` + a new
   machine-readable JSON under `docs/evidence/` (artifact identity, WASM SHA-256, UTC
   timestamps, HTTP statuses, captured framing, violation counts, request
   dispositions, cleanup status). Then reference the re-run on #48/#49/#50 and, if all
   corrected cases pass, note it in `MANAGED-CHAIN-VERIFICATION.md`.

## Boundaries (load-bearing)

- **Verification only.** No runtime/enum/schema changes; file issues, don't patch to
  pass. Preserve the prior failed results; do not silently substitute controls.
- Keep everything in the authorized disposable scope; **delete every test resource**
  afterward (gateway, API instances, test Exchange versions, backend, network,
  registration) and confirm deletion. Never print or copy identity material.
- Preserve the immutable source tag `v0.1.0-rc.1`. No final release, no production
  Exchange publication.
- **Honesty:** monitor-mode labels a hit even though the backend still receives it —
  not proof of enforcement. Host-failure / response-termination containment remains
  unverified. Never treat headers as trusted provenance.

## Definition of done

CI green (policies + upload-gate + GitGuardian); a committed, reproducible evidence
doc + JSON with the **captured Tool Mapping framing** and the corrected cases run on
a real gateway, resources deleted; #48/#49/#50 annotated with the re-run reference.
