# Managed/Connected chain verification (recommended chain)

Local Mode (`cargo test --lib`) proves this policy's own logic, but it **cannot
exercise the included MuleSoft MCP policies** (MCP Support, MCP Schema Validation,
MCP Global Access, ABAC, Tool Mapping) — those load only on a real Flex/Omni
Gateway. This runbook is the integration test that closes that gap: it specifies
the exact chain, request/response order and per-detector assertions to run on a
Managed or Connected gateway. It is the plan for a live run, not a claim that a
run has happened — the Local Mode suite remains the authoritative automated
verification here (#42).

Treat every resource below as a disposable, explicitly authorized test artifact.
Never reuse a production API, gateway registration or Exchange asset identity;
delete all test resources afterward (see `../../docs/CONNECTED-MONITORING-EVIDENCE.md`
for the deletion discipline).

## Connected live-run status

The [2026-09-25 disposable live run](../../docs/COORDINATOR-CONNECTED-CHAIN-EVIDENCE.md)
executed all seven cases using an explicitly approved API deployment operation.
**Three cases passed, one was qualified, and three failed their prescribed
expectations; this is not an all-seven passing result.** Sentinel monitor/block
attribution and bounded response redaction were verified. Cached discovery,
seeding, event-stream rejection and Tool Mapping require the qualifications in
the evidence. Supplemental drift controls also found removal of unchanged tools.

Follow-up issues: [mapping/inspection #48](https://github.com/msaleme/agent-decoy-policies/issues/48),
[test expectations #49](https://github.com/msaleme/agent-decoy-policies/issues/49),
and [baseline schema drift #50](https://github.com/msaleme/agent-decoy-policies/issues/50).
The original matrix below is preserved as the executed contract, including its
failed assumptions; do not cite it as a passing result. The JSON records runtime
configuration checks, Monitoring, infrastructure retries and resource deletion.
Runtime behavior, enums and policy schemas were not changed.

## Chain under test

Apply, in this **request** order (the response path runs in reverse):

1. **MCP Support** — must be first.
2. **MCP Schema Validation** (`validateToolSchema`) — set to `LogOnly` for the
   read so a seeded description surfaces as descriptor drift without removing the
   tool; this is the interaction that motivates `seeding: disabled` (#42).
3. **Authentication** (client-id enforcement or equivalent).
4. **MCP Global Access / ABAC** — the decoy tool must be inert, present in the
   approved asset, and allowed for the monitored principal, or Sentinel loses
   discoverability.
5. **Decoy Coordinator** — after all of the above, so its values-only
   sanitization never mutates a body those policies already trusted.

## Test matrix

Run each case against `POST /<base>/` (trailing slash) with a single JSON-RPC
envelope, `content-type: application/json`, exact `content-length`.

| # | Coordinator config | Request | Expected wire result | Expected chain interaction |
|---|---|---|---|---|
| 1 | observe-first (all monitor/observe, `seeding: disabled`) | clean `tools/list` | 200, body unchanged | Schema Validation clean; no Coordinator edit |
| 2 | observe-first | `tools/call` of the decoy tool | 200 forwarded (monitor) | Coordinator emits a PDK violation; ABAC still allows the inert decoy |
| 3 | `sentinelMode: block` | `tools/call` of the decoy tool | 200 + JSON-RPC `-32008`, backend NOT reached | Coordinator blocks before upstream |
| 4 | `honeytokenMode: block` | response carrying the honeytoken (bounded JSON) | honeytoken absent from body | Coordinator redacts on the reverse path |
| 5 | `seeding: enabled`, Schema Validation `RemoveTool` | `tools/list` | seeded tool removed OR response blocked | confirms the seeding/trusted-descriptor conflict → keep `seeding: disabled` |
| 6 | any enforcing mode | `text/event-stream` request | 415, backend NOT reached | Coordinator fails closed on uninspectable; SSE handled by MCP Support/ABAC, not this policy |
| 7 | Tool Mapping renaming the decoy | `tools/call` of the **mapped** name, Coordinator configured on the **mapped** name | 200 `-32008` in block mode | confirms decoy/breadcrumb must be configured against mapped names |

## Assertions

- **Ordering:** with Schema Validation before the Coordinator, a body the
  Coordinator sanitizes (values-only) must not retroactively fail schema
  validation — verify the reverse response order does not re-trigger a
  validation error on an edited-but-valid envelope.
- **Enforcement, not just registration:** after applying the chain via API, do a
  **UI Save & Apply** and confirm `deployment.updatedDate` bumped and status
  cycled Active→Updating→Active before asserting — API PATCH alone does not push
  config to the running gateway.
- **Violation attribution:** only Sentinel hits should raise a Monitoring policy
  violation (cases 2/3); honeytoken-only and breadcrumb-only hits must not.

## Live-run corrections (#48 / #49 / #50)

The 2026-09-25 run showed four of the prescribed expectations above do not match
the behavior of the included policy chain. The original matrix is preserved as the
executed contract; **the corrected expectations below supersede it** and are the
contract a re-run must satisfy. Do not present the original rows as passing.

- **Case 1 — discovery is cached, not a backend round-trip (#49).** With MCP Schema
  Validation `validateToolSchema: true`, `tools/list` is served from the pinned
  Exchange asset (0 backend calls), and the returned input schemas omit the
  fixture's `additionalProperties: false`. This case therefore verifies a clean
  200 and no Coordinator edit, but **not** an unchanged backend response and **not**
  the Coordinator response path. Add a separate case that forces a backend
  `tools/list` (a config where discovery is not asset-served) to exercise the
  response leg.
- **Case 5 + baseline drift — the seeding/drift beat is confounded (#49, #50).**
  `validateToolSchema: true` makes descriptor-drift/poisoning detection **inactive**
  (the two are mutually exclusive), so `RemoveTool` cannot be attributed to seeding
  under that setting. Under `validateToolSchema: false` with drift `RemoveTool`, the
  chain removed **all** tools as `inputSchema` drift **even with `seeding: disabled`
  and backend descriptors byte-equal to the pinned asset** (#50) — an intermediate
  policy normalizes `inputSchema` before the trusted-pin comparison, so removal is
  not clean proof of a seeding conflict. Redesign the beat: isolate the descriptor
  representation an intermediate policy emits vs. the pinned asset first (#50), then
  demonstrate the seeding conflict only as the *incremental* `description` drift that
  appears when `seeding: enabled` adds a breadcrumb to a tool that lacked one — never
  as bare tool removal. Give the response enough whitespace capacity for the
  non-growing seed edit.
- **Case 6 — SSE is rejected by MCP Support, not the Coordinator (#49).** A JSON-RPC
  body sent with `Content-Type: text/event-stream` was rejected **earlier in the
  chain**: the client saw 200 / JSON-RPC `-32600` ("Invalid JSON RPC Request"), 0
  backend calls — the Coordinator's own 415 never ran. The assertion this case
  should make is **whole-chain fail-closed** (uninspectable transport never reaches
  the backend), not a Coordinator-specific 415. The Coordinator's own SSE/enforcing
  415 remains covered by the Local Mode suite
  (`enforcing_mode_fails_closed_on_an_sse_request`).
- **Case 7 — Tool Mapping tripped the Coordinator's admission, now loosened (#48).**
  With MCP Tool Mapping ahead of the Coordinator, the mapped `tools/call` returned
  **415 `uninspectable-body`** before any decoy matching, in **both** the
  mapped-name and original-name `decoyTools` configs; only the un-mapped control
  reached `-32008`. The exact framing Tool Mapping emits was **not instrumented** —
  a dropped `Content-Length` after the body rewrite is the hypothesis. This policy's
  admission has been loosened accordingly: a JSON body whose `Content-Length` is
  **absent** is now inspected and bounded against the 64 KiB ceiling instead of being
  rejected (see `a_json_body_with_a_dropped_content_length_is_still_inspected` and
  `an_undeclared_body_over_the_limit_still_fails_closed` in the Local Mode suite; SSE,
  compressed, and present-but-oversized/malformed lengths still fail closed). A re-run
  must (a) **instrument** the actual content-type / content-length / transfer-encoding
  the mapped request carries to confirm the root cause, then (b) re-verify Case 7
  reaches `-32008` with the decoy configured on the **mapped** name.

## Automation hook

An executable version belongs in this policy's own ignored
`tests/requests.rs` + `tests/config` (a disposable `registration.yaml`), run
serially:

```bash
cargo +1.89.0 test --test requests --locked --offline -- --test-threads=1
```

That harness needs an authorized registration that is intentionally absent from
the repo, so it does not run in CI or in a clean clone — the matrix above is the
manual procedure until a registration is provisioned. Delete the remote
registration with `flexctl registration delete --file` before deleting the local
file; keep only nonsecret lifecycle evidence.
