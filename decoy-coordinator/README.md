# Decoy Coordinator (0.1.0)

An opt-in single Flex policy implementing the bounded composition contract in
[COMPOSITION.md](../COMPOSITION.md). Use it instead of chaining the three
independent filters when their actions must be coordinated. It is not a drop-in
configuration replacement for those policies.

## Scope

This policy inspects **bounded, unencoded, finite single-envelope JSON-RPC 2.0**
only. It is deliberately not a generic MCP Streamable HTTP policy. Inspectable
traffic is an unencoded JSON media type with an exact decimal `Content-Length` at
most 64 KiB carrying one unambiguous JSON-RPC envelope. `text/event-stream` and
other streamed bodies, chunked/unknown length, compressed content, non-JSON,
oversized declared length, batches and duplicate members are **uninspectable or
unsupported**, and are never buffered (so a long-lived stream cannot stall the
filter). If your deployment relies on SSE MCP tool results, redaction/seeding on
that leg does not apply — pair this policy with MuleSoft MCP Support / Global
Access / ABAC, which do process MCP SSE.

## Contract

- Admission is mode-aware. In an **enforcing** mode (any block mode with matching
  detectors) uninspectable or unsupported traffic **fails closed** (415/413/400).
  In **monitor/observe** it passes through **unmodified** with an
  `inspection_skipped` event, so unrelated valid traffic is never blocked.
- Honeytoken, Sentinel and Breadcrumb decisions inspect the original body before
  any mutation. Required block decisions win. Sentinel hits emit a PDK violation;
  Honeytoken-only and Breadcrumb-only hits do **not** emit a PDK violation.
- Breadcrumb sanitization removes the marker only from inert JSON **string values**.
  Object **keys are preserved byte-for-byte** — a marker in a key fails closed
  rather than renaming a field (e.g. `decoy_role` never becomes `role`). A marker
  inside `tools/call` `params` fails closed rather than synthesizing an argument.
  Sanitization also preserves RPC `id`/`method`, leaves a valid envelope, and all
  enforcing detectors are re-checked afterward.
- Response Honeytoken removal runs before optional tools/list seeding. Seeding
  requires an ID captured from the admitted request and a matching valid response.
  A final scan withholds output if seeding creates a protected value.
- Every edit is non-expanding, so **seeding is best-effort**: it is skipped (with a
  `seed_skipped_no_capacity` event) when the marker cannot fit without growing the
  body — a normal compact `tools/list` response has no spare room. For guaranteed
  breadcrumbs, plant them in the backend or an asset-approved tool description and
  leave `seeding: disabled`.
- Headers carry no trusted provenance. Any locally-generated denial undergoes
  decoded containment: if reflecting the RPC `id` would echo **any** configured
  lure back — regardless of which detector blocked or which breadcrumb mode is set,
  and even when the marker is JSON-escaped in the serialized `id` — an empty HTTP
  403 is returned instead of an in-band error. Otherwise blocked requests with IDs
  get HTTP 200 / JSON-RPC -32008; notifications get empty HTTP 202.
- Structured events record stage, requested action, applied action and reason.
  Detector events expose booleans, never configured Honeytoken values. **Warning
  level is reserved for detections and enforcement actions/failures; clean
  pass-through is logged at debug** to avoid warning-log noise. Monitor mode
  records detections without requiring redaction.

## Configuration bounds

Configuration is validated at startup and rejected if it exceeds these caps, so a
mistaken or hostile config cannot turn a bounded request into unbounded scan work:
at most 64 Honeytokens and 64 decoy tools, each detector at most 256 bytes, the
breadcrumb at most 256 bytes, and at most 8 KiB of aggregate detector bytes.
Case-folded detectors are normalized once per request rather than at every visited
JSON node. Expect the per-request cost to stay within a small single-digit
millisecond budget at the maximum body size and detector count; measure the full
policy chain against your latency SLO before enabling on a hot path.

## Interoperability with included MCP policies

`seeding: enabled` mutates tool descriptions, which can conflict with trusted-
descriptor controls. When any of the following are enabled, use the recommended
profile below.

| Included policy | Interaction | Recommended setting |
|---|---|---|
| MCP Support | Must be first in the chain | Keep first; Coordinator after it |
| MCP Schema Validation (`validateToolSchema`) | Treats a seeded description as descriptor drift (LogOnly/RemoveTool/BlockResponse) | `seeding: disabled`; plant the breadcrumb in the approved asset |
| MCP Global Access / ABAC | Can hide or reject the decoy tool, removing Sentinel discoverability | The decoy tool must be inert, present in the approved asset, and allowed for monitored principals |
| MCP Tool Mapping | Renames tools before this policy sees them | Configure decoy/breadcrumb against the mapped names |

**Recommended profile:** observe-first (`honeytokenMode: monitor`,
`sentinelMode: monitor`, `breadcrumbMode: observe`, `seeding: disabled`) to learn
traffic, then enable block modes per detector. When trusted-descriptor controls
are on, keep `seeding: disabled`.

**Policy ordering.** On the request path this policy should run **after** schema
validation, authentication, ABAC/Global Access and any integrity/signature
verification, so its (values-only) sanitization never mutates a body those policies
already trusted. On the response path the chain runs in reverse; verify the exact
request order and resulting reverse response order in Managed or Connected Mode
(Local Mode cannot exercise the included MCP policies).

## Configuration

```yaml
honeytokens: [example-decoy-value]
decoyTools: [admin_override_do_not_use]
breadcrumb: internal_lure_do_not_follow
honeytokenMode: block       # block or monitor
sentinelMode: block         # block or monitor
breadcrumbMode: sanitize   # observe, sanitize, block
seeding: disabled          # disabled or enabled
caseSensitive: false       # ASCII case folding for Honeytokens only
```

Empty detector lists disable their detector; an empty breadcrumb disables its
matching and seeding. Blank list entries and unknown modes are rejected.

## Runtime boundary

Configure and validate gateway buffer/timeout controls before deployment. As with
standalone Honeytoken, an uninspectable enforcing response must be buffered to
withhold it through PDK 1.10. Successful write and empty-body fallback paths are
covered locally. If **both** response writes fail, this policy can report failure
but cannot independently terminate downstream output. The
[PDK termination gap](../mcp-honeytoken-tripwire/docs/pdk-response-termination-gap.md)
still applies; a hard guarantee requires an outer enforcement capability. A
single coordinator solves action ordering, not that missing platform operation.

This version is source/test infrastructure, not an Exchange publication or
production deployment. Anypoint Monitoring export is not proven by its violation
property or by these Local Mode tests.

## Verification

From this directory:

```bash
cargo +1.89.0 test --lib --locked --offline
cargo +1.89.0 clippy --all-targets --locked --offline -- -D warnings
```

From the repository root, `python3 scripts/flex_runtime_gate.py --prepare
--assets-only` builds and checks all four policies without credentials. To run
`cargo +1.89.0 test --test requests --locked --offline -- --test-threads=1`, first
provision an authorized disposable registration in this policy's own ignored
`tests/config` directory. Never reuse another policy's identity. Delete the remote
registration using `flexctl registration delete --file` before deleting the local
file; keep only nonsecret lifecycle evidence.
