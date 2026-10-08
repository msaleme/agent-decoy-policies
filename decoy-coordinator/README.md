# Decoy Coordinator (0.1.0)

**Requires Flex Gateway / Omni Gateway ≥ 1.14.0.**
On 1.12.1 the combined response state can hang the response leg (Envoy 504, #12/#67).

An opt-in single Flex policy implementing the bounded composition contract in
[COMPOSITION.md](../COMPOSITION.md). Use it instead of chaining the three
independent filters when their actions must be coordinated. It is not a drop-in
configuration replacement for those policies.

## Scope

This policy inspects **bounded, unencoded, finite single-envelope JSON-RPC 2.0**
only. It is deliberately not a generic MCP Streamable HTTP policy. Inspectable
traffic is an unencoded JSON media type carrying one unambiguous JSON-RPC envelope
whose buffered body is at most 64 KiB. A decimal `Content-Length`, when present,
must match the body exactly.

- **Requests:** on Flex Gateway 1.14, the host de-chunks uploads and strips
  `Transfer-Encoding` before this policy runs (#63). JSON uploads without a visible
  `Content-Length` or `Transfer-Encoding` are buffered up to the host's downstream
  buffer limit, then inspected against the 64 KiB ceiling; a decoy is still blocked.
  An earlier policy such as Tool Mapping can also drop `Content-Length` after a
  rewrite. Configure `FLEX_DOWNSTREAM_CONNECTION_BUFFER_LIMIT_BYTES` and the
  gateway's request timeout before deployment: the policy's 64 KiB check applies
  **after** the host buffers an undeclared-length body, including an HTTP/2 upload.
  The `Transfer-Encoding` admission guard only applies on hosts that retain that
  header. To refuse chunked framing before buffering, use ingress enforcement:
  the optional [upload gate](../deployment/upload-gate/README.md) rejects any
  `Transfer-Encoding` and requires one declared `Content-Length` ≤ 64 KiB.
- **Responses:** must declare a valid `Content-Length` within 64 KiB. A chunked or
  otherwise undeclared-length response is uninspectable, including one whose length
  a policy placed after this one in the chain dropped.

`text/event-stream` and other streamed bodies (excluded by the media type),
compressed content, non-JSON and a present-but-oversized/malformed declared length
are **uninspectable**: they are classified in the header phase and never buffered
(so a slow or long-lived stream cannot stall the filter). Batches and duplicate
members are **unsupported**: they are buffered within the bounds above, parsed,
rejected or skipped by mode, and still raw-scanned for detection telemetry.

**Response redaction needs a declared length.** Chunked `application/json`
responses, which many upstreams (streaming frameworks, HTTP/2 backends) send by
default, are forwarded unredacted with the event below; confirm your upstream
sets `Content-Length` before relying on Honeytoken response redaction.

**Streamed responses are not redacted, even in `honeytokenMode: block`.** An
uninspectable response (MCP Streamable HTTP servers commonly answer `POST` with
`text/event-stream`) is forwarded unmodified, and the policy logs a
**warning-level** `response_inspection_skipped` event in Honeytoken block mode
(info level otherwise). If your deployment relies on SSE MCP tool results, pair
this policy with MuleSoft MCP Support / Global Access / ABAC, which do process MCP
SSE.

## Contract

- Admission is mode-aware. In an **enforcing** mode (any block mode, or Breadcrumb
  `sanitize`, with configured detectors) uninspectable or unsupported request
  traffic **fails closed** with a bare HTTP status: **415** uninspectable body,
  **413** invalid framing (length mismatch or over 64 KiB), **400** unsupported
  envelope (batch, duplicate members, non-JSON-RPC). These are deliberately not
  in-band JSON-RPC errors: until a body is proven to be one well-formed request
  there is no unambiguous `id` to reflect. In **monitor/observe** such traffic
  passes through **unmodified** with a warning-level `inspection_skipped` event,
  so unrelated valid traffic is never blocked but the blind spot is visible.
- Honeytoken, Sentinel and Breadcrumb decisions inspect the original body. Required
  block decisions win. Sentinel hits emit a PDK violation; Honeytoken-only and
  Breadcrumb-only hits do **not** emit a PDK violation.
- **Requests are never rewritten.** Breadcrumb `sanitize` is accepted for
  configuration compatibility but, on requests, **blocks exactly like `block`**
  (in-band -32008 for a request with an `id`). Removing a marker from any request
  field could change which tool, resource (`resources/read` `uri`), prompt
  (`prompts/get` `arguments`) or argument an earlier schema, authorization or ABAC
  policy already approved, and no `(method, field)` pair — including unknown future
  methods — is provably inert to rewrite, so the allow-list of rewritable request
  fields is empty.
- Response Honeytoken removal runs before optional tools/list seeding. Seeding
  requires an ID captured from the admitted request and a matching valid response.
  A final scan withholds output if seeding creates a protected value.
- Every edit is non-expanding, so **seeding is best-effort**: it is skipped (with an
  info-level `seed_skipped_no_capacity` event) when the marker cannot fit without growing the
  body — a normal compact `tools/list` response has no spare room. For guaranteed
  breadcrumbs, plant them in the backend or an asset-approved tool description and
  leave `seeding: disabled`.
- Headers carry no trusted provenance. Any locally-generated denial undergoes
  decoded containment: if reflecting the RPC `id` would echo **any** configured
  lure back — regardless of which detector blocked or which breadcrumb mode is set,
  and even when the marker is JSON-escaped in the serialized `id` — an empty HTTP
  403 is returned instead of an in-band error. Otherwise blocked requests with IDs
  get HTTP 200 / JSON-RPC -32008; notifications get empty HTTP 202.
- Structured gateway log events (JSON, one per line):

  | `event` | Level | When |
  |---|---|---|
  | `agent_decoy_detection` | warn | A request detector or response Honeytoken matched (`stage: "request"` or `"response"`). Request matches include an unsupported envelope or a mismatched-length body within 64 KiB (raw-byte match; Sentinel needs a parsed `tools/call`). Fields: `stage`, `honeytoken`, `breadcrumb`, `sentinel` — booleans only, never lure values |
  | `inspection_skipped` | warn | Monitor/observe forwarded a request it could not inspect. Fields: `stage`, `reason` (`uninspectable-body`, `invalid-framing`, `unsupported-jsonrpc`) |
  | `response_inspection_skipped` | warn in Honeytoken block mode, info otherwise | Response inspection was skipped for `uninspectable-body` (streamed, undeclared length, compressed, non-JSON), or `declared-length-mismatch` on an unchanged body. Fields: `stage`, `reason` |
  | `seed_skipped_no_capacity` | info | Seeding applied but the marker did not fit without growing the body |
  | `agent_decoy_composition` | warn for detections and enforcement actions/failures; debug for clean pass-through and no-ops | Coordinated verdict. Fields: `stage`, `requested`, `applied`, `reason`; `declared-length-mismatch` identifies withholding for invalid response framing, distinct from `final-output-validated`. Failed mutation and fallback use `pdk-response-termination-unavailable` |

  Monitor mode records detections without requiring redaction.

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
| MCP Tool Mapping | Placed before this policy, it maps client-visible names back to backend names on the request, and renames after this policy on the response | Configure `decoyTools`/breadcrumb with the **backend (asset) names** — the names this policy actually sees — not the client-visible mapped names (verified connected, #48) |

**Recommended profile:** observe-first (`honeytokenMode: monitor`,
`sentinelMode: monitor`, `breadcrumbMode: observe`, `seeding: disabled`) to learn
traffic, then enable block modes per detector. When trusted-descriptor controls
are on, keep `seeding: disabled`.

**Policy ordering.** On the request path this policy should run **after** schema
validation, authentication, ABAC/Global Access and any integrity/signature
verification. This policy never rewrites a request body, so it cannot invalidate a
body those policies already trusted. On the response path the chain runs in reverse; verify the exact
request order and resulting reverse response order in Managed or Connected Mode
(Local Mode cannot exercise the included MCP policies). The exact chain, request
matrix and per-detector assertions are in
[docs/MANAGED-CHAIN-VERIFICATION.md](docs/MANAGED-CHAIN-VERIFICATION.md).

## Configuration

```yaml
honeytokens: [example-decoy-value]
decoyTools: [admin_override_do_not_use]
breadcrumb: internal_lure_do_not_follow
honeytokenMode: block       # block or monitor
sentinelMode: block         # block or monitor
breadcrumbMode: block      # observe or block (sanitize = block on requests)
seeding: disabled          # disabled or enabled
caseSensitive: false       # ASCII case folding for Honeytokens only
```

Empty detector lists disable their detector; an empty breadcrumb disables its
matching and seeding. Blank list entries and unknown modes are rejected.

## Runtime boundary

Configure and validate gateway buffer/timeout controls before deployment. Unlike
standalone Honeytoken, this policy does not buffer an uninspectable response to
withhold it; it forwards it with the `response_inspection_skipped` event described
above. For an inspectable response, successful write and empty-body fallback paths are
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

The Makefile is the standard PDK policy Makefile (`setup`, `build-asset-files`,
`build`, `run`, `test`, `publish`, `release`, `show-policy-ref-name`). `make build`
builds only this policy: `target/wasm32-wasip1/release/decoy_coordinator.wasm` plus
its generated definition and implementation YAML (`decoy-coordinator-v0-1-impl`).
`make build`/`publish` need `group_id` in `Cargo.toml` set to your Anypoint
organization ID; the committed placeholder is rejected.

`make runtime-gate` (or `python3 scripts/flex_runtime_gate.py --prepare
--assets-only` from the repository root) builds and checks the local Flex runtime
bundles for all four policies without credentials; it is a test gate, not on the
publish path. Any existing Exchange metadata is also checked for the 1.14.0 pin.
With the owning group ID supplied through `ANYPOINT_GROUP_ID`,
`python3 scripts/verify_exchange_runtime.py` generates both Exchange metadata
variants for all four policies, validates the runtime pin, and redacts the group
ID without publishing or changing `Cargo.toml`. The CI `exchange-metadata` job
requires that repository secret and is explicitly skipped when it is unavailable
(including fork PRs). `python3 scripts/flex_runtime_gate.py --exchange-metadata-only`
requires and checks all eight generated metadata files. To run
`cargo +1.89.0 test --test requests --locked --offline -- --test-threads=1`, first
provision an authorized disposable registration in this policy's own ignored
`tests/config` directory. Never reuse another policy's identity. Delete the remote
registration using `flexctl registration delete --file` before deleting the local
file; keep only nonsecret lifecycle evidence.
