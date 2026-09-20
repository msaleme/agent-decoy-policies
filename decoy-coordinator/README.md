# Decoy Coordinator (0.1.0)

An opt-in single Flex policy implementing the bounded composition contract in
[COMPOSITION.md](../COMPOSITION.md). Use it instead of chaining the three
independent filters when their actions must be coordinated. It is not a drop-in
configuration replacement for those policies.

## Contract

- Nonempty requests require an unencoded JSON media type and a valid declared
  length at most 64 KiB. They must be one unambiguous JSON-RPC 2.0 envelope.
  Batches, duplicate members, parser-limit failures and unsupported bodies are
  rejected. This admission rule applies in every mode.
- Honeytoken, Sentinel and Breadcrumb decisions inspect the original body before
  any mutation. Required block decisions win. Sentinel hits emit a PDK violation.
- Breadcrumb sanitization may change JSON string values and keys only when it
  preserves RPC `id` and `method`, creates no duplicate keys, and leaves a valid
  envelope. All enforcing detectors are checked again after sanitization.
- Response Honeytoken removal runs before optional tools/list seeding. Seeding
  requires an ID captured from the admitted request and a matching valid response.
  A final scan withholds output if seeding creates a protected value.
- Every edit is non-expanding. Optional seeding is skipped if it cannot fit within
  the original body length. This conservative limit preserves required redaction
  and avoids relying on response buffer growth. Whitespace compaction or required
  redaction may provide room for a seed.
- Headers carry no trusted provenance. Local denials also undergo containment
  checks: if echoing an RPC ID would expose a protected value, return an empty
  HTTP 403 instead of an in-band error. Otherwise blocked requests with IDs get
  HTTP 200 / JSON-RPC -32008; notifications get empty HTTP 202.
- Structured events record stage, requested action, applied action and reason.
  Detector events expose booleans, never configured Honeytoken values. Monitor
  mode records detections without requiring redaction.

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
