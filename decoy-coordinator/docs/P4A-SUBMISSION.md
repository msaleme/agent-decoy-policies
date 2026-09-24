# P4A submission — Decoy Coordinator

Paste-ready catalog copy for the [Submit Policy](https://docs.p4a.ai/docs/guides/submitting-a-policy)
wizard. **The P4A catalog is frozen at submission time and does not auto-pull from
this repo** — after any change here, update the wizard tabs by hand and ask the
reviewer to refresh the listing.

## Basics

- **Name:** Decoy Coordinator
- **Category:** **Security** (not `Other`) — matches `definition/gcl.yaml`
  (`category: Security`) and the three standalone decoy policies.
- **Project type:** unified-model, subdirectory → `/tree/main/decoy-coordinator`
- **Classification:** MCP (single JSON-RPC envelope; batches rejected/skipped by mode)
- **Direction:** inbound (auto-derived, non-editable)

## Overview (Description tab)

An opt-in single Flex policy that coordinates the three decoy detectors —
Honeytoken, Decoy-Tool Sentinel and Breadcrumb — over one bounded JSON-RPC 2.0
exchange, so their block/sanitize/redact/seed actions are ordered deterministically
instead of racing as independent filters.

- **Scope:** bounded, unencoded, finite **single-envelope** JSON-RPC 2.0 only
  (unencoded JSON media, exact `Content-Length` ≤ 64 KiB). It is **not** a generic
  MCP Streamable HTTP policy: `text/event-stream` and other streamed, chunked,
  compressed, non-JSON or oversized bodies are uninspectable and are never buffered.
- **Detection before mutation:** all three detectors evaluate the original body
  first; a required block wins over any sanitize/seed edit.
- **Telemetry:** the policy emits **structured gateway log events** for a
  coordinated verdict (stage / requested / applied / reason) — not a single audit
  record. **Only Sentinel hits raise an Anypoint Monitoring policy violation**
  (`generate_policy_violation`); Honeytoken-only and Breadcrumb-only hits are logged
  but do not raise a violation, and at most one active violation survives a policy
  chain. Detector events expose booleans only, never configured lure values.
- **Enforcement shape:** requests are hard short-circuited (`Flow::Break`) for
  admitted traffic. Response containment (Honeytoken redaction / withholding) is
  conditional on the documented PDK host-write gap — see the repository
  `pdk-response-termination-gap.md`; a hard response guarantee needs an outer
  enforcement capability.
- **Mode-aware admission:** in enforcing modes uninspectable/unsupported traffic
  fails closed; in monitor/observe it passes through unmodified with an
  `inspection_skipped` event so unrelated valid traffic is never blocked.

## Configuration tab

```yaml
honeytokens: [example-decoy-value]     # planted values to watch for (≤64, ≤256B each)
decoyTools: [admin_override_do_not_use]# decoy tool names for the Sentinel
breadcrumb: internal_lure_do_not_follow# single lure string (≤256B)
honeytokenMode: monitor                # monitor | block
sentinelMode: monitor                  # monitor | block
breadcrumbMode: observe                # observe | sanitize | block
seeding: disabled                      # disabled | enabled (best-effort; see FAQ)
caseSensitive: false                   # ASCII case folding for Honeytokens only
```

Startup rejects out-of-bound configuration: ≤64 detectors per list, ≤256 bytes per
detector, ≤256-byte breadcrumb, ≤8 KiB aggregate detector bytes. Empty detector
lists / an empty breadcrumb disable that detector; blank entries and unknown modes
are rejected.

## Examples tab

**Example 1 — observe-first (recommended starting point).** Learn traffic without
mutating it, then tighten per detector.

```yaml
honeytokens: [SK-DECOY-4417]
decoyTools: [export_all_customers_debug]
breadcrumb: do-not-call-internal-admin
honeytokenMode: monitor
sentinelMode: monitor
breadcrumbMode: observe
seeding: disabled
caseSensitive: false
```

**Example 2 — enforcing, OOTB-compatible with trusted-descriptor controls.** Block
on hits; keep seeding disabled so MCP Schema Validation / Global Access / ABAC are
not tripped (plant the breadcrumb in the approved asset instead).

```yaml
honeytokens: [SK-DECOY-4417]
decoyTools: [export_all_customers_debug]
breadcrumb: do-not-call-internal-admin
honeytokenMode: block
sentinelMode: block
breadcrumbMode: block
seeding: disabled
caseSensitive: false
```

## FAQ tab

**Does it support SSE / streaming MCP responses?** No. Scope is bounded finite
single-envelope JSON-RPC. Uninspectable bodies are never buffered (no stall); pair
with MCP Support / Global Access / ABAC for SSE processing.

**Is `seeding: enabled` guaranteed to plant the breadcrumb?** No — seeding is
best-effort. Every edit is non-expanding, so on a compact `tools/list` response
there is no room and seeding is skipped with a `seed_skipped_no_capacity` event.
For a guaranteed breadcrumb, plant it in the backend or an asset-approved tool
description and leave `seeding: disabled`.

**Will breadcrumb sanitization change my message semantics?** No. It removes the
marker only from inert string values; object keys are preserved byte-for-byte and a
marker in a key or inside `tools/call` arguments fails closed instead of rewriting.

**Where should it sit in the policy chain?** After MCP Support, schema validation,
authentication, ABAC/Global Access and any integrity/signature verification (see
the interoperability matrix in the README). Prove the recommended chain in
Managed/Connected Mode; Local Mode cannot exercise the included MCP policies (the
chain, request matrix and assertions are in `docs/MANAGED-CHAIN-VERIFICATION.md`).

**Which detections raise a Monitoring violation?** Only Decoy-Tool Sentinel hits.
Honeytoken and Breadcrumb hits are logged (warning level) but do not raise a PDK
policy violation.
