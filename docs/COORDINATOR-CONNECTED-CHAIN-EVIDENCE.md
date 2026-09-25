# Coordinator Connected Mode chain — live results, with failed expectations

On **2026-09-25 UTC**, all seven prescribed cases were exercised on a disposable
Flex Gateway **1.14.0** using the user-approved **API deployment operation** in
place of UI Save & Apply. **This is not an all-seven passing result.** Sentinel
monitor/block behavior and bounded response redaction passed; discovery,
seeding, content-type rejection and Tool Mapping exposed qualifications or
failed expectations. The #42 live-verification gap therefore remains open.

The [machine-readable live record](evidence/coordinator-connected-chain-2026-09-25.json)
contains requests, responses, backend counts, exact configurations, runtime
snapshots, deployment timestamps, detector events, Monitoring rows and cleanup.
The [2026-09-24 record](evidence/coordinator-connected-chain-2026-09-24.json)
preserves the earlier attempt that stopped before traffic because Chrome's
administrator policy prevented the required UI operation. Its resources were
removed before this fresh run.

## Artifact identity and isolation

- Source: `b117fec54a6d534a43011f2d742c6527f15979b7`, the unchanged source used by
  the fresh verification branch. Runtime behavior, enums and policy schemas
  were not modified.
- Immutable citation tag `v0.1.0-rc.1` remains at
  `f442cba95082b2fcb60c26c0613e327d420635a2`.
- Rust **1.89.0**, PDK **1.10.0**; locked offline library tests: **34 passed**.
  The `wasm32-wasip1` release build succeeded.
- Built and runtime-loaded Coordinator WASM SHA-256:
  `59c813f6083b968bab41872b560a5e387dd2f11eeaad4bad4e65974e6d9895de`.
- API **21196660**, deployment **28449353**, fresh gateway registration
  `9b6aead3-1558-4d11-bbad-391500cdacff`, disposable client **188950488** and
  approved contract **9420676**. Only Sandbox test resources were changed.
- Dedicated Docker network and inert Python JSON-RPC backend. The gateway
  listener was **127.0.0.1:18084**, forwarding `/chain/` to the backend's `/`.
  The backend had no published port and a **128 MiB** memory/swap cap.
- The gateway started with a **1 GiB** cap. It was OOM-killed at
  `00:38:50.448Z`, before the first honeytoken request. Its cap was raised to
  **2 GiB**, with equal memory and memory-plus-swap limits, and it was restarted.
  The transport failure and one subsequent authentication-cache warm-up 401
  remain in the evidence; neither was counted as a redaction result.
- Publication used disposable development policy IDs/version
  `0.0.1-20260925002656`. API Manager selected the custom implementation with
  `minRuntimeVersion: 1.6.1`; the actual tested runtime was 1.14.0. No production
  Exchange version or final release was published.

## Chain and API push verification

| Request order | Policy | Definition | Flex implementation | Policy ID |
| --- | --- | --- | --- | --- |
| 1 | MCP Support | 1.1.1 | 1.1.1 | 9336493 |
| 2 | MCP Schema Validation | 1.3.0 | 1.3.0 | 9336494 |
| 3 | Client ID Enforcement | 1.3.3 | 1.2.0 | 9336495 |
| 4 | MCP Global Access | 1.0.1 | 1.0.2 | 9336496 |
| 5 | MCP ABAC | 1.0.2 | 1.0.6 | 9336497 |
| 6 | Decoy Coordinator | 0.0.1-20260925002656 | same | 9336498 |

Response order is reversed. Global Access allowed the four inert fixture tools;
ABAC used `ClientId` with `permit(principal,action,resource);`, behind client ID
enforcement. Coordinator started with monitor/observe modes, `seeding: disabled`,
`inert_decoy`, synthetic honeytoken `synthetic_honeytoken_42` and asset-planted
breadcrumb `coordinator_lure_42`.

For case 7 only, MCP Tool Mapping definition **1.0.1**, implementation **1.0.6**,
policy **9336600**, was placed immediately after MCP Support. Schema Validation,
authentication and access policies retained their relative order, with Coordinator
last. The mapping was `inert_decoy` → `mapped_inert_decoy` (`literal`).

Configuration changes used the API Manager policy endpoint, followed by
`PATCH /proxies/xapi/v1/organizations/{org}/environments/{env}/apis/{api}/deployments/{deployment}`.
The pre-traffic push advanced `deployment.updatedDate` to
`2026-09-25T00:36:19.592Z`. Each later configuration push has its own timestamp
and exact runtime configuration check in JSON. The Tool Mapping push required
additional propagation time; traffic waited until the runtime matched.

The portal-documented deployment `/status` endpoint returned **`applied`**;
API autodiscovery status remained **`unregistered`**. Runtime `ApiInstanceReady`,
`ServiceReady`, `PoliciesReady` and `Ready` conditions were true. **An Active →
Updating → Active cycle was not observed and is not claimed.** Timestamp advancement,
applied deployment status and matching live configuration were the evidence for
the approved API substitution.

The supplied developer portal's
[Secure MCP Server skill](https://dev-portal.mulesoft.com/skills/secure-mcp-server/SKILL.md),
[Apply Policy skill](https://dev-portal.mulesoft.com/skills/apply-policy-to-api-instance/SKILL.md)
and [Proxies API specification](https://dev-portal.mulesoft.com/apis/proxies-xapi/api.yaml)
were used to verify the workflow.

## Seven-case results

| Case | Observed result | Assessment |
| --- | --- | --- |
| 1: clean discovery | HTTP 200; four Exchange-cached tools; backend 0; no violation | Qualified: discovery/schema clean, but not an unchanged backend response. Coordinator's downstream response path was not exercised. |
| 2: monitor decoy | 3 × HTTP 200 success; backend 3; 3 Coordinator violations; logs show only Sentinel | Pass |
| 3: block decoy | 3 × HTTP 200 / JSON-RPC `-32008`; backend 0; 3 Coordinator violations | Pass |
| 4: honeytoken response | Successful retry: HTTP 200, token replaced by empty text, valid JSON-RPC; backend 1; no violation | Pass after retained infrastructure retries |
| 5: seeding + `RemoveTool` | HTTP 200; all four cached tools remained; backend 0 | Failed expectation: `validateToolSchema: true` bypassed backend inspection and Coordinator seeding. |
| 6: enforcing event-stream request | HTTP 200 / JSON-RPC `-32600`; backend 0 | Failed expected status/attribution: an earlier included policy rejected it instead of Coordinator returning 415. |
| 7: mapped decoy | HTTP 415; backend 0; Coordinator logged `uninspectable-body` | Failed: no Sentinel `-32008`; same result with Coordinator configured for the original name. |

The strict matrix therefore has **three passes, one qualified result and three
failed expectations**. Supplemental controls do not replace those original results.

### Controls and interpretation

**Mapping:** With Mapping still installed and Coordinator configured for
`inert_decoy`, an incoming call already named `inert_decoy` returned HTTP 200 /
`-32008` with zero backend calls. Both calls requiring inbound transformation
returned 415. This establishes a request-inspection incompatibility after Tool
Mapping. The exact header/framing change was not instrumented, so a missing
content length is a hypothesis, not a measured root cause. The prescribed
mapped-name recommendation is not validated by this run. See [issue #48](https://github.com/msaleme/agent-decoy-policies/issues/48).
The vendor's [Tool Mapping documentation](https://docs.mulesoft.com/gateway/latest/policies-included-mcp-tool-mapping)
confirms that incoming mapped names are reverse-transformed before the backend.

**Breadcrumb attribution:** A `legitimate_tool` call carried the breadcrumb in
`params._meta.test`, forwarded with HTTP 200 and one backend call, and logged
`breadcrumb: true`, `sentinel: false`, `honeytoken: false`. Its minute contains one processed request and zero policy violations.

**Discovery and drift:** The included policy serves `tools/list` from the asset
when `validateToolSchema` is true; its warning explicitly says poisoning detection
is inactive in that mode. That agrees with the
[Schema Validation documentation](https://docs.mulesoft.com/gateway/latest/policies-included-mcp-schema-validation).
For separate drift controls, `validateToolSchema` was set to false. An attempted
normalization matching cached discovery (omitting `additionalProperties`) produced
input-schema drift for all four tools, both with and without seeding. Those
confounded attempts remain in the record. The original backend schemas were then
restored and pretty JSON supplied whitespace capacity for the Coordinator's
optional non-growing seed operation. A read-back of the published asset confirmed
that its tool descriptors exactly matched the original backend fixture.

Even that unseeded baseline returned `tools: []`, with `inputSchema` drift for all
four tools. With seeding enabled, the findings additionally named `description`
for the three tools without the asset-planted breadcrumb. The Coordinator logged
a response transformation. This supports a seeding/descriptor conflict, but
removal already occurred in the baseline; removal alone cannot establish the
cause. The unchanged-tool problem is tracked in
[issue #50](https://github.com/msaleme/agent-decoy-policies/issues/50). See [issue #49](https://github.com/msaleme/agent-decoy-policies/issues/49) for the unresolved runbook expectations.

**Setup correction:** The first disposable MCP asset version was uploaded as a
ZIP and did not produce a runtime Exchange binding. Before any traffic, version
**0.0.2** was published as raw `mcp-metadata.json`, with boolean capability flags,
then the API asset version was updated and redeployed. Runtime binding appeared
and discovery succeeded. This was a fixture error, not a confirmed platform defect.
The [Exchange API publication reference](https://anypoint.mulesoft.com/exchange/portals/anypoint-platform/f1e97bc6-315a-4490-82a7-23abe036327a.anypoint-platform/exchange-experience-api/minor/2.4/pages/Asset%20Creation/)
specifies that artifact format.

## Monitoring evidence

Queries used `mulesoft.api.summary` through
`POST /observability/api/v1/metrics:search?offset=0&limit=100`, scoped to the
single disposable API and recorded epoch-millisecond windows. The query shape
and interpretation match [the Sentinel evidence](CONNECTED-MONITORING-EVIDENCE.md#query-and-interpretation).
The final query returned HTTP 200, **15 rows totaling 19 requests**, and no next
page. That matches all 19 HTTP responses; the one connection failure never reached
the gateway. Backend logs contain **9 calls**. Coordinator has **7 violations**:
three monitor decoys, three block decoys and the unmapped control. Schema Validation
has four drift-control violations, and Client ID Enforcement has the one warm-up
401. The honeytoken-only and breadcrumb-only success windows each contain exactly
one processed request and zero violations. The event-stream JSON-RPC error and
the two mapping 415 responses are also exported as `PROCESSED` without violations,
further demonstrating that disposition is not a wire-level enforcement oracle.

Monitor and block decoy rows both have `request.disposition: BLOCKED` and
Coordinator policy ID **9336498**, although monitor requests reached the backend.
Detector logs identify Sentinel within the composed policy; Monitoring itself
identifies the Coordinator policy instance. The warm-up 401 is attributed to
Client ID Enforcement and is kept separate from detector results. No empty or
missing export is treated as a measured detector zero without checking request totals.

## Reproduction and cleanup

Use fresh disposable resource identities and the exact source/WASM identity above.
Publish the MCP fixture as raw JSON using `fixture.toolsInitial` from the live
record; use the recorded backend implementation, initially using compact response serialization and that tool list until
the explicitly recorded fixture changes. Approve a disposable client
contract and apply `initialPolicyConfiguration` in order. Send the recorded
`requests[*].request` JSON to `POST /chain/`, compactly serialized with exact
content length, `Accept: application/json, text/event-stream`, protocol version
`2025-06-18` and the private disposable client headers. The single event-stream
case changes only Content-Type. Each request records the Coordinator/schema
configuration and policy order; push changes through the deployment operation
and verify the actual runtime configuration before sending it. Separate test
classes into UTC minute windows for Monitoring attribution.

Cleanup completed after evidence capture: the contract was revoked and deleted;
the API, deployment and client were deleted; all returned 404 on scoped GETs.
The custom definition, implementation and both MCP asset versions were hard-deleted
and returned 404. `flexctl registration delete --file` succeeded; gateway inventory
reported `DELETED` with **zero connected replicas** (two disconnected replica
history entries remained). Both containers and the dedicated network were removed
and verified absent. Local registration material was removed after remote
verification. Private staging, client credentials and raw diagnostic dumps were
removed after the sanitized evidence was written.

No credentials, signed asset URLs or raw configuration dumps are included in the
artifacts. Host-failure and response-termination containment remain unverified;
the OOM event is infrastructure evidence, not a containment test. Headers were
never treated as trusted provenance. Local library tests remain the automated
authority. This live run documents actual interoperability limits rather than
claiming the #42 all-pass condition has been met.
