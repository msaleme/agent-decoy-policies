# Sentinel Connected Mode Monitoring evidence

On **2026-09-20**, an explicitly authorized disposable Sandbox run verified
Sentinel's exported policy-violation counts on **Flex Gateway 1.14.0**. Both
monitor and block modes reported three violations for three decoy requests;
five clean requests per mode reported none. This closes the previously documented
export-evidence gap. It does not change the original reviewer's prior acceptance
of issue #6 or establish production readiness.

## Setup and artifact identity

- Reviewed source: `f442cba95082b2fcb60c26c0613e327d420635a2`, source tag
  `v0.1.0-rc.1`; PDK 1.10.0, Rust 1.89.0, release `wasm32-wasip1` build.
- All three Sentinel Rust source files were byte-identical to that checkout.
  An isolated copy used unique test Exchange asset IDs, the authorized org's
  group ID, a disposable package version and minimum runtime 1.14.0 metadata.
  No policy logic or schema was changed.
- Tested WASM SHA-256:
  `348ba2020ea9629f867f3d77169a9c67e83f8cc9d2f63e202e099a3208f5e433`.
  This identifies the disposable build, not a published repository release binary.
- One connected gateway, two new API instances, one inert Python backend and a
  dedicated Docker network. The listener was bound to host loopback. Flex had a
  1 GiB memory cap; the backend had 128 MiB, with swap disabled for both.
- Each API had exactly one user-applied policy: the test Sentinel implementation,
  configured with `decoyTools: [inert_decoy_for_metrics]` and its respective mode.
  API Manager policy inventories confirmed implementation version and policy IDs.
  Flex's automatic API context remained present. No competing custom policy was
  installed, so this does not test later-policy violation replacement.
- Existing CLI authentication was sufficient. The registration identity stayed
  outside the repository. No shared API or production deployment was modified.

## Controlled traffic and exported results

All times are UTC. Both APIs received `POST /<mode>/rpc` with JSON-RPC `tools/call`,
object `arguments: {}`, and IDs 100–104 for clean calls or 200–202 for decoys.
The clean tool name was `legitimate_tool`; the decoy name was the configured
`inert_decoy_for_metrics`. The backend only counted requests and returned an inert
JSON-RPC result.

| Window | Mode | Calls | Wire result | Backend calls | Exported violations |
| --- | --- | ---: | --- | ---: | ---: |
| 14:13:48–14:23:59.999 | Both, separately | 0 | No traffic | 0 | 0 |
| 14:24:19 | Monitor | 5 clean | HTTP 200, inert result | 5 | 0 |
| 14:24:19 | Block | 5 clean | HTTP 200, inert result | 5 | 0 |
| 14:27:48 | Monitor | 3 decoy | HTTP 200, inert result | 3 | 3 |
| 14:27:48 | Block | 3 decoy | HTTP 200, JSON-RPC error `-32008` | 0 | 3 |

The final backend counters were **10 clean, 3 decoy**. An earlier route preflight
at 14:24:03 used bare `/monitor`, received 404 and did not reach the backend. It
was not attributed to either API in the exported rows. The successful traffic
used `/monitor/rpc` and `/block/rpc`; no retries of successful calls were needed.

At 14:28:51–52 the API summary dataset returned the expected counts. Queries at
14:29 and the final window-specific assertions reproduced them. The before-traffic
window was checked retrospectively in this dataset; initial live queries against
`mulesoft.api` (the path dataset alias) had returned no rows even after clean
traffic. Those empty path results are **not** the successful baseline evidence.

The [machine-readable evidence](evidence/sentinel-connected-monitoring-2026-09-20.json)
retains the actual API/policy IDs, minute timestamps, row counts, HTTP statuses and
violation/disposition fields, together with artifact identity and cleanup status.
Org/environment IDs, identity material and raw authenticated logs are omitted.
All six before/clean/decoy checks passed: exact request totals, exact
Sentinel-attributed violation totals, HTTP 200 and no paginated results left unread.

## Query and interpretation

Use the authorized Metrics API endpoint
`POST /observability/api/v1/metrics:search?offset=0&limit=100` with a JSON `query`
field containing this query, replacing placeholders with the designated target
and epoch-millisecond window:

```sql
SELECT timestamp, COUNT(requests), "api.instance.id",
       "policy.violation.status", "policy.id", "http.status_code",
       "request.disposition"
FROM "mulesoft.api.summary"
WHERE "sub_org.id" = '<org-id>' AND "env.id" = '<environment-id>'
  AND "api.instance.id" = '<disposable-api-id>'
  AND timestamp BETWEEN <start-ms> AND <end-ms>
GROUP BY "api.instance.id", "policy.violation.status", "policy.id",
         "http.status_code", "request.disposition"
TIMESERIES
```

Clean rows had `request.disposition=PROCESSED` and no violation/policy fields.
Decoy rows in **both modes** had `policy.violation.status=Violation`, the correct
Sentinel policy ID and `request.disposition=BLOCKED`, despite monitor mode forwarding
all three calls. Therefore the exported disposition is not an upstream-blocking
oracle. Combine violation counts with client and backend observations when checking
enforcement. HTTP 200 JSON-RPC denials still contributed to the violation count.

The [Metrics API reference](https://dev-portal.mulesoft.com/apis/metrics.html)
describes the query interface. MuleSoft's
[Connected Mode key metrics documentation](https://docs.mulesoft.com/gateway/latest/conn-view-api-metrics)
documents per-minute aggregation. The
[PDK violation contract](https://docs.mulesoft.com/pdk/latest/policies-pdk-configure-features-violations)
explains that reporting a violation does not itself reject traffic and that only
one violation is active per request. Do not extrapolate this isolated test to
arbitrary policy chains, other runtime versions or notification/batch export counts.

## Verification and cleanup

The disposable source copy passed **25/25 Sentinel library tests** and its release
WASM build. Runtime traffic assertions and the six Metrics API window assertions
passed. These are actual Connected Mode observations, separate from library tests
and earlier Local Mode wire tests. The PDK response-write containment limitation
is unaffected.

Cleanup completed after evidence capture:

- Both API instances were deleted; subsequent scoped GETs returned 404.
- The test policy implementation, definition and HTTP API Exchange asset versions
  were hard-deleted; each subsequent scoped GET returned 404.
- `flexctl registration delete --file` succeeded. The gateway inventory retained
  a `DELETED` tombstone with zero connected replicas. The local registration file
  and its directory were then removed.
- Both Docker containers and the dedicated network were removed; absence was checked.

The existing source tag was not moved. No production policy version was published.
Repeating this procedure requires fresh, explicitly scoped disposable resources;
do not reuse the deleted IDs or recreate identity material from an evidence file.
