# Post-merge issue follow-up

This is a historical evidence log. For current issue and registration-cleanup
status, see [Remaining security work](REMAINING-ISSUES-PLAN.md). The older
registrations described below were subsequently recovered and deleted. The original
reviewer also closed #6 and #13 on 2026-09-20; older keep-open instructions below
are historical, not current next steps.

PR #21 merged the reviewed remediation as `5a1ce61`. Issues #1, #2, #3, #4, #5,
#9, #11, #12 and #16 were subsequently closed with issue-specific links to the
merged implementation, tests and independent review. SSE issues #2/#11 were
closed against the owner's documented-exclusion acceptance option, not as
streaming implementations. Issues #6 and #13 remain open.

## #6: Monitoring verification needs a designated Connected Mode target

Sentinel emits a PDK violation for both monitor and block hits. Library tests
observe that property and its single-slot replacement semantics. The two real
Flex suites prove HTTP behavior, not exported Anypoint Monitoring metrics.

The current disposable registrations use Local Mode. MuleSoft documents
[Local Mode monitoring](https://docs.mulesoft.com/gateway/latest/local-monitor)
as independent of Anypoint Platform, whereas
[Connected Mode monitoring](https://docs.mulesoft.com/gateway/latest/conn-monitor)
provides platform metrics. Its
[API key metrics](https://docs.mulesoft.com/gateway/latest/conn-view-api-metrics)
include policy-violation counts aggregated per minute. The
[PDK violation documentation](https://docs.mulesoft.com/pdk/latest/policies-pdk-configure-features-violations)
also confirms reporting does not itself reject a request and only one violation
is active per request.

A read-only Sandbox API inventory succeeded, but no clearly designated disposable
decoy verification API was identified. No shared API was changed or probed.
The user was asked to identify a disposable Connected Mode Sandbox API/gateway.
Names, IDs and credentials from unrelated APIs are not included in this report.

Once a target is designated:

1. Establish the baseline violation counter and a quiet test window for that API.
2. Verify the exact reviewed Sentinel implementation is installed, with no later
   policy overwriting the violation property. Policy publication/installation is
   a separate external change if the implementation is not already available.
3. Send controlled clean, monitor-hit and block-hit requests to an inert backend.
   Record request times, request IDs, configured mode and upstream hit counts.
4. Observe exported policy-violation increments in distinct one-minute windows,
   allowing for ingestion delay. A JSON-RPC HTTP 200 denial must still count;
   clean traffic must not generate Sentinel violations.
5. Save only redacted/nonsecret query results identifying the policy/API and
   time window. Do not substitute a log line or alert header for export evidence.

Keep #6 open until this observation is made. No connected-mode deployment,
Exchange publication or shared-API mutation occurred in this follow-up.

## #13: actual gateway buffer and timeout controls now have runtime evidence

MuleSoft's [stop-iteration documentation](https://docs.mulesoft.com/pdk/latest/policies-pdk-configure-features-headers-stop)
identifies `FLEX_DOWNSTREAM_CONNECTION_BUFFER_LIMIT_BYTES` as the buffer limit.
[Local environment settings](https://docs.mulesoft.com/gateway/latest/local-env-variables)
and [timeout configuration](https://docs.mulesoft.com/gateway/latest/local-timeout)
document the corresponding gateway controls.

The new `gateway_resource_limits_bound_buffering_and_stalled_upstreams` test uses
Flex 1.14.0, a deliberately small 4096-byte buffer cap and a one-second upstream
response timeout. The policy's declared-length admission ceiling remains 64 KiB,
so an 8192-byte request is eligible for policy inspection and independently tests
the gateway's smaller cap. These are test settings, not imposed production defaults.

| Scenario | Observed result |
| --- | --- |
| Small clean exchange | 200; original expected response bytes |
| 8192-byte eligible request | 413; mock backend records zero requests |
| Oversized text response containing decoy | 500; no decoy in client response |
| Oversized finite SSE response containing decoy | 500; no decoy in client response |
| Backend delays its response for three seconds | Gateway 504 before the eight-second client deadline; no decoy returned |

The new test first failed without explicit gateway controls. With controls applied,
this runtime returns **413** on request overflow, rather than the generic 500 stated
in the documentation; the regression records the observed request/response statuses.
The focused configured run passed: **1 passed, 0 failed, 12.29 seconds**.
The final full Honeytoken runtime suite passed: **3 passed, 0 failed, 34.85 seconds**.

Reproduce from the repository root after supplying the already documented local
registration prerequisite:

```bash
python3 scripts/flex_runtime_gate.py --prepare
cd mcp-honeytoken-tripwire
cargo +1.89.0 test --test requests gateway_resource_limits --locked --offline -- --test-threads=1
```

These observations establish a gateway-enforced bound for the tested buffered
exchanges. They do not establish a total process-memory ceiling, adversarial
HTTP framing behavior, slow downstream uploads, or an indefinite active stream
that sends data often enough to avoid an idle timeout. A delayed whole response
is not a streaming test. Response-stage double-write failure and cross-policy
coordination also remain separate unresolved boundaries. Keep #13 open while
those scenarios are specified and exercised; do not describe this as complete
fail-closed streaming support.

## Review and next resource scenarios

A separate reviewer approved the test and its scoped claims, and independently
compiled the integration executable. No production policy logic changed. Strict
all-target Clippy, formatting, source/asset freshness and diff hygiene pass.

The next #13 experiment needs a controlled raw streaming backend: send chunks
frequently enough to avoid the idle timeout, exceed the configured response
deadline without ending the stream, and assert that no upstream prefix reaches
the client. Follow with unknown-length and inconsistent-framing cases, including
connection reuse. Do not infer those outcomes from the delayed-response test.

## Active-stream follow-up

`gateway_bounds_active_and_unknown_length_streams` adds a controlled raw chunked
backend, rebuilt from the checked-in Dockerfile and Python source before each
run. Cache its pinned base first:

```bash
docker pull python:3.12.12-slim-bookworm@sha256:593bd06efe90efa80dc4eee3948be7c0fde4134606dd40d8dd8dbcade98e669c
```

Then prepare current assets and run the Honeytoken suite as above. The test
uses the existing separately authorized disposable registration. Public CI
compiles this test but never runs it or receives registration credentials.

The active fixture emits its decoy immediately, then a chunk every 100 ms for
up to ten seconds. Its decoded body stays below the 4096-byte buffer limit.
The gateway must return 504 within five seconds (client deadline eight seconds),
with no decoy in the body. This tests the response deadline while data remains
active, rather than waiting for initial headers or relying on buffer overflow.
Other cases cover finite unknown-length SSE withholding (200 and the withholding
alert), oversized chunked output, malformed chunk framing, and clean exchanges
before and after these cases through the same client. The client may reconnect;
this does not prove that it reused a particular TCP connection.

This remains bounded runtime evidence, not proof about infinite streams or total
process memory. Conflicting Content-Length/Transfer-Encoding, slow downstream
uploads, guaranteed connection reuse and double-write termination remain open.

## Continuous checks and release migration

`.github/workflows/verify.yml` builds on pushes to main and pull requests. It runs
all library tests, formatting, strict Clippy, integration compilation, release
WASM generation and bundle/Makefile contract checks. The assets-only gate neither
requires nor reads registration files, and does not claim runtime verification.

See [Breadcrumb migration](BREADCRUMB-MIGRATION.md) before deploying the changed
schema. The next incompatible Breadcrumb release is reserved as 2.0.0; publishing
and changing package/asset versions remain a coordinated release task.

Final strengthened Honeytoken runtime result: **4 passed, 0 failed, 48.09 seconds**.
All 81 library tests and 11 Python gate/build-contract tests pass, as do strict
Clippy and release bundle validation. Composition implementation is tracked in
[#23](https://github.com/msaleme/agent-decoy-policies/issues/23); it is not supplied
by this CI/test/documentation change.

## Disposable registration cleanup

After the final runtime suite, the three policy-local `registration.yaml` files
were removed without reading or copying their contents. The ignored lifecycle
records retain only gateway names and cleanup status. Future runtime runs require
new, separately authorized disposable identities; asset-only CI remains usable.

Remote revocation is **not verified**. The documented Sandbox standalone gateway
inventory returned HTTP 200 with zero records, so no matching gateway ID was
available for a safe deletion. A second documented inventory route did not return
JSON. No unrelated gateway was deleted, and deleting local files is not evidence
of platform certificate revocation. Resolve the three names in the private local
lifecycle records with the platform administrator before claiming revocation.
