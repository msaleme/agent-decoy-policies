# Independent remediation review

Latest issue state and remaining verification: [post-merge follow-up](POST-MERGE-FOLLOW-UP.md).

Review date: 2026-09-19. Worktree: `/tmp/agent-decoy-policies-honeytoken-streaming`.
Base/HEAD: `03a5bf8b477e9bd7cf12f808013f17608349ae01`.

**Current recommendation: the four findings below are resolved and independently re-reviewed.**
The scoped buffered-policy remediation is ready for merge consideration, with #6 Monitoring
export and #13 actual buffering/stream limits remaining open. This is not production certification.
Review and verification finished before Git publication. The user subsequently authorized
commit, push and merge subject to repository checks; issue closure and deployment are not
part of this change.

## Fix verification and second review

- Honeytoken: bounded parse failures on explicit JSON and missing-content-type object/array
  bodies reject requests with 415 and withhold responses in block mode. Depth, overflow,
  malformed JSON, escaped-token and clean controls are covered; monitor/plain-text behavior
  is documented. TDD reproduced both exploit directions and the legacy-header variant.
  **42/42 library tests pass**; Flex **2/2 pass, 22.92s**. Missing-content-type cases have
  library coverage; the new real-Flex parser-limit cases use explicit JSON media types.
- Sentinel: valid client result/error envelopes pass unchanged; malformed field types and
  mixed request/response envelopes reject; blocked batch replies include only request IDs.
  Four new matrix tests failed before the fix and now pass. **25/25 library tests pass**;
  Flex **2/2 pass, 22.65s**, including client responses and mixed-envelope batches.
- Build: all three Makefiles unexport legacy compatibility and derive the extension reference
  from the definition name. Both previously failing policies now pass the offline actual
  Makefile/generator name check. The check also passes with inherited compatibility 1.4.0.
  Sentinel/Breadcrumb playground images now match the verified Flex 1.14.0 target.
- A separate reviewer who authored neither policy fix nor the build fix re-reviewed all three
  changes and approved their scoped behavior without new blockers. That reviewer reran both
  affected library suites and inspected runtime tests; the coordinating agent ran Flex.
- Formatting, strict all-target Clippy and release WASM passed for affected policies. Asset
  gate: all three bundles PASS, 8 helper tests PASS; build-contract test: one test covering
  all three projects PASS. Breadcrumb's unchanged policy retains its earlier 14/14 library
  and 3/3 Flex evidence. Diff hygiene and scoped credential checks pass.

## Original findings and reproductions (resolved)

The original recommendation below was to withhold merge until these defects were fixed.
Retained reproduction details explain why the earlier green suites were insufficient.

Three separate AI reviewer agents, given no prior conversation, reviewed Honeytoken, Sentinel,
and Breadcrumb independently. The coordinating agent reviewed build/test integration and
checked the protocol references. This is an independent AI review, not a human approval.
Production source was not modified during the original review; fixes were implemented afterward. No credentials, Docker runtime, publication,
GitHub writes, commits, or pushes were involved.

## P1 — Escaped honeytokens bypass block mode when JSON parsing reaches limits

Locations: `mcp-honeytoken-tripwire/src/lib.rs:501` and `:607`.

Decoded string detection runs only if `serde_json::from_str::<Value>` succeeds. When a body
contains an escaped token plus a value that exceeds the parser's depth or numeric range,
raw matching misses the escaped token, parsing fails, and both request and response paths
return without enforcing block mode.

Reproducer: valid UTF-8 `application/json`, accurate Content-Length, under 64 KiB. Construct:

```python
body = ('{"token":"\\u0061cct_DECOY_9x1f-do-not-use","padding":'
        + '[' * 128 + '0' + ']' * 128 + '}')
```

This is a 311-byte JSON body whose decoded token is the configured fixture token.
Two added regressions in an isolated source copy failed against the actual PDK policy:
the request reached the backend with HTTP 200, and the response reached the client unchanged.
The isolated regressions are `review_regression::escaped_token_in_deep_json_must_be_blocked`
and `review_regression::escaped_token_in_deep_json_response_must_be_withheld`. The reviewer ran
`cargo test --offline --lib review_regression --target-dir /tmp/agent-decoy-policies-honeytoken-streaming/mcp-honeytoken-tripwire/target`
in `/tmp/honeytoken-review-regression-441r55la`; the regression source is preserved there as
`review-regression-lib.rs`. The shared test artifact was restored to the original source.
The normal 37 tests still pass. A standalone parser probe also confirms the same parse gate
fails with `"padding":1e400` (number out of range).

This is an incomplete escaped-token remediation rather than a regression from the original
raw-only detector. It nevertheless invalidates the current decoded-detection containment claim.
Fix by making admitted JSON inspection fail closed on unsupported parsing, or by using an
appropriately bounded syntax/string scanner independent of `Value` representation limits.
Do not simply raise or disable recursion limits. Cover request and response, depth and numeric
range, escaped matches and clean controls; rerun the affected full suite and Flex tests.

## P1 — Sentinel rejects valid MCP client response messages

Location: `decoy-tool-sentinel/src/lib.rs:230`; request-only classifier at `:133`.

A client POST body such as `{"jsonrpc":"2.0","id":1,"result":{"ok":true}}` is a valid
JSON-RPC response to a server-initiated request. It has no `method`, so `called_tools` returns
None and the new block-mode branch returns HTTP 400. Previously it continued upstream.
This prevents server-initiated MCP operations from receiving client replies.

The [MCP Streamable HTTP specification](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports)
allows client POST bodies containing requests, notifications, or responses. The response is
still a buffered JSON body; excluding SSE does not justify rejecting this envelope.

The reviewer reproduced the classification with an isolated probe using the exact current
parser. Existing 21 tests pass because none covers a client response. Add separate validated
request/notification/response classification. Forward valid client result/error envelopes;
retain generic rejection for ambiguous or malformed input and atomic decoy batch blocking.
Add filter-level regressions and a real upstream oracle for both response envelope forms.

## P2 — Standard Makefile builds do not match two integration fixture references

Locations: `decoy-tool-sentinel/tests/common/mod.rs:14` and
`breadcrumb-misdirection/tests/common/mod.rs:14`; both Makefiles still export
`PDK_COMPATIBILITY_VERSION = 1.4.0` at line 1.

Fixtures changed to names ending in `-flex-v1-0-impl`, while the unchanged compatibility-mode
Makefiles generate names ending in `-flex-v1-0`. Reproduced offline for Sentinel:

```bash
PDK_COMPATIBILITY_VERSION=1.4.0 cargo anypoint get-policy-implementation-name
# decoy-tool-sentinel-flex-v1-0
```

A separate `gcl-gen` invocation with the same compatibility setting and current release WASM
confirmed that exact generated metadata name. The fixture instead references
`decoy-tool-sentinel-flex-v1-0-impl`. Breadcrumb has the identical mismatch.
Thus the advertised `make test` path rebuilds assets with names the fixtures cannot resolve.
The passing local asset helper synthesizes matching names and does not test this normal path.
Align generator settings and fixture naming across both build routes, and add a check that
compares the standard generated extension name with the fixture. The Sentinel/Breadcrumb
playgrounds also still use Flex 1.10.0, whereas the reported runtime evidence is for 1.14.0;
align or explicitly validate that separate runtime target before calling them verified.

## P2 — Sentinel's strengthened malformed-input contract is incomplete

Location: `decoy-tool-sentinel/src/lib.rs:133` through response-ID collection at `:142`.

The classifier checks only `jsonrpc` and `method`. `id:true` and `id:{}` are accepted and
copied into decoy denial envelopes. `params:7` is also accepted. These violate the envelope
types in the [JSON-RPC specification](https://www.jsonrpc.org/specification).
The isolated exact-parser probe reproduced each case. This defect predates the diff, but
contradicts the new generic-400 malformed-input guarantee. Address it with the envelope
classification fix. No downstream coercion or tool-execution bypass was established.

## No new blocking Breadcrumb finding

The separate Breadcrumb reviewer found no actionable new defect in supported-body sanitation,
duplicate-key handling, response correlation, required-write failure or optional-write framing.
All 14 existing tests pass. Additional direct coverage for sanitation-created duplicate keys,
residual markers and notification/batch seeding exclusion would improve regression protection.

## Validation and remaining boundaries

Independent offline suite results: Honeytoken 37/37, Sentinel 21/21, Breadcrumb 14/14.
Asset-helper tests: 8/8. `git diff --check` passed. The two new isolated Honeytoken regressions
fail; this explains why the existing green suites cannot establish merge readiness.
Earlier Flex passes remain evidence for their tested scenarios; no Docker tests were rerun
as part of this review. Known Monitoring export (#6), actual-byte buffer/stream limits (#13),
response-write termination, and composition limitations remain unresolved separately.

The fixes, permanent regression tests, relevant local/runtime checks and second review are now
complete, as recorded at the top of this report. Publication and
issue closure remain separate actions; this report does not authorize them.
