# Codex handoff — current remediation state

Latest issue state and remaining verification: [post-merge follow-up](POST-MERGE-FOLLOW-UP.md).

Work only in `/tmp/agent-decoy-policies-honeytoken-streaming`, branch
`fix/honeytoken-streaming-contract`. Implementation base:
`03a5bf8b477e9bd7cf12f808013f17608349ae01`. See Git history for the published revision.

## Handling constraints

The user subsequently authorized committing, pushing, and merging this remediation when
repository checks permit. This supersedes the original no-commit/no-push/no-PR handoff.
Keep #6 and #13 open. Deployment and Exchange publication remain outside scope.
The user also authorized bounded Sandbox registration and Flex verification. Each policy now has a separate ignored local identity;
never display identity contents or copy them between projects. Nonsecret lifecycle records
are in each policy's ignored `target/disposable-registration-record.json`. Revoke and remove
these disposable fixtures when follow-up runtime verification is finished.
Never trust headers as local provenance or cross-policy control state.

## Read first

- [Current issue/evidence checklist](REMEDIATION-EVIDENCE.md)
- [Composition boundary](../COMPOSITION.md)
- [Flex runtime boundary](flex-runtime-verification-boundary.md)
- [PDK response-termination gap](../mcp-honeytoken-tripwire/docs/pdk-response-termination-gap.md)

## Implemented

Sentinel duplicate-member fail-closed admission, Breadcrumb write/framing failure behavior,
mode/status documentation, registration guidance, Honeytoken residual-token rescanning and
schema-default loading, strict transport/UTF-8 admission, and correlated optional Breadcrumb
seeding are implemented. Sentinel now emits a PDK violation for monitor and block decoy hits;
local tests cover its single-slot precedence. Playground configurations are populated.

Library results: **Honeytoken 42/42, Sentinel 25/25, Breadcrumb 14/14**.
Formatting, strict all-target Clippy, release WASM and all asset gates pass. The asset gate has
8 passing regression tests. Real Flex 1.14.0 fixtures now cover all three policies; see the
current evidence checklist for exact latest runtime counts and limitations.

## Remaining work

The four [independent-review findings](INDEPENDENT-REVIEW.md) are fixed and independently
re-reviewed: Honeytoken parser-limit containment, valid MCP client response admission,
Sentinel envelope validation, and Makefile/fixture name alignment. A separate reviewer
approved these fixes. New Honeytoken/Sentinel Flex runs each pass 2/2; unchanged Breadcrumb
retains 3/3. The build-contract regression passes for all three projects.

The live issue checklist supports scoped merge consideration, not production certification.
Keep #6 open until
Anypoint Monitoring/export is independently observed and #13 open until actual buffering and
indefinite-response limits are enforced at the gateway. Nothing has been closed on GitHub.

PDK response-stage double-write failure, pre-buffer actual-byte limits, live SSE transformation,
and multi-policy coordination remain platform/implementation boundaries. Finite SSE exclusion
fixtures do not prove live-stream containment. No production-readiness claim is justified.

For further source defects, add and observe a focused failing regression, make the smallest fix,
then run the affected full library suite, strict Clippy, WASM build and hygiene checks. Regenerate
local assets after source/schema/fixture changes using `python3 scripts/flex_runtime_gate.py --prepare`.
Do not relax block behavior or substitute header control state to bypass a platform limitation.
