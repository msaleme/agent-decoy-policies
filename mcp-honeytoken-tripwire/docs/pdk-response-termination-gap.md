# PDK response-write and termination contract boundary

This is a documented platform-contract limitation, **not a reproduced Flex
response disclosure**. The original reviewer closed #13 after accepting its
headers-admission/buffering remediation. That acceptance does not supply new
low-level host-failure evidence. See the [current issue status](../../docs/REMAINING-ISSUES-PLAN.md).

## What the pinned implementation establishes

The source audit checked the `pdk-classy` 1.10.0 archive against Cargo.lock's
SHA-256 and matched `src/hl/body.rs`, `src/hl/headers_body.rs`, and `src/host.rs`
to that archive. [Recorded audit](https://github.com/msaleme/agent-decoy-policies/issues/13#issuecomment-5747199535).

- In `HeadersBodyExchange::set_body`, `BodyNotSent` means the handler's internal
  body state is absent. With a present body state and a positive buffer limit,
  an empty replacement passes the SDK size check.
- The handler validates size, calls `B::write_body`, and returns `Ok(())`.
  The default host's response setter wraps `hostcalls::set_buffer` with
  `unwrap_or_default`: a low-level error is logged and converted to a unit return,
  rather than propagated as a `BodyError`.
- Consequently, `set_body`'s typed result alone is not an acknowledgement that the
  host applied the replacement. No supported response-body-stage abort/reset or
  local-reply operation has been established for this integration.

It would be inaccurate to describe the ordinary empty-body fallback as known to
fail, or a synthetic handler double-error as a reproduced Flex leak. It would also
be inaccurate to infer an unconditional host-failure containment guarantee from
successful local replacements.

## Evidence and limits

The policy uses a non-expanding replacement and attempts an empty-body fallback
when the SDK returns an error. The **library regression**
`response_redaction_falls_back_to_empty_body_when_pdk_rejects_rewrite` uses a mock
host property for a one-byte buffer limit. It verifies rejection of the intended
replacement, successful empty fallback, and removal of stale framing headers.
It is not a real Flex double-write fault-injection test.

Separate Local Mode wire suites verify successful response redaction/withholding,
framing, transport exclusions, gateway limits and deadlines. They do not inject
a low-level host write failure. The outer HAProxy gate bounds request uploads;
it does not inspect responses or provide a response containment acknowledgement.

Uninspectable responses in block mode still enter the buffered response state so
they can be withheld. Headers admission reduces unnecessary request/monitor-mode
inspection; it does not remove all response buffering.

## Requirement for an unconditional failure guarantee

A hard guarantee under host write failure requires a supported, testable operation
that atomically replaces or terminates the downstream response after inspection,
or an independently validated response enforcement component. Suitable platform
semantics could include downstream reset, atomic replacement, or a body-stage
local response with specified failure behavior.

The platform contract must cover rejected host writes, not merely SDK size
validation. Until that contract and failure-path evidence exist, the verified
successful-write behavior must remain distinct from an unconditional containment
claim. No production workaround based on trusted headers or best-effort pass-through
is supplied or implied.
