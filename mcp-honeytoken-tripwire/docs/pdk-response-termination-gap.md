# PDK response-termination gap — minimal reproducible contract

## Claim

A response-body policy cannot prove fail-closed containment after it has consumed an upstream response body unless the runtime provides a supported operation that atomically replaces, terminates, resets, or locally replies to the downstream response.

## Minimal policy sequence

```rust
let state = response_state.into_headers_body_state().await;
let handler = state.handler();
let original = handler.body();

// The safe path when writes succeed.
handler.set_body(b"")?;
```

The PDK 1.10 `BodyHandler` interface exposes only:

```rust
fn body(&self) -> Vec<u8>;
fn set_body(&self, body: &[u8]) -> Result<(), BodyError>;
```

`set_body` can report `BodyNotSent` or `ExceededBodySize`. The response callback has no documented `Flow::Break`, downstream-reset, abort, or local-reply operation after the body state has been entered. Therefore a policy that receives an error from both its intended replacement and its empty-body fallback has no supported way to guarantee that the original upstream bytes will not continue.

## Repository evidence

- `src/lib.rs` uses a non-expanding replacement and, if that fails, attempts `set_body(b"")`.
- `response_redaction_falls_back_to_empty_body_when_pdk_rejects_rewrite` uses `FLEX_DOWNSTREAM_CONNECTION_BUFFER_LIMIT_BYTES=1` and proves the supported fallback path: replacement is rejected, empty-body replacement succeeds, and framing headers are removed.
- This test intentionally does **not** claim to prove the unsupported double-failure path. An empty-body replacement can itself return `BodyNotSent`; no supported PDK recovery action remains at that point.

## Deployment requirement

For a hard response-containment guarantee, deploy this policy behind or inside an enforcement component that can terminate/reset the downstream exchange after inspection. Until Flex/PDK exposes such an operation in the response body state, this policy's response guarantee is conditional:

> If Flex accepts the empty-body replacement, no configured Honeytoken is forwarded by this policy's admitted response paths. If Flex rejects it, the policy emits an error but cannot independently guarantee termination.

## Requested platform capability

A supported response-body-stage API with semantics equivalent to one of:

- `terminate_downstream_response()`;
- `reset_downstream_stream()`;
- `replace_response_atomically(status, headers, body)`; or
- a `Flow::Break`/local-response operation valid after response body consumption.

The operation must have documented behavior when body mutation is rejected and must be testable in Flex integration.
