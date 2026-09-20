# Policy Composition Contract

The policy extensions in this repository are independent WebAssembly filters. They do not share
proxy-WASM state and MUST NOT use request or response headers as cross-policy control state.
A gateway deployment that chains them owns ordering, original-body access, resolution, and the
final forwarding decision.

## Required gateway behavior

1. **Detect against the original eligible body.** Every detector receives the same admitted,
   decoded request or response body before another policy mutates it.
2. **Classify actions.** Sentinel and request-side Honeytoken/Breadcrumb `block` decisions are
   required terminal actions. Breadcrumb `sanitize` is a required transformation only after all
   terminal decisions are resolved. Breadcrumb `seeding=enabled` is optional.
3. **Resolve request actions before forwarding.** A required block terminates the request. If no
   terminal decision applies, sanitize may run. Observe never changes bytes.
4. **Resolve response actions in security order.** Apply required Honeytoken withholding/redaction
   before optional Breadcrumb seeding. If two required edits overlap and the gateway cannot prove
   an ordered merge preserves both, terminate or withhold the response rather than forward an
   ambiguous body.
5. **Re-scan final output.** Before forwarding a transformed response, the gateway re-runs
   Honeytoken detection against the final bytes. A remaining decoy is a terminal composition
   failure, not a successful transformation.
6. **Record requested and applied actions separately.** Events must include `stage`, `requested`,
   `applied`, and `reason`; a configuration request is not evidence that its change reached the
   wire.

## Supported merge

The only predefined response merge is:

```text
Honeytoken required redaction/withholding -> Breadcrumb optional tools/list seeding -> final Honeytoken re-scan
```

The final scan is mandatory because JSON-valid output alone does not prove a protected value was
preserved or removed correctly.

## Platform boundary

The opt-in [Decoy Coordinator](decoy-coordinator/README.md) implements these
ordering and final-scan decisions inside one extension for bounded, unencoded,
single-envelope JSON-RPC traffic. Its native tests and Local Mode Flex suites
cover original-body decisions, sanitization, final seeding containment and forged
headers. Its admission rules and non-expanding optional seeding are stricter than
the standalone filters; see its configuration contract before migration.

The three original independent filters still do not share original-body state or
a final-chain callback. Arbitrary ordering of those filters is not equivalent to
the coordinator. The PDK response-stage double-write termination limitation also
remains: an outer component is still needed for unconditional containment when
body replacement and empty-body fallback are both rejected.

Streaming, compressed, non-UTF-8, and body classes outside an individual policy's documented
admission boundary remain unsupported for composed security transformations.
