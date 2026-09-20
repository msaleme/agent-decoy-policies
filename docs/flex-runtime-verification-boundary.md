# Flex runtime verification boundary

## Finding

The repository must not store a Flex Gateway `registration.yaml` in source control. That file contains a client certificate and private key used as a local Flex registration identity. It is not a safe shared test fixture, even when it is labeled as a test asset.

All four policies retain Docker/Flex integration tests, but those tests are **runtime-evidence gates**, not a substitute for local/unit evidence. A runner must supply an untracked registration generated for its own locally registered Flex Gateway instance.

## Minimal reproducible observation

Environment:

- Flex Gateway container: `mulesoft/flex-gateway:1.14.0`
- PDK test harness: `pdk-test = 1.10.0`
- custom policy definition and implementation mounted beneath `custom-policies`
- API instance bound to the generated implementation extension name

A newly generated self-signed X.509 certificate can be mounted as the `flex-registration` secret and is readable by the container. Flex reads the configuration, but rejects it with:

```text
Configuration default/registration: certificate is invalid
ApiInstance default/my-api: the registration configuration is missing
```

The runtime consequently installs no API listener and the HTTP oracle ends with `connection closed before message completed`. Omitting the registration produces the same downstream admission failure (`the registration configuration is missing`).

This demonstrates that a syntactically valid self-signed certificate is not an acceptable replacement for a genuine local Flex registration identity. It is not a policy behavior result.

## Required local procedure

1. Register a disposable/local Flex Gateway instance using the supported Flex local-mode procedure.
2. Keep its generated `registration.yaml` outside source control; it is ignored by the policy projects.
3. Place it only in the relevant project's `tests/config/` directory with restrictive local permissions.
4. Rebuild the target WASM and regenerate the implementation YAML from that exact WASM.
5. Run the policy's Docker integration test and retain nonsecret request/upstream evidence; never publish raw identity-bearing logs.
6. Delete the disposable registration remotely with the supported `flexctl registration delete --file` operation before removing its local fixture. If remote deletion fails, retain the local file securely for a retry.

Do not copy a registration identity between policy projects or use a fake/self-signed certificate to claim a Flex runtime pass.

## Evidence status

- **Verified:** Flex 1.14.0 loads the policy assets when mounted correctly; the harness preserves container logs on failure.
- **Verified:** missing or invalid registration prevents API-instance admission before policy request behavior is observable.
- **Verified after user authorization on Flex 1.14.0:** Honeytoken request denial, response
  redaction with correct received framing, monitor preservation and finite transport exclusions;
  Sentinel block/monitor controls, atomic batch refusal and exact upstream counts; Breadcrumb
  observe/sanitize/block, correlated discovery seeding and optional seeding exclusions.
- **Scope limits:** Sentinel's exported Anypoint Monitoring counts and containment under
  low-level response-write failure remain unverified. Bounded resource, active-stream,
  framing, upload-deadline and OOM/restart cases have since passed; these are not
  general live-SSE transformation support. See [current acceptance and evidence](REMAINING-ISSUES-PLAN.md).
- Registration material stays ignored and local-only. Each authorized policy run used its
  own disposable identity; the review identities have now been remotely deleted and locally
  removed. Only nonsecret lifecycle metadata remains in ignored target directories.
- **Separate platform limitation:** `mcp-honeytoken-tripwire/docs/pdk-response-termination-gap.md` documents the PDK response-stage double-write containment gap; a successful registration would not resolve that limitation.
