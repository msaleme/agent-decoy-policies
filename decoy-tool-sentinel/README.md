# Decoy Tool Sentinel

> Part of the [Agent Decoy Policies](../README.md) family. CISA primitive: **decoy tool**.
> NIST SP 800-53 Rev 5 **SC-26** (Decoys), **SC-30** (Concealment & Misdirection), **SI-4**. OWASP **LLM06**.

You wire an **inert** tool into the fabric that has no legitimate use, then register its
exact unique name here. The registered implementation **must perform no privileged action,
export, authorization or logging change, state mutation, or external side effect**; it should
return a plausible but inconsequential result. Do not reuse the name of a real tool anywhere in
the fabric. This is mandatory even in `monitor` mode: monitor intentionally forwards the decoy
call, and a gateway enforcement point can be bypassed or misconfigured. A well-chosen inert
decoy whose invocation is reviewed in its local operating context yields an event worth
investigating; this repository cannot establish that a particular call proves compromise.

The sentinel inspects only a complete MCP/JSON-RPC 2.0 request body—one request, notification, or client response object, or a non-empty batch of these messages—and fires **only on `tools/call`** of a decoy name. In block mode, malformed, duplicate-member, non-JSON-RPC, and mixed-invalid bodies are rejected with generic HTTP `400`; they never reach upstream. Monitor leaves these ambiguous bodies unchanged without claiming a decoy verdict. Valid client result/error responses pass unchanged without a decoy verdict, including responses to server-initiated requests. IDs must be strings, numbers, or null; request params must be structured, and `tools/call` requires object params with a string `name` and optional object `arguments`. Request and response fields cannot be combined, and error responses require an integer code and string message. It never fires on `tools/list`, so the decoy stays discoverable in the catalog (the bait) while only *calling* it is the signal.

- **`monitor`** (Expose) — emit the anomaly, stamp the alert header, let the call proceed.
- **`block`** (Affect) — refuse the call with a JSON-RPC error (`-32008`) so the decoy never executes. A response-bearing JSON-RPC request receives HTTP `200` with an `application/json` error envelope; a notification-only input receives HTTP `202` with no body.

### Configuration

| Field | Type | Default | Purpose |
|---|---|---|---|
| `decoyTools` | string[] | `[]` | MCP tool names that are decoys. Match the exact names as they appear in `tools/list`. |
| `mode` | `monitor`\|`block` | `monitor` | Flag-only vs. reject with a JSON-RPC error. |
| `alertHeader` | string | `x-agent-decoy-sentinel` | Header stamped when a decoy tool is called. |

```yaml
- policyRef:
    name: decoy-tool-sentinel-flex-v1-0-impl
  config:
    decoyTools:
      - "dump_all_records"
      - "export_secrets"
    mode: block
    alertHeader: x-agent-decoy-sentinel
```

A blocked call returns a JSON-RPC error envelope, e.g.
`{"jsonrpc":"2.0","id":7,"error":{"code":-32008,"message":"decoy tool 'dump_all_records' is not callable"}}`.

Sentinel emits the same control mapping in either mode, with action reflecting the configured behavior:

- block: `{"event":"agent_decoy_tool_call","control":"NIST SC-26/SC-30/SI-4","tool":"dump_all_records","action":"blocked"}`
- monitor: `{"event":"agent_decoy_tool_call","control":"NIST SC-26/SC-30/SI-4","tool":"dump_all_records","action":"flagged"}`

Response-bearing decoy denials use HTTP `200` with JSON-RPC errors; notification-only denials use HTTP `202` without a body. Every detected decoy call, in monitor or block mode, calls PDK's `generate_policy_violation()` once per request; clean and uninspectable calls do not. Local tests observe this property.

[Connected Mode Sandbox evidence](../docs/CONNECTED-MONITORING-EVIDENCE.md) on Flex 1.14.0 also verifies exported counts: five clean calls produced zero violations and three decoy calls produced three violations in each mode. Monitoring reported `request.disposition=BLOCKED` for monitor hits too, despite all three reaching the backend; use wire/backend evidence to establish actual blocking.

PDK stores one active violation per request: this call replaces an earlier violation, and a later policy may replace this one. Policy ordering therefore determines the reported violation; the alert header is not trusted monitoring evidence.

A detected decoy causes atomic rejection of its entire batch. Only request IDs receive error replies; notifications and client responses never receive JSON-RPC replies. A rejected batch with no request IDs receives HTTP `202` with no body.

Batch coverage is generic JSON-RPC / legacy MCP compatibility, not a claim about current MCP clients. No client interoperability claim is made here.

### Body admission

When decoys are configured, inspection requires an explicit decimal `Content-Length` at most 64 KiB, an `application/json` or `application/*+json` media type, and no `Content-Encoding`. Actual buffered length must match the declared length. Block rejects ineligible bodies with HTTP `415`; monitor forwards them uninspected. Bodyless traffic passes. This eligibility gate is not a pre-buffering actual-byte memory cap. Streaming/SSE, compression, and non-JSON traffic are not inspected by Sentinel. Deploy it on the intended JSON-RPC endpoint.


---

This policy was created with the Flex Gateway Policy Development Kit (PDK). To find the complete PDK documentation, see [PDK Overview](https://docs.mulesoft.com/pdk/latest/policies-pdk-overview) on the Mulesoft documentation site.


## Make command reference
This project has a Makefile that includes different goals that assist the developer during the policy development lifecycle.

*For more information about the Makefile, see [Makefile](https://docs.mulesoft.com/pdk/latest/policies-pdk-create-project#makefile).*

### Setup
The `make setup` goal installs the Policy Development Kit internal dependencies for the rest of the Makefile goals.

*For more information about `make setup`, see [Setup the PDK Build environment](https://docs.mulesoft.com/pdk/latest/policies-pdk-create-project#setup-the-pdk-build-environment).*

### Build asset files
The `make build-asset-files` goal generates all the policy asset files required to build, execute, and publish the policy. This command also updates the `config.rs` source code file with the latest configurations defined in the policy definition.

*For more information about creating a policy definition, see [Defining a Policy Schema Definition](https://docs.mulesoft.com/pdk/latest/policies-pdk-create-schema-definition).*

*For more information about `make build-asset-files`, see [Compiling Custom Policies](https://docs.mulesoft.com/pdk/latest/policies-pdk-compile-policies).*

### Build
The `make build` goal compiles the WebAssembly binary of the policy.
Since the source code must be in sync with the policy definition configurations, this goal runs the `build-asset-files` before compiling.

*For more information about `make build`, see [Compiling Custom Policies](https://docs.mulesoft.com/pdk/latest/policies-pdk-compile-policies).*

### Run
The `make run` goal provides a simple way to execute the current build of the policy in a Docker containerized environment. In order to run this goal, the `playground/config` directory must contain a set of files required for executing the policy in a Flex Gateway instance:
- A `registration.yaml` generated for a **local, disposable** Flex Gateway registration. It contains client-identity material: keep it untracked, do not copy it between projects or machines, and never commit it. If no local registration is available, treat Docker runtime verification as blocked rather than replacing it with a self-signed certificate or claiming a runtime pass. See [`../docs/flex-runtime-verification-boundary.md`](../docs/flex-runtime-verification-boundary.md).
Otherwise, to complete the registration we recommend using the Anypoint Platform:
    1. Go to `Runtime Manager`
    2. Navigate to the `Flex Gateway` tab
    3. Click the `Add Gateway` button
    4. Select `Docker` as your OS and copy the registration command replacing `--connected=true` to `--connected=false`.
    5. Paste the command and run it in the `playground/config` directory.

- An `api.yaml` file updated with the desired policy configuration. This file also supports adding other policies to be applied along the one being developed.

The `playground/config` directory can also contain other resource definitions, such as accessory services used by the policy (Eg. a remote authentication service).

*For more information about `make run`, see [Debugging Custom Policies Locally with PDK](https://docs.mulesoft.com/pdk/latest/policies-pdk-debug-local).*

### Test
The `make test` goal runs unit tests and integration tests. Integration tests are placed in the `tests` directory and are configured with the files placed at the
`tests/<module-name>/<test-name>` directory.

*For more information about writing integration tests, see [Writing Integration Tests](https://docs.mulesoft.com/pdk/latest/policies-pdk-integration-tests).*

### Publish
The `make publish` goal publishes the policy asset in Anypoint Exchange, in your configured Organization.

Since the publish goal is intended to publish a policy asset in development, the _assetId_ and name published will explicitly say `dev`, and the versions published will include a timestamp at the end of the version. Eg.
- groupId: your configured organization id
- visible name: _{Your policy name} Dev_
- assetId: _{your-policy-asset-id}-dev_
- version: _{your-policy-version}-20230618115723_

*For more information about publishing policies, see [Uploading Custom Policies to Exchange](https://docs.mulesoft.com/pdk/latest/policies-pdk-publish-policies).*

### Release
The `make release` goal also publishes the policy to Anypoint Exchange, but as a ready for production asset. In this case, the groupId, visible name, assetId and version will be the ones defined in the project.

*For more information about releasing policies, see [Uploading Custom Policies to Exchange](https://docs.mulesoft.com/pdk/latest/policies-pdk-publish-policies).*


### Policy Examples

The PDK provides provides a set of example policy projects to get started creating policies and using the PDK features. To learn more about these examples see [Custom policy Examples](https://docs.mulesoft.com/pdk/latest/policies-pdk-policy-templates).
