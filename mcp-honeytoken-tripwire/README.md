# MCP Honeytoken Tripwire

> Part of the [Agent Decoy Policies](../README.md) family. CISA primitive: **honeytoken**.
> NIST SP 800-53 Rev 5 **SC-26** (Decoys), **SI-20** (Tainting), **SI-4**. OWASP **LLM06**.

A honeytoken is a value with **no legitimate use**: a fake credential, a synthetic record id, a decoy
email or URL. You plant it in data an agent can reach; this policy watches **both directions**
of eligible exchanges for it. Matching is presence-only rather than field-aware: a token quoted in
an agent status report can trip the wire. A well-chosen decoy, matched appropriately to local
traffic and operating response, yields an event worth investigating; this policy cannot establish
that a match alone proves compromise.

- **`monitor`** (Expose) — emit a structured anomaly to the gateway log and stamp the alert header;
  eligible traffic continues unchanged.
- **`block`** (Affect) — reject a **request** that references a honeytoken. For one complete JSON-RPC 2.0 request object, or a non-empty batch whose every member has `jsonrpc: "2.0"` and a string `method`, the policy returns an HTTP `200` JSON-RPC `-32008` error preserving request IDs; notification-only input returns HTTP `202` with no body. These batch paths are generic JSON-RPC and compatibility coverage for legacy MCP (≤2025-03-26), not current MCP behavior. A tripped response-eligible batch is atomically refused in `block` mode; there is no batch forwarding override. A detected token in parseable non-JSON-RPC or mixed-invalid traffic retains the generic HTTP `403` policy response. Explicit JSON that cannot be parsed within the supported limits instead receives HTTP `415`. For eligible response bodies, a honeytoken is stripped without expanding the body; rewrite/framing failures trigger an empty-body withholding attempt, subject to the response-containment platform boundary below.

### Inspection boundary

To avoid inspecting unbounded or lossy payload classes, the policy only semantically scans request or response bodies that have all of the following: an explicit, valid `Content-Length` no greater than **64 KiB**; no `Content-Encoding`; and `application/json`, `application/*+json`, or `text/plain` (legacy requests/responses with no content type are retained for compatibility, but still require a valid length). In `monitor` mode, bodies outside this boundary pass uninspected. In `block` mode they are rejected before upstream on requests and withheld with an empty body on responses. Explicit JSON media types and legacy bodies without a content type that begin with `{` or `[` (after whitespace) must also parse within the default bounded `serde_json::Value` depth and numeric representation limits. Invalid JSON, excessive nesting, and out-of-range numbers (for example `1e400`) are rejected with HTTP `415` on requests and withheld on responses in `block` mode, whether or not a token was detected. `monitor` preserves those bodies; it cannot guarantee decoded-token detection outside these limits. Plain text and other legacy missing-content-type bodies retain best-effort raw/parseable-JSON scanning. This is a **declared-length eligibility filter**, not an independently enforced received-byte memory cap: Flex/Gateway infrastructure must enforce framing and actual buffering limits.

Rewritten output is rescanned for raw and decoded matches before forwarding. Residual matches, including numeric/boolean values alongside string matches, cause an empty-body withholding attempt. SSE is not an admitted media type.

When a response is redacted, the policy removes `Content-Length` and `Content-Encoding` rather than forwarding framing metadata for pre-rewrite bytes.

### Response-containment platform boundary

The policy uses a non-expanding replacement and then an empty-body fallback. If Flex rejects both writes, PDK 1.10 exposes no supported response-stage abort/local-reply operation, so this policy cannot independently guarantee downstream termination. See [the minimal PDK gap record](docs/pdk-response-termination-gap.md) for the verified fallback path, remaining limitation, and required outer enforcement capability.

### Configuration

| Field | Type | Default | Purpose |
|---|---|---|---|
| `honeytokens` | string[] | `[]` | Decoy values to watch for. Plant the same value in the agent's reachable data. |
| `decoyIds` | string[] | `[]` | Opaque operator-assigned IDs parallel to `honeytokens`; used in logs instead of token content. Empty/omitted uses positional `unlabeled-decoy-N` labels; a nonempty list must be complete, unique, and nonblank. |
| `mode` | `monitor`\|`block` | `monitor` | Flag-only vs. reject-and-strip. |
| `alertHeader` | string | `x-agent-decoy-tripwire` | Header stamped on a tripped exchange (for SIEM / Kill Switch). |
| `caseSensitive` | boolean | `false` | ASCII case-insensitive matching by default, so casing changes don't evade the wire. |

```yaml
- policyRef:
    name: mcp-honeytoken-tripwire-v1-0-impl
  config:
    honeytokens:
      - "acct_DECOY_9x1f-do-not-use"
      - "sk-live-DECOY-0000-not-a-real-key"
    mode: block
    alertHeader: x-agent-decoy-tripwire
    caseSensitive: false
```

On a hit the log carries a structured event, e.g.
`{"event":"agent_decoy_tripwire","control":"NIST SC-26/SI-20","direction":"request","decoy_id":"billing-canary-01","action":"blocked"}`

`decoy_id` is an opaque operator-supplied correlation label; the policy never logs the token value, prefix, or length.

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
