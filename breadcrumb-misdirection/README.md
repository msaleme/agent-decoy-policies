# Breadcrumb Misdirection

> Part of the [Agent Decoy Policies](../README.md) family. CISA primitive: **breadcrumb**.
> NIST SP 800-53 Rev 5 **SC-30** (Concealment & Misdirection), **SI-4**. OWASP **LLM06**.

The gateway can optionally plant a **breadcrumb** — text naming a resource no real task
needs — into the tool descriptions an agent reads from `tools/list`. This is a detection-only
breadcrumb: it does not lead to another decoy asset or controlled environment. When a request
contains the breadcrumb, the policy records an event; the selected response mode determines
whether the original request is forwarded, sanitized, or refused.

### Configuration

| Field | Type | Default | Purpose |
|---|---|---|---|
| `breadcrumb` | string | `""` | The lure text. Empty disables the policy. |
| `mode` | `observe`\|`sanitize`\|`block` | `observe` | Observe logs and forwards unmodified; sanitize logs, removes the lure, and forwards; block rejects. |
| `seeding` | `disabled`\|`enabled` | `disabled` | Independently controls whether `tools/list` descriptions are modified to carry the lure. |
| `alertHeader` | string | `x-agent-breadcrumb` | Header stamped on a request that followed the lure. |

```yaml
- policyRef:
    name: breadcrumb-misdirection-flex-v1-0-impl
  config:
    breadcrumb: "admin_override_do_not_use"
    mode: observe
    seeding: disabled
    alertHeader: x-agent-breadcrumb
```

`breadcrumb` is the exact, case-sensitive marker, both planted and detected. Use a standalone
identifier such as the example above. If you configure a sentence, only that entire sentence
matches; mentioning a resource named inside the sentence does not match. This policy does not
infer intent or resolve resource references.

On an admitted match, observe logs `observed` and forwards the original body; sanitize removes
the marker and forwards only after a successful write; block rejects with HTTP `403`. Failed
required sanitization rejects with HTTP `500` without upstream execution. Unsafe JSON edits
(such as creating duplicate keys) reject with HTTP `415`. Events include `stage`, `requested`,
`applied`, and `reason`; unsuccessful writes are never reported as successful sanitation/seeding.
Observe can stamp an alert header, so “unchanged” refers to body bytes, not all metadata.

### Inspection and seeding boundaries

Eligible bodies require a decimal `Content-Length` at most 64 KiB, no `Content-Encoding`, and
`application/json`, `application/*+json`, or `text/plain`. JSON must be valid UTF-8 with unique
object members. Detection checks raw text and decoded JSON string keys/values; JSON sanitation
preserves syntax and refuses edits that leave a marker. Invalid UTF-8, missing/invalid/mismatched
length, unsupported media types, compression, and streaming/SSE requests are rejected with HTTP
`415` in block/sanitize mode. Observe forwards them byte-for-byte uninspected. Bodyless traffic
passes. The size rule is a declared-length eligibility check, not an actual-byte buffer cap.

Seeding is independent of mode and optional. It applies only to an admitted single `tools/list`
request and a JSON-RPC response with the same ID, valid JSON, and eligible JSON framing. Local
request data carries this correlation; headers are never trusted as provenance. Batches and
notifications do not authorize seeding. Unsupported/streaming responses pass unchanged without
seeding. A failed optional write preserves original body and framing. Successful rewrites remove
stale framing headers. Only `seeding: disabled` with `mode: observe` preserves bodies in both directions.
SSE seeding remains unsupported; these tests do not establish Flex streaming behavior.

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

## Migrating existing configurations

See [Breadcrumb migration](../docs/BREADCRUMB-MIGRATION.md) for the explicit
`monitor` → `sanitize` and `seedToolDescriptions` → `seeding` mapping, changed
defaults, rollback checks, and the next major release boundary.
