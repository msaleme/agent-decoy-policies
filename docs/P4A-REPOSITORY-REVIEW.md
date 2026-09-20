# P4A repository comparison

Reviewed **2026-09-20**. This is a sample of public repositories under the
[P4A organization](https://github.com/P4A-Policies-for-Agents), not a claim about
all catalog entries. GitHub tags/releases APIs and repository trees were inspected;
README content and representative manifests were read without importing code.

## What other repositories do

| Repository | Layout | Root license file | Git tags / GitHub releases |
| --- | --- | --- | --- |
| [utcp-policy](https://github.com/P4A-Policies-for-Agents/utcp-policy) | Unified root crate with `.project.yaml` | None in tree; README says internal use | 0 / 0 |
| [a2a-pii-guard-policy](https://github.com/P4A-Policies-for-Agents/a2a-pii-guard-policy) | Separate definition and implementation | Apache-2.0 | 0 / 0 |
| [mcp-response-cache-policy](https://github.com/P4A-Policies-for-Agents/mcp-response-cache-policy) | Separate definition and implementation | Apache-2.0 | 0 / 0 |
| [ai-semantic-cache](https://github.com/P4A-Policies-for-Agents/ai-semantic-cache) | Multiple variants in a workspace | Apache-2.0 | 0 / 0 |
| [claude-a2a-bridge-policy](https://github.com/P4A-Policies-for-Agents/claude-a2a-bridge-policy) | Separate definition and implementation | Apache-2.0 | 0 / 0 |
| [omni-policy-mcp-tool-poisoning-detection-exchange](https://github.com/P4A-Policies-for-Agents/omni-policy-mcp-tool-poisoning-detection-exchange) | Unified root crate with `.project.yaml` | None in tree | 0 / 0 |
| [jwt-token-injection](https://github.com/P4A-Policies-for-Agents/jwt-token-injection) | Nested unified crate with `.project.yaml` | None in tree | 0 / 0 |
| [tamper-evident-audit-logging-policy](https://github.com/P4A-Policies-for-Agents/tamper-evident-audit-logging-policy) | Separate definition/implementation plus support crates | Apache-2.0 | 0 / 0 |

Useful conventions include configuration tables, operational examples, explicit
unsupported behavior, build commands, and design/evidence documents. The audit
logging repository also documents dependency licenses and separates completed
checks from runtime gaps. None of the sampled trees contained a GitHub Actions
workflow or changelog; that is an observation, not a reason to remove ours.

Version numbers exist without Git tags: UTCP's manifest was `0.3.1` at
[`b7fe351`](https://github.com/P4A-Policies-for-Agents/utcp-policy/blob/b7fe3516161af73d7b80cc529054212612c49670/Cargo.toml),
while MCP Response Cache's implementation and definition asset were `1.0.1` at
[`8bc0f32`](https://github.com/P4A-Policies-for-Agents/mcp-response-cache-policy/blob/8bc0f32e56a2eebf7af9e6ed6f402f3e3084c179/implementation/Cargo.toml).
These manifest values do not prove that a corresponding Exchange release exists.

## Submission fit

[P4A's submission guide](https://docs.p4a.ai/docs/guides/submitting-a-policy)
accepts unified, split, and nested policy projects. It checks public accessibility,
Cargo project structure, a resolvable PDK dependency, and PDK 1.8.0 or newer.
Unified project roots need `.project.yaml`. Documentation and media can be supplied
through the submission workflow; they are not proof of catalog acceptance.

Our repository contains four independent unified projects, each pinned to PDK
1.10.0. Submit and validate the intended project explicitly. The guide's support
for nested projects does not prove automatic discovery of all four independent
policies from one root URL; a real P4A validation result is still needed.

| Area | Repository action / status |
| --- | --- |
| Project discovery | Add the missing coordinator `.project.yaml`; regression checks all four local project descriptors |
| Usage documentation | Keep policy-specific configuration/examples and the root selection table, quick start, and evidence links |
| CI and runtime evidence | Keep automated checks and separate credential-free CI from authenticated Local Mode tests |
| Attribution | Restore removed Salesforce notices, retain supplied PDK terms, and credit design sources in [ATTRIBUTION.md](../ATTRIBUTION.md) |
| License scope | Keep MIT for project contributions; preserve upstream terms and document unresolved historical template provenance |
| Versioning | Add an unreleased changelog and [release guidance](RELEASING.md); recommend an annotated source prerelease snapshot |
| Marketplace state | No submission, acceptance, deployment, or publication is claimed by this comparison |

No additional workspace conversion or marketplace-specific file is inferred solely
from another repository's layout. No peer implementation was copied during this
review. Actual catalog validation and binary license packaging remain distinct
follow-up steps before those distributions.
