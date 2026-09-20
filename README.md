# Agent Decoy Policies

[![Verify policies](https://github.com/msaleme/agent-decoy-policies/actions/workflows/verify.yml/badge.svg?branch=main)](https://github.com/msaleme/agent-decoy-policies/actions/workflows/verify.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Cyber-deception policies for AI agent and Model Context Protocol (MCP) traffic,
built with Rust and WebAssembly for MuleSoft Flex/Omni Gateway.**

Detect configured honeytokens, intercept calls to inert decoy tools, and observe or
sanitize breadcrumb markers in eligible message bodies. Use the standalone policies
individually, or the opt-in coordinator when detection and transformations must run
in a defined order.

This repository includes policy source, configuration schemas, automated checks,
and bounded Local Mode runtime evidence. Deployment support is limited to the
[documented contracts and verification scope](docs/REMAINING-ISSUES-PLAN.md).

## Choose a policy

| Policy | Purpose | Available behavior |
| --- | --- | --- |
| [Honeytoken Tripwire](mcp-honeytoken-tripwire/README.md) | Detect configured decoy values in eligible request and response bodies | Monitor; block matching requests; redact or withhold responses |
| [Decoy Tool Sentinel](decoy-tool-sentinel/README.md) | Detect JSON-RPC `tools/call` requests for configured inert tools | Monitor or block; reject an entire batch on a decoy hit; emit PDK policy violations |
| [Breadcrumb Misdirection](breadcrumb-misdirection/README.md) | Detect configured lure text and optionally seed matching `tools/list` responses | Observe, sanitize, or block requests; enable response seeding separately |
| [Decoy Coordinator](decoy-coordinator/README.md) | Combine all three detectors in one extension for bounded, single-envelope JSON-RPC | Inspect the original body, resolve blocks before edits, and rescan transformed output |

Each policy README defines its configuration, admission rules, and protocol behavior.
The coordinator has a stricter contract and separate configuration. Chaining the
standalone filters does not provide the same ordering guarantees; read the
[composition contract](COMPOSITION.md) before combining them.

Operators supply decoy values and choose the response appropriate to their environment.
Decoy tools must remain inert even when a policy is bypassed or runs in monitor mode.
A match provides an investigation signal; its meaning depends on local traffic,
decoy placement, and false-positive review.

## Quick start

Each policy is an independent Rust project. Native tests and WebAssembly compilation
use the committed generated configuration and require no Anypoint credentials.

```bash
git clone https://github.com/msaleme/agent-decoy-policies.git
cd agent-decoy-policies

rustup toolchain install 1.89.0 --profile minimal \
  --component rustfmt --component clippy --target wasm32-wasip1

cd mcp-honeytoken-tripwire
cargo +1.89.0 test --lib --locked
cargo +1.89.0 build --release --target wasm32-wasip1 --locked
```

Use the same commands in any of the four policy directories. Dependencies require
network access on first use; add `--offline` after they are cached.

For schema regeneration and Anypoint asset tooling, follow the selected policy's
Makefile instructions. Replace `REPLACE_WITH_YOUR_ANYPOINT_ORG_ID` in its
`Cargo.toml` before organization-specific asset generation or Exchange publication.
A local build does not publish or deploy a policy.

## Validation and deployment

The [CI workflow](.github/workflows/verify.yml) runs:

- Rust library tests, formatting, strict Clippy, and integration-test compilation
  for all four policies.
- Python verification tests and release WebAssembly bundle checks.
- Credential-free Docker tests for the optional upload gate, including active
  upload deadlines, framing rejection, memory limits, and explicit restart recovery.

The [verification record](docs/REMAINING-ISSUES-PLAN.md) documents 100 passing Rust
library tests, 22 Python tests, and separate bounded Flex 1.14.0 Local Mode runs.
Public CI does not run authenticated Flex behavior suites or receive a gateway identity.

For runtime setup, use the [Flex runbook](docs/FLEX-RUNTIME-RUNBOOK.md) and
[registration and evidence boundary](docs/flex-runtime-verification-boundary.md).
Keep registrations and other identity material outside version control. Delete each
disposable remote registration before removing its local fixture.

The optional [HAProxy upload gate](deployment/upload-gate/README.md) enforces a
two-second body collection deadline for bounded POST requests, with a separate
header timeout. The [resource preflight](docs/GATEWAY-RESOURCE-PREFLIGHT.md) checks
Docker and live cgroup memory limits. These deployment examples require environment-specific
network isolation, sizing, and transport validation.

## Supported scope and known limits

- **Bounded bodies:** semantic inspection is limited to each policy's admitted media
  types and decoded bodies, generally with a declared length of at most 64 KiB.
  Admission checks alone do not impose a received-byte memory cap.
- **Transport exclusions:** SSE, streaming, compressed, and non-UTF-8 bodies are
  outside semantic inspection coverage. Rejection, withholding, or uninspected
  forwarding depends on the policy and mode; consult its README.
- **Response containment:** successful response transformations are tested, but the
  PDK does not expose a low-level body-write acknowledgement or a supported
  response-stage abort. Unconditional containment during host-write failure remains
  a [documented platform limitation](mcp-honeytoken-tripwire/docs/pdk-response-termination-gap.md).
  The upload gate enforces request admission and does not close this response gap.
- **Monitoring:** Sentinel emits PDK policy violations in monitor and block modes.
  [Connected Mode Sandbox verification](docs/CONNECTED-MONITORING-EVIDENCE.md) observed
  the expected exported counts in both modes. Monitoring labels monitor-mode
  violations `BLOCKED` too; that label does not prove upstream rejection.
- **Operational coverage:** matches inspect selected message bodies, not URL paths,
  query strings, or arbitrary headers. Alert headers are not trusted provenance.
  Local tests do not establish general MCP interoperability or production effectiveness.

## Documentation map

| Area | Start here |
| --- | --- |
| Policy configuration | The four policy READMEs linked above |
| Coordinated enforcement | [Composition contract](COMPOSITION.md) |
| Accepted fixes and current evidence | [Verification status](docs/REMAINING-ISSUES-PLAN.md) |
| Flex runtime testing | [Runtime runbook](docs/FLEX-RUNTIME-RUNBOOK.md) |
| Upload deadline and memory controls | [Upload gate](deployment/upload-gate/README.md) · [Resource preflight](docs/GATEWAY-RESOURCE-PREFLIGHT.md) |
| Attribution and license scope | [Attribution](ATTRIBUTION.md) |
| Versions and community conventions | [Changelog](CHANGELOG.md) · [Release guidance](docs/RELEASING.md) · [P4A comparison](docs/P4A-REPOSITORY-REVIEW.md) |
| Automated verification | [CI workflow](.github/workflows/verify.yml) · [Verification scripts](scripts/) |

## Contributing

For a bug report, include the policy, mode, gateway/PDK versions, a synthetic
reproduction, and expected versus observed behavior. Exclude credentials and real
sensitive payloads. For a behavior change, add a focused regression and run the
affected policy's tests, formatting, Clippy, and release build. Keep source,
configuration schemas, generated assets, and documentation consistent.

## Design references

The project applies deception concepts to gateway policy enforcement. Relevant
background includes [NIST SP 800-53 Rev. 5](https://doi.org/10.6028/NIST.SP.800-53r5)
(SC-26, SC-30, SI-4, and SI-20) and
[NIST SP 800-160 Vol. 2 Rev. 1](https://doi.org/10.6028/NIST.SP.800-160v2r1)
(cyber-resiliency engineering). These references describe design context, not a
compliance certification. See also the
[MuleSoft PDK overview](https://docs.mulesoft.com/pdk/latest/policies-pdk-overview).

Design-source credit, PDK/template provenance, and dependency declarations are
recorded in [ATTRIBUTION.md](ATTRIBUTION.md).

## License

Project contributions: [MIT](LICENSE). Upstream templates and dependencies retain
their own notices and terms; see [attribution and license scope](ATTRIBUTION.md).
