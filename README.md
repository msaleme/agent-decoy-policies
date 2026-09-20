# Agent Decoy Policies

A family of **MuleSoft Flex/Omni Gateway custom policies** (PDK, Rust → WebAssembly) that bring
**cyber-deception** to selected agent and MCP message bodies. Operators choose decoys that are
meaningful in their own environment; this repository does not establish that a particular value has no
legitimate use or that a match alone proves compromise. The gateway is a useful enforcement point, but
deployment needs an operator-defined response and false-positive review path.

Inspired by the CISA decoys guidance and informed by **MITRE Engage's** Expose, Affect, and
Elicit engagement-goal vocabulary. These policies detect and optionally neutralize traffic; they
do not implement a controlled decoy environment. See [COMPOSITION.md](./COMPOSITION.md) before
chaining policies: independent Flex extensions cannot themselves guarantee ordered, fail-closed
multi-policy transformations.

## Why deception at the gateway

Traditional detection asks "does this request look malicious?" — a noisy, model-dependent judgement.
A well-chosen decoy can make unauthorized interaction a useful, high-signal investigation input. Its actual
false-positive rate depends on the local decoy design, traffic, and operating response. The three primitives
below map one-to-one to CISA's decoy taxonomy.

## Current validation and support boundary

The current remediation passes Rust unit tests, WebAssembly release builds, and bounded behavior tests
on Flex 1.14.0 for all three policies. Exact results and issue-specific limits are tracked in
[the remediation evidence](docs/REMEDIATION-EVIDENCE.md). These tests cover supported buffered bodies
and explicit finite transport exclusions; they do not establish production effectiveness, general
interoperability, or fail-closed guarantees after platform write failures. Monitoring export,
actual-byte buffering limits, indefinite streams, and whole-chain composition remain open boundaries.

The current implementations process decoded bodies made available to the filter. They do not claim
coverage for SSE or other streaming bodies, compressed or non-UTF-8 content, oversized bodies, URL paths,
query strings, or request/response headers unless a policy's source and a passing behavior test explicitly
say otherwise.

## The policies

| Policy | CISA primitive | What it does | NIST controls |
|---|---|---|---|
| [`mcp-honeytoken-tripwire`](./mcp-honeytoken-tripwire) | Honeytoken | Prototype for detecting configured values in decoded request/response bodies. Its current source and tests define the behavior; Flex request/response behavior is not yet integration-validated. | SC-26 (Decoys), SI-20 (Tainting), SI-4 |
| [`decoy-tool-sentinel`](./decoy-tool-sentinel) | Decoy tool | Prototype for inspecting JSON-RPC `tools/call` objects and batches. A decoy hit atomically blocks an otherwise response-eligible batch in source-level unit coverage; Flex runtime behavior is not yet integration-validated. | SC-26 (Decoys), SC-30 (Concealment & Misdirection), SI-4 |
| [`breadcrumb-misdirection`](./breadcrumb-misdirection) | Breadcrumb | Prototype for JSON tool-list/body transformations. Streaming/SSE and production response-rewrite semantics are outside the currently validated scope. | SC-30 (Concealment & Misdirection), SI-4 |

All three are self-contained Rust implementations with no intentional outbound network calls. Their
configuration modes, logging, and headers are source-level features; operators should verify their
gateway logging/SIEM and downstream-enforcement integration in their own environment. The presence of a
decoy match is an alerting input, not an automatically proven security verdict.

### NIST anchors

- **SP 800-53 Rev 5** — `SC-26` Decoys, `SC-30` Concealment & Misdirection, `SI-20` Tainting,
  `SI-4` System Monitoring.
- **SP 800-160 Vol 2 Rev 1** — cyber-resiliency technique **Deception** (Obfuscation / Disinformation /
  Misdirection / Tainting) and **Analytic Monitoring**.

Both are cited in the CISA decoys document's Prerequisites. These policies also address
**OWASP LLM Top 10 (2025)** LLM06 *Excessive Agency* (a hijacked agent reaching for data/tools it should
never touch).

## Build & test

Each policy is an independent PDK project. Requirements: Rust **1.89.0** with the `wasm32-wasip1` target,
and — only for regenerating asset files or publishing — `anypoint-cli-v4` with the PDK plugin plus
`cargo-anypoint` (`make setup`).

```bash
cd mcp-honeytoken-tripwire

# Compile the policy to WebAssembly (uses the committed src/generated/config.rs):
cargo build --target wasm32-wasip1 --release

# Run the unit tests:
cargo test --lib

# Full asset-file regeneration + WASM build (requires your Anypoint org id, see below):
make setup          # one-time: installs cargo-anypoint + llvm-cov
make build
```

> **Set your Anypoint org id before `make build` or publishing.** Each `Cargo.toml` ships
> `group_id = "REPLACE_WITH_YOUR_ANYPOINT_ORG_ID"` under `[package.metadata.anypoint]`. Replace it with
> your own organization id. `cargo build`/`cargo test` do **not** need it (the generated config is
> committed); only `make build-asset-files`, `make build`, and publishing to Exchange do.

## Contributing to P4A ("Policies for Agents")

These are built for the community **[P4A](https://www.p4a.ai/)** marketplace of Omni Gateway agent
policies (PDK 1.8+). Two paths:
- **Bring Your Own Policy** — this GitHub-hosted PDK project is built/validated and listed.
- **Community Ideas** — propose the decoy family as ideas and gather upvotes.

The decoy/deception family fills a gap in the existing catalog (MCP poisoning/drift detection, A2A skill
governance, delegation-depth limiting, semantic cache) — none of which plant decoys.

## Layout

```
agent-decoy-policies/
├── mcp-honeytoken-tripwire/     # honeytoken tripwire prototype
├── decoy-tool-sentinel/         # decoy MCP tool sentinel prototype
└── breadcrumb-misdirection/     # breadcrumb lure prototype
```

Each project keeps the standard PDK structure: `definition/gcl.yaml` (config schema),
`src/lib.rs` (filter logic), `src/generated/` (auto-generated from the schema — do not hand-edit),
`tests/`, `playground/` (local Docker Flex Gateway), and `AGENTS.md` (PDK guidance).

## References

The design of each policy is anchored to public guidance. Every control cited in the tables above is
traceable to one of these documents:

- **CISA**, *Using Cyber Decoys to Strengthen Detection and Response*, TLP:CLEAR, September 2026 — the
  Expose / Affect / Elicit taxonomy and the honeytoken, decoy-tool, and breadcrumb primitives this family
  implements.
  <https://www.cisa.gov/sites/default/files/2026-09/using-cyber-decoys-to-strengthen-detection-and-response_508c.pdf>
- **NIST SP 800-53 Rev. 5**, *Security and Privacy Controls for Information Systems and Organizations*,
  Sept 2020 (updates through Dec 2020) — controls **SC-26** (Decoys), **SC-30** (Concealment &
  Misdirection), **SI-4** (System Monitoring), **SI-20** (Tainting).
  DOI: [10.6028/NIST.SP.800-53r5](https://doi.org/10.6028/NIST.SP.800-53r5)
- **NIST SP 800-160 Vol. 2 Rev. 1**, *Developing Cyber-Resilient Systems: A Systems Security Engineering
  Approach*, Dec 2021 — the cyber-resiliency techniques **Deception** (Obfuscation / Disinformation /
  Misdirection / Tainting) and **Analytic Monitoring**.
  DOI: [10.6028/NIST.SP.800-160v2r1](https://doi.org/10.6028/NIST.SP.800-160v2r1)
- **OWASP Top 10 for LLM Applications (2025)**, **LLM06: Excessive Agency** — a hijacked agent reaching
  for data or tools it should never touch, which these decoys are designed to surface.
  <https://genai.owasp.org/llm-top-10/>
