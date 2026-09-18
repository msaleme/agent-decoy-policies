# Agent Decoy Policies

A family of **MuleSoft Flex/Omni Gateway custom policies** (PDK, Rust → WebAssembly) that bring
**cyber-deception** to agent and MCP traffic. You plant decoys — data, tools, and lures that have **no
legitimate use** — so that a single interaction with one is a high-fidelity, near-zero-noise signal that
an agent has been hijacked, poisoned, or is exfiltrating. The gateway is the natural place to do this:
it already sits in front of every model, tool, and MCP server, so it can both **plant** the decoy and
**watch** every request and response for a touch.

Inspired by CISA's *[Using Cyber Decoys to Strengthen Detection and Response](https://www.cisa.gov/sites/default/files/2026-09/using-cyber-decoys-to-strengthen-detection-and-response_508c.pdf)*
(TLP:CLEAR, 2026) and grounded in NIST controls. These policies stay firmly in CISA's **Expose**
(detect) and **Affect** (impose cost) tiers — they flag and neutralize. They deliberately do **not**
implement **Elicit** (building a fake environment to entrap and study an adversary), which CISA flags as
an advanced technique with legal risk that does not belong in a general-purpose gateway policy.

## Why deception at the gateway

Traditional detection asks "does this request look malicious?" — a noisy, model-dependent judgement.
A decoy inverts the question: nothing legitimate ever touches it, so **any** touch is the alert. That
gives you a signal with almost no false positives, which is exactly what an autonomous, high-volume
agent fabric needs. The three primitives below map one-to-one to CISA's decoy taxonomy.

## The policies

| Policy | CISA primitive | What it does | NIST controls |
|---|---|---|---|
| [`mcp-honeytoken-tripwire`](./mcp-honeytoken-tripwire) | Honeytoken | Watches every request/response for a planted decoy value (fake credential, record, URL). Flags on any reference; in block mode refuses the request and strips the token from responses so the decoy never leaves. | SC-26 (Decoys), SI-20 (Tainting), SI-4 |
| [`decoy-tool-sentinel`](./decoy-tool-sentinel) | Decoy tool | Watches MCP `tools/call` for a decoy tool no honest agent should ever invoke (e.g. `dump_all_records`). Any call is unambiguous; block mode rejects it with a JSON-RPC error so it never executes. | SC-26 (Decoys), SC-30 (Concealment & Misdirection), SI-4 |
| [`breadcrumb-misdirection`](./breadcrumb-misdirection) | Breadcrumb | Plants a lure into `tools/list` descriptions, logs any agent that follows it, and strips the lure from the request before it reaches a real upstream. Expose-not-Elicit. | SC-30 (Concealment & Misdirection), SI-4 |

All three:
- run **inbound** on any API/MCP instance the gateway fronts;
- support `monitor` (Expose — flag only) and `block` (Affect) modes;
- emit a **structured anomaly** to the gateway log (`logger::warn`), which Message Logging / SSE Logging
  and any SIEM forwarder pick up, and stamp a configurable **alert header** that a Kill Switch or
  downstream policy can key off;
- are self-contained Rust with no outbound network calls (no fail-open/closed ambiguity).

### NIST anchors

- **SP 800-53 Rev 5** — `SC-26` Decoys, `SC-30` Concealment & Misdirection, `SI-20` Tainting,
  `SI-4` System Monitoring.
- **SP 800-160 Vol 2 Rev 1** — cyber-resiliency technique **Deception** (Obfuscation / Disinformation /
  Misdirection / Tainting) and **Analytic Monitoring**.

Both are cited in the CISA decoys document's Prerequisites. These policies also address
**OWASP LLM Top 10 (2025)** LLM06 *Excessive Agency* (a hijacked agent reaching for data/tools it should
never touch).

## Build & test

Each policy is an independent PDK project. Requirements: Rust (stable) with the `wasm32-wasip1` target,
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
├── mcp-honeytoken-tripwire/     # honeytoken tripwire (fully implemented + tested)
├── decoy-tool-sentinel/         # decoy MCP tool sentinel (fully implemented + tested)
└── breadcrumb-misdirection/     # breadcrumb lure + strip (fully implemented + tested)
```

Each project keeps the standard PDK structure: `definition/gcl.yaml` (config schema),
`src/lib.rs` (filter logic), `src/generated/` (auto-generated from the schema — do not hand-edit),
`tests/`, `playground/` (local Docker Flex Gateway), and `AGENTS.md` (PDK guidance).
