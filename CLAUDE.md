# CLAUDE.md

Guidance for Claude Code when working in this repository.

## What this is

`agent-decoy-policies` is a **public MIT-licensed** repository of cyber-deception
policies for AI agent / Model Context Protocol (MCP) traffic on **MuleSoft
Flex/Omni Gateway**, built with the MuleSoft **Policy Development Kit (PDK)**:
Rust compiled to `wasm32-wasip1`, running as a proxy-wasm filter. Three standalone
detectors (Honeytoken Tripwire, Decoy Tool Sentinel, Breadcrumb Misdirection) can
run independently, or be combined via an opt-in Decoy Coordinator that guarantees
ordering and a final re-scan across all three within one bounded, single-envelope
JSON-RPC extension. Deception concepts draw on MITRE Engage and CISA cyber-decoy
guidance (see `ATTRIBUTION.md` for exact scope/limits of those citations).

**This repo is PUBLIC (github.com/msaleme/agent-decoy-policies).** Scan every
change for secrets, credentials, and registration/identity material before any
commit or push — nothing like that belongs in tracked source.

**A primary autonomous agent (Codex, per `docs/CODEX-HANDOFF.md`) develops this
repo day-to-day.** When resuming work here, read `docs/CODEX-HANDOFF.md` first —
it has the current working-tree state, authorized scope, and the exact
next-step instructions. Then `docs/REMAINING-ISSUES-PLAN.md` for issue/CI status.

## Repository layout

- `mcp-honeytoken-tripwire/`, `decoy-tool-sentinel/`, `breadcrumb-misdirection/`,
  `decoy-coordinator/` — the four independent Rust/PDK policy projects. Each has
  its own `Cargo.toml`/`Cargo.lock`, `rust-toolchain.toml`, `Makefile`,
  `definition/gcl.yaml` (config schema), `src/lib.rs` (filter logic),
  `src/generated/config.rs` (auto-generated — never hand-edit), `tests/`
  (integration tests via `pdk-test`, need Docker), `playground/` (local Flex +
  sample backend via `make run`), and its own `README.md` (the three standalone policies also carry an `AGENTS.md`).
- `COMPOSITION.md` — the composition contract standalone filters must follow if
  a gateway chains them (they don't share state or a callback); the coordinator
  implements this contract natively.
- `ATTRIBUTION.md` — license/provenance scope: upstream PDK scaffold notices,
  direct Rust dependency licenses, and the exact boundaries of the CISA/MITRE/NIST
  design-reference citations.
- `docs/` — `CODEX-HANDOFF.md` (read first when resuming), `REMAINING-ISSUES-PLAN.md`
  (current acceptance/CI/issue status — supersedes older instructions),
  `PREPRINT-CITATION-AND-FOLLOW-UPS.md` (claim audit + proposed, not-yet-implemented
  follow-ups), `RELEASING.md`, `FLEX-RUNTIME-RUNBOOK.md` +
  `flex-runtime-verification-boundary.md` (Local Mode setup/evidence boundary),
  `CONNECTED-MONITORING-EVIDENCE.md`, `GATEWAY-RESOURCE-PREFLIGHT.md`,
  `BREADCRUMB-MIGRATION.md`, `P4A-REPOSITORY-REVIEW.md`, `INDEPENDENT-REVIEW.md`,
  `REMEDIATION-EVIDENCE.md`, `POST-MERGE-FOLLOW-UP.md`.
- `deployment/` — `upload-gate/` (optional HAProxy outer gate enforcing a bounded
  request-body collection deadline) and `docker-resource-limits.yaml`.
- `scripts/` — Python verification tooling: `flex_runtime_gate.py` (build/asset
  gate + Local Mode orchestration), `verify_upload_gate.py` (Docker upload-gate
  tests), `gateway_resource_preflight.py` (Docker/cgroup memory checks), and
  their `test_*.py` unittest suites.
- `licenses/` — verbatim upstream license text (e.g. `Salesforce-PDK-1.10.0.txt`).
- `.github/workflows/verify.yml` — the authoritative CI job definitions.

## Build / test / lint commands

Per-policy (run from inside `mcp-honeytoken-tripwire/`, `decoy-tool-sentinel/`,
`breadcrumb-misdirection/`, or `decoy-coordinator/` — same shape in all four):

```bash
# one-time toolchain (pinned exact version, matches rust-toolchain.toml/CI)
rustup toolchain install 1.89.0 --profile minimal \
  --component rustfmt --component clippy --target wasm32-wasip1

cargo +1.89.0 fetch --locked
cargo +1.89.0 fmt --check
cargo +1.89.0 test --lib --locked --offline          # unit tests, no Docker/network
cargo +1.89.0 clippy --all-targets --locked --offline -- -D warnings
cargo +1.89.0 test --tests --no-run --locked --offline  # integration tests compile only (CI does not execute them)
cargo +1.89.0 build --release --target wasm32-wasip1 --locked   # release WASM bundle
```

Makefile targets (need `cargo-anypoint` + `anypoint-cli-v4`, mostly for the
Anypoint/Exchange side, not plain dev iteration): `make setup`, `make build`,
`make run` (local Flex Gateway + sample backend via `playground/docker-compose.yaml`),
`make test` (integration tests, Docker), `make test-coverage FORMAT=json|html`,
`make publish` / `make release` (Anypoint asset publish — requires org creds;
replace `REPLACE_WITH_YOUR_ANYPOINT_ORG_ID` in `Cargo.toml`'s
`[package.metadata.anypoint]` first).

Repo-wide Python verification (from repo root):

```bash
python3 -m unittest discover -s scripts -p 'test_*.py'
python3 scripts/flex_runtime_gate.py --prepare --assets-only   # regenerate/check build assets, no Docker/registration
git diff --exit-code                                            # CI fails if regen produced a diff
```

Regenerate assets after any `definition/gcl.yaml` or source change that affects
the generated config:

```bash
python3 scripts/flex_runtime_gate.py --prepare --assets-only
```

The full CI matrix (`.github/workflows/verify.yml`, two jobs) is the ground truth:
- `upload-gate` job: `docker pull haproxy:3.2-alpine@...` + `python:3.12.12-slim-bookworm@...`,
  then `python3 scripts/verify_upload_gate.py` (credential-free Docker tests).
- `policies` job: installs Rust 1.89.0 + `cargo-anypoint@1.9.0`, then for each of
  the four policy dirs runs `fetch → fmt --check → test --lib → clippy --all-targets -D warnings → test --tests --no-run`,
  then the Python unittest discovery + `flex_runtime_gate.py --prepare --assets-only` + `git diff --exit-code`.

Authenticated Flex Local/Connected Mode runtime suites are **not** run in public
CI — they require a disposable, explicitly user-authorized registration (see
`docs/FLEX-RUNTIME-RUNBOOK.md` and `docs/flex-runtime-verification-boundary.md`).
Do not attempt to run them without that authorization, and never commit
registration/identity material.

## Architecture

- **Four independent Rust crates**, each a PDK-scaffolded custom Flex/Omni Gateway
  policy compiled to a single `cdylib` targeting `wasm32-wasip1`, running inside
  the gateway's proxy-wasm sandbox: single-threaded, no `unsafe`, no blocking I/O
  or multithreading primitives (`Arc`/`Mutex`/etc. forbidden — see each project's
  `AGENTS.md` "proxy-wasm runtime" section).
- **Honeytoken Tripwire** — detects configured honeytoken values in eligible
  request/response bodies; monitor, block, redact, or withhold.
- **Decoy Tool Sentinel** — detects JSON-RPC `tools/call` requests targeting
  configured inert decoy tools; monitor or block, rejects a whole batch on a hit,
  emits PDK policy violations in *both* monitor and block modes.
- **Breadcrumb Misdirection** — detects configured lure text; observe, sanitize,
  or block requests, and can separately seed matching `tools/list` responses.
- **Decoy Coordinator** (opt-in, stricter contract, version 0.1.0 — the others
  are 1.0.0) — runs all three detectors against the *original* admitted JSON-RPC
  body and **never rewrites a request**: a required block wins, and Breadcrumb
  `sanitize` blocks exactly like `block` on requests (#54). Response-side: required Honeytoken
  redaction/withholding before optional non-expanding `tools/list` seeding,
  followed by a **mandatory final Honeytoken re-scan** of the actual output bytes
  (a remaining decoy after transformation is a hard composition failure, not a
  success). Bounded to unencoded, single-envelope, ≤64 KiB JSON-RPC 2.0 traffic;
  admission is mode-aware — enforcing modes fail closed with bare 415/413/400 on
  uninspectable/invalid-framing/unsupported requests, monitor/observe forwards them
  with a warn `inspection_skipped`; a response must declare `Content-Length` or is
  forwarded uninspected (`response_inspection_skipped`). Event names/levels are in
  `decoy-coordinator/README.md`. See
  `COMPOSITION.md` for the full contract standalone filters must satisfy if
  chained manually (they do **not** share state — chaining ≠ the coordinator).
- Config schema lives in each project's `definition/gcl.yaml`; `src/generated/config.rs`
  is generated from it via `cargo anypoint config-gen` (invoked by `make build-asset-files`) — never hand-edit.
- Events must record `stage`, `requested`, `applied`, and `reason` separately —
  a requested change is not evidence it reached the wire.

## Conventions & gotchas

- **Public repo — scan for secrets before every push.** No registration/identity
  material, Anypoint org IDs beyond the `REPLACE_WITH_YOUR_ANYPOINT_ORG_ID`
  placeholder, or credentials belong in tracked source.
- **Immutable source tag `v0.1.0-rc.1`** at commit `f442cba95082b2fcb60c26c0613e327d420635a2`
  is a citation anchor (100 Rust library tests: Honeytoken 42, Sentinel 25,
  Breadcrumb 14, Coordinator 19; plus 23 Python tests). Never move a published
  tag — cut a new version for corrections.
- **`enable_stop_iteration` PDK feature is required** on both the `pdk` and
  `pdk-unit` dependencies in every policy's `Cargo.toml` — it exposes
  `into_headers_body_state`, letting one filter inspect the body and also
  stamp/modify headers on the same request/response. Don't drop it when
  touching dependencies.
- **Honesty boundaries — do not overstate what's verified:**
  - Sentinel's exported Monitoring disposition labels a **monitor-mode** hit
    `BLOCKED` even when the backend still received the request. That label is
    not proof of upstream enforcement — see `docs/CONNECTED-MONITORING-EVIDENCE.md`.
  - Response-side containment on a low-level host **write failure** is an
    unverified/undemonstrated platform boundary, not a reproduced Flex bug: the
    PDK's `set_body` result doesn't acknowledge the host actually applied the
    replacement. Full detail: `mcp-honeytoken-tripwire/docs/pdk-response-termination-gap.md`.
  - Public CI runs library/Python/static/build checks only; authenticated Flex
    Local/Connected Mode runtime evidence is separate, bounded, and requires
    explicit user authorization + disposable registrations that get deleted
    after use — never assume it's ambient or reusable.
- **No mock code / no fabricated evidence** (repo-wide norm, matches the global
  convention): every verification claim in docs is tied to an actual CI run, a
  specific commit, or a named disposable evidence run — don't add claims that
  aren't backed the same way.
- **`docs/CODEX-HANDOFF.md` is the first read when resuming work** — it holds
  current authorized scope, working-tree/branch state, and explicit "do not
  assume" warnings (e.g., don't resume a stale local `main` checkout without
  verifying against `origin/main`).
- **Distribution target is the P4A (Policies for Agents) marketplace**
  (`https://www.p4a.ai/`) — see `docs/P4A-REPOSITORY-REVIEW.md` for the
  comparison against sampled P4A repos. A GitHub tag/source snapshot is
  distinct from a P4A submission or an Anypoint Exchange publication — none of
  those are implied by CI passing or a tag existing (`docs/RELEASING.md`).
