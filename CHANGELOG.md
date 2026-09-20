# Changelog

## Unreleased

- Verified Sentinel's exported Monitoring counts in a disposable Connected Mode
  Sandbox; see [evidence and cleanup](docs/CONNECTED-MONITORING-EVIDENCE.md).
- Correct Honeytoken's monitor-mode safety and status descriptions; document
  buffering, operational review and opaque-ID logging without raw body/token logging.
- Restore concise design provenance, identify “decoy tool” as project terminology,
  and correct the cited snapshot's Python test count to 23.
- Record [citation boundaries and proposed compatibility work](docs/PREPRINT-CITATION-AND-FOLLOW-UPS.md).
  Configuration mode names and runtime behavior are unchanged.

## [v0.1.0-rc.1](https://github.com/msaleme/agent-decoy-policies/releases/tag/v0.1.0-rc.1) — 2026-09-20

First repository-wide source prerelease. Includes Honeytoken Tripwire 1.0.0,
Decoy Tool Sentinel 1.0.0, Breadcrumb Misdirection 1.0.0, and Decoy Coordinator
0.1.0, built with Rust 1.89.0 and PDK 1.10.0. The repository tag identifies the
family snapshot; it does not change those policy versions or establish an Exchange
publication. No compiled release assets are included.

### Added

- Honeytoken Tripwire, Decoy Tool Sentinel, and Breadcrumb Misdirection policies.
- Opt-in Decoy Coordinator for ordered detection and transformations within one
  bounded, single-envelope JSON-RPC extension.
- Credential-free CI, bounded Flex Local Mode evidence, an optional HAProxy upload
  gate, and Docker/cgroup resource verification.
- Explicit attribution, upstream notice preservation, and a source-release process.

### Changed

- Fail-closed admission for enforcing modes, duplicate-member rejection, atomic
  batch blocking, and consistent JSON-RPC notification/error handling.
- Safe mutation ordering, response rescanning, and Sentinel PDK violation reporting.
- Breadcrumb `observe`, `sanitize`, and `block` behavior and independent response
  seeding. Existing users should follow the [migration guide](docs/BREADCRUMB-MIGRATION.md).
- Public documentation now distinguishes CI, Local Mode runtime evidence, and
  deployment-specific guarantees.

### Known limitations

- Streaming/SSE, compressed bodies, and other unsupported payload classes remain
  outside semantic inspection coverage.
- Exported Anypoint Monitoring counts remain unverified.
- Response containment on low-level host-write failure remains a PDK capability
  boundary; the optional request upload gate does not resolve it.
- The exact original scaffold release remains unrecorded, and the original CISA
  reference could not be independently revalidated. See [attribution](ATTRIBUTION.md).
  This source snapshot preserves those uncertainties; it is not a complete binary
  redistribution license inventory.

See [verification status](docs/REMAINING-ISSUES-PLAN.md), individual policy contracts,
and [release guidance](docs/RELEASING.md) before selecting a release snapshot.
