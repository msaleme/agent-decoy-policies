# Changelog

## Unreleased

No repository version tag or GitHub release has been published. This entry records
the initial source baseline and its review changes; it does not backdate a release.

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

See [verification status](docs/REMAINING-ISSUES-PLAN.md), individual policy contracts,
and [release guidance](docs/RELEASING.md) before selecting a release snapshot.
