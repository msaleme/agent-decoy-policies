# Versioning and releases

## Adopted tag convention

The first repository-wide source snapshot uses the **annotated tag
`v0.1.0-rc.1`**, accompanied by a GitHub prerelease describing its tested scope.
The family remains bounded by documented runtime and attribution limitations.
Later family snapshots use `v<major>.<minor>.<patch>`, with prerelease suffixes
while release-candidate validation is in progress. Tagging a source snapshot does
not publish compiled assets, submit to P4A, or deploy to Exchange.

Repository snapshot versions are separate from the versions in each policy's
Cargo manifest. The snapshot includes all four projects:

| Policy | Current Cargo version |
| --- | --- |
| Honeytoken Tripwire | 1.0.0 |
| Decoy Tool Sentinel | 1.0.0 |
| Breadcrumb Misdirection | 1.0.0 |
| Decoy Coordinator | 0.1.0 |

These existing manifest numbers are not evidence that those versions have been
published. Do not rewrite them merely to match the repository tag. Before an
Exchange publication, verify the actual asset version history and select policy
versions consistent with compatibility changes. In particular, the earlier
Breadcrumb mode migration and stricter admission rules require explicit release
notes and may require a major policy version change for existing consumers.

If policy releases later have independent schedules, adopt explicit tags such as
`decoy-coordinator/v0.2.0`. Do not use ambiguous unprefixed tags to represent only
one policy in this repository.

For policy releases, use semantic versioning: patch for compatible corrections,
minor for compatible capabilities, and major for incompatible configuration or
behavior changes. Admission changes that reject previously supported traffic need
an explicit compatibility assessment. Keep policy tags aligned with the selected
policy's Cargo version. Immutable annotated tags are the default; use signed tags
when a maintainer signing setup is available.

## Preparing a source snapshot

1. Select a merged commit whose complete CI checks passed. Record its full SHA,
   policy versions, Rust/PDK versions, and CI URL in the release notes.
2. Update [CHANGELOG.md](../CHANGELOG.md) with the actual release date and tag.
   Include configuration/protocol changes, migration links, verified behaviors,
   and the [remaining platform limitations](REMAINING-ISSUES-PLAN.md).
3. Review the source archive and [attribution record](../ATTRIBUTION.md), preserving
   upstream notices. Exclude registrations, credentials, local logs, build caches,
   and unrelated untracked files.
4. For the separately authorized release, create an annotated tag pointing to that
   exact commit. Never move a published tag; publish a new version for corrections.
5. Start with a source-only GitHub prerelease. Compiled bundles require a complete
   resolved dependency/license inventory, all required third-party notices, artifact
   checksums, and verification of the exact distributable artifacts. The direct
   dependency table alone is insufficient for this step.

GitHub releases, P4A submissions, and Anypoint Exchange publications are distinct
operations. A successful source build or GitHub tag does not establish marketplace
acceptance, platform publication, Monitoring export, or production validation.

## Community practice

The [2026-09-20 comparison](P4A-REPOSITORY-REVIEW.md) found no tags or GitHub releases
in the eight sampled P4A repositories. Their Cargo/asset versions still vary.
Tags are useful here for reproducibility and rollback references, not because the
sample establishes a community requirement to use them.
