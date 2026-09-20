# Versioning and releases

## Recommended first release

Use an **annotated repository tag `v0.1.0-rc.1`** for the first explicitly approved
source snapshot, with a GitHub prerelease describing its tested scope. The family
is still bounded by documented runtime limitations. This recommendation does not
create a tag, publish binaries, submit to P4A, or deploy to Exchange.

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
