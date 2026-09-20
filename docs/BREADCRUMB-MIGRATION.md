# Breadcrumb configuration migration

The remediated configuration is incompatible with the original schema. Reserve
**2.0.0** for the next Breadcrumb release; this is a release decision, not a
published release. The current scaffold/package version remains 1.0.0. Before
publication, update the package, lockfile, generated asset metadata and runtime
fixture references together, then rerun CI and the authorized runtime suites.
Do not publish the changed schema over an existing 1.0.0 asset.

## Translate existing configurations explicitly

| Original setting | Replacement | Behavior |
| --- | --- | --- |
| `mode: monitor` | `mode: sanitize` | Detect and remove the marker before forwarding |
| `mode: block` | `mode: block` | Reject a detected follow |
| `seedToolDescriptions: true` | `seeding: enabled` | Opt into modifying eligible tools/list descriptions |
| `seedToolDescriptions: false` | `seeding: disabled` | Leave response descriptions unchanged |

Remove `seedToolDescriptions` after conversion. The new defaults are
`mode: observe` and `seeding: disabled`. Do not simply omit old settings: the
original defaults sanitized requests and enabled response seeding. `observe`
detects without removing the marker; choosing it changes enforcement behavior.

For example, an original monitor configuration with seeding enabled becomes:

```yaml
breadcrumb: admin_override_do_not_use
mode: sanitize
seeding: enabled
alertHeader: x-agent-breadcrumb
```

Keep the existing marker unless deliberately rotating it. Matching is against the
entire configured marker, not a resource name embedded in a longer sentence.
An empty marker disables detection/seeding. Alert headers are telemetry and must
not be treated as authenticated provenance or a trusted block decision.

## Validate before rollout

Exercise a clean request, a marker follow, and a correlated tools/list response
against an inert backend. Assert upstream bytes as well as client status.
Sanitize/block reject unsupported enforcing request bodies; seeding does not
promise transformation of streams, batches, notifications, or unmatched IDs.
Review the current [policy contract](../breadcrumb-misdirection/README.md) and
[composition boundary](../COMPOSITION.md) before chaining filters. Save the prior
configuration and matching implementation for rollback; rolling back the schema
alone is insufficient. Publication and deployment require a designated target.
