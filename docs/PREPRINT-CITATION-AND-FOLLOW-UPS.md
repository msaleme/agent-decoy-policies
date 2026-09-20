# Research citation, claim audit and proposed follow-ups

Checked on 2026-09-20 for the preprint *Deception Primitives at an MCP-Aware
Enforcement Point*, reported by its author as v0.13 at the time of this audit.
This audit covers the author's supplied claim list, not the full manuscript.

**Updated 2026-09-20: the paper is now deposited and has a DOI.** It was published
to Zenodo on 2026-09-20 under CC BY 4.0, as v1.0 and then v1.1 the same day. Concept
DOI [`10.5281/zenodo.22859851`](https://doi.org/10.5281/zenodo.22859851) resolves to
the newest version; the version DOIs are
[`10.5281/zenodo.22860118`](https://doi.org/10.5281/zenodo.22860118) (v1.1, current)
and [`10.5281/zenodo.22859852`](https://doi.org/10.5281/zenodo.22859852) (v1.0).
Cite a version DOI wherever a claim depends on exact wording, including the
corrections recorded below, because the concept DOI moves with each new version;
two versions appearing on the deposit date is the concrete reason. The corrections
in this document were checked against the v0.13 claim list and have not been
re-verified against the deposited text.

## Citation anchor and release decision

Keep **`v0.1.0-rc.1` / `f442cba95082b2fcb60c26c0613e327d420635a2`** as the
immutable reference implementation for evidence collected at that snapshot.
A release candidate is a valid reproducible research anchor when clearly labeled.
There is no scheduled or promised `v0.1.0` final; do not delay a citation on the
assumption that it is imminent, or describe this candidate as production certified.
The source tag is separate from policy package versions and Exchange publication.

Before a final source release, resolve the intended configuration vocabulary,
record migrations and supported protocol/batch scope, rerun the relevant checks,
and publish evidence tied to the exact selected commit. A new candidate should
precede final if those contracts change. Binary distribution has additional
licensing and artifact requirements in [the release process](RELEASING.md).
Do not move the existing tag or transplant later results into its evidence section.

## Corrections and qualifications for the paper

| Supplied claim | Checked result / required wording |
| --- | --- |
| Citation anchor `v0.1.0-rc.1` / `f442cba` | Correct. Use the full SHA above for reproducibility. |
| 100 library tests: 42 Honeytoken, 25 Sentinel, 14 Breadcrumb, 19 Coordinator | Correct for the anchor. |
| 22 Python tests | **Correct to 23.** The anchor's CI log reports 23; the README/current-status count was stale. No new test was added to cause this correction. |
| Library/Python/Clippy/WASM freshness and Docker upload-gate checks are CI-attested; Flex Local Mode suites are not | Correct. CI also compiles integration tests; compilation is not authenticated Flex execution. |
| Independent review covered `03a5bf8b`, not the tag | Qualify: the record identifies that SHA as its **base/HEAD while reviewing uncommitted remediation**, then records fix verification and re-review. It is not a comprehensive independent audit of the later tag or coordinator. Preserve “not production certification.” |
| Family admission is JSON only, declared Content-Length ≤64 KiB, no Content-Encoding | Scope JSON-only to Sentinel and Coordinator. Honeytoken additionally admits `text/plain` and legacy missing Content-Type; Breadcrumb additionally admits `text/plain`. These are eligibility rules, not an actual-byte memory guarantee. Bodyless paths and behavior outside admission also differ by policy/mode. |
| Coordinator requires one unambiguous JSON-RPC envelope and rejects batches | Correct for nonempty request inspection in every mode; bodyless traffic passes. |
| Response termination gap is a capability boundary, not a reproduced double-failure defect | Correct; retain the precise [PDK source audit](../mcp-honeytoken-tripwire/docs/pdk-response-termination-gap.md). |
| Monitor routes message content into logging infrastructure | Too broad for Honeytoken: its anomaly logs emit opaque configured decoy IDs and event metadata, not matched tokens or raw bodies. IDs must be nonsensitive. Inspection still buffers eligible bodies, may add latency/memory use, stamps headers and requires deployment review. |
| All design attribution was removed | The root README lacked a concise line, but `ATTRIBUTION.md` retained design references. The README now links them. “Decoy tool” is project terminology, not a CISA primitive. |

[CI for the anchor](https://github.com/msaleme/agent-decoy-policies/actions/runs/35515031903)
records both successful jobs and all test counts. The
[historical independent review](INDEPENDENT-REVIEW.md) describes its scope.
No mode names, matching behavior or admission rules change with these wording
corrections; the anchor's files remain immutable.

A **post-anchor** result is available: [PR #32](https://github.com/msaleme/agent-decoy-policies/pull/32),
merged as `a1cd92fcab85a35585d98e51213ff8ae4a15c7f7`, records actual Connected Mode
Sentinel export. Five clean calls per mode produced zero violations, and three
hits per mode produced three violations. Monitor hits reached the inert backend
although the exported disposition was `BLOCKED`. Cite this evidence separately
if included; it is a manually authorized Sandbox experiment, not public CI or
new evidence of low-level response-write containment.

## Mode vocabulary proposal — not implemented

Prefer `observe` as the canonical non-enforcing label across the family, with
`sanitize` retained where supported and `block` retaining its existing meaning.
Introduce `observe` for Honeytoken and Sentinel and the coordinator's corresponding
fields, while retaining `monitor` as a documented deprecated compatibility alias.
Do not rename Breadcrumb's existing `observe` or conflate response seeding with
observation: seeding remains separately configured and changes response bodies.

This additive transition need not break existing configurations. Removing `monitor`,
changing defaults, rejecting previously accepted values or changing event vocabulary
needs an explicit compatibility assessment and migration record. Select the
repository snapshot and individual policy asset versions independently. A final
release should have one documented canonical vocabulary even if an old alias remains.

Before implementation:

1. Add focused failing regressions for equivalent observe/monitor body, status,
   alert and violation behavior, plus missing/unknown mode handling. Invalid values
   must not silently disable enforcement.
2. Update schemas, validation and examples together; regenerate config structs
   through the existing tooling. Preserve block semantics and default behavior.
3. Keep event compatibility explicit; a config spelling change must not silently
   break SIEM rules. Document exactly which log fields change, if any.
4. Run affected full library suites, strict Clippy, release WASM/bundle freshness,
   and relevant authorized runtime checks. Record new test counts and exact commits.
5. Publish a new source candidate and migration notes before considering final.

## Other proposals — not implemented

These remain design gaps or capability choices, not undisclosed completed work.
They do not reopen the original reviewer's accepted findings.

1. **Static decoy overlap validation.** Begin with the coordinator, which owns the
   combined configuration. Reject breadcrumb text containing a configured
   honeytoken under the actual trimming/case-matching rules; assess reverse and
   tool-name overlaps as distinct cases. Check after normalization, return errors
   without token values, and test casing, Unicode, empty values and disabled seeding.
   Independently configured policies need a deployment-level preflight because
   they do not share configuration. Retain final output rescanning: a static
   overlap check cannot prove that every runtime transformation is safe.
2. **Field-aware matching.** This is the largest semantic improvement, but needs
   explicit per-direction selectors and method/context rules. Start with opt-in
   exact JSON paths or equivalent bounded selectors; specify missing/wrong-type
   fields, arrays, duplicate keys, numeric values, case handling and malformed
   input. Retain the documented presence-only mode during migration. Regressions
   must distinguish a quoted status report from a protected field carrying a token,
   without turning selector failure into an enforcing-mode bypass. This reduces
   false positives within configured scope; it still cannot prove malicious intent.
3. **Protocol-version enforcement.** Specify the supported deployment versions and
   initialization/missing-header behavior before implementation. Treat
   `MCP-Protocol-Version` as protocol input, never trusted provenance or permission
   to downgrade a deployment's minimum version. Test missing, duplicate, malformed,
   unsupported and conflicting versions, alongside single/batch bodies. The
   [2025-06-18 transport contract](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports)
   requires a single JSON-RPC POST body and defines version-header handling. Current
   legacy batch support is not negotiated-version enforcement.
4. **Configurable batch admission.** A useful bounded choice is to reject every
   batch or retain legacy JSON-RPC admission with atomic rejection on any detected
   decoy. Keep atomic rejection as the enforcing behavior for admitted batches.
   Do not add a “forward on hit” option or partial execution without a separately
   designed splitter, ID/notification handling and proof of zero forbidden upstream
   effects. A documented containment choice does not imply that every weaker
   alternative must be exposed. The coordinator's single-envelope restriction remains.

For any implementation, capture a focused failing regression first, then the
smallest change and affected full-suite verification. Tell the paper author the
new commit, schema/behavior delta, changed test counts and evidence class; changes
to main do not rewrite what the existing tag demonstrated. No paper DOI or author
endorsement should be invented before the citation is supplied.
