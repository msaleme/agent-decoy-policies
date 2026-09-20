# Codex handoff — accepted remediation

Read [current acceptance and verification status](REMAINING-ISSUES-PLAN.md) and
[the preprint claim audit and proposed follow-ups](PREPRINT-CITATION-AND-FOLLOW-UPS.md) first.
As of 2026-09-20, the original reviewer has closed #6 and #13; no GitHub issues
remain open. Older instructions to keep those issues open are superseded by those
acceptance decisions. A later [Connected Mode Sandbox run](CONNECTED-MONITORING-EVIDENCE.md)
verified Sentinel Monitoring export. Host-failure containment remains unverified.

## Working state

All implementation, evidence and documentation work through **PR #33** is committed,
pushed and merged. The verified checkpoint before this handoff-only update is
`3b785e7dffd6ae3c299613eb4abb95d44121446a` on `main`:

- [PR #32](https://github.com/msaleme/agent-decoy-policies/pull/32): actual Connected
  Mode Sentinel export counts and verified disposable-resource cleanup.
- [PR #33](https://github.com/msaleme/agent-decoy-policies/pull/33): monitor-mode cost
  and logging clarification, design provenance, corrected Python test count, and
  paper-facing citation/compatibility proposals. No runtime behavior or enum changed.
- [Successful main CI](https://github.com/msaleme/agent-decoy-policies/actions/runs/35518561698):
  policies and upload-gate jobs pass. There were zero open issues and PRs at handoff.

Fetch current `origin/main` and create a fresh topic branch. Do not resume an older
local branch merely because it is named `main`: the original main worktree remains
at `03a5bf8`. Historical topic commits were squash-merged; ancestry alone can make
completed work appear unmerged. Verify content and the associated merged PR before
cherry-picking anything.
The working checkout used for the review is
`/tmp/agent-decoy-policies-honeytoken-streaming`.
At handoff, this checkout was detached at the current remote main, with no tracked
changes. The other two registered worktrees also had no tracked changes. Preserve
the pre-existing untracked `.hermes/` directory; it is unrelated local state and
was intentionally not committed.

Do not assume `/home/mikes/projects/agent-decoy-policies` is the checkout: in this
session Git there resolved to an unrelated home-directory repository. Check
`git rev-parse --show-toplevel` before staging. If the temporary checkout is absent,
clone `https://github.com/msaleme/agent-decoy-policies` into a fresh directory.
All evidence needed for review is tracked; no `/tmp` script or credential is needed.

## Authorization and handling

The user authorized commits, pushes and merges after checks pass, and bounded
Local Mode Sandbox verification. Disposable identities from those runs have been
remotely deleted and locally removed. Do not assume an old fixture remains valid.
Never display identity contents or copy them between policy projects.
The user subsequently authorized a disposable Connected Mode Sandbox run and its
necessary test-only Exchange publication. That run is complete and its resources
are deleted; see the linked evidence. Keep any future provisioning within the
user's explicitly authorized disposable scope; do not infer shared-API or production
mutation authority from these completed runs.
No shared API or production deployment was changed.
Never use headers as trusted provenance or cross-policy control state.

## Verified implementation

The three standalone policies and opt-in coordinator include fail-closed JSON
admission, protocol/status contracts, safe mutation ordering, residual-token
rescanning, and Sentinel PDK violations in monitor/block modes. The coordinator
provides bounded composition; it is not an arbitrary ordering of independent filters.
The optional outer upload gate and memory profile have actual Docker and Local Mode
full-chain evidence. See the current status document for exact counts and limits.

## Citation and evidence boundaries

- Preserve the immutable source tag **`v0.1.0-rc.1`** at
  `f442cba95082b2fcb60c26c0613e327d420635a2`. No final release is scheduled; no
  compiled GitHub release assets or production Exchange versions were published.
- The anchor has **100 library tests** (42 Honeytoken, 25 Sentinel, 14 Breadcrumb,
  19 Coordinator) and **23 Python tests**, not 22. The claim audit links its CI log.
- Public CI runs library/Python/static/build checks and credential-free Docker
  upload-gate tests; authenticated Flex runtime observations are separate evidence.
- Connected Mode export is post-anchor evidence: each mode exported three Sentinel
  violations for three decoy calls and zero for five clean calls. Monitoring labels
  monitor hits `BLOCKED` even when the backend receives them; do not infer actual
  enforcement from that field.
- All Connected Mode test APIs, three test Exchange asset versions, containers and
  network were deleted. The gateway reported `DELETED` with zero connected replicas;
  the local registration identity was removed after remote deletion verification.
- The author has not supplied a minted paper DOI. Do not invent a citation or contact
  the paper author without user instructions. See `ATTRIBUTION.md` for source limits.

## Proposed work — not implemented

The paper feedback did not result in a mode rename or any of these new capabilities.
Use the [detailed acceptance plan](PREPRINT-CITATION-AND-FOLLOW-UPS.md) when the user
selects further implementation work:

1. Make `observe` canonical for Honeytoken/Sentinel and matching coordinator fields,
   initially retaining `monitor` as a deprecated alias. Assess defaults and event
   vocabulary separately; alias removal would be breaking.
2. Add static decoy-overlap checks, beginning with the combined coordinator config;
   keep runtime final rescanning and define preflight for independent policies.
3. Design opt-in field-aware matching with explicit selectors and fail-closed rules.
4. Specify protocol-version enforcement, missing/invalid-header handling and
   downgrade resistance; version-header negotiation is not implemented today.
5. Consider stricter reject-all-batches admission alongside legacy atomic rejection.
   Do not reintroduce block-mode forwarding on a hit or claim partial execution safe.

The host-write response-containment capability boundary and deployment-specific
validation remain. No real double-write failure disclosure has been reproduced.

## Further work

There are no outstanding accepted-review code findings. Optional deployment
verification must preserve these boundaries:

- PDK property/log evidence is not exported Anypoint Monitoring evidence.
- Uninspectable block-mode responses still buffer to be withheld.
- PDK body-write success is not a low-level host acknowledgement; the documented
  response termination limitation is not a reproduced runtime disclosure.
- Source tests, Local Mode wire tests, and production guarantees are distinct.

For a newly demonstrated source defect, first run a focused failing regression,
make the smallest fix, then run the affected library suite, strict Clippy, release
WASM and hygiene checks. Regenerate assets after relevant source/schema changes:
`python3 scripts/flex_runtime_gate.py --prepare --assets-only`.
Do not relax block semantics to bypass a platform limitation.
