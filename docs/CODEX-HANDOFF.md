# Codex handoff — accepted remediation

Read [current acceptance and verification status](REMAINING-ISSUES-PLAN.md) first.
As of 2026-09-20, the original reviewer has closed #6 and #13; no GitHub issues
remain open. Older instructions to keep those issues open are superseded by those
acceptance decisions. A later [Connected Mode Sandbox run](CONNECTED-MONITORING-EVIDENCE.md)
verified Sentinel Monitoring export. Host-failure containment remains unverified.

## Working state

The remediation and follow-ups through PR #27 are merged. Use current `origin/main`
and a fresh topic branch for additional changes; do not resume the old
`fix/honeytoken-streaming-contract` base at `03a5bf8`.
The working checkout used for the review is
`/tmp/agent-decoy-policies-honeytoken-streaming`.
Preserve the pre-existing untracked `.hermes/` directory.

## Authorization and handling

The user authorized commits, pushes and merges after checks pass, and bounded
Local Mode Sandbox verification. Disposable identities from those runs have been
remotely deleted and locally removed. Do not assume an old fixture remains valid.
Never display identity contents or copy them between policy projects.
The user subsequently authorized a disposable Connected Mode Sandbox run and its
necessary test-only Exchange publication. That run is complete and its resources
are deleted; see the linked evidence. Future provisioning needs its own scope.
No shared API or production deployment was changed.
Never use headers as trusted provenance or cross-policy control state.

## Verified implementation

The three standalone policies and opt-in coordinator include fail-closed JSON
admission, protocol/status contracts, safe mutation ordering, residual-token
rescanning, and Sentinel PDK violations in monitor/block modes. The coordinator
provides bounded composition; it is not an arbitrary ordering of independent filters.
The optional outer upload gate and memory profile have actual Docker and Local Mode
full-chain evidence. See the current status document for exact counts and limits.

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
