# Local Flex runtime gate

This runbook reproduces the bounded Flex verification. Results and limits are recorded in
[REMEDIATION-EVIDENCE.md](REMEDIATION-EVIDENCE.md).
No Exchange publication, authentication, credential creation, or external calls are part of
local bundle preparation.

## Prepare and check local test assets

From the worktree root, using installed Rust 1.89.0, cargo-anypoint, and PyYAML:

```bash
python3 scripts/test_flex_runtime_gate.py
python3 scripts/test_build_contract.py
python3 scripts/flex_runtime_gate.py --prepare
```

Preparation builds release WASM offline, creates local-mode definition resources from the
current schema (adding only the name/namespace required by the fixture), and uses the installed
`cargo anypoint gcl-gen` to embed the exact release WASM. It writes SHA-256 fingerprints of
source, schema, fixture, binary and generated resources to each ignored release directory's
`runtime-bundle.json`. These are local test bundles, not Exchange publication assets. Official
Exchange metadata generation remains a separate authenticated workflow.

The build-contract test also invokes the actual Makefile environment and installed generator
with an inert WASM header in a temporary directory. It checks generated extension names and
`show-policy-ref-name` against each fixture, without registration, Docker, or Exchange publication.
It does not exercise authenticated asset publication or Windows builds.

To check existing bundles without rebuilding:

```bash
python3 scripts/flex_runtime_gate.py
```

The gate verifies definition/schema correspondence, extension names/references, exact embedded
WASM bytes, and source/build fingerprint freshness. It checks registration **existence only**;
it never opens, parses, copies, or prints registration files. It does not invoke Docker.
Exit status `2` means a prerequisite is missing/stale, `1` means preparation failed, and `0`
means these static prerequisites pass. Zero is not proof of valid registration or runtime behavior.

## Operator prerequisite

A valid local disposable registration must be provisioned by the operator directly in the
selected policy's `tests/config/registration.yaml`, with restrictive permissions and outside
source control. Do not paste it into chat, send it for review, or copy a shared identity between
projects. Follow [the runtime boundary](flex-runtime-verification-boundary.md).

The original handoff prohibited credential creation. The user subsequently authorized the
bounded Sandbox registrations and Flex runs. Each policy now has a separate ignored local
identity; never display it or copy it between projects. Future provisioning requires explicit
authorization. The bounded local Docker verification mounts the fixture for Flex to read. Container images/dependencies must already be available locally,
or their download must be separately authorized. Preparation does not check Docker or
image availability, so those remain runtime preflight checks.

## Bounded runtime run, after prerequisites

Run serially, from each policy directory with its own operator-managed fixture:

```bash
cargo +1.89.0 test --test requests --locked --offline -- --test-threads=1
```

Do not use `make test`: it invokes the broader authenticated asset workflow. The command above
uses the local test bundles prepared by the gate. Rust's `--offline` does not prevent Docker
from attempting image downloads; image availability must be checked first.

Required evidence:

- Honeytoken: request denial, response containment, and clean traffic control, from the freshly
  generated assets. An earlier pass from a different source or schema does not count.
- Sentinel: clean upstream call, decoy/batch errors, notification-only behavior, ambiguous-input
  refusal, and exact upstream counts. The current HTTP fixture does not independently observe
  the gateway analytics export of the PDK violation property; that remains a separate gate.
- Breadcrumb: observe preserves request bytes, sanitize changes them as intended, block makes
  zero upstream calls, and matching discovery responses are seeded with valid framing.

A failure before request assertions is an environment/harness blocker, not a policy pass.
Do not retain or display identity-bearing diagnostics. Runtime logs must be reviewed for
credential exposure by the operator before any evidence is shared. The operator owns fixture
cleanup after the bounded run.

## Unresolved independently of registration

PDK response-stage double-write termination, pre-buffer actual-byte limits, SSE seeding, and
cross-policy composition are still not proven by these fixtures. See
[the issue/evidence checklist](REMEDIATION-EVIDENCE.md).

## Current coordinator and lifecycle procedure

The [remaining-issues plan](REMAINING-ISSUES-PLAN.md) records the newer coordinator
and raw-socket verification. The asset gate now covers four policies. Use
`--prepare --assets-only` for builds without registrations.

Run policy runtime suites **serially** on a shared Docker daemon. PDK 1.10 cleanup
selects shared test labels and can interfere with another process's containers.

After authorized runtime tests, use the supported `flexctl registration delete`
operation with `--file` pointing to that policy's disposable registration and the
operator's authorized authentication. Capture its success before removing the
local identity. Preserve only nonsecret name/ID/deletion evidence. For Local Mode,
a name alone is insufficient for subsequent deletion. Older missing-ID cleanup
is explicitly tracked in the remaining-issues plan.
