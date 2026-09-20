# Current acceptance and verification status

Checked on **2026-09-20** against `main` at
`4bb7b45bf0774ba572b151fc3305992ca73791c1`. GitHub has **zero open issues and
zero open pull requests** at this checkpoint. This document supersedes the
issue-state and next-step instructions in the older remediation logs.

## Reviewer acceptance

| Issue | Accepted result | Closure evidence |
| --- | --- | --- |
| #6 | Sentinel calls `generate_policy_violation()` for hits in both monitor and block modes, before the block branch | [Original reviewer's code verification and closure](https://github.com/msaleme/agent-decoy-policies/issues/6#issuecomment-5749661111), 2026-09-20 12:00 UTC |
| #13 | Headers-phase admission and bounded buffering remediation accepted | [Original reviewer's closure](https://github.com/msaleme/agent-decoy-policies/issues/13#issuecomment-5749860250), 2026-09-20 12:40 UTC |
| #23 | Opt-in single coordinator implements original-body detection, action ordering and final rescanning for its documented bounded JSON-RPC scope | [Merged PR #25](https://github.com/msaleme/agent-decoy-policies/pull/25) |

The issue closures accept their original implementation scope. They do not provide
new runtime evidence or remove the platform limitations below. In particular, the
#13 closure summary must not be read as saying *all* unsupported responses bypass
buffering: in **block mode**, Honeytoken still enters the buffered response state
to withhold an uninspectable body. Monitor mode skips that inspection. Requests
that fail headers admission are rejected before body inspection/upstream execution.

## Verification on merged main

[Successful main CI run](https://github.com/msaleme/agent-decoy-policies/actions/runs/35485920509):

- **100 library tests:** Honeytoken 42, Sentinel 25, Breadcrumb 14, Coordinator 19.
- **22 Python tests**, all four formatting/strict all-target Clippy checks,
  integration-test compilation, and four release WASM/bundle checks.
- Actual credential-free Docker upload-gate tests: active upload deadline,
  framing/buffer-saturation rejection, zero unexpected backend connections,
  sixteen concurrent slow uploads, a 64 KiB clean exchange, verified 128 MiB
  cgroup cap, kernel OOM event and explicit restart/recovery.

The previous authorized Local Mode runs also verified the complete
edge → Flex 1.14.0 → synthetic-backend chain: Honeytoken denial, sixteen concurrent
64 KiB clean exchanges, a live 1 GiB Flex cgroup cap, kernel OOM event and explicit
restart/recovery. See [the reproduction and evidence boundary](../deployment/upload-gate/README.md).
These full-chain tests are local evidence; public CI does not receive a Flex identity.
Run different PDK policy runtime suites serially on one Docker daemon because
PDK cleanup selects shared labels.

## Remaining limitations and optional follow-up

1. **Monitoring export:** Sentinel's PDK violation implementation is accepted;
   exported Anypoint Monitoring counts have not been observed. A dedicated
   Connected Mode target and any test-only publication remain separately authorized
   deployment work. They are not a remaining condition for the reviewer's #6 closure.
2. **Response containment under host failure:** successful redaction/withholding
   cases are tested, but the PDK does not acknowledge low-level body writes through
   `set_body`'s result. No real Flex double-error disclosure has been reproduced.
   See the [precise source audit and capability boundary](../mcp-honeytoken-tripwire/docs/pdk-response-termination-gap.md).
3. **Deployment scope:** the optional outer gate restricts requests to bounded
   POST bodies. Production ingress isolation, workload sizing, TLS and transport
   compatibility require deployment-specific validation. Explicit restart tests
   do not establish automatic recovery or uninterrupted availability.

No new policy publication or Connected Mode deployment is needed to record the
accepted issue status. Do not reopen closed issues solely because older handoff
instructions said to keep them open, or describe these bounded tests as universal
production certification.

## Lifecycle and repository hygiene

All disposable registrations created for the review rounds were deleted remotely
before the final local cleanup. For the three older identities whose local files
had already been removed, exact names/IDs/environment were recovered from creation
audit records and supported deletion by ID succeeded. Later identities were deleted
using `flexctl registration delete --file` before local removal. Nonsecret lifecycle
records remain outside tracked source; no registration material belongs in Git.

The audit found no tracked working-tree changes before this documentation correction.
The pre-existing untracked `.hermes/` directory is preserved and excluded from commits.
