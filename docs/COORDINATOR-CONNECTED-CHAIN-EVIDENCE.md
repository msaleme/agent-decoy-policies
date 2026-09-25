# Coordinator Connected Mode chain attempt — blocked before traffic

On **2026-09-24**, a disposable Sandbox gateway was provisioned and the recommended
six-policy chain was configured, but the required UI **Save & Apply** gate could
not be completed. **None of the seven matrix cases ran. This is not a passing
Connected Mode result and does not close the live-verification gap in #42.**

Chrome initially allowed an isolated sign-in session. On reopening that session,
it reported `DevTools remote debugging is disallowed by the system admin.` The
administrator policy was not changed. An alternative API deployment operation
was prepared but not substituted for the explicitly required UI action without
approval. The initial API deployment was accepted; repeated scoped reads showed
`active` with the same deployment timestamp. An Active → Updating → Active cycle
following UI Save & Apply was not observed.

## Artifact identity and isolation

- Tested source checkout: `b117fec54a6d534a43011f2d742c6527f15979b7`, fetched from
  `origin/main` into a fresh topic branch.
- Immutable citation tag `v0.1.0-rc.1` remains at
  `f442cba95082b2fcb60c26c0613e327d420635a2`. The current checkout is a separate,
  post-anchor source identity.
- Coordinator library suite: **34 passed, 0 failed** using Rust 1.89.0 and
  PDK 1.10.0. The locked, offline `wasm32-wasip1` release build succeeded.
- WASM SHA-256:
  `59c813f6083b968bab41872b560a5e387dd2f11eeaad4bad4e65974e6d9895de`.
  This is the disposable build; it is not a release binary.
- Definition and implementation publication used dedicated development asset IDs
  and test-only package versions. Packaging metadata set the minimum runtime to
  1.14.0. The source policy and its configuration schema were unchanged.
- Flex Gateway **1.14.0** and an inert Python JSON-RPC backend used one dedicated
  Docker network. The gateway listener was bound to **127.0.0.1:18084**. Docker
  inspection verified a **1 GiB** gateway cap and **128 MiB** backend cap, with
  equal memory and memory-plus-swap limits. The backend had no published port.
- A fresh registration, MCP Exchange asset, API instance, client application and
  client contract were created solely for this attempt. No shared API, gateway,
  or production resource was modified. Identity material stayed outside Git.

## Configured chain and deployment evidence

API instance **21196583** was configured in this request order; response order is
reversed. The API Manager inventory confirmed each definition, implementation,
configuration and order. This is configuration evidence, not a traffic pass.

| Order | Policy | Definition version | Flex implementation version | Applied policy ID |
| --- | --- | --- | --- | --- |
| 1 | MCP Support | 1.1.1 | 1.1.1 | 9336148 |
| 2 | MCP Schema Validation | 1.3.0 | 1.3.0 | 9336149 |
| 3 | Client ID Enforcement | 1.3.3 | 1.2.0 | 9336150 |
| 4 | MCP Global Access Control | 1.0.1 | 1.0.2 | 9336151 |
| 5 | MCP Attribute-Based Access Control | 1.0.2 | 1.0.6 | 9336152 |
| 6 | Disposable Decoy Coordinator | 0.0.1-20260924233809 | 0.0.1-20260924233809 | 9336153 |

Schema Validation had `validateToolSchema: true` and descriptor-drift detection
set to `LogOnly`. Global Access explicitly allowed the three inert fixture tools;
ABAC used `ClientId` authentication and a permit rule behind Client ID Enforcement.
The disposable client contract was approved. Coordinator used monitor/observe
modes with `seeding: disabled`, synthetic honeytoken `synthetic_honeytoken_42`,
decoy `inert_decoy`, and asset-planted breadcrumb `coordinator_lure_42`.

Initial deployment **28449331** was accepted with HTTP 201 and
`deployment.updatedDate = 2026-09-24T23:44:28.832Z`. Subsequent reads showed
`active`. The required later UI push was not completed, so no matrix traffic was
sent and no enforcement assertion was inferred from the `active` status.

The Metrics API summary query returned HTTP 200, no rows, and no next page for the
pre-traffic window recorded in JSON. This is only an empty baseline; without test
traffic it does not prove that Monitoring export works for this chain.

## Seven-case result

| Case | Required assertion | Result |
| --- | --- | --- |
| 1 | Clean `tools/list`: 200 unchanged; Schema Validation clean | Not run |
| 2 | Monitor decoy call forwards; only Sentinel raises a violation | Not run |
| 3 | Sentinel block: JSON-RPC `-32008`; zero backend calls | Not run |
| 4 | Honeytoken response redacted on the reverse path | Not run |
| 5 | Seeding with `RemoveTool` exposes descriptor drift | Not run |
| 6 | Enforcing `text/event-stream`: 415; zero backend calls | Not run |
| 7 | Mapped decoy name blocks with JSON-RPC `-32008` | Not run |

The [machine-readable record](evidence/coordinator-connected-chain-2026-09-24.json)
uses `not_run` and null traffic/violation fields. Null is not a measured zero.

## Observations requiring follow-up, not confirmed defects

Gateway startup logs warned that Schema Validation had no bound Exchange asset,
despite the API instance referencing the disposable MCP asset. The warning said
that tool-schema validation would fall back to JSON-RPC-only validation and that
poisoning detection would fail closed on `tools/list`. This was observed before
the required UI push and was not reproduced with traffic. It is insufficient to
file a confirmed runtime interoperability defect.

Two runbook assumptions also need care during a resumed test:

- Current [Schema Validation documentation](https://docs.mulesoft.com/gateway/latest/policies-included-mcp-schema-validation)
  and the published 1.3.0 definition say `validateToolSchema: true` serves
  `tools/list` from the trusted asset and makes poisoning detection inactive.
- [Tool Mapping documentation](https://docs.mulesoft.com/gateway/latest/policies-included-mcp-tool-mapping)
  describes reverse mapping of incoming calls from the client-visible name to
  the backend name. The Coordinator-visible name must be established at its
  actual position in the deployed chain.

These are source/documentation observations, not results from cases 5 or 7.
Runtime behavior, enums and schemas were not changed to resolve them.

## Cleanup and reproduction boundary

Cleanup completed after evidence capture:

- The client contract was revoked, then deleted. The contract, API instance and
  client application all returned 404 on subsequent scoped GETs.
- The three test Exchange versions were hard-deleted; all scoped GETs returned 404.
- `flexctl registration delete --file` succeeded. Gateway inventory reported
  `DELETED` with zero connected replicas. The local registration directory was
  removed only after that remote verification.
- Both Docker containers and the dedicated network were removed and verified absent.

The JSON retains cleanup attempts as well as successful final checks. An initial
active-contract deletion was refused until the contract was revoked; an initial
Exchange v2 delete was rejected before the supported v1 hard-delete endpoint was
used. These were cleanup API requirements, not policy interoperability findings.

A resumed run requires fresh disposable resources and
either an operator completing UI Save & Apply or an explicitly approved deviation
using the deployment operation. Do not reuse deleted resource IDs or credentials.

The [managed-chain runbook](../decoy-coordinator/docs/MANAGED-CHAIN-VERIFICATION.md)
remains the test contract. Local library tests remain the automated authority.
Monitoring's `BLOCKED` disposition alone is not proof of upstream enforcement;
client observations and backend counts are required. Host-failure and
response-termination containment remain unverified. Headers were not treated as
trusted provenance. No final release or production Exchange version was published.
