# Astra task — design the decoy→Kill-Switch containment signal (review, then bounded spec)

**Context.** A fielded, endorsed request (James Losack; Tommaso called it an "easy
upgrade"): *"Would love to see those [decoy policies] plugged into the Agent Kill
Switch mechanism."* Today a decoy hit is scoped to **one request** — the policy
`deny()`s that call and emits a detection signal, but it cannot stop the *same
agent's next* call. The Agent Kill Switch is a separate MuleSoft platform policy
(`llm` asset type, on the Model Proxy) that, once armed and scoped to an agent's
`client_id`, hard-stops **all** future calls from that agent and is reversible. The
ask is to make a decoy hit **contain the offending agent**, not just block one
request: detect-divert-deceive **→ and contain**.

This is a **design/review task first**, and — if approved — a **bounded emission
spec**, not a runtime rewrite. The Kill Switch and the control-plane bridge that arms
it live **outside this repo** (in the `llm-gateway` demo). This repo's only job is the
**contract**: what durable, audited, identity-bearing signal the decoy side must
guarantee so an external control plane can safely act on it. **Do not change decoy
matching, modes, enums, or schemas** to accommodate this; if a capability gap is real,
spec it as proposed work with fail-closed rules — do not patch to pass.

Read first, in order:
1. `docs/CODEX-HANDOFF.md` — working-state / branch / authorization conventions, and
   the load-bearing rule **"Never use headers as trusted provenance or cross-policy
   control state."** That rule governs this entire design (see Boundaries).
2. `decoy-coordinator/src/lib.rs` — the current emission surface: the `detection(...)`
   (`agent_decoy_detection`, warn, booleans only) and `event`/`alert`
   (`agent_decoy_composition`) structured logs (#58), the PDK
   `violations.generate_policy_violation()`, and `deny(...)`.
3. `decoy-coordinator/src/adapter_tests.rs` — specifically
   `forged_headers_cannot_suppress_response_redaction`: the `x-agent-decoy-tripwire` /
   `x-agent-breadcrumb` headers are treated as **untrusted, forgeable client input**.
   They are response *annotations*, **not** a trust channel — the containment trigger
   must not depend on them.
4. `mcp-honeytoken-tripwire/docs/pdk-response-termination-gap.md` — the block-mode
   hard-termination boundary that still applies and must be stated, not papered over.
5. The companion demo-side spec (in the `llm-gateway` repo):
   `demo/mcp/DECOY-KILLSWITCH-INTEGRATION.md` — the bridge + Kill-Switch arming design
   this task feeds. Reconcile the two; where they disagree, this repo's honesty
   boundaries win.

## The design question to answer

*What is the minimum, audited, tamper-resistant signal the decoy policies must emit so
that an out-of-band control plane can identify the offending agent and arm the Agent
Kill Switch against it — without ever treating a header or in-gateway shared state as
trusted provenance?*

Concretely, assess and specify:

1. **Identity binding.** The containment signal must carry the **gateway-authenticated
   caller identity** — the `client_id` enforced by `client-id-enforcement`, which the
   Kill Switch also scopes to — **not** any client-supplied header. Determine whether
   `agent_decoy_detection` today can reference that authenticated identity within PDK
   constraints, and if not, spec the smallest addition that does, fail-closed (omit the
   field rather than emit an unauthenticated or guessed value). This is the crux —
   without a trusted identity the bridge cannot know *whom* to contain.
2. **Signal durability + trust path.** The trigger must be an **audited event**
   (PDK policy violation / structured detection log consumed via Anypoint Monitoring or
   Message Logging **export**), not the forgeable response header and not cross-policy
   in-gateway state. Confirm which of the existing emissions already qualify as
   exportable audited evidence (per `docs/CONNECTED-MONITORING-EVIDENCE.md`), and note
   the honesty gap that **PDK property/log evidence is not itself exported Anypoint
   Monitoring evidence**.
3. **Confidence tiering (advisory to the bridge).** A decoy touch is an *investigation
   signal*, not proof of malice. Specify what the event should expose so the bridge can
   apply a threshold policy — e.g. honeytoken hit = high-confidence (planted secret,
   near-zero false positive), breadcrumb/sentinel exploration = lower-confidence,
   count-in-window. The **decoy side classifies and reports; it does not decide to
   kill** — that decision (and the human-in-the-loop gate) belongs to the bridge.
4. **Boundary delegation.** State explicitly what stays out of this repo: the bridge,
   the API-Manager arm call, and the managed-gateway **UI Save & Apply** push
   limitation (full auto-containment needs a self-managed/connected gateway). Do not
   re-implement any of it here.

## Deliverable

A committed design doc — `decoy-coordinator/docs/KILLSWITCH-CONTAINMENT-SIGNAL.md` —
containing: the trusted-signal contract (identity field + audited event shape),
the confidence-tier fields, an explicit trust-boundary section citing the header /
cross-policy-state prohibition, the delegation boundary to the demo-side bridge, and a
**"proposed work — not implemented"** list for any emission change (with fail-closed
rules), mirroring the style of `docs/PREPRINT-CITATION-AND-FOLLOW-UPS.md`. If the
design requires an emission change, file it as a GitHub issue with the fail-closed
spec — **do not implement it in this task.**

## Boundaries (load-bearing)

- **Design/spec only.** No decoy runtime, enum, or schema changes in this task; no
  relaxing block semantics to bypass the platform limitation. File issues, don't patch.
- **Never a header or in-gateway shared state as trust channel.** The `x-agent-*`
  headers are forgeable annotations; cross-policy control state is prohibited
  (`CODEX-HANDOFF.md`). The only trusted identity is the gateway-authenticated
  `client_id`; the only trusted trigger is an audited exported violation/log event.
- **Honesty.** A decoy hit is an investigation signal, not proof of malice or of
  successful containment. Monitor-mode labels a hit `BLOCKED` even when the backend
  received it — not enforcement. Host-failure / response-termination containment
  remains unverified. PDK log evidence ≠ exported Anypoint Monitoring evidence.
- Preserve the immutable source tag `v0.1.0-rc.1`; no release, no production Exchange
  publication. Keep any verification within explicitly authorized disposable scope.

## Definition of done

`decoy-coordinator/docs/KILLSWITCH-CONTAINMENT-SIGNAL.md` committed on a fresh topic
branch, CI green, cross-referenced from the demo-side `DECOY-KILLSWITCH-INTEGRATION.md`;
any required emission change filed as an issue with a fail-closed spec (not implemented);
the trust-boundary and honesty sections present and specific.
