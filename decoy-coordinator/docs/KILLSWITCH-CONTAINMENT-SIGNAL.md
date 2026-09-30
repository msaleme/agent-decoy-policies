# Decoy Containment Signal Contract — Agent Kill Switch Integration

**Baseline Version:** `v0.1.0-rc.1`
**Target Version:** `v0.2.0-rc.1` (Functional Update: Containment Signal)
**Status:** Design Specification

This document specifies the trusted signal contract between the **Agent Decoy Policies** and an external **Control Plane (the Bridge)**. The goal is to transition from per-request blocking to agent-level containment by arming the Agent Kill Switch upon detection of decoy interaction.

## 1. Trusted Signal Contract

To safely identify an offending agent for containment, the decoy side must emit a durable, audited event containing a trusted identity.

### 1.1 Signal Identity Binding
The containment trigger must key off the **gateway-authenticated caller identity** — the `client_id` enforced by `client-id-enforcement`. 

**Trusted Provenance Rules:**
- **NO client-supplied headers:** The signal must NOT rely on `x-agent-*` or any other header provided by the caller. These are forgeable annotations and are strictly forbidden as trust channels for containment (`CODEX-HANDOFF.md`).
- **NO cross-policy state:** The signal must NOT rely on shared in-gateway state.

### 1.2 Event Shape
The signal is emitted as a structured PDK log event or policy violation.

**Proposed Event Schema:**
```json
{
  "event": "agent_decoy_detection",
  "authenticated_client_id": "string (Trusted ID from client-id-enforcement)",
  "confidence_tier": "HIGH | MEDIUM | LOW",
  "detection_class": "honeytoken | sentinel | breadcrumb",
  "stage": "request | response",
  "timestamp": "ISO-8601"
}
```

### 1.3 Signal Durability & Trust Path
The trigger must be an **audited, exported event**.
- **Path:** PDK violation $\rightarrow$ Structured Log $\rightarrow$ Anypoint Monitoring/Message Logging export.
- **Honesty Gap:** PDK property/log evidence is a local signal; it is not itself exported Anypoint Monitoring evidence until processed by the platform's export pipeline.

## 2. Confidence Tiering

A decoy hit is an investigation signal, not absolute proof of malice. The decoy side **classifies** the hit; the bridge **decides** on containment based on a threshold policy.

| Tier | Detection Class | Confidence | Rationale |
|---|---|---|---|
| **HIGH** | Honeytoken | Absolute | Interaction with a planted secret (near-zero false positive). |
| **MEDIUM** | Sentinel | Strong | Access to a forbidden tool or system path. |
| **LOW** | Breadcrumb | Advisory | Interaction with a lure (may be accidental exploration). |

The bridge may implement logic such as:
- `IF confidence == HIGH $\rightarrow$ ARM KILL SWITCH immediately`
- `IF confidence == LOW AND count > N in window $\rightarrow$ FLAG FOR REVIEW`

## 3. Trust Boundaries & Delegation

### 3.1 Internal Boundaries (This Repo)
The decoy policies are responsible only for:
1. Detecting the interaction.
2. Classifying the confidence tier.
3. Emitting the trusted `authenticated_client_id` in an audited event.

### 3.2 External Delegation (The Bridge)
The following operations are **out of scope** for this repo and are delegated to the external Control Plane (the Bridge):
- **Decision Logic:** Determining whether a signal justifies containment.
- **Containment Execution:** Making the API-Manager call to arm the Agent Kill Switch.
- **State Management:** Tracking hit counts across requests for a specific `client_id`.
- **Administrative Push:** Handling the managed-gateway `UI Save & Apply` limitation (requiring a self-managed/connected gateway for automation).
- **Human-in-the-loop:** Providing the gate for a human operator to review or reverse a kill action.

## 4. Proposed Work — Not Implemented

The current emission surface in `decoy-coordinator/src/lib.rs` lacks the trusted identity binding.

**Required Change:**
- Update `request_filter` and `response_filter` to extract the authenticated `client_id` from the PDK request context and include it in the `agent_decoy_detection` event.

**Fail-Closed Rule:**
If the authenticated identity cannot be retrieved from a trusted PDK context, the `authenticated_client_id` field must be omitted from the event. The bridge must treat events without a trusted identity as **non-actionable** for containment.

---
**Source Tag:** `v0.1.0-rc.1`
