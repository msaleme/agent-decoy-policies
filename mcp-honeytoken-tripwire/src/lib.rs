// Copyright 2026 Salesforce, Inc. All rights reserved.
//
// MCP Honeytoken Tripwire — a decoy tripwire for agent traffic.
//
// A honeytoken is a value with NO legitimate use: a fake credential, a synthetic
// record ID, a decoy email or URL. You plant it in the data an agent can reach.
// Because nothing real ever references it, a single appearance of that value in a
// request or response is a high-fidelity, near-zero-noise signal that an agent has
// been compromised or is exfiltrating the decoy.
//
// This filter watches both directions of every exchange for the configured
// honeytokens. On a hit it emits a structured anomaly to the gateway log
// (CISA "Expose") and, in `block` mode, refuses the request and strips the token
// from the response so the decoy never actually leaves (CISA "Affect").
//
// NIST SP 800-53 Rev 5: SC-26 (Decoys), SI-20 (Tainting), SI-4 (Monitoring).
// NIST SP 800-160 Vol 2 Rev 1: Deception (Disinformation), Analytic Monitoring.
mod generated;

use anyhow::{anyhow, Result};

use pdk::hl::*;
use pdk::logger;
use serde_json::json;

use crate::generated::config::Config;

/// Marker substituted for a honeytoken when it is stripped out of a response in
/// block mode, so the decoy value never leaves the gateway.
const REDACTION_MARKER: &str = "[decoy-withheld]";

/// Compiled tripwire, built once at configuration time so the per-request path
/// does no allocation beyond scanning the body it is handed.
struct Tripwire {
    /// The decoy values to watch for, in their original form (used for logging a
    /// fingerprint) alongside the search form (lowercased when case-insensitive).
    needles: Vec<Needle>,
    /// True when the policy should reject requests / strip responses on a hit.
    block: bool,
    /// Header stamped on the exchange when the wire trips.
    alert_header: String,
}

/// One honeytoken, precomputed for matching.
struct Needle {
    /// Original configured value — only ever surfaced as a truncated fingerprint.
    original: String,
    /// Search form: ASCII-lowercased when matching is case-insensitive, otherwise
    /// identical to `original`. Empty needles are dropped at build time.
    search: String,
    /// Whether `search` was lowercased (so the haystack must be folded to match).
    fold: bool,
}

impl Tripwire {
    fn from_config(config: &Config) -> Self {
        let case_sensitive = config.case_sensitive;
        let needles = config
            .honeytokens
            .iter()
            .map(|t| t.trim())
            .filter(|t| !t.is_empty())
            .map(|t| Needle {
                original: t.to_string(),
                search: if case_sensitive {
                    t.to_string()
                } else {
                    t.to_ascii_lowercase()
                },
                fold: !case_sensitive,
            })
            .collect();

        Self {
            needles,
            block: config.mode.eq_ignore_ascii_case("block"),
            alert_header: config.alert_header.clone(),
        }
    }

    /// Returns the first honeytoken present in `haystack`, if any. ASCII case
    /// folding keeps byte length stable, which the response redactor relies on.
    fn detect<'a>(&'a self, haystack: &str) -> Option<&'a Needle> {
        // Fold the haystack once only if at least one needle needs folding.
        let folded = if self.needles.iter().any(|n| n.fold) {
            Some(haystack.to_ascii_lowercase())
        } else {
            None
        };
        self.needles.iter().find(|n| {
            let hay = if n.fold {
                folded.as_deref().unwrap_or(haystack)
            } else {
                haystack
            };
            hay.contains(&n.search)
        })
    }

    /// Replaces every honeytoken occurrence in `input` with [`REDACTION_MARKER`].
    /// Matching mirrors [`detect`]: ASCII case-insensitive when configured, which
    /// is byte-length-stable so the folded index maps straight back onto `input`.
    fn redact(&self, input: &str) -> Option<String> {
        let mut out = input.to_string();
        let mut changed = false;
        for n in &self.needles {
            if n.fold {
                out = replace_ascii_ci(&out, &n.search, REDACTION_MARKER, &mut changed);
            } else if out.contains(&n.search) {
                out = out.replace(&n.search, REDACTION_MARKER);
                changed = true;
            }
        }
        changed.then_some(out)
    }
}

/// ASCII case-insensitive replace. `needle` must already be ASCII-lowercased.
/// Operates on the lowercased copy to find matches, then splices the marker into
/// the original bytes at the same offsets (safe because ASCII lowercasing never
/// changes byte length).
fn replace_ascii_ci(input: &str, needle: &str, marker: &str, changed: &mut bool) -> String {
    if needle.is_empty() {
        return input.to_string();
    }
    let hay = input.as_bytes();
    let low = input.to_ascii_lowercase();
    let low = low.as_bytes();
    let nee = needle.as_bytes();

    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    while i < hay.len() {
        if i + nee.len() <= low.len() && &low[i..i + nee.len()] == nee {
            out.push_str(marker);
            i += nee.len();
            *changed = true;
        } else {
            // Copy the original byte through. `input` is valid UTF-8 and we only
            // ever split on ASCII-aligned needle boundaries, so pushing the
            // original char at this index preserves multi-byte sequences.
            let ch = input[i..].chars().next().unwrap_or('\u{FFFD}');
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

/// A short, non-reversible fingerprint of a honeytoken for logs, so the log line
/// itself does not become a copy of the decoy value.
fn fingerprint(token: &str) -> String {
    let head: String = token.chars().take(3).collect();
    format!("{head}…(len={})", token.chars().count())
}

/// Emits the structured anomaly to the gateway log. This is the "Expose" beat —
/// Message Logging / SSE Logging and any SIEM forwarder pick it up.
fn emit_anomaly(direction: &str, needle: &Needle, action: &str) {
    let event = json!({
        "event": "agent_decoy_tripwire",
        "control": "NIST SC-26/SI-20",
        "direction": direction,
        "token": fingerprint(&needle.original),
        "action": action,
    });
    logger::warn!("{event}");
}

/// Request path: scan the outbound body an agent is sending. A honeytoken here
/// means the agent is trying to *use* the decoy — the strongest compromise tell.
async fn request_filter(request_state: RequestState, tripwire: &Tripwire) -> Flow<()> {
    if tripwire.needles.is_empty() {
        return Flow::Continue(());
    }

    let state = request_state
        .into_headers_state()
        .await
        .into_headers_body_state()
        .await;
    let handler = state.handler();

    let body = handler.body();
    if body.is_empty() {
        return Flow::Continue(());
    }
    let text = String::from_utf8_lossy(&body);

    let hit = match tripwire.detect(&text) {
        Some(n) => n,
        None => return Flow::Continue(()),
    };

    let action = if tripwire.block { "blocked" } else { "flagged" };
    emit_anomaly("request", hit, action);
    handler.set_header(&tripwire.alert_header, "fired;direction=request");

    if tripwire.block {
        Flow::Break(
            Response::new(403)
                .with_headers([
                    ("Content-Type".to_string(), "application/json".to_string()),
                    (tripwire.alert_header.clone(), "fired;direction=request".to_string()),
                ])
                .with_body(
                    json!({
                        "error": "request referenced a honeytoken decoy",
                        "control": "NIST SC-26/SI-20",
                    })
                    .to_string(),
                ),
        )
    } else {
        Flow::Continue(())
    }
}

/// Response path: scan the tool result / model output coming back. A honeytoken
/// here means the decoy is being exfiltrated. In block mode we strip it so it
/// cannot actually leave; otherwise we flag and let it pass (Expose only).
async fn response_filter(response_state: ResponseState, tripwire: &Tripwire) {
    if tripwire.needles.is_empty() {
        return;
    }

    let state = response_state
        .into_headers_state()
        .await
        .into_headers_body_state()
        .await;
    let handler = state.handler();

    let body = handler.body();
    if body.is_empty() {
        return;
    }
    let text = String::from_utf8_lossy(&body);

    let hit = match tripwire.detect(&text) {
        Some(n) => n,
        None => return,
    };

    let action = if tripwire.block { "redacted" } else { "flagged" };
    emit_anomaly("response", hit, action);
    handler.set_header(&tripwire.alert_header, "fired;direction=response");

    if tripwire.block {
        if let Some(clean) = tripwire.redact(&text) {
            let bytes = clean.into_bytes();
            handler.set_header("content-length", &bytes.len().to_string());
            if let Err(err) = handler.set_body(&bytes) {
                logger::error!("Unable to strip honeytoken from response: {err:?}");
            }
        }
    }
}

#[entrypoint]
async fn configure(launcher: Launcher, Configuration(bytes): Configuration) -> Result<()> {
    let config: Config = serde_json::from_slice(&bytes).map_err(|err| {
        anyhow!(
            "Failed to parse configuration '{}'. Cause: {}",
            String::from_utf8_lossy(&bytes),
            err
        )
    })?;

    let tripwire = Tripwire::from_config(&config);
    logger::info!(
        "MCP Honeytoken Tripwire armed: {} token(s), mode={}",
        tripwire.needles.len(),
        if tripwire.block { "block" } else { "monitor" }
    );

    let filter = on_request(|rs| request_filter(rs, &tripwire))
        .on_response(|res| response_filter(res, &tripwire));
    launcher.launch(filter).await?;
    Ok(())
}

#[cfg(test)]
mod test {
    use pdk_unit::{
        TraceBackend, UnitHttpMessage, UnitHttpRequest, UnitHttpResponse, UnitTestBuilder,
    };
    use serde_json::json;
    use std::rc::Rc;

    const DECOY: &str = "acct_DECOY_9x1f-do-not-use";

    fn monitor_config() -> String {
        json!({
            "honeytokens": [DECOY],
            "mode": "monitor",
            "alertHeader": "x-agent-decoy-tripwire",
            "caseSensitive": false
        })
        .to_string()
    }

    fn block_config() -> String {
        json!({
            "honeytokens": [DECOY],
            "mode": "block",
            "alertHeader": "x-agent-decoy-tripwire",
            "caseSensitive": false
        })
        .to_string()
    }

    // Backend that echoes the decoy back in the response body, simulating a tool
    // result that carries the planted honeytoken.
    fn leaking_backend(_req: UnitHttpRequest) -> UnitHttpResponse {
        UnitHttpResponse::new(200)
            .with_body(format!("{{\"record\":\"{DECOY}\"}}").as_bytes())
    }

    fn clean_backend(_req: UnitHttpRequest) -> UnitHttpResponse {
        UnitHttpResponse::new(200).with_body(b"{\"record\":\"acct_real_customer\"}")
    }

    #[test]
    fn clean_request_passes_in_monitor_mode() {
        let mut tester = UnitTestBuilder::default()
            .with_config(monitor_config())
            .with_backend(clean_backend)
            .with_entrypoint(super::configure);

        let response = tester.request(
            UnitHttpRequest::post().with_body("{\"tool\":\"get_orders\",\"arg\":\"normal\"}"),
        );
        assert_eq!(response.status_code(), 200);
    }

    #[test]
    fn request_referencing_decoy_is_flagged_not_blocked_in_monitor_mode() {
        let backend = Rc::new(TraceBackend::new(clean_backend));
        let mut tester = UnitTestBuilder::default()
            .with_config(monitor_config())
            .with_backend(Rc::clone(&backend))
            .with_entrypoint(super::configure);

        let response = tester.request(
            UnitHttpRequest::post().with_body(format!("{{\"lookup\":\"{DECOY}\"}}")),
        );
        // Monitor mode: high-signal flag, but traffic continues to the upstream.
        assert_eq!(response.status_code(), 200);
        // The alert header is stamped on the request forwarded upstream (for
        // downstream logging / SIEM), not on the client-facing response.
        let forwarded = backend.next().unwrap();
        assert_eq!(
            forwarded.header("x-agent-decoy-tripwire"),
            Some("fired;direction=request")
        );
    }

    #[test]
    fn request_referencing_decoy_is_blocked_in_block_mode() {
        let mut tester = UnitTestBuilder::default()
            .with_config(block_config())
            .with_backend(clean_backend)
            .with_entrypoint(super::configure);

        let response = tester.request(
            UnitHttpRequest::post().with_body(format!("{{\"lookup\":\"{DECOY}\"}}")),
        );
        assert_eq!(response.status_code(), 403);
    }

    #[test]
    fn case_variant_still_trips_when_case_insensitive() {
        let mut tester = UnitTestBuilder::default()
            .with_config(block_config())
            .with_backend(clean_backend)
            .with_entrypoint(super::configure);

        let response = tester.request(
            UnitHttpRequest::post().with_body(format!("{{\"lookup\":\"{}\"}}", DECOY.to_uppercase())),
        );
        assert_eq!(response.status_code(), 403);
    }

    #[test]
    fn decoy_is_stripped_from_response_in_block_mode() {
        let backend = Rc::new(TraceBackend::new(leaking_backend));
        let mut tester = UnitTestBuilder::default()
            .with_config(block_config())
            .with_backend(Rc::clone(&backend))
            .with_entrypoint(super::configure);

        let response = tester.request(UnitHttpRequest::post().with_body("{\"tool\":\"read\"}"));
        assert_eq!(response.status_code(), 200);
        let body = String::from_utf8_lossy(&response.body()).to_string();
        assert!(!body.contains(DECOY), "decoy must not leave the gateway");
        assert!(body.contains("[decoy-withheld]"));
        assert_eq!(
            response.header("x-agent-decoy-tripwire"),
            Some("fired;direction=response")
        );
    }

    #[test]
    fn decoy_in_response_is_flagged_but_kept_in_monitor_mode() {
        let mut tester = UnitTestBuilder::default()
            .with_config(monitor_config())
            .with_backend(leaking_backend)
            .with_entrypoint(super::configure);

        let response = tester.request(UnitHttpRequest::post().with_body("{\"tool\":\"read\"}"));
        assert_eq!(response.status_code(), 200);
        let body = String::from_utf8_lossy(&response.body()).to_string();
        // Monitor = Expose only: we flag it, we do not alter the payload.
        assert!(body.contains(DECOY));
        assert_eq!(
            response.header("x-agent-decoy-tripwire"),
            Some("fired;direction=response")
        );
    }
}
