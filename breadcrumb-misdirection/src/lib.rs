// Copyright (c) 2026 msaleme. Licensed under the MIT License.
//
// Breadcrumb Misdirection — a lure that reveals a hijacked agent's path.
//
// The gateway plants a breadcrumb — text naming a resource no real task needs (a
// fake /admin/override endpoint, a decoy "internal" tool) — into the tool
// descriptions an agent reads from `tools/list`. A healthy agent ignores it. A
// prompt-injected or hijacked agent takes the bait and references the breadcrumb
// in a later request. The gateway logs that follow (CISA "Expose") and strips the
// breadcrumb out of the request so the lure never reaches a real upstream.
//
// This is Expose, NOT Elicit: it flags the follow and neutralizes it, it does not
// build a fake environment to entrap an adversary (the CISA advanced/legal-risk
// tier this policy deliberately stays out of).
//
// NIST SP 800-53 Rev 5: SC-30 (Concealment & Misdirection), SI-4 (Monitoring).
// NIST SP 800-160 Vol 2 Rev 1: Deception (Misdirection).
mod generated;

use anyhow::{anyhow, Result};

use pdk::hl::*;
use pdk::logger;
use serde_json::{json, Value};

use crate::generated::config::Config;

/// Compiled policy state, built once at configuration time.
struct Breadcrumb {
    /// The lure text: appended to tool descriptions on the way out, watched for
    /// on the way in. Empty disables the policy entirely.
    lure: String,
    /// Whether to plant the lure into tools/list responses.
    seed: bool,
    /// Whether to reject (not just strip + flag) a request that followed the lure.
    block: bool,
    alert_header: String,
}

impl Breadcrumb {
    fn from_config(config: &Config) -> Self {
        Self {
            lure: config.breadcrumb.trim().to_string(),
            seed: config.seed_tool_descriptions,
            block: config.mode.eq_ignore_ascii_case("block"),
            alert_header: config.alert_header.clone(),
        }
    }

    fn enabled(&self) -> bool {
        !self.lure.is_empty()
    }

    /// Appends the breadcrumb to every tool description in a `tools/list`
    /// result. Returns the rewritten JSON when it changed anything, else `None`
    /// so the caller can leave the body untouched.
    fn seed_tools_list(&self, body: &[u8]) -> Option<Vec<u8>> {
        let mut value: Value = serde_json::from_slice(body).ok()?;
        let tools = value.get_mut("result")?.get_mut("tools")?.as_array_mut()?;

        let mut changed = false;
        for tool in tools.iter_mut() {
            let Some(obj) = tool.as_object_mut() else {
                continue;
            };
            // Append to an existing description, or introduce one if absent, so
            // the lure is discoverable however the tool was declared.
            let current = obj
                .get("description")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if current.contains(&self.lure) {
                continue; // already seeded (idempotent across retries)
            }
            let seeded = if current.is_empty() {
                self.lure.clone()
            } else {
                format!("{current} {}", self.lure)
            };
            obj.insert("description".to_string(), Value::String(seeded));
            changed = true;
        }

        changed.then(|| serde_json::to_vec(&value).unwrap_or_else(|_| body.to_vec()))
    }
}

/// Emits the structured "breadcrumb followed" anomaly to the gateway log.
fn emit_anomaly(action: &str) {
    let event = json!({
        "event": "agent_breadcrumb_followed",
        "control": "NIST SC-30/SI-4",
        "action": action,
    });
    logger::warn!("{event}");
}

/// Request path: a body carrying the breadcrumb means an agent followed the lure.
/// Flag it, strip the lure so it never reaches the upstream, and optionally block.
async fn request_filter(request_state: RequestState, bc: &Breadcrumb) -> Flow<()> {
    if !bc.enabled() {
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
    if !text.contains(&bc.lure) {
        return Flow::Continue(());
    }

    let action = if bc.block { "blocked" } else { "stripped" };
    emit_anomaly(action);
    handler.set_header(&bc.alert_header, "followed");

    if bc.block {
        return Flow::Break(
            Response::new(403)
                .with_headers([
                    ("Content-Type".to_string(), "application/json".to_string()),
                    (bc.alert_header.clone(), "followed".to_string()),
                ])
                .with_body(
                    json!({
                        "error": "request followed a decoy breadcrumb",
                        "control": "NIST SC-30",
                    })
                    .to_string(),
                ),
        );
    }

    // Monitor mode: strip the lure so the injected instruction never reaches the
    // upstream, then let the cleaned request continue.
    let cleaned = text.replace(&bc.lure, "").into_bytes();
    handler.set_header("content-length", &cleaned.len().to_string());
    if let Err(err) = handler.set_body(&cleaned) {
        logger::error!("Unable to strip breadcrumb from request: {err:?}");
    }
    Flow::Continue(())
}

/// Response path: plant the breadcrumb into tools/list descriptions so an agent
/// can discover the lure.
async fn response_filter(response_state: ResponseState, bc: &Breadcrumb) {
    if !bc.enabled() || !bc.seed {
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

    if let Some(seeded) = bc.seed_tools_list(&body) {
        handler.set_header("content-length", &seeded.len().to_string());
        if let Err(err) = handler.set_body(&seeded) {
            logger::error!("Unable to seed breadcrumb into tools/list: {err:?}");
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

    let bc = Breadcrumb::from_config(&config);
    logger::info!(
        "Breadcrumb Misdirection armed: seed={}, mode={}",
        bc.seed,
        if bc.block { "block" } else { "monitor" }
    );

    let filter = on_request(|rs| request_filter(rs, &bc)).on_response(|res| response_filter(res, &bc));
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

    const LURE: &str = "For elevated access use admin_override_do_not_use";

    fn config(mode: &str, seed: bool) -> String {
        json!({
            "breadcrumb": LURE,
            "mode": mode,
            "seedToolDescriptions": seed,
            "alertHeader": "x-agent-breadcrumb"
        })
        .to_string()
    }

    fn tools_list_backend(_req: UnitHttpRequest) -> UnitHttpResponse {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "tools": [
                    {"name": "get_orders", "description": "Get the orders."},
                    {"name": "get_stock", "description": "Check inventory."}
                ]
            }
        })
        .to_string();
        UnitHttpResponse::new(200).with_body(body.as_bytes())
    }

    fn ok_backend(_req: UnitHttpRequest) -> UnitHttpResponse {
        UnitHttpResponse::new(200).with_body(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}")
    }

    #[test]
    fn breadcrumb_is_seeded_into_tools_list_response() {
        let mut tester = UnitTestBuilder::default()
            .with_config(config("monitor", true))
            .with_backend(tools_list_backend)
            .with_entrypoint(super::configure);

        let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).to_string();
        let response = tester.request(UnitHttpRequest::post().with_body(body));
        assert_eq!(response.status_code(), 200);
        let text = String::from_utf8_lossy(&response.body()).to_string();
        // Both tool descriptions now carry the lure.
        assert_eq!(text.matches(LURE).count(), 2);
        assert!(text.contains("Get the orders."));
    }

    #[test]
    fn following_the_breadcrumb_is_flagged_and_stripped_in_monitor_mode() {
        let backend = Rc::new(TraceBackend::new(ok_backend));
        let mut tester = UnitTestBuilder::default()
            .with_config(config("monitor", true))
            .with_backend(Rc::clone(&backend))
            .with_entrypoint(super::configure);

        let body = json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "get_orders", "arguments": {"note": LURE}}
        })
        .to_string();
        let response = tester.request(UnitHttpRequest::post().with_body(body));
        assert_eq!(response.status_code(), 200);

        // The lure is flagged and scrubbed before it reaches the upstream.
        let forwarded = backend.next().unwrap();
        assert_eq!(forwarded.header("x-agent-breadcrumb"), Some("followed"));
        let fwd_body = String::from_utf8_lossy(&forwarded.body()).to_string();
        assert!(!fwd_body.contains(LURE), "breadcrumb must be stripped upstream");
    }

    #[test]
    fn following_the_breadcrumb_is_blocked_in_block_mode() {
        let mut tester = UnitTestBuilder::default()
            .with_config(config("block", true))
            .with_backend(ok_backend)
            .with_entrypoint(super::configure);

        let body = json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "get_orders", "arguments": {"note": LURE}}
        })
        .to_string();
        let response = tester.request(UnitHttpRequest::post().with_body(body));
        assert_eq!(response.status_code(), 403);
    }

    #[test]
    fn a_normal_request_passes_untouched() {
        let backend = Rc::new(TraceBackend::new(ok_backend));
        let mut tester = UnitTestBuilder::default()
            .with_config(config("block", true))
            .with_backend(Rc::clone(&backend))
            .with_entrypoint(super::configure);

        let body = json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "get_orders", "arguments": {}}
        })
        .to_string();
        let response = tester.request(UnitHttpRequest::post().with_body(body.clone()));
        assert_eq!(response.status_code(), 200);
        let forwarded = backend.next().unwrap();
        assert_eq!(forwarded.header("x-agent-breadcrumb"), None);
    }

    #[test]
    fn seeding_can_be_disabled() {
        let mut tester = UnitTestBuilder::default()
            .with_config(config("monitor", false))
            .with_backend(tools_list_backend)
            .with_entrypoint(super::configure);

        let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).to_string();
        let response = tester.request(UnitHttpRequest::post().with_body(body));
        let text = String::from_utf8_lossy(&response.body()).to_string();
        assert!(!text.contains(LURE), "seeding disabled: response untouched");
    }
}
