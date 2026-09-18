// Copyright (c) 2026 msaleme. Licensed under the MIT License.
//
// Decoy Tool Sentinel — a decoy MCP tool no honest agent should ever call.
//
// You wire a tool into the fabric that has no legitimate use — dump_all_records,
// export_secrets, disable_audit — and register its name here. Because no real
// workflow ever calls it, a single MCP `tools/call` naming that tool is an
// unambiguous, high-fidelity signal that an agent has been hijacked or is probing
// for reach (CISA's "fake network-scanning tool on a nontechnical user's box —
// any execution indicates malicious activity").
//
// On a hit the filter emits a structured anomaly to the gateway log
// (CISA "Expose") and, in `block` mode, refuses the call with a JSON-RPC error so
// the decoy tool never executes (CISA "Affect").
//
// NIST SP 800-53 Rev 5: SC-26 (Decoys), SC-30 (Concealment & Misdirection),
// SI-4 (Monitoring). NIST SP 800-160 Vol 2 Rev 1: Deception (Misdirection).
mod generated;

use anyhow::{anyhow, Result};

use pdk::hl::*;
use pdk::logger;
use serde_json::{json, Value};

use crate::generated::config::Config;

/// JSON-RPC error code MuleSoft's MCP policies use to signal a blocked tool.
const MCP_BLOCKED_CODE: i64 = -32008;

/// Compiled sentinel, built once at configuration time.
struct Sentinel {
    /// Decoy tool names, matched case-sensitively against the MCP `params.name`.
    /// MCP tool names are exact identifiers, so casing is significant here.
    decoy_tools: Vec<String>,
    block: bool,
    alert_header: String,
}

impl Sentinel {
    fn from_config(config: &Config) -> Self {
        Self {
            decoy_tools: config
                .decoy_tools
                .iter()
                .map(|t| t.trim().to_string())
                .filter(|t| !t.is_empty())
                .collect(),
            block: config.mode.eq_ignore_ascii_case("block"),
            alert_header: config.alert_header.clone(),
        }
    }

    /// Extracts the tool name from an MCP `tools/call` request, if this body is
    /// one. Returns `None` for any other method or a non-JSON-RPC body — the
    /// sentinel only fires on an actual tool invocation, never on `tools/list`.
    fn called_tool(body: &[u8]) -> Option<String> {
        let value: Value = serde_json::from_slice(body).ok()?;
        if value.get("method")?.as_str()? != "tools/call" {
            return None;
        }
        Some(value.get("params")?.get("name")?.as_str()?.to_string())
    }

    /// The request's JSON-RPC id, echoed back in a block response so the client
    /// can correlate the error. Defaults to null when absent.
    fn rpc_id(body: &[u8]) -> Value {
        serde_json::from_slice::<Value>(body)
            .ok()
            .and_then(|v| v.get("id").cloned())
            .unwrap_or(Value::Null)
    }
}

/// Emits the structured anomaly to the gateway log (the "Expose" beat —
/// Message Logging / SSE Logging and any SIEM forwarder pick it up).
fn emit_anomaly(tool: &str, action: &str) {
    let event = json!({
        "event": "agent_decoy_tool_call",
        "control": "NIST SC-26/SC-30",
        "tool": tool,
        "action": action,
    });
    logger::warn!("{event}");
}

async fn request_filter(request_state: RequestState, sentinel: &Sentinel) -> Flow<()> {
    if sentinel.decoy_tools.is_empty() {
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

    let tool = match Sentinel::called_tool(&body) {
        Some(t) => t,
        None => return Flow::Continue(()),
    };
    if !sentinel.decoy_tools.iter().any(|d| d == &tool) {
        return Flow::Continue(());
    }

    let action = if sentinel.block { "blocked" } else { "flagged" };
    emit_anomaly(&tool, action);
    handler.set_header(&sentinel.alert_header, "fired");

    if sentinel.block {
        let id = Sentinel::rpc_id(&body);
        Flow::Break(
            Response::new(403)
                .with_headers([
                    ("Content-Type".to_string(), "application/json".to_string()),
                    (sentinel.alert_header.clone(), "fired".to_string()),
                ])
                .with_body(
                    json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": MCP_BLOCKED_CODE,
                            "message": format!("decoy tool '{tool}' is not callable"),
                        }
                    })
                    .to_string(),
                ),
        )
    } else {
        Flow::Continue(())
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

    let sentinel = Sentinel::from_config(&config);
    logger::info!(
        "Decoy Tool Sentinel armed: {} decoy tool(s), mode={}",
        sentinel.decoy_tools.len(),
        if sentinel.block { "block" } else { "monitor" }
    );

    let filter = on_request(|rs| request_filter(rs, &sentinel));
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

    const DECOY: &str = "dump_all_records";

    fn monitor_config() -> String {
        json!({
            "decoyTools": [DECOY, "export_secrets"],
            "mode": "monitor",
            "alertHeader": "x-agent-decoy-sentinel"
        })
        .to_string()
    }

    fn block_config() -> String {
        json!({
            "decoyTools": [DECOY, "export_secrets"],
            "mode": "block",
            "alertHeader": "x-agent-decoy-sentinel"
        })
        .to_string()
    }

    fn ok_backend(_req: UnitHttpRequest) -> UnitHttpResponse {
        UnitHttpResponse::new(200).with_body(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}")
    }

    fn tools_call(name: &str) -> String {
        json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": { "name": name, "arguments": {} }
        })
        .to_string()
    }

    #[test]
    fn legitimate_tool_call_passes() {
        let mut tester = UnitTestBuilder::default()
            .with_config(block_config())
            .with_backend(ok_backend)
            .with_entrypoint(super::configure);

        let response = tester.request(UnitHttpRequest::post().with_body(tools_call("get_orders")));
        assert_eq!(response.status_code(), 200);
    }

    #[test]
    fn tools_list_never_trips() {
        // Discovery (tools/list) must never fire — the decoy is meant to be
        // visible in the catalog; only *calling* it is the signal.
        let mut tester = UnitTestBuilder::default()
            .with_config(block_config())
            .with_backend(ok_backend)
            .with_entrypoint(super::configure);

        let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).to_string();
        let response = tester.request(UnitHttpRequest::post().with_body(body));
        assert_eq!(response.status_code(), 200);
    }

    #[test]
    fn decoy_call_is_blocked_in_block_mode() {
        let mut tester = UnitTestBuilder::default()
            .with_config(block_config())
            .with_backend(ok_backend)
            .with_entrypoint(super::configure);

        let response = tester.request(UnitHttpRequest::post().with_body(tools_call(DECOY)));
        assert_eq!(response.status_code(), 403);
        let body = String::from_utf8_lossy(&response.body()).to_string();
        assert!(body.contains("-32008"), "expected JSON-RPC block error");
        assert!(body.contains(DECOY));
    }

    #[test]
    fn decoy_call_is_flagged_not_blocked_in_monitor_mode() {
        let backend = Rc::new(TraceBackend::new(ok_backend));
        let mut tester = UnitTestBuilder::default()
            .with_config(monitor_config())
            .with_backend(Rc::clone(&backend))
            .with_entrypoint(super::configure);

        let response = tester.request(UnitHttpRequest::post().with_body(tools_call(DECOY)));
        // Monitor mode: high-signal flag, but the call proceeds upstream.
        assert_eq!(response.status_code(), 200);
        let forwarded = backend.next().unwrap();
        assert_eq!(forwarded.header("x-agent-decoy-sentinel"), Some("fired"));
    }

    #[test]
    fn non_jsonrpc_body_passes() {
        let mut tester = UnitTestBuilder::default()
            .with_config(block_config())
            .with_backend(ok_backend)
            .with_entrypoint(super::configure);

        let response = tester.request(UnitHttpRequest::post().with_body("not json at all"));
        assert_eq!(response.status_code(), 200);
    }
}
