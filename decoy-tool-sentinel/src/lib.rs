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
use pdk::policy_violation::PolicyViolations;
use serde::{
    de::{self, MapAccess, SeqAccess, Visitor},
    Deserialize,
};
use serde_json::{json, Value};

use crate::generated::config::Config;

/// JSON-RPC error code MuleSoft's MCP policies use to signal a blocked tool.
const MCP_BLOCKED_CODE: i64 = -32008;
/// NIST controls represented by Sentinel's structured anomaly event.
const SENTINEL_CONTROL_MAPPING: &str = "NIST SC-26/SC-30/SI-4";

/// Compiled sentinel, built once at configuration time.
struct Sentinel {
    /// Decoy tool names, matched case-sensitively against the MCP `params.name`.
    /// MCP tool names are exact identifiers, so casing is significant here.
    decoy_tools: Vec<String>,
    block: bool,
    alert_header: String,
}

struct ParsedCalls {
    is_batch: bool,
    calls: Vec<String>,
    response_ids: Vec<Value>,
}

/// Deserialize JSON while rejecting a duplicate member in any object. This avoids
/// parser-differential JSON-RPC admission decisions before a map-backed Value is built.
struct NoDuplicateMembers;

impl<'de> Deserialize<'de> for NoDuplicateMembers {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(NoDuplicateVisitor)
    }
}

struct NoDuplicateVisitor;
impl<'de> Visitor<'de> for NoDuplicateVisitor {
    type Value = NoDuplicateMembers;
    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("JSON with no duplicate object members")
    }
    fn visit_bool<E: de::Error>(self, _: bool) -> Result<Self::Value, E> {
        Ok(NoDuplicateMembers)
    }
    fn visit_i64<E: de::Error>(self, _: i64) -> Result<Self::Value, E> {
        Ok(NoDuplicateMembers)
    }
    fn visit_u64<E: de::Error>(self, _: u64) -> Result<Self::Value, E> {
        Ok(NoDuplicateMembers)
    }
    fn visit_f64<E: de::Error>(self, _: f64) -> Result<Self::Value, E> {
        Ok(NoDuplicateMembers)
    }
    fn visit_str<E: de::Error>(self, _: &str) -> Result<Self::Value, E> {
        Ok(NoDuplicateMembers)
    }
    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(NoDuplicateMembers)
    }
    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(NoDuplicateMembers)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        while seq.next_element::<NoDuplicateMembers>()?.is_some() {}
        Ok(NoDuplicateMembers)
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut keys = std::collections::HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key) {
                return Err(de::Error::custom("duplicate JSON object member"));
            }
            map.next_value::<NoDuplicateMembers>()?;
        }
        Ok(NoDuplicateMembers)
    }
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

    /// Parses complete JSON-RPC 2.0 requests, notifications, responses or batches, preserving batch
    /// shape and response IDs for protocol-valid block responses. Ambiguous or
    /// malformed input is rejected generically in block mode.
    fn called_tools(body: &[u8]) -> Option<ParsedCalls> {
        serde_json::from_slice::<NoDuplicateMembers>(body).ok()?;
        let root: Value = serde_json::from_slice(body).ok()?;
        let is_batch = matches!(root, Value::Array(_));
        let items: Vec<&Value> = match &root {
            Value::Array(items) if !items.is_empty() => items.iter().collect(),
            Value::Object(_) => vec![&root],
            _ => return None,
        };

        let mut response_ids = Vec::new();
        let mut calls = Vec::new();
        for item in items {
            let object = item.as_object()?;
            if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
                return None;
            }
            let id = object.get("id");
            if id.is_some_and(|id| !matches!(id, Value::Null | Value::String(_) | Value::Number(_)))
            {
                return None;
            }
            if let Some(method) = object.get("method") {
                let method = method.as_str()?;
                if object.contains_key("result") || object.contains_key("error") {
                    return None;
                }
                if object
                    .get("params")
                    .is_some_and(|params| !params.is_object() && !params.is_array())
                {
                    return None;
                }
                if method == "tools/call" {
                    let params = object.get("params")?.as_object()?;
                    let name = params.get("name")?.as_str()?;
                    if params
                        .get("arguments")
                        .is_some_and(|args| !args.is_object())
                    {
                        return None;
                    }
                    calls.push(name.to_owned());
                }
                if let Some(id) = id {
                    response_ids.push(id.clone());
                }
            } else {
                // Client replies to server requests travel over the same MCP POST
                // endpoint. They are not calls and must never receive another reply.
                if id.is_none()
                    || object.contains_key("params")
                    || object.contains_key("result") == object.contains_key("error")
                {
                    return None;
                }
                if let Some(error) = object.get("error") {
                    let error = error.as_object()?;
                    let code = error.get("code")?;
                    if (!code.is_i64() && !code.is_u64())
                        || error.get("message").and_then(Value::as_str).is_none()
                    {
                        return None;
                    }
                }
            }
        }

        Some(ParsedCalls {
            is_batch,
            calls,
            response_ids,
        })
    }
}

/// Emits the structured anomaly to the gateway log (the "Expose" beat —
/// Message Logging / SSE Logging and any SIEM forwarder pick it up).
fn emit_anomaly(tool: &str, action: &str) {
    let event = json!({
        "event": "agent_decoy_tool_call",
        "control": SENTINEL_CONTROL_MAPPING,
        "tool": tool,
        "action": action,
    });
    logger::warn!("{event}");
}

async fn request_filter(
    request_state: RequestState,
    sentinel: &Sentinel,
    violations: &PolicyViolations,
) -> Flow<()> {
    if sentinel.decoy_tools.is_empty() {
        return Flow::Continue(());
    }

    let headers = request_state.into_headers_state().await;
    if !headers.contains_body() {
        return Flow::Continue(());
    }
    let length = headers
        .handler()
        .header("content-length")
        .filter(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|n| *n <= 64 * 1024);
    let json = headers
        .handler()
        .header("content-type")
        .is_some_and(|value| {
            let media = value
                .split(';')
                .next()
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase();
            media == "application/json"
                || (media.starts_with("application/") && media.ends_with("+json"))
        });
    if length.is_none() || !json || headers.handler().header("content-encoding").is_some() {
        return if sentinel.block {
            Flow::Break(Response::new(415).with_body("request body cannot be safely inspected"))
        } else {
            Flow::Continue(())
        };
    }
    let state = headers.into_headers_body_state().await;
    let handler = state.handler();
    let body = handler.body();
    if Some(body.len()) != length || body.len() > 64 * 1024 {
        return if sentinel.block {
            Flow::Break(Response::new(415).with_body("request body framing is invalid"))
        } else {
            Flow::Continue(())
        };
    }

    let parsed = match Sentinel::called_tools(&body) {
        Some(parsed) => parsed,
        None if sentinel.block => {
            return Flow::Break(
                Response::new(400)
                    .with_headers([("Content-Type".to_string(), "application/json".to_string())])
                    .with_body(json!({"error":"request is not unambiguous JSON-RPC"}).to_string()),
            )
        }
        None => return Flow::Continue(()),
    };
    let tool = match parsed
        .calls
        .iter()
        .find(|tool| sentinel.decoy_tools.iter().any(|decoy| decoy == *tool))
    {
        Some(hit) => hit,
        None => return Flow::Continue(()),
    };

    let action = if sentinel.block { "blocked" } else { "flagged" };
    emit_anomaly(tool, action);
    handler.set_header(&sentinel.alert_header, "fired");

    violations.generate_policy_violation();

    if sentinel.block {
        if parsed.response_ids.is_empty() {
            return Flow::Break(Response::new(202));
        }

        if parsed.is_batch {
            let errors: Vec<Value> = parsed
                .response_ids
                .into_iter()
                .map(|id| {
                    json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": MCP_BLOCKED_CODE,
                            "message": format!("batch rejected because decoy tool '{tool}' is not callable"),
                        }
                    })
                })
                .collect();
            Flow::Break(
                Response::new(200)
                    .with_headers([
                        ("Content-Type".to_string(), "application/json".to_string()),
                        (sentinel.alert_header.clone(), "fired".to_string()),
                    ])
                    .with_body(Value::Array(errors).to_string()),
            )
        } else {
            let id = parsed.response_ids.into_iter().next().unwrap();
            Flow::Break(
                Response::new(200)
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
        }
    } else {
        Flow::Continue(())
    }
}

#[entrypoint]
async fn configure(
    launcher: Launcher,
    Configuration(bytes): Configuration,
    violations: PolicyViolations,
) -> Result<()> {
    let config: Config = serde_json::from_slice(&bytes).map_err(|err| {
        anyhow!(
            "Invalid policy configuration at line {}, column {} ({:?})",
            err.line(),
            err.column(),
            err.classify()
        )
    })?;

    let sentinel = Sentinel::from_config(&config);
    logger::info!(
        "Decoy Tool Sentinel armed: {} decoy tool(s), mode={}",
        sentinel.decoy_tools.len(),
        if sentinel.block { "block" } else { "monitor" }
    );

    let filter = on_request(|rs| request_filter(rs, &sentinel, &violations));
    launcher.launch(filter).await?;
    Ok(())
}

#[cfg(test)]
mod test {
    use super::MCP_BLOCKED_CODE;
    use pdk_unit::{
        TraceBackend, UnitHttpMessage, UnitHttpRequest, UnitHttpResponse, UnitTestBuilder,
    };
    use serde_json::{json, Value};
    use std::rc::Rc;

    const DECOY: &str = "dump_all_records";

    #[test]
    fn emitted_control_mapping_matches_documented_nist_controls() {
        assert_eq!(super::SENTINEL_CONTROL_MAPPING, "NIST SC-26/SC-30/SI-4");
    }

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

        let response = tester.request(json_request(tools_call("get_orders")));
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
        let response = tester.request(json_request(body));
        assert_eq!(response.status_code(), 200);
    }

    #[test]
    fn decoy_call_is_blocked_in_block_mode() {
        let mut tester = UnitTestBuilder::default()
            .with_config(block_config())
            .with_backend(ok_backend)
            .with_entrypoint(super::configure);

        let response = tester.request(json_request(tools_call(DECOY)));
        assert_eq!(
            response.status_code(),
            200,
            "response-bearing MCP requests receive an in-band JSON-RPC error"
        );
        assert_eq!(response.header("content-type"), Some("application/json"));
        let body = String::from_utf8_lossy(response.body()).to_string();
        assert!(body.contains("-32008"), "expected JSON-RPC block error");
        assert!(body.contains(DECOY));
    }

    #[test]
    fn decoy_call_in_jsonrpc_batch_is_blocked_in_block_mode() {
        let mut tester = UnitTestBuilder::default()
            .with_config(block_config())
            .with_backend(ok_backend)
            .with_entrypoint(super::configure);

        let batch = json!([
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "get_orders", "arguments": {}}},
            {"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": {"name": DECOY, "arguments": {}}}
        ])
        .to_string();
        let response = tester.request(json_request(batch));

        assert_eq!(
            response.status_code(),
            200,
            "a response-bearing batch receives an in-band JSON-RPC error array"
        );
        assert_eq!(response.header("content-type"), Some("application/json"));
        let body: Value = serde_json::from_slice(response.body()).expect("batch response is JSON");
        let errors = body.as_array().expect("batch response is an array");
        assert_eq!(
            errors.len(),
            2,
            "atomic rejection returns one error per request id"
        );
        assert!(errors.iter().all(|error| error["error"]["code"] == -32008));
        assert!(errors.iter().any(|error| error["id"] == 3));
        assert!(errors.iter().any(|error| error["id"] == 9));
    }

    #[test]
    fn clean_jsonrpc_batch_passes() {
        let mut tester = UnitTestBuilder::default()
            .with_config(block_config())
            .with_backend(ok_backend)
            .with_entrypoint(super::configure);

        let batch = json!([
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "get_orders", "arguments": {}}},
            {"jsonrpc": "2.0", "id": 4, "method": "tools/list", "params": {}}
        ])
        .to_string();
        let response = tester.request(json_request(batch));

        assert_eq!(response.status_code(), 200);
    }

    #[test]
    fn decoy_call_in_jsonrpc_batch_is_flagged_in_monitor_mode() {
        let backend = Rc::new(TraceBackend::new(ok_backend));
        let mut tester = UnitTestBuilder::default()
            .with_config(monitor_config())
            .with_backend(Rc::clone(&backend))
            .with_entrypoint(super::configure);

        let batch = json!([
            {"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": {"name": DECOY, "arguments": {}}}
        ])
        .to_string();
        let response = tester.request(json_request(batch));

        assert_eq!(response.status_code(), 200);
        let forwarded = backend.next().unwrap();
        assert_eq!(forwarded.header("x-agent-decoy-sentinel"), Some("fired"));
    }

    #[test]
    fn malformed_jsonrpc_batch_is_rejected() {
        let backend = Rc::new(TraceBackend::new(ok_backend));
        let mut tester = UnitTestBuilder::default()
            .with_config(block_config())
            .with_backend(Rc::clone(&backend))
            .with_entrypoint(super::configure);

        let batch = json!([
            {"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": {}},
            "not an object"
        ])
        .to_string();
        let response = tester.request(json_request(batch));

        assert_eq!(response.status_code(), 400);
        assert!(
            backend.next().is_none(),
            "malformed input must not reach upstream"
        );
    }

    #[test]
    fn non_jsonrpc_decoy_shaped_body_is_rejected() {
        let backend = Rc::new(TraceBackend::new(ok_backend));
        let mut tester = UnitTestBuilder::default()
            .with_config(block_config())
            .with_backend(Rc::clone(&backend))
            .with_entrypoint(super::configure);

        let body = json!({
            "id": 7,
            "method": "tools/call",
            "params": {"name": DECOY, "arguments": {}}
        })
        .to_string();
        let response = tester.request(json_request(body));

        assert_eq!(response.status_code(), 400);
        assert!(
            backend.next().is_none(),
            "non-JSON-RPC traffic must not reach upstream"
        );
    }

    #[test]
    fn mixed_non_jsonrpc_batch_with_decoy_is_rejected() {
        let backend = Rc::new(TraceBackend::new(ok_backend));
        let mut tester = UnitTestBuilder::default()
            .with_config(block_config())
            .with_backend(Rc::clone(&backend))
            .with_entrypoint(super::configure);

        let batch = json!([
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "get_orders", "arguments": {}}},
            {"id": 9, "method": "tools/call", "params": {"name": DECOY, "arguments": {}}}
        ])
        .to_string();
        let response = tester.request(json_request(batch));

        assert_eq!(response.status_code(), 400);
        assert!(
            backend.next().is_none(),
            "a mixed invalid batch must not reach upstream"
        );
    }

    #[test]
    fn decoy_notification_has_no_jsonrpc_response_body() {
        let mut tester = UnitTestBuilder::default()
            .with_config(block_config())
            .with_backend(ok_backend)
            .with_entrypoint(super::configure);

        let notification = json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": DECOY, "arguments": {}}
        })
        .to_string();
        let response = tester.request(json_request(notification));

        assert_eq!(
            response.status_code(),
            202,
            "accepted MCP notifications return 202 with no body"
        );
        assert!(response.body().is_empty());
    }

    #[test]
    fn decoy_notification_in_mixed_batch_returns_errors_only_for_request_ids() {
        let mut tester = UnitTestBuilder::default()
            .with_config(block_config())
            .with_backend(ok_backend)
            .with_entrypoint(super::configure);

        let batch = json!([
            {"jsonrpc": "2.0", "method": "tools/call", "params": {"name": DECOY, "arguments": {}}},
            {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "get_orders", "arguments": {}}}
        ])
        .to_string();
        let response = tester.request(json_request(batch));

        assert_eq!(
            response.status_code(),
            200,
            "a response-bearing batch receives an in-band JSON-RPC error array"
        );
        assert_eq!(response.header("content-type"), Some("application/json"));
        let body: Value = serde_json::from_slice(response.body()).expect("batch response is JSON");
        assert_eq!(
            body,
            json!([{
                "jsonrpc": "2.0",
                "id": 4,
                "error": {"code": MCP_BLOCKED_CODE, "message": format!("batch rejected because decoy tool '{DECOY}' is not callable")}
            }])
        );
    }

    #[test]
    fn decoy_call_is_flagged_not_blocked_in_monitor_mode() {
        let backend = Rc::new(TraceBackend::new(ok_backend));
        let mut tester = UnitTestBuilder::default()
            .with_config(monitor_config())
            .with_backend(Rc::clone(&backend))
            .with_entrypoint(super::configure);

        let response = tester.request(json_request(tools_call(DECOY)));
        // Monitor mode: high-signal flag, but the call proceeds upstream.
        assert_eq!(response.status_code(), 200);
        let forwarded = backend.next().unwrap();
        assert_eq!(forwarded.header("x-agent-decoy-sentinel"), Some("fired"));
    }

    #[test]
    fn non_jsonrpc_body_is_rejected() {
        let mut tester = UnitTestBuilder::default()
            .with_config(block_config())
            .with_backend(ok_backend)
            .with_entrypoint(super::configure);

        let response = tester.request(json_request("not json at all"));
        assert_eq!(response.status_code(), 400);
    }
    #[test]
    fn ambiguous_or_mixed_invalid_json_never_reaches_upstream_in_block_mode() {
        for body in [
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","method":"tools/list","params":{"name":"dump_all_records"}}"#,
            r#"{"jsonrpc":"2.0","id":1,"id":2,"method":"tools/call","params":{"name":"dump_all_records"}}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"dump_all_records","name":"get_orders"}}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"dump_all_records","na\u006de":"get_orders"}}"#,
            r#"[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"dump_all_records"}},42]"#,
        ] {
            let backend = Rc::new(TraceBackend::new(ok_backend));
            let mut tester = UnitTestBuilder::default()
                .with_config(block_config())
                .with_backend(Rc::clone(&backend))
                .with_entrypoint(super::configure);
            let response = tester.request(json_request(body));
            assert_eq!(
                response.status_code(),
                400,
                "ambiguous input uses a generic rejection"
            );
            assert!(
                backend.next().is_none(),
                "ambiguous input must not reach upstream"
            );
        }
    }

    #[test]
    fn monitor_preserves_ambiguous_json_without_claiming_a_decoy_verdict() {
        let body = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"dump_all_records","name":"get_orders"}}"#;
        let backend = Rc::new(TraceBackend::new(ok_backend));
        let mut tester = UnitTestBuilder::default()
            .with_config(monitor_config())
            .with_backend(Rc::clone(&backend))
            .with_entrypoint(super::configure);
        tester.request(json_request(body));
        let forwarded = backend.next().unwrap();
        assert_eq!(forwarded.body(), body.as_bytes());
        assert_eq!(forwarded.header("x-agent-decoy-sentinel"), None);
    }

    #[test]
    fn blocked_decoy_sets_policy_violation_without_upstream_execution() {
        let backend = Rc::new(TraceBackend::new(ok_backend));
        let mut tester = UnitTestBuilder::default()
            .with_config(block_config())
            .with_backend(Rc::clone(&backend))
            .with_entrypoint(super::configure);
        let response = tester.request(json_request(tools_call(DECOY)));
        assert!(backend.next().is_none());
        assert!(
            response.violation().is_some(),
            "a JSON-RPC 200 denial must signal a policy violation"
        );
    }

    #[test]
    fn clean_calls_do_not_generate_policy_violations() {
        for config in [block_config(), monitor_config()] {
            let backend = Rc::new(TraceBackend::new(ok_backend));
            let mut tester = UnitTestBuilder::default()
                .with_config(config)
                .with_backend(Rc::clone(&backend))
                .with_entrypoint(super::configure);
            tester.request(json_request(tools_call("get_orders")));
            assert!(backend.next().unwrap().violation().is_none());
        }
    }

    #[test]
    fn monitor_preserves_prior_violation_until_a_decoy_hit_replaces_it() {
        use pdk::policy_violation::{PolicyViolation, PolicyViolationType};
        for name in ["get_orders", DECOY] {
            let backend = Rc::new(TraceBackend::new(ok_backend));
            let mut tester = UnitTestBuilder::default()
                .with_config(monitor_config())
                .with_backend(Rc::clone(&backend))
                .with_entrypoint(super::configure);
            let prior = PolicyViolation::new(
                "earlier-policy".into(),
                PolicyViolationType::Violation,
                None,
                None,
            );
            tester.request(json_request(tools_call(name)).with_policy_violation(prior));
            let forwarded = backend.next().unwrap();
            let violation = forwarded.violation().expect("one active violation");
            if name == DECOY {
                assert_ne!(violation.get_policy_name(), "earlier-policy");
            } else {
                assert_eq!(violation.get_policy_name(), "earlier-policy");
            }
        }
    }

    #[test]
    fn monitored_decoy_reports_violation_and_still_reaches_upstream() {
        let backend = Rc::new(TraceBackend::new(ok_backend));
        let mut tester = UnitTestBuilder::default()
            .with_config(monitor_config())
            .with_backend(Rc::clone(&backend))
            .with_entrypoint(super::configure);
        tester.request(json_request(tools_call(DECOY)));
        let forwarded = backend.next().expect("monitor forwards the request");
        assert!(
            forwarded.violation().is_some(),
            "monitor hits must signal a violation"
        );
    }

    fn json_request(body: impl AsRef<str>) -> UnitHttpRequest {
        let body = body.as_ref();
        UnitHttpRequest::post()
            .with_header("content-type", "application/json")
            .with_header("content-length", body.len().to_string())
            .with_body(body)
    }

    #[test]
    fn block_rejects_uninspectable_transport_before_upstream() {
        for request in [
            json_request("{}").with_header("content-encoding", "gzip"),
            UnitHttpRequest::post()
                .with_header("content-type", "text/event-stream")
                .with_header("content-length", "2")
                .with_body("{}"),
            UnitHttpRequest::post()
                .with_header("content-type", "application/json")
                .with_header("content-length", "65537")
                .with_body("{}"),
            UnitHttpRequest::post()
                .with_header("content-type", "application/json")
                .with_header("content-length", "1")
                .with_body("{}"),
            UnitHttpRequest::post().with_body("{}"),
        ] {
            let backend = Rc::new(TraceBackend::new(ok_backend));
            let mut tester = UnitTestBuilder::default()
                .with_config(block_config())
                .with_backend(Rc::clone(&backend))
                .with_entrypoint(super::configure);
            let response = tester.request(request);
            assert_eq!(response.status_code(), 415);
            assert!(backend.next().is_none());
        }
    }
    #[test]
    fn client_responses_pass_unchanged_without_a_decoy_verdict() {
        for config in [block_config(), monitor_config()] {
            for body in [
                r#"{"jsonrpc":"2.0","id":7,"result":{"name":"dump_all_records","method":"tools/call"}}"#,
                r#"{"jsonrpc":"2.0","id":"sampling-1","error":{"code":-32601,"message":"dump_all_records","data":null}}"#,
            ] {
                let backend = Rc::new(TraceBackend::new(ok_backend));
                let mut tester = UnitTestBuilder::default()
                    .with_config(config.clone())
                    .with_backend(Rc::clone(&backend))
                    .with_entrypoint(super::configure);
                tester.request(json_request(body));
                let forwarded = backend.next().expect("client response must reach server");
                assert_eq!(forwarded.body(), body.as_bytes());
                assert_eq!(forwarded.header("x-agent-decoy-sentinel"), None);
                assert!(forwarded.violation().is_none());
            }
        }
    }

    #[test]
    fn invalid_rpc_envelopes_are_rejected_without_a_decoy_verdict() {
        for body in [
            r#"{"jsonrpc":"2.0","id":true,"method":"tools/call","params":{"name":"dump_all_records"}}"#,
            r#"{"jsonrpc":"2.0","id":{},"method":"tools/list"}"#,
            r#"{"jsonrpc":"2.0","id":[],"result":{}}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":7}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":null}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call"}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":7}}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"dump_all_records","arguments":[]}}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","result":{}}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","error":{"code":1,"message":"x"}}"#,
            r#"{"jsonrpc":"2.0","result":{}}"#,
            r#"{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":1,"message":"x"}}"#,
            r#"{"jsonrpc":"2.0","id":1,"result":{},"params":{}}"#,
            r#"{"jsonrpc":"2.0","id":1,"error":{}}"#,
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":1.5,"message":"x"}}"#,
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":1,"message":7}}"#,
        ] {
            let backend = Rc::new(TraceBackend::new(ok_backend));
            let mut tester = UnitTestBuilder::default()
                .with_config(block_config())
                .with_backend(Rc::clone(&backend))
                .with_entrypoint(super::configure);
            let response = tester.request(json_request(body));
            assert_eq!(response.status_code(), 400, "{body}");
            assert!(response.violation().is_none());
            assert!(backend.next().is_none());
        }
    }

    #[test]
    fn rejected_mixed_batch_never_replies_to_client_responses() {
        let body = r#"[{"jsonrpc":"2.0","id":"server","result":{}},{"jsonrpc":"2.0","method":"tools/call","params":{"name":"dump_all_records"}},{"jsonrpc":"2.0","id":8,"method":"tools/list"}]"#;
        let backend = Rc::new(TraceBackend::new(ok_backend));
        let mut tester = UnitTestBuilder::default()
            .with_config(block_config())
            .with_backend(Rc::clone(&backend))
            .with_entrypoint(super::configure);
        let response = tester.request(json_request(body));
        assert_eq!(response.status_code(), 200);
        let errors: Value = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(errors.as_array().unwrap().len(), 1);
        assert_eq!(errors[0]["id"], 8);
        assert_eq!(errors[0]["error"]["code"], MCP_BLOCKED_CODE);
        assert!(backend.next().is_none());
    }

    #[test]
    fn response_and_decoy_notification_batch_has_no_response_body() {
        let body = r#"[{"jsonrpc":"2.0","id":"server","result":{}},{"jsonrpc":"2.0","method":"tools/call","params":{"name":"dump_all_records"}}]"#;
        let backend = Rc::new(TraceBackend::new(ok_backend));
        let mut tester = UnitTestBuilder::default()
            .with_config(block_config())
            .with_backend(Rc::clone(&backend))
            .with_entrypoint(super::configure);
        let response = tester.request(json_request(body));
        assert_eq!(response.status_code(), 202);
        assert!(response.body().is_empty());
        assert!(backend.next().is_none());
    }
}
