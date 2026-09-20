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
use serde::{
    de::{self, IgnoredAny, MapAccess, SeqAccess, Visitor},
    Deserialize,
};
use serde_json::{json, Value};

use crate::generated::config::Config;

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

/// Validate JSON without building a map, then return every wire string literal
/// range (end-exclusive). This retains duplicate keys and values.
fn json_string_ranges(input: &str) -> Option<Vec<(usize, usize)>> {
    serde_json::from_str::<IgnoredAny>(input).ok()?;
    let bytes = input.as_bytes();
    let mut ranges = Vec::new();
    let mut start = 0;
    while start < bytes.len() {
        if bytes[start] != b'"' {
            start += 1;
            continue;
        }
        let mut end = start + 1;
        while end < bytes.len() {
            match bytes[end] {
                b'\\' => end += 2,
                b'"' => {
                    end += 1;
                    break;
                }
                _ => end += 1,
            }
        }
        if end > bytes.len() || bytes.get(end - 1) != Some(&b'"') {
            return None;
        }
        ranges.push((start, end));
        start = end;
    }
    Some(ranges)
}

// Admission is a declared-length eligibility gate, not a pre-buffering byte cap.
const MAX_SCAN_BYTES: usize = 64 * 1024;

fn body_kind(content_type: Option<String>) -> Option<bool> {
    let content_type = content_type?;
    let media = content_type.split(';').next()?.trim().to_ascii_lowercase();
    if media == "application/json"
        || (media.starts_with("application/") && media.ends_with("+json"))
    {
        Some(true)
    } else if media == "text/plain" {
        Some(false)
    } else {
        None
    }
}

fn body_length(value: Option<String>) -> Option<usize> {
    value
        .filter(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))?
        .parse::<usize>()
        .ok()
        .filter(|n| *n <= MAX_SCAN_BYTES)
}

fn contains_marker(text: &str, marker: &str, json: bool) -> bool {
    text.contains(marker)
        || (json
            && json_string_ranges(text).is_some_and(|ranges| {
                ranges.into_iter().any(|(start, end)| {
                    serde_json::from_str::<String>(&text[start..end])
                        .is_ok_and(|value| value.contains(marker))
                })
            }))
}

fn sanitize_json(text: &str, marker: &str) -> Option<String> {
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0;
    for (start, end) in json_string_ranges(text)? {
        out.push_str(&text[cursor..start]);
        let value: String = serde_json::from_str(&text[start..end]).ok()?;
        if value.contains(marker) {
            out.push_str(&serde_json::to_string(&value.replace(marker, "")).ok()?);
        } else {
            out.push_str(&text[start..end]);
        }
        cursor = end;
    }
    out.push_str(&text[cursor..]);
    // Removing markers in object keys may create duplicates. Reject those edits.
    serde_json::from_str::<NoDuplicateMembers>(&out).ok()?;
    (!contains_marker(&out, marker, true)).then_some(out)
}

fn uninspectable_request(bc: &Breadcrumb, reason: &str) -> Flow<Option<Value>> {
    if bc.mode == Mode::Observe {
        emit_anomaly("request", "observe", "unchanged", reason);
        Flow::Continue(None)
    } else {
        let requested = if bc.mode == Mode::Block {
            "block"
        } else {
            "sanitize"
        };
        emit_anomaly("request", requested, "blocked", reason);
        Flow::Break(Response::new(415).with_body("request body cannot be safely inspected"))
    }
}

/// Detection response selected by the operator. Only observe leaves a followed
/// request byte-for-byte unchanged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    Observe,
    Sanitize,
    Block,
}

/// Compiled policy state, built once at configuration time.
struct Breadcrumb {
    /// The lure text: appended to tool descriptions on the way out, watched for
    /// on the way in. Empty disables the policy entirely.
    lure: String,
    /// Whether to plant the lure into tools/list responses.
    seed: bool,
    /// How to handle an inbound request that follows the lure.
    mode: Mode,
    alert_header: String,
}

impl Breadcrumb {
    fn from_config(config: &Config) -> Self {
        let mode = match config.mode.as_str() {
            "sanitize" => Mode::Sanitize,
            "block" => Mode::Block,
            _ => Mode::Observe,
        };
        Self {
            lure: config.breadcrumb.trim().to_string(),
            seed: config.seeding.eq_ignore_ascii_case("enabled"),
            mode,
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
fn emit_anomaly(stage: &str, requested: &str, applied: &str, reason: &str) {
    let event = json!({
        "event": if stage == "response" { "agent_breadcrumb_seeding" } else { "agent_breadcrumb_followed" },
        "control": "NIST SC-30/SI-4",
        "action": applied,
        "stage": stage,
        "requested": requested,
        "applied": applied,
        "reason": reason,
    });
    logger::warn!("{event}");
}

/// Request path: a body carrying the breadcrumb means an agent followed the lure.
/// Flag it, strip the lure so it never reaches the upstream, and optionally block.
async fn request_filter(request_state: RequestState, bc: &Breadcrumb) -> Flow<Option<Value>> {
    if !bc.enabled() {
        return Flow::Continue(None);
    }
    let headers = request_state.into_headers_state().await;
    if !headers.contains_body() {
        return Flow::Continue(None);
    }
    let kind = body_kind(headers.handler().header("content-type"));
    let length = body_length(headers.handler().header("content-length"));
    if kind.is_none() || length.is_none() || headers.handler().header("content-encoding").is_some()
    {
        return uninspectable_request(bc, "uninspectable-body");
    }
    let json = kind == Some(true);
    let state = headers.into_headers_body_state().await;
    let handler = state.handler();
    let body = handler.body();
    if Some(body.len()) != length || body.len() > MAX_SCAN_BYTES {
        return uninspectable_request(bc, "invalid-body-framing");
    }
    let Ok(text) = std::str::from_utf8(&body) else {
        return uninspectable_request(bc, "invalid-utf8");
    };
    if json && serde_json::from_slice::<NoDuplicateMembers>(&body).is_err() {
        return uninspectable_request(bc, "ambiguous-or-invalid-json");
    }
    // Local request data is the only provenance used for response seeding.
    let list_id = if json {
        serde_json::from_slice::<Value>(&body)
            .ok()
            .and_then(|value| {
                if value["jsonrpc"] == "2.0" && value["method"] == "tools/list" {
                    value
                        .get("id")
                        .filter(|id| id.is_string() || id.is_number())
                        .cloned()
                } else {
                    None
                }
            })
    } else {
        None
    };
    if !contains_marker(text, &bc.lure, json) {
        return Flow::Continue(list_id);
    }
    handler.set_header(&bc.alert_header, "followed");
    if bc.mode == Mode::Block {
        emit_anomaly("request", "block", "blocked", "marker-match");
        return Flow::Break(
            Response::new(403)
                .with_headers([
                    ("Content-Type".to_string(), "application/json".to_string()),
                    (bc.alert_header.clone(), "followed".to_string()),
                ])
                .with_body(
                    json!({"error":"request followed a decoy breadcrumb","control":"NIST SC-30"})
                        .to_string(),
                ),
        );
    }
    if bc.mode == Mode::Observe {
        emit_anomaly("request", "observe", "observed", "marker-match");
        return Flow::Continue(list_id);
    }
    let cleaned = if json {
        sanitize_json(text, &bc.lure)
    } else {
        let clean = text.replace(&bc.lure, "");
        (!clean.contains(&bc.lure)).then_some(clean)
    };
    let Some(cleaned) = cleaned else {
        return uninspectable_request(bc, "unsafe-sanitization");
    };
    if let Err(err) = handler.set_body(cleaned.as_bytes()) {
        logger::error!("Unable to strip breadcrumb from request: {err:?}");
        emit_anomaly("request", "sanitize", "blocked", "body-write-failed");
        return Flow::Break(Response::new(500).with_body("required request sanitization failed"));
    }
    handler.remove_header("content-length");
    handler.remove_header("content-encoding");
    emit_anomaly("request", "sanitize", "sanitized", "marker-match");
    // A modified request must not authorize seeding of a differently identified response.
    Flow::Continue(None)
}

/// Response path: plant the breadcrumb into tools/list descriptions so an agent
/// can discover the lure.
async fn response_filter(
    response_state: ResponseState,
    request_data: RequestData<Option<Value>>,
    bc: &Breadcrumb,
) {
    if !bc.enabled() || !bc.seed {
        return;
    }
    let RequestData::Continue(Some(id)) = request_data else {
        return;
    };
    let headers = response_state.into_headers_state().await;
    if !headers.contains_body() {
        return;
    }
    let length = body_length(headers.handler().header("content-length"));
    if body_kind(headers.handler().header("content-type")) != Some(true)
        || length.is_none()
        || headers.handler().header("content-encoding").is_some()
    {
        emit_anomaly("response", "seed", "unchanged", "uninspectable-body");
        return;
    }
    let state = headers.into_headers_body_state().await;
    let handler = state.handler();
    let body = handler.body();
    if Some(body.len()) != length || serde_json::from_slice::<NoDuplicateMembers>(&body).is_err() {
        emit_anomaly("response", "seed", "unchanged", "invalid-body");
        return;
    }
    let Ok(value) = serde_json::from_slice::<Value>(&body) else {
        return;
    };
    if value["jsonrpc"] != "2.0" || value.get("id") != Some(&id) || value.get("error").is_some() {
        return;
    }
    if let Some(seeded) = bc.seed_tools_list(&body) {
        if seeded.len() > MAX_SCAN_BYTES {
            emit_anomaly("response", "seed", "unchanged", "replacement-too-large");
            return;
        }
        if let Err(err) = handler.set_body(&seeded) {
            logger::error!("Unable to seed breadcrumb into tools/list: {err:?}");
            emit_anomaly("response", "seed", "unchanged", "body-write-failed");
            return;
        }
        handler.remove_header("content-length");
        handler.remove_header("content-encoding");
        emit_anomaly("response", "seed", "seeded", "tools-list");
    }
}

#[entrypoint]
async fn configure(launcher: Launcher, Configuration(bytes): Configuration) -> Result<()> {
    let config: Config = serde_json::from_slice(&bytes).map_err(|err| {
        anyhow!(
            "Invalid policy configuration at line {}, column {} ({:?})",
            err.line(),
            err.column(),
            err.classify()
        )
    })?;

    let bc = Breadcrumb::from_config(&config);
    logger::info!(
        "Breadcrumb Misdirection armed: seeding={}, mode={}",
        if bc.seed { "enabled" } else { "disabled" },
        match bc.mode {
            Mode::Observe => "observe",
            Mode::Sanitize => "sanitize",
            Mode::Block => "block",
        }
    );

    let filter = on_request(|rs| request_filter(rs, &bc))
        .on_response(|res, data| response_filter(res, data, &bc));
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
            "seeding": if seed { "enabled" } else { "disabled" },
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
        UnitHttpResponse::new(200)
            .with_header("content-type", "application/json")
            .with_header("content-length", body.len().to_string())
            .with_body(body.as_bytes())
    }

    fn ok_backend(_req: UnitHttpRequest) -> UnitHttpResponse {
        UnitHttpResponse::new(200).with_body(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}")
    }

    #[test]
    fn empty_breadcrumb_disables_follow_detection_and_seeding() {
        let body = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
        let expected = tools_list_backend(json_request(body));
        let backend = Rc::new(TraceBackend::new(tools_list_backend));
        let mut tester = UnitTestBuilder::default()
            .with_config(json!({"breadcrumb":"", "mode":"block", "seeding":"enabled", "alertHeader":"x-agent-breadcrumb"}).to_string())
            .with_backend(Rc::clone(&backend))
            .with_entrypoint(super::configure);
        let response = tester.request(json_request(body));
        assert_eq!(response.body(), expected.body());
        let forwarded = backend.next().unwrap();
        assert_eq!(forwarded.body(), body.as_bytes());
        assert_eq!(forwarded.header("x-agent-breadcrumb"), None);
    }

    #[test]
    fn breadcrumb_is_seeded_into_tools_list_response() {
        let mut tester = UnitTestBuilder::default()
            .with_config(config("sanitize", true))
            .with_backend(tools_list_backend)
            .with_entrypoint(super::configure);

        let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).to_string();
        let response = tester.request(json_request(&body));
        assert_eq!(response.status_code(), 200);
        let text = String::from_utf8_lossy(response.body()).to_string();
        // Both tool descriptions now carry the lure.
        assert_eq!(text.matches(LURE).count(), 2);
        assert!(text.contains("Get the orders."));
    }

    #[test]
    fn following_the_breadcrumb_is_sanitized_in_sanitize_mode() {
        let backend = Rc::new(TraceBackend::new(ok_backend));
        let mut tester = UnitTestBuilder::default()
            .with_config(config("sanitize", true))
            .with_backend(Rc::clone(&backend))
            .with_entrypoint(super::configure);

        let body = json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "get_orders", "arguments": {"note": LURE}}
        })
        .to_string();
        let response = tester.request(json_request(&body));
        assert_eq!(response.status_code(), 200);

        // The lure is flagged and scrubbed before it reaches the upstream.
        let forwarded = backend.next().unwrap();
        assert_eq!(forwarded.header("x-agent-breadcrumb"), Some("followed"));
        let fwd_body = String::from_utf8_lossy(forwarded.body()).to_string();
        assert!(
            !fwd_body.contains(LURE),
            "breadcrumb must be stripped upstream"
        );
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
        let response = tester.request(json_request(&body));
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
        let response = tester.request(json_request(&body));
        assert_eq!(response.status_code(), 200);
        let forwarded = backend.next().unwrap();
        assert_eq!(forwarded.header("x-agent-breadcrumb"), None);
    }

    #[test]
    fn seeding_can_be_disabled() {
        let mut tester = UnitTestBuilder::default()
            .with_config(config("sanitize", false))
            .with_backend(tools_list_backend)
            .with_entrypoint(super::configure);

        let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).to_string();
        let response = tester.request(json_request(&body));
        let text = String::from_utf8_lossy(response.body()).to_string();
        assert!(!text.contains(LURE), "seeding disabled: response untouched");
    }

    #[test]
    fn observe_with_disabled_seeding_forwards_a_followed_lure_unchanged() {
        let backend = Rc::new(TraceBackend::new(ok_backend));
        let mut tester = UnitTestBuilder::default()
            .with_config(
                json!({
                    "breadcrumb": LURE,
                    "mode": "observe",
                    "seeding": "disabled",
                    "alertHeader": "x-agent-breadcrumb"
                })
                .to_string(),
            )
            .with_backend(Rc::clone(&backend))
            .with_entrypoint(super::configure);
        let body = json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "get_orders", "arguments": {"note": LURE}}
        })
        .to_string();

        let response = tester.request(json_request(&body));
        assert_eq!(response.status_code(), 200);
        let forwarded = backend.next().expect("observe forwards to upstream");
        assert_eq!(forwarded.body(), body.as_bytes());
        assert_eq!(forwarded.header("x-agent-breadcrumb"), Some("followed"));
    }
    #[test]
    fn failed_required_sanitize_never_forwards_original_body() {
        let backend = Rc::new(TraceBackend::new(ok_backend));
        let mut tester = UnitTestBuilder::default()
            .with_config(config("sanitize", false))
            .with_backend(Rc::clone(&backend))
            .with_property(
                vec![
                    "node",
                    "metadata",
                    "flex_env",
                    "FLEX_DOWNSTREAM_CONNECTION_BUFFER_LIMIT_BYTES",
                ],
                b"1",
            )
            .with_entrypoint(super::configure);
        let body = json!({"note":LURE,"other":"keep"}).to_string();
        let response = tester.request(
            UnitHttpRequest::post()
                .with_header("content-type", "application/json")
                .with_header("content-length", body.len().to_string())
                .with_body(body),
        );
        assert_eq!(response.status_code(), 500);
        assert!(
            backend.next().is_none(),
            "failed required sanitation must not forward"
        );
    }

    #[test]
    fn failed_optional_seeding_preserves_original_bytes_and_framing() {
        let body = r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"lookup"}]}}"#;
        let mut tester = UnitTestBuilder::default()
            .with_config(config("observe", true))
            .with_backend(move |_: UnitHttpRequest| {
                UnitHttpResponse::new(200)
                    .with_header("content-type", "application/json")
                    .with_header("content-length", body.len().to_string())
                    .with_body(body)
            })
            .with_property(
                vec![
                    "node",
                    "metadata",
                    "flex_env",
                    "FLEX_DOWNSTREAM_CONNECTION_BUFFER_LIMIT_BYTES",
                ],
                b"1",
            )
            .with_entrypoint(super::configure);
        let response = tester.request(json_request(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
        ));
        assert_eq!(response.body(), body.as_bytes());
        assert_eq!(
            response.header("content-length"),
            Some(body.len().to_string().as_str())
        );
    }

    fn json_request(body: &str) -> UnitHttpRequest {
        UnitHttpRequest::post()
            .with_header("content-type", "application/json")
            .with_header("content-length", body.len().to_string())
            .with_body(body)
    }

    fn marker_config(mode: &str, seed: bool) -> String {
        json!({"breadcrumb":"admin_override_do_not_use","mode":mode,
            "seeding":if seed {"enabled"} else {"disabled"},"alertHeader":"x-agent-breadcrumb"})
        .to_string()
    }

    #[test]
    fn escaped_marker_is_blocked_or_sanitized_as_decoded_json() {
        let body = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"\u0061dmin_override_do_not_use","arguments":{"keep":"yes"}}}"#;
        for mode in ["block", "sanitize"] {
            let backend = Rc::new(TraceBackend::new(ok_backend));
            let mut tester = UnitTestBuilder::default()
                .with_config(marker_config(mode, false))
                .with_backend(Rc::clone(&backend))
                .with_entrypoint(super::configure);
            let response = tester.request(json_request(body));
            if mode == "block" {
                assert_eq!(response.status_code(), 403);
                assert!(backend.next().is_none());
            } else {
                let forwarded = backend.next().unwrap();
                let value: serde_json::Value = serde_json::from_slice(forwarded.body()).unwrap();
                assert_eq!(value["params"]["name"], "");
                assert_eq!(value["params"]["arguments"]["keep"], "yes");
                assert_eq!(forwarded.header("content-length"), None);
            }
        }
    }

    #[test]
    fn enforcing_modes_reject_uninspectable_bodies_and_observe_preserves_bytes() {
        let body = b"\xffadmin_override_do_not_use";
        for mode in ["block", "sanitize", "observe"] {
            let backend = Rc::new(TraceBackend::new(ok_backend));
            let mut tester = UnitTestBuilder::default()
                .with_config(marker_config(mode, false))
                .with_backend(Rc::clone(&backend))
                .with_entrypoint(super::configure);
            let response = tester.request(
                UnitHttpRequest::post()
                    .with_header("content-type", "application/json")
                    .with_header("content-length", body.len().to_string())
                    .with_body(body),
            );
            if mode == "observe" {
                assert_eq!(backend.next().unwrap().body(), body);
            } else {
                assert_eq!(response.status_code(), 415);
                assert!(backend.next().is_none());
            }
        }
    }

    #[test]
    fn enforcing_modes_reject_encoding_streaming_unknown_or_forged_lengths() {
        for mode in ["block", "sanitize"] {
            for request in [
                json_request("{}").with_header("content-encoding", "gzip"),
                UnitHttpRequest::post()
                    .with_header("content-type", "text/event-stream")
                    .with_header("content-length", "2")
                    .with_body("{}"),
                UnitHttpRequest::post()
                    .with_header("content-type", "application/octet-stream")
                    .with_header("content-length", "2")
                    .with_body("{}"),
                UnitHttpRequest::post()
                    .with_header("content-type", "application/json")
                    .with_body("{}"),
                UnitHttpRequest::post()
                    .with_header("content-type", "application/json")
                    .with_header("content-length", "1")
                    .with_body("{}"),
                UnitHttpRequest::post()
                    .with_header("content-type", "application/json")
                    .with_header("content-length", "65537")
                    .with_body("{}"),
                UnitHttpRequest::post()
                    .with_header("content-type", "application/json")
                    .with_header("content-length", "invalid")
                    .with_body("{}"),
                UnitHttpRequest::post()
                    .with_header("content-type", "application/notjson")
                    .with_header("content-length", "2")
                    .with_body("{}"),
            ] {
                let backend = Rc::new(TraceBackend::new(ok_backend));
                let mut tester = UnitTestBuilder::default()
                    .with_config(marker_config(mode, false))
                    .with_backend(Rc::clone(&backend))
                    .with_entrypoint(super::configure);
                let response = tester.request(request);
                assert!(response.status_code() >= 400);
                assert!(backend.next().is_none());
            }
        }
    }

    #[test]
    fn seeding_requires_matching_tools_list_request_and_response() {
        for (request, response_body) in [
            (
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"lookup"}}"#,
                r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"lookup"}]}}"#,
            ),
            (
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
                r#"{"jsonrpc":"2.0","id":99,"result":{"tools":[{"name":"lookup"}]}}"#,
            ),
        ] {
            let mut tester = UnitTestBuilder::default()
                .with_config(marker_config("observe", true))
                .with_backend(move |_: UnitHttpRequest| {
                    UnitHttpResponse::new(200)
                        .with_header("content-type", "application/json")
                        .with_header("content-length", response_body.len().to_string())
                        .with_body(response_body)
                })
                .with_entrypoint(super::configure);
            let response = tester.request(json_request(request));
            assert_eq!(response.body(), response_body.as_bytes());
        }
    }

    #[test]
    fn optional_seeding_skips_streaming_and_encoded_responses() {
        let body = r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"lookup"}]}}"#;
        for (header, value) in [
            ("content-type", "text/event-stream"),
            ("content-encoding", "gzip"),
        ] {
            let mut tester = UnitTestBuilder::default()
                .with_config(marker_config("observe", true))
                .with_backend(move |_: UnitHttpRequest| {
                    UnitHttpResponse::new(200)
                        .with_header(
                            "content-type",
                            if header == "content-type" {
                                value
                            } else {
                                "application/json"
                            },
                        )
                        .with_header(
                            if header == "content-encoding" {
                                header
                            } else {
                                "x-test"
                            },
                            value,
                        )
                        .with_header("content-length", body.len().to_string())
                        .with_body(body)
                })
                .with_entrypoint(super::configure);
            let response = tester.request(json_request(
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
            ));
            assert_eq!(response.body(), body.as_bytes());
            assert_eq!(response.header(header), Some(value));
        }
    }
}
