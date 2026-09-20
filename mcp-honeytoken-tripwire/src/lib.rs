// Copyright (c) 2026 msaleme. Licensed under the MIT License.
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
use serde::de::{self, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::generated::config::Config;

/// Marker substituted for a honeytoken when it is stripped out of a response in
/// block mode, so the decoy value never leaves the gateway.
const REDACTION_MARKER: &str = "[decoy-withheld]";

/// JSON-RPC server-error code used when a policy prevents a request from
/// reaching its upstream tool. It intentionally matches the Sentinel policy.
const MCP_BLOCKED_CODE: i64 = -32008;

/// Maximum declared length eligible for inspection. This is an admission filter,
/// not an observed cap on bytes Flex buffers before exposing the body to PDK code.
const MAX_SCAN_BYTES: usize = 64 * 1024;

fn declared_body_length(value: Option<String>) -> Option<usize> {
    value
        .filter(|length| !length.is_empty() && length.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|length| length.parse::<usize>().ok())
}

fn is_json_content_type(value: Option<String>) -> bool {
    value.is_some_and(|content_type| {
        let media = content_type
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        media == "application/json"
            || (media.starts_with("application/") && media.ends_with("+json"))
    })
}

fn is_scannable_content_type(value: Option<String>) -> bool {
    // Legacy deployments may omit this header; preserve their existing behavior
    // while refusing to decode explicitly binary payloads as lossy UTF-8.
    value.is_none_or(|content_type| {
        let media = content_type
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        media == "application/json"
            || media == "text/plain"
            || (media.starts_with("application/") && media.ends_with("+json"))
    })
}

/// The response shape to preserve when Honeytoken blocks a parseable JSON-RPC
/// request. Non-JSON-RPC traffic intentionally remains on the generic policy
/// response path below.
struct ParsedJsonRpcRequest {
    is_batch: bool,
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

fn parse_jsonrpc_request(body: &[u8]) -> Option<ParsedJsonRpcRequest> {
    serde_json::from_slice::<NoDuplicateMembers>(body).ok()?;
    let root: Value = serde_json::from_slice(body).ok()?;
    let is_batch = matches!(root, Value::Array(_));
    let items: Vec<&Value> = match &root {
        Value::Array(items) if !items.is_empty() => items.iter().collect(),
        Value::Object(_) => vec![&root],
        _ => return None,
    };

    if items.iter().any(|item| {
        item.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
            || item.get("method").and_then(Value::as_str).is_none()
            || item
                .get("id")
                .is_some_and(|id| !matches!(id, Value::String(_) | Value::Number(_) | Value::Null))
    }) {
        return None;
    }

    Some(ParsedJsonRpcRequest {
        is_batch,
        response_ids: items
            .iter()
            .filter_map(|item| item.get("id").cloned())
            .collect(),
    })
}

fn blocked_jsonrpc_response(parsed: ParsedJsonRpcRequest, alert_header: &str) -> Response {
    if parsed.response_ids.is_empty() {
        return Response::new(202).with_headers([(
            alert_header.to_string(),
            "fired;direction=request".to_string(),
        )]);
    }

    let error = |id: Value| {
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": MCP_BLOCKED_CODE,
                "message": "request referenced a honeytoken decoy",
            }
        })
    };
    let body = if parsed.is_batch {
        Value::Array(parsed.response_ids.into_iter().map(error).collect()).to_string()
    } else {
        error(
            parsed
                .response_ids
                .into_iter()
                .next()
                .expect("response ID exists"),
        )
        .to_string()
    };

    Response::new(200)
        .with_headers([
            ("Content-Type".to_string(), "application/json".to_string()),
            (
                alert_header.to_string(),
                "fired;direction=request".to_string(),
            ),
        ])
        .with_body(body)
}

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
    /// Opaque operator-configured correlation value emitted to logs.
    id: String,
    /// Original configured value — only used for in-process matching/redaction.
    original: String,
    /// Search form: ASCII-lowercased when matching is case-insensitive, otherwise
    /// identical to `original`. Empty needles are dropped at build time.
    search: String,
    /// Whether `search` was lowercased (so the haystack must be folded to match).
    fold: bool,
}

impl Tripwire {
    fn from_config(config: &Config) -> Result<Self> {
        if config
            .honeytokens
            .iter()
            .any(|token| token.trim().is_empty())
        {
            return Err(anyhow!("honeytokens must not contain blank values"));
        }
        if let Some(ids) = config.decoy_ids.as_ref().filter(|ids| !ids.is_empty()) {
            if ids.len() != config.honeytokens.len() {
                return Err(anyhow!("decoyIds must contain one ID for each honeytoken"));
            }
            let mut seen = std::collections::HashSet::new();
            if ids
                .iter()
                .any(|id| id.trim().is_empty() || !seen.insert(id))
            {
                return Err(anyhow!("decoyIds must be non-blank and unique"));
            }
        }
        let case_sensitive = config.case_sensitive;
        let needles = config
            .honeytokens
            .iter()
            .enumerate()
            .filter_map(|(index, token)| {
                let t = token.trim();
                (!t.is_empty()).then(|| Needle {
                    id: config
                        .decoy_ids
                        .as_ref()
                        .and_then(|ids| ids.get(index))
                        .filter(|id| !id.trim().is_empty())
                        .cloned()
                        .unwrap_or_else(|| format!("unlabeled-decoy-{index}")),
                    original: t.to_string(),
                    search: if case_sensitive {
                        t.to_string()
                    } else {
                        t.to_ascii_lowercase()
                    },
                    fold: !case_sensitive,
                })
            })
            .collect();

        Ok(Self {
            needles,
            block: config.mode.eq_ignore_ascii_case("block"),
            alert_header: config.alert_header.clone(),
        })
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

    /// Detect honeytokens in every JSON string token (keys and values), preserving
    /// duplicate object members that a map-backed JSON representation would collapse.
    fn detect_json_strings<'a>(&'a self, input: &str) -> Option<&'a Needle> {
        json_string_ranges(input)?
            .into_iter()
            .find_map(|(start, end)| {
                serde_json::from_str::<String>(&input[start..end])
                    .ok()
                    .and_then(|decoded| self.detect(&decoded))
            })
    }

    /// Replaces every honeytoken occurrence in `input` with [`REDACTION_MARKER`].
    /// Matching mirrors [`detect`]: ASCII case-insensitive when configured, which
    /// is byte-length-stable so the folded index maps straight back onto `input`.
    fn redact(&self, input: &str) -> Option<String> {
        let mut out = input.to_string();
        let mut changed = false;
        for n in &self.needles {
            // Never make the wire body larger: a short configured honeytoken is
            // removed rather than replaced with a longer explanatory marker.
            let marker = if REDACTION_MARKER.len() <= n.original.len() {
                REDACTION_MARKER
            } else {
                ""
            };
            if n.fold {
                out = replace_ascii_ci(&out, &n.search, marker, &mut changed);
            } else if out.contains(&n.search) {
                out = out.replace(&n.search, marker);
                changed = true;
            }
        }
        changed.then_some(out)
    }

    /// Rewrite every JSON string literal on the wire. Duplicate members survive;
    /// each replacement is non-expanding so it remains writable under the original
    /// configured body limit.
    fn redact_json(&self, input: &str) -> Option<String> {
        let ranges = json_string_ranges(input)?;
        let mut cursor = 0;
        let mut out = Vec::with_capacity(input.len());
        let mut changed = false;
        for (start, end) in ranges {
            out.extend_from_slice(&input.as_bytes()[cursor..start]);
            let literal = &input[start..end];
            let decoded = serde_json::from_str::<String>(literal).ok()?;
            if let Some(clean) = self.redact(&decoded) {
                let encoded = serde_json::to_vec(&clean).ok()?;
                if encoded.len() <= literal.len() {
                    out.extend_from_slice(&encoded);
                } else {
                    out.extend_from_slice(b"\"\"");
                }
                changed = true;
            } else {
                out.extend_from_slice(literal.as_bytes());
            }
            cursor = end;
        }
        out.extend_from_slice(&input.as_bytes()[cursor..]);
        changed.then(|| String::from_utf8(out).expect("JSON rewriting emits UTF-8"))
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

/// Emits the structured anomaly without disclosing the matched honeytoken value.
fn emit_anomaly(direction: &str, needle: &Needle, action: &str) {
    let event = json!({
        "event": "agent_decoy_tripwire",
        "control": "NIST SC-26/SI-20",
        "direction": direction,
        "decoy_id": needle.id,
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

    let headers_state = request_state.into_headers_state().await;
    let declared_length = declared_body_length(headers_state.handler().header("content-length"));
    let content_type = headers_state.handler().header("content-type");
    let missing_content_type = content_type.is_none();
    let requires_json = is_json_content_type(content_type);
    let uninspectable = !is_scannable_content_type(headers_state.handler().header("content-type"))
        || headers_state.handler().header("content-encoding").is_some()
        || declared_length.is_none_or(|length| length > MAX_SCAN_BYTES);
    if !headers_state.contains_body() {
        return Flow::Continue(());
    }
    if uninspectable {
        if tripwire.block {
            return Flow::Break(
                Response::new(415)
                    .with_headers([(
                        tripwire.alert_header.clone(),
                        "rejected;reason=uninspectable-body".to_string(),
                    )])
                    .with_body("request body cannot be safely inspected"),
            );
        }
        return Flow::Continue(());
    }
    let declared_length = declared_length.expect("admitted request has a declared length");

    let state = headers_state.into_headers_body_state().await;
    let handler = state.handler();

    let body = handler.body();
    if body.is_empty() {
        return Flow::Continue(());
    }
    if body.len() != declared_length || body.len() > MAX_SCAN_BYTES {
        if tripwire.block {
            return Flow::Break(
                Response::new(413)
                    .with_headers([(
                        tripwire.alert_header.clone(),
                        "rejected;reason=invalid-body-framing".to_string(),
                    )])
                    .with_body("request body framing is invalid"),
            );
        }
        return Flow::Continue(());
    }
    let text = match std::str::from_utf8(&body) {
        Ok(text) => text,
        Err(_) if tripwire.block => {
            return Flow::Break(
                Response::new(415)
                    .with_headers([(
                        tripwire.alert_header.clone(),
                        "rejected;reason=invalid-utf8".to_string(),
                    )])
                    .with_body("request body cannot be safely inspected"),
            );
        }
        Err(_) => return Flow::Continue(()),
    };

    // Parse limits are inspection limits, not evidence that a JSON body is clean.
    // Keep serde's bounded parser and reject unsupported JSON before raw matching.
    if (requires_json || (missing_content_type && text.trim_start().starts_with(['{', '['])))
        && tripwire.block
        && serde_json::from_str::<Value>(text).is_err()
    {
        return Flow::Break(
            Response::new(415)
                .with_headers([(
                    tripwire.alert_header.clone(),
                    "rejected;reason=uninspectable-json".to_string(),
                )])
                .with_body("request JSON cannot be safely inspected"),
        );
    }

    let hit = match tripwire.detect(text).or_else(|| {
        serde_json::from_str::<Value>(text)
            .ok()
            .and_then(|_| tripwire.detect_json_strings(text))
    }) {
        Some(n) => n,
        None => return Flow::Continue(()),
    };

    let action = if tripwire.block { "blocked" } else { "flagged" };
    emit_anomaly("request", hit, action);
    handler.set_header(&tripwire.alert_header, "fired;direction=request");

    if tripwire.block {
        if let Some(parsed) = parse_jsonrpc_request(&body) {
            Flow::Break(blocked_jsonrpc_response(parsed, &tripwire.alert_header))
        } else {
            Flow::Break(
                Response::new(403)
                    .with_headers([
                        ("Content-Type".to_string(), "application/json".to_string()),
                        (
                            tripwire.alert_header.clone(),
                            "fired;direction=request".to_string(),
                        ),
                    ])
                    .with_body(
                        json!({
                            "error": "request referenced a honeytoken decoy",
                            "control": "NIST SC-26/SI-20",
                        })
                        .to_string(),
                    ),
            )
        }
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

    let headers_state = response_state.into_headers_state().await;
    let declared_length = declared_body_length(headers_state.handler().header("content-length"));
    let content_type = headers_state.handler().header("content-type");
    let missing_content_type = content_type.is_none();
    let requires_json = is_json_content_type(content_type);
    let uninspectable = !is_scannable_content_type(headers_state.handler().header("content-type"))
        || headers_state.handler().header("content-encoding").is_some()
        || declared_length.is_none_or(|length| length > MAX_SCAN_BYTES);
    if !headers_state.contains_body() {
        return;
    }
    if uninspectable {
        if tripwire.block {
            let state = headers_state.into_headers_body_state().await;
            let handler = state.handler();
            handler.set_header(&tripwire.alert_header, "withheld;reason=uninspectable-body");
            if let Err(err) = handler.set_body(b"") {
                logger::error!("Unable to withhold uninspectable response: {err:?}");
                return;
            }
            handler.remove_header("content-length");
            handler.remove_header("content-encoding");
        }
        return;
    }
    let declared_length = declared_length.expect("admitted response has a declared length");

    let state = headers_state.into_headers_body_state().await;
    let handler = state.handler();

    let body = handler.body();
    if body.is_empty() {
        return;
    }
    if body.len() != declared_length || body.len() > MAX_SCAN_BYTES {
        if tripwire.block {
            handler.set_header(&tripwire.alert_header, "fired;direction=response");
            if let Err(err) = handler.set_body(b"") {
                logger::error!("Unable to withhold invalidly framed response: {err:?}");
                return;
            }
            handler.remove_header("content-length");
            handler.remove_header("content-encoding");
        }
        return;
    }
    let text = match std::str::from_utf8(&body) {
        Ok(text) => text,
        Err(_) if tripwire.block => {
            handler.set_header(&tripwire.alert_header, "withheld;reason=invalid-utf8");
            if let Err(err) = handler.set_body(b"") {
                logger::error!("Unable to withhold invalid UTF-8 response: {err:?}");
                return;
            }
            handler.remove_header("content-length");
            handler.remove_header("content-encoding");
            return;
        }
        Err(_) => return,
    };

    if (requires_json || (missing_content_type && text.trim_start().starts_with(['{', '['])))
        && tripwire.block
        && serde_json::from_str::<Value>(text).is_err()
    {
        handler.set_header(&tripwire.alert_header, "withheld;reason=uninspectable-json");
        if let Err(err) = handler.set_body(b"") {
            logger::error!("Unable to withhold uninspectable JSON response: {err:?}");
            return;
        }
        handler.remove_header("content-length");
        handler.remove_header("content-encoding");
        return;
    }

    let hit = match tripwire.detect(text).or_else(|| {
        serde_json::from_str::<Value>(text)
            .ok()
            .and_then(|_| tripwire.detect_json_strings(text))
    }) {
        Some(n) => n,
        None => return,
    };

    let action = if tripwire.block {
        "redacted"
    } else {
        "flagged"
    };
    emit_anomaly("response", hit, action);
    handler.set_header(&tripwire.alert_header, "fired;direction=response");

    if tripwire.block {
        let clean = if json_string_ranges(text).is_some() {
            // A raw hit in valid JSON that did not occur in a string literal is
            // a primitive token. Replacing it with a marker could expand the body;
            // withhold the complete response instead of forwarding the decoy.
            tripwire.redact_json(text).or_else(|| Some(String::new()))
        } else {
            tripwire.redact(text)
        };
        if let Some(mut clean) = clean {
            // String edits can leave primitive matches or create new matches at
            // splice boundaries. Never accept a replacement without rescanning.
            if tripwire
                .detect(&clean)
                .or_else(|| tripwire.detect_json_strings(&clean))
                .is_some()
            {
                clean.clear();
            }
            let bytes = clean.into_bytes();
            if let Err(err) = handler.set_body(&bytes) {
                logger::error!("Unable to strip honeytoken from response: {err:?}");
                if let Err(withhold_err) = handler.set_body(b"") {
                    logger::error!(
                        "Unable to withhold response after redaction failure: {withhold_err:?}"
                    );
                    return;
                }
            }
            // The original framing no longer describes the successfully rewritten
            // bytes, including the fail-closed empty-body fallback.
            handler.remove_header("content-length");
            handler.remove_header("content-encoding");
        }
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

    let tripwire = Tripwire::from_config(&config)?;
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
    use serde_json::{json, Value};
    use std::rc::Rc;

    const DECOY: &str = "acct_DECOY_9x1f-do-not-use";

    fn monitor_config() -> String {
        json!({
            "honeytokens": [DECOY],
            "decoyIds": ["test-decoy"],
            "mode": "monitor",
            "alertHeader": "x-agent-decoy-tripwire",
            "caseSensitive": false
        })
        .to_string()
    }

    fn block_config() -> String {
        json!({
            "honeytokens": [DECOY],
            "decoyIds": ["test-decoy"],
            "mode": "block",
            "alertHeader": "x-agent-decoy-tripwire",
            "caseSensitive": false
        })
        .to_string()
    }

    fn json_request(body: impl AsRef<str>) -> UnitHttpRequest {
        let body = body.as_ref();
        UnitHttpRequest::post()
            .with_header("content-type", "application/json")
            .with_header("content-length", body.len().to_string())
            .with_body(body)
    }

    // Backend that echoes the decoy back in the response body, simulating a tool
    // result that carries the planted honeytoken.
    fn leaking_backend(_req: UnitHttpRequest) -> UnitHttpResponse {
        let body = format!("{{\"record\":\"{DECOY}\"}}");
        UnitHttpResponse::new(200)
            .with_header("content-type", "application/json")
            .with_header("content-length", body.len().to_string())
            .with_body(body.as_bytes())
    }

    fn leaking_backend_unknown_length(_req: UnitHttpRequest) -> UnitHttpResponse {
        UnitHttpResponse::new(200).with_body(format!("{{\"record\":\"{DECOY}\"}}").as_bytes())
    }

    fn clean_backend(_req: UnitHttpRequest) -> UnitHttpResponse {
        UnitHttpResponse::new(200).with_body(b"{\"record\":\"acct_real_customer\"}")
    }

    fn leaking_backend_with_content_length(_req: UnitHttpRequest) -> UnitHttpResponse {
        let body = format!("{{\"record\":\"{DECOY}\"}}");
        UnitHttpResponse::new(200)
            .with_header("content-type", "application/json")
            .with_header("content-length", body.len().to_string())
            .with_body(body.as_bytes())
    }

    fn binary_backend_containing_decoy(_req: UnitHttpRequest) -> UnitHttpResponse {
        UnitHttpResponse::new(200)
            .with_header("content-type", "application/octet-stream")
            .with_body(format!("binary:{DECOY}").as_bytes())
    }

    fn oversized_json_backend_containing_decoy(_req: UnitHttpRequest) -> UnitHttpResponse {
        let body = format!("{{\"record\":\"{DECOY}\"}}");
        UnitHttpResponse::new(200)
            .with_header("content-type", "application/json")
            .with_header("content-length", "65537")
            .with_body(body.as_bytes())
    }

    fn forged_short_length_response_backend(_req: UnitHttpRequest) -> UnitHttpResponse {
        let body = format!(
            "{{\"record\":\"{DECOY}\",\"padding\":\"{}\"}}",
            "x".repeat(super::MAX_SCAN_BYTES)
        );
        UnitHttpResponse::new(200)
            .with_header("content-type", "application/json")
            .with_header("content-length", "1")
            .with_body(body.as_bytes())
    }

    fn encoded_json_backend_containing_decoy(_req: UnitHttpRequest) -> UnitHttpResponse {
        let body = format!("{{\"record\":\"{DECOY}\"}}");
        UnitHttpResponse::new(200)
            .with_header("content-type", "application/json")
            .with_header("content-encoding", "gzip")
            .with_header("content-length", body.len().to_string())
            .with_body(body.as_bytes())
    }

    fn unicode_escaped_honeytoken_backend(_req: UnitHttpRequest) -> UnitHttpResponse {
        let body = "{\"record\":\"acct_\\u0044ECOY_9x1f-do-not-use\"}";
        UnitHttpResponse::new(200)
            .with_header("content-type", "application/json")
            .with_header("content-length", body.len().to_string())
            .with_body(body.as_bytes())
    }

    fn boolean_honeytoken_backend(_req: UnitHttpRequest) -> UnitHttpResponse {
        let body = "{\"enabled\":true}";
        UnitHttpResponse::new(200)
            .with_header("content-type", "application/json")
            .with_header("content-length", body.len().to_string())
            .with_body(body.as_bytes())
    }

    fn leaking_backend_with_spoofed_request_alert(_req: UnitHttpRequest) -> UnitHttpResponse {
        let body = format!("{{\"record\":\"{DECOY}\"}}");
        UnitHttpResponse::new(200)
            .with_header("content-type", "application/json")
            .with_header("content-length", body.len().to_string())
            .with_header("x-agent-decoy-tripwire", "fired;direction=request")
            .with_body(body.as_bytes())
    }

    fn invalid_utf8_json_backend(_req: UnitHttpRequest) -> UnitHttpResponse {
        let body = b"{\"record\":\"acct_DECOY_9x1f-do-not-use\"}\xff";
        UnitHttpResponse::new(200)
            .with_header("content-type", "application/json")
            .with_header("content-length", body.len().to_string())
            .with_body(body)
    }

    fn mixed_raw_and_escaped_honeytoken_backend(_req: UnitHttpRequest) -> UnitHttpResponse {
        let body = "{\"first\":\"acct_DECOY_9x1f-do-not-use\",\"second\":\"acct_\\u0044ECOY_9x1f-do-not-use\"}";
        UnitHttpResponse::new(200)
            .with_header("content-type", "application/json")
            .with_header("content-length", body.len().to_string())
            .with_body(body.as_bytes())
    }

    fn duplicate_key_escaped_honeytoken_backend(_req: UnitHttpRequest) -> UnitHttpResponse {
        let body = "{\"record\":\"acct_\\u0044ECOY_9x1f-do-not-use\",\"record\":\"clean\"}";
        UnitHttpResponse::new(200)
            .with_header("content-type", "application/json")
            .with_header("content-length", body.len().to_string())
            .with_body(body.as_bytes())
    }

    #[test]
    fn clean_request_passes_in_monitor_mode() {
        let mut tester = UnitTestBuilder::default()
            .with_config(monitor_config())
            .with_backend(clean_backend)
            .with_entrypoint(super::configure);

        let response = tester.request(json_request("{\"tool\":\"get_orders\",\"arg\":\"normal\"}"));
        assert_eq!(response.status_code(), 200);
    }

    #[test]
    fn request_referencing_decoy_is_flagged_not_blocked_in_monitor_mode() {
        let backend = Rc::new(TraceBackend::new(clean_backend));
        let mut tester = UnitTestBuilder::default()
            .with_config(monitor_config())
            .with_backend(Rc::clone(&backend))
            .with_entrypoint(super::configure);

        let response = tester.request(json_request(format!("{{\"lookup\":\"{DECOY}\"}}")));
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
    fn encoded_request_is_rejected_in_block_mode_before_upstream() {
        let backend = Rc::new(TraceBackend::new(clean_backend));
        let mut tester = UnitTestBuilder::default()
            .with_config(block_config())
            .with_backend(Rc::clone(&backend))
            .with_entrypoint(super::configure);
        let body = format!("{{\"lookup\":\"{DECOY}\"}}");

        let response = tester.request(
            UnitHttpRequest::post()
                .with_header("content-type", "application/json")
                .with_header("content-encoding", "gzip")
                .with_header("content-length", body.len().to_string())
                .with_body(body),
        );
        assert_eq!(response.status_code(), 415);
        assert!(
            backend.next().is_none(),
            "uninspectable body must not reach upstream"
        );
    }

    #[test]
    fn oversized_request_is_rejected_in_block_mode_before_upstream() {
        let backend = Rc::new(TraceBackend::new(clean_backend));
        let mut tester = UnitTestBuilder::default()
            .with_config(block_config())
            .with_backend(Rc::clone(&backend))
            .with_entrypoint(super::configure);

        let response = tester.request(
            UnitHttpRequest::post()
                .with_header("content-type", "application/json")
                .with_header("content-length", "65537")
                .with_body(format!("{{\"lookup\":\"{DECOY}\"}}")),
        );
        assert_eq!(response.status_code(), 415);
        assert!(
            backend.next().is_none(),
            "oversized body must not reach upstream"
        );
    }

    #[test]
    fn unicode_escaped_honeytoken_object_key_is_blocked() {
        let mut tester = UnitTestBuilder::default()
            .with_config(block_config())
            .with_backend(clean_backend)
            .with_entrypoint(super::configure);
        let escaped = "{\"acct_\\u0044ECOY_9x1f-do-not-use\":\"value\"}";

        let response = tester.request(json_request(escaped));
        assert_eq!(response.status_code(), 403);
    }

    #[test]
    fn unicode_escaped_honeytoken_request_is_blocked() {
        let mut tester = UnitTestBuilder::default()
            .with_config(block_config())
            .with_backend(clean_backend)
            .with_entrypoint(super::configure);
        let escaped = "{\"lookup\":\"acct_\\u0044ECOY_9x1f-do-not-use\"}";

        let response = tester.request(json_request(escaped));
        assert_eq!(response.status_code(), 403);
    }

    #[test]
    fn request_referencing_decoy_is_blocked_in_block_mode() {
        let mut tester = UnitTestBuilder::default()
            .with_config(block_config())
            .with_backend(clean_backend)
            .with_entrypoint(super::configure);

        let response = tester.request(json_request(format!("{{\"lookup\":\"{DECOY}\"}}")));
        assert_eq!(response.status_code(), 403);
        assert!(
            response.body().is_empty(),
            "response filtering must not trust a request alert header as provenance"
        );
    }

    #[test]
    fn mcp_request_referencing_decoy_returns_in_band_jsonrpc_error() {
        let mut tester = UnitTestBuilder::default()
            .with_config(block_config())
            .with_backend(clean_backend)
            .with_entrypoint(super::configure);
        let request = json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {"name": "lookup", "arguments": {"account": DECOY}}
        })
        .to_string();

        let response = tester.request(json_request(request));
        assert_eq!(response.status_code(), 200);
        assert_eq!(response.header("content-type"), Some("application/json"));
        assert!(
            response.body().is_empty(),
            "strict response containment withholds the local block envelope"
        );
    }

    #[test]
    fn mcp_notification_referencing_decoy_returns_202_without_body() {
        let mut tester = UnitTestBuilder::default()
            .with_config(block_config())
            .with_backend(clean_backend)
            .with_entrypoint(super::configure);
        let notification = json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "lookup", "arguments": {"account": DECOY}}
        })
        .to_string();

        let response = tester.request(json_request(notification));
        assert_eq!(response.status_code(), 202);
        assert!(response.body().is_empty());
    }

    #[test]
    fn mcp_batch_referencing_decoy_is_atomically_withheld_after_block() {
        let mut tester = UnitTestBuilder::default()
            .with_config(block_config())
            .with_backend(clean_backend)
            .with_entrypoint(super::configure);
        let batch = json!([
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "lookup", "arguments": {}}},
            {"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": {"name": "lookup", "arguments": {"account": DECOY}}}
        ])
        .to_string();

        let response = tester.request(json_request(batch));
        assert_eq!(response.status_code(), 200);
        assert!(response.body().is_empty());
    }

    #[test]
    fn duplicate_jsonrpc_protocol_member_uses_generic_fail_closed_response() {
        let mut tester = UnitTestBuilder::default()
            .with_config(block_config())
            .with_backend(clean_backend)
            .with_entrypoint(super::configure);
        let request = format!(
            r#"{{"jsonrpc":"2.0","jsonrpc":"2.0","id":7,"method":"tools/call","params":{{"account":"{DECOY}"}}}}"#
        );
        let response = tester.request(json_request(request));
        assert_eq!(response.status_code(), 403);
    }

    #[test]
    fn mixed_invalid_batch_referencing_decoy_keeps_generic_block_response() {
        let mut tester = UnitTestBuilder::default()
            .with_config(block_config())
            .with_backend(clean_backend)
            .with_entrypoint(super::configure);
        let batch = json!([
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "lookup", "arguments": {}}},
            {"id": 9, "method": "tools/call", "params": {"name": "lookup", "arguments": {"account": DECOY}}}
        ])
        .to_string();

        let response = tester.request(json_request(batch));
        assert_eq!(response.status_code(), 403);
        assert!(response.body().is_empty());
    }

    #[test]
    fn case_variant_still_trips_when_case_insensitive() {
        let mut tester = UnitTestBuilder::default()
            .with_config(block_config())
            .with_backend(clean_backend)
            .with_entrypoint(super::configure);

        let response = tester.request(json_request(format!(
            "{{\"lookup\":\"{}\"}}",
            DECOY.to_uppercase()
        )));
        assert_eq!(response.status_code(), 403);
    }

    #[test]
    fn decoy_is_stripped_from_response_in_block_mode() {
        let backend = Rc::new(TraceBackend::new(leaking_backend));
        let mut tester = UnitTestBuilder::default()
            .with_config(block_config())
            .with_backend(Rc::clone(&backend))
            .with_entrypoint(super::configure);

        let response = tester.request(json_request("{\"tool\":\"read\"}"));
        assert_eq!(response.status_code(), 200);
        let body = String::from_utf8_lossy(response.body()).to_string();
        assert!(!body.contains(DECOY), "decoy must not leave the gateway");
        assert!(body.contains("[decoy-withheld]"));
        assert_eq!(
            response.header("x-agent-decoy-tripwire"),
            Some("fired;direction=response")
        );
    }

    #[test]
    fn binary_response_is_withheld_in_block_mode() {
        let mut tester = UnitTestBuilder::default()
            .with_config(block_config())
            .with_backend(binary_backend_containing_decoy)
            .with_entrypoint(super::configure);

        let response = tester.request(json_request("{\"tool\":\"read\"}"));
        assert!(response.body().is_empty());
        assert_eq!(
            response.header("x-agent-decoy-tripwire"),
            Some("withheld;reason=uninspectable-body")
        );
    }

    #[test]
    fn short_honeytoken_redaction_does_not_expand_body() {
        let config: super::Config = serde_json::from_value(json!({
            "honeytokens": ["x"],
            "decoyIds": ["short-decoy"],
            "mode": "block",
            "alertHeader": "x-agent-decoy-tripwire",
            "caseSensitive": true
        }))
        .expect("test config parses");
        let tripwire = super::Tripwire::from_config(&config).expect("valid test config");
        let redacted = tripwire.redact("x").expect("token is redacted");
        assert_eq!(redacted, "");
        assert!(redacted.len() <= 1);
    }

    #[test]
    fn duplicate_key_escaped_honeytoken_response_is_redacted_without_collapsing_members() {
        let mut tester = UnitTestBuilder::default()
            .with_config(block_config())
            .with_backend(duplicate_key_escaped_honeytoken_backend)
            .with_entrypoint(super::configure);

        let response = tester.request(json_request("{\"tool\":\"read\"}"));
        let body = std::str::from_utf8(response.body()).expect("rewritten JSON is UTF-8");
        assert_eq!(response.status_code(), 200);
        assert!(!body.contains(DECOY));
        assert!(!body.contains("acct_\\u0044ECOY_9x1f-do-not-use"));
        assert_eq!(
            body.matches("\"record\"").count(),
            2,
            "duplicate members survive"
        );
        assert_eq!(response.header("content-length"), None);
    }

    #[test]
    fn mixed_raw_and_escaped_honeytokens_response_is_fully_redacted() {
        let mut tester = UnitTestBuilder::default()
            .with_config(block_config())
            .with_backend(mixed_raw_and_escaped_honeytoken_backend)
            .with_entrypoint(super::configure);

        let response = tester.request(json_request("{\"tool\":\"read\"}"));
        let body = std::str::from_utf8(response.body()).expect("redacted JSON is UTF-8");

        assert_eq!(response.status_code(), 200);
        assert!(!body.contains("acct_DECOY_9x1f-do-not-use"));
        assert!(!body.contains("acct_\\u0044ECOY_9x1f-do-not-use"));
        assert_eq!(
            serde_json::from_str::<Value>(body).expect("redacted body is JSON")["first"],
            super::REDACTION_MARKER
        );
        assert_eq!(
            serde_json::from_str::<Value>(body).expect("redacted body is JSON")["second"],
            super::REDACTION_MARKER
        );
    }

    #[test]
    fn upstream_spoofed_request_alert_does_not_bypass_response_containment() {
        let mut tester = UnitTestBuilder::default()
            .with_config(block_config())
            .with_backend(leaking_backend_with_spoofed_request_alert)
            .with_entrypoint(super::configure);

        let response = tester.request(json_request("{\"tool\":\"read\"}"));
        assert!(
            response.body().is_empty()
                || !response
                    .body()
                    .windows(DECOY.len())
                    .any(|window| window == DECOY.as_bytes())
        );
    }

    #[test]
    fn invalid_utf8_request_with_decoy_is_rejected_before_upstream() {
        let backend = Rc::new(TraceBackend::new(clean_backend));
        let body = [format!("{{\"lookup\":\"{DECOY}\"}}").as_bytes(), b"\xff"].concat();
        let request = UnitHttpRequest::post()
            .with_header("content-type", "application/json")
            .with_header("content-length", body.len().to_string())
            .with_body(body);
        let mut tester = UnitTestBuilder::default()
            .with_config(block_config())
            .with_backend(Rc::clone(&backend))
            .with_entrypoint(super::configure);

        let response = tester.request(request);
        assert_eq!(response.status_code(), 415);
        assert!(
            backend.next().is_none(),
            "invalid UTF-8 must not reach upstream in block mode"
        );
    }

    #[test]
    fn invalid_utf8_response_is_withheld_in_block_mode() {
        let mut tester = UnitTestBuilder::default()
            .with_config(block_config())
            .with_backend(invalid_utf8_json_backend)
            .with_entrypoint(super::configure);

        let response = tester.request(json_request("{\"tool\":\"read\"}"));
        assert!(response.body().is_empty());
        assert_eq!(
            response.header("x-agent-decoy-tripwire"),
            Some("withheld;reason=invalid-utf8")
        );
        assert_eq!(response.header("content-length"), None);
    }

    #[test]
    fn invalid_utf8_response_passes_byte_for_byte_in_monitor_mode() {
        let mut tester = UnitTestBuilder::default()
            .with_config(monitor_config())
            .with_backend(invalid_utf8_json_backend)
            .with_entrypoint(super::configure);

        let response = tester.request(json_request("{\"tool\":\"read\"}"));
        assert_eq!(
            response.body(),
            b"{\"record\":\"acct_DECOY_9x1f-do-not-use\"}\xff"
        );
    }

    #[test]
    fn primitive_json_honeytoken_is_withheld_without_expanding_the_body() {
        let config = json!({
            "honeytokens": ["true"],
            "decoyIds": ["boolean-decoy"],
            "mode": "block",
            "alertHeader": "x-agent-decoy-tripwire",
            "caseSensitive": true
        })
        .to_string();
        let mut tester = UnitTestBuilder::default()
            .with_config(config)
            .with_backend(boolean_honeytoken_backend)
            .with_entrypoint(super::configure);

        let response = tester.request(json_request("{\"tool\":\"read\"}"));
        assert!(
            response.body().is_empty(),
            "primitive decoy must not leave the gateway"
        );
        assert_eq!(response.header("content-length"), None);
    }

    #[test]
    fn unicode_escaped_honeytoken_response_is_redacted() {
        let mut tester = UnitTestBuilder::default()
            .with_config(block_config())
            .with_backend(unicode_escaped_honeytoken_backend)
            .with_entrypoint(super::configure);

        let response = tester.request(json_request("{\"tool\":\"read\"}"));
        let body = String::from_utf8_lossy(response.body());
        assert!(!body.contains("acct_\\u0044ECOY_9x1f-do-not-use"));
        assert!(body.contains(super::REDACTION_MARKER));
    }

    #[test]
    fn encoded_response_is_withheld_in_block_mode() {
        let mut tester = UnitTestBuilder::default()
            .with_config(block_config())
            .with_backend(encoded_json_backend_containing_decoy)
            .with_entrypoint(super::configure);

        let response = tester.request(json_request("{\"tool\":\"read\"}"));
        assert!(response.body().is_empty());
        assert_eq!(response.header("content-encoding"), None);
        assert_eq!(
            response.header("x-agent-decoy-tripwire"),
            Some("withheld;reason=uninspectable-body")
        );
    }

    #[test]
    fn unknown_length_response_is_withheld_in_block_mode() {
        let mut tester = UnitTestBuilder::default()
            .with_config(block_config())
            .with_backend(leaking_backend_unknown_length)
            .with_entrypoint(super::configure);

        let response = tester.request(json_request("{\"tool\":\"read\"}"));
        assert!(response.body().is_empty());
        assert_eq!(
            response.header("x-agent-decoy-tripwire"),
            Some("withheld;reason=uninspectable-body")
        );
    }

    #[test]
    fn response_redaction_falls_back_to_empty_body_when_pdk_rejects_rewrite() {
        let mut tester = UnitTestBuilder::default()
            .with_config(block_config())
            .with_backend(leaking_backend_with_content_length)
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

        let response = tester.request(json_request("{\"tool\":\"read\"}"));
        assert!(
            response.body().is_empty(),
            "fallback must withhold the decoy"
        );
        assert_eq!(response.header("content-length"), None);
        assert_eq!(response.header("content-encoding"), None);
    }

    #[test]
    fn forged_short_response_content_length_is_withheld_in_block_mode() {
        let mut tester = UnitTestBuilder::default()
            .with_config(block_config())
            .with_backend(forged_short_length_response_backend)
            .with_entrypoint(super::configure);

        let response = tester.request(json_request("{\"tool\":\"read\"}"));
        assert!(
            response.body().is_empty(),
            "invalidly framed response is withheld"
        );
        assert_eq!(
            response.header("x-agent-decoy-tripwire"),
            Some("fired;direction=response")
        );
        assert_eq!(response.header("content-length"), None);
        assert_eq!(response.header("content-encoding"), None);
    }

    #[test]
    fn oversized_response_is_withheld_in_block_mode() {
        let mut tester = UnitTestBuilder::default()
            .with_config(block_config())
            .with_backend(oversized_json_backend_containing_decoy)
            .with_entrypoint(super::configure);

        let response = tester.request(json_request("{\"tool\":\"read\"}"));
        assert!(response.body().is_empty());
        assert_eq!(
            response.header("x-agent-decoy-tripwire"),
            Some("withheld;reason=uninspectable-body")
        );
    }

    #[test]
    fn response_rewrite_removes_stale_content_length() {
        let mut tester = UnitTestBuilder::default()
            .with_config(block_config())
            .with_backend(leaking_backend_with_content_length)
            .with_entrypoint(super::configure);

        let response = tester.request(json_request("{\"tool\":\"read\"}"));
        assert!(!String::from_utf8_lossy(response.body()).contains(DECOY));
        assert_eq!(response.header("content-length"), None);
        assert_eq!(response.header("content-encoding"), None);
    }

    #[test]
    fn forged_short_content_length_is_rejected_before_a_block_mode_request_reaches_upstream() {
        let backend = Rc::new(TraceBackend::new(clean_backend));
        let mut tester = UnitTestBuilder::default()
            .with_config(block_config())
            .with_backend(Rc::clone(&backend))
            .with_entrypoint(super::configure);
        let body = format!(
            "{{\"lookup\":\"{DECOY}\",\"padding\":\"{}\"}}",
            "x".repeat(super::MAX_SCAN_BYTES)
        );

        let response = tester.request(
            UnitHttpRequest::post()
                .with_header("content-type", "application/json")
                .with_header("content-length", "1")
                .with_body(body),
        );
        assert_eq!(response.status_code(), 413);
        assert!(
            backend.next().is_none(),
            "invalid framing must not reach upstream"
        );
    }

    #[test]
    fn decoy_in_response_is_flagged_but_kept_in_monitor_mode() {
        let mut tester = UnitTestBuilder::default()
            .with_config(monitor_config())
            .with_backend(leaking_backend)
            .with_entrypoint(super::configure);

        let response = tester.request(json_request("{\"tool\":\"read\"}"));
        assert_eq!(response.status_code(), 200);
        let body = String::from_utf8_lossy(response.body()).to_string();
        // Monitor = Expose only: we flag it, we do not alter the payload.
        assert!(body.contains(DECOY));
        assert_eq!(
            response.header("x-agent-decoy-tripwire"),
            Some("fired;direction=response")
        );
    }
    #[test]
    fn mixed_string_and_primitive_response_is_fully_contained() {
        for body in [
            r#"{"text":"12345","record_id":12345}"#,
            r#"{"text":"true","flag":true}"#,
        ] {
            let token = if body.contains("12345") {
                "12345"
            } else {
                "true"
            };
            let response_body = body.to_string();
            let mut tester = UnitTestBuilder::default()
                .with_config(json!({"honeytokens":[token],"decoyIds":["mixed"],"mode":"block","alertHeader":"x-agent-decoy-tripwire","caseSensitive":false}).to_string())
                .with_backend(move |_: UnitHttpRequest| UnitHttpResponse::new(200)
                    .with_header("content-type", "application/json")
                    .with_header("content-length", response_body.len().to_string())
                    .with_body(response_body.as_bytes()))
                .with_entrypoint(super::configure);
            let response = tester.request(json_request("{}"));
            assert!(
                response.body().is_empty(),
                "residual primitive must withhold the entire response"
            );
        }
    }

    #[test]
    fn redaction_created_token_is_not_forwarded() {
        let mut tester = UnitTestBuilder::default()
            .with_config(json!({"honeytokens":["X","abcd"],"decoyIds":["one","two"],"mode":"block","alertHeader":"x-agent-decoy-tripwire","caseSensitive":false}).to_string())
            .with_backend(|_: UnitHttpRequest| {
                let body = r#"{"text":"abXcd"}"#;
                UnitHttpResponse::new(200).with_header("content-type","application/json")
                    .with_header("content-length",body.len().to_string()).with_body(body)
            }).with_entrypoint(super::configure);
        let response = tester.request(json_request("{}"));
        assert!(!String::from_utf8_lossy(response.body()).contains("abcd"));
    }

    #[test]
    fn misleading_json_and_sse_media_types_are_uninspectable() {
        for content_type in ["application/notjson", "text/event-stream", "text/html"] {
            let backend = Rc::new(TraceBackend::new(clean_backend));
            let mut tester = UnitTestBuilder::default()
                .with_config(block_config())
                .with_backend(Rc::clone(&backend))
                .with_entrypoint(super::configure);
            let response = tester.request(
                UnitHttpRequest::post()
                    .with_header("content-type", content_type)
                    .with_header("content-length", "2")
                    .with_body("{}"),
            );
            assert_eq!(response.status_code(), 415);
            assert!(backend.next().is_none());
        }
    }
    #[test]
    fn gateway_default_empty_decoy_ids_uses_opaque_fallback_labels() {
        // Flex fills the schema's [] default before passing configuration to PDK.
        let config: super::Config = serde_json::from_value(json!({
            "honeytokens":[DECOY], "decoyIds":[], "mode":"block",
            "alertHeader":"x-agent-decoy-tripwire", "caseSensitive":false
        }))
        .unwrap();
        let tripwire = super::Tripwire::from_config(&config).expect("schema default must load");
        assert_eq!(tripwire.needles[0].id, "unlabeled-decoy-0");
        assert!(tripwire.detect(DECOY).is_some());
    }

    #[test]
    fn explicit_decoy_ids_still_require_complete_unique_nonblank_labels() {
        for ids in [json!(["one"]), json!(["one", "one"]), json!(["one", ""])] {
            let config: super::Config = serde_json::from_value(json!({
                "honeytokens":["first","second"], "decoyIds":ids, "mode":"block",
                "alertHeader":"x-agent-decoy-tripwire", "caseSensitive":false
            }))
            .unwrap();
            assert!(super::Tripwire::from_config(&config).is_err());
        }
    }
    fn unsupported_json_cases() -> Vec<String> {
        [r"\u0061cct_DECOY_9x1f-do-not-use", "clean"]
            .iter()
            .flat_map(|token| {
                [
                    format!(
                        r#"{{"token":"{token}","padding":{}0{}}}"#,
                        "[".repeat(128),
                        "]".repeat(128)
                    ),
                    format!(r#"{{"token":"{token}","padding":1e400}}"#),
                    format!(r#"{{"token":"{token}","padding":}}"#),
                ]
            })
            .collect()
    }

    #[test]
    fn unsupported_json_requests_fail_closed_in_block_mode() {
        for body in unsupported_json_cases() {
            let backend = Rc::new(TraceBackend::new(clean_backend));
            let mut tester = UnitTestBuilder::default()
                .with_config(block_config())
                .with_backend(Rc::clone(&backend))
                .with_entrypoint(super::configure);
            let response = tester.request(json_request(body));
            assert_eq!(response.status_code(), 415);
            assert!(backend.next().is_none());
        }
    }

    #[test]
    fn unsupported_json_responses_fail_closed_in_block_mode() {
        for body in unsupported_json_cases() {
            let mut tester = UnitTestBuilder::default()
                .with_config(block_config())
                .with_backend(move |_: UnitHttpRequest| {
                    UnitHttpResponse::new(200)
                        .with_header("content-type", "application/problem+json; charset=utf-8")
                        .with_header("content-length", body.len().to_string())
                        .with_body(body.as_bytes())
                })
                .with_entrypoint(super::configure);
            let response = tester.request(json_request("{}"));
            assert!(response.body().is_empty());
            assert_eq!(
                response.header("x-agent-decoy-tripwire"),
                Some("withheld;reason=uninspectable-json")
            );
            assert_eq!(response.header("content-length"), None);
        }
    }

    #[test]
    fn unsupported_json_monitor_and_plain_text_controls_preserve_bytes() {
        for body in unsupported_json_cases() {
            for (config, content_type) in [
                (monitor_config(), "application/json"),
                (block_config(), "text/plain"),
            ] {
                let expected = body.clone();
                let backend = Rc::new(TraceBackend::new(move |_: UnitHttpRequest| {
                    UnitHttpResponse::new(200)
                        .with_header("content-type", content_type)
                        .with_header("content-length", expected.len().to_string())
                        .with_body(expected.as_bytes())
                }));
                let mut tester = UnitTestBuilder::default()
                    .with_config(config)
                    .with_backend(Rc::clone(&backend))
                    .with_entrypoint(super::configure);
                let response = tester.request(
                    UnitHttpRequest::post()
                        .with_header("content-type", content_type)
                        .with_header("content-length", body.len().to_string())
                        .with_body(body.as_bytes()),
                );
                assert_eq!(response.status_code(), 200);
                assert_eq!(backend.next().unwrap().body(), body.as_bytes());
                assert_eq!(response.body(), body.as_bytes());
            }
        }
    }
    #[test]
    fn legacy_json_requests_fail_closed_at_parser_limits() {
        for body in unsupported_json_cases() {
            let backend = Rc::new(TraceBackend::new(clean_backend));
            let mut tester = UnitTestBuilder::default()
                .with_config(block_config())
                .with_backend(Rc::clone(&backend))
                .with_entrypoint(super::configure);
            let response = tester.request(
                UnitHttpRequest::post()
                    .with_header("content-length", body.len().to_string())
                    .with_body(body),
            );
            assert_eq!(response.status_code(), 415);
            assert!(backend.next().is_none());
        }
    }

    #[test]
    fn legacy_json_responses_fail_closed_at_parser_limits() {
        for body in unsupported_json_cases() {
            let mut tester = UnitTestBuilder::default()
                .with_config(block_config())
                .with_backend(move |_: UnitHttpRequest| {
                    UnitHttpResponse::new(200)
                        .with_header("content-length", body.len().to_string())
                        .with_body(body.as_bytes())
                })
                .with_entrypoint(super::configure);
            let response = tester.request(json_request("{}"));
            assert!(response.body().is_empty());
        }
    }
}
