// Copyright (c) 2026 msaleme. Licensed under the MIT License.
mod engine;
mod generated;
mod json;
use anyhow::{anyhow, Result};
use engine::{Engine, LIMIT};
use generated::config::Config;
use pdk::hl::*;
use pdk::logger;
use pdk::policy_violation::PolicyViolations;
use serde_json::{json, Value};

/// Header-phase admission decision.
enum Admit {
    /// Not an unencoded JSON media type (SSE, compressed, non-JSON, missing or
    /// malformed content-type, or an over-limit declared length): out of scope,
    /// never buffered.
    Uninspectable,
    /// JSON media with a valid declared Content-Length within the 64 KiB ceiling.
    Declared(usize),
    /// Request-leg JSON media with no declared Content-Length and no
    /// Transfer-Encoding. A trusted earlier MCP policy that rewrites the request
    /// body (e.g. Tool Mapping) drops Content-Length after `set_body`, so that
    /// missing length is NOT by itself uninspectable; the buffered body is bounded
    /// against LIMIT instead (#48). A client-chunked upload and every response
    /// with an undeclared length stay uninspectable, so a slow or long-lived body
    /// is classified in the header phase and never buffered (#56). Flex Gateway
    /// 1.14 strips Transfer-Encoding from a de-chunked upload before this filter,
    /// so there such an upload lands here; refuse chunked framing at ingress (#63).
    Undeclared,
}
fn admission(
    content_type: Option<String>,
    length: Option<String>,
    encoding: Option<String>,
    allow_undeclared: bool,
) -> Admit {
    let media = match content_type {
        Some(ct) => ct
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase(),
        None => return Admit::Uninspectable,
    };
    if !(media == "application/json"
        || (media.starts_with("application/") && media.ends_with("+json")))
        || encoding.is_some()
    {
        return Admit::Uninspectable;
    }
    match length {
        None if allow_undeclared => Admit::Undeclared,
        None => Admit::Uninspectable,
        Some(length) => {
            // A present-but-malformed or over-limit length stays uninspectable so
            // an oversized or garbled declared body still fails closed.
            if length.is_empty() || !length.bytes().all(|b| b.is_ascii_digit()) {
                return Admit::Uninspectable;
            }
            match length.parse::<usize>() {
                Ok(n) if n <= LIMIT => Admit::Declared(n),
                _ => Admit::Uninspectable,
            }
        }
    }
}
// Clean pass-through and no-op accounting: debug so operators are not drowned in
// warning-log noise for ordinary traffic (#43).
fn event(stage: &str, requested: &str, applied: &str, reason: &str) {
    logger::debug!(
        "{}",
        json!({"event":"agent_decoy_composition","stage":stage,"requested":requested,"applied":applied,"reason":reason})
    );
}
// Detections and enforcement actions/failures: warning level is reserved for
// these so they stand out in logs (#43).
fn alert(stage: &str, requested: &str, applied: &str, reason: &str) {
    logger::warn!(
        "{}",
        json!({"event":"agent_decoy_composition","stage":stage,"requested":requested,"applied":applied,"reason":reason})
    );
}
// Documented, operator-visible skips: a body the detectors could not inspect, or
// best-effort seeding that did not fit (#57). Warning level when the skip leaves
// an enforcing detector blind; info otherwise, so ordinary SSE traffic in an
// observe-only deployment does not flood warning logs.
fn skipped(name: &str, stage: &str, reason: &str, warning: bool) {
    let line = json!({"event":name,"stage":stage,"reason":reason});
    if warning {
        logger::warn!("{}", line);
    } else {
        logger::info!("{}", line);
    }
}
// Booleans only: never the configured lure values (#55).
fn detection(stage: &str, honeytoken: bool, breadcrumb: bool, sentinel: bool) {
    if honeytoken || breadcrumb || sentinel {
        logger::warn!(
            "{}",
            json!({"event":"agent_decoy_detection","stage":stage,"honeytoken":honeytoken,"breadcrumb":breadcrumb,"sentinel":sentinel})
        );
    }
}
fn deny(body: &[u8], engine: &Engine) -> Response {
    let value: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
    if value.get("method").is_some() {
        if let Some(id) = value.get("id") {
            let body=json!({"jsonrpc":"2.0","id":id,"error":{"code":-32008,"message":"decoy policy rejected request"}}).to_string();
            // Withhold the in-band error whenever reflecting the id would echo any
            // configured lure back — regardless of which detector caused the block
            // or which breadcrumb mode is set (#44).
            if body.len() > LIMIT || engine.echoes_protected(body.as_bytes()) {
                return Response::new(403);
            }
            return Response::new(200)
                .with_headers([("content-type".to_owned(), "application/json".to_owned())])
                .with_body(body);
        }
        return Response::new(202);
    }
    Response::new(403)
}
async fn request_filter(
    state: RequestState,
    engine: &Engine,
    violations: &PolicyViolations,
) -> Flow<Option<Value>> {
    let headers = state.into_headers_state().await;
    if !headers.contains_body() {
        return Flow::Continue(None);
    }
    // Classify in the header phase, before any whole-body buffering. Uninspectable
    // traffic (text/event-stream and other true streams, compressed, non-JSON, a
    // client-chunked upload, or an oversized/malformed declared length) fails
    // closed when enforcing and otherwise passes through untouched (#38, #56). A
    // JSON body whose Content-Length a trusted earlier policy dropped is still
    // inspected, bounded against LIMIT (#48).
    //
    // Rejections before a body is proven to be one well-formed JSON-RPC request
    // (415, 413, 400) are bare HTTP statuses: there is no unambiguous `id` to
    // reflect in an in-band -32008 error (#57).
    let expected = match admission(
        headers.handler().header("content-type"),
        headers.handler().header("content-length"),
        headers.handler().header("content-encoding"),
        headers.handler().header("transfer-encoding").is_none(),
    ) {
        Admit::Uninspectable => {
            if engine.enforcing() {
                alert("request", "inspect", "blocked", "uninspectable-body");
                return Flow::Break(Response::new(415));
            }
            skipped("inspection_skipped", "request", "uninspectable-body", true);
            return Flow::Continue(None);
        }
        Admit::Declared(n) => Some(n),
        Admit::Undeclared => None,
    };
    let state = headers.into_headers_body_state().await;
    let handler = state.handler();
    let original = handler.body();
    // A declared length must match exactly; an undeclared body is only bounded.
    let framing_ok = expected.is_none_or(|n| original.len() == n) && original.len() <= LIMIT;
    if !framing_ok {
        // A within-limit body with a mismatched length is already buffered, so
        // still report raw-byte detections before skipping or rejecting it (#55).
        if original.len() <= LIMIT {
            let (honey, breadcrumb) = engine.raw_hits(&original);
            detection("request", honey, breadcrumb, false);
        }
        if engine.enforcing() {
            alert("request", "inspect", "blocked", "invalid-framing");
            return Flow::Break(Response::new(413));
        }
        skipped("inspection_skipped", "request", "invalid-framing", true);
        return Flow::Continue(None);
    }
    let plan = match engine.request(&original) {
        Ok(plan) => plan,
        Err(reason) => {
            // Unsupported envelope (batch, duplicate members, non-JSON-RPC): still
            // report raw-byte detections, then reject only when enforcing,
            // otherwise forward unmodified.
            let (honey, breadcrumb) = engine.raw_hits(&original);
            detection("request", honey, breadcrumb, false);
            if engine.enforcing() {
                alert("request", "inspect", "blocked", reason);
                return Flow::Break(Response::new(400));
            }
            skipped("inspection_skipped", "request", reason, true);
            return Flow::Continue(None);
        }
    };
    detection(
        "request",
        plan.honey_hit,
        plan.breadcrumb_hit,
        plan.sentinel_hit,
    );
    if plan.sentinel_hit {
        violations.generate_policy_violation();
    }
    if plan.blocked {
        alert("request", "coordinate", "blocked", "terminal-detector");
        return Flow::Break(deny(&original, engine));
    }
    event("request", "inspect", "forwarded", "no-terminal-decision");
    Flow::Continue(plan.list_id)
}
async fn response_filter(
    state: ResponseState,
    context: RequestData<Option<Value>>,
    engine: &Engine,
) {
    let RequestData::Continue(id) = context else {
        return;
    };
    let headers = state.into_headers_state().await;
    if !headers.contains_body() {
        return;
    }
    // Responses must declare a Content-Length within LIMIT. Streamed/uninspectable
    // responses (text/event-stream, chunked or otherwise undeclared length,
    // compressed, non-JSON) are out of the bounded-JSON scope: they never enter
    // body buffering, which could stall on a long-lived stream, and are forwarded
    // without redaction. In Honeytoken block mode that skip is a warning, because
    // block-mode redaction does not apply to them (#38, #56).
    let expected = match admission(
        headers.handler().header("content-type"),
        headers.handler().header("content-length"),
        headers.handler().header("content-encoding"),
        false,
    ) {
        Admit::Declared(n) => n,
        // With `allow_undeclared` false the only other outcome is Uninspectable.
        Admit::Uninspectable | Admit::Undeclared => {
            skipped(
                "response_inspection_skipped",
                "response",
                "uninspectable-body",
                engine.response_enforced(),
            );
            return;
        }
    };
    let state = headers.into_headers_body_state().await;
    let handler = state.handler();
    let original = handler.body();
    if engine.response_hit(&original) {
        alert(
            "response",
            if engine.response_enforced() {
                "redact"
            } else {
                "monitor"
            },
            "detected",
            "honeytoken-match",
        );
    }
    let bounded = original.len() == expected && original.len() <= LIMIT;
    let output = if bounded {
        engine.response(&original, id.as_ref())
    } else if engine.response_enforced() {
        Vec::new()
    } else {
        original.clone()
    };
    if output == original {
        // Distinguish enabled-but-skipped seeding from a genuine no-op so operators
        // do not mistake best-effort seeding for a guaranteed edit (#41).
        if engine.seed_applicable(&original, id.as_ref()) {
            skipped("seed_skipped_no_capacity", "response", "no-capacity", false);
        } else {
            event(
                "response",
                "coordinate",
                "unchanged",
                "no-safe-edit-required",
            );
        }
        return;
    }
    let mut applied = if output.is_empty() {
        "withheld"
    } else {
        "transformed"
    };
    if handler.set_body(&output).is_err() {
        if handler.set_body(b"").is_err() {
            alert(
                "response",
                "withhold",
                "failed",
                "pdk-response-termination-unavailable",
            );
            logger::error!("Required response mutation and empty-body fallback both failed");
            return;
        }
        applied = "withheld";
    }
    handler.remove_header("content-length");
    handler.remove_header("content-encoding");
    alert("response", "coordinate", applied, "final-output-validated");
}
#[entrypoint]
async fn configure(
    launcher: Launcher,
    Configuration(bytes): Configuration,
    violations: PolicyViolations,
) -> Result<()> {
    let config: Config =
        serde_json::from_slice(&bytes).map_err(|_| anyhow!("Invalid coordinator configuration"))?;
    let engine = Engine(config);
    if !engine.validate() {
        return Err(anyhow!("Unsupported coordinator mode or blank detector"));
    }
    if !engine.within_limits() {
        return Err(anyhow!(
            "Coordinator configuration exceeds supported detector/breadcrumb bounds"
        ));
    }
    launcher
        .launch(
            on_request(|state| request_filter(state, &engine, &violations))
                .on_response(|state, context| response_filter(state, context, &engine)),
        )
        .await?;
    Ok(())
}

#[cfg(test)]
mod adapter_tests;
