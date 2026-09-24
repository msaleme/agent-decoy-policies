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

fn admission(
    content_type: Option<String>,
    length: Option<String>,
    encoding: Option<String>,
) -> Option<usize> {
    let media = content_type?.split(';').next()?.trim().to_ascii_lowercase();
    if !(media == "application/json"
        || (media.starts_with("application/") && media.ends_with("+json")))
        || encoding.is_some()
    {
        return None;
    }
    let length = length?;
    if length.is_empty() || !length.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    length.parse::<usize>().ok().filter(|n| *n <= LIMIT)
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
    let length = admission(
        headers.handler().header("content-type"),
        headers.handler().header("content-length"),
        headers.handler().header("content-encoding"),
    );
    // Uninspectable traffic (text/event-stream and other streamed bodies, chunked
    // or unknown length, compressed, non-JSON, or an oversized declared length) is
    // classified here in the header phase, before any whole-body buffering. In an
    // enforcing mode we fail closed; otherwise we pass valid unrelated traffic
    // through untouched rather than block it (#38).
    let Some(length) = length else {
        if engine.enforcing() {
            alert("request", "inspect", "blocked", "uninspectable-body");
            return Flow::Break(Response::new(415));
        }
        event("request", "inspect", "skipped", "uninspectable-body");
        return Flow::Continue(None);
    };
    let state = headers.into_headers_body_state().await;
    let handler = state.handler();
    let original = handler.body();
    if original.len() != length || original.len() > LIMIT {
        if engine.enforcing() {
            alert("request", "inspect", "blocked", "invalid-framing");
            return Flow::Break(Response::new(413));
        }
        event("request", "inspect", "skipped", "invalid-framing");
        return Flow::Continue(None);
    }
    let plan = match engine.request(&original) {
        Ok(plan) => plan,
        Err(reason) => {
            // Unsupported envelope (batch, duplicate members, non-JSON-RPC): reject
            // only when enforcing, otherwise forward unmodified.
            if engine.enforcing() {
                alert("request", "inspect", "blocked", reason);
                return Flow::Break(Response::new(400));
            }
            event("request", "inspect", "skipped", reason);
            return Flow::Continue(None);
        }
    };
    if plan.honey_hit || plan.breadcrumb_hit || plan.sentinel_hit {
        logger::warn!(
            "{}",
            json!({"event":"agent_decoy_detection","stage":"request","honeytoken":plan.honey_hit,"breadcrumb":plan.breadcrumb_hit,"sentinel":plan.sentinel_hit})
        );
    }
    if plan.sentinel_hit {
        violations.generate_policy_violation();
    }
    if plan.blocked {
        alert("request", "coordinate", "blocked", "terminal-detector");
        return Flow::Break(deny(&original, engine));
    }
    if plan.body != original {
        if handler.set_body(&plan.body).is_err() {
            alert("request", "sanitize", "blocked", "body-write-failed");
            return Flow::Break(Response::new(500));
        }
        handler.remove_header("content-length");
        handler.remove_header("content-encoding");
        alert("request", "sanitize", "sanitized", "required-edit");
    } else {
        event("request", "inspect", "forwarded", "no-terminal-decision");
    }
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
    // Streamed/uninspectable responses (text/event-stream, chunked/unknown length,
    // compressed, non-JSON) are out of the bounded-JSON scope: do NOT enter body
    // buffering, which could stall on a long-lived stream, and do not attempt
    // redaction on them. This is a documented limitation (#38).
    let Some(length) = admission(
        headers.handler().header("content-type"),
        headers.handler().header("content-length"),
        headers.handler().header("content-encoding"),
    ) else {
        event("response", "inspect", "skipped", "uninspectable-body");
        return;
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
    let output = if original.len() == length && original.len() <= LIMIT {
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
            event("response", "seed", "skipped", "no-capacity");
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
