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
fn event(stage: &str, requested: &str, applied: &str, reason: &str) {
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
            if body.len() > LIMIT
                || (engine.response_enforced() && engine.response_hit(body.as_bytes()))
                || (engine.breadcrumb_enforced() && engine.breadcrumb_hit(body.as_bytes()))
            {
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
    let Some(length) = length else {
        event("request", "inspect", "blocked", "uninspectable-body");
        return Flow::Break(Response::new(415));
    };
    let state = headers.into_headers_body_state().await;
    let handler = state.handler();
    let original = handler.body();
    if original.len() != length || original.len() > LIMIT {
        event("request", "inspect", "blocked", "invalid-framing");
        return Flow::Break(Response::new(413));
    }
    let plan = match engine.request(&original) {
        Ok(plan) => plan,
        Err(reason) => {
            event("request", "inspect", "blocked", reason);
            return Flow::Break(Response::new(400));
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
        event("request", "coordinate", "blocked", "terminal-detector");
        return Flow::Break(deny(&original, engine));
    }
    if plan.body != original {
        if handler.set_body(&plan.body).is_err() {
            event("request", "sanitize", "blocked", "body-write-failed");
            return Flow::Break(Response::new(500));
        }
        handler.remove_header("content-length");
        handler.remove_header("content-encoding");
        event("request", "sanitize", "sanitized", "required-edit");
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
    let length = admission(
        headers.handler().header("content-type"),
        headers.handler().header("content-length"),
        headers.handler().header("content-encoding"),
    );
    if length.is_none() && !engine.response_enforced() {
        event("response", "seed", "unchanged", "uninspectable-body");
        return;
    }
    let state = headers.into_headers_body_state().await;
    let handler = state.handler();
    let original = handler.body();
    if engine.response_hit(&original) {
        event(
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
    let output = if Some(original.len()) == length && original.len() <= LIMIT {
        engine.response(&original, id.as_ref())
    } else if engine.response_enforced() {
        Vec::new()
    } else {
        original.clone()
    };
    if output == original {
        event(
            "response",
            "coordinate",
            "unchanged",
            "no-safe-edit-required",
        );
        return;
    }
    let mut applied = if output.is_empty() {
        "withheld"
    } else {
        "transformed"
    };
    if handler.set_body(&output).is_err() {
        if handler.set_body(b"").is_err() {
            event(
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
    event("response", "coordinate", applied, "final-output-validated");
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
