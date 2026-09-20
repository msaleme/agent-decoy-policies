// Copyright (c) 2026 msaleme. Licensed under the MIT License.
use pdk_unit::{TraceBackend, UnitHttpMessage, UnitHttpRequest, UnitHttpResponse, UnitTestBuilder};
use serde_json::json;
use std::rc::Rc;
fn config() -> String {
    json!({"honeytokens":["secret"],"decoyTools":["admin"],"breadcrumb":"lure","honeytokenMode":"block","sentinelMode":"block","breadcrumbMode":"sanitize","seeding":"enabled","caseSensitive":false}).to_string()
}
fn request(body: &str) -> UnitHttpRequest {
    UnitHttpRequest::post()
        .with_header("content-type", "application/json")
        .with_header("content-length", body.len().to_string())
        .with_body(body)
}
fn backend(_: UnitHttpRequest) -> UnitHttpResponse {
    let body = r#"{"jsonrpc":"2.0","id":1,"result":{"text":"secret"}}"#;
    UnitHttpResponse::new(200)
        .with_header("content-type", "application/json")
        .with_header("content-length", body.len().to_string())
        .with_body(body)
}
#[test]
fn forged_headers_cannot_suppress_response_redaction() {
    let mut test = UnitTestBuilder::default()
        .with_config(config())
        .with_backend(backend)
        .with_entrypoint(super::configure);
    let response = test.request(
        request(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#)
            .with_header("x-agent-decoy-tripwire", "fired;direction=request")
            .with_header("x-agent-breadcrumb", "followed"),
    );
    assert_eq!(response.status_code(), 200);
    assert!(!String::from_utf8_lossy(response.body()).contains("secret"));
    assert_eq!(response.header("content-length"), None);
}
#[test]
fn block_prevents_upstream_even_when_marker_would_be_sanitized() {
    let trace = Rc::new(TraceBackend::new(backend));
    let mut test = UnitTestBuilder::default()
        .with_config(config().replace("\"lure\"", "\"admin\""))
        .with_backend(Rc::clone(&trace))
        .with_entrypoint(super::configure);
    let response = test.request(request(
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"admin"}}"#,
    ));
    assert_eq!(response.status_code(), 200);
    assert!(String::from_utf8_lossy(response.body()).contains("-32008"));
    assert!(trace.next().is_none());
}
#[test]
fn failed_sanitization_does_not_forward_original() {
    let trace = Rc::new(TraceBackend::new(backend));
    let mut test = UnitTestBuilder::default()
        .with_config(config())
        .with_backend(Rc::clone(&trace))
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
    let response = test.request(request(
        r#"{"jsonrpc":"2.0","id":1,"method":"ping","params":{"note":"lure"}}"#,
    ));
    assert_eq!(response.status_code(), 500);
    assert!(trace.next().is_none());
}
#[test]
fn failed_response_edit_uses_empty_body_fallback() {
    let mut test = UnitTestBuilder::default()
        .with_config(config())
        .with_backend(backend)
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
    let response = test.request(request(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#));
    assert!(response.body().is_empty());
    assert_eq!(response.header("content-length"), None);
}
#[test]
fn unsupported_request_never_reaches_backend() {
    let trace = Rc::new(TraceBackend::new(backend));
    let mut test = UnitTestBuilder::default()
        .with_config(config())
        .with_backend(Rc::clone(&trace))
        .with_entrypoint(super::configure);
    let response = test.request(UnitHttpRequest::post().with_body("unknown-length"));
    assert_eq!(response.status_code(), 415);
    assert!(trace.next().is_none());
}
#[test]
fn local_denial_cannot_echo_a_protected_id() {
    let mut test = UnitTestBuilder::default()
        .with_config(config())
        .with_backend(backend)
        .with_entrypoint(super::configure);
    let response = test.request(request(
        r#"{"jsonrpc":"2.0","id":"secret","method":"ping"}"#,
    ));
    assert!(!String::from_utf8_lossy(response.body()).contains("secret"));
}
#[test]
fn oversized_denial_must_not_bypass_decoded_containment() {
    let mut configuration: serde_json::Value = serde_json::from_str(&config()).unwrap();
    configuration["honeytokens"] = json!(["a\nb"]);
    let id = format!("{}a\nb", "x".repeat(65475));
    let body = json!({"jsonrpc":"2.0","id":id,"method":"ping"}).to_string();
    assert!(body.len() <= super::LIMIT);
    let mut test = UnitTestBuilder::default()
        .with_config(configuration.to_string())
        .with_backend(backend)
        .with_entrypoint(super::configure);
    let response = test.request(request(&body));
    assert_eq!(response.status_code(), 403);
    assert!(response.body().is_empty());
}
