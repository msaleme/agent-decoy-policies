// Copyright (c) 2026 msaleme. Licensed under the MIT License.
use pdk_unit::{
    TraceBackend, UnitHttpMessage, UnitHttpRequest, UnitHttpResponse, UnitTest, UnitTestBuilder,
};
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
// Every detector configured, nothing in block mode except what `breadcrumb_mode`
// implies.
fn monitor_config(breadcrumb_mode: &str) -> String {
    json!({"honeytokens":["secret"],"decoyTools":["admin"],"breadcrumb":"lure","honeytokenMode":"monitor","sentinelMode":"monitor","breadcrumbMode":breadcrumb_mode,"seeding":"disabled","caseSensitive":false}).to_string()
}
// PDK unit log lines are "<millis> - <Level>: <message>".
fn logged(test: &UnitTest, level: &str, needle: &str) -> bool {
    test.logs()
        .iter()
        .any(|l| l.contains(&format!(" - {level}: ")) && l.contains(needle))
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
fn response_honeytoken_detection_logs_only_boolean_detectors_in_both_modes() {
    for configuration in [config(), monitor_config("observe")] {
        let mut test = UnitTestBuilder::default()
            .with_config(configuration)
            .with_backend(backend)
            .with_entrypoint(super::configure);
        assert_eq!(
            test.request(request(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#))
                .status_code(),
            200
        );
        let events: Vec<serde_json::Value> = test
            .logs()
            .iter()
            .filter_map(|line| line.split_once(" - Warn: "))
            .filter_map(|(_, message)| message.find('{').map(|start| &message[start..]))
            .filter_map(|message| serde_json::from_str::<serde_json::Value>(message).ok())
            .filter(|event| event["event"] == "agent_decoy_detection")
            .collect();
        assert_eq!(
            events,
            vec![json!({
                "event": "agent_decoy_detection", "stage": "response",
                "honeytoken": true, "breadcrumb": false, "sentinel": false
            })]
        );
        assert!(!test
            .logs()
            .iter()
            .any(|line| line.contains("secret") || line.contains("lure")));
    }
}
#[test]
fn response_length_mismatch_is_withheld_with_a_distinct_reason() {
    let body = r#"{"jsonrpc":"2.0","id":1,"result":{}}"#;
    let mut test = UnitTestBuilder::default()
        .with_config(config())
        .with_backend(move |_: UnitHttpRequest| {
            UnitHttpResponse::new(200)
                .with_header("content-type", "application/json")
                .with_header("content-length", (body.len() + 1).to_string())
                .with_body(body)
        })
        .with_entrypoint(super::configure);
    let response = test.request(request(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#));
    assert_eq!(response.status_code(), 200);
    assert!(response.body().is_empty());
    assert_eq!(response.header("content-length"), None);
    assert!(logged(
        &test,
        "Warn",
        r#""reason":"declared-length-mismatch""#
    ));
    assert!(logged(&test, "Warn", r#""applied":"withheld""#));
    assert!(!test
        .logs()
        .iter()
        .any(|line| line.contains("final-output-validated")));
}
#[test]
fn monitor_response_length_mismatch_is_not_reported_as_seeding_capacity() {
    let list = r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"t","description":"d"}]}}"#;
    let mut test = UnitTestBuilder::default()
        .with_config(monitor_config("observe").replace("\"disabled\"", "\"enabled\""))
        .with_backend(move |_: UnitHttpRequest| {
            UnitHttpResponse::new(200)
                .with_header("content-type", "application/json")
                .with_header("content-length", (list.len() + 1).to_string())
                .with_body(list)
        })
        .with_entrypoint(super::configure);
    let response = test.request(request(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#));
    assert_eq!(response.status_code(), 200);
    assert_eq!(response.body(), list.as_bytes());
    assert_eq!(
        response.header("content-length"),
        Some((list.len() + 1).to_string()).as_deref()
    );
    assert!(logged(
        &test,
        "Info",
        r#""event":"response_inspection_skipped""#
    ));
    assert!(logged(
        &test,
        "Info",
        r#""reason":"declared-length-mismatch""#
    ));
    assert!(!test
        .logs()
        .iter()
        .any(|line| line.contains("seed_skipped_no_capacity")));
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
fn sanitize_with_monitor_modes_blocks_a_followed_breadcrumb_and_logs_it() {
    // Before #55, a refused sanitization in `sanitize` + monitor modes forwarded
    // the original body with the breadcrumb intact and logged no detection. It must
    // now be contained in-band like any block, never reach the backend, and emit
    // the boolean-only detection log at warning level.
    for body in [
        r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"safe","arguments":{"note":"lure"}}}"#,
        r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"safe","arguments":{"lure_role":"admin"}}}"#,
    ] {
        let trace = Rc::new(TraceBackend::new(backend));
        let mut test = UnitTestBuilder::default()
            .with_config(monitor_config("sanitize"))
            .with_backend(Rc::clone(&trace))
            .with_entrypoint(super::configure);
        let response = test.request(request(body));
        assert_eq!(response.status_code(), 200, "{}", body);
        let reply: serde_json::Value = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(reply["error"]["code"], -32008, "{}", body);
        assert_eq!(reply["id"], 7, "{}", body);
        assert!(trace.next().is_none(), "{}", body);
        assert!(
            logged(&test, "Warn", r#""event":"agent_decoy_detection""#)
                && logged(&test, "Warn", r#""breadcrumb":true"#),
            "{}",
            body
        );
        assert!(!test.logs().iter().any(|l| l.contains("lure")), "{}", body);
    }
}
#[test]
fn unsupported_envelope_still_emits_detection_telemetry() {
    // A batch carrying the breadcrumb is out of scope; in observe mode it is
    // forwarded, but the raw-byte detection is still logged at warning level (#55).
    let trace = Rc::new(TraceBackend::new(backend));
    let mut test = UnitTestBuilder::default()
        .with_config(monitor_config("observe"))
        .with_backend(Rc::clone(&trace))
        .with_entrypoint(super::configure);
    let response = test.request(request(
        r#"[{"jsonrpc":"2.0","id":1,"method":"ping","params":{"note":"lure"}}]"#,
    ));
    assert_eq!(response.status_code(), 200);
    assert!(trace.next().is_some());
    assert!(logged(&test, "Warn", r#""event":"agent_decoy_detection""#));
    assert!(logged(&test, "Warn", r#""event":"inspection_skipped""#));
    assert!(!test.logs().iter().any(|l| l.contains("lure")));
}
#[test]
fn a_client_chunked_json_upload_is_classified_in_the_header_phase() {
    // Host-dependent: this fixture retains Transfer-Encoding; Flex 1.14 strips it.
    // A client-chunked JSON upload has no declared length and could be slow or
    // oversized. It is not admitted as `Undeclared` (#56): enforcing fails closed
    // with 415 before buffering, observe forwards it with a warning-level skip.
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"ping","params":{{"pad":"{}"}}}}"#,
        "a".repeat(super::LIMIT)
    );
    let chunked = || {
        UnitHttpRequest::post()
            .with_header("content-type", "application/json")
            .with_header("transfer-encoding", "chunked")
            .with_body(body.as_str())
    };
    let trace = Rc::new(TraceBackend::new(backend));
    let mut test = UnitTestBuilder::default()
        .with_config(config())
        .with_backend(Rc::clone(&trace))
        .with_entrypoint(super::configure);
    assert_eq!(test.request(chunked()).status_code(), 415);
    assert!(trace.next().is_none());
    assert!(logged(&test, "Warn", r#""reason":"uninspectable-body""#));

    let trace = Rc::new(TraceBackend::new(backend));
    let mut test = UnitTestBuilder::default()
        .with_config(monitor_config("observe"))
        .with_backend(Rc::clone(&trace))
        .with_entrypoint(super::configure);
    assert_eq!(test.request(chunked()).status_code(), 200);
    assert!(trace.next().is_some());
    assert!(logged(&test, "Warn", r#""event":"inspection_skipped""#));
}
#[test]
fn an_undeclared_length_response_is_not_buffered_and_warns_in_block_mode() {
    // Responses must declare their length (#56): a chunked JSON response carrying
    // the honeytoken is forwarded unredacted, and Honeytoken block mode records a
    // warning-level response_inspection_skipped instead of a silent skip.
    let body = r#"{"jsonrpc":"2.0","id":1,"result":{"text":"secret"}}"#;
    let mut test = UnitTestBuilder::default()
        .with_config(config())
        .with_backend(move |_: UnitHttpRequest| {
            UnitHttpResponse::new(200)
                .with_header("content-type", "application/json")
                .with_header("transfer-encoding", "chunked")
                .with_body(body)
        })
        .with_entrypoint(super::configure);
    let response = test.request(request(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#));
    assert_eq!(response.status_code(), 200);
    assert!(String::from_utf8_lossy(response.body()).contains("secret"));
    assert!(logged(
        &test,
        "Warn",
        r#""event":"response_inspection_skipped""#
    ));
}
#[test]
fn a_small_chunked_upload_is_rejected_by_headers_not_size() {
    // Host-dependent: only hosts retaining Transfer-Encoding exercise this guard.
    // Unlike the over-limit case above, this body would pass every size check, so
    // a 415 proves the classification is made from the headers alone (#56).
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#;
    let trace = Rc::new(TraceBackend::new(backend));
    let mut test = UnitTestBuilder::default()
        .with_config(config())
        .with_backend(Rc::clone(&trace))
        .with_entrypoint(super::configure);
    let response = test.request(
        UnitHttpRequest::post()
            .with_header("content-type", "application/json")
            .with_header("transfer-encoding", "chunked")
            .with_body(body),
    );
    assert_eq!(response.status_code(), 415);
    assert!(trace.next().is_none());
}
#[test]
fn a_response_skip_is_info_level_outside_honeytoken_block_mode() {
    let sse = "event: message\ndata: {}\n\n";
    let mut test = UnitTestBuilder::default()
        .with_config(monitor_config("observe"))
        .with_backend(move |_: UnitHttpRequest| {
            UnitHttpResponse::new(200)
                .with_header("content-type", "text/event-stream")
                .with_header("content-length", sse.len().to_string())
                .with_body(sse.as_bytes())
        })
        .with_entrypoint(super::configure);
    let response = test.request(request(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#));
    assert_eq!(response.status_code(), 200);
    assert!(logged(
        &test,
        "Info",
        r#""event":"response_inspection_skipped""#
    ));
    assert!(!logged(&test, "Warn", "response_inspection_skipped"));
}
#[test]
fn sanitize_alone_makes_the_policy_fail_closed_on_uninspectable_requests() {
    // Every other detector is in monitor mode; Breadcrumb `sanitize` is enforcing (#54).
    let trace = Rc::new(TraceBackend::new(backend));
    let mut test = UnitTestBuilder::default()
        .with_config(monitor_config("sanitize"))
        .with_backend(Rc::clone(&trace))
        .with_entrypoint(super::configure);
    let response = test.request(
        UnitHttpRequest::post()
            .with_header("content-type", "text/event-stream")
            .with_header("content-length", "2")
            .with_body("{}"),
    );
    assert_eq!(response.status_code(), 415);
    assert!(trace.next().is_none());
}
#[test]
fn an_enforcing_rejection_of_an_unsupported_envelope_still_logs_the_detection() {
    let trace = Rc::new(TraceBackend::new(backend));
    let mut test = UnitTestBuilder::default()
        .with_config(config())
        .with_backend(Rc::clone(&trace))
        .with_entrypoint(super::configure);
    let response = test.request(request(
        r#"[{"jsonrpc":"2.0","id":1,"method":"ping","params":{"note":"lure"}}]"#,
    ));
    assert_eq!(response.status_code(), 400);
    assert!(trace.next().is_none());
    assert!(logged(&test, "Warn", r#""event":"agent_decoy_detection""#));
    assert!(logged(&test, "Warn", r#""breadcrumb":true"#));
    assert!(!test.logs().iter().any(|l| l.contains("lure")));
}
#[test]
fn a_mismatched_length_body_in_monitor_mode_still_logs_the_detection() {
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"ping","params":{"note":"lure"}}"#;
    let trace = Rc::new(TraceBackend::new(backend));
    let mut test = UnitTestBuilder::default()
        .with_config(monitor_config("observe"))
        .with_backend(Rc::clone(&trace))
        .with_entrypoint(super::configure);
    let response = test.request(
        UnitHttpRequest::post()
            .with_header("content-type", "application/json")
            .with_header("content-length", (body.len() + 1).to_string())
            .with_body(body),
    );
    assert_eq!(response.status_code(), 200);
    assert!(trace.next().is_some());
    assert!(logged(&test, "Warn", r#""event":"agent_decoy_detection""#));
    assert!(logged(&test, "Warn", r#""reason":"invalid-framing""#));
    assert!(!test.logs().iter().any(|l| l.contains("lure")));
}
#[test]
fn seeding_without_room_logs_an_info_level_skip() {
    let list = r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"t","description":"d"}]}}"#;
    let mut test = UnitTestBuilder::default()
        .with_config(config())
        .with_backend(move |_: UnitHttpRequest| {
            UnitHttpResponse::new(200)
                .with_header("content-type", "application/json")
                .with_header("content-length", list.len().to_string())
                .with_body(list)
        })
        .with_entrypoint(super::configure);
    let response = test.request(request(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#));
    assert_eq!(response.status_code(), 200);
    assert_eq!(response.body(), list.as_bytes());
    assert!(logged(
        &test,
        "Info",
        r#""event":"seed_skipped_no_capacity""#
    ));
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
fn breadcrumb_denial_cannot_echo_a_protected_id() {
    // Block triggered purely by breadcrumb (honeytoken in monitor); the breadcrumb
    // string sits in the JSON-RPC id, which deny() would otherwise echo back.
    let configuration = json!({"honeytokens":["secret"],"decoyTools":["admin"],"breadcrumb":"lure","honeytokenMode":"monitor","sentinelMode":"block","breadcrumbMode":"block","seeding":"enabled","caseSensitive":false}).to_string();
    let mut test = UnitTestBuilder::default()
        .with_config(configuration)
        .with_backend(backend)
        .with_entrypoint(super::configure);
    let response = test.request(request(r#"{"jsonrpc":"2.0","id":"lure","method":"ping"}"#));
    assert_eq!(response.status_code(), 403);
    assert!(!String::from_utf8_lossy(response.body()).contains("lure"));
}
#[test]
fn escaped_breadcrumb_in_id_is_not_echoed_in_a_denial() {
    // Breadcrumb block is the sole trigger; the marker sits in the JSON-RPC id and,
    // once serialized into the denial, is JSON-escaped. Decoded containment must
    // still catch it and withhold the reflection (#44).
    for marker in ["a\nb", "a\tb", "a\"b", "a\\b"] {
        let configuration = json!({
            "honeytokens": ["secret"], "decoyTools": ["admin"], "breadcrumb": marker,
            "honeytokenMode": "monitor", "sentinelMode": "monitor", "breadcrumbMode": "block",
            "seeding": "disabled", "caseSensitive": false
        })
        .to_string();
        let body = json!({"jsonrpc":"2.0","id":marker,"method":"ping"}).to_string();
        let mut test = UnitTestBuilder::default()
            .with_config(configuration)
            .with_backend(backend)
            .with_entrypoint(super::configure);
        let response = test.request(request(&body));
        assert_eq!(response.status_code(), 403, "marker {:?}", marker);
        assert!(response.body().is_empty(), "marker {:?}", marker);
    }
}
#[test]
fn sentinel_denial_in_sanitize_mode_does_not_echo_a_breadcrumb_id() {
    // Block is triggered by Sentinel while breadcrumb mode is `sanitize` (so the
    // old block-only containment guard would not have run); the breadcrumb in the
    // id must still be withheld (#44).
    let configuration = json!({
        "honeytokens": ["secret"], "decoyTools": ["admin"], "breadcrumb": "lure",
        "honeytokenMode": "monitor", "sentinelMode": "block", "breadcrumbMode": "sanitize",
        "seeding": "disabled", "caseSensitive": false
    })
    .to_string();
    let body = r#"{"jsonrpc":"2.0","id":"lure","method":"tools/call","params":{"name":"admin"}}"#;
    let mut test = UnitTestBuilder::default()
        .with_config(configuration)
        .with_backend(backend)
        .with_entrypoint(super::configure);
    let response = test.request(request(body));
    assert_eq!(response.status_code(), 403);
    assert!(!String::from_utf8_lossy(response.body()).contains("lure"));
}
#[test]
fn monitor_mode_forwards_uninspectable_traffic_instead_of_blocking() {
    // No enforcing mode is active, so an uninspectable body (no JSON media / length)
    // must pass through untouched rather than be rejected 415 (#38).
    let trace = Rc::new(TraceBackend::new(backend));
    let configuration = json!({
        "honeytokens": ["secret"], "decoyTools": ["admin"], "breadcrumb": "lure",
        "honeytokenMode": "monitor", "sentinelMode": "monitor", "breadcrumbMode": "observe",
        "seeding": "disabled", "caseSensitive": false
    })
    .to_string();
    let mut test = UnitTestBuilder::default()
        .with_config(configuration)
        .with_backend(Rc::clone(&trace))
        .with_entrypoint(super::configure);
    let response = test.request(UnitHttpRequest::post().with_body("not-json-no-length"));
    assert_eq!(response.status_code(), 200);
    assert!(trace.next().is_some());
}
#[test]
fn enforcing_mode_fails_closed_on_an_sse_request() {
    // text/event-stream is out of the bounded-JSON scope. Under an enforcing
    // config it must fail closed in the header phase and never buffer (#38).
    let trace = Rc::new(TraceBackend::new(backend));
    let body = "event: message\ndata: {\"secret\":1}\n\n";
    let mut test = UnitTestBuilder::default()
        .with_config(config())
        .with_backend(Rc::clone(&trace))
        .with_entrypoint(super::configure);
    let response = test.request(
        UnitHttpRequest::post()
            .with_header("content-type", "text/event-stream")
            .with_header("content-length", body.len().to_string())
            .with_body(body),
    );
    assert_eq!(response.status_code(), 415);
    assert!(trace.next().is_none());
}
#[test]
fn a_json_body_with_a_dropped_content_length_is_still_inspected() {
    // A trusted earlier MCP policy that rewrites the body (e.g. Tool Mapping) drops
    // Content-Length after set_body. Such a
    // body is bounded and must be inspected, not rejected: a clean call reaches the
    // backend, and a decoy is still caught and blocked before the backend (#48).
    let trace = Rc::new(TraceBackend::new(backend));
    let mut test = UnitTestBuilder::default()
        .with_config(config())
        .with_backend(Rc::clone(&trace))
        .with_entrypoint(super::configure);
    let clean = test.request(
        UnitHttpRequest::post()
            .with_header("content-type", "application/json")
            .with_body(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#),
    );
    assert_eq!(clean.status_code(), 200);
    assert!(trace.next().is_some());

    // The mapped-name decoy case from #48, reproduced in Local Mode: no
    // Content-Length, decoy tools/call -> blocked in-band, backend not reached.
    let trace = Rc::new(TraceBackend::new(backend));
    let mut test = UnitTestBuilder::default()
        .with_config(config())
        .with_backend(Rc::clone(&trace))
        .with_entrypoint(super::configure);
    let decoy = test.request(
        UnitHttpRequest::post()
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"admin"}}"#,
            ),
    );
    assert_eq!(decoy.status_code(), 200);
    assert!(String::from_utf8_lossy(decoy.body()).contains("-32008"));
    assert!(trace.next().is_none());
}
#[test]
fn an_undeclared_body_over_the_limit_still_fails_closed() {
    // A missing Content-Length does not mean unbounded: a buffered body beyond
    // 64 KiB is still rejected when enforcing, so #48 does not re-open oversized
    // buffering.
    let trace = Rc::new(TraceBackend::new(backend));
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"ping","params":{{"pad":"{}"}}}}"#,
        "a".repeat(super::LIMIT)
    );
    let mut test = UnitTestBuilder::default()
        .with_config(config())
        .with_backend(Rc::clone(&trace))
        .with_entrypoint(super::configure);
    let response = test.request(
        UnitHttpRequest::post()
            .with_header("content-type", "application/json")
            .with_body(body.as_str()),
    );
    assert_eq!(response.status_code(), 413);
    assert!(trace.next().is_none());
}
#[test]
fn enforcing_mode_fails_closed_on_compressed_content() {
    // A Content-Encoding means the declared length is post-compression bytes we
    // cannot scan; enforcing must reject rather than pass an opaque body (#38).
    let trace = Rc::new(TraceBackend::new(backend));
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#;
    let mut test = UnitTestBuilder::default()
        .with_config(config())
        .with_backend(Rc::clone(&trace))
        .with_entrypoint(super::configure);
    let response = test.request(request(body).with_header("content-encoding", "gzip"));
    assert_eq!(response.status_code(), 415);
    assert!(trace.next().is_none());
}
#[test]
fn a_body_at_exactly_64_kib_is_inspected_and_one_byte_over_is_rejected() {
    // The 64 KiB ceiling is inclusive: a valid envelope of exactly LIMIT bytes is
    // inspected and (decoy-free) forwarded; LIMIT+1 fails closed (#38).
    let prefix = r#"{"jsonrpc":"2.0","id":1,"method":"ping","params":{"pad":""#;
    let suffix = r#""}}"#;
    let at_limit = {
        let pad = super::LIMIT - prefix.len() - suffix.len();
        format!("{prefix}{}{suffix}", "a".repeat(pad))
    };
    assert_eq!(at_limit.len(), super::LIMIT);
    let trace = Rc::new(TraceBackend::new(backend));
    let mut test = UnitTestBuilder::default()
        .with_config(config())
        .with_backend(Rc::clone(&trace))
        .with_entrypoint(super::configure);
    let response = test.request(request(&at_limit));
    assert_eq!(response.status_code(), 200);
    assert!(trace.next().is_some());

    let over_limit = format!("{prefix}{}{suffix}", "a".repeat(super::LIMIT));
    assert!(over_limit.len() > super::LIMIT);
    let trace = Rc::new(TraceBackend::new(backend));
    let mut test = UnitTestBuilder::default()
        .with_config(config())
        .with_backend(Rc::clone(&trace))
        .with_entrypoint(super::configure);
    let response = test.request(request(&over_limit));
    assert_eq!(response.status_code(), 415);
    assert!(trace.next().is_none());
}
#[test]
fn an_sse_response_is_forwarded_unbuffered_not_redacted() {
    // A streamed response carrying the honeytoken is out of scope: it is forwarded
    // as-is (no buffering, so no stall) rather than redacted, and in Honeytoken
    // block mode the skip is a warning, not silent (#38, #56). Pair with MCP
    // Support/Global Access/ABAC for SSE.
    let sse = "event: message\ndata: {\"text\":\"secret\"}\n\n";
    let mut test = UnitTestBuilder::default()
        .with_config(config())
        .with_backend(move |_: UnitHttpRequest| {
            UnitHttpResponse::new(200)
                .with_header("content-type", "text/event-stream")
                .with_header("content-length", sse.len().to_string())
                .with_body(sse.as_bytes())
        })
        .with_entrypoint(super::configure);
    let response = test.request(request(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#));
    assert_eq!(response.status_code(), 200);
    // Not redacted: the skip path leaves the streamed body untouched.
    assert!(String::from_utf8_lossy(response.body()).contains("secret"));
    assert!(logged(
        &test,
        "Warn",
        r#""event":"response_inspection_skipped""#
    ));
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
