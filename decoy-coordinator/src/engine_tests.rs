// Copyright (c) 2026 msaleme. Licensed under the MIT License.

use super::*;
use serde_json::json;
fn engine() -> Engine {
    Engine(serde_json::from_value(json!({"honeytokens":["secret"],"decoyTools":["admin"],"breadcrumb":"secret","honeytokenMode":"block","sentinelMode":"block","breadcrumbMode":"sanitize","seeding":"enabled","caseSensitive":false})).unwrap())
}
#[test]
fn original_honeytoken_cannot_be_erased_before_detection() {
    let plan=engine().request(br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"safe","arguments":{"x":"secret"}}}"#).unwrap();
    assert!(plan.blocked);
}
#[test]
fn original_tool_cannot_be_sanitized_before_detection() {
    let mut e = engine();
    e.0.breadcrumb = "admin".into();
    let plan = e
        .request(br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"admin"}}"#)
        .unwrap();
    assert!(plan.blocked && plan.sentinel_hit);
}
#[test]
fn final_response_rescan_withholds_token_introduced_by_seeding() {
    let body =
        br#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"safe","description":"clean"}]}}"#;
    assert!(engine().response(body, Some(&json!(1))).is_empty());
}
#[test]
fn duplicate_json_members_and_batches_fail_closed() {
    assert!(engine()
        .request(br#"{"jsonrpc":"2.0","method":"ping","method":"tools/call"}"#)
        .is_err());
    assert!(engine()
        .request(br#"[{"jsonrpc":"2.0","method":"ping"}]"#)
        .is_err());
}
#[test]
fn sanitization_cannot_create_a_protected_value() {
    let mut e = engine();
    e.0.breadcrumb = "-".into();
    let plan = e
        .request(br#"{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":"sec-ret"}}"#)
        .unwrap();
    assert!(plan.blocked);
}

#[test]
fn monitor_preserves_bytes_and_observes_hits() {
    let mut e = engine();
    e.0.honeytoken_mode = "monitor".into();
    e.0.sentinel_mode = "monitor".into();
    e.0.breadcrumb_mode = "observe".into();
    e.0.seeding = "disabled".into();
    let body=br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"admin","arguments":{"x":"secret"}}}"#;
    let plan = e.request(body).unwrap();
    assert!(!plan.blocked && plan.sentinel_hit && plan.honey_hit);
    assert_eq!(plan.body, body);
    assert_eq!(e.response(body, None), body);
}
#[test]
fn safe_sanitize_preserves_protocol_and_correlation() {
    let mut e = engine();
    e.0.breadcrumb = "lure".into();
    let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"note":"lure"}}"#;
    let plan = e.request(body).unwrap();
    assert!(!plan.blocked);
    assert_eq!(plan.list_id, Some(json!(1)));
    assert!(!String::from_utf8_lossy(&plan.body).contains("lure"));
}
#[test]
fn seed_requires_correlation_and_room_for_nonexpanding_edit() {
    let mut e = engine();
    e.0.breadcrumb = "lure".into();
    let body=br#"{ "jsonrpc": "2.0", "id": 1, "result": { "tools": [ { "name": "safe", "description": "clean" } ] } }"#;
    assert_eq!(e.response(body, Some(&json!(2))), body);
    let seeded = e.response(body, Some(&json!(1)));
    assert!(String::from_utf8_lossy(&seeded).contains("clean lure"));
    assert!(seeded.len() <= body.len());
}
#[test]
fn escaped_tokens_and_primitive_matches_cannot_escape() {
    let e = engine();
    let escaped = br#"{"jsonrpc":"2.0","id":1,"result":"s\u0065cret"}"#;
    let clean = e.response(escaped, None);
    assert!(!String::from_utf8_lossy(&clean).contains("0065"));
    let mut e = engine();
    e.0.honeytokens = vec!["true".into()];
    assert!(e
        .response(br#"{"jsonrpc":"2.0","id":1,"result":true}"#, None)
        .is_empty());
}
#[test]
fn sanitizing_keys_cannot_silently_collapse_members() {
    let mut e = engine();
    e.0.breadcrumb = "lure".into();
    assert!(e
        .request(br#"{"jsonrpc":"2.0","method":"ping","params":{"xlure":1,"x":2}}"#)
        .is_err());
}

#[test]
fn request_sanitization_must_not_change_id_or_method() {
    let mut e = engine();
    e.0.breadcrumb = "lure".into();
    for body in [
        br#"{"jsonrpc":"2.0","id":"client-lure-1","method":"ping"}"#.as_slice(),
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/lurelist"}"#.as_slice(),
    ] {
        assert!(e.request(body).is_err());
    }
}

#[test]
fn sanitization_preserves_object_keys_and_fails_closed_on_a_key_marker() {
    let mut e = engine();
    e.0.breadcrumb = "decoy_".into();
    // A marker embedded in a key must not be deleted (that would rename the field
    // and change semantics, e.g. decoy_role -> role); fail closed instead (#39).
    assert!(e
        .request(br#"{"jsonrpc":"2.0","method":"ping","params":{"decoy_role":"admin"}}"#)
        .is_err());
}
#[test]
fn sanitization_strips_inert_values_but_keeps_the_key() {
    let mut e = engine();
    e.0.breadcrumb = "lure".into();
    let plan = e
        .request(br#"{"jsonrpc":"2.0","method":"ping","params":{"role":"admin_lure"}}"#)
        .unwrap();
    let body = String::from_utf8_lossy(&plan.body);
    assert!(!plan.blocked);
    assert!(!body.contains("lure"));
    assert!(body.contains("\"role\""));
    assert!(body.contains("admin_"));
}
#[test]
fn sanitization_cannot_synthesize_a_tools_call_argument() {
    let mut e = engine();
    e.0.breadcrumb = "lure".into();
    // A marker inside tools/call arguments is load-bearing; fail closed rather than
    // rewrite it into a different (possibly privileged) argument (#39).
    assert!(e
        .request(
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"safe","arguments":{"note":"lure"}}}"#
        )
        .is_err());
}
#[test]
fn configuration_bounds_are_enforced() {
    let base = |ht: Vec<String>, breadcrumb: String| -> Engine {
        Engine(
            serde_json::from_value(json!({
                "honeytokens": ht, "decoyTools": ["admin"], "breadcrumb": breadcrumb,
                "honeytokenMode": "block", "sentinelMode": "block",
                "breadcrumbMode": "observe", "seeding": "disabled", "caseSensitive": false
            }))
            .unwrap(),
        )
    };
    assert!(base(vec!["secret".into()], "lure".into()).within_limits());
    // Too many detectors.
    let many: Vec<String> = (0..MAX_DETECTORS + 1).map(|i| format!("t{i}")).collect();
    assert!(!base(many, "lure".into()).within_limits());
    // Over-long breadcrumb.
    assert!(!base(vec!["secret".into()], "x".repeat(MAX_BREADCRUMB_LEN + 1)).within_limits());
    // Over-long individual detector.
    assert!(!base(vec!["x".repeat(MAX_DETECTOR_LEN + 1)], "lure".into()).within_limits());
}
#[test]
fn seeding_is_best_effort_and_skips_a_compact_response() {
    let mut e = engine();
    e.0.breadcrumb = "lure".into();
    // A minified tools/list response has no spare whitespace, so a non-expanding
    // seed cannot fit: seeding is best-effort and leaves the body unchanged (#41).
    let body =
        br#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"safe","description":"clean"}]}}"#;
    assert_eq!(e.response(body, Some(&json!(1))), body);
    assert!(e.seed_applicable(body, Some(&json!(1))));
}
#[test]
fn response_monitor_reports_hit_without_mutation() {
    let mut e = engine();
    e.0.honeytoken_mode = "monitor".into();
    e.0.seeding = "disabled".into();
    let body = br#"{"jsonrpc":"2.0","id":1,"result":"secret"}"#;
    assert!(e.response_hit(body));
    assert_eq!(e.response(body, None), body);
}
