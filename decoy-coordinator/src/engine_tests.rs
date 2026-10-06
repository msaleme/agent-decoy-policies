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
fn monitor_preserves_bytes_and_observes_hits() {
    let mut e = engine();
    e.0.honeytoken_mode = "monitor".into();
    e.0.sentinel_mode = "monitor".into();
    e.0.breadcrumb_mode = "observe".into();
    e.0.seeding = "disabled".into();
    let body=br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"admin","arguments":{"x":"secret"}}}"#;
    let plan = e.request(body).unwrap();
    assert!(!plan.blocked && plan.sentinel_hit && plan.honey_hit);
    assert_eq!(e.response(body, None), body);
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
fn worst_case_scan_stays_within_a_bounded_latency_budget() {
    // Guards against an accidental super-linear regression in the per-request scan
    // cost. It is a coarse budget rather than a Criterion micro-benchmark so it adds
    // no dependency and runs under `--locked --offline` (#40). It exercises the
    // maximum allowed configuration (case-folded, so the more expensive path) against
    // a near-limit body with many nodes; real cost is a few ms, so the budget is
    // deliberately loose to avoid CI flakiness.
    let honeytokens: Vec<String> = (0..MAX_DETECTORS)
        .map(|i| format!("decoy-{i:0>93}"))
        .collect();
    let engine = Engine(
        serde_json::from_value(json!({
            "honeytokens": honeytokens, "decoyTools": ["admin"], "breadcrumb": "lure",
            "honeytokenMode": "monitor", "sentinelMode": "monitor",
            "breadcrumbMode": "observe", "seeding": "disabled", "caseSensitive": false
        }))
        .unwrap(),
    );
    assert!(
        engine.within_limits(),
        "the stressed config must be an accepted worst case"
    );
    let items: Vec<String> = (0..1500)
        .map(|i| format!("item-{i}-payload-value"))
        .collect();
    let body = json!({"jsonrpc":"2.0","id":1,"method":"ping","params":{"items":items}}).to_string();
    assert!(body.len() <= LIMIT, "stress body must fit the 64 KiB scope");
    let body = body.into_bytes();

    let start = std::time::Instant::now();
    for _ in 0..50 {
        let plan = engine.request(&body).expect("valid envelope");
        assert!(!plan.blocked);
        let _ = engine.response(&body, Some(&json!(1)));
    }
    let elapsed = start.elapsed();
    assert!(
        elapsed < std::time::Duration::from_secs(2),
        "worst-case scan budget exceeded: {:?} for 50 request+response passes",
        elapsed
    );
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
#[test]
fn sanitize_mode_blocks_a_breadcrumb_in_every_request_location() {
    // No (method, field) pair is provably inert to rewrite, so `sanitize` never
    // edits a request: a breadcrumb anywhere blocks, including fields outside
    // tools/call that select a resource, prompt or argument (#54).
    let mut e = engine();
    e.0.honeytoken_mode = "monitor".into();
    e.0.sentinel_mode = "monitor".into();
    e.0.breadcrumb = "decoy_".into();
    assert!(e.enforcing() && e.breadcrumb_enforced());
    for body in [
        r#"{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"file:///decoy_admin_secrets"}}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":"prompts/get","params":{"name":"p","arguments":{"role":"decoy_admin"}}}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":"vendor/futureMethod","params":{"x":"decoy_"}}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":"completion/complete","params":{"argument":{"name":"a","value":"decoy_"}}}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"safe","arguments":{"note":"decoy_"}}}"#,
        r#"{"jsonrpc":"2.0","method":"ping","params":{"decoy_role":"admin"}}"#,
        r#"{"jsonrpc":"2.0","id":"client-decoy_-1","method":"ping"}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/decoy_list"}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"note":"decoy_"}}"#,
    ] {
        let plan = e.request(body.as_bytes()).expect("supported envelope");
        assert!(plan.blocked && plan.breadcrumb_hit, "{}", body);
        assert_eq!(plan.list_id, None, "{}", body);
    }
}
#[test]
fn observe_mode_never_blocks_a_breadcrumb_and_keeps_correlation() {
    let mut e = engine();
    e.0.breadcrumb = "lure".into();
    e.0.breadcrumb_mode = "observe".into();
    let plan = e
        .request(br#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"note":"lure"}}"#)
        .unwrap();
    assert!(!plan.blocked && plan.breadcrumb_hit);
    assert_eq!(plan.list_id, Some(json!(1)));
}
#[test]
fn raw_hits_report_detections_on_an_unsupported_envelope() {
    let mut e = engine();
    e.0.breadcrumb = "lure".into();
    let batch = br#"[{"jsonrpc":"2.0","id":1,"method":"ping","params":{"a":"SECRET","b":"lure"}}]"#;
    assert!(e.request(batch).is_err());
    assert_eq!(e.raw_hits(batch), (true, true));
    assert_eq!(
        e.raw_hits(br#"[{"jsonrpc":"2.0","method":"ping"}]"#),
        (false, false)
    );
    e.0.case_sensitive = true;
    assert_eq!(e.raw_hits(batch), (false, true));
}
