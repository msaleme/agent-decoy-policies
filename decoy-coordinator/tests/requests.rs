// Copyright (c) 2026 msaleme. Licensed under the MIT License.
mod common;
use common::*;
use httpmock::MockServer;
use pdk_test::services::flex::{ApiConfig, Flex, FlexConfig, PolicyConfig};
use pdk_test::services::httpmock::{HttpMock, HttpMockConfig};
use pdk_test::{pdk_test, TestComposite};
use serde_json::json;

async fn exercise(breadcrumb: &str) -> anyhow::Result<()> {
    let backend = HttpMockConfig::builder()
        .port(80)
        .version("latest")
        .hostname("backend")
        .build();
    let policy = PolicyConfig::builder()
        .name(POLICY_NAME)
        .configuration(json!({
            "honeytokens":["secret"],"decoyTools":["admin"],"breadcrumb":breadcrumb,
            "honeytokenMode":"block","sentinelMode":"block","breadcrumbMode":"sanitize",
            "seeding":"enabled","caseSensitive":false
        }))
        .build();
    let api = ApiConfig::builder()
        .name("coordinator")
        .upstream(&backend)
        .path("/")
        .port(8081)
        .policies([policy])
        .build();
    let flex = FlexConfig::builder()
        .version("1.14.0")
        .hostname("local-flex")
        .env([
            ("FLEX_DOWNSTREAM_CONNECTION_BUFFER_LIMIT_BYTES", "65536"),
            ("FLEX_UPSTREAM_RESPONSE_TIMEOUT_SECONDS", "2"),
        ])
        .with_api(api)
        .config_mounts([
            (POLICY_DIR, "custom-policies"),
            (COMMON_CONFIG_DIR, "common"),
        ])
        .build();
    let composite = TestComposite::builder()
        .with_service(flex)
        .with_service(backend)
        .build()
        .await?;
    let flex: Flex = composite.service()?;
    let url = flex.external_url(8081).unwrap();
    let backend: HttpMock = composite.service()?;
    let server = MockServer::connect_async(backend.socket()).await;
    let response = r#"{ "jsonrpc": "2.0", "id": 1, "result": { "tools": [ { "name": "safe", "description": "secret description with room" } ] } }"#;
    let upstream = server
        .mock_async(|when, then| {
            let when = when.body_contains("\"method\":\"tools/list\"");
            if breadcrumb == "lure" {
                when.body_contains("\"note\":\"\"");
            }
            then.status(200)
                .header("content-type", "application/json")
                .body(response);
        })
        .await;
    let unexpected = server
        .mock_async(|when, then| {
            when.any_request();
            then.status(500);
        })
        .await;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .build()?;
    for body in [
        json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"admin"}}),
        json!({"jsonrpc":"2.0","id":"secret","method":"ping"}),
        json!({"jsonrpc":"2.0","id":1,"method":"ping","params":{"note":"secret"}}),
    ] {
        let reply = client
            .post(&url)
            .header("content-type", "application/json")
            .header("x-agent-decoy-tripwire", "fired;direction=request")
            .body(body.to_string())
            .send()
            .await?;
        assert!(reply.status() == 200 || reply.status() == 403);
        assert!(!reply.text().await?.contains("secret"));
    }
    upstream.assert_hits_async(0).await;
    let body=json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"note":if breadcrumb=="lure" { "lure" } else { "safe" }}}).to_string();
    let reply = client
        .post(&url)
        .header("content-type", "application/json")
        .header("x-agent-breadcrumb", "followed")
        .body(body)
        .send()
        .await?;
    assert_eq!(reply.status(), 200);
    let output = reply.bytes().await?;
    assert!(!String::from_utf8_lossy(&output).contains("secret"));
    if breadcrumb == "secret" {
        assert!(
            output.is_empty(),
            "seed-created token must withhold the whole response"
        );
    } else {
        let value: serde_json::Value = serde_json::from_slice(&output)?;
        assert!(value["result"]["tools"][0]["description"]
            .as_str()
            .unwrap()
            .contains("lure"));
        assert_eq!(value["id"], 1);
    }
    upstream.assert_hits_async(1).await;
    unexpected.assert_hits_async(0).await;
    Ok(())
}
#[pdk_test]
async fn original_detectors_and_final_seed_rescan() -> anyhow::Result<()> {
    exercise("secret").await
}
#[pdk_test]
async fn required_redaction_precedes_safe_optional_seed() -> anyhow::Result<()> {
    exercise("lure").await
}
