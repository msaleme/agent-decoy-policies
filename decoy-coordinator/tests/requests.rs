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
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .build()?;
    wait_until_ready(&client, &url, &server).await?;
    let response = r#"{ "jsonrpc": "2.0", "id": 1, "result": { "tools": [ { "name": "safe", "description": "secret description with room" } ] } }"#;
    let upstream = server
        .mock_async(|when, then| {
            when.body_contains("\"method\":\"tools/list\"")
                .body_contains("\"note\":\"safe\"");
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
    for body in [
        json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"admin"}}),
        json!({"jsonrpc":"2.0","id":"secret","method":"ping"}),
        json!({"jsonrpc":"2.0","id":1,"method":"ping","params":{"note":"secret"}}),
        // `sanitize` blocks a request breadcrumb rather than rewriting it (#54).
        json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"note":breadcrumb}}),
    ] {
        let reply = client
            .post(&url)
            .header("content-type", "application/json")
            .header("x-agent-decoy-tripwire", "fired;direction=request")
            .body(body.to_string())
            .send()
            .await?;
        let status = reply.status();
        let text = reply.text().await?;
        assert!(
            status == 200 || status == 403,
            "unexpected status {} for {}: {}",
            status,
            body,
            text
        );
        assert!(
            !text.contains("secret"),
            "honeytoken leaked for {}: {}",
            body,
            text
        );
    }
    upstream.assert_hits_async(0).await;
    let body =
        json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"note":"safe"}}).to_string();
    let reply = client
        .post(&url)
        .header("content-type", "application/json")
        .header("x-agent-breadcrumb", "followed")
        .body(body)
        .send()
        .await?;
    let status = reply.status();
    let output = reply.bytes().await?;
    assert_eq!(
        status,
        200,
        "clean tools/list body: {}",
        String::from_utf8_lossy(&output)
    );
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
/// Poll a clean request until Flex and the mock backend both serve it (#72). A cold host can
/// answer 5xx (or refuse the connection) for the first requests; the block-loop assertions accept
/// 403, so without this wait an unready gateway only surfaced at the clean `tools/list` check.
/// Ready means the probe reached the backend: a blocked request with an id is denied with HTTP 200
/// and a JSON-RPC error, so status alone is not enough. The probe has its own mock, deleted before
/// the test's mocks are registered.
async fn wait_until_ready(
    client: &reqwest::Client,
    url: &str,
    server: &MockServer,
) -> anyhow::Result<()> {
    let probe = server
        .mock_async(|when, then| {
            when.body_contains("\"note\":\"readiness\"");
            then.status(200)
                .header("content-type", "application/json")
                .body(r#"{"jsonrpc":"2.0","id":0,"result":{}}"#);
        })
        .await;
    let body = json!({"jsonrpc":"2.0","id":0,"method":"ping","params":{"note":"readiness"}});
    let mut last = String::from("no attempt");
    for _ in 0..30 {
        match client
            .post(url)
            .header("content-type", "application/json")
            .body(body.to_string())
            .send()
            .await
        {
            Ok(reply) => {
                let status = reply.status();
                let text = reply.text().await.unwrap_or_default();
                if status == 200 && probe.hits_async().await > 0 {
                    probe.delete_async().await;
                    return Ok(());
                }
                last = format!("{} {}", status, text);
            }
            Err(err) => last = err.to_string(),
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    anyhow::bail!("gateway not ready after 30 attempts; last: {}", last)
}
#[pdk_test]
async fn original_detectors_and_final_seed_rescan() -> anyhow::Result<()> {
    exercise("secret").await
}
#[pdk_test]
async fn required_redaction_precedes_safe_optional_seed() -> anyhow::Result<()> {
    exercise("lure").await
}
