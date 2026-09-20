// Copyright (c) 2026 msaleme. Licensed under the MIT License.

mod common;

use httpmock::MockServer;
use pdk_test::port::Port;
use pdk_test::services::flex::{ApiConfig, Flex, FlexConfig, PolicyConfig};
use pdk_test::services::httpmock::{HttpMock, HttpMockConfig};
use pdk_test::{pdk_test, TestComposite};

use common::*;

// Flex port for the internal test network
const FLEX_PORT: Port = 8081;

// Runtime evidence gate: requires fresh policy assets and operator-supplied local registration.
async fn exercise_mode(mode: &str) -> anyhow::Result<()> {
    // Configure an HttpMock service
    let httpmock_config = HttpMockConfig::builder()
        .port(80)
        .version("latest")
        .hostname("backend")
        .build();

    let policy_config = PolicyConfig::builder()
        .name(POLICY_NAME)
        .configuration(serde_json::json!({
            "decoyTools": ["dump_all_records"],
            "mode": mode,
            "alertHeader": "x-agent-decoy-sentinel"
        }))
        .build();

    let api_config = ApiConfig::builder()
        .name("myApi")
        .upstream(&httpmock_config)
        .path("/anything/echo/")
        .port(FLEX_PORT)
        .policies([policy_config])
        .build();

    // Configure a Flex service
    let flex_config = FlexConfig::builder()
        .version("1.14.0")
        .hostname("local-flex")
        .with_api(api_config)
        .config_mounts([
            (POLICY_DIR, "custom-policies"),
            (COMMON_CONFIG_DIR, "common"),
        ])
        .build();

    // Compose the services
    let composite = TestComposite::builder()
        .with_service(flex_config)
        .with_service(httpmock_config)
        .build()
        .await?;

    // Get a handle to the Flex service
    let flex: Flex = composite.service()?;

    // Get an external URL to point the Flex service
    let flex_url = flex.external_url(FLEX_PORT).unwrap();

    // Get a handle to the HttpMock service
    let httpmock: HttpMock = composite.service()?;

    // Create a MockServer
    let mock_server = MockServer::connect_async(httpmock.socket()).await;

    let upstream = mock_server
        .mock_async(|when, then| {
            when.any_request();
            then.status(200)
                .header("content-type", "application/json")
                .body(r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#);
        })
        .await;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()?;
    let clean = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_orders"}}"#;
    let response = client
        .post(&flex_url)
        .header("content-type", "application/json")
        .body(clean)
        .send()
        .await?;
    assert_eq!(response.status(), 200);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&response.bytes().await?)?["result"]["ok"],
        true
    );
    upstream.assert_hits_async(1).await;

    upstream.delete_async().await;
    let list = r#"{"jsonrpc":"2.0","id":5,"method":"tools/list"}"#;
    let list_mock = mock_server
        .mock_async(|when, then| {
            when.body(list);
            then.status(200).body("discovery");
        })
        .await;
    let response = client
        .post(&flex_url)
        .header("content-type", "application/json")
        .body(list)
        .send()
        .await?;
    assert_eq!(response.status(), 200);
    assert_eq!(response.text().await?, "discovery");
    list_mock.assert_hits_async(1).await;
    list_mock.delete_async().await;

    for body in [
        r#"{"jsonrpc":"2.0","id":"server-1","result":{"name":"dump_all_records"}}"#,
        r#"{"jsonrpc":"2.0","id":"server-2","error":{"code":-32601,"message":"dump_all_records"}}"#,
    ] {
        let fixture = mock_server
            .mock_async(|when, then| {
                when.body(body);
                then.status(202);
            })
            .await;
        let response = client
            .post(&flex_url)
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await?;
        assert_eq!(response.status(), 202);
        assert!(response.bytes().await?.is_empty());
        fixture.assert_hits_async(1).await;
        fixture.delete_async().await;
    }

    for (body, content_type, block_status, detected) in [
        (
            r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"dump_all_records"}}"#,
            "application/json",
            200,
            true,
        ),
        (
            r#"[{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"dump_all_records"}},{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"get_orders"}}]"#,
            "application/json",
            200,
            true,
        ),
        (
            r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"dump_all_records","name":"get_orders"}}"#,
            "application/json",
            400,
            false,
        ),
        (
            r#"[{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"dump_all_records"}},42]"#,
            "application/json",
            400,
            false,
        ),
        (
            r#"{"jsonrpc":"2.0","id":true,"method":"tools/call","params":{"name":"dump_all_records"}}"#,
            "application/json",
            400,
            false,
        ),
        (
            r#"{"jsonrpc":"2.0","id":7,"method":"tools/list","params":7}"#,
            "application/json",
            400,
            false,
        ),
        (
            r#"{"jsonrpc":"2.0","id":7,"error":{"code":"invalid","message":"bad"}}"#,
            "application/json",
            400,
            false,
        ),
        (
            r#"[{"jsonrpc":"2.0","id":"server","result":{}},{"jsonrpc":"2.0","method":"tools/call","params":{"name":"dump_all_records"}},{"jsonrpc":"2.0","id":7,"method":"tools/list"},{"jsonrpc":"2.0","id":8,"method":"tools/list"}]"#,
            "application/json",
            200,
            true,
        ),
        (
            r#"[{"jsonrpc":"2.0","id":"server","result":{}},{"jsonrpc":"2.0","method":"tools/call","params":{"name":"dump_all_records"}}]"#,
            "application/json",
            202,
            true,
        ),
        ("not JSON", "application/json", 400, false),
        ("not JSON", "text/plain", 415, false),
        (
            r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"dump_all_records"}}"#,
            "application/json",
            202,
            true,
        ),
    ] {
        let fixture = mock_server
            .mock_async(|when, then| {
                let when = when.body(body);
                if detected {
                    when.header("x-agent-decoy-sentinel", "fired");
                }
                then.status(200).body("forwarded");
            })
            .await;
        let response = client
            .post(&flex_url)
            .header("content-type", content_type)
            .body(body)
            .send()
            .await?;
        if mode == "monitor" {
            assert_eq!(response.status(), 200);
            assert_eq!(response.text().await?, "forwarded");
            fixture.assert_hits_async(1).await;
        } else {
            assert_eq!(response.status(), block_status);
            let bytes = response.bytes().await?;
            if block_status == 202 {
                assert!(bytes.is_empty());
            }
            if block_status == 200 {
                let value: serde_json::Value = serde_json::from_slice(&bytes)?;
                let errors = if let Some(batch) = value.as_array() {
                    batch.clone()
                } else {
                    vec![value]
                };
                assert_eq!(errors.len(), if body.starts_with('[') { 2 } else { 1 });
                for (index, error) in errors.iter().enumerate() {
                    assert_eq!(error["id"], 7 + index);
                    assert_eq!(error["error"]["code"], -32008);
                }
            }
            fixture.assert_hits_async(0).await;
        }
        fixture.delete_async().await;
    }
    Ok(())
}

#[pdk_test]
async fn blocks_decoys_without_upstream_execution() -> anyhow::Result<()> {
    exercise_mode("block").await
}

#[pdk_test]
async fn monitor_forwards_exact_bodies_and_marks_detected_decoys() -> anyhow::Result<()> {
    exercise_mode("monitor").await
}
