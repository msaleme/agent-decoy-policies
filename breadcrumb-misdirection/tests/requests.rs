// Copyright 2026 Salesforce, Inc. All rights reserved.
// Modifications Copyright (c) 2026 msaleme. Licensed under the MIT License.

mod common;

use httpmock::MockServer;
use pdk_test::port::Port;
use pdk_test::services::flex::{ApiConfig, Flex, FlexConfig, PolicyConfig};
use pdk_test::services::httpmock::{HttpMock, HttpMockConfig};
use pdk_test::{pdk_test, TestComposite};

use common::*;

// Flex port for the internal test network
const FLEX_PORT: Port = 8081;

// Runtime evidence gate: fresh assets and operator-supplied local registration required.
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
            "breadcrumb": "internal://breadcrumb",
            "mode": mode,
            "seeding": "enabled",
            "alertHeader": "x-agent-decoy-breadcrumb"
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

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()?;
    let clean = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"lookup"}}"#;
    let clean_mock = mock_server
        .mock_async(|when, then| {
            when.body(clean);
            then.status(200).body("clean");
        })
        .await;
    let response = client
        .post(&flex_url)
        .header("content-type", "application/json")
        .body(clean)
        .send()
        .await?;
    assert_eq!(response.status(), 200);
    assert_eq!(response.text().await?, "clean");
    clean_mock.assert_hits_async(1).await;

    let follow = r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"internal://breadcrumb"}}"#;
    let sanitized = r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":""}}"#;
    let original_mock = mock_server
        .mock_async(|when, then| {
            when.body(follow)
                .header("x-agent-decoy-breadcrumb", "followed");
            then.status(200).body("original");
        })
        .await;
    let sanitized_mock = mock_server
        .mock_async(|when, then| {
            when.body(sanitized)
                .header("x-agent-decoy-breadcrumb", "followed");
            then.status(200).body("sanitized");
        })
        .await;
    let response = client
        .post(&flex_url)
        .header("content-type", "application/json")
        .body(follow)
        .send()
        .await?;
    if mode == "block" {
        assert_eq!(response.status(), 403);
    } else {
        assert_eq!(response.status(), 200);
        assert_eq!(
            response.text().await?,
            if mode == "observe" {
                "original"
            } else {
                "sanitized"
            }
        );
    }
    original_mock
        .assert_hits_async(usize::from(mode == "observe"))
        .await;
    sanitized_mock
        .assert_hits_async(usize::from(mode == "sanitize"))
        .await;

    let list = r#"{"jsonrpc":"2.0","id":4,"method":"tools/list"}"#;
    let list_mock = mock_server.mock_async(|when, then| {
        when.body(list);
        then.status(200).header("content-type","application/json")
            .body(r#"{"jsonrpc":"2.0","id":4,"result":{"tools":[{"name":"lookup","description":"Lookup"}]}}"#);
    }).await;
    let response = client
        .post(&flex_url)
        .header("content-type", "application/json")
        .body(list)
        .send()
        .await?;
    assert_eq!(response.status(), 200);
    let length = response
        .headers()
        .get("content-length")
        .map(|v| v.to_str().unwrap().parse::<usize>().unwrap());
    let bytes = response.bytes().await?;
    if let Some(length) = length {
        assert_eq!(length, bytes.len());
    }
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    assert_eq!(
        value["result"]["tools"][0]["description"],
        "Lookup internal://breadcrumb"
    );
    list_mock.assert_hits_async(1).await;
    list_mock.delete_async().await;
    for (content_type, encoding, payload) in [
        (
            "text/event-stream",
            None,
            "data: {\"jsonrpc\":\"2.0\",\"id\":4,\"result\":{\"tools\":[]}}\n\n",
        ),
        ("application/json", Some("gzip"), "encoded bytes"),
    ] {
        let fixture = mock_server
            .mock_async(|when, then| {
                when.body(list);
                let then = then.status(200).header("content-type", content_type);
                let then = if let Some(encoding) = encoding {
                    then.header("content-encoding", encoding)
                } else {
                    then
                };
                then.body(payload);
            })
            .await;
        let response = client
            .post(&flex_url)
            .header("content-type", "application/json")
            .body(list)
            .send()
            .await?;
        assert_eq!(response.status(), 200);
        assert_eq!(
            response.bytes().await?.as_ref(),
            payload.as_bytes(),
            "unsupported seeding response must remain unchanged"
        );
        fixture.assert_hits_async(1).await;
        fixture.delete_async().await;
    }
    for (content_type, payload) in [
        ("text/event-stream", b"uninspectable".to_vec()),
        ("application/json", vec![0xff, 0xfe]),
        ("text/plain", "x".repeat(65537).into_bytes()),
    ] {
        let fixture = mock_server
            .mock_async(|when, then| {
                when.any_request();
                then.status(200).body("unchanged");
            })
            .await;
        let response = client
            .post(&flex_url)
            .header("content-type", content_type)
            .body(payload)
            .send()
            .await?;
        assert_eq!(response.status(), if mode == "observe" { 200 } else { 415 });
        fixture
            .assert_hits_async(usize::from(mode == "observe"))
            .await;
        fixture.delete_async().await;
    }
    Ok(())
}

#[pdk_test]
async fn observe_preserves_followed_body_and_seeds_discovery() -> anyhow::Result<()> {
    exercise_mode("observe").await
}

#[pdk_test]
async fn sanitize_removes_marker_and_seeds_discovery() -> anyhow::Result<()> {
    exercise_mode("sanitize").await
}

#[pdk_test]
async fn block_refuses_follow_without_upstream_execution() -> anyhow::Result<()> {
    exercise_mode("block").await
}
