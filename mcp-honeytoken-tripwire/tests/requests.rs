// Copyright (c) 2026 msaleme. Licensed under the MIT License.

mod common;

use httpmock::MockServer;
use pdk_test::port::Port;
use pdk_test::services::flex::{ApiConfig, Flex, FlexConfig, PolicyConfig};
use pdk_test::services::httpmock::{HttpMock, HttpMockConfig};
use pdk_test::{pdk_test, TestComposite};

use common::*;

const FLEX_PORT: Port = 8081;
const HONEYTOKEN: &str = "acct_DECOY_9x1f-do-not-use";

async fn exercise_mode(mode: &str) -> anyhow::Result<()> {
    let httpmock_config = HttpMockConfig::builder()
        .port(80)
        .version("latest")
        .hostname("backend")
        .build();
    let policy_config = PolicyConfig::builder()
        .name(POLICY_NAME)
        .configuration(serde_json::json!({
            "honeytokens": [HONEYTOKEN],
            "decoyIds": ["integration-honeytoken"],
            "mode": mode,
            "alertHeader": "x-agent-decoy-tripwire",
            "caseSensitive": false
        }))
        .build();
    let api_config = ApiConfig::builder()
        .name("myApi")
        .upstream(&httpmock_config)
        .path("/anything/echo/")
        .port(FLEX_PORT)
        .policies([policy_config])
        .build();
    let flex_config = FlexConfig::builder()
        .version("1.14.0")
        .hostname("local-flex")
        .with_api(api_config)
        .config_mounts([
            (POLICY_DIR, "custom-policies"),
            (COMMON_CONFIG_DIR, "common"),
        ])
        .build();
    let composite = TestComposite::builder()
        .with_service(flex_config)
        .with_service(httpmock_config)
        .build()
        .await?;

    let flex: Flex = composite.service()?;
    let flex_url = flex.external_url(FLEX_PORT).unwrap();
    let httpmock: HttpMock = composite.service()?;
    let mock_server = MockServer::connect_async(httpmock.socket()).await;
    let upstream = mock_server
        .mock_async(|when, then| {
            when.any_request();
            then.status(200)
                .header("content-type", "application/json")
                .body("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}");
        })
        .await;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()?;
    let legitimate = client
        .post(&flex_url)
        .header("content-type", "application/json")
        .body(
            serde_json::json!({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "get_orders", "arguments": {}}
            })
            .to_string(),
        )
        .send()
        .await?;
    assert_eq!(legitimate.status(), 200);
    upstream.assert_async().await;

    if mode == "block" {
        let blocked = client
            .post(&flex_url)
            .header("content-type", "application/json")
            .body(
                serde_json::json!({
                    "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                    "params": {"account": HONEYTOKEN}
                })
                .to_string(),
            )
            .send()
            .await?;
        assert_eq!(blocked.status(), 200);
        assert_eq!(
            blocked
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("application/json")
        );
        let body: serde_json::Value = serde_json::from_str(&blocked.text().await?)?;
        assert_eq!(body["id"], 2);
        assert_eq!(body["error"]["code"], -32008);
        assert_eq!(
            upstream.hits_async().await,
            1,
            "blocked honeytoken request must not reach upstream"
        );
    }
    upstream.delete_async().await;
    for (content_type, payload) in [
        ("text/plain", "x".repeat(65537).into_bytes()),
        ("text/event-stream", b"data: excluded\n\n".to_vec()),
        ("application/json", vec![0xff, 0xfe]),
    ] {
        let fixture = mock_server
            .mock_async(|when, then| {
                when.any_request();
                then.status(200)
                    .header("content-type", "text/plain")
                    .body("forwarded");
            })
            .await;
        let response = client
            .post(&flex_url)
            .header("content-type", content_type)
            .body(payload)
            .send()
            .await?;
        assert_eq!(response.status(), if mode == "block" { 415 } else { 200 });
        fixture
            .assert_hits_async(usize::from(mode == "monitor"))
            .await;
        fixture.delete_async().await;
    }
    // Parsing depth/range failures must not turn escaped matches into clean bodies.
    for token in [r"\u0061cct_DECOY_9x1f-do-not-use", "clean"] {
        for payload in [
            format!(
                r#"{{"token":"{token}","padding":{}0{}}}"#,
                "[".repeat(128),
                "]".repeat(128)
            ),
            format!(r#"{{"token":"{token}","padding":1e400}}"#),
            format!(r#"{{"token":"{token}","padding":}}"#),
        ] {
            let fixture = mock_server
                .mock_async(|when, then| {
                    when.any_request();
                    then.status(200)
                        .header("content-type", "application/problem+json")
                        .body(payload.as_str());
                })
                .await;
            let rejected = client
                .post(&flex_url)
                .header("content-type", "application/json")
                .body(payload.clone())
                .send()
                .await?;
            assert_eq!(rejected.status(), if mode == "block" { 415 } else { 200 });
            fixture
                .assert_hits_async(usize::from(mode == "monitor"))
                .await;
            if mode == "monitor" {
                assert_eq!(rejected.bytes().await?.as_ref(), payload.as_bytes());
            }
            let response = client
                .post(&flex_url)
                .header("content-type", "application/json")
                .body("{}")
                .send()
                .await?;
            assert_eq!(response.status(), 200);
            let headers = response.headers().clone();
            let bytes = response.bytes().await?;
            if mode == "block" {
                assert!(bytes.is_empty());
                assert_eq!(
                    headers.get("x-agent-decoy-tripwire").unwrap(),
                    "withheld;reason=uninspectable-json"
                );
            } else {
                assert_eq!(bytes.as_ref(), payload.as_bytes());
            }
            if let Some(length) = headers.get("content-length") {
                assert_eq!(length.to_str()?.parse::<usize>()?, bytes.len());
            }
            fixture
                .assert_hits_async(1 + usize::from(mode == "monitor"))
                .await;
            fixture.delete_async().await;
        }
    }
    for (index, content_type, encoding, payload) in [
        (
            0,
            "application/json",
            None,
            format!(r#"{{"record":"{HONEYTOKEN}"}}"#),
        ),
        (1, "text/plain", None, format!("prefix {HONEYTOKEN} suffix")),
        (
            2,
            "text/event-stream",
            None,
            format!("data: {HONEYTOKEN}\n\n"),
        ),
        (
            3,
            "application/json",
            Some("gzip"),
            format!(r#"{{"record":"{HONEYTOKEN}"}}"#),
        ),
        (4, "text/plain", None, "x".repeat(65537)),
    ] {
        let request = format!("response-case-{index}");
        let fixture = mock_server
            .mock_async(|when, then| {
                when.body(request.as_str());
                let then = then.status(200).header("content-type", content_type);
                let then = if let Some(encoding) = encoding {
                    then.header("content-encoding", encoding)
                } else {
                    then
                };
                then.body(payload.as_str());
            })
            .await;
        let response = client
            .post(&flex_url)
            .header("content-type", "text/plain")
            .body(request)
            .send()
            .await?;
        assert_eq!(response.status(), 200, "case {index}");
        let headers = response.headers().clone();
        let bytes = response.bytes().await?;
        if let Some(length) = headers.get("content-length") {
            assert_eq!(
                length.to_str()?.parse::<usize>()?,
                bytes.len(),
                "stale framing in case {index}"
            );
        }
        if mode == "monitor" {
            assert_eq!(bytes.as_ref(), payload.as_bytes());
            if index < 2 {
                assert_eq!(
                    headers.get("x-agent-decoy-tripwire").unwrap(),
                    "fired;direction=response"
                );
            }
        } else {
            assert!(!String::from_utf8_lossy(&bytes).contains(HONEYTOKEN));
            assert!(headers.get("content-encoding").is_none());
            assert!(headers.get("x-agent-decoy-tripwire").is_some());
            if index >= 2 {
                assert!(bytes.is_empty(), "unsupported response must be withheld");
            }
            if index < 2 {
                assert_eq!(
                    bytes.as_ref(),
                    payload.replace(HONEYTOKEN, "[decoy-withheld]").as_bytes()
                );
            }
        }
        fixture.assert_hits_async(1).await;
        fixture.delete_async().await;
    }
    Ok(())
}

#[pdk_test]
async fn block_checks_request_denial_response_redaction_and_transport_exclusions(
) -> anyhow::Result<()> {
    exercise_mode("block").await
}

#[pdk_test]
async fn monitor_preserves_response_bytes_including_excluded_transports() -> anyhow::Result<()> {
    exercise_mode("monitor").await
}
