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

// The smaller gateway cap proves actual buffering enforcement independently of
// this policy's 64 KiB declared-length admission rule.
#[pdk_test]
async fn gateway_resource_limits_bound_buffering_and_stalled_upstreams() -> anyhow::Result<()> {
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
            "mode": "block",
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
        .env([
            ("FLEX_DOWNSTREAM_CONNECTION_BUFFER_LIMIT_BYTES", "4096"),
            ("FLEX_UPSTREAM_RESPONSE_TIMEOUT_SECONDS", "1"),
        ])
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

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .build()?;
    let clean = mock_server
        .mock_async(|when, then| {
            when.body("clean-control");
            then.status(200)
                .header("content-type", "text/plain")
                .body("clean-response");
        })
        .await;
    let response = client
        .post(&flex_url)
        .header("content-type", "text/plain")
        .body("clean-control")
        .send()
        .await?;
    assert_eq!(response.status(), 200);
    assert_eq!(response.text().await?, "clean-response");
    clean.assert_hits_async(1).await;
    clean.delete_async().await;

    let large = "x".repeat(8192);
    let oversized_request = mock_server
        .mock_async(|when, then| {
            when.body(large.as_str());
            then.status(200)
                .header("content-type", "text/plain")
                .body("unexpected-forwarding");
        })
        .await;
    let response = client
        .post(&flex_url)
        .header("content-type", "text/plain")
        .body(large)
        .send()
        .await?;
    assert_eq!(
        response.status(),
        413,
        "gateway cap must reject a body below the policy admission ceiling"
    );
    oversized_request.assert_hits_async(0).await;
    oversized_request.delete_async().await;

    for content_type in ["text/plain", "text/event-stream"] {
        let payload = format!("{HONEYTOKEN}{}", "x".repeat(8192));
        let fixture = mock_server
            .mock_async(|when, then| {
                when.body("large-response");
                then.status(200)
                    .header("content-type", content_type)
                    .body(payload);
            })
            .await;
        let response = client
            .post(&flex_url)
            .header("content-type", "text/plain")
            .body("large-response")
            .send()
            .await?;
        assert_eq!(
            response.status(),
            500,
            "gateway cap must abort buffered response"
        );
        assert!(!response.text().await?.contains(HONEYTOKEN));
        fixture.assert_hits_async(1).await;
        fixture.delete_async().await;
    }
    let stalled = mock_server
        .mock_async(|when, then| {
            when.body("stalled-response");
            then.status(200)
                .header("content-type", "text/plain")
                .delay(std::time::Duration::from_secs(3))
                .body(HONEYTOKEN);
        })
        .await;
    let response = client
        .post(&flex_url)
        .header("content-type", "text/plain")
        .body("stalled-response")
        .send()
        .await?;
    assert_eq!(
        response.status(),
        504,
        "gateway timeout must win before the client timeout"
    );
    assert!(!response.text().await?.contains(HONEYTOKEN));
    stalled.assert_hits_async(1).await;
    Ok(())
}

// Rebuild the fixture from current sources; the pinned base must be cached locally.
#[pdk_test]
async fn gateway_bounds_active_and_unknown_length_streams() -> anyhow::Result<()> {
    let build = std::process::Command::new("docker")
        .args([
            "build",
            "--pull=false",
            "--network=none",
            "-t",
            "agent-decoy-streaming:review",
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/streaming-backend"),
        ])
        .output()?;
    assert!(
        build.status.success(),
        "streaming fixture build failed; cache the pinned Python base first"
    );
    let httpmock_config = HttpMockConfig::builder()
        .port(80)
        .image_name("agent-decoy-streaming")
        .version("review")
        .hostname("backend")
        .build();
    let policy_config = PolicyConfig::builder()
        .name(POLICY_NAME)
        .configuration(serde_json::json!({
            "honeytokens": [HONEYTOKEN],
            "decoyIds": ["integration-honeytoken"],
            "mode": "block",
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
        .env([
            ("FLEX_DOWNSTREAM_CONNECTION_BUFFER_LIMIT_BYTES", "4096"),
            ("FLEX_UPSTREAM_RESPONSE_TIMEOUT_SECONDS", "1"),
        ])
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

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .build()?;
    for command in [
        "clean",
        "finite",
        "oversized",
        "active",
        "malformed",
        "clean",
    ] {
        let start = std::time::Instant::now();
        let response = client
            .post(&flex_url)
            .header("content-type", "text/plain")
            .body(command)
            .send()
            .await?;
        let status = response.status();
        if command == "finite" {
            assert_eq!(status, 200);
            assert_eq!(
                response.headers().get("x-agent-decoy-tripwire").unwrap(),
                "withheld;reason=uninspectable-body"
            );
        }
        let body = response.bytes().await?;
        assert!(!body
            .windows(HONEYTOKEN.len())
            .any(|part| part == HONEYTOKEN.as_bytes()));
        match command {
            "clean" => {
                assert_eq!(status, 200);
                assert_eq!(body.as_ref(), b"clean");
            }
            "active" => {
                assert_eq!(status, 504);
                assert!(start.elapsed() < std::time::Duration::from_secs(5));
            }
            "oversized" | "malformed" => assert!(status.is_server_error()),
            "finite" => assert!(body.is_empty()),
            _ => unreachable!(),
        }
    }
    Ok(())
}

#[pdk_test]
async fn raw_framing_idle_upload_and_same_socket_reuse() -> anyhow::Result<()> {
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
            "mode": "block",
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
        .env([
            ("FLEX_DOWNSTREAM_CONNECTION_BUFFER_LIMIT_BYTES", "4096"),
            ("FLEX_UPSTREAM_RESPONSE_TIMEOUT_SECONDS", "1"),
            ("FLEX_STREAM_IDLE_TIMEOUT_SECONDS", "1"),
        ])
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

    let clean = mock_server
        .mock_async(|when, then| {
            when.body("clean");
            then.status(200)
                .header("content-type", "text/plain")
                .body("safe");
        })
        .await;
    let never = mock_server
        .mock_async(|when, then| {
            when.any_request();
            then.status(200).body("unexpected");
        })
        .await;
    // This object owns one TCP stream; it has no reconnect mechanism.
    let mut connection = raw::Connection::new(&flex_url)?;
    let clean_wire=b"POST /anything/echo/ HTTP/1.1\r\nHost: localhost\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nclean";
    connection.send(clean_wire)?;
    assert_eq!(connection.response()?, (200, b"safe".to_vec()));
    let blocked=format!("POST /anything/echo/ HTTP/1.1\r\nHost: localhost\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",HONEYTOKEN.len(),HONEYTOKEN);
    connection.send(blocked.as_bytes())?;
    let (status, body) = connection.response()?;
    assert_eq!(status, 403);
    assert!(!String::from_utf8_lossy(&body).contains(HONEYTOKEN));
    connection.send(clean_wire)?;
    assert_eq!(connection.response()?, (200, b"safe".to_vec()));
    clean.assert_hits_async(2).await;

    for headers in [
        "Content-Length: 8\r\nTransfer-Encoding: chunked",
        "Content-Length: 8\r\nContent-Length: 9",
    ] {
        let mut conn = raw::Connection::new(&flex_url)?;
        conn.send(format!("POST /anything/echo/ HTTP/1.1\r\nHost: localhost\r\nContent-Type: text/plain\r\n{headers}\r\n\r\n0\r\n\r\nsmuggled").as_bytes())?;
        let (status, body) = conn.response()?;
        assert_eq!(status, 400);
        assert!(!String::from_utf8_lossy(&body).contains(HONEYTOKEN));
    }
    let mut slow = raw::Connection::new(&flex_url)?;
    slow.send(b"POST /anything/echo/ HTTP/1.1\r\nHost: localhost\r\nContent-Type: text/plain\r\nContent-Length: 100\r\n\r\nsmuggled")?;
    let start = std::time::Instant::now();
    let (status, _) = slow.response()?;
    assert_eq!(status, 408);
    assert!(start.elapsed() < std::time::Duration::from_secs(5));
    never.assert_hits_async(0).await;
    Ok(())
}
