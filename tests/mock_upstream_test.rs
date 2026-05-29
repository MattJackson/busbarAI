// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicU64, AtomicUsize},
    Arc,
};

use busbar::auth::AuthMiddleware;
use busbar::config::AuthCfg;
use busbar::forward::forward;
use busbar::proto::AnthropicProtocol;
use busbar::state::{App, Lane};
use reqwest::Client;

use tests_support::mock_upstream::{MockResponse, MockServer, MockServerState};

#[tokio::test]
async fn test_mock_server_ok_response() {
    use serde_json::json;

    let state = Arc::new(MockServerState::new());
    state.push(MockResponse::Ok {
        status: axum::http::StatusCode::OK,
        body: json!({ "message": "hello" }),
    });

    let server = MockServer::new(state).await;
    let client = Client::new();

    let res = client
        .get(format!("http://{}/v1/messages", server.address()))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), axum::http::StatusCode::OK);

    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["message"], "hello");

    server.shutdown().await;
}

#[tokio::test]
async fn test_mock_server_rate_limit() {
    let state = Arc::new(MockServerState::new());
    state.push(MockResponse::RateLimit {
        status: axum::http::StatusCode::TOO_MANY_REQUESTS,
        provider_signal: Some("1302"),
    });

    let server = MockServer::new(state).await;
    let client = Client::new();

    let res = client
        .get(format!("http://{}/v1/messages", server.address()))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), axum::http::StatusCode::TOO_MANY_REQUESTS);

    server.shutdown().await;
}

#[tokio::test]
async fn test_mock_server_billing_error() {
    let state = Arc::new(MockServerState::new());
    state.push(MockResponse::Billing {
        status: axum::http::StatusCode::PAYMENT_REQUIRED,
        code: "1113",
        message: "insufficient balance",
    });

    let server = MockServer::new(state).await;
    let client = Client::new();

    let res = client
        .get(format!(
            "http://{}/v1/messages",
            server.address()
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), axum::http::StatusCode::PAYMENT_REQUIRED);

    server.shutdown().await;
}

#[tokio::test]
async fn test_mock_server_auth_error() {
    let state = Arc::new(MockServerState::new());
    state.push(MockResponse::Auth {
        status: axum::http::StatusCode::UNAUTHORIZED,
    });

    let server = MockServer::new(state).await;
    let client = Client::new();

    let res = client
        .get(format!(
            "http://{}/v1/messages",
            server.address()
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), axum::http::StatusCode::UNAUTHORIZED);

    server.shutdown().await;
}

#[tokio::test]
async fn test_mock_server_5xx_error() {
    use serde_json::json;

    let state = Arc::new(MockServerState::new());
    state.push(MockResponse::ServerError {
        status: axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        body: json!({ "error": "server error" }),
    });

    let server = MockServer::new(state).await;
    let client = Client::new();

    let res = client
        .get(format!(
            "http://{}/v1/messages",
            server.address()
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), axum::http::StatusCode::INTERNAL_SERVER_ERROR);

    server.shutdown().await;
}

#[tokio::test]
async fn test_mock_server_smoke_integration() {
    use serde_json::json;

    let state = Arc::new(MockServerState::new());

    // First request: 2xx success
    state.push(MockResponse::Ok {
        status: axum::http::StatusCode::OK,
        body: json!({ "content": ["Hello world"], "model": "claude-3-haiku-20240307", "stop": [] }),
    });

    let server = MockServer::new(state.clone()).await;

    // Create a test app with a lane pointing to the mock server
    let protocol = Arc::new(AnthropicProtocol::new());
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap();

    let mut lanes = Vec::new();
    let lane = Lane {
        model: "claude-3-haiku".to_string(),
        provider: "test-provider".to_string(),
        base_url: server.base_url(),
        api_key: "test-key".to_string(),
        protocol,
        sem: Arc::new(tokio::sync::Semaphore::new(10)),
        max: 10,
        limited: false,
        budget: AtomicI64::new(100),
        cooldown_until: AtomicU64::new(0),
        streak: AtomicU32::new(0),
        dead: AtomicBool::new(false),
        dead_reason: std::sync::Mutex::new(String::new()),
        inflight: AtomicI64::new(0),
        ok: AtomicU64::new(0),
        err: AtomicU64::new(0),
    };
    lanes.push(lane);

    let by_model = {
        let mut m = HashMap::new();
        m.insert("claude-3-haiku".to_string(), 0);
        m
    };

    let pools = {
        let mut p = HashMap::new();
        p.insert("default".to_string(), vec![0]);
        p
    };

    let cfg = AuthCfg::default_none();
    let auth = Arc::new(AuthMiddleware::new(&cfg));

    let app = App {
        lanes,
        by_model,
        pools,
        rr: AtomicUsize::new(0),
        client,
        auth,
    };
    let app = Arc::new(app);

    // Test 1: Forward should succeed with 2xx response
    let body_bytes = serde_json::to_vec(&json!({
        "model": "claude-3-haiku",
        "messages": [{"role": "user", "content": "hi"}],
        "max_tokens": 100
    }))
    .unwrap();

    let response = forward(app.clone(), vec![0], body_bytes.into()).await;
    assert_eq!(response.status().as_u16(), 200);

    // Test 2: Now send a 429 and verify it triggers cooldown
    state.push(MockResponse::RateLimit {
        status: axum::http::StatusCode::TOO_MANY_REQUESTS,
        provider_signal: Some("1302"),
    });

    let body_bytes = serde_json::to_vec(&json!({
        "model": "claude-3-haiku",
        "messages": [{"role": "user", "content": "hi"}],
        "max_tokens": 100
    }))
    .unwrap();

    let response = forward(app.clone(), vec![0], body_bytes.into()).await;

    // The lane should have been rate limited (cooldown transient) and we get SERVICE_UNAVAILABLE
    assert_eq!(response.status().as_u16(), 503);

    server.shutdown().await;
}
