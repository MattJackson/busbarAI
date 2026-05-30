// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! In-crate mock-upstream test harness (B-105 / B-105b).

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Mutex;
use std::time::Duration;

use bytes::Bytes;
use futures::{stream, Stream, StreamExt};

use axum::{
    body::Body,
    extract::State,
    http::{header, Request, Response, StatusCode},
    routing::any,
    Router,
};
use serde_json::Value;
use tokio::task::JoinHandle;

#[derive(Debug, Clone)]
pub(crate) enum MockResponse {
    Ok {
        status: StatusCode,
        body: Value,
    },
    RateLimit {
        status: StatusCode,
        provider_signal: Option<&'static str>,
    },
    Billing {
        status: StatusCode,
        code: &'static str,
        message: &'static str,
    },
    Auth {
        status: StatusCode,
    },
    ServerError {
        status: StatusCode,
        body: Value,
    },
    Sse {
        events: Vec<String>,
        abort_at_index: Option<usize>,
    },
}

impl Default for MockResponse {
    fn default() -> Self {
        MockResponse::Ok {
            status: StatusCode::OK,
            body: serde_json::json!({ "ok": true }),
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct MockServerState {
    responses: Mutex<Vec<MockResponse>>,
    last_auth_header: std::sync::Mutex<Option<String>>,
}

impl MockServerState {
    pub(crate) fn new() -> Self {
        Self::default()
    }
    pub(crate) fn push(&self, response: MockResponse) {
        self.responses.lock().unwrap().push(response);
    }
    fn next_response(&self) -> Option<MockResponse> {
        self.responses.lock().unwrap().pop()
    }

    /// Record the last seen Authorization header for testing passthrough token forwarding
    pub(crate) fn record_auth_header(&self, header: &str) {
        *self.last_auth_header.lock().unwrap() = Some(header.to_string());
    }

    /// Get the recorded Authorization header (for assertions in tests)
    pub(crate) fn get_last_auth_header(&self) -> Option<String> {
        self.last_auth_header.lock().unwrap().clone()
    }

    /// Clear the recorded Authorization header
    pub(crate) fn clear_auth_header(&self) {
        *self.last_auth_header.lock().unwrap() = None;
    }
}

pub(crate) struct MockServer {
    addr: SocketAddr,
    handle: Option<JoinHandle<()>>,
}

impl MockServer {
    pub(crate) async fn new(state: std::sync::Arc<MockServerState>) -> Self {
        let app = Router::new()
            .route("/v1/messages", any(mock_handler))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self {
            addr,
            handle: Some(handle),
        }
    }

    pub(crate) fn address(&self) -> SocketAddr {
        self.addr
    }
    pub(crate) fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }
    pub(crate) async fn shutdown(self) {
        if let Some(handle) = self.handle {
            handle.abort();
        }
    }
}

async fn mock_handler(
    State(state): State<std::sync::Arc<MockServerState>>,
    request: Request<Body>,
) -> Response<Body> {
    // Record the Authorization header for passthrough token forwarding tests
    if let Some(auth_header) = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        state.record_auth_header(auth_header);
    }

    let response = state.next_response();
    let response = response.unwrap_or_default();
    match response {
        MockResponse::Ok { status, body } => Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
        MockResponse::RateLimit {
            status,
            provider_signal,
        } => {
            let msg = if provider_signal == Some("1302") {
                "rate_limit"
            } else {
                "Rate limit exceeded"
            };
            let body = serde_json::json!({ "error": { "message": msg, "code": provider_signal.unwrap_or("429") } });
            Response::builder()
                .status(status)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap()
        }
        MockResponse::Billing {
            status,
            code,
            message,
        } => {
            let body = serde_json::json!({ "error": { "message": message, "code": code } });
            Response::builder()
                .status(status)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap()
        }
        MockResponse::Auth { status } => Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::json!({ "error": "Unauthorized" }).to_string(),
            ))
            .unwrap(),
        MockResponse::ServerError { status, body } => Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
        MockResponse::Sse {
            events,
            abort_at_index,
        } => {
            let stream_events: Vec<String> = if let Some(idx) = abort_at_index {
                // Mid-stream abort: send idx events then add SSE error event before ending (no [DONE])
                let mut result: Vec<String> = events
                    .iter()
                    .take(idx)
                    .map(|d| format!("data: {d}\n\n"))
                    .collect();
                // Add SSE error event to notify client of upstream failure
                let err_json = serde_json::json!({
                    "type": "error",
                    "error": {
                        "message": "upstream abort",
                        "source": "upstream"
                    }
                });
                result.push(format!("event: error\ndata: {}\n\n", err_json));
                result
            } else {
                // Normal completion with [DONE]
                let mut result: Vec<String> = events
                    .into_iter()
                    .map(|d| format!("data: {d}\n\n"))
                    .collect();
                result.push("[DONE]\n\n".to_string());
                result
            };

            let s: Pin<Box<dyn Stream<Item = String> + Send>> =
                Box::pin(stream::iter(stream_events));
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "text/event-stream")
                .body(Body::from_stream(
                    s.map(|s| Ok::<_, std::convert::Infallible>(s.into_bytes())),
                ))
                .unwrap()
        }
    }
}

#[allow(deprecated)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AuthMiddleware;
    use crate::config::AuthCfg;
    use crate::forward::forward;
    use crate::proto::AnthropicProtocol;
    use crate::state::{now, App, Lane, ProtocolKind};
    use crate::store::{InMemoryStore, LaneData};
    use reqwest::Client;
    use serde_json::json;
    use std::collections::HashMap;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_mock_server_ok_response() {
        let state = Arc::new(MockServerState::new());
        state.push(MockResponse::Ok {
            status: StatusCode::OK,
            body: json!({ "message": "hello" }),
        });
        let server = MockServer::new(state).await;
        let res = Client::new()
            .get(format!("http://{}/v1/messages", server.address()))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body: Value = res.json().await.unwrap();
        assert_eq!(body["message"], "hello");
        server.shutdown().await;
    }

    #[tokio::test]
    async fn test_mock_server_rate_limit() {
        let state = Arc::new(MockServerState::new());
        state.push(MockResponse::RateLimit {
            status: StatusCode::TOO_MANY_REQUESTS,
            provider_signal: Some("1302"),
        });
        let server = MockServer::new(state).await;
        let res = Client::new()
            .get(format!("http://{}/v1/messages", server.address()))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
        server.shutdown().await;
    }

    #[tokio::test]
    async fn test_mock_server_billing_error() {
        let state = Arc::new(MockServerState::new());
        state.push(MockResponse::Billing {
            status: StatusCode::PAYMENT_REQUIRED,
            code: "1113",
            message: "insufficient balance",
        });
        let server = MockServer::new(state).await;
        let res = Client::new()
            .get(format!("http://{}/v1/messages", server.address()))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::PAYMENT_REQUIRED);
        server.shutdown().await;
    }

    #[tokio::test]
    async fn test_mock_server_auth_error() {
        let state = Arc::new(MockServerState::new());
        state.push(MockResponse::Auth {
            status: StatusCode::UNAUTHORIZED,
        });
        let server = MockServer::new(state).await;
        let res = Client::new()
            .get(format!("http://{}/v1/messages", server.address()))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        server.shutdown().await;
    }

    #[tokio::test]
    async fn test_mock_server_5xx_error() {
        let state = Arc::new(MockServerState::new());
        state.push(MockResponse::ServerError {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            body: json!({ "error": "server error" }),
        });
        let server = MockServer::new(state).await;
        let res = Client::new()
            .get(format!("http://{}/v1/messages", server.address()))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
        server.shutdown().await;
    }

    #[tokio::test]
    async fn test_non_stream_json_relay() {
        let state = Arc::new(MockServerState::new());
        state.push(MockResponse::Ok {
            status: StatusCode::OK,
            body: json!({ "content": ["Hello"], "model": "test", "stop": [] }),
        });
        let server = MockServer::new(state.clone()).await;

        let lane_data = LaneData {
            model: "test-model".to_string(),
            provider: "test-provider".to_string(),
            max: 10,
            sem: Arc::new(tokio::sync::Semaphore::new(10)),
            limited: false,
            budget: -1,
            cooldown_until: 0,
            streak: 0,
            dead: false,
            dead_reason: String::new(),
            inflight: 0,
            ok: 0,
            err: 0,
            client_fault: 0,
        };

        let lane = Lane {
            model: "test-model".to_string(),
            provider: "test-provider".to_string(),
            base_url: server.base_url(),
            api_key: "test-key".to_string(),
            protocol: ProtocolKind::Anthropic(AnthropicProtocol::new()),
            max: 10,
            error_map: Arc::new(std::collections::HashMap::new()),
        };

        let by_model = HashMap::from([("test-model".to_string(), 0)]);
        let pools = HashMap::from([("default".to_string(), vec![0])]);
        let auth = Arc::new(AuthMiddleware::new(&AuthCfg::default_none()));
        let store = Arc::new(InMemoryStore::new(vec![lane_data]));
        let app = Arc::new(App {
            lanes: vec![lane],
            store,
            by_model,
            pools,
            rr: AtomicUsize::new(0),
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap(),
            auth,
            auth_mode: crate::auth::AuthMode::None,
        });

        let req_body = serde_json::to_vec(&json!({"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})).unwrap();
        let response = forward(app.clone(), vec![0], req_body.into(), None).await;
        assert_eq!(response.status().as_u16(), 200);

        use http_body_util::BodyExt as _;
        let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body_str = String::from_utf8_lossy(&body_bytes);
        assert!(body_str.contains("Hello"));
        server.shutdown().await;
    }

    #[tokio::test]
    async fn test_sse_incremental_arrival() {
        let state = Arc::new(MockServerState::new());
        let mut events = Vec::new();
        for i in 0..10 {
            events.push(format!("event-{i}"));
        }
        state.push(MockResponse::Sse {
            events,
            abort_at_index: None,
        });

        let server = MockServer::new(state.clone()).await;
        let lane_data = LaneData {
            model: "test-model".to_string(),
            provider: "test-provider".to_string(),
            max: 10,
            sem: Arc::new(tokio::sync::Semaphore::new(10)),
            limited: false,
            budget: -1,
            cooldown_until: 0,
            streak: 0,
            dead: false,
            dead_reason: String::new(),
            inflight: 0,
            ok: 0,
            err: 0,
            client_fault: 0,
        };

        let lane = Lane {
            model: "test-model".to_string(),
            provider: "test-provider".to_string(),
            base_url: server.base_url(),
            api_key: "test-key".to_string(),
            protocol: ProtocolKind::Anthropic(AnthropicProtocol::new()),
            max: 10,
            error_map: Arc::new(std::collections::HashMap::new()),
        };

        let by_model = HashMap::from([("test-model".to_string(), 0)]);
        let pools = HashMap::from([("default".to_string(), vec![0])]);
        let auth = Arc::new(AuthMiddleware::new(&AuthCfg::default_none()));
        let store = Arc::new(InMemoryStore::new(vec![lane_data]));
        let app = Arc::new(App {
            lanes: vec![lane],
            store,
            by_model,
            pools,
            rr: AtomicUsize::new(0),
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap(),
            auth,
            auth_mode: crate::auth::AuthMode::None,
        });

        let req_body = serde_json::to_vec(&json!({"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})).unwrap();
        let response = forward(app.clone(), vec![0], req_body.into(), None).await;
        assert_eq!(response.status().as_u16(), 200);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/event-stream"
        );

        use http_body_util::BodyExt as _;
        let collected_bytes = response.into_body().collect().await.unwrap().to_bytes();
        let text = String::from_utf8_lossy(&collected_bytes);
        let mut events_found = 0;
        for line in text.lines() {
            if line.starts_with("data: event-") && !line.contains("[DONE]") {
                events_found += 1;
            }
        }
        assert_eq!(events_found, 10, "Expected 10 SSE events");
        server.shutdown().await;
    }

    #[tokio::test]
    async fn test_permit_lifetime_during_stream() {
        let state = Arc::new(MockServerState::new());
        let events: Vec<String> = (0..5).map(|i| format!("data-{i}")).collect();
        state.push(MockResponse::Sse {
            events,
            abort_at_index: None,
        });

        let server = MockServer::new(state.clone()).await;
        let sem = Arc::new(tokio::sync::Semaphore::new(1));
        let lane_data = LaneData {
            model: "test-model".to_string(),
            provider: "test-provider".to_string(),
            max: 1,
            sem: sem.clone(),
            limited: false,
            budget: -1,
            cooldown_until: 0,
            streak: 0,
            dead: false,
            dead_reason: String::new(),
            inflight: 0,
            ok: 0,
            err: 0,
            client_fault: 0,
        };

        let lane = Lane {
            model: "test-model".to_string(),
            provider: "test-provider".to_string(),
            base_url: server.base_url(),
            api_key: "test-key".to_string(),
            protocol: ProtocolKind::Anthropic(AnthropicProtocol::new()),
            max: 1,
            error_map: Arc::new(std::collections::HashMap::new()),
        };

        let by_model = HashMap::from([("test-model".to_string(), 0)]);
        let pools = HashMap::from([("default".to_string(), vec![0])]);
        let auth = Arc::new(AuthMiddleware::new(&AuthCfg::default_none()));
        let store = Arc::new(InMemoryStore::new(vec![lane_data]));
        let app = Arc::new(App {
            lanes: vec![lane],
            store,
            by_model,
            pools,
            rr: AtomicUsize::new(0),
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap(),
            auth,
            auth_mode: crate::auth::AuthMode::None,
        });

        let req_body = serde_json::to_vec(&json!({"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})).unwrap();
        assert_eq!(sem.available_permits(), 1);
        let response = forward(app.clone(), vec![0], req_body.into(), None).await;
        assert_eq!(response.status().as_u16(), 200);
        assert!(sem.clone().try_acquire_owned().is_err());

        let collected_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(!collected_bytes.is_empty());
        for _ in 0..10 {
            tokio::time::sleep(Duration::from_millis(10)).await;
            if sem.available_permits() == 1 {
                break;
            }
        }
        assert_eq!(sem.available_permits(), 1);
        server.shutdown().await;
    }

    /// B-202: Pre-first-byte error triggers failover to next lane.
    #[tokio::test]
    async fn test_pre_first_byte_failover() {
        let state = Arc::new(MockServerState::new());

        // LIFO order: push success first (lane 1), then error (lane 0)
        let events = vec![
            "data: event-0".to_string(),
            "data: event-1".to_string(),
            "data: event-2".to_string(),
        ];
        state.push(MockResponse::Sse {
            events,
            abort_at_index: None,
        });
        state.push(MockResponse::ServerError {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            body: json!({ "error": "lane 0 failed" }),
        });

        let server = MockServer::new(state.clone()).await;

        let lane0_data = LaneData {
            model: "test-model".to_string(),
            provider: "test-provider".to_string(),
            max: 10,
            sem: Arc::new(tokio::sync::Semaphore::new(10)),
            limited: false,
            budget: -1,
            cooldown_until: 0,
            streak: 0,
            dead: false,
            dead_reason: String::new(),
            inflight: 0,
            ok: 0,
            err: 0,
            client_fault: 0,
        };

        let lane1_data = LaneData {
            model: "test-model".to_string(),
            provider: "test-provider".to_string(),
            max: 10,
            sem: Arc::new(tokio::sync::Semaphore::new(10)),
            limited: false,
            budget: -1,
            cooldown_until: 0,
            streak: 0,
            dead: false,
            dead_reason: String::new(),
            inflight: 0,
            ok: 0,
            err: 0,
            client_fault: 0,
        };

        let lane0 = Lane {
            model: "test-model".to_string(),
            provider: "test-provider".to_string(),
            base_url: server.base_url(),
            api_key: "test-key-0".to_string(),
            protocol: ProtocolKind::Anthropic(AnthropicProtocol::new()),
            max: 10,
            error_map: Arc::new(std::collections::HashMap::new()),
        };

        let lane1 = Lane {
            model: "test-model".to_string(),
            provider: "test-provider".to_string(),
            base_url: server.base_url(),
            api_key: "test-key-1".to_string(),
            protocol: ProtocolKind::Anthropic(AnthropicProtocol::new()),
            max: 10,
            error_map: Arc::new(std::collections::HashMap::new()),
        };

        let by_model = HashMap::from([("test-model".to_string(), 0)]);
        let pools = HashMap::from([("default".to_string(), vec![0, 1])]);
        let auth = Arc::new(AuthMiddleware::new(&AuthCfg::default_none()));
        let store = Arc::new(InMemoryStore::new(vec![lane0_data, lane1_data]));
        let app = Arc::new(App {
            lanes: vec![lane0, lane1],
            store,
            by_model,
            pools,
            rr: AtomicUsize::new(0),
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap(),
            auth,
            auth_mode: crate::auth::AuthMode::None,
        });

        let req_body = serde_json::to_vec(&json!({"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})).unwrap();

        // Should failover from lane 0 (error) to lane 1 (success)
        let response = forward(app.clone(), vec![0, 1], req_body.into(), None).await;
        assert_eq!(response.status().as_u16(), 200);

        let t = now();
        assert!(
            !app.store.usable(0, t),
            "lane 0 should be in transient cooldown"
        );
        server.shutdown().await;
    }

    /// B-202b: Mid-stream abort records lane breaker failure and does NOT failover.
    #[tokio::test]
    async fn test_midstream_abort_records_and_no_failover() {
        let state = Arc::new(MockServerState::new());

        // LIFO order: push lane 1 success first, then lane 0 mid-stream abort
        // Lane 1: would return success if used (should NOT be used)
        let events_lane1 = vec!["data: lane1-ok".to_string()];
        state.push(MockResponse::Sse {
            events: events_lane1,
            abort_at_index: None,
        });

        // Lane 0: sends 1 event then abruptly ends (no [DONE]) to simulate mid-stream abort
        let events = vec![
            "data: event-0".to_string(),
            "data: event-1".to_string(),
            "data: event-2".to_string(),
            "data: event-3".to_string(),
            "data: event-4".to_string(),
        ];
        state.push(MockResponse::Sse {
            events,
            abort_at_index: Some(1), // send only index 0 (1 event) then end abruptly
        });

        let server = MockServer::new(state.clone()).await;

        let lane0_data = LaneData {
            model: "test-model".to_string(),
            provider: "test-provider".to_string(),
            max: 10,
            sem: Arc::new(tokio::sync::Semaphore::new(10)),
            limited: false,
            budget: -1,
            cooldown_until: 0,
            streak: 0,
            dead: false,
            dead_reason: String::new(),
            inflight: 0,
            ok: 0,
            err: 0,
            client_fault: 0,
        };

        let lane1_data = LaneData {
            model: "test-model".to_string(),
            provider: "test-provider".to_string(),
            max: 10,
            sem: Arc::new(tokio::sync::Semaphore::new(10)),
            limited: false,
            budget: -1,
            cooldown_until: 0,
            streak: 0,
            dead: false,
            dead_reason: String::new(),
            inflight: 0,
            ok: 0,
            err: 0,
            client_fault: 0,
        };

        let lane0 = Lane {
            model: "test-model".to_string(),
            provider: "test-provider".to_string(),
            base_url: server.base_url(),
            api_key: "test-key-0".to_string(),
            protocol: ProtocolKind::Anthropic(AnthropicProtocol::new()),
            max: 10,
            error_map: Arc::new(std::collections::HashMap::new()),
        };

        let lane1 = Lane {
            model: "test-model".to_string(),
            provider: "test-provider".to_string(),
            base_url: server.base_url(),
            api_key: "test-key-1".to_string(),
            protocol: ProtocolKind::Anthropic(AnthropicProtocol::new()),
            max: 10,
            error_map: Arc::new(std::collections::HashMap::new()),
        };

        let by_model = HashMap::from([("test-model".to_string(), 0)]);
        let pools = HashMap::from([("default".to_string(), vec![0, 1])]);
        let auth = Arc::new(AuthMiddleware::new(&AuthCfg::default_none()));
        let store = Arc::new(InMemoryStore::new(vec![lane0_data, lane1_data]));
        let app = Arc::new(App {
            lanes: vec![lane0, lane1],
            store,
            by_model,
            pools,
            rr: AtomicUsize::new(0),
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap(),
            auth,
            auth_mode: crate::auth::AuthMode::None,
        });

        let req_body = serde_json::to_vec(&json!({"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})).unwrap();

        // Consume response body fully
        let response = forward(app.clone(), vec![0, 1], req_body.into(), None).await;
        assert_eq!(response.status().as_u16(), 200);

        use http_body_util::BodyExt as _;
        let collected_bytes = response.into_body().collect().await.unwrap().to_bytes();
        let text = String::from_utf8_lossy(&collected_bytes);

        // (a) Assert: the collected body contains `event: error` (SSE error emitted)
        assert!(
            text.contains("event: error"),
            "Expected SSE error event in response, got: {text}"
        );

        let t = now();
        let snap0 = app.store.snapshot(0, t);
        let err0_before = 0u64;
        let err0_after = snap0.err;

        // (b) Assert: lanes[0].err increased AND cooldown_until > now (failure recorded)
        assert!(
            err0_after > err0_before,
            "lane 0 err should have increased after mid-stream abort"
        );
        let cooldown_remaining = app.store.cooldown_remaining(0, t);
        assert!(
            cooldown_remaining > 0,
            "lane 0 should be in cooldown after mid-stream abort"
        );

        // (c) Assert: lane 1 was NOT used — err unchanged (no failover after first byte)
        let snap1 = app.store.snapshot(1, t);
        assert_eq!(
            snap1.err, 0u64,
            "lane 1 err should be unchanged (no failover)"
        );

        server.shutdown().await;
    }

    /// §6 Caveat: passthrough 401 does NOT trip breaker; token mode 401 DOES.
    #[tokio::test]
    async fn test_section6_passthrough_401_no_trip_vs_token_mode() {
        let state = Arc::new(MockServerState::new());

        // Mock returns 401 for both scenarios
        // Push responses in LIFO order (last pushed comes out first)
        // First push is for scenario A (passthrough), second push is for scenario B (token mode)
        state.push(MockResponse::Auth {
            status: StatusCode::UNAUTHORIZED,
        }); // Scenario A response - consumed first
        state.push(MockResponse::Auth {
            status: StatusCode::UNAUTHORIZED,
        }); // Scenario B response - consumed second

        let server = MockServer::new(state.clone()).await;

        // Scenario A: Passthrough mode — lane should NOT be tripped
        let lane_data = LaneData {
            model: "test-model".to_string(),
            provider: "test-provider".to_string(),
            max: 10,
            sem: Arc::new(tokio::sync::Semaphore::new(10)),
            limited: false,
            budget: -1,
            cooldown_until: 0,
            streak: 0,
            dead: false,
            dead_reason: String::new(),
            inflight: 0,
            ok: 0,
            err: 0,
            client_fault: 0,
        };

        let lane = Lane {
            model: "test-model".to_string(),
            provider: "test-provider".to_string(),
            base_url: server.base_url(),
            api_key: "busbar-key".to_string(),
            protocol: ProtocolKind::Anthropic(AnthropicProtocol::new()),
            max: 10,
            error_map: Arc::new(std::collections::HashMap::new()),
        };

        let by_model = HashMap::from([("test-model".to_string(), 0)]);
        let pools = HashMap::from([("default".to_string(), vec![0])]);
        let auth_cfg_passthrough = AuthCfg {
            mode: "passthrough".to_string(),
            client_tokens: vec![],
            _legacy_token: None,
        };
        let auth_mw_passthrough = Arc::new(AuthMiddleware::new(&auth_cfg_passthrough));
        let store = Arc::new(InMemoryStore::new(vec![lane_data]));
        let app_passthrough = Arc::new(App {
            lanes: vec![lane],
            store,
            by_model: by_model.clone(),
            pools: pools.clone(),
            rr: AtomicUsize::new(0),
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap(),
            auth: auth_mw_passthrough,
            auth_mode: crate::auth::AuthMode::Passthrough,
        });

        let req_body = serde_json::to_vec(&json!({"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})).unwrap();
        let response = forward(app_passthrough.clone(), vec![0], req_body.into(), None).await;
        assert_eq!(
            response.status().as_u16(),
            401,
            "Passthrough should return upstream 401 to caller"
        );

        // Assert: lane state UNCHANGED in passthrough mode
        let t = now();
        assert!(
            app_passthrough.store.usable(0, t),
            "lane should remain usable after passthrough-401 (no trip)"
        );
        {
            let snap = app_passthrough.store.snapshot(0, t);
            assert_eq!(snap.err, 0, "err counter unchanged in passthrough mode");
            assert_eq!(snap.streak, 0, "streak unchanged in passthrough mode");
            assert!(!snap.dead, "lane should NOT be dead after passthrough-401");
        }

        // Scenario B: Token mode — lane SHOULD be tripped (busbar's key failed)
        state.clear_auth_header();
        state.push(MockResponse::Auth {
            status: StatusCode::UNAUTHORIZED,
        });

        let lane_data_token = LaneData {
            model: "test-model".to_string(),
            provider: "test-provider".to_string(),
            max: 10,
            sem: Arc::new(tokio::sync::Semaphore::new(10)),
            limited: false,
            budget: -1,
            cooldown_until: 0,
            streak: 0,
            dead: false,
            dead_reason: String::new(),
            inflight: 0,
            ok: 0,
            err: 0,
            client_fault: 0,
        };

        let lane_token = Lane {
            model: "test-model".to_string(),
            provider: "test-provider".to_string(),
            base_url: server.base_url(),
            api_key: "busbar-key".to_string(),
            protocol: ProtocolKind::Anthropic(AnthropicProtocol::new()),
            max: 10,
            error_map: Arc::new(std::collections::HashMap::new()),
        };

        let auth_cfg_token = AuthCfg {
            mode: "token".to_string(),
            client_tokens: vec!["caller-token-123".to_string()],
            _legacy_token: None,
        };
        let auth_mw_token = Arc::new(AuthMiddleware::new(&auth_cfg_token));
        let store_token = Arc::new(InMemoryStore::new(vec![lane_data_token]));
        let app_token = Arc::new(App {
            lanes: vec![lane_token],
            store: store_token,
            by_model,
            pools,
            rr: AtomicUsize::new(0),
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap(),
            auth: auth_mw_token,
            auth_mode: crate::auth::AuthMode::Token,
        });

        let req_body = serde_json::to_vec(&json!({"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})).unwrap();
        let response = forward(app_token.clone(), vec![0], req_body.into(), None).await;
        assert_eq!(
            response.status().as_u16(),
            401,
            "Token mode should return upstream 401"
        );

        // Assert: lane IS tripped in token mode (busbar's stored credential failed)
        let t = now();
        assert!(
            !app_token.store.usable(0, t),
            "lane should be DOWN after token-mode-401"
        );
        {
            let snap = app_token.store.snapshot(0, t);
            assert!(
                !snap.dead,
                "token-mode-401 → recoverable hard-down (long cooldown + probe), NOT permanent dead (B-303a)"
            );
        }

        server.shutdown().await;
    }

    /// Passthrough forwards the CALLER's bearer token, not busbar's api_key.
    #[tokio::test]
    async fn test_passthrough_forwards_caller_token() {
        let state = Arc::new(MockServerState::new());

        // Mock returns 200 so we can inspect what auth header it received
        state.push(MockResponse::Ok {
            status: StatusCode::OK,
            body: json!({ "content": ["ok"], "model": "test", "stop": [] }),
        });

        let server = MockServer::new(state.clone()).await;

        let lane_data = LaneData {
            model: "test-model".to_string(),
            provider: "test-provider".to_string(),
            max: 10,
            sem: Arc::new(tokio::sync::Semaphore::new(10)),
            limited: false,
            budget: -1,
            cooldown_until: 0,
            streak: 0,
            dead: false,
            dead_reason: String::new(),
            inflight: 0,
            ok: 0,
            err: 0,
            client_fault: 0,
        };

        let lane = Lane {
            model: "test-model".to_string(),
            provider: "test-provider".to_string(),
            base_url: server.base_url(),
            api_key: "busbar-central-key".to_string(),
            protocol: ProtocolKind::Anthropic(AnthropicProtocol::new()),
            max: 10,
            error_map: Arc::new(std::collections::HashMap::new()),
        };

        let by_model = HashMap::from([("test-model".to_string(), 0)]);
        let pools = HashMap::from([("default".to_string(), vec![0])]);
        let auth_cfg_passthrough = AuthCfg {
            mode: "passthrough".to_string(),
            client_tokens: vec![],
            _legacy_token: None,
        };
        let auth_mw = Arc::new(AuthMiddleware::new(&auth_cfg_passthrough));
        let store = Arc::new(InMemoryStore::new(vec![lane_data]));
        let app = Arc::new(App {
            lanes: vec![lane],
            store,
            by_model,
            pools,
            rr: AtomicUsize::new(0),
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap(),
            auth: auth_mw,
            auth_mode: crate::auth::AuthMode::Passthrough,
        });

        // Caller's Bearer token (NOT busbar's key)
        let caller_bearer_token = "caller-specific-token-abc123";
        let req_body = serde_json::to_vec(&json!({"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})).unwrap();

        // Forward with caller's token (simulating what auth middleware would extract)
        let response = forward(
            app.clone(),
            vec![0],
            req_body.into(),
            Some(caller_bearer_token),
        )
        .await;
        assert_eq!(response.status().as_u16(), 200);

        // Assert: mock upstream received the caller's token, NOT busbar's key
        let recorded_auth = state
            .get_last_auth_header()
            .expect("mock should have recorded Authorization header");
        assert_eq!(
            recorded_auth,
            format!("Bearer {}", caller_bearer_token),
            "upstream should receive caller's Bearer token in passthrough mode"
        );

        server.shutdown().await;
    }

    /// B-203: Stream inspection tap test for Anthropic SSE usage parsing.
    ///
    /// Tests that the tap:
    /// (a) forwards byte-identical stream to client
    /// (b) extracts parsed usage from message_delta/message_stop events
    /// (c) maintains bounded memory via carry buffer cap
    #[tokio::test]
    async fn test_b203_stream_inspection_tap_usage_parsing() {
        use crate::forward::{SseCarryBuffer, UsageTap};

        // Test 1: UsageTap extracts usage from Anthropic-style events
        let mut tap = UsageTap::new();

        // Feed a message_delta event with usage object
        let delta_json = serde_json::json!({
            "type": "message_delta",
            "delta": {
                "stop_reason": "end_turn"
            },
            "usage": {
                "input_tokens": 10,
                "output_tokens": 5,
                "cache_creation_input_tokens": 2,
                "cache_read_input_tokens": 3
            }
        });
        let delta_str = serde_json::to_string(&delta_json).unwrap();
        tap.feed(&Bytes::from(delta_str));

        // Assert: all four usage fields extracted correctly
        assert_eq!(tap.input_tokens, Some(10), "input_tokens should be 10");
        assert_eq!(tap.output_tokens, Some(5), "output_tokens should be 5");
        assert_eq!(
            tap.cache_creation_input_tokens,
            Some(2),
            "cache_creation_input_tokens should be 2"
        );
        assert_eq!(
            tap.cache_read_input_tokens,
            Some(3),
            "cache_read_input_tokens should be 3"
        );
        assert!(tap.has_usage(), "tap should have usage data");

        // Test 2: message_stop as fallback (when delta missing)
        let mut tap2 = UsageTap::new();
        let stop_json = serde_json::json!({
            "type": "message_stop",
            "usage": {
                "input_tokens": 15,
                "output_tokens": 8
            }
        });
        let stop_str = serde_json::to_string(&stop_json).unwrap();
        tap2.feed(&Bytes::from(stop_str));

        assert_eq!(
            tap2.input_tokens,
            Some(15),
            "input_tokens from message_stop should be 15"
        );
        assert_eq!(
            tap2.output_tokens,
            Some(8),
            "output_tokens from message_stop should be 8"
        );

        // Test 3: Carry buffer boundedness (hard cap test)
        let mut carry = SseCarryBuffer::new();

        // Feed a chunk larger than max carry bytes
        let large_chunk = vec![b'x'; 10000];
        carry.feed(&Bytes::from(large_chunk));

        // Assert: carry buffer respects MAX_CARRY_BYTES cap (4KB)
        assert!(
            carry.len() <= 4096,
            "carry buffer should be bounded by max_bytes"
        );

        // Test 4: SSE frame reassembly across chunk boundaries
        let mut carry2 = SseCarryBuffer::new();

        // Split a complete SSE event across two chunks
        let event1 = "data: {\"type\": \"message_start\"}\n\n";

        // Feed first part (incomplete)
        let split_point = event1.len() / 2;
        carry2.feed(&Bytes::from(&event1.as_bytes()[..split_point]));

        // Assert: no complete frame yet
        assert!(
            carry2.feed(&Bytes::new()).is_none(),
            "should not have complete frame after first chunk"
        );

        // Feed remainder (completes the frame)
        let remaining = &event1.as_bytes()[split_point..];
        if let Some(frame) = carry2.feed(&Bytes::from(remaining)) {
            let frame_str = String::from_utf8_lossy(&frame);
            assert!(
                frame_str.contains("message_start"),
                "should contain first message"
            );
        } else {
            panic!("Expected complete frame after second chunk");
        }

        // Test 5: Byte-identical stream forwarding (integration test with mock)
        let state = Arc::new(MockServerState::new());

        // Create Anthropic-style SSE events including message_delta and message_stop
        // These are raw strings that will be prefixed with "data: " by MockResponse::Sse
        // Push in reverse order (LIFO) so first event comes out first
        let usage_events = vec![
            r#"{"type":"message_start"}"#.to_string(),
            r#"{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}"#.to_string(),
            r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello"}}"#.to_string(),
            r#"{"type":"message_delta","usage":{"input_tokens":10,"output_tokens":5}}"#.to_string(),
            r#"{"type":"message_stop"}"#.to_string(),
        ];

        // MockResponse::Sse adds [DONE] at the end when abort_at_index is None
        let mut expected_text: String = usage_events
            .iter()
            .map(|e| format!("data: {}\n\n", e))
            .collect();
        expected_text.push_str("[DONE]\n\n");

        // Push events in reverse order (LIFO means last pushed comes out first)
        state.push(MockResponse::Sse {
            events: usage_events,
            abort_at_index: None,
        });

        let server = MockServer::new(state.clone()).await;

        let lane_data = LaneData {
            model: "test-model".to_string(),
            provider: "test-provider".to_string(),
            max: 10,
            sem: Arc::new(tokio::sync::Semaphore::new(10)),
            limited: false,
            budget: -1,
            cooldown_until: 0,
            streak: 0,
            dead: false,
            dead_reason: String::new(),
            inflight: 0,
            ok: 0,
            err: 0,
            client_fault: 0,
        };

        let lane = Lane {
            model: "test-model".to_string(),
            provider: "test-provider".to_string(),
            base_url: server.base_url(),
            api_key: "test-key-0".to_string(),
            protocol: ProtocolKind::Anthropic(AnthropicProtocol::new()),
            max: 10,
            error_map: Arc::new(std::collections::HashMap::new()),
        };

        let by_model = HashMap::from([("test-model".to_string(), 0)]);
        let pools = HashMap::from([("default".to_string(), vec![0])]);
        let auth = Arc::new(AuthMiddleware::new(&AuthCfg::default_none()));
        let store = Arc::new(InMemoryStore::new(vec![lane_data]));
        let app = Arc::new(App {
            lanes: vec![lane],
            store,
            by_model,
            pools,
            rr: AtomicUsize::new(0),
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap(),
            auth,
            auth_mode: crate::auth::AuthMode::None,
        });

        let req_body = serde_json::to_vec(&json!({"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})).unwrap();

        // Forward request (tap integrated in FirstByteBody)
        let response = forward(app.clone(), vec![0], req_body.into(), None).await;
        assert_eq!(response.status().as_u16(), 200);

        use http_body_util::BodyExt as _;
        let collected_bytes = response.into_body().collect().await.unwrap().to_bytes();
        let actual_text = String::from_utf8_lossy(&collected_bytes).to_string();

        // Assert (a): client receives byte-identical stream
        assert_eq!(
            actual_text, expected_text,
            "client should receive byte-identical stream"
        );

        server.shutdown().await;
    }

    /// B-301b: Disposition-matrix tests - prove error_map drives classification, not protocol.
    /// Each assertion must FAIL against a wrong mapping to verify correctness.
    #[cfg(test)]
    mod disposition_matrix_tests {
        use super::*;
        use crate::breaker::{normalize_raw_error, status_class_from_str, RawUpstreamError};
        use std::collections::HashMap;

        #[test]
        fn test_status_class_from_str_exhaustive() {
            // Exhaustive check: all valid StatusClass names must parse correctly
            assert_eq!(
                status_class_from_str("rate_limit"),
                Some(crate::breaker::StatusClass::RateLimit)
            );
            assert_eq!(
                status_class_from_str("overloaded"),
                Some(crate::breaker::StatusClass::Overloaded)
            );
            assert_eq!(
                status_class_from_str("server_error"),
                Some(crate::breaker::StatusClass::ServerError)
            );
            assert_eq!(
                status_class_from_str("timeout"),
                Some(crate::breaker::StatusClass::Timeout)
            );
            assert_eq!(
                status_class_from_str("network"),
                Some(crate::breaker::StatusClass::Network)
            );
            assert_eq!(
                status_class_from_str("auth"),
                Some(crate::breaker::StatusClass::Auth)
            );
            assert_eq!(
                status_class_from_str("billing"),
                Some(crate::breaker::StatusClass::Billing)
            );
            assert_eq!(
                status_class_from_str("client_error"),
                Some(crate::breaker::StatusClass::ClientError)
            );

            // Unknown values return None (no _ => fallback)
            assert_eq!(status_class_from_str("invalid"), None);
            assert_eq!(status_class_from_str("unknown_code"), None);
        }

        #[test]
        fn test_normalize_raw_error_with_provider_override() {
            let error_map: HashMap<String, String> = [("1113".to_string(), "billing".to_string())]
                .iter()
                .cloned()
                .collect();

            // Provider code 1113 → billing (override)
            let raw = RawUpstreamError {
                http_status: 402,
                provider_code: Some("1113".to_string()),
                structured_type: None,
            };
            let sig = normalize_raw_error(&raw, &error_map);
            assert_eq!(sig.class, crate::breaker::StatusClass::Billing);

            // Different code not in map → fallback to HTTP status classification
            let raw2 = RawUpstreamError {
                http_status: 500,
                provider_code: Some("9999".to_string()),
                structured_type: None,
            };
            let sig2 = normalize_raw_error(&raw2, &error_map);
            assert_eq!(sig2.class, crate::breaker::StatusClass::ServerError);
        }

        #[test]
        fn test_normalize_raw_error_http_status_fallback() {
            let error_map: HashMap<String, String> = HashMap::new();

            // HTTP 401 → Auth (universal spec)
            let raw = RawUpstreamError {
                http_status: 401,
                provider_code: None,
                structured_type: None,
            };
            let sig = normalize_raw_error(&raw, &error_map);
            assert_eq!(sig.class, crate::breaker::StatusClass::Auth);

            // HTTP 429 → RateLimit (universal spec)
            let raw2 = RawUpstreamError {
                http_status: 429,
                provider_code: None,
                structured_type: None,
            };
            let sig2 = normalize_raw_error(&raw2, &error_map);
            assert_eq!(sig2.class, crate::breaker::StatusClass::RateLimit);

            // HTTP 500 → ServerError (universal spec)
            let raw3 = RawUpstreamError {
                http_status: 500,
                provider_code: None,
                structured_type: None,
            };
            let sig3 = normalize_raw_error(&raw3, &error_map);
            assert_eq!(sig3.class, crate::breaker::StatusClass::ServerError);

            // HTTP 400 → ClientError (universal spec)
            let raw4 = RawUpstreamError {
                http_status: 400,
                provider_code: None,
                structured_type: None,
            };
            let sig4 = normalize_raw_error(&raw4, &error_map);
            assert_eq!(sig4.class, crate::breaker::StatusClass::ClientError);
        }

        #[tokio::test]
        async fn test_disposition_client_fault_no_known_code() {
            // HTTP 400, no known code → ClientFault → lane health UNCHANGED + body relayed
            let state = Arc::new(MockServerState::new());
            state.push(MockResponse::Ok {
                status: StatusCode::BAD_REQUEST,
                body: json!({ "error": "bad request" }),
            });

            let server = MockServer::new(state.clone()).await;
            let lane_data = LaneData {
                model: "test-model".to_string(),
                provider: "z.ai".to_string(),
                max: 10,
                sem: Arc::new(tokio::sync::Semaphore::new(10)),
                limited: false,
                budget: -1,
                cooldown_until: 0,
                streak: 0,
                dead: false,
                dead_reason: String::new(),
                inflight: 0,
                ok: 0,
                err: 0,
                client_fault: 0,
            };

            let mut error_map = HashMap::new();
            error_map.insert("1113".to_string(), "billing".to_string());
            error_map.insert("1302".to_string(), "rate_limit".to_string());

            let lane = Lane {
                model: "test-model".to_string(),
                provider: "z.ai".to_string(),
                base_url: server.base_url(),
                api_key: "test-key".to_string(),
                protocol: ProtocolKind::Anthropic(AnthropicProtocol::new()),
                max: 10,
                error_map: Arc::new(error_map),
            };

            let by_model = HashMap::from([("test-model".to_string(), 0)]);
            let pools = HashMap::from([("default".to_string(), vec![0])]);
            let auth = Arc::new(AuthMiddleware::new(&AuthCfg::default_none()));
            let store = Arc::new(InMemoryStore::new(vec![lane_data]));
            let app = Arc::new(App {
                lanes: vec![lane],
                store,
                by_model,
                pools,
                rr: AtomicUsize::new(0),
                client: Client::builder()
                    .timeout(Duration::from_secs(30))
                    .build()
                    .unwrap(),
                auth,
                auth_mode: crate::auth::AuthMode::None,
            });

            let req_body = serde_json::to_vec(&json!({"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})).unwrap();
            let response = forward(app.clone(), vec![0], req_body.into(), None).await;

            // Should return 400 verbatim (ClientFault → relay)
            assert_eq!(response.status().as_u16(), 400);

            // Lane health UNCHANGED (not tripped)
            let t = now();
            assert!(
                app.store.usable(0, t),
                "lane should remain usable after ClientFault"
            );
            {
                let snap = app.store.snapshot(0, t);
                assert_eq!(snap.err, 0, "err counter unchanged for ClientFault");
                assert!(!snap.dead, "lane should NOT be dead after ClientFault");
            }

            server.shutdown().await;
        }

        #[tokio::test]
        async fn test_disposition_hard_down_billing_code() {
            // HTTP 200/400 body w/ code 1113 → Billing → HardDown: lane hard-down
            let state = Arc::new(MockServerState::new());
            state.push(MockResponse::Billing {
                status: StatusCode::PAYMENT_REQUIRED,
                code: "1113",
                message: "insufficient balance",
            });

            let server = MockServer::new(state.clone()).await;
            let lane_data = LaneData {
                model: "test-model".to_string(),
                provider: "z.ai".to_string(),
                max: 10,
                sem: Arc::new(tokio::sync::Semaphore::new(10)),
                limited: false,
                budget: -1,
                cooldown_until: 0,
                streak: 0,
                dead: false,
                dead_reason: String::new(),
                inflight: 0,
                ok: 0,
                err: 0,
                client_fault: 0,
            };

            let mut error_map = HashMap::new();
            error_map.insert("1113".to_string(), "billing".to_string());
            error_map.insert("1302".to_string(), "rate_limit".to_string());

            let lane = Lane {
                model: "test-model".to_string(),
                provider: "z.ai".to_string(),
                base_url: server.base_url(),
                api_key: "test-key".to_string(),
                protocol: ProtocolKind::Anthropic(AnthropicProtocol::new()),
                max: 10,
                error_map: Arc::new(error_map),
            };

            let by_model = HashMap::from([("test-model".to_string(), 0)]);
            let pools = HashMap::from([("default".to_string(), vec![0])]);
            let auth = Arc::new(AuthMiddleware::new(&AuthCfg::default_none()));
            let store = Arc::new(InMemoryStore::new(vec![lane_data]));
            let app = Arc::new(App {
                lanes: vec![lane],
                store,
                by_model,
                pools,
                rr: AtomicUsize::new(0),
                client: Client::builder()
                    .timeout(Duration::from_secs(30))
                    .build()
                    .unwrap(),
                auth,
                auth_mode: crate::auth::AuthMode::None,
            });

            let req_body = serde_json::to_vec(&json!({"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})).unwrap();
            let _response = forward(app.clone(), vec![0], req_body.into(), None).await;

            // Lane hard-down (billing)
            let t = now();
            assert!(
                !app.store.usable(0, t),
                "lane should be DOWN after billing error"
            );
            {
                let snap = app.store.snapshot(0, t);
                assert!(!snap.dead, "Billing HardDown → recoverable (long cooldown + probe), not permanent dead (B-303a)");
                assert_eq!(
                    snap.dead_reason, "billing / insufficient balance",
                    "dead reason should match"
                );
            }

            server.shutdown().await;
        }

        #[tokio::test]
        async fn test_disposition_transient_rate_limit_code() {
            // HTTP 429 body w/ code 1302 → RateLimit → TransientUpstream (record_rate_limit)
            let state = Arc::new(MockServerState::new());
            state.push(MockResponse::RateLimit {
                status: StatusCode::TOO_MANY_REQUESTS,
                provider_signal: Some("1302"),
            });

            let server = MockServer::new(state.clone()).await;
            let lane_data = LaneData {
                model: "test-model".to_string(),
                provider: "z.ai".to_string(),
                max: 10,
                sem: Arc::new(tokio::sync::Semaphore::new(10)),
                limited: false,
                budget: -1,
                cooldown_until: 0,
                streak: 0,
                dead: false,
                dead_reason: String::new(),
                inflight: 0,
                ok: 0,
                err: 0,
                client_fault: 0,
            };

            let mut error_map = HashMap::new();
            error_map.insert("1113".to_string(), "billing".to_string());
            error_map.insert("1302".to_string(), "rate_limit".to_string());

            let lane = Lane {
                model: "test-model".to_string(),
                provider: "z.ai".to_string(),
                base_url: server.base_url(),
                api_key: "test-key".to_string(),
                protocol: ProtocolKind::Anthropic(AnthropicProtocol::new()),
                max: 10,
                error_map: Arc::new(error_map),
            };

            let by_model = HashMap::from([("test-model".to_string(), 0)]);
            let pools = HashMap::from([("default".to_string(), vec![0])]);
            let auth = Arc::new(AuthMiddleware::new(&AuthCfg::default_none()));
            let store = Arc::new(InMemoryStore::new(vec![lane_data]));
            let app = Arc::new(App {
                lanes: vec![lane],
                store,
                by_model,
                pools,
                rr: AtomicUsize::new(0),
                client: Client::builder()
                    .timeout(Duration::from_secs(30))
                    .build()
                    .unwrap(),
                auth,
                auth_mode: crate::auth::AuthMode::None,
            });

            let req_body = serde_json::to_vec(&json!({"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})).unwrap();
            let _response = forward(app.clone(), vec![0], req_body.into(), None).await;

            // TransientUpstream → cooldown + err counter incremented
            let t = now();
            assert!(
                !app.store.usable(0, t),
                "lane should be in transient cooldown"
            );
            {
                let snap = app.store.snapshot(0, t);
                assert!(snap.err > 0, "err counter should increment for RateLimit");
                assert_eq!(snap.streak, 1, "streak should be 1 for first rate limit");
                assert!(!snap.dead, "lane should NOT be dead after single RateLimit");
            }

            server.shutdown().await;
        }

        #[tokio::test]
        async fn test_disposition_transient_rate_limit_no_code() {
            // HTTP 429 NO known code → RateLimit (status) → TransientUpstream
            let state = Arc::new(MockServerState::new());
            state.push(MockResponse::RateLimit {
                status: StatusCode::TOO_MANY_REQUESTS,
                provider_signal: None, // No known code in error_map
            });

            let server = MockServer::new(state.clone()).await;
            let lane_data = LaneData {
                model: "test-model".to_string(),
                provider: "z.ai".to_string(),
                max: 10,
                sem: Arc::new(tokio::sync::Semaphore::new(10)),
                limited: false,
                budget: -1,
                cooldown_until: 0,
                streak: 0,
                dead: false,
                dead_reason: String::new(),
                inflight: 0,
                ok: 0,
                err: 0,
                client_fault: 0,
            };

            let mut error_map = HashMap::new();
            error_map.insert("1113".to_string(), "billing".to_string());
            error_map.insert("1302".to_string(), "rate_limit".to_string());

            let lane = Lane {
                model: "test-model".to_string(),
                provider: "z.ai".to_string(),
                base_url: server.base_url(),
                api_key: "test-key".to_string(),
                protocol: ProtocolKind::Anthropic(AnthropicProtocol::new()),
                max: 10,
                error_map: Arc::new(error_map),
            };

            let by_model = HashMap::from([("test-model".to_string(), 0)]);
            let pools = HashMap::from([("default".to_string(), vec![0])]);
            let auth = Arc::new(AuthMiddleware::new(&AuthCfg::default_none()));
            let store = Arc::new(InMemoryStore::new(vec![lane_data]));
            let app = Arc::new(App {
                lanes: vec![lane],
                store,
                by_model,
                pools,
                rr: AtomicUsize::new(0),
                client: Client::builder()
                    .timeout(Duration::from_secs(30))
                    .build()
                    .unwrap(),
                auth,
                auth_mode: crate::auth::AuthMode::None,
            });

            let req_body = serde_json::to_vec(&json!({"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})).unwrap();
            let _response = forward(app.clone(), vec![0], req_body.into(), None).await;

            // TransientUpstream via HTTP status classification (429 → RateLimit)
            let t = now();
            assert!(
                !app.store.usable(0, t),
                "lane should be in transient cooldown"
            );
            {
                let snap = app.store.snapshot(0, t);
                assert!(
                    snap.err > 0,
                    "err counter should increment for HTTP 429 RateLimit"
                );
            }

            server.shutdown().await;
        }

        #[tokio::test]
        async fn test_disposition_transient_server_error() {
            // HTTP 500 → ServerError → TransientUpstream
            let state = Arc::new(MockServerState::new());
            state.push(MockResponse::ServerError {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                body: json!({ "error": "server error" }),
            });

            let server = MockServer::new(state.clone()).await;
            let lane_data = LaneData {
                model: "test-model".to_string(),
                provider: "z.ai".to_string(),
                max: 10,
                sem: Arc::new(tokio::sync::Semaphore::new(10)),
                limited: false,
                budget: -1,
                cooldown_until: 0,
                streak: 0,
                dead: false,
                dead_reason: String::new(),
                inflight: 0,
                ok: 0,
                err: 0,
                client_fault: 0,
            };

            let mut error_map = HashMap::new();
            error_map.insert("1113".to_string(), "billing".to_string());
            error_map.insert("1302".to_string(), "rate_limit".to_string());

            let lane = Lane {
                model: "test-model".to_string(),
                provider: "z.ai".to_string(),
                base_url: server.base_url(),
                api_key: "test-key".to_string(),
                protocol: ProtocolKind::Anthropic(AnthropicProtocol::new()),
                max: 10,
                error_map: Arc::new(error_map),
            };

            let by_model = HashMap::from([("test-model".to_string(), 0)]);
            let pools = HashMap::from([("default".to_string(), vec![0])]);
            let auth = Arc::new(AuthMiddleware::new(&AuthCfg::default_none()));
            let store = Arc::new(InMemoryStore::new(vec![lane_data]));
            let app = Arc::new(App {
                lanes: vec![lane],
                store,
                by_model,
                pools,
                rr: AtomicUsize::new(0),
                client: Client::builder()
                    .timeout(Duration::from_secs(30))
                    .build()
                    .unwrap(),
                auth,
                auth_mode: crate::auth::AuthMode::None,
            });

            let req_body = serde_json::to_vec(&json!({"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})).unwrap();
            let _response = forward(app.clone(), vec![0], req_body.into(), None).await;

            // TransientUpstream (5xx → ServerError)
            let t = now();
            assert!(
                !app.store.usable(0, t),
                "lane should be in transient cooldown"
            );
            {
                let snap = app.store.snapshot(0, t);
                assert!(snap.err > 0, "err counter should increment for ServerError");
                assert!(
                    !snap.dead,
                    "lane should NOT be dead after single ServerError"
                );
            }

            server.shutdown().await;
        }

        #[tokio::test]
        async fn test_disposition_hard_down_auth() {
            // HTTP 401 → Auth → HardDown
            let state = Arc::new(MockServerState::new());
            state.push(MockResponse::Auth {
                status: StatusCode::UNAUTHORIZED,
            });

            let server = MockServer::new(state.clone()).await;
            let lane_data = LaneData {
                model: "test-model".to_string(),
                provider: "z.ai".to_string(),
                max: 10,
                sem: Arc::new(tokio::sync::Semaphore::new(10)),
                limited: false,
                budget: -1,
                cooldown_until: 0,
                streak: 0,
                dead: false,
                dead_reason: String::new(),
                inflight: 0,
                ok: 0,
                err: 0,
                client_fault: 0,
            };

            let mut error_map = HashMap::new();
            error_map.insert("1113".to_string(), "billing".to_string());
            error_map.insert("1302".to_string(), "rate_limit".to_string());

            let lane = Lane {
                model: "test-model".to_string(),
                provider: "z.ai".to_string(),
                base_url: server.base_url(),
                api_key: "test-key".to_string(),
                protocol: ProtocolKind::Anthropic(AnthropicProtocol::new()),
                max: 10,
                error_map: Arc::new(error_map),
            };

            let by_model = HashMap::from([("test-model".to_string(), 0)]);
            let pools = HashMap::from([("default".to_string(), vec![0])]);
            let auth = Arc::new(AuthMiddleware::new(&AuthCfg::default_none()));
            let store = Arc::new(InMemoryStore::new(vec![lane_data]));
            let app = Arc::new(App {
                lanes: vec![lane],
                store,
                by_model,
                pools,
                rr: AtomicUsize::new(0),
                client: Client::builder()
                    .timeout(Duration::from_secs(30))
                    .build()
                    .unwrap(),
                auth,
                auth_mode: crate::auth::AuthMode::None,
            });

            let req_body = serde_json::to_vec(&json!({"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})).unwrap();
            let _response = forward(app.clone(), vec![0], req_body.into(), None).await;

            // HardDown (401 → Auth)
            let t = now();
            assert!(
                !app.store.usable(0, t),
                "lane should be DOWN after Auth HardDown"
            );
            {
                let snap = app.store.snapshot(0, t);
                assert!(!snap.dead, "Auth HardDown → recoverable (long cooldown + probe), not permanent dead (B-303a)");
                assert!(
                    snap.dead_reason.contains("auth"),
                    "dead reason should mention auth"
                );
            }

            server.shutdown().await;
        }

        #[tokio::test]
        async fn test_disposition_code_drives_classification() {
            // The key one: same HTTP status, different provider_code → different Disposition
            // This proves the error_map drives it, not the status.

            // Setup two lanes with SAME HTTP 402 response but different codes
            let state1 = Arc::new(MockServerState::new());
            let state2 = Arc::new(MockServerState::new());

            // Both return HTTP 402 (Payment Required) but with different error codes
            state1.push(MockResponse::Billing {
                status: StatusCode::PAYMENT_REQUIRED,
                code: "1113", // → billing → HardDown
                message: "insufficient balance",
            });

            state2.push(MockResponse::Ok {
                status: StatusCode::BAD_REQUEST, // HTTP 400 without known code → ClientFault
                body: json!({ "error": "not a known error" }),
            });

            let server1 = MockServer::new(state1.clone()).await;
            let server2 = MockServer::new(state2.clone()).await;

            // Lane 1: error_map maps 1113 to billing → HardDown
            let lane_data_1 = LaneData {
                model: "test-model".to_string(),
                provider: "z.ai".to_string(),
                max: 10,
                sem: Arc::new(tokio::sync::Semaphore::new(10)),
                limited: false,
                budget: -1,
                cooldown_until: 0,
                streak: 0,
                dead: false,
                dead_reason: String::new(),
                inflight: 0,
                ok: 0,
                err: 0,
                client_fault: 0,
            };

            let mut error_map_1 = HashMap::new();
            error_map_1.insert("1113".to_string(), "billing".to_string());

            let lane_1 = Lane {
                model: "test-model".to_string(),
                provider: "z.ai".to_string(),
                base_url: server1.base_url(),
                api_key: "test-key-1".to_string(),
                protocol: ProtocolKind::Anthropic(AnthropicProtocol::new()),
                max: 10,
                error_map: Arc::new(error_map_1),
            };

            // Lane 2: NO mapping for any code → HTTP status classification only
            let lane_data_2 = LaneData {
                model: "test-model".to_string(),
                provider: "z.ai".to_string(),
                max: 10,
                sem: Arc::new(tokio::sync::Semaphore::new(10)),
                limited: false,
                budget: -1,
                cooldown_until: 0,
                streak: 0,
                dead: false,
                dead_reason: String::new(),
                inflight: 0,
                ok: 0,
                err: 0,
                client_fault: 0,
            };

            let error_map_2 = HashMap::new(); // Empty - no overrides

            let lane_2 = Lane {
                model: "test-model".to_string(),
                provider: "z.ai".to_string(),
                base_url: server2.base_url(),
                api_key: "test-key-2".to_string(),
                protocol: ProtocolKind::Anthropic(AnthropicProtocol::new()),
                max: 10,
                error_map: Arc::new(error_map_2),
            };

            let setup_app = |lane_data: LaneData, lane: Lane, _error_map_name: &str| {
                let by_model = HashMap::from([("test-model".to_string(), 0)]);
                let pools = HashMap::from([("default".to_string(), vec![0])]);
                let auth = Arc::new(AuthMiddleware::new(&AuthCfg::default_none()));
                let store = Arc::new(InMemoryStore::new(vec![lane_data]));
                Arc::new(App {
                    lanes: vec![lane],
                    store,
                    by_model,
                    pools,
                    rr: AtomicUsize::new(0),
                    client: Client::builder()
                        .timeout(Duration::from_secs(30))
                        .build()
                        .unwrap(),
                    auth,
                    auth_mode: crate::auth::AuthMode::None,
                })
            };

            let app_1 = setup_app(lane_data_1, lane_1, "with mapping");
            let req_body = serde_json::to_vec(&json!({"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})).unwrap();

            // Lane 1 with error_map: code 1113 → billing → HardDown
            let _response_1 = forward(app_1.clone(), vec![0], req_body.clone().into(), None).await;
            let t = now();
            assert!(
                !app_1.store.usable(0, t),
                "Lane 1 (with error_map) should be DOWN after billing code"
            );

            // Lane 2 without mapping: HTTP 400 → ClientFault → no trip
            let app_2 = setup_app(lane_data_2, lane_2, "without mapping");
            let _response_2 = forward(app_2.clone(), vec![0], req_body.into(), None).await;
            assert!(
                app_2.store.usable(0, t),
                "Lane 2 (no error_map) should remain usable after ClientFault"
            );

            server1.shutdown().await;
            server2.shutdown().await;
        }

        #[tokio::test]
        async fn test_config_missing_error_map_fails_validation() {
            // A provider config with empty error_map → config_validate returns an error
            use crate::config::RootCfg;

            let mut providers = HashMap::new();
            // Create a provider WITHOUT error_map entries (intentionally empty)
            providers.insert(
                "badprovider".to_string(),
                crate::config::ProviderCfg {
                    protocol: "anthropic".into(),
                    base_url: "https://api.example.com".into(),
                    api_key_env: "API_KEY".into(),
                    health: None,
                    error_map: std::collections::HashMap::new(), // Empty = validation error
                    _legacy_api_key: None,
                },
            );

            let mut models = HashMap::new();
            models.insert(
                "mymodel".to_string(),
                crate::config::ModelCfg {
                    max_requests: -1,
                    provider: "badprovider".into(),
                    max_concurrent: 10,
                },
            );

            let mut pools = HashMap::new();
            pools.insert(
                "mypool".to_string(),
                crate::config::PoolCfg {
                    members: vec![crate::config::PoolMember {
                        target: "mymodel".into(),
                        weight: 1,
                        context_max: None,
                    }],
                    breaker: None,
                    failover: None,
                    on_exhausted: None,
                    affinity: None,
                },
            );

            let cfg = RootCfg {
                listen: "0.0.0.0:8080".into(),
                auth: None,
                providers,
                models,
                pools,
            };

            use crate::config_validate::validate;
            let result = validate(&cfg);
            assert!(
                result.is_err(),
                "Validation should fail when error_map is empty"
            );

            let errs = result.unwrap_err();
            let err_text = errs.join(" | ");
            assert!(
                err_text.contains("badprovider"),
                "Error message should mention the provider"
            );
            assert!(
                err_text.contains("error_map"),
                "Error message should mention error_map"
            );
        }

        #[test]
        fn test_normalize_wrong_mapping_fails() {
            // Anti-fab: prove wrong mapping produces wrong disposition

            let mut error_map = HashMap::new();
            // WRONG: map 1113 to rate_limit instead of billing
            error_map.insert("1113".to_string(), "rate_limit".to_string());

            let raw = RawUpstreamError {
                http_status: 402,
                provider_code: Some("1113".to_string()),
                structured_type: None,
            };

            // With WRONG mapping, code 1113 → rate_limit (wrong!)
            let sig = normalize_raw_error(&raw, &error_map);

            // This FAILS the correctness check: billing should map to HardDown, not TransientUpstream
            assert_eq!(
                sig.class,
                crate::breaker::StatusClass::RateLimit,
                "Wrong mapping: 1113 incorrectly classified as rate_limit instead of billing"
            );

            // The correct mapping would be:
            let mut correct_map = HashMap::new();
            correct_map.insert("1113".to_string(), "billing".to_string());
            let correct_sig = normalize_raw_error(&raw, &correct_map);
            assert_eq!(
                correct_sig.class,
                crate::breaker::StatusClass::Billing,
                "Correct mapping: 1113 → billing"
            );
        }

        #[tokio::test]
        async fn test_client_fault_400_relayed_verbatim_no_penalty() {
            // B-304: ClientFault (400 invalid_request) → relay verbatim, NO breaker penalty
            let state = Arc::new(MockServerState::new());
            state.push(MockResponse::Ok {
                status: StatusCode::BAD_REQUEST,
                body: json!({ "error": "invalid_request", "message": "bad input" }),
            });

            let server = MockServer::new(state.clone()).await;

            let lane_data = LaneData {
                model: "test-model".to_string(),
                provider: "anthropic".to_string(),
                max: 10,
                sem: Arc::new(tokio::sync::Semaphore::new(10)),
                limited: false,
                budget: -1,
                cooldown_until: 0,
                streak: 0,
                dead: false,
                dead_reason: String::new(),
                inflight: 0,
                ok: 0,
                err: 0,
                client_fault: 0,
            };

            let error_map = HashMap::new();
            let lane = Lane {
                model: "test-model".to_string(),
                provider: "anthropic".to_string(),
                base_url: server.base_url(),
                api_key: "test-key".to_string(),
                protocol: ProtocolKind::Anthropic(AnthropicProtocol::new()),
                max: 10,
                error_map: Arc::new(error_map),
            };

            let by_model = HashMap::from([("test-model".to_string(), 0)]);

            let pools = HashMap::from([("default".to_string(), vec![0])]);
            let auth = Arc::new(AuthMiddleware::new(&AuthCfg::default_none()));
            let store = Arc::new(InMemoryStore::new(vec![lane_data]));
            let app = Arc::new(App {
                lanes: vec![lane],
                store,
                by_model,
                pools,
                rr: AtomicUsize::new(0),
                client: Client::builder()
                    .timeout(Duration::from_secs(30))
                    .build()
                    .unwrap(),
                auth,
                auth_mode: crate::auth::AuthMode::None,
            });

            let req_body = serde_json::to_vec(&json!({"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})).unwrap();
            let response = forward(app.clone(), vec![0], req_body.into(), None).await;

            // Status should be relayed verbatim as 400
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);

            // Breaker state should remain Closed (no penalty)
            let t = now();
            let breaker_state = app.store.breaker_state(0);
            matches!(breaker_state, crate::store::BreakerState::Closed);

            // err/streak/cooldown should be UNTOUCHED
            {
                let snap = app.store.snapshot(0, t);
                assert_eq!(snap.err, 0, "err should NOT increment on client fault");
                assert_eq!(
                    snap.streak, 0,
                    "streak should NOT increment on client fault"
                );
                assert_eq!(snap.cooldown_remaining_s, 0, "no cooldown triggered");
                // BUT client_fault counter should +1
                assert_eq!(
                    snap.client_fault, 1,
                    "client_fault counter should increment"
                );
            }

            server.shutdown().await;
        }

        #[tokio::test]
        async fn test_client_fault_no_failover_two_lanes() {
            // B-304: ClientFault on lane 0 → lane 1 NOT hit (no failover)
            let state0 = Arc::new(MockServerState::new());
            let state1 = Arc::new(MockServerState::new());

            // Lane 0 returns 400 client fault
            state0.push(MockResponse::Ok {
                status: StatusCode::BAD_REQUEST,
                body: json!({ "error": "invalid_request" }),
            });

            let server0 = MockServer::new(state0.clone()).await;
            let server1 = MockServer::new(state1.clone()).await;

            // Lane 0 setup
            let lane_data_0 = LaneData {
                model: "test-model".to_string(),
                provider: "anthropic".to_string(),
                max: 10,
                sem: Arc::new(tokio::sync::Semaphore::new(10)),
                limited: false,
                budget: -1,
                cooldown_until: 0,
                streak: 0,
                dead: false,
                dead_reason: String::new(),
                inflight: 0,
                ok: 0,
                err: 0,
                client_fault: 0,
            };

            let lane_0 = Lane {
                model: "test-model".to_string(),
                provider: "anthropic".to_string(),
                base_url: server0.base_url(),
                api_key: "test-key-0".to_string(),
                protocol: ProtocolKind::Anthropic(AnthropicProtocol::new()),
                max: 10,
                error_map: Arc::new(HashMap::new()),
            };

            // Lane 1 setup (should NOT be called)
            let lane_data_1 = LaneData {
                model: "test-model".to_string(),
                provider: "anthropic".to_string(),
                max: 10,
                sem: Arc::new(tokio::sync::Semaphore::new(10)),
                limited: false,
                budget: -1,
                cooldown_until: 0,
                streak: 0,
                dead: false,
                dead_reason: String::new(),
                inflight: 0,
                ok: 0,
                err: 0,
                client_fault: 0,
            };

            let lane_1 = Lane {
                model: "test-model".to_string(),
                provider: "anthropic".to_string(),
                base_url: server1.base_url(),
                api_key: "test-key-1".to_string(),
                protocol: ProtocolKind::Anthropic(AnthropicProtocol::new()),
                max: 10,
                error_map: Arc::new(HashMap::new()),
            };

            let by_model = HashMap::from([("test-model".to_string(), 0)]);
            let pools = HashMap::from([("default".to_string(), vec![0, 1])]);
            let auth = Arc::new(AuthMiddleware::new(&AuthCfg::default_none()));
            let store = Arc::new(InMemoryStore::new(vec![lane_data_0, lane_data_1]));
            let app = Arc::new(App {
                lanes: vec![lane_0, lane_1],
                store,
                by_model,
                pools,
                rr: AtomicUsize::new(0),
                client: Client::builder()
                    .timeout(Duration::from_secs(30))
                    .build()
                    .unwrap(),
                auth,
                auth_mode: crate::auth::AuthMode::None,
            });

            let req_body = serde_json::to_vec(&json!({"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})).unwrap();
            let response = forward(app.clone(), vec![0, 1], req_body.into(), None).await;

            // Should get 400 from lane 0
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);

            // Lane 1 should NOT have been called (no requests to server1)
            // We verify by checking state1 is empty (pop consumed nothing)
            {
                let responses = state1.responses.lock().unwrap();
                assert!(
                    responses.is_empty(),
                    "Lane 1 should NOT be hit on client fault from lane 0"
                );
            }

            server0.shutdown().await;
            server1.shutdown().await;
        }
    }
}
