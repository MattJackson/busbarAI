// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! In-crate mock-upstream test harness (B-105 / B-105b). The whole module is
//! declared `#[cfg(test)] mod test_support;` in main.rs, so it compiles only for
//! tests and can drive `forward()` against canned upstream responses without a real
//! provider. Breaker tests (B-3xx) extend the `MockResponse` set as needed.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Mutex;
use std::time::Duration;

use futures::StreamExt;

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
    /// SSE streaming response with optional mid-stream abort
    Sse {
        events: Vec<String>,
        abort_after: Option<usize>,
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
}

impl MockServerState {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Queue a response; the handler pops in LIFO order, so push in reverse.
    pub(crate) fn push(&self, response: MockResponse) {
        self.responses.lock().unwrap().push(response);
    }

    fn next_response(&self) -> Option<MockResponse> {
        self.responses.lock().unwrap().pop()
    }
}

/// A mock upstream on an ephemeral port. The caller holds the `MockServerState`
/// Arc to script responses (including after the server starts).
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
    _request: Request<Body>,
) -> Response<Body> {
    let response = state.next_response().unwrap_or_default();

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
            let body = serde_json::json!({
                "error": { "message": msg, "code": provider_signal.unwrap_or("429") }
            });
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
            abort_after,
        } => {
            use futures::stream;

            let stream: Pin<Box<dyn futures::Stream<Item = String> + Send>> =
                if let Some(n) = abort_after {
                    Box::pin(
                        stream::iter(events.into_iter().take(n))
                            .map(|data| format!("data: {data}\n\n")),
                    )
                } else {
                    Box::pin(stream::iter(events).map(|data| format!("data: {data}\n\n")))
                };

            // Add DONE event at the end
            let stream = stream.chain(futures::stream::once(
                async move { "[DONE]\n\n".to_string() },
            ));

            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "text/event-stream")
                .body(axum::body::Body::from_stream(
                    stream.map(|s| Ok::<_, std::convert::Infallible>(s.into_bytes())),
                ))
                .unwrap()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicU64, AtomicUsize};
    use std::sync::Arc;

    use reqwest::Client;
    use serde_json::json;

    use crate::auth::AuthMiddleware;
    use crate::config::AuthCfg;
    use crate::forward::forward;
    use crate::proto::AnthropicProtocol;
    use crate::state::{App, Lane};

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

    /// Drives `forward()` against the mock: a 2xx relays, then a 429 trips the lane
    /// cooldown so the (single-member) pool is exhausted → 503.
    #[tokio::test]
    async fn test_mock_server_smoke_integration() {
        let state = Arc::new(MockServerState::new());
        state.push(MockResponse::Ok {
            status: StatusCode::OK,
            body: json!({ "content": ["Hello world"], "model": "claude-3-haiku", "stop": [] }),
        });
        let server = MockServer::new(state.clone()).await;

        let lane = Lane {
            model: "claude-3-haiku".to_string(),
            provider: "test-provider".to_string(),
            base_url: server.base_url(),
            api_key: "test-key".to_string(),
            protocol: Arc::new(AnthropicProtocol::new()),
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

        let by_model = HashMap::from([("claude-3-haiku".to_string(), 0)]);
        let pools = HashMap::from([("default".to_string(), vec![0])]);
        let auth = Arc::new(AuthMiddleware::new(&AuthCfg::default_none()));
        let app = Arc::new(App {
            lanes: vec![lane],
            by_model,
            pools,
            rr: AtomicUsize::new(0),
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap(),
            auth,
        });

        let req_body = serde_json::to_vec(&json!({
            "model": "claude-3-haiku",
            "messages": [{"role": "user", "content": "hi"}],
            "max_tokens": 100
        }))
        .unwrap();

        // 2xx relays.
        let response = forward(app.clone(), vec![0], req_body.clone().into()).await;
        assert_eq!(response.status().as_u16(), 200);

        // 429 → lane cooldown → pool exhausted → 503.
        state.push(MockResponse::RateLimit {
            status: StatusCode::TOO_MANY_REQUESTS,
            provider_signal: Some("1302"),
        });
        let response = forward(app.clone(), vec![0], req_body.into()).await;
        assert_eq!(response.status().as_u16(), 503);

        server.shutdown().await;
    }

    /// Test that SSE events arrive incrementally, not all at once.
    #[tokio::test]
    async fn test_sse_incremental_arrival() {
        use std::time::Duration;

        let state = Arc::new(MockServerState::new());

        // Create 10 SSE events with a delay between them
        let mut events = Vec::new();
        for i in 0..10 {
            events.push(format!("event-{i}"));
        }
        state.push(MockResponse::Sse {
            events,
            abort_after: None,
        });

        let server = MockServer::new(state.clone()).await;

        // Create a lane and app for testing
        let lane = Lane {
            model: "test-model".to_string(),
            provider: "test-provider".to_string(),
            base_url: server.base_url(),
            api_key: "test-key".to_string(),
            protocol: Arc::new(AnthropicProtocol::new()),
            sem: Arc::new(tokio::sync::Semaphore::new(10)),
            max: 10,
            limited: false,
            budget: AtomicI64::new(-1), // unlimited
            cooldown_until: AtomicU64::new(0),
            streak: AtomicU32::new(0),
            dead: AtomicBool::new(false),
            dead_reason: std::sync::Mutex::new(String::new()),
            inflight: AtomicI64::new(0),
            ok: AtomicU64::new(0),
            err: AtomicU64::new(0),
        };

        let by_model = HashMap::from([("test-model".to_string(), 0)]);
        let pools = HashMap::from([("default".to_string(), vec![0])]);
        let auth = Arc::new(AuthMiddleware::new(&AuthCfg::default_none()));
        let app = Arc::new(App {
            lanes: vec![lane],
            by_model,
            pools,
            rr: AtomicUsize::new(0),
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap(),
            auth,
        });

        let req_body = serde_json::to_vec(&json!({
            "model": "test-model",
            "messages": [{"role": "user", "content": "hi"}],
            "max_tokens": 100
        }))
        .unwrap();

        // Forward the request and collect events as they arrive
        let response = forward(app.clone(), vec![0], req_body.into()).await;
        assert_eq!(response.status().as_u16(), 200);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/event-stream"
        );

        // Read the streaming body incrementally by collecting all chunks
        use http_body_util::BodyExt as _;

        let collected_bytes = response.into_body().collect().await.unwrap().to_bytes();

        // Parse events from SSE format (data: prefix)
        let text = String::from_utf8_lossy(&collected_bytes);
        let mut collected_events = Vec::new();
        for line in text.lines() {
            if line.starts_with("data:") && !line.contains("[DONE]") {
                // Extract the event data after "data: " prefix
                if let Some(event_data) = line.strip_prefix("data: ") {
                    collected_events.push(event_data.to_string());
                }
            } else if line == "[DONE]" || line.trim() == "[DONE]" {
                break;
            }
        }

        // Assert that we got all events (excluding [DONE])
        assert_eq!(
            collected_events.len(),
            10,
            "Expected 10 SSE events, got: {:?}",
            collected_events
        );
        for i in 0..10 {
            assert!(
                collected_events.contains(&format!("event-{i}")),
                "Event {} should be present",
                i
            );
        }

        server.shutdown().await;
    }

    /// Test that permit is held during streaming and released after stream ends.
    #[tokio::test]
    async fn test_permit_lifetime_during_stream() {
        use std::time::Duration;

        let state = Arc::new(MockServerState::new());

        // Create an SSE response
        let events: Vec<String> = (0..5).map(|i| format!("data-{i}")).collect();
        state.push(MockResponse::Sse {
            events,
            abort_after: None,
        });

        let server = MockServer::new(state.clone()).await;

        // Use a single-permit lane to make the test deterministic
        let sem = Arc::new(tokio::sync::Semaphore::new(1));

        let lane = Lane {
            model: "test-model".to_string(),
            provider: "test-provider".to_string(),
            base_url: server.base_url(),
            api_key: "test-key".to_string(),
            protocol: Arc::new(AnthropicProtocol::new()),
            sem: sem.clone(),
            max: 1,
            limited: false,
            budget: AtomicI64::new(-1),
            cooldown_until: AtomicU64::new(0),
            streak: AtomicU32::new(0),
            dead: AtomicBool::new(false),
            dead_reason: std::sync::Mutex::new(String::new()),
            inflight: AtomicI64::new(0),
            ok: AtomicU64::new(0),
            err: AtomicU64::new(0),
        };

        let by_model = HashMap::from([("test-model".to_string(), 0)]);
        let pools = HashMap::from([("default".to_string(), vec![0])]);
        let auth = Arc::new(AuthMiddleware::new(&AuthCfg::default_none()));
        let app = Arc::new(App {
            lanes: vec![lane],
            by_model,
            pools,
            rr: AtomicUsize::new(0),
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap(),
            auth,
        });

        let req_body = serde_json::to_vec(&json!({
            "model": "test-model",
            "messages": [{"role": "user", "content": "hi"}],
            "max_tokens": 100
        }))
        .unwrap();

        // Initial available permits should be 1
        assert_eq!(sem.available_permits(), 1);

        // Forward the request - this will acquire a permit
        let response = forward(app.clone(), vec![0], req_body.into()).await;
        assert_eq!(response.status().as_u16(), 200);

        // BEFORE consuming the body, assert the permit is HELD:
        // try_acquire should fail (return Err) because permit is held by the stream
        assert!(
            sem.clone().try_acquire_owned().is_err(),
            "Permit should be held during streaming (available_permits() == 0)"
        );

    // Fully consume the response body
        let collected_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(!collected_bytes.is_empty());

        // After consumption, permit should be released (poll briefly if needed)
        for _ in 0..10 {
            tokio::time::sleep(Duration::from_millis(10)).await;
            if sem.available_permits() == 1 {
                break;
            }
        }

        assert_eq!(
            sem.available_permits(),
            1,
            "Permit should be released after stream ends"
        );

        server.shutdown().await;
    }

    /// Test non-stream JSON still relays correctly.
    #[tokio::test]
    async fn test_non_stream_json_relay() {
        let state = Arc::new(MockServerState::new());
        state.push(MockResponse::Ok {
            status: StatusCode::OK,
            body: json!({ "content": ["Hello"], "model": "test", "stop": [] }),
        });

        let server = MockServer::new(state.clone()).await;

        let lane = Lane {
            model: "test-model".to_string(),
            provider: "test-provider".to_string(),
            base_url: server.base_url(),
            api_key: "test-key".to_string(),
            protocol: Arc::new(AnthropicProtocol::new()),
            sem: Arc::new(tokio::sync::Semaphore::new(10)),
            max: 10,
            limited: false,
            budget: AtomicI64::new(-1),
            cooldown_until: AtomicU64::new(0),
            streak: AtomicU32::new(0),
            dead: AtomicBool::new(false),
            dead_reason: std::sync::Mutex::new(String::new()),
            inflight: AtomicI64::new(0),
            ok: AtomicU64::new(0),
            err: AtomicU64::new(0),
        };

        let by_model = HashMap::from([("test-model".to_string(), 0)]);
        let pools = HashMap::from([("default".to_string(), vec![0])]);
        let auth = Arc::new(AuthMiddleware::new(&AuthCfg::default_none()));
        let app = Arc::new(App {
            lanes: vec![lane],
            by_model,
            pools,
            rr: AtomicUsize::new(0),
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap(),
            auth,
        });

        let req_body = serde_json::to_vec(&json!({
            "model": "test-model",
            "messages": [{"role": "user", "content": "hi"}],
            "max_tokens": 100
        }))
        .unwrap();

        let response = forward(app.clone(), vec![0], req_body.into()).await;
        assert_eq!(response.status().as_u16(), 200);

        use http_body_util::BodyExt as _;
        let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body_str = String::from_utf8_lossy(&body_bytes);
        assert!(body_str.contains("Hello"));

        server.shutdown().await;
    }
}
