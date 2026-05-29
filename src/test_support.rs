// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! In-crate mock-upstream test harness (B-105 / B-105b).

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Mutex;
use std::time::Duration;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AuthMiddleware;
    use crate::config::AuthCfg;
    use crate::forward::forward;
    use crate::proto::AnthropicProtocol;
    use crate::state::{now, App, Lane};
    use reqwest::Client;
    use serde_json::json;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicU64, AtomicUsize, Ordering};
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

        let req_body = serde_json::to_vec(&json!({"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})).unwrap();
        let response = forward(app.clone(), vec![0], req_body.into()).await;
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

        let req_body = serde_json::to_vec(&json!({"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})).unwrap();
        let response = forward(app.clone(), vec![0], req_body.into()).await;
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

        let req_body = serde_json::to_vec(&json!({"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})).unwrap();
        assert_eq!(sem.available_permits(), 1);
        let response = forward(app.clone(), vec![0], req_body.into()).await;
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

        let lane0 = Lane {
            model: "test-model".to_string(),
            provider: "test-provider".to_string(),
            base_url: server.base_url(),
            api_key: "test-key-0".to_string(),
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

        let lane1 = Lane {
            model: "test-model".to_string(),
            provider: "test-provider".to_string(),
            base_url: server.base_url(),
            api_key: "test-key-1".to_string(),
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
        let pools = HashMap::from([("default".to_string(), vec![0, 1])]);
        let auth = Arc::new(AuthMiddleware::new(&AuthCfg::default_none()));
        let app = Arc::new(App {
            lanes: vec![lane0, lane1],
            by_model,
            pools,
            rr: AtomicUsize::new(0),
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap(),
            auth,
        });

        let req_body = serde_json::to_vec(&json!({"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})).unwrap();

        // Should failover from lane 0 (error) to lane 1 (success)
        let response = forward(app.clone(), vec![0, 1], req_body.into()).await;
        assert_eq!(response.status().as_u16(), 200);

        let t = now();
        assert!(
            !app.lanes[0].usable(t),
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

        let err0_before = 0u64;
        let _cooldown0_before = 0u64;
        let inflight0_before = 0i64;
        let ok0_before = 0u64;

        let lane0 = Lane {
            model: "test-model".to_string(),
            provider: "test-provider".to_string(),
            base_url: server.base_url(),
            api_key: "test-key-0".to_string(),
            protocol: Arc::new(AnthropicProtocol::new()),
            sem: Arc::new(tokio::sync::Semaphore::new(10)),
            max: 10,
            limited: false,
            budget: AtomicI64::new(-1),
            cooldown_until: AtomicU64::new(0),
            streak: AtomicU32::new(0),
            dead: AtomicBool::new(false),
            dead_reason: std::sync::Mutex::new(String::new()),
            inflight: AtomicI64::new(inflight0_before),
            ok: AtomicU64::new(ok0_before),
            err: AtomicU64::new(err0_before),
        };

        let err1_before = 0u64;
        let inflight1_before = 0i64;
        let ok1_before = 0u64;

        let lane1 = Lane {
            model: "test-model".to_string(),
            provider: "test-provider".to_string(),
            base_url: server.base_url(),
            api_key: "test-key-1".to_string(),
            protocol: Arc::new(AnthropicProtocol::new()),
            sem: Arc::new(tokio::sync::Semaphore::new(10)),
            max: 10,
            limited: false,
            budget: AtomicI64::new(-1),
            cooldown_until: AtomicU64::new(0),
            streak: AtomicU32::new(0),
            dead: AtomicBool::new(false),
            dead_reason: std::sync::Mutex::new(String::new()),
            inflight: AtomicI64::new(inflight1_before),
            ok: AtomicU64::new(ok1_before),
            err: AtomicU64::new(err1_before),
        };

        let by_model = HashMap::from([("test-model".to_string(), 0)]);
        let pools = HashMap::from([("default".to_string(), vec![0, 1])]);
        let auth = Arc::new(AuthMiddleware::new(&AuthCfg::default_none()));
        let app = Arc::new(App {
            lanes: vec![lane0, lane1],
            by_model,
            pools,
            rr: AtomicUsize::new(0),
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap(),
            auth,
        });

        let req_body = serde_json::to_vec(&json!({"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})).unwrap();

        // Consume response body fully
        let response = forward(app.clone(), vec![0, 1], req_body.into()).await;
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
        let err0_after = app.lanes[0].err.load(Ordering::Relaxed);
        let cooldown0_after = app.lanes[0].cooldown_until.load(Ordering::Relaxed);
        let _inflight0_after = app.lanes[0].inflight.load(Ordering::Relaxed);
        let _ok0_after = app.lanes[0].ok.load(Ordering::Relaxed);

        // (b) Assert: lanes[0].err increased AND cooldown_until > now (failure recorded)
        assert!(
            err0_after > err0_before,
            "lane 0 err should have increased after mid-stream abort, before={before}, after={after}",
            before = err0_before,
            after = err0_after
        );
        assert!(
            cooldown0_after > t,
            "lane 0 cooldown_until should be set after mid-stream abort, now={now}, cooldown={cooldown}",
            now = t,
            cooldown = cooldown0_after
        );

        // (c) Assert: lane 1 was NOT used — inflight/ok untouched (no failover after first byte)
        let err1_after = app.lanes[1].err.load(Ordering::Relaxed);
        let inflight1_after = app.lanes[1].inflight.load(Ordering::Relaxed);
        let ok1_after = app.lanes[1].ok.load(Ordering::Relaxed);

        assert_eq!(
            err1_after,
            err1_before,
            "lane 1 err should be unchanged (no failover), before={before}, after={after}",
            before = err1_before,
            after = err1_after
        );
        assert_eq!(
            inflight1_after,
            inflight1_before,
            "lane 1 inflight should be unchanged (no failover), before={before}, after={after}",
            before = inflight1_before,
            after = inflight1_after
        );
        assert_eq!(
            ok1_after,
            ok1_before,
            "lane 1 ok should be unchanged (no failover), before={before}, after={after}",
            before = ok1_before,
            after = ok1_after
        );

        server.shutdown().await;
    }
}
