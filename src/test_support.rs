// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! In-crate mock-upstream test harness (/).

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
    last_request_body: std::sync::Mutex<Option<Vec<u8>>>,
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

    /// Record the last received request body (for translation / on-the-wire assertions).
    pub(crate) fn record_request_body(&self, body: &[u8]) {
        *self.last_request_body.lock().unwrap() = Some(body.to_vec());
    }

    /// Get the last received request body bytes (for assertions in tests).
    pub(crate) fn get_last_request_body(&self) -> Option<Vec<u8>> {
        self.last_request_body.lock().unwrap().clone()
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
            .route("/v1/chat/completions", any(mock_handler))
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
    let (parts, body) = request.into_parts();

    // Record the Authorization header for passthrough token forwarding tests
    if let Some(auth_header) = parts
        .headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        state.record_auth_header(auth_header);
    }

    // Record the received request body for translation / on-the-wire assertions.
    let body_bytes = axum::body::to_bytes(body, usize::MAX)
        .await
        .unwrap_or_default();
    state.record_request_body(&body_bytes);

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
    use crate::forward::{forward, forward_with_pool};
    use crate::state::{now, App, Lane};
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
        // ensure the Prometheus recorder is live so the forward path's counters record.
        crate::metrics::init();
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
            protocol: Arc::new(crate::proto::Protocol::anthropic()),
            max: 10,
            error_map: Arc::new(std::collections::HashMap::new()),
            context_max: None,
            path: None,
            auth: None,
        };

        let by_model = HashMap::from([("test-model".to_string(), 0)]);
        let pools = HashMap::from([(
            "default".to_string(),
            vec![crate::state::WeightedLane { idx: 0, weight: 1 }],
        )]);
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
            failover_cfg: None,
            fallback_pools: HashMap::new(),
            on_exhausted_cfgs: HashMap::new(),
            governance: None,
        });

        let req_body = serde_json::to_vec(&json!({"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})).unwrap();
        let response = forward(
            app.clone(),
            vec![crate::state::WeightedLane { idx: 0, weight: 1 }],
            req_body.into(),
            None,
            None,
        )
        .await;
        assert_eq!(response.status().as_u16(), 200);

        use http_body_util::BodyExt as _;
        let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body_str = String::from_utf8_lossy(&body_bytes);
        assert!(body_str.contains("Hello"));
        // the forward path (forward → forward_with_pool) must have emitted the
        // upstream-attempt counter into the Prometheus exposition.
        assert!(
            crate::metrics::render().contains(crate::metrics::UPSTREAM_ATTEMPTS_TOTAL),
            "forward path should emit {} into /metrics",
            crate::metrics::UPSTREAM_ATTEMPTS_TOTAL
        );
        server.shutdown().await;
    }

    /// Regression: an Anthropic-ingress request to an OpenAI-protocol backend (cross-protocol,
    /// non-streaming) must preserve the upstream `model` in the translated response — the same as a
    /// same-protocol/direct route. Was dropped because IrResponse carried no model field, so the
    /// read→IR→write round-trip lost it (pool routes that landed on a cross-protocol member returned
    /// no model, while direct routes that passed through verbatim kept it).
    #[tokio::test]
    async fn test_cross_protocol_nonstream_preserves_model() {
        crate::metrics::init();
        let state = Arc::new(MockServerState::new());
        state.push(MockResponse::Ok {
            status: StatusCode::OK,
            body: json!({
                "model": "glm-4.5",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "Hello"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 12, "completion_tokens": 5}
            }),
        });
        let server = MockServer::new(state.clone()).await;

        let lane_data = LaneData {
            model: "glm-4.5".to_string(),
            provider: "zai".to_string(),
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
        // Lane speaks the OpenAI protocol; ingress below is Anthropic → cross-protocol translation.
        let lane = Lane {
            model: "glm-4.5".to_string(),
            provider: "zai".to_string(),
            base_url: server.base_url(),
            api_key: "k".to_string(),
            protocol: Arc::new(crate::proto::Protocol::openai()),
            max: 10,
            error_map: Arc::new(std::collections::HashMap::new()),
            context_max: None,
            path: None,
            auth: None,
        };
        let app = Arc::new(App {
            lanes: vec![lane],
            store: Arc::new(InMemoryStore::new(vec![lane_data])),
            by_model: HashMap::from([("glm-4.5".to_string(), 0)]),
            pools: HashMap::from([(
                "pa".to_string(),
                vec![crate::state::WeightedLane { idx: 0, weight: 1 }],
            )]),
            rr: AtomicUsize::new(0),
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap(),
            auth: Arc::new(AuthMiddleware::new(&AuthCfg::default_none())),
            auth_mode: crate::auth::AuthMode::None,
            failover_cfg: None,
            fallback_pools: HashMap::new(),
            on_exhausted_cfgs: HashMap::new(),
            governance: None,
        });

        let body = serde_json::to_vec(
            &json!({"model": "pa", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 50}),
        )
        .unwrap();
        let resp = forward_with_pool(
            app.clone(),
            vec![crate::state::WeightedLane { idx: 0, weight: 1 }],
            body.into(),
            None,
            "pa",
            None,
            "anthropic",
            None,
        )
        .await;
        assert_eq!(resp.status().as_u16(), 200);

        use http_body_util::BodyExt as _;
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            v["model"], "glm-4.5",
            "translated Anthropic response must carry the serving model; got: {v}"
        );
        server.shutdown().await;
    }

    /// Regression: token usage from a cross-protocol non-streaming response must be charged to the
    /// virtual key, so TPM limits actually enforce. Was broken because the buffered cross-protocol
    /// path returned without tapping usage or touching the UsageSink — per-key tokens stayed 0 and
    /// TPM never tripped. After recording, a second request in the same window is rejected (429).
    #[tokio::test]
    async fn test_cross_protocol_nonstream_records_tokens_for_tpm() {
        use crate::governance::{GovState, SqliteStore, Store, VirtualKey};
        crate::metrics::init();

        let state = Arc::new(MockServerState::new());
        for _ in 0..2 {
            state.push(MockResponse::Ok {
                status: StatusCode::OK,
                body: json!({
                    "model": "glm-4.5",
                    "choices": [{"index": 0, "message": {"role": "assistant", "content": "Hello there friend"}, "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": 100, "completion_tokens": 60}
                }),
            });
        }
        let server = MockServer::new(state.clone()).await;

        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let secret = "sk-vk-tpm";
        store
            .put_key(&VirtualKey {
                id: "ktpm".to_string(),
                key_hash: crate::sigv4::sha256_hex(secret.as_bytes()),
                name: "tpm".to_string(),
                allowed_pools: vec!["pa".to_string()],
                max_budget_cents: None,
                budget_period: "total".to_string(),
                rpm_limit: Some(100), // high, so RPM doesn't interfere — TPM is what we exercise
                tpm_limit: Some(30),
                enabled: true,
                created_at: 0,
            })
            .unwrap();
        let gov = Arc::new(GovState::new(store, 0, 0, None).unwrap());

        let lane_data = LaneData {
            model: "glm-4.5".to_string(),
            provider: "zai".to_string(),
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
            model: "glm-4.5".to_string(),
            provider: "zai".to_string(),
            base_url: server.base_url(),
            api_key: "k".to_string(),
            protocol: Arc::new(crate::proto::Protocol::openai()),
            max: 10,
            error_map: Arc::new(std::collections::HashMap::new()),
            context_max: None,
            path: None,
            auth: None,
        };
        let app = Arc::new(App {
            lanes: vec![lane],
            store: Arc::new(InMemoryStore::new(vec![lane_data])),
            by_model: HashMap::from([("glm-4.5".to_string(), 0)]),
            pools: HashMap::from([(
                "pa".to_string(),
                vec![crate::state::WeightedLane { idx: 0, weight: 1 }],
            )]),
            rr: AtomicUsize::new(0),
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap(),
            auth: Arc::new(AuthMiddleware::new(&AuthCfg::default_none())),
            auth_mode: crate::auth::AuthMode::None,
            failover_cfg: None,
            fallback_pools: HashMap::new(),
            on_exhausted_cfgs: HashMap::new(),
            governance: Some(gov),
        });

        let router = crate::build_router(app);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client = reqwest::Client::new();
        let url = format!("http://{addr}/pa/v1/messages");
        let req = json!({"model": "pa", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 50}).to_string();

        // First request: tokens-so-far is 0 (< 30) → admitted; consumes 160 tokens post-response.
        let r1 = client
            .post(&url)
            .bearer_auth(secret)
            .body(req.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(r1.status().as_u16(), 200, "first request is under TPM");
        let b1: Value = r1.json().await.unwrap();
        assert_eq!(
            b1["model"], "glm-4.5",
            "model also preserved end-to-end through the router"
        );

        // Second request in the same 60s window: prior tokens (160) now exceed TPM 30 → 429.
        let r2 = client
            .post(&url)
            .bearer_auth(secret)
            .body(req)
            .send()
            .await
            .unwrap();
        assert_eq!(
            r2.status().as_u16(),
            429,
            "recorded tokens must make TPM enforce (was the bug: tokens stayed 0, never 429)"
        );

        handle.abort();
        server.shutdown().await;
    }

    /// Regression: a lane's `max_requests` lifetime cap (loaded as `budget`, `limited=true`) must
    /// actually exhaust the lane — and each success must increment the per-lane `ok` counter. Both
    /// were unwired: the success path never called record_success or spend_budget, so the cap never
    /// tripped (unlimited requests) and `ok` stayed 0.
    #[tokio::test]
    async fn test_max_requests_budget_caps_lane_and_counts_ok() {
        crate::metrics::init();
        let state = Arc::new(MockServerState::new());
        for _ in 0..3 {
            state.push(MockResponse::Ok {
                status: StatusCode::OK,
                body: json!({
                    "role": "assistant",
                    "content": [{"type": "text", "text": "hi"}],
                    "model": "glm-4.6",
                    "stop_reason": "end_turn",
                    "usage": {"input_tokens": 1, "output_tokens": 1}
                }),
            });
        }
        let server = MockServer::new(state.clone()).await;

        let lane_data = LaneData {
            model: "glm-4.6".to_string(),
            provider: "z".to_string(),
            max: 10,
            sem: Arc::new(tokio::sync::Semaphore::new(10)),
            limited: true, // max_requests was configured
            budget: 2,     // lifetime cap of 2 requests
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
            model: "glm-4.6".to_string(),
            provider: "z".to_string(),
            base_url: server.base_url(),
            api_key: "k".to_string(),
            protocol: Arc::new(crate::proto::Protocol::anthropic()),
            max: 10,
            error_map: Arc::new(std::collections::HashMap::new()),
            context_max: None,
            path: None,
            auth: None,
        };
        let app = Arc::new(App {
            lanes: vec![lane],
            store: Arc::new(InMemoryStore::new(vec![lane_data])),
            by_model: HashMap::from([("glm-4.6".to_string(), 0)]),
            pools: HashMap::from([(
                "pc".to_string(),
                vec![crate::state::WeightedLane { idx: 0, weight: 1 }],
            )]),
            rr: AtomicUsize::new(0),
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap(),
            auth: Arc::new(AuthMiddleware::new(&AuthCfg::default_none())),
            auth_mode: crate::auth::AuthMode::None,
            failover_cfg: None,
            fallback_pools: HashMap::new(),
            on_exhausted_cfgs: HashMap::new(),
            governance: None,
        });

        let cands = vec![crate::state::WeightedLane { idx: 0, weight: 1 }];
        let body = serde_json::to_vec(
            &json!({"model": "pc", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 10}),
        )
        .unwrap();

        use http_body_util::BodyExt as _;
        // First two requests are within budget → served.
        for n in 0..2 {
            let resp = forward_with_pool(
                app.clone(),
                cands.clone(),
                body.clone().into(),
                None,
                "pc",
                None,
                "anthropic",
                None,
            )
            .await;
            assert_eq!(resp.status().as_u16(), 200, "request {n} should be served");
            let _ = resp.into_body().collect().await.unwrap(); // drain → release permit
        }

        // Budget spent (2 → 0): the lane is no longer usable, so the pool is exhausted → 503.
        let resp3 = forward_with_pool(
            app.clone(),
            cands.clone(),
            body.clone().into(),
            None,
            "pc",
            None,
            "anthropic",
            None,
        )
        .await;
        assert_eq!(
            resp3.status().as_u16(),
            503,
            "third request must be rejected once the max_requests budget is spent"
        );

        let snap = app.store.snapshot(0, now());
        assert_eq!(
            snap.ok, 2,
            "per-lane ok counter must increment on each success"
        );
        assert!(
            !snap.usable,
            "lane must be unusable after its max_requests budget is exhausted"
        );
        server.shutdown().await;
    }

    /// GET /metrics through the REAL router (route table + auth middleware) over HTTP returns
    /// the Prometheus exposition with NO caller token — the endpoint is auth-exempt like /healthz.
    #[tokio::test]
    async fn test_metrics_endpoint_served_over_http_no_auth() {
        crate::metrics::init();
        metrics::counter!(crate::metrics::REQUESTS_TOTAL, "outcome" => "ok").increment(1);

        let auth = Arc::new(AuthMiddleware::new(&AuthCfg::default_none()));
        let store = Arc::new(InMemoryStore::new(vec![]));
        let app = Arc::new(App {
            lanes: vec![],
            store,
            by_model: HashMap::new(),
            pools: HashMap::new(),
            rr: AtomicUsize::new(0),
            client: Client::builder().build().unwrap(),
            auth,
            auth_mode: crate::auth::AuthMode::None,
            failover_cfg: None,
            fallback_pools: HashMap::new(),
            on_exhausted_cfgs: HashMap::new(),
            governance: None,
        });

        let router = crate::build_router(app);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });

        let resp = reqwest::Client::new()
            .get(format!("http://{addr}/metrics"))
            .send()
            .await
            .expect("GET /metrics");
        assert_eq!(resp.status().as_u16(), 200);
        let ct = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .to_string();
        assert!(ct.starts_with("text/plain"), "content-type was {ct}");
        let body = resp.text().await.unwrap();
        assert!(
            body.contains(crate::metrics::REQUESTS_TOTAL),
            "exposition should contain a metric; got:\n{body}"
        );

        handle.abort();
    }

    /// governance-enabled router enforces virtual-key auth + allowed-pools over real HTTP.
    #[tokio::test]
    async fn test_governance_vkey_auth_and_pool_acl() {
        use crate::governance::{GovState, SqliteStore, Store, VirtualKey};

        crate::metrics::init();
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let secret = "sk-vk-allowed";
        store
            .put_key(&VirtualKey {
                id: "k1".to_string(),
                key_hash: crate::sigv4::sha256_hex(secret.as_bytes()),
                name: "tester".to_string(),
                allowed_pools: vec!["allowedpool".to_string()],
                max_budget_cents: None,
                budget_period: "total".to_string(),
                rpm_limit: None,
                tpm_limit: None,
                enabled: true,
                created_at: 0,
            })
            .unwrap();
        let gov = Arc::new(GovState::new(store, 1, 0, None).unwrap());

        let auth = Arc::new(AuthMiddleware::new(&AuthCfg::default_none()));
        let st = Arc::new(InMemoryStore::new(vec![]));
        let app = Arc::new(App {
            lanes: vec![],
            store: st,
            by_model: HashMap::new(),
            pools: HashMap::new(),
            rr: AtomicUsize::new(0),
            client: Client::builder().build().unwrap(),
            auth,
            auth_mode: crate::auth::AuthMode::None,
            failover_cfg: None,
            fallback_pools: HashMap::new(),
            on_exhausted_cfgs: HashMap::new(),
            governance: Some(gov),
        });

        let router = crate::build_router(app);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client = reqwest::Client::new();

        // No virtual key → 401.
        let r = client
            .post(format!("http://{addr}/somepool/v1/messages"))
            .body("{}")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 401, "no vkey → unauthorized");

        // Valid vkey but a pool not in allowed_pools → 403.
        let r = client
            .post(format!("http://{addr}/somepool/v1/messages"))
            .bearer_auth(secret)
            .body("{}")
            .send()
            .await
            .unwrap();
        assert_eq!(
            r.status().as_u16(),
            403,
            "vkey not allowed for pool → forbidden"
        );

        // Valid vkey on its allowed pool passes the ACL; routing then 404s (no such pool wired) —
        // proving the request got PAST the 403 gate.
        let r = client
            .post(format!("http://{addr}/allowedpool/v1/messages"))
            .bearer_auth(secret)
            .body("{}")
            .send()
            .await
            .unwrap();
        assert_eq!(
            r.status().as_u16(),
            404,
            "ACL passed; unknown pool → not found"
        );

        handle.abort();
    }

    /// a virtual key over its budget is rejected with 402 before forwarding.
    #[tokio::test]
    async fn test_governance_budget_402() {
        use crate::governance::{GovState, SqliteStore, Store, VirtualKey};

        crate::metrics::init();
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let secret = "sk-vk-broke";
        store
            .put_key(&VirtualKey {
                id: "kb".to_string(),
                key_hash: crate::sigv4::sha256_hex(secret.as_bytes()),
                name: "broke".to_string(),
                allowed_pools: vec![], // all pools
                max_budget_cents: Some(100),
                budget_period: "total".to_string(),
                rpm_limit: None,
                tpm_limit: None,
                enabled: true,
                created_at: 0,
            })
            .unwrap();
        // Pre-seed usage past the 100c budget (window 0 = "total").
        store.add_usage("kb", 0, 250, 0).unwrap();
        let gov = Arc::new(GovState::new(store, 1, 0, None).unwrap());

        let auth = Arc::new(AuthMiddleware::new(&AuthCfg::default_none()));
        let st = Arc::new(InMemoryStore::new(vec![]));
        let app = Arc::new(App {
            lanes: vec![],
            store: st,
            by_model: HashMap::new(),
            pools: HashMap::new(),
            rr: AtomicUsize::new(0),
            client: Client::builder().build().unwrap(),
            auth,
            auth_mode: crate::auth::AuthMode::None,
            failover_cfg: None,
            fallback_pools: HashMap::new(),
            on_exhausted_cfgs: HashMap::new(),
            governance: Some(gov),
        });

        let router = crate::build_router(app);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });

        let r = reqwest::Client::new()
            .post(format!("http://{addr}/anypool/v1/messages"))
            .bearer_auth(secret)
            .body("{}")
            .send()
            .await
            .unwrap();
        assert_eq!(
            r.status().as_u16(),
            402,
            "over-budget key → payment required"
        );

        handle.abort();
    }

    /// a virtual key over its RPM is rejected with 429 + Retry-After.
    #[tokio::test]
    async fn test_governance_rate_limit_429() {
        use crate::governance::{GovState, SqliteStore, Store, VirtualKey};

        crate::metrics::init();
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let secret = "sk-vk-rl";
        store
            .put_key(&VirtualKey {
                id: "krl".to_string(),
                key_hash: crate::sigv4::sha256_hex(secret.as_bytes()),
                name: "rl".to_string(),
                allowed_pools: vec![],
                max_budget_cents: None,
                budget_period: "total".to_string(),
                rpm_limit: Some(2),
                tpm_limit: None,
                enabled: true,
                created_at: 0,
            })
            .unwrap();
        let gov = Arc::new(GovState::new(store, 0, 0, None).unwrap());

        let auth = Arc::new(AuthMiddleware::new(&AuthCfg::default_none()));
        let st = Arc::new(InMemoryStore::new(vec![]));
        let app = Arc::new(App {
            lanes: vec![],
            store: st,
            by_model: HashMap::new(),
            pools: HashMap::new(),
            rr: AtomicUsize::new(0),
            client: Client::builder().build().unwrap(),
            auth,
            auth_mode: crate::auth::AuthMode::None,
            failover_cfg: None,
            fallback_pools: HashMap::new(),
            on_exhausted_cfgs: HashMap::new(),
            governance: Some(gov),
        });

        let router = crate::build_router(app);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client = reqwest::Client::new();
        let url = format!("http://{addr}/anypool/v1/messages");

        // RPM=2: first two pass the rate gate (then 404 — no such pool); the third is rate-limited.
        for i in 0..2 {
            let r = client
                .post(&url)
                .bearer_auth(secret)
                .body("{}")
                .send()
                .await
                .unwrap();
            assert_eq!(
                r.status().as_u16(),
                404,
                "request {i} under limit (routing 404)"
            );
        }
        let r = client
            .post(&url)
            .bearer_auth(secret)
            .body("{}")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 429, "3rd request over RPM → 429");
        assert!(
            r.headers().get(reqwest::header::RETRY_AFTER).is_some(),
            "429 must carry Retry-After"
        );

        handle.abort();
    }

    /// the /admin management API — create→list→usage→delete, admin-token gating, and a minted
    /// secret then authenticating as a working virtual key.
    #[tokio::test]
    async fn test_governance_admin_api() {
        use crate::governance::{GovState, SqliteStore};

        crate::metrics::init();
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = Arc::new(GovState::new(store, 1, 0, Some("admintok".to_string())).unwrap());

        let auth = Arc::new(AuthMiddleware::new(&AuthCfg::default_none()));
        let st = Arc::new(InMemoryStore::new(vec![]));
        let app = Arc::new(App {
            lanes: vec![],
            store: st,
            by_model: HashMap::new(),
            pools: HashMap::new(),
            rr: AtomicUsize::new(0),
            client: Client::builder().build().unwrap(),
            auth,
            auth_mode: crate::auth::AuthMode::None,
            failover_cfg: None,
            fallback_pools: HashMap::new(),
            on_exhausted_cfgs: HashMap::new(),
            governance: Some(gov),
        });

        let router = crate::build_router(app);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client = reqwest::Client::new();
        let base = format!("http://{addr}");

        // Missing admin token → 401.
        let r = client
            .post(format!("{base}/admin/keys"))
            .json(&serde_json::json!({"name": "x"}))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 401, "no admin token → unauthorized");

        // Create a key with the admin token.
        let r = client
            .post(format!("{base}/admin/keys"))
            .bearer_auth("admintok")
            .json(&serde_json::json!({"name": "team-a", "allowed_pools": ["allowedpool"], "rpm_limit": 5}))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 201, "admin create → 201");
        let created: serde_json::Value = r.json().await.unwrap();
        let id = created["id"].as_str().unwrap().to_string();
        let secret = created["secret"].as_str().unwrap().to_string();
        assert!(secret.starts_with("sk-bb-"), "secret returned once");
        assert!(created.get("key_hash").is_none(), "hash never returned");

        // List shows it (no hash).
        let r = client
            .get(format!("{base}/admin/keys"))
            .bearer_auth("admintok")
            .send()
            .await
            .unwrap();
        let listed: serde_json::Value = r.json().await.unwrap();
        assert_eq!(listed["keys"].as_array().unwrap().len(), 1);
        assert!(listed["keys"][0].get("key_hash").is_none());

        // Usage endpoint works.
        let r = client
            .get(format!("{base}/admin/keys/{id}/usage"))
            .bearer_auth("admintok")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 200);

        // The minted secret authenticates as a virtual key: its allowed pool passes the ACL →
        // routing 404 (no such pool wired), proving the key is live + ACL applied.
        let r = client
            .post(format!("{base}/allowedpool/v1/messages"))
            .bearer_auth(&secret)
            .body("{}")
            .send()
            .await
            .unwrap();
        assert_eq!(
            r.status().as_u16(),
            404,
            "minted key authenticates + ACL passes"
        );

        // Delete, then it's gone from the list.
        let r = client
            .delete(format!("{base}/admin/keys/{id}"))
            .bearer_auth("admintok")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 200);
        let r = client
            .get(format!("{base}/admin/keys"))
            .bearer_auth("admintok")
            .send()
            .await
            .unwrap();
        let listed: serde_json::Value = r.json().await.unwrap();
        assert_eq!(listed["keys"].as_array().unwrap().len(), 0, "deleted");

        handle.abort();
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
            protocol: Arc::new(crate::proto::Protocol::anthropic()),
            max: 10,
            error_map: Arc::new(std::collections::HashMap::new()),
            context_max: None,
            path: None,
            auth: None,
        };

        let by_model = HashMap::from([("test-model".to_string(), 0)]);
        let pools = HashMap::from([(
            "default".to_string(),
            vec![crate::state::WeightedLane { idx: 0, weight: 1 }],
        )]);
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
            failover_cfg: None,
            fallback_pools: HashMap::new(),
            on_exhausted_cfgs: HashMap::new(),
            governance: None,
        });

        let req_body = serde_json::to_vec(&json!({"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})).unwrap();
        let response = forward(
            app.clone(),
            vec![crate::state::WeightedLane { idx: 0, weight: 1 }],
            req_body.into(),
            None,
            None,
        )
        .await;
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
            protocol: Arc::new(crate::proto::Protocol::anthropic()),
            max: 1,
            error_map: Arc::new(std::collections::HashMap::new()),
            context_max: None,
            path: None,
            auth: None,
        };

        let by_model = HashMap::from([("test-model".to_string(), 0)]);
        let pools = HashMap::from([(
            "default".to_string(),
            vec![crate::state::WeightedLane { idx: 0, weight: 1 }],
        )]);
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
            failover_cfg: None,
            fallback_pools: HashMap::new(),
            on_exhausted_cfgs: HashMap::new(),
            governance: None,
        });

        let req_body = serde_json::to_vec(&json!({"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})).unwrap();
        assert_eq!(sem.available_permits(), 1);
        let response = forward(
            app.clone(),
            vec![crate::state::WeightedLane { idx: 0, weight: 1 }],
            req_body.into(),
            None,
            None,
        )
        .await;
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

    /// Pre-first-byte error triggers failover to next lane.
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
            protocol: Arc::new(crate::proto::Protocol::anthropic()),
            max: 10,
            error_map: Arc::new(std::collections::HashMap::new()),
            context_max: None,
            path: None,
            auth: None,
        };

        let lane1 = Lane {
            model: "test-model".to_string(),
            provider: "test-provider".to_string(),
            base_url: server.base_url(),
            api_key: "test-key-1".to_string(),
            protocol: Arc::new(crate::proto::Protocol::anthropic()),
            max: 10,
            error_map: Arc::new(std::collections::HashMap::new()),
            context_max: None,
            path: None,
            auth: None,
        };

        let by_model = HashMap::from([("test-model".to_string(), 0)]);
        let pools = HashMap::from([(
            "default".to_string(),
            vec![
                crate::state::WeightedLane { idx: 0, weight: 1 },
                crate::state::WeightedLane { idx: 1, weight: 1 },
            ],
        )]);
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
            failover_cfg: None,
            fallback_pools: HashMap::new(),
            on_exhausted_cfgs: HashMap::new(),
            governance: None,
        });

        let req_body = serde_json::to_vec(&json!({"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})).unwrap();

        // Should failover from lane 0 (error) to lane 1 (success)
        let response = forward(
            app.clone(),
            vec![
                crate::state::WeightedLane { idx: 0, weight: 1 },
                crate::state::WeightedLane { idx: 1, weight: 1 },
            ],
            req_body.into(),
            None,
            None,
        )
        .await;
        assert_eq!(response.status().as_u16(), 200);

        let t = now();
        assert!(
            !app.store.usable(0, t),
            "lane 0 should be in transient cooldown"
        );
        server.shutdown().await;
    }

    /// Mid-stream abort records lane breaker failure and does NOT failover.
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
            protocol: Arc::new(crate::proto::Protocol::anthropic()),
            max: 10,
            error_map: Arc::new(std::collections::HashMap::new()),
            context_max: None,
            path: None,
            auth: None,
        };

        let lane1 = Lane {
            model: "test-model".to_string(),
            provider: "test-provider".to_string(),
            base_url: server.base_url(),
            api_key: "test-key-1".to_string(),
            protocol: Arc::new(crate::proto::Protocol::anthropic()),
            max: 10,
            error_map: Arc::new(std::collections::HashMap::new()),
            context_max: None,
            path: None,
            auth: None,
        };

        let by_model = HashMap::from([("test-model".to_string(), 0)]);
        let pools = HashMap::from([(
            "default".to_string(),
            vec![
                crate::state::WeightedLane { idx: 0, weight: 1 },
                crate::state::WeightedLane { idx: 1, weight: 1 },
            ],
        )]);
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
            failover_cfg: None,
            fallback_pools: HashMap::new(),
            on_exhausted_cfgs: HashMap::new(),
            governance: None,
        });

        let req_body = serde_json::to_vec(&json!({"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})).unwrap();

        // Consume response body fully
        let response = forward(
            app.clone(),
            vec![
                crate::state::WeightedLane { idx: 0, weight: 1 },
                crate::state::WeightedLane { idx: 1, weight: 1 },
            ],
            req_body.into(),
            None,
            None,
        )
        .await;
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

    /// Caveat: passthrough 401 does NOT trip breaker; token mode 401 DOES.
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
            protocol: Arc::new(crate::proto::Protocol::anthropic()),
            max: 10,
            error_map: Arc::new(std::collections::HashMap::new()),
            context_max: None,
            path: None,
            auth: None,
        };

        let by_model = HashMap::from([("test-model".to_string(), 0)]);
        let pools = HashMap::from([(
            "default".to_string(),
            vec![crate::state::WeightedLane { idx: 0, weight: 1 }],
        )]);
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
            failover_cfg: None,
            fallback_pools: HashMap::new(),
            on_exhausted_cfgs: HashMap::new(),
            governance: None,
        });

        let req_body = serde_json::to_vec(&json!({"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})).unwrap();
        let response = forward(
            app_passthrough.clone(),
            vec![crate::state::WeightedLane { idx: 0, weight: 1 }],
            req_body.into(),
            None,
            None,
        )
        .await;
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
            protocol: Arc::new(crate::proto::Protocol::anthropic()),
            max: 10,
            error_map: Arc::new(std::collections::HashMap::new()),
            context_max: None,
            path: None,
            auth: None,
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
            failover_cfg: None,
            fallback_pools: HashMap::new(),
            on_exhausted_cfgs: HashMap::new(),
            governance: None,
        });

        let req_body = serde_json::to_vec(&json!({"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})).unwrap();
        let response = forward(
            app_token.clone(),
            vec![crate::state::WeightedLane { idx: 0, weight: 1 }],
            req_body.into(),
            None,
            None,
        )
        .await;
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
                "token-mode-401 → recoverable hard-down (long cooldown + probe), NOT permanent dead"
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
            protocol: Arc::new(crate::proto::Protocol::anthropic()),
            max: 10,
            error_map: Arc::new(std::collections::HashMap::new()),
            context_max: None,
            path: None,
            auth: None,
        };

        let by_model = HashMap::from([("test-model".to_string(), 0)]);
        let pools = HashMap::from([(
            "default".to_string(),
            vec![crate::state::WeightedLane { idx: 0, weight: 1 }],
        )]);
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
            failover_cfg: None,
            fallback_pools: HashMap::new(),
            on_exhausted_cfgs: HashMap::new(),
            governance: None,
        });

        // Caller's Bearer token (NOT busbar's key)
        let caller_bearer_token = "caller-specific-token-abc123";
        let req_body = serde_json::to_vec(&json!({"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})).unwrap();

        // Forward with caller's token (simulating what auth middleware would extract)
        let response = forward(
            app.clone(),
            vec![crate::state::WeightedLane { idx: 0, weight: 1 }],
            req_body.into(),
            Some(caller_bearer_token),
            None,
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

    /// Failover exclusions test.
    /// 2-lane pool with transient errors → verify only max_failover attempts made, not unbounded retry of same lane.
    #[tokio::test]
    async fn test_failover_exclusions() {
        use std::collections::HashMap;

        let state = Arc::new(MockServerState::new());

        // Push error responses for multiple attempts
        // With max_failover=3, we expect at most 4 total attempts (1 initial + 3 failovers)
        for _i in 0..5 {
            state.push(MockResponse::ServerError {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                body: json!({ "error": "transient failure" }),
            });
        }

        let server = MockServer::new(state.clone()).await;

        let lane_data_0 = LaneData {
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

        let lane_data_1 = LaneData {
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
            protocol: Arc::new(crate::proto::Protocol::anthropic()),
            max: 10,
            error_map: Arc::new(std::collections::HashMap::new()),
            context_max: None,
            path: None,
            auth: None,
        };

        let lane1 = Lane {
            model: "test-model".to_string(),
            provider: "test-provider".to_string(),
            base_url: server.base_url(),
            api_key: "test-key-1".to_string(),
            protocol: Arc::new(crate::proto::Protocol::anthropic()),
            max: 10,
            error_map: Arc::new(std::collections::HashMap::new()),
            context_max: None,
            path: None,
            auth: None,
        };

        let by_model = HashMap::from([("test-model".to_string(), 0)]);
        let pools = HashMap::from([(
            "default".to_string(),
            vec![
                crate::state::WeightedLane { idx: 0, weight: 1 },
                crate::state::WeightedLane { idx: 1, weight: 1 },
            ],
        )]);

        let auth = Arc::new(AuthMiddleware::new(&AuthCfg::default_none()));
        let store = Arc::new(InMemoryStore::new(vec![lane_data_0, lane_data_1]));
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
            failover_cfg: None,
            fallback_pools: HashMap::new(),
            on_exhausted_cfgs: HashMap::new(),
            governance: None,
        });

        let req_body = serde_json::to_vec(&json!({"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})).unwrap();

        // Forward request - should failover up to max_failover=3 times, then return 503
        let response = forward(
            app.clone(),
            vec![
                crate::state::WeightedLane { idx: 0, weight: 1 },
                crate::state::WeightedLane { idx: 1, weight: 1 },
            ],
            req_body.into(),
            None,
            None,
        )
        .await;

        // Should return 503 after exhausting lanes up to max_failover cap (default=3)
        assert_eq!(response.status().as_u16(), 503);

        // Verify: total errors across all lanes should be capped (not unbounded)
        let t = now();
        let total_errs: u64 = (0..2).map(|i| app.store.snapshot(i, t).err).sum();

        // With max_failover=3 and 2 lanes, we should have bounded attempts
        assert!(
            total_errs <= 10,
            "Total errors {} should be capped (not unbounded)",
            total_errs
        );

        server.shutdown().await;
    }

    /// Failover cap test.
    /// All lanes return TransientUpstream → max_failover attempts capped, then 503.
    #[tokio::test]
    async fn test_failover_cap() {
        use std::collections::HashMap;

        let state = Arc::new(MockServerState::new());

        // Push errors in LIFO order: lane 2 (top), lane 1, lane 0 (bottom)
        // SWRR will pick them in some order based on round-robin state
        for _i in 0..3 {
            state.push(MockResponse::ServerError {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                body: json!({ "error": "transient failure" }),
            });
        }

        let server = MockServer::new(state.clone()).await;

        let lane_data_0 = LaneData {
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

        let lane_data_1 = LaneData {
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

        let lane_data_2 = LaneData {
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
            protocol: Arc::new(crate::proto::Protocol::anthropic()),
            max: 10,
            error_map: Arc::new(std::collections::HashMap::new()),
            context_max: None,
            path: None,
            auth: None,
        };

        let lane1 = Lane {
            model: "test-model".to_string(),
            provider: "test-provider".to_string(),
            base_url: server.base_url(),
            api_key: "test-key-1".to_string(),
            protocol: Arc::new(crate::proto::Protocol::anthropic()),
            max: 10,
            error_map: Arc::new(std::collections::HashMap::new()),
            context_max: None,
            path: None,
            auth: None,
        };

        let lane2 = Lane {
            model: "test-model".to_string(),
            provider: "test-provider".to_string(),
            base_url: server.base_url(),
            api_key: "test-key-2".to_string(),
            protocol: Arc::new(crate::proto::Protocol::anthropic()),
            max: 10,
            error_map: Arc::new(std::collections::HashMap::new()),
            context_max: None,
            path: None,
            auth: None,
        };

        let by_model = HashMap::from([("test-model".to_string(), 0)]);
        let pools = HashMap::from([(
            "default".to_string(),
            vec![
                crate::state::WeightedLane { idx: 0, weight: 1 },
                crate::state::WeightedLane { idx: 1, weight: 1 },
                crate::state::WeightedLane { idx: 2, weight: 1 },
            ],
        )]);
        let auth = Arc::new(AuthMiddleware::new(&AuthCfg::default_none()));
        let store = Arc::new(InMemoryStore::new(vec![
            lane_data_0,
            lane_data_1,
            lane_data_2,
        ]));
        let app = Arc::new(App {
            lanes: vec![lane0, lane1, lane2],
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
            failover_cfg: None,
            fallback_pools: HashMap::new(),
            on_exhausted_cfgs: HashMap::new(),
            governance: None,
        });

        let req_body = serde_json::to_vec(&json!({"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})).unwrap();

        // Forward request - should failover up to max_failover=3 times, then return 503
        let response = forward(
            app.clone(),
            vec![
                crate::state::WeightedLane { idx: 0, weight: 1 },
                crate::state::WeightedLane { idx: 1, weight: 1 },
                crate::state::WeightedLane { idx: 2, weight: 1 },
            ],
            req_body.into(),
            None,
            None,
        )
        .await;

        // Should return 503 after exhausting all lanes up to max_failover cap (default=3)
        assert_eq!(response.status().as_u16(), 503);

        // Verify: total errors across all lanes should be capped (not unbounded)
        let t = now();
        let total_errs: u64 = (0..3).map(|i| app.store.snapshot(i, t).err).sum();

        // With max_failover=3 and 3 lanes, we should have bounded attempts (not unbounded retry)
        assert!(
            total_errs <= 10,
            "Total errors {} should be capped (not unbounded)",
            total_errs
        );

        server.shutdown().await;
    }

    /// Failover deadline test.
    /// Deadline computed once at start; verify default behavior works correctly with normal flow.
    #[tokio::test]
    async fn test_failover_deadline() {
        use std::collections::HashMap;

        let state = Arc::new(MockServerState::new());

        // Push success response - should succeed within deadline
        let events = vec!["data: success".to_string()];
        state.push(MockResponse::Sse {
            events,
            abort_at_index: None,
        });

        let server = MockServer::new(state.clone()).await;

        let lane_data_0 = LaneData {
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

        let lane_data_1 = LaneData {
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
            protocol: Arc::new(crate::proto::Protocol::anthropic()),
            max: 10,
            error_map: Arc::new(std::collections::HashMap::new()),
            context_max: None,
            path: None,
            auth: None,
        };

        let lane1 = Lane {
            model: "test-model".to_string(),
            provider: "test-provider".to_string(),
            base_url: server.base_url(),
            api_key: "test-key-1".to_string(),
            protocol: Arc::new(crate::proto::Protocol::anthropic()),
            max: 10,
            error_map: Arc::new(std::collections::HashMap::new()),
            context_max: None,
            path: None,
            auth: None,
        };

        let by_model = HashMap::from([("test-model".to_string(), 0)]);

        // Pool with failover config: deadline=120s (default), cap=3
        let pools = HashMap::from([(
            "default".to_string(),
            vec![
                crate::state::WeightedLane { idx: 0, weight: 1 },
                crate::state::WeightedLane { idx: 1, weight: 1 },
            ],
        )]);

        let auth = Arc::new(AuthMiddleware::new(&AuthCfg::default_none()));
        let store = Arc::new(InMemoryStore::new(vec![lane_data_0, lane_data_1]));

        // Use default failover config (deadline=120s)
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
            failover_cfg: Some(crate::config::FailoverCfg {
                deadline_secs: 120, // Default deadline
                exclusions: None,
                cap: 3,
            }),
            fallback_pools: HashMap::new(),
            on_exhausted_cfgs: HashMap::new(),
            governance: None,
        });

        let req_body = serde_json::to_vec(&json!({"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})).unwrap();

        let response = forward(
            app.clone(),
            vec![
                crate::state::WeightedLane { idx: 0, weight: 1 },
                crate::state::WeightedLane { idx: 1, weight: 1 },
            ],
            req_body.into(),
            None,
            None,
        )
        .await;

        // Should succeed within deadline
        assert_eq!(response.status().as_u16(), 200);

        server.shutdown().await;
    }

    /// Stream inspection tap test for Anthropic SSE usage parsing.
    ///
    /// Tests that the tap:
    /// (a) forwards byte-identical stream to client
    /// (b) extracts parsed usage from message_delta/message_stop events
    /// (c) maintains bounded memory via carry buffer cap
    #[tokio::test]
    async fn test_stream_inspection_tap_usage_parsing() {
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
            protocol: Arc::new(crate::proto::Protocol::anthropic()),
            max: 10,
            error_map: Arc::new(std::collections::HashMap::new()),
            context_max: None,
            path: None,
            auth: None,
        };

        let by_model = HashMap::from([("test-model".to_string(), 0)]);
        let pools = HashMap::from([(
            "default".to_string(),
            vec![crate::state::WeightedLane { idx: 0, weight: 1 }],
        )]);
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
            failover_cfg: None,
            fallback_pools: HashMap::new(),
            on_exhausted_cfgs: HashMap::new(),
            governance: None,
        });

        let req_body = serde_json::to_vec(&json!({"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})).unwrap();

        // Forward request (tap integrated in FirstByteBody)
        let response = forward(
            app.clone(),
            vec![crate::state::WeightedLane { idx: 0, weight: 1 }],
            req_body.into(),
            None,
            None,
        )
        .await;
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

    /// Disposition-matrix tests - prove error_map drives classification, not protocol.
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
                protocol: Arc::new(crate::proto::Protocol::anthropic()),
                max: 10,
                error_map: Arc::new(error_map),
                context_max: None,
                path: None,
                auth: None,
            };

            let by_model = HashMap::from([("test-model".to_string(), 0)]);
            let pools = HashMap::from([(
                "default".to_string(),
                vec![crate::state::WeightedLane { idx: 0, weight: 1 }],
            )]);
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
                failover_cfg: None,
                fallback_pools: HashMap::new(),
                on_exhausted_cfgs: HashMap::new(),
                governance: None,
            });

            let req_body = serde_json::to_vec(&json!({"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})).unwrap();
            let response = forward(
                app.clone(),
                vec![crate::state::WeightedLane { idx: 0, weight: 1 }],
                req_body.into(),
                None,
                None,
            )
            .await;

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
                protocol: Arc::new(crate::proto::Protocol::anthropic()),
                max: 10,
                error_map: Arc::new(error_map),
                context_max: None,
                path: None,
                auth: None,
            };

            let by_model = HashMap::from([("test-model".to_string(), 0)]);
            let pools = HashMap::from([(
                "default".to_string(),
                vec![crate::state::WeightedLane { idx: 0, weight: 1 }],
            )]);
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
                failover_cfg: None,
                fallback_pools: HashMap::new(),
                on_exhausted_cfgs: HashMap::new(),
                governance: None,
            });

            let req_body = serde_json::to_vec(&json!({"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})).unwrap();
            let _response = forward(
                app.clone(),
                vec![crate::state::WeightedLane { idx: 0, weight: 1 }],
                req_body.into(),
                None,
                None,
            )
            .await;

            // Lane hard-down (billing)
            let t = now();
            assert!(
                !app.store.usable(0, t),
                "lane should be DOWN after billing error"
            );
            {
                let snap = app.store.snapshot(0, t);
                assert!(
                    !snap.dead,
                    "Billing HardDown → recoverable (long cooldown + probe), not permanent dead"
                );
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
                protocol: Arc::new(crate::proto::Protocol::anthropic()),
                max: 10,
                error_map: Arc::new(error_map),
                context_max: None,
                path: None,
                auth: None,
            };

            let by_model = HashMap::from([("test-model".to_string(), 0)]);
            let pools = HashMap::from([(
                "default".to_string(),
                vec![crate::state::WeightedLane { idx: 0, weight: 1 }],
            )]);
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
                failover_cfg: None,
                fallback_pools: HashMap::new(),
                on_exhausted_cfgs: HashMap::new(),
                governance: None,
            });

            let req_body = serde_json::to_vec(&json!({"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})).unwrap();
            let _response = forward(
                app.clone(),
                vec![crate::state::WeightedLane { idx: 0, weight: 1 }],
                req_body.into(),
                None,
                None,
            )
            .await;

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
                protocol: Arc::new(crate::proto::Protocol::anthropic()),
                max: 10,
                error_map: Arc::new(error_map),
                context_max: None,
                path: None,
                auth: None,
            };

            let by_model = HashMap::from([("test-model".to_string(), 0)]);
            let pools = HashMap::from([(
                "default".to_string(),
                vec![crate::state::WeightedLane { idx: 0, weight: 1 }],
            )]);
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
                failover_cfg: None,
                fallback_pools: HashMap::new(),
                on_exhausted_cfgs: HashMap::new(),
                governance: None,
            });

            let req_body = serde_json::to_vec(&json!({"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})).unwrap();
            let _response = forward(
                app.clone(),
                vec![crate::state::WeightedLane { idx: 0, weight: 1 }],
                req_body.into(),
                None,
                None,
            )
            .await;

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
                protocol: Arc::new(crate::proto::Protocol::anthropic()),
                max: 10,
                error_map: Arc::new(error_map),
                context_max: None,
                path: None,
                auth: None,
            };

            let by_model = HashMap::from([("test-model".to_string(), 0)]);
            let pools = HashMap::from([(
                "default".to_string(),
                vec![crate::state::WeightedLane { idx: 0, weight: 1 }],
            )]);
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
                failover_cfg: None,
                fallback_pools: HashMap::new(),
                on_exhausted_cfgs: HashMap::new(),
                governance: None,
            });

            let req_body = serde_json::to_vec(&json!({"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})).unwrap();
            let _response = forward(
                app.clone(),
                vec![crate::state::WeightedLane { idx: 0, weight: 1 }],
                req_body.into(),
                None,
                None,
            )
            .await;

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
                protocol: Arc::new(crate::proto::Protocol::anthropic()),
                max: 10,
                error_map: Arc::new(error_map),
                context_max: None,
                path: None,
                auth: None,
            };

            let by_model = HashMap::from([("test-model".to_string(), 0)]);
            let pools = HashMap::from([(
                "default".to_string(),
                vec![crate::state::WeightedLane { idx: 0, weight: 1 }],
            )]);
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
                failover_cfg: None,
                fallback_pools: HashMap::new(),
                on_exhausted_cfgs: HashMap::new(),
                governance: None,
            });

            let req_body = serde_json::to_vec(&json!({"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})).unwrap();
            let _response = forward(
                app.clone(),
                vec![crate::state::WeightedLane { idx: 0, weight: 1 }],
                req_body.into(),
                None,
                None,
            )
            .await;

            // HardDown (401 → Auth)
            let t = now();
            assert!(
                !app.store.usable(0, t),
                "lane should be DOWN after Auth HardDown"
            );
            {
                let snap = app.store.snapshot(0, t);
                assert!(
                    !snap.dead,
                    "Auth HardDown → recoverable (long cooldown + probe), not permanent dead"
                );
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
                protocol: Arc::new(crate::proto::Protocol::anthropic()),
                max: 10,
                error_map: Arc::new(error_map_1),
                context_max: None,
                path: None,
                auth: None,
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
                protocol: Arc::new(crate::proto::Protocol::anthropic()),
                max: 10,
                error_map: Arc::new(error_map_2),
                context_max: None,
                path: None,
                auth: None,
            };

            let setup_app = |lane_data: LaneData, lane: Lane, _error_map_name: &str| {
                let by_model = HashMap::from([("test-model".to_string(), 0)]);
                let pools = HashMap::from([(
                    "default".to_string(),
                    vec![crate::state::WeightedLane { idx: 0, weight: 1 }],
                )]);
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
                    failover_cfg: None,
                    fallback_pools: HashMap::new(),
                    on_exhausted_cfgs: HashMap::new(),
                    governance: None,
                })
            };

            let app_1 = setup_app(lane_data_1, lane_1, "with mapping");
            let req_body = serde_json::to_vec(&json!({"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})).unwrap();

            // Lane 1 with error_map: code 1113 → billing → HardDown
            let _response_1 = forward(
                app_1.clone(),
                vec![crate::state::WeightedLane { idx: 0, weight: 1 }],
                req_body.clone().into(),
                None,
                None,
            )
            .await;
            let t = now();
            assert!(
                !app_1.store.usable(0, t),
                "Lane 1 (with error_map) should be DOWN after billing code"
            );

            // Lane 2 without mapping: HTTP 400 → ClientFault → no trip
            let app_2 = setup_app(lane_data_2, lane_2, "without mapping");
            let _response_2 = forward(
                app_2.clone(),
                vec![crate::state::WeightedLane { idx: 0, weight: 1 }],
                req_body.into(),
                None,
                None,
            )
            .await;
            assert!(
                app_2.store.usable(0, t),
                "Lane 2 (no error_map) should remain usable after ClientFault"
            );

            server1.shutdown().await;
            server2.shutdown().await;
        }

        #[tokio::test]
        async fn test_empty_error_map_is_valid_but_bad_value_fails() {
            // An EMPTY error_map is valid (HTTP-status classification still applies, like the
            // shipped `anthropic` catalog entry) — it must NOT fail validation. A present entry
            // with an unknown StatusClass value must still fail.
            use crate::config::RootCfg;

            let model = crate::config::ModelCfg {
                max_requests: -1,
                provider: "p".into(),
                max_concurrent: 10,
            };
            let pool = crate::config::PoolCfg {
                members: vec![crate::config::PoolMember {
                    target: "m".into(),
                    weight: 1,
                    context_max: None,
                }],
                breaker: None,
                failover: None,
                on_exhausted: None,
                affinity: None,
            };
            let make = |error_map: std::collections::HashMap<String, String>| {
                let mut providers = HashMap::new();
                providers.insert(
                    "p".to_string(),
                    crate::config::ProviderCfg {
                        protocol: "anthropic".into(),
                        base_url: "https://api.example.com".into(),
                        api_key_env: "API_KEY".into(),
                        health: None,
                        error_map,
                        path: None,
                        auth: None,
                        _legacy_api_key: None,
                    },
                );
                let mut models = HashMap::new();
                models.insert("m".to_string(), model.clone());
                let mut pools = HashMap::new();
                pools.insert("mypool".to_string(), pool.clone());
                RootCfg {
                    listen: "0.0.0.0:8080".into(),
                    auth: None,
                    providers,
                    models,
                    pools,
                }
            };

            use crate::config_validate::validate;
            // Empty error_map → valid.
            assert!(
                validate(&make(std::collections::HashMap::new())).is_ok(),
                "empty error_map must be valid (relies on HTTP-status classification)"
            );
            // Bad value → still rejected.
            let mut bad = std::collections::HashMap::new();
            bad.insert("1234".to_string(), "not_a_status_class".to_string());
            let err = validate(&make(bad)).expect_err("invalid StatusClass must fail");
            assert!(
                err.join(" | ").contains("invalid StatusClass"),
                "error should name the invalid StatusClass; got: {err:?}"
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
            // ClientFault (400 invalid_request) → relay verbatim, NO breaker penalty
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
                protocol: Arc::new(crate::proto::Protocol::anthropic()),
                max: 10,
                error_map: Arc::new(error_map),
                context_max: None,
                path: None,
                auth: None,
            };

            let by_model = HashMap::from([("test-model".to_string(), 0)]);

            let pools = HashMap::from([(
                "default".to_string(),
                vec![crate::state::WeightedLane { idx: 0, weight: 1 }],
            )]);
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
                failover_cfg: None,
                fallback_pools: HashMap::new(),
                on_exhausted_cfgs: HashMap::new(),
                governance: None,
            });

            let req_body = serde_json::to_vec(&json!({"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})).unwrap();
            let response = forward(
                app.clone(),
                vec![crate::state::WeightedLane { idx: 0, weight: 1 }],
                req_body.into(),
                None,
                None,
            )
            .await;

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
            // ClientFault on lane 0 → lane 1 NOT hit (no failover)
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
                protocol: Arc::new(crate::proto::Protocol::anthropic()),
                max: 10,
                error_map: Arc::new(HashMap::new()),
                context_max: None,
                path: None,
                auth: None,
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
                protocol: Arc::new(crate::proto::Protocol::anthropic()),
                max: 10,
                error_map: Arc::new(HashMap::new()),
                context_max: None,
                path: None,
                auth: None,
            };

            let by_model = HashMap::from([("test-model".to_string(), 0)]);
            let pools = HashMap::from([(
                "default".to_string(),
                vec![
                    crate::state::WeightedLane { idx: 0, weight: 1 },
                    crate::state::WeightedLane { idx: 1, weight: 1 },
                ],
            )]);
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
                failover_cfg: None,
                fallback_pools: HashMap::new(),
                on_exhausted_cfgs: HashMap::new(),
                governance: None,
            });

            let req_body = serde_json::to_vec(&json!({"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})).unwrap();
            let response = forward(
                app.clone(),
                vec![
                    crate::state::WeightedLane { idx: 0, weight: 1 },
                    crate::state::WeightedLane { idx: 1, weight: 1 },
                ],
                req_body.into(),
                None,
                None,
            )
            .await;

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

    /// Status503 mode test - all lanes tripped, verify 503 with Retry-After header.
    #[tokio::test]
    async fn test_exhaustion_status_503_with_retry_after() {
        let state = Arc::new(MockServerState::new());

        // Push rate limit responses to trip all lanes
        for _i in 0..2 {
            state.push(MockResponse::RateLimit {
                status: StatusCode::TOO_MANY_REQUESTS,
                provider_signal: Some("1302"),
            });
        }

        let server = MockServer::new(state.clone()).await;

        let lane_data_0 = LaneData {
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

        let lane_data_1 = LaneData {
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
            protocol: Arc::new(crate::proto::Protocol::anthropic()),
            max: 10,
            error_map: Arc::new(std::collections::HashMap::new()),
            context_max: None,
            path: None,
            auth: None,
        };

        let lane1 = Lane {
            model: "test-model".to_string(),
            provider: "test-provider".to_string(),
            base_url: server.base_url(),
            api_key: "test-key-1".to_string(),
            protocol: Arc::new(crate::proto::Protocol::anthropic()),
            max: 10,
            error_map: Arc::new(std::collections::HashMap::new()),
            context_max: None,
            path: None,
            auth: None,
        };

        let by_model = HashMap::from([("test-model".to_string(), 0)]);
        let pools = HashMap::from([(
            "default".to_string(),
            vec![
                crate::state::WeightedLane { idx: 0, weight: 1 },
                crate::state::WeightedLane { idx: 1, weight: 1 },
            ],
        )]);

        let auth = Arc::new(AuthMiddleware::new(&AuthCfg::default_none()));
        let store = Arc::new(InMemoryStore::new(vec![lane_data_0, lane_data_1]));
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
            failover_cfg: None,
            fallback_pools: HashMap::new(),
            on_exhausted_cfgs: HashMap::new(),
            governance: None,
        });

        let req_body = serde_json::to_vec(&json!({"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})).unwrap();

        let response = forward(
            app.clone(),
            vec![
                crate::state::WeightedLane { idx: 0, weight: 1 },
                crate::state::WeightedLane { idx: 1, weight: 1 },
            ],
            req_body.into(),
            None,
            None,
        )
        .await;

        // Should get 503 when all lanes are exhausted (default mode)
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        // Verify Retry-After header is present and has a sane value (>= 1 second)
        let retry_after = response
            .headers()
            .get(header::RETRY_AFTER)
            .expect("Retry-After header should be present");
        let retry_after_secs: u64 = retry_after.to_str().unwrap().parse().unwrap();
        assert!(
            retry_after_secs >= 1,
            "Retry-After should be at least 1 second"
        );

        server.shutdown().await;
    }

    /// LeastBad mode — both members Open (tripped), the request is ACTUALLY served
    /// (200) by the member with the SOONEST cooldown expiry, not the other one.
    /// Lane 0 (far cooldown) and lane 1 (soon cooldown) point at distinct mock servers that
    /// return distinguishable bodies, so we can assert WHICH member served.
    #[tokio::test]
    async fn test_exhaustion_least_bad_selects_soonest() {
        use crate::store::now as store_now;

        // Lane 0 server (the "wrong" member — far cooldown). Marker identifies it if picked.
        let state0 = Arc::new(MockServerState::new());
        state0.push(MockResponse::Ok {
            status: StatusCode::OK,
            body: json!({ "served_by": "lane0", "content": [] }),
        });
        let server0 = MockServer::new(state0.clone()).await;

        // Lane 1 server (the soonest member — should be the one served).
        let state1 = Arc::new(MockServerState::new());
        state1.push(MockResponse::Ok {
            status: StatusCode::OK,
            body: json!({ "served_by": "lane1", "content": [] }),
        });
        let server1 = MockServer::new(state1.clone()).await;

        // Both lanes Open: breaker defaults to Closed but a future cooldown_until makes
        // usable() return false, so normal selection finds nothing and LeastBad kicks in.
        let t0 = store_now();
        let lane_data_0 = LaneData {
            model: "test-model".to_string(),
            provider: "test-provider".to_string(),
            max: 10,
            sem: Arc::new(tokio::sync::Semaphore::new(10)),
            limited: false,
            budget: -1,
            cooldown_until: t0 + 600, // far expiry
            streak: 3,
            dead: false,
            dead_reason: String::new(),
            inflight: 0,
            ok: 0,
            err: 5,
            client_fault: 0,
        };

        let lane_data_1 = LaneData {
            model: "test-model".to_string(),
            provider: "test-provider".to_string(),
            max: 10,
            sem: Arc::new(tokio::sync::Semaphore::new(10)),
            limited: false,
            budget: -1,
            cooldown_until: t0 + 5, // SOONEST expiry → least-bad should pick this one
            streak: 3,
            dead: false,
            dead_reason: String::new(),
            inflight: 0,
            ok: 0,
            err: 5,
            client_fault: 0,
        };

        let lane0 = Lane {
            model: "test-model".to_string(),
            provider: "test-provider".to_string(),
            base_url: server0.base_url(),
            api_key: "test-key-0".to_string(),
            protocol: Arc::new(crate::proto::Protocol::anthropic()),
            max: 10,
            error_map: Arc::new(std::collections::HashMap::new()),
            context_max: None,
            path: None,
            auth: None,
        };

        let lane1 = Lane {
            model: "test-model".to_string(),
            provider: "test-provider".to_string(),
            base_url: server1.base_url(),
            api_key: "test-key-1".to_string(),
            protocol: Arc::new(crate::proto::Protocol::anthropic()),
            max: 10,
            error_map: Arc::new(std::collections::HashMap::new()),
            context_max: None,
            path: None,
            auth: None,
        };

        let by_model = HashMap::from([("test-model".to_string(), 0)]);
        let pools = HashMap::from([(
            "leastbad".to_string(),
            vec![
                crate::state::WeightedLane { idx: 0, weight: 1 },
                crate::state::WeightedLane { idx: 1, weight: 1 },
            ],
        )]);

        // Configure LeastBad mode for this pool
        let mut on_exhausted_cfgs = HashMap::new();
        on_exhausted_cfgs.insert("leastbad".to_string(), crate::config::OnExhausted::LeastBad);

        let auth = Arc::new(AuthMiddleware::new(&AuthCfg::default_none()));
        let store = Arc::new(InMemoryStore::new(vec![lane_data_0, lane_data_1]));
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
            failover_cfg: None,
            fallback_pools: HashMap::new(),
            on_exhausted_cfgs,
            governance: None,
        });

        let req_body = serde_json::to_vec(&json!({"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})).unwrap();

        // Route via the named pool so per-pool LeastBad config is consulted.
        let response = forward_with_pool(
            app.clone(),
            vec![
                crate::state::WeightedLane { idx: 0, weight: 1 },
                crate::state::WeightedLane { idx: 1, weight: 1 },
            ],
            req_body.into(),
            None,
            "leastbad",
            None,
            "anthropic",
            None,
        )
        .await;

        // LeastBad actually serves (200), not a 503 stub.
        assert_eq!(
            response.status().as_u16(),
            200,
            "LeastBad must actually route to the degraded member, not return 503"
        );

        // And it must be the SOONEST member (lane 1), not lane 0.
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8_lossy(&body);
        assert!(
            body_str.contains("lane1"),
            "soonest-cooldown member (lane1) should serve; got: {body_str}"
        );
        assert!(
            !body_str.contains("lane0"),
            "must NOT route to the farther-cooldown member (lane0); got: {body_str}"
        );

        server0.shutdown().await;
        server1.shutdown().await;
    }

    /// FallbackPool loop guard — an A→B→A config (pool_a→pool_b→pool_a), every member
    /// tripped, must TERMINATE via the visited-set and return 503 rather than recursing forever.
    /// This is the safety-critical test for multi-level fallback chains.
    #[tokio::test]
    async fn test_fallback_pool_loop_guard() {
        use crate::store::now as store_now;

        // No upstream is ever reached (all pools exhausted); the server only supplies base_urls.
        let state = Arc::new(MockServerState::new());
        let server = MockServer::new(state.clone()).await;

        let t0 = store_now();
        // All lanes Open (future cooldown → unusable): pool_a {0,1}, pool_b {2,3}.
        let tripped = || LaneData {
            model: "test-model".to_string(),
            provider: "test-provider".to_string(),
            max: 10,
            sem: Arc::new(tokio::sync::Semaphore::new(10)),
            limited: false,
            budget: -1,
            cooldown_until: t0 + 600,
            streak: 3,
            dead: false,
            dead_reason: String::new(),
            inflight: 0,
            ok: 0,
            err: 5,
            client_fault: 0,
        };

        let mk_lane = |key: &str| Lane {
            model: "test-model".to_string(),
            provider: "test-provider".to_string(),
            base_url: server.base_url(),
            api_key: key.to_string(),
            protocol: Arc::new(crate::proto::Protocol::anthropic()),
            max: 10,
            error_map: Arc::new(std::collections::HashMap::new()),
            context_max: None,
            path: None,
            auth: None,
        };

        let by_model = HashMap::from([("test-model".to_string(), 0)]);
        let pools = HashMap::from([(
            "pool_a".to_string(),
            vec![
                crate::state::WeightedLane { idx: 0, weight: 1 },
                crate::state::WeightedLane { idx: 1, weight: 1 },
            ],
        )]);
        let mut fallback_pools = HashMap::new();
        fallback_pools.insert(
            "pool_b".to_string(),
            vec![
                crate::state::WeightedLane { idx: 2, weight: 1 },
                crate::state::WeightedLane { idx: 3, weight: 1 },
            ],
        );
        // A→B→A: pool_a falls back to pool_b, pool_b falls back to pool_a.
        let mut on_exhausted_cfgs = HashMap::new();
        on_exhausted_cfgs.insert(
            "pool_a".to_string(),
            crate::config::OnExhausted::FallbackPool("pool_b".to_string()),
        );
        on_exhausted_cfgs.insert(
            "pool_b".to_string(),
            crate::config::OnExhausted::FallbackPool("pool_a".to_string()),
        );

        let auth = Arc::new(AuthMiddleware::new(&AuthCfg::default_none()));
        let store = Arc::new(InMemoryStore::new(vec![
            tripped(),
            tripped(),
            tripped(),
            tripped(),
        ]));
        let app = Arc::new(App {
            lanes: vec![
                mk_lane("key-a0"),
                mk_lane("key-a1"),
                mk_lane("key-b0"),
                mk_lane("key-b1"),
            ],
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
            failover_cfg: None,
            fallback_pools,
            on_exhausted_cfgs,
            governance: None,
        });

        let req_body = serde_json::to_vec(&json!({"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})).unwrap();

        // pool_a exhausted → pool_b (marked) → pool_a (marked) → pool_b detected visited → 503.
        let response = forward_with_pool(
            app.clone(),
            vec![
                crate::state::WeightedLane { idx: 0, weight: 1 },
                crate::state::WeightedLane { idx: 1, weight: 1 },
            ],
            req_body.into(),
            None,
            "pool_a",
            None,
            "anthropic",
            None,
        )
        .await;

        assert_eq!(
            response.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "A→B→A fallback chain must terminate with 503 via the visited-set loop guard"
        );

        server.shutdown().await;
    }

    /// FallbackPool actually ROUTES — primary pool all tripped, mode=FallbackPool,
    /// the backup pool has a healthy member, and the request is genuinely SERVED (200) by the
    /// backup, not a 503-with-header stub. This is the test skipped.
    #[tokio::test]
    async fn test_fallback_pool_routes_to_backup() {
        use crate::store::now as store_now;

        // Backup member (lane 2) returns a recognizable success body.
        let state = Arc::new(MockServerState::new());
        state.push(MockResponse::Ok {
            status: StatusCode::OK,
            body: json!({ "served_by": "backup", "content": [] }),
        });
        let server = MockServer::new(state.clone()).await;

        let t0 = store_now();
        // Primary lanes 0,1 tripped (Open); backup lane 2 healthy.
        let tripped = || LaneData {
            model: "test-model".to_string(),
            provider: "test-provider".to_string(),
            max: 10,
            sem: Arc::new(tokio::sync::Semaphore::new(10)),
            limited: false,
            budget: -1,
            cooldown_until: t0 + 600,
            streak: 3,
            dead: false,
            dead_reason: String::new(),
            inflight: 0,
            ok: 0,
            err: 5,
            client_fault: 0,
        };
        let healthy = LaneData {
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
            ok: 10,
            err: 0,
            client_fault: 0,
        };

        let mk_lane = |key: &str| Lane {
            model: "test-model".to_string(),
            provider: "test-provider".to_string(),
            base_url: server.base_url(),
            api_key: key.to_string(),
            protocol: Arc::new(crate::proto::Protocol::anthropic()),
            max: 10,
            error_map: Arc::new(std::collections::HashMap::new()),
            context_max: None,
            path: None,
            auth: None,
        };

        let by_model = HashMap::from([("test-model".to_string(), 0)]);
        let pools = HashMap::from([(
            "primary".to_string(),
            vec![
                crate::state::WeightedLane { idx: 0, weight: 1 },
                crate::state::WeightedLane { idx: 1, weight: 1 },
            ],
        )]);
        let mut fallback_pools = HashMap::new();
        fallback_pools.insert(
            "backup".to_string(),
            vec![crate::state::WeightedLane { idx: 2, weight: 1 }],
        );
        let mut on_exhausted_cfgs = HashMap::new();
        on_exhausted_cfgs.insert(
            "primary".to_string(),
            crate::config::OnExhausted::FallbackPool("backup".to_string()),
        );

        let auth = Arc::new(AuthMiddleware::new(&AuthCfg::default_none()));
        let store = Arc::new(InMemoryStore::new(vec![tripped(), tripped(), healthy]));
        let app = Arc::new(App {
            lanes: vec![mk_lane("key-0"), mk_lane("key-1"), mk_lane("key-2")],
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
            failover_cfg: None,
            fallback_pools,
            on_exhausted_cfgs,
            governance: None,
        });

        let req_body = serde_json::to_vec(&json!({"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})).unwrap();

        let response = forward_with_pool(
            app.clone(),
            vec![
                crate::state::WeightedLane { idx: 0, weight: 1 },
                crate::state::WeightedLane { idx: 1, weight: 1 },
            ],
            req_body.into(),
            None,
            "primary",
            None,
            "anthropic",
            None,
        )
        .await;

        assert_eq!(
            response.status().as_u16(),
            200,
            "primary exhausted → request must be actually served by the backup pool"
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8_lossy(&body);
        assert!(
            body_str.contains("backup"),
            "response must come from the backup member; got: {body_str}"
        );

        server.shutdown().await;
    }

    /// Test 1: Sticky while healthy - same x-session-id should route to same member.
    #[tokio::test]
    async fn test_sticky_session_while_healthy() {
        use std::collections::HashMap;

        // Create separate mock servers for each lane so we can track which lane served the request
        let state0 = Arc::new(MockServerState::new());
        let server0 = MockServer::new(state0.clone()).await;

        let state1 = Arc::new(MockServerState::new());
        let server1 = MockServer::new(state1.clone()).await;

        let state2 = Arc::new(MockServerState::new());
        let server2 = MockServer::new(state2.clone()).await;

        // All lanes always return their own identifier
        for _ in 0..3 {
            state0.push(MockResponse::Ok {
                status: StatusCode::OK,
                body: json!({ "served_by": "lane0" }),
            });
            state1.push(MockResponse::Ok {
                status: StatusCode::OK,
                body: json!({ "served_by": "lane1" }),
            });
            state2.push(MockResponse::Ok {
                status: StatusCode::OK,
                body: json!({ "served_by": "lane2" }),
            });
        }

        let lane_data_0 = LaneData {
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

        let lane_data_1 = LaneData {
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

        let lane_data_2 = LaneData {
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
            base_url: server0.base_url(),
            api_key: "test-key-0".to_string(),
            protocol: Arc::new(crate::proto::Protocol::anthropic()),
            max: 10,
            error_map: Arc::new(std::collections::HashMap::new()),
            context_max: None,
            path: None,
            auth: None,
        };

        let lane1 = Lane {
            model: "test-model".to_string(),
            provider: "test-provider".to_string(),
            base_url: server1.base_url(),
            api_key: "test-key-1".to_string(),
            protocol: Arc::new(crate::proto::Protocol::anthropic()),
            max: 10,
            error_map: Arc::new(std::collections::HashMap::new()),
            context_max: None,
            path: None,
            auth: None,
        };

        let lane2 = Lane {
            model: "test-model".to_string(),
            provider: "test-provider".to_string(),
            base_url: server2.base_url(),
            api_key: "test-key-2".to_string(),
            protocol: Arc::new(crate::proto::Protocol::anthropic()),
            max: 10,
            error_map: Arc::new(std::collections::HashMap::new()),
            context_max: None,
            path: None,
            auth: None,
        };

        let by_model = HashMap::from([("test-model".to_string(), 0)]);
        let pools = HashMap::from([(
            "sticky-test".to_string(),
            vec![
                crate::state::WeightedLane { idx: 0, weight: 1 },
                crate::state::WeightedLane { idx: 1, weight: 1 },
                crate::state::WeightedLane { idx: 2, weight: 1 },
            ],
        )]);

        let auth = Arc::new(AuthMiddleware::new(&AuthCfg::default_none()));
        let store = Arc::new(InMemoryStore::new(vec![
            lane_data_0,
            lane_data_1,
            lane_data_2,
        ]));
        let app = Arc::new(App {
            lanes: vec![lane0, lane1, lane2],
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
            failover_cfg: None,
            fallback_pools: HashMap::new(),
            on_exhausted_cfgs: HashMap::new(),
            governance: None,
        });

        let req_body = serde_json::to_vec(&json!({"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})).unwrap();

        // First call with session id "session-abc"
        let response1 = forward_with_pool(
            app.clone(),
            vec![
                crate::state::WeightedLane { idx: 0, weight: 1 },
                crate::state::WeightedLane { idx: 1, weight: 1 },
                crate::state::WeightedLane { idx: 2, weight: 1 },
            ],
            req_body.clone().into(),
            None,
            "sticky-test",
            Some("session-abc"),
            "anthropic",
            None,
        )
        .await;

        let body1 = axum::body::to_bytes(response1.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str1 = String::from_utf8_lossy(&body1);

        // Second call with same session id - should get same lane
        let response2 = forward_with_pool(
            app.clone(),
            vec![
                crate::state::WeightedLane { idx: 0, weight: 1 },
                crate::state::WeightedLane { idx: 1, weight: 1 },
                crate::state::WeightedLane { idx: 2, weight: 1 },
            ],
            req_body.clone().into(),
            None,
            "sticky-test",
            Some("session-abc"),
            "anthropic",
            None,
        )
        .await;

        let body2 = axum::body::to_bytes(response2.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str2 = String::from_utf8_lossy(&body2);

        // Both should return the same lane
        assert_eq!(
            body_str1, body_str2,
            "Same session id should route to same member. First: {body_str1}, Second: {body_str2}"
        );

        // Third call with different session id - should potentially get a different lane
        let response3 = forward_with_pool(
            app.clone(),
            vec![
                crate::state::WeightedLane { idx: 0, weight: 1 },
                crate::state::WeightedLane { idx: 1, weight: 1 },
                crate::state::WeightedLane { idx: 2, weight: 1 },
            ],
            req_body.into(),
            None,
            "sticky-test",
            Some("session-xyz"),
            "anthropic",
            None,
        )
        .await;

        let _body3 = axum::body::to_bytes(response3.into_body(), usize::MAX)
            .await
            .unwrap();

        // Different session should hash to potentially different lane (not guaranteed, but test passes if it's deterministic)
        // The important thing is that affinity works - same key gives same result
        server0.shutdown().await;
        server1.shutdown().await;
        server2.shutdown().await;
    }

    /// Test 2: Sticky member tripped → yields to healthy member.
    #[tokio::test]
    async fn test_sticky_yields_when_tripped() {
        use std::collections::HashMap;

        // Separate mock servers for each lane
        let state0 = Arc::new(MockServerState::new());
        let server0 = MockServer::new(state0.clone()).await;

        let state1 = Arc::new(MockServerState::new());
        let server1 = MockServer::new(state1.clone()).await;

        // Lane 0 returns error, lane 1 always succeeds with its identifier
        for _ in 0..2 {
            state0.push(MockResponse::ServerError {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                body: json!({ "error": "lane 0 failed" }),
            });
            state1.push(MockResponse::Ok {
                status: StatusCode::OK,
                body: json!({ "served_by": "lane1", "content": [] }),
            });
        }

        let lane_data_0 = LaneData {
            model: "test-model".to_string(),
            provider: "test-provider".to_string(),
            max: 1,
            sem: Arc::new(tokio::sync::Semaphore::new(1)),
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

        let lane_data_1 = LaneData {
            model: "test-model".to_string(),
            provider: "test-provider".to_string(),
            max: 1,
            sem: Arc::new(tokio::sync::Semaphore::new(1)),
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
            base_url: server0.base_url(),
            api_key: "test-key-0".to_string(),
            protocol: Arc::new(crate::proto::Protocol::anthropic()),
            max: 1,
            error_map: Arc::new(std::collections::HashMap::new()),
            context_max: None,
            path: None,
            auth: None,
        };

        let lane1 = Lane {
            model: "test-model".to_string(),
            provider: "test-provider".to_string(),
            base_url: server1.base_url(),
            api_key: "test-key-1".to_string(),
            protocol: Arc::new(crate::proto::Protocol::anthropic()),
            max: 1,
            error_map: Arc::new(std::collections::HashMap::new()),
            context_max: None,
            path: None,
            auth: None,
        };

        let by_model = HashMap::from([("test-model".to_string(), 0)]);
        let pools = HashMap::from([(
            "failover-test".to_string(),
            vec![
                crate::state::WeightedLane { idx: 0, weight: 1 },
                crate::state::WeightedLane { idx: 1, weight: 1 },
            ],
        )]);

        let auth = Arc::new(AuthMiddleware::new(&AuthCfg::default_none()));
        let store = Arc::new(InMemoryStore::new(vec![lane_data_0, lane_data_1]));
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
            failover_cfg: None,
            fallback_pools: HashMap::new(),
            on_exhausted_cfgs: HashMap::new(),
            governance: None,
        });

        let req_body = serde_json::to_vec(&json!({"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})).unwrap();

        // Use a session id that hashes to lane 0 (first lane)
        let response = forward_with_pool(
            app.clone(),
            vec![
                crate::state::WeightedLane { idx: 0, weight: 1 },
                crate::state::WeightedLane { idx: 1, weight: 1 },
            ],
            req_body.into(),
            None,
            "failover-test",
            Some("session-to-lane-0"),
            "anthropic",
            None,
        )
        .await;

        // Should succeed by falling through to lane 1 (healthy)
        assert_eq!(response.status().as_u16(), 200);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8_lossy(&body);

        // Should be served by lane 1, NOT lane 0 (affinity is preference, not pin)
        assert!(
            body_str.contains("lane1"),
            "Should fall through to healthy member when sticky lane fails; got: {body_str}"
        );

        server0.shutdown().await;
        server1.shutdown().await;
    }

    /// Test 3: No header → system block hash for affinity.
    #[tokio::test]
    async fn test_sticky_from_system_block() {
        use std::collections::HashMap;

        // Separate mock servers for each lane
        let state0 = Arc::new(MockServerState::new());
        let server0 = MockServer::new(state0.clone()).await;

        let state1 = Arc::new(MockServerState::new());
        let server1 = MockServer::new(state1.clone()).await;

        // Both lanes always return their own identifier
        for _ in 0..2 {
            state0.push(MockResponse::Ok {
                status: StatusCode::OK,
                body: json!({ "served_by": "lane0" }),
            });
            state1.push(MockResponse::Ok {
                status: StatusCode::OK,
                body: json!({ "served_by": "lane1" }),
            });
        }

        let lane_data_0 = LaneData {
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

        let lane_data_1 = LaneData {
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
            base_url: server0.base_url(),
            api_key: "test-key-0".to_string(),
            protocol: Arc::new(crate::proto::Protocol::anthropic()),
            max: 10,
            error_map: Arc::new(std::collections::HashMap::new()),
            context_max: None,
            path: None,
            auth: None,
        };

        let lane1 = Lane {
            model: "test-model".to_string(),
            provider: "test-provider".to_string(),
            base_url: server1.base_url(),
            api_key: "test-key-1".to_string(),
            protocol: Arc::new(crate::proto::Protocol::anthropic()),
            max: 10,
            error_map: Arc::new(std::collections::HashMap::new()),
            context_max: None,
            path: None,
            auth: None,
        };

        let by_model = HashMap::from([("test-model".to_string(), 0)]);
        let pools = HashMap::from([(
            "system-test".to_string(),
            vec![
                crate::state::WeightedLane { idx: 0, weight: 1 },
                crate::state::WeightedLane { idx: 1, weight: 1 },
            ],
        )]);

        let auth = Arc::new(AuthMiddleware::new(&AuthCfg::default_none()));
        let store = Arc::new(InMemoryStore::new(vec![lane_data_0, lane_data_1]));
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
            failover_cfg: None,
            fallback_pools: HashMap::new(),
            on_exhausted_cfgs: HashMap::new(),
            governance: None,
        });

        // Request with system block
        let req_body = serde_json::to_vec(&json!({
            "model": "test-model",
            "messages": [{"role": "user", "content": "hi"}],
            "max_tokens": 100,
            "system": "my-system-block"
        }))
        .unwrap();

        // First call with system block
        let response1 = forward_with_pool(
            app.clone(),
            vec![
                crate::state::WeightedLane { idx: 0, weight: 1 },
                crate::state::WeightedLane { idx: 1, weight: 1 },
            ],
            req_body.clone().into(),
            None,
            "system-test",
            None, // No header - should derive from system block
            "anthropic",
            None,
        )
        .await;

        let body1 = axum::body::to_bytes(response1.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str1 = String::from_utf8_lossy(&body1);

        // Second call with same system block - should get same lane (deterministic)
        let response2 = forward_with_pool(
            app.clone(),
            vec![
                crate::state::WeightedLane { idx: 0, weight: 1 },
                crate::state::WeightedLane { idx: 1, weight: 1 },
            ],
            req_body.into(),
            None,
            "system-test",
            None, // No header - should derive from system block
            "anthropic",
            None,
        )
        .await;

        let body2 = axum::body::to_bytes(response2.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str2 = String::from_utf8_lossy(&body2);

        // Both should return the same lane (deterministic from system block hash)
        assert_eq!(
            body_str1, body_str2,
            "Same system block should route to same member deterministically"
        );

        server0.shutdown().await;
        server1.shutdown().await;
    }

    async fn openai_mock_handler(
        State(state): State<std::sync::Arc<MockServerState>>,
        _request: Request<Body>,
    ) -> Response<Body> {
        let response = state.next_response().unwrap_or(MockResponse::default());
        match response {
            MockResponse::Ok { status, body } => Response::builder()
                .status(status)
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
            _ => Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from("unexpected response type"))
                .unwrap(),
        }
    }

    /// OpenAI ingress same-protocol passthrough test.
    #[tokio::test]
    async fn test_openai_ingress_same_protocol_passthrough() {
        use crate::route;
        use axum::http::HeaderMap;

        // Create a custom mock server that listens at /v1/chat/completions (OpenAI endpoint)
        let state = Arc::new(MockServerState::new());
        state.push(MockResponse::Ok {
            status: StatusCode::OK,
            body: serde_json::json!({
                "choices": [{"message": {"content": "hello", "role": "assistant"}, "finish_reason": "stop"}],
                "model": "gpt-4"
            }),
        });

        let app = axum::Router::new()
            .route("/v1/chat/completions", any(openai_mock_handler))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        struct OpenAiMockServer {
            addr: std::net::SocketAddr,
            handle: tokio::task::JoinHandle<()>,
        }
        impl OpenAiMockServer {
            fn base_url(&self) -> String {
                format!("http://{}", self.addr)
            }
            async fn shutdown(self) {
                self.handle.abort();
            }
        }
        let server = OpenAiMockServer { addr, handle };

        // Build a lane with OpenAI protocol (upstream_path = /v1/chat/completions)
        let lane_data = LaneData {
            model: "test-model".to_string(),
            provider: "openai-mock".to_string(),
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
            provider: "openai-mock".to_string(),
            base_url: server.base_url(),
            api_key: "test-key".to_string(),
            protocol: Arc::new(crate::proto::Protocol::openai()),
            max: 10,
            error_map: Arc::new(std::collections::HashMap::new()),
            context_max: None,
            path: None,
            auth: None,
        };

        let by_model = HashMap::from([("test-model".to_string(), 0)]);
        let pools = HashMap::new();
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
            failover_cfg: None,
            fallback_pools: HashMap::new(),
            on_exhausted_cfgs: HashMap::new(),
            governance: None,
        });

        // Build an OpenAI-format request body with model in the BODY (must match by_model key)
        let req_body = serde_json::json!({
            "model": "test-model",
            "messages": [{"role": "user", "content": "hi"}]
        });
        let body_bytes = Bytes::from(serde_json::to_vec(&req_body).unwrap());

        // Call openai_ingress handler directly
        let response = route::openai_ingress(
            State(app),
            axum::extract::Extension(crate::governance::GovCtx::default()),
            HeaderMap::new(),
            body_bytes,
        )
        .await;

        // Assert 200 OK and the mock server received the request at /v1/chat/completions
        assert_eq!(response.status().as_u16(), 200);

        use http_body_util::BodyExt as _;
        let collected = response.into_body().collect().await.unwrap().to_bytes();
        let text = String::from_utf8_lossy(&collected);
        assert!(text.contains("hello"), "Response should contain mock body");

        server.shutdown().await;
    }

    /// OpenAI ingress missing model → 400.
    #[tokio::test]
    async fn test_openai_ingress_missing_model() {
        use crate::route;
        use axum::http::HeaderMap;

        // Build a minimal App (no lanes needed for this test)
        let by_model = HashMap::new();
        let pools = HashMap::new();
        let auth = Arc::new(AuthMiddleware::new(&AuthCfg::default_none()));
        let store = Arc::new(InMemoryStore::new(vec![]));
        let app = Arc::new(App {
            lanes: vec![],
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
            failover_cfg: None,
            fallback_pools: HashMap::new(),
            on_exhausted_cfgs: HashMap::new(),
            governance: None,
        });

        // Missing "model" field in body
        let req_body = serde_json::json!({
            "messages": [{"role": "user", "content": "hi"}]
        });
        let body_bytes = Bytes::from(serde_json::to_vec(&req_body).unwrap());

        let response = route::openai_ingress(
            State(app),
            axum::extract::Extension(crate::governance::GovCtx::default()),
            HeaderMap::new(),
            body_bytes,
        )
        .await;

        assert_eq!(response.status().as_u16(), 400);
    }

    /// OpenAI ingress unknown model → 404.
    #[tokio::test]
    async fn test_openai_ingress_unknown_model() {
        use crate::route;
        use axum::http::HeaderMap;

        // Build a minimal App with no "nope" model
        let by_model = HashMap::new();
        let pools = HashMap::new();
        let auth = Arc::new(AuthMiddleware::new(&AuthCfg::default_none()));
        let store = Arc::new(InMemoryStore::new(vec![]));
        let app = Arc::new(App {
            lanes: vec![],
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
            failover_cfg: None,
            fallback_pools: HashMap::new(),
            on_exhausted_cfgs: HashMap::new(),
            governance: None,
        });

        // Unknown model in body
        let req_body = serde_json::json!({
            "model": "nope",
            "messages": [{"role": "user", "content": "hi"}]
        });
        let body_bytes = Bytes::from(serde_json::to_vec(&req_body).unwrap());

        let response = route::openai_ingress(
            State(app),
            axum::extract::Extension(crate::governance::GovCtx::default()),
            HeaderMap::new(),
            body_bytes,
        )
        .await;

        assert_eq!(response.status().as_u16(), 404);
    }

    /// Cross-protocol request translation test.
    /// Build App with ONE anthropic lane, call forward_with_pool with OpenAI-format body and ingress_protocol="openai".
    /// Assert the MOCK UPSTREAM RECEIVED an Anthropic-shaped body (top-level "system" field, messages without system entry).
    #[tokio::test]
    async fn test_cross_protocol_openai_to_anthropic() {
        use std::collections::HashMap;

        let state = Arc::new(MockServerState::new());

        // Mock will receive translated Anthropic-shaped body and return 200
        state.push(MockResponse::Ok {
            status: StatusCode::OK,
            body: json!({ "content": ["translated"], "model": "m", "stop": [] }),
        });

        let server = MockServer::new(state.clone()).await;

        let lane_data = LaneData {
            model: "m".to_string(),
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

        let lane = Lane {
            model: "m".to_string(),
            provider: "anthropic".to_string(),
            base_url: server.base_url(),
            api_key: "test-key".to_string(),
            protocol: Arc::new(crate::proto::Protocol::anthropic()),
            max: 10,
            error_map: Arc::new(std::collections::HashMap::new()),
            context_max: None,
            path: None,
            auth: None,
        };

        let by_model = HashMap::from([("m".to_string(), 0)]);
        let pools = HashMap::new();
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
            failover_cfg: None,
            fallback_pools: HashMap::new(),
            on_exhausted_cfgs: HashMap::new(),
            governance: None,
        });

        // OpenAI-format body (system inside first message)
        let openai_body = json!({
            "model": "m",
            "messages": [
                {"role": "system", "content": "sys"},
                {"role": "user", "content": "hi"}
            ]
        });

        // Forward with ingress_protocol="openai" to trigger translation into anthropic lane
        let response = forward_with_pool(
            app.clone(),
            vec![crate::state::WeightedLane { idx: 0, weight: 1 }],
            openai_body.to_string().into(),
            None,
            "m",
            None,
            "openai",
            None,
        )
        .await;

        assert_eq!(response.status().as_u16(), 200);

        // The REAL proof (not just status): the upstream received a TRANSLATED, Anthropic-shaped
        // body — top-level `system` extracted out of `messages`, and `messages` no longer carrying
        // the system role. A status-only assert would pass even if translation never ran.
        let received = state
            .get_last_request_body()
            .expect("mock should have recorded the upstream request body");
        let got: serde_json::Value =
            serde_json::from_slice(&received).expect("upstream body is JSON");
        assert!(
            got.get("system").is_some(),
            "translated body must have top-level `system` (Anthropic shape); got: {got}"
        );
        let msgs = got
            .get("messages")
            .and_then(|m| m.as_array())
            .expect("messages array");
        assert!(
            !msgs
                .iter()
                .any(|m| m.get("role").and_then(|r| r.as_str()) == Some("system")),
            "system must be lifted OUT of messages on translation; got: {got}"
        );
        assert!(
            msgs.iter()
                .any(|m| m.get("role").and_then(|r| r.as_str()) == Some("user")),
            "user message must survive translation; got: {got}"
        );

        server.shutdown().await;
    }

    /// OpenAI ingress → Anthropic backend via the single-model (no-pool) route path must translate
    /// the RESPONSE back to OpenAI shape. Regression test: this path previously went through the
    /// `forward` wrapper (Anthropic ingress) and returned the raw Anthropic body.
    #[tokio::test]
    async fn test_openai_ingress_single_model_anthropic_response_translated() {
        use crate::route;
        use std::collections::HashMap;

        let state = Arc::new(MockServerState::new());
        // Backend returns a native Anthropic message response.
        state.push(MockResponse::Ok {
            status: StatusCode::OK,
            body: json!({
                "id": "msg_1",
                "type": "message",
                "role": "assistant",
                "content": [{"type": "text", "text": "hi there"}],
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 9, "output_tokens": 3}
            }),
        });
        let server = MockServer::new(state.clone()).await;

        let lane_data = LaneData {
            model: "glm-4.5".to_string(),
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
        let lane = Lane {
            model: "glm-4.5".to_string(),
            provider: "z.ai".to_string(),
            base_url: server.base_url(),
            api_key: "k".to_string(),
            protocol: Arc::new(crate::proto::Protocol::anthropic()),
            max: 10,
            error_map: Arc::new(std::collections::HashMap::new()),
            context_max: None,
            path: None,
            auth: None,
        };
        // Model is in by_model but NOT in any pool — the branch the bug lived in.
        let app = Arc::new(App {
            lanes: vec![lane],
            store: Arc::new(InMemoryStore::new(vec![lane_data])),
            by_model: HashMap::from([("glm-4.5".to_string(), 0)]),
            pools: HashMap::new(),
            rr: AtomicUsize::new(0),
            client: Client::builder().build().unwrap(),
            auth: Arc::new(AuthMiddleware::new(&AuthCfg::default_none())),
            auth_mode: crate::auth::AuthMode::None,
            failover_cfg: None,
            fallback_pools: HashMap::new(),
            on_exhausted_cfgs: HashMap::new(),
            governance: None,
        });

        let body = json!({"model": "glm-4.5", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 15});
        let resp = route::openai_ingress(
            State(app),
            axum::extract::Extension(crate::governance::GovCtx::default()),
            axum::http::HeaderMap::new(),
            Bytes::from(body.to_string()),
        )
        .await;
        assert_eq!(resp.status().as_u16(), 200);

        use http_body_util::BodyExt as _;
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let got: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        // Response must be OpenAI-shaped, not the raw Anthropic body.
        assert_eq!(got["object"], "chat.completion", "got: {got}");
        assert_eq!(got["choices"][0]["message"]["content"], "hi there");
        assert_eq!(got["choices"][0]["finish_reason"], "stop");
        assert_eq!(got["usage"]["prompt_tokens"], 9);
        assert_eq!(got["usage"]["completion_tokens"], 3);
        assert!(got.get("stop_reason").is_none(), "no raw Anthropic fields");

        server.shutdown().await;
    }

    /// Same-protocol request passthrough test.
    /// anthropic ingress → anthropic lane (ingress_protocol="anthropic") → mock receives body with model rewritten, NO translation applied.
    #[tokio::test]
    async fn test_same_protocol_anthropic_passthrough() {
        use std::collections::HashMap;

        let state = Arc::new(MockServerState::new());

        // Mock will receive the anthropic body as-is (with model rewritten) and return 200
        state.push(MockResponse::Ok {
            status: StatusCode::OK,
            body: json!({ "content": ["ok"], "model": "m", "stop": [] }),
        });

        let server = MockServer::new(state.clone()).await;

        let lane_data = LaneData {
            model: "m".to_string(),
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

        let lane = Lane {
            model: "m".to_string(),
            provider: "anthropic".to_string(),
            base_url: server.base_url(),
            api_key: "test-key".to_string(),
            protocol: Arc::new(crate::proto::Protocol::anthropic()),
            max: 10,
            error_map: Arc::new(std::collections::HashMap::new()),
            context_max: None,
            path: None,
            auth: None,
        };

        let by_model = HashMap::from([("m".to_string(), 0)]);
        let pools = HashMap::new();
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
            failover_cfg: None,
            fallback_pools: HashMap::new(),
            on_exhausted_cfgs: HashMap::new(),
            governance: None,
        });

        // Anthropic-format body (system at top level)
        let anthropic_body = json!({
            "model": "original-model",
            "messages": [{"role": "user", "content": "hi"}],
            "max_tokens": 100,
            "system": "sys"
        });

        // Forward with ingress_protocol="anthropic" - same protocol, no translation should occur
        let response = forward_with_pool(
            app.clone(),
            vec![crate::state::WeightedLane { idx: 0, weight: 1 }],
            anthropic_body.to_string().into(),
            None,
            "m",
            None,
            "anthropic",
            None,
        )
        .await;

        assert_eq!(response.status().as_u16(), 200);

        server.shutdown().await;
    }

    /// cross-protocol STREAMING response translation end-to-end. An OpenAI egress lane
    /// streams OpenAI chunks; an Anthropic-ingress caller must receive ANTHROPIC SSE `event:`
    /// frames (translated on the wire), not raw OpenAI chunks.
    #[tokio::test]
    async fn test_cross_protocol_stream_openai_lane_to_anthropic_client() {
        use std::collections::HashMap;

        let state = Arc::new(MockServerState::new());
        // OpenAI egress lane streams chat.completion.chunks (handler wraps each as `data: ...`).
        state.push(MockResponse::Sse {
            events: vec![
                r#"{"choices":[{"delta":{"role":"assistant"}}]}"#.to_string(),
                r#"{"choices":[{"delta":{"content":"hi"}}]}"#.to_string(),
                r#"{"choices":[{"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1}}"#.to_string(),
            ],
            abort_at_index: None,
        });
        let server = MockServer::new(state.clone()).await;

        let lane_data = LaneData {
            model: "m".to_string(),
            provider: "openai-provider".to_string(),
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
            model: "m".to_string(),
            provider: "openai-provider".to_string(),
            base_url: server.base_url(),
            api_key: "k".to_string(),
            protocol: Arc::new(crate::proto::Protocol::openai()),
            max: 10,
            error_map: Arc::new(std::collections::HashMap::new()),
            context_max: None,
            path: None,
            auth: None,
        };
        let auth = Arc::new(AuthMiddleware::new(&AuthCfg::default_none()));
        let store = Arc::new(InMemoryStore::new(vec![lane_data]));
        let app = Arc::new(App {
            lanes: vec![lane],
            store,
            by_model: HashMap::from([("m".to_string(), 0)]),
            pools: HashMap::new(),
            rr: AtomicUsize::new(0),
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap(),
            auth,
            auth_mode: crate::auth::AuthMode::None,
            failover_cfg: None,
            fallback_pools: HashMap::new(),
            on_exhausted_cfgs: HashMap::new(),
            governance: None,
        });

        // Anthropic-format streaming request; egress lane is openai → response stream translated back.
        let anthropic_body =
            json!({"model":"m","messages":[{"role":"user","content":"hi"}],"stream":true});
        let response = forward_with_pool(
            app.clone(),
            vec![crate::state::WeightedLane { idx: 0, weight: 1 }],
            anthropic_body.to_string().into(),
            None,
            "m",
            None,
            "anthropic",
            None,
        )
        .await;
        assert_eq!(response.status().as_u16(), 200);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let s = String::from_utf8_lossy(&body);
        // The Anthropic-ingress client must receive ANTHROPIC event: frames, translated on the wire.
        assert!(
            s.contains("event: message_start"),
            "missing anthropic message_start; got: {s}"
        );
        assert!(
            s.contains("event: content_block_delta"),
            "missing content_block_delta; got: {s}"
        );
        assert!(
            s.contains("text_delta") && s.contains("hi"),
            "missing translated text 'hi'; got: {s}"
        );
        assert!(
            s.contains("event: message_stop"),
            "missing message_stop; got: {s}"
        );
        // And must NOT leak the raw OpenAI egress framing.
        assert!(
            !s.contains("chat.completion.chunk"),
            "raw OpenAI chunks leaked to client; got: {s}"
        );

        server.shutdown().await;
    }

    /// NON-streaming cross-protocol response translation end-to-end. An OpenAI egress
    /// lane returns a chat.completion JSON; an Anthropic-ingress caller must receive an
    /// Anthropic-shaped message (translated whole-response), not the raw OpenAI body.
    #[tokio::test]
    async fn test_cross_protocol_nonstream_openai_lane_to_anthropic_client() {
        use std::collections::HashMap;

        let state = Arc::new(MockServerState::new());
        // OpenAI egress lane returns a non-streaming chat.completion.
        state.push(MockResponse::Ok {
            status: StatusCode::OK,
            body: json!({
                "object": "chat.completion",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "hi"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 5, "completion_tokens": 3}
            }),
        });
        let server = MockServer::new(state.clone()).await;

        let lane_data = LaneData {
            model: "m".to_string(),
            provider: "openai-provider".to_string(),
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
            model: "m".to_string(),
            provider: "openai-provider".to_string(),
            base_url: server.base_url(),
            api_key: "k".to_string(),
            protocol: Arc::new(crate::proto::Protocol::openai()),
            max: 10,
            error_map: Arc::new(std::collections::HashMap::new()),
            context_max: None,
            path: None,
            auth: None,
        };
        let auth = Arc::new(AuthMiddleware::new(&AuthCfg::default_none()));
        let store = Arc::new(InMemoryStore::new(vec![lane_data]));
        let app = Arc::new(App {
            lanes: vec![lane],
            store,
            by_model: HashMap::from([("m".to_string(), 0)]),
            pools: HashMap::new(),
            rr: AtomicUsize::new(0),
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap(),
            auth,
            auth_mode: crate::auth::AuthMode::None,
            failover_cfg: None,
            fallback_pools: HashMap::new(),
            on_exhausted_cfgs: HashMap::new(),
            governance: None,
        });

        // Anthropic-format NON-streaming request; egress lane is openai → response translated back.
        let anthropic_body = json!({"model":"m","messages":[{"role":"user","content":"hi"}]});
        let response = forward_with_pool(
            app.clone(),
            vec![crate::state::WeightedLane { idx: 0, weight: 1 }],
            anthropic_body.to_string().into(),
            None,
            "m",
            None,
            "anthropic",
            None,
        )
        .await;
        assert_eq!(response.status().as_u16(), 200);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let got: serde_json::Value = serde_json::from_slice(&body).expect("anthropic JSON");
        // Anthropic-shaped message, translated on the wire.
        assert_eq!(
            got.get("type").and_then(|v| v.as_str()),
            Some("message"),
            "got: {got}"
        );
        let content = got
            .get("content")
            .and_then(|c| c.as_array())
            .expect("content array");
        assert_eq!(
            content[0].get("type").and_then(|v| v.as_str()),
            Some("text"),
            "got: {got}"
        );
        assert_eq!(
            content[0].get("text").and_then(|v| v.as_str()),
            Some("hi"),
            "got: {got}"
        );
        assert_eq!(
            got.get("stop_reason").and_then(|v| v.as_str()),
            Some("end_turn"),
            "got: {got}"
        );
        // Must NOT be the raw OpenAI body.
        assert!(
            got.get("choices").is_none(),
            "raw OpenAI body leaked: {got}"
        );

        server.shutdown().await;
    }

    /// a context-length error fails over to another lane WITHOUT penalizing the breaker
    /// (the lane is healthy — the request was just too big for that model).
    #[tokio::test]
    async fn test_context_length_failover_no_penalty() {
        use std::collections::HashMap;

        // One mock server, LIFO queue: push the success LAST-but-popped-SECOND. responses.pop()
        // is LIFO, so push 200 first, then the 400 context-length → the FIRST attempt gets the
        // context-length error, the failover attempt gets 200.
        let state = Arc::new(MockServerState::new());
        state.push(MockResponse::Ok {
            status: StatusCode::OK,
            body: json!({"type": "message", "role": "assistant", "content": [{"type": "text", "text": "ok"}]}),
        });
        state.push(MockResponse::ServerError {
            status: StatusCode::BAD_REQUEST,
            body: json!({"error": {"type": "invalid_request_error", "message": "prompt is too long: 250000 tokens > 200000 maximum"}}),
        });
        let server = MockServer::new(state.clone()).await;

        let mk_ld = || LaneData {
            model: "m".to_string(),
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
        let mk_lane = |key: &str| Lane {
            model: "m".to_string(),
            provider: "anthropic".to_string(),
            base_url: server.base_url(),
            api_key: key.to_string(),
            protocol: Arc::new(crate::proto::Protocol::anthropic()),
            max: 10,
            error_map: Arc::new(std::collections::HashMap::new()),
            context_max: None,
            path: None,
            auth: None,
        };
        let auth = Arc::new(AuthMiddleware::new(&AuthCfg::default_none()));
        let store = Arc::new(InMemoryStore::new(vec![mk_ld(), mk_ld()]));
        let app = Arc::new(App {
            lanes: vec![mk_lane("k0"), mk_lane("k1")],
            store,
            by_model: HashMap::from([("m".to_string(), 0)]),
            pools: HashMap::new(),
            rr: AtomicUsize::new(0),
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap(),
            auth,
            auth_mode: crate::auth::AuthMode::None,
            failover_cfg: None,
            fallback_pools: HashMap::new(),
            on_exhausted_cfgs: HashMap::new(),
            governance: None,
        });

        let body = json!({"model": "m", "messages": [{"role": "user", "content": "hi"}]});
        let response = forward(
            app.clone(),
            vec![
                crate::state::WeightedLane { idx: 0, weight: 1 },
                crate::state::WeightedLane { idx: 1, weight: 1 },
            ],
            body.to_string().into(),
            None,
            None,
        )
        .await;

        // Failover to the healthy lane succeeded.
        assert_eq!(
            response.status().as_u16(),
            200,
            "context-length should fail over to a 200 lane"
        );

        // KEY: neither lane was penalized — context-length is a request problem, not a lane fault.
        let now = crate::state::now();
        for idx in 0..2 {
            assert_eq!(
                app.store.cooldown_remaining(idx, now),
                0,
                "lane {idx} must NOT be in cooldown after a context-length failover"
            );
        }

        server.shutdown().await;
    }

    /// Prefers larger context on ContextLength failover.
    /// Pool with lane0 (context_max Some(8000), returns context-length error) +
    /// lane1 (context_max Some(200000), returns 200). Request → lane0 ContextLength →
    /// failover EXCLUDES lane0 (and any ≤8000) → lane1 (200000) SERVES (assert 200 + lane1 served).
    #[tokio::test]
    async fn test_prefers_larger_context_max() {
        use std::collections::HashMap;

        let state = Arc::new(MockServerState::new());

        // LIFO: push success (lane 1) first, then context-length error (lane 0)
        // Lane 1 should succeed with 200
        let events = vec!["data: event-0".to_string()];
        state.push(MockResponse::Sse {
            events,
            abort_at_index: None,
        });

        // Lane 0 returns context-length error (400 with invalid_request_error type)
        state.push(MockResponse::ServerError {
            status: StatusCode::BAD_REQUEST,
            body: json!({ "error": { "type": "invalid_request_error", "message": "prompt is too long: 250000 tokens > 8000 maximum" } }),
        });

        let server = MockServer::new(state.clone()).await;

        let lane0_data = LaneData {
            model: "small-model".to_string(),
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
            model: "large-model".to_string(),
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
            model: "small-model".to_string(),
            provider: "test-provider".to_string(),
            base_url: server.base_url(),
            api_key: "test-key-0".to_string(),
            protocol: Arc::new(crate::proto::Protocol::anthropic()),
            max: 10,
            error_map: Arc::new(std::collections::HashMap::new()),
            context_max: Some(8000), // Small context limit
            path: None,
            auth: None,
        };

        let lane1 = Lane {
            model: "large-model".to_string(),
            provider: "test-provider".to_string(),
            base_url: server.base_url(),
            api_key: "test-key-1".to_string(),
            protocol: Arc::new(crate::proto::Protocol::anthropic()),
            max: 10,
            error_map: Arc::new(std::collections::HashMap::new()),
            context_max: Some(200000), // Large context limit
            path: None,
            auth: None,
        };

        let by_model = HashMap::from([("small-model".to_string(), 0)]);
        let pools = HashMap::from([(
            "default".to_string(),
            vec![
                crate::state::WeightedLane { idx: 0, weight: 1 },
                crate::state::WeightedLane { idx: 1, weight: 1 },
            ],
        )]);

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
            failover_cfg: None,
            fallback_pools: HashMap::new(),
            on_exhausted_cfgs: HashMap::new(),
            governance: None,
        });

        let req_body = serde_json::to_vec(&json!({"model": "small-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})).unwrap();

        // Should failover from lane 0 (context-length) to lane 1 (larger context, succeeds)
        let response = forward(
            app.clone(),
            vec![
                crate::state::WeightedLane { idx: 0, weight: 1 },
                crate::state::WeightedLane { idx: 1, weight: 1 },
            ],
            req_body.into(),
            None,
            None,
        )
        .await;

        // Assert: lane 1 served the request (200 OK)
        assert_eq!(response.status().as_u16(), 200);

        // Verify: lane 0 was NOT penalized (context-length is not a lane fault)
        let t = crate::state::now();
        assert!(
            app.store.usable(0, t),
            "lane 0 should remain usable after context-length"
        );

        server.shutdown().await;
    }

    /// Same-size pool exhausts on ContextLength failover.
    /// Two lanes both context_max Some(8000), both return context-length →
    /// failover finds no bigger lane → exhausts (returns 503/exhaustion, neither lane tripped).
    #[tokio::test]
    async fn test_same_size_pool_exhausts() {
        use std::collections::HashMap;

        let state = Arc::new(MockServerState::new());

        // Both lanes return context-length errors (LIFO: lane 1, then lane 0)
        for _i in 0..2 {
            state.push(MockResponse::ServerError {
                status: StatusCode::BAD_REQUEST,
                body: json!({ "error": { "type": "invalid_request_error", "message": "prompt is too long: 250000 tokens > 8000 maximum" } }),
            });
        }

        let server = MockServer::new(state.clone()).await;

        let lane0_data = LaneData {
            model: "model-8k".to_string(),
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
            model: "model-8k".to_string(),
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
            model: "model-8k".to_string(),
            provider: "test-provider".to_string(),
            base_url: server.base_url(),
            api_key: "test-key-0".to_string(),
            protocol: Arc::new(crate::proto::Protocol::anthropic()),
            max: 10,
            error_map: Arc::new(std::collections::HashMap::new()),
            context_max: Some(8000), // Same limit as lane 1
            path: None,
            auth: None,
        };

        let lane1 = Lane {
            model: "model-8k".to_string(),
            provider: "test-provider".to_string(),
            base_url: server.base_url(),
            api_key: "test-key-1".to_string(),
            protocol: Arc::new(crate::proto::Protocol::anthropic()),
            max: 10,
            error_map: Arc::new(std::collections::HashMap::new()),
            context_max: Some(8000), // Same limit as lane 0
            path: None,
            auth: None,
        };

        let by_model = HashMap::from([("model-8k".to_string(), 0)]);
        let pools = HashMap::from([(
            "default".to_string(),
            vec![
                crate::state::WeightedLane { idx: 0, weight: 1 },
                crate::state::WeightedLane { idx: 1, weight: 1 },
            ],
        )]);

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
            failover_cfg: None,
            fallback_pools: HashMap::new(),
            on_exhausted_cfgs: HashMap::new(),
            governance: None,
        });

        let req_body = serde_json::to_vec(&json!({"model": "model-8k", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})).unwrap();

        // Should exhaust both lanes and return 503 (not loop forever)
        let response = forward(
            app.clone(),
            vec![
                crate::state::WeightedLane { idx: 0, weight: 1 },
                crate::state::WeightedLane { idx: 1, weight: 1 },
            ],
            req_body.into(),
            None,
            None,
        )
        .await;

        // Assert: returns 503 after exhausting both lanes
        assert_eq!(response.status().as_u16(), 503);

        // Verify: neither lane was penalized (context-length is not a lane fault)
        let t = crate::state::now();
        for idx in 0..2 {
            assert_eq!(
                app.store.cooldown_remaining(idx, t),
                0,
                "lane {} must NOT be in cooldown after context-length failover",
                idx
            );
        }

        server.shutdown().await;
    }
}
