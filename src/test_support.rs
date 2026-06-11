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
        /// When set, the mock emits a `Retry-After: <n>` response header (whole seconds).
        retry_after: Option<u64>,
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
    /// A non-2xx error that ALSO carries arbitrary response headers (e.g. a native Bedrock error's
    /// `x-amzn-requestid` + `x-amzn-errortype`), so a test can assert the proxy relays them verbatim.
    ServerErrorWithHeaders {
        status: StatusCode,
        body: Value,
        headers: Vec<(&'static str, &'static str)>,
    },
    Sse {
        events: Vec<String>,
        abort_at_index: Option<usize>,
    },
    /// A TRUE mid-stream transport failure: emit `ok_events` real SSE frames, then make the body
    /// stream yield an `Err`, aborting the connection mid-body (NOT a clean SSE `event: error` text
    /// frame, which `Sse{abort_at_index}` emits). The downstream client sees a reqwest transport
    /// error, exercising `FirstByteBody`'s `Poll::Ready(Some(Err))` arm — the path that appends the
    /// ingress protocol's native mid-stream error (a binary exception frame for bedrock ingress, an
    /// SSE error frame for SSE ingress) AFTER the already-sent real frames.
    SseTransportError {
        ok_events: Vec<String>,
    },
    /// A native AWS binary event-stream body (`application/vnd.amazon.eventstream`), as a real
    /// Bedrock ConverseStream backend emits it. `frames` is the ordered `(event_type, json_payload)`
    /// sequence (messageStart / contentBlockDelta / messageStop / metadata, …); each is encoded with
    /// `crate::eventstream::encode_frame` so the bytes carry real prelude/message CRC32s an AWS SDK
    /// validates. `amzn_request_id` is served as the `x-amzn-RequestId` response header — the value a
    /// same-protocol bedrock passthrough must forward VERBATIM rather than synthesizing a fresh UUID.
    /// Exercises the same-protocol bedrock-stream branch (verbatim binary relay, eventstream CT
    /// preservation, upstream-request-id passthrough) that the SSE/`text/event-stream` variants cannot
    /// reach.
    EventStream {
        frames: Vec<(&'static str, Vec<u8>)>,
        amzn_request_id: &'static str,
    },
    /// The BINARY-stream twin of `SseTransportError`: a TRUE mid-stream transport failure on a native
    /// AWS `application/vnd.amazon.eventstream` body. Emits `ok_frames` real CRC-valid binary frames
    /// (each encoded via `crate::eventstream::encode_frame`), then PAUSES so the proxy reliably reads
    /// and forwards the first byte to the client (crossing the after-first-byte failover boundary),
    /// THEN makes the body stream yield an `Err`, aborting the connection mid-binary-body. reqwest
    /// surfaces this as a transport error to the proxy's `FirstByteBody`, exercising the
    /// `Poll::Ready(Some(Err))` arm on a SAME-PROTOCOL bedrock→bedrock passthrough (upstream CT is
    /// `application/vnd.amazon.eventstream`, so `is_sse` is true and `ingress_eventstream` is true).
    /// The proxy must therefore append a CRC-valid BINARY `:message-type: exception` frame — NOT SSE
    /// `event:`/`data:` ASCII text spliced into the binary body. `amzn_request_id` is served as the
    /// `x-amzn-RequestId` header, as a native ConverseStream backend always does.
    EventStreamTransportError {
        ok_frames: Vec<(&'static str, Vec<u8>)>,
        amzn_request_id: &'static str,
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
    last_request_headers: std::sync::Mutex<Option<axum::http::HeaderMap>>,
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

    /// Record the full set of request headers the upstream received (for indistinguishability
    /// assertions — e.g. that a health probe sends the same User-Agent/Accept as organic traffic).
    pub(crate) fn record_request_headers(&self, headers: &axum::http::HeaderMap) {
        *self.last_request_headers.lock().unwrap() = Some(headers.clone());
    }

    /// Get a single request header value the upstream received, by name (case-insensitive).
    pub(crate) fn get_last_request_header(&self, name: &str) -> Option<String> {
        self.last_request_headers
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|h| h.get(name))
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
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
            // Serve EVERY other upstream path through the same handler so backends whose writer
            // builds a model-scoped path (Bedrock `/model/{model}/converse[-stream]`, Gemini
            // `/v1beta/models/...`, Cohere `/v2/chat`) reach the queued mock response instead of a
            // 404. The queued `MockResponse` already encodes the protocol-specific body shape, so a
            // catch-all route is sufficient and keeps the named routes above for clarity.
            .fallback(any(mock_handler))
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

    // Record the full header set the upstream received (indistinguishability assertions).
    state.record_request_headers(&parts.headers);

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
            retry_after,
        } => {
            let msg = if provider_signal == Some("1302") {
                "rate_limit"
            } else {
                "Rate limit exceeded"
            };
            let body = serde_json::json!({ "error": { "message": msg, "code": provider_signal.unwrap_or("429") } });
            let mut rb = Response::builder()
                .status(status)
                .header(header::CONTENT_TYPE, "application/json");
            if let Some(ra) = retry_after {
                rb = rb.header(header::RETRY_AFTER, ra.to_string());
            }
            rb.body(Body::from(body.to_string())).unwrap()
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
        MockResponse::ServerErrorWithHeaders {
            status,
            body,
            headers,
        } => {
            let mut rb = Response::builder()
                .status(status)
                .header(header::CONTENT_TYPE, "application/json");
            for (k, v) in headers {
                rb = rb.header(k, v);
            }
            rb.body(Body::from(body.to_string())).unwrap()
        }
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
                result.push("data: [DONE]\n\n".to_string());
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
        MockResponse::SseTransportError { ok_events } => {
            // Emit the real frames, PAUSE so the proxy reliably reads + forwards the first byte to the
            // client (crossing the after-first-byte failover boundary), THEN yield a stream Err so the
            // connection aborts mid-body. The `io::Error` item type makes `Body::from_stream`
            // propagate a transport failure (not a clean EOF), which reqwest surfaces as a transport
            // error to the proxy's `FirstByteBody`. Without the pause, on fast localhost the error can
            // race ahead of the first byte and trip pre-first-byte failover (a 503) instead.
            // step: 0..ok_events.len() emit a real frame; the final step sleeps then errors; then end.
            let frames: Vec<Bytes> = ok_events
                .into_iter()
                .map(|d| Bytes::from(format!("data: {d}\n\n")))
                .collect();
            let s = stream::unfold((0usize, frames), |(i, frames)| async move {
                if i < frames.len() {
                    let item = Ok::<Bytes, std::io::Error>(frames[i].clone());
                    Some((item, (i + 1, frames)))
                } else if i == frames.len() {
                    // Pause so the proxy forwards the first byte before the error arrives.
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    let item = Err(std::io::Error::other("mid-stream connection drop"));
                    Some((item, (i + 1, frames)))
                } else {
                    None
                }
            });
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "text/event-stream")
                .body(Body::from_stream(s))
                .unwrap()
        }
        MockResponse::EventStream {
            frames,
            amzn_request_id,
        } => {
            // Encode each (event_type, payload) into a CRC-valid binary AWS event-stream frame and
            // concatenate — the exact byte layout a native Bedrock ConverseStream backend returns. The
            // `x-amzn-RequestId` header carries the upstream's REAL request id; a same-protocol bedrock
            // passthrough must relay this verbatim (never re-synthesize a fresh UUID).
            let mut bytes: Vec<u8> = Vec::new();
            for (event_type, payload) in &frames {
                bytes.extend(crate::eventstream::encode_frame(event_type, payload));
            }
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/vnd.amazon.eventstream")
                .header("x-amzn-requestid", amzn_request_id)
                .body(Body::from(bytes))
                .unwrap()
        }
        MockResponse::EventStreamTransportError {
            ok_frames,
            amzn_request_id,
        } => {
            // Encode each (event_type, payload) into a CRC-valid binary AWS event-stream frame, then
            // PAUSE and yield a stream `Err` so the connection aborts mid-binary-body — the binary
            // counterpart of `SseTransportError`. The pause lets the proxy forward the first byte
            // (crossing the after-first-byte boundary) before the error races in; on fast localhost
            // an immediate error can otherwise trip pre-first-byte failover (a 503) instead.
            let frames: Vec<Bytes> = ok_frames
                .into_iter()
                .map(|(event_type, payload)| {
                    Bytes::from(crate::eventstream::encode_frame(event_type, &payload))
                })
                .collect();
            let s = stream::unfold((0usize, frames), |(i, frames)| async move {
                if i < frames.len() {
                    let item = Ok::<Bytes, std::io::Error>(frames[i].clone());
                    Some((item, (i + 1, frames)))
                } else if i == frames.len() {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    let item = Err(std::io::Error::other("mid-stream connection drop"));
                    Some((item, (i + 1, frames)))
                } else {
                    None
                }
            });
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/vnd.amazon.eventstream")
                .header("x-amzn-requestid", amzn_request_id)
                .body(Body::from_stream(s))
                .unwrap()
        }
    }
}

// ───────────────────────── test fixtures ─────────────────────────
// One `LaneSpec` describes a lane and emits BOTH its `Lane` (routing/health view) and its
// `LaneData` (breaker/permit view), so the two can't drift. `TestApp` collects lanes + optional
// pools/auth/governance and builds an `Arc<App>` with the in-memory store wired up — replacing the
// ~20-field `Lane`/`LaneData`/`App` literals every test used to hand-roll. Defaults match the
// common case; chainable setters override only what a test cares about. Adding a field to
// `Lane`/`LaneData`/`App` is now a one-line change in `to_lane`/`to_lane_data`/`build`.
//
// `allow(dead_code)`: this is a test DSL — not every setter is exercised by every revision of the
// suite; keeping the full, symmetric builder surface is intentional.
#[allow(dead_code)]
pub(crate) struct LaneSpec {
    model: String,
    provider: String,
    base_url: String,
    protocol: std::sync::Arc<crate::proto::Protocol>,
    max: usize,
    api_key: String,
    error_map: std::collections::HashMap<String, String>,
    context_max: Option<usize>,
    path: Option<String>,
    auth: Option<String>,
    health: Option<crate::config::HealthCfg>,
    default_max_tokens: Option<u32>,
    // LaneData-only runtime state (defaults = a fresh, healthy, unlimited lane):
    limited: bool,
    budget: i64,
    cooldown_until: u64,
    streak: u32,
    dead: bool,
    dead_reason: String,
    ok: u64,
    err: u64,
    client_fault: u64,
    /// Optional shared semaphore override. When set, `to_lane_data` reuses this handle instead of
    /// constructing a fresh one, so a test can hold a clone and observe permit acquisition/release.
    sem: Option<std::sync::Arc<tokio::sync::Semaphore>>,
}

#[allow(dead_code)]
impl LaneSpec {
    pub(crate) fn new(model: &str, protocol: crate::proto::Protocol, base_url: &str) -> Self {
        Self {
            model: model.into(),
            provider: "test-provider".into(),
            base_url: base_url.into(),
            protocol: std::sync::Arc::new(protocol),
            max: 10,
            api_key: "k".into(),
            error_map: std::collections::HashMap::new(),
            context_max: None,
            path: None,
            auth: None,
            health: None,
            default_max_tokens: None,
            limited: false,
            budget: -1,
            cooldown_until: 0,
            streak: 0,
            dead: false,
            dead_reason: String::new(),
            ok: 0,
            err: 0,
            client_fault: 0,
            sem: None,
        }
    }
    pub(crate) fn provider(mut self, p: &str) -> Self {
        self.provider = p.into();
        self
    }
    pub(crate) fn max(mut self, n: usize) -> Self {
        self.max = n;
        self
    }
    pub(crate) fn api_key(mut self, k: &str) -> Self {
        self.api_key = k.into();
        self
    }
    pub(crate) fn error_map(mut self, m: std::collections::HashMap<String, String>) -> Self {
        self.error_map = m;
        self
    }
    pub(crate) fn context_max(mut self, n: usize) -> Self {
        self.context_max = Some(n);
        self
    }
    pub(crate) fn path(mut self, p: &str) -> Self {
        self.path = Some(p.into());
        self
    }
    pub(crate) fn auth(mut self, a: &str) -> Self {
        self.auth = Some(a.into());
        self
    }
    pub(crate) fn health(mut self, h: crate::config::HealthCfg) -> Self {
        self.health = Some(h);
        self
    }
    pub(crate) fn default_max_tokens(mut self, n: u32) -> Self {
        self.default_max_tokens = Some(n);
        self
    }
    /// Mark the lane as budget-limited with `n` remaining requests (sets `limited = true`).
    pub(crate) fn budget(mut self, n: i64) -> Self {
        self.limited = true;
        self.budget = n;
        self
    }
    pub(crate) fn cooldown_until(mut self, t: u64) -> Self {
        self.cooldown_until = t;
        self
    }
    pub(crate) fn streak(mut self, n: u32) -> Self {
        self.streak = n;
        self
    }
    pub(crate) fn dead(mut self, reason: &str) -> Self {
        self.dead = true;
        self.dead_reason = reason.into();
        self
    }
    pub(crate) fn ok(mut self, n: u64) -> Self {
        self.ok = n;
        self
    }
    pub(crate) fn err(mut self, n: u64) -> Self {
        self.err = n;
        self
    }
    /// Override the lane's permit semaphore with a shared handle the test retains, so it can
    /// observe permit acquisition/release across the request lifetime.
    pub(crate) fn sem(mut self, sem: std::sync::Arc<tokio::sync::Semaphore>) -> Self {
        self.sem = Some(sem);
        self
    }

    fn to_lane(&self) -> crate::state::Lane {
        crate::state::Lane {
            model: self.model.clone(),
            provider: self.provider.clone(),
            base_url: self.base_url.clone(),
            api_key: self.api_key.clone(),
            protocol: self.protocol.clone(),
            max: self.max,
            error_map: std::sync::Arc::new(self.error_map.clone()),
            context_max: self.context_max,
            path: self.path.clone(),
            auth: self.auth.clone(),
            health: self.health.clone(),
            default_max_tokens: self.default_max_tokens,
        }
    }
    fn to_lane_data(&self) -> crate::store::LaneData {
        crate::store::LaneData {
            model: self.model.clone(),
            provider: self.provider.clone(),
            max: self.max,
            sem: self
                .sem
                .clone()
                .unwrap_or_else(|| std::sync::Arc::new(tokio::sync::Semaphore::new(self.max))),
            limited: self.limited,
            budget: self.budget,
            cooldown_until: self.cooldown_until,
            streak: self.streak,
            dead: self.dead,
            dead_reason: self.dead_reason.clone(),
            ok: self.ok,
            err: self.err,
            client_fault: self.client_fault,
        }
    }
}

#[allow(dead_code)]
pub(crate) struct TestApp {
    lanes: Vec<LaneSpec>,
    pools: std::collections::HashMap<String, Vec<crate::state::WeightedLane>>,
    auth: Option<std::sync::Arc<crate::auth::AuthMiddleware>>,
    governance: Option<std::sync::Arc<crate::governance::GovState>>,
    failover_cfg: Option<crate::config::FailoverCfg>,
    pool_runtime: std::collections::HashMap<String, crate::state::PoolRuntime>,
    fallback_pools: std::collections::HashMap<String, Vec<crate::state::WeightedLane>>,
    on_exhausted_cfgs: std::collections::HashMap<String, crate::config::OnExhausted>,
}

#[allow(dead_code)]
impl TestApp {
    pub(crate) fn new() -> Self {
        Self {
            lanes: Vec::new(),
            pools: std::collections::HashMap::new(),
            auth: None,
            governance: None,
            failover_cfg: None,
            pool_runtime: std::collections::HashMap::new(),
            fallback_pools: std::collections::HashMap::new(),
            on_exhausted_cfgs: std::collections::HashMap::new(),
        }
    }
    pub(crate) fn lane(mut self, spec: LaneSpec) -> Self {
        self.lanes.push(spec);
        self
    }
    /// Define a pool over lane indices: `members` is `(lane_index, weight)` pairs.
    pub(crate) fn pool(mut self, name: &str, members: &[(usize, u32)]) -> Self {
        self.pools.insert(name.into(), weighted(members));
        self
    }
    /// Set the auth mode by installing an `AuthMiddleware` configured for that mode (empty
    /// `client_tokens`). The middleware is now the SINGLE source of the mode (see `App::auth_mode`),
    /// so this drives BOTH the ingress gate and egress credential selection — matching production,
    /// where the two are always the same value. Tests that need a specific `client_tokens` allowlist
    /// (token-mode ingress) should use `.auth(...)` with an explicit middleware instead; calling both
    /// is last-wins.
    pub(crate) fn auth_mode(mut self, m: crate::auth::AuthMode) -> Self {
        // Struct-update from `default_none()` (mode none, empty client_tokens) so we only override
        // `mode` and never name the deprecated `_legacy_token` field.
        let cfg = crate::config::AuthCfg {
            mode: m.as_config_str().to_string(),
            ..crate::config::AuthCfg::default_none()
        };
        self.auth = Some(std::sync::Arc::new(crate::auth::AuthMiddleware::new(&cfg)));
        self
    }
    pub(crate) fn auth(mut self, a: std::sync::Arc<crate::auth::AuthMiddleware>) -> Self {
        self.auth = Some(a);
        self
    }
    pub(crate) fn governance(mut self, g: std::sync::Arc<crate::governance::GovState>) -> Self {
        self.governance = Some(g);
        self
    }
    pub(crate) fn failover(mut self, f: crate::config::FailoverCfg) -> Self {
        self.failover_cfg = Some(f);
        self
    }
    pub(crate) fn pool_runtime(mut self, name: &str, rt: crate::state::PoolRuntime) -> Self {
        self.pool_runtime.insert(name.into(), rt);
        self
    }
    pub(crate) fn fallback_pool(mut self, name: &str, members: &[(usize, u32)]) -> Self {
        self.fallback_pools.insert(name.into(), weighted(members));
        self
    }
    pub(crate) fn on_exhausted(mut self, name: &str, oe: crate::config::OnExhausted) -> Self {
        self.on_exhausted_cfgs.insert(name.into(), oe);
        self
    }
    pub(crate) fn build(self) -> std::sync::Arc<crate::state::App> {
        let mut by_model = std::collections::HashMap::new();
        let mut lanes = Vec::with_capacity(self.lanes.len());
        let mut lane_data = Vec::with_capacity(self.lanes.len());
        for (i, spec) in self.lanes.iter().enumerate() {
            by_model.insert(spec.model.clone(), i);
            lanes.push(spec.to_lane());
            lane_data.push(spec.to_lane_data());
        }
        let auth = self.auth.unwrap_or_else(|| {
            std::sync::Arc::new(crate::auth::AuthMiddleware::new(
                &crate::config::AuthCfg::default_none(),
            ))
        });
        std::sync::Arc::new(crate::state::App {
            lanes,
            store: std::sync::Arc::new(crate::store::InMemoryStore::new(lane_data)),
            by_model,
            pools: self.pools,
            client: reqwest::Client::builder().build().unwrap(),
            auth,
            failover_cfg: self.failover_cfg,
            pool_runtime: self.pool_runtime,
            fallback_pools: self.fallback_pools,
            on_exhausted_cfgs: self.on_exhausted_cfgs,
            governance: self.governance,
        })
    }
}

fn weighted(members: &[(usize, u32)]) -> Vec<crate::state::WeightedLane> {
    members
        .iter()
        .map(|&(idx, weight)| crate::state::WeightedLane { idx, weight })
        .collect()
}

#[allow(deprecated)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AuthMiddleware;
    use crate::config::AuthCfg;
    use crate::forward::{forward, forward_with_pool};
    use crate::state::now;

    use reqwest::Client;
    use serde_json::json;
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
            retry_after: None,
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

        let app = TestApp::new()
            .lane(LaneSpec::new(
                "test-model",
                crate::proto::Protocol::anthropic(),
                &server.base_url(),
            ))
            .pool("default", &[(0, 1)])
            .build();

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

        // Lane speaks the OpenAI protocol; ingress below is Anthropic → cross-protocol translation.
        let app = TestApp::new()
            .lane(
                LaneSpec::new(
                    "glm-4.5",
                    crate::proto::Protocol::openai(),
                    &server.base_url(),
                )
                .provider("zai"),
            )
            .pool("pa", &[(0, 1)])
            .build();

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

        let app = TestApp::new()
            .lane(
                LaneSpec::new(
                    "glm-4.5",
                    crate::proto::Protocol::openai(),
                    &server.base_url(),
                )
                .provider("zai"),
            )
            .pool("pa", &[(0, 1)])
            .governance(gov)
            .build();

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

    /// Regression: token usage from a cross-protocol STREAMING response must be charged to the
    /// virtual key, so TPM limits enforce on streams too. The streaming path records tokens through
    /// a completely separate code path from the non-stream test above: `FirstByteBody`'s stream-end
    /// handler taps `UsageTap` and calls `UsageSink`'s `gov.record_tokens` on clean 2xx completion
    /// (forward.rs:1341-1344), NOT the buffered `record_nonstream_usage`. A regression that broke the
    /// stream-end charge (the drop/poll handler not firing, the sink not wired into the streaming
    /// branch) would leave streaming token usage uncharged and TPM would silently stop enforcing for
    /// streams — the non-stream test gives no coverage because the paths are disjoint. After the first
    /// stream fully drains (160 tokens charged), a second request in the same window is rejected (429).
    #[tokio::test]
    async fn test_cross_protocol_stream_records_tokens_for_tpm() {
        use crate::governance::{GovState, SqliteStore, Store, VirtualKey};
        crate::metrics::init();

        // OpenAI-protocol SSE stream whose final chunk carries usage totalling 160 tokens
        // (prompt 100 + completion 60). The OpenAI reader decodes bare `data:`-framed chunks the
        // mock emits; the trailing-usage chunk is where `UsageTap` reads prompt/completion tokens.
        let stream_events = || -> Vec<String> {
            vec![
                r#"{"choices":[{"delta":{"role":"assistant"}}]}"#.to_string(),
                r#"{"choices":[{"delta":{"content":"Hello there friend"}}]}"#.to_string(),
                r#"{"choices":[{"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":100,"completion_tokens":60}}"#.to_string(),
            ]
        };

        let state = Arc::new(MockServerState::new());
        for _ in 0..2 {
            state.push(MockResponse::Sse {
                events: stream_events(),
                abort_at_index: None,
            });
        }
        let server = MockServer::new(state.clone()).await;

        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let secret = "sk-vk-tpm-stream";
        store
            .put_key(&VirtualKey {
                id: "ktpmstream".to_string(),
                key_hash: crate::sigv4::sha256_hex(secret.as_bytes()),
                name: "tpm-stream".to_string(),
                allowed_pools: vec!["pas".to_string()],
                max_budget_cents: None,
                budget_period: "total".to_string(),
                rpm_limit: Some(100), // high, so RPM doesn't interfere — TPM is what we exercise
                tpm_limit: Some(30),
                enabled: true,
                created_at: 0,
            })
            .unwrap();
        let gov = Arc::new(GovState::new(store, 0, 0, None).unwrap());

        // Lane speaks OpenAI; ingress below is Anthropic streaming → cross-protocol SSE reframe.
        let app = TestApp::new()
            .lane(
                LaneSpec::new(
                    "glm-4.5",
                    crate::proto::Protocol::openai(),
                    &server.base_url(),
                )
                .provider("zai"),
            )
            .pool("pas", &[(0, 1)])
            .governance(gov)
            .build();

        let router = crate::build_router(app);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client = reqwest::Client::new();
        let url = format!("http://{addr}/pas/v1/messages");
        let req = json!({"model": "pas", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 50, "stream": true}).to_string();

        // First request: tokens-so-far is 0 (< 30) → admitted. The stream must be FULLY DRAINED so
        // `FirstByteBody`'s stream-end handler fires and charges the 160 tokens via the UsageSink.
        let r1 = client
            .post(&url)
            .bearer_auth(secret)
            .body(req.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(
            r1.status().as_u16(),
            200,
            "first streaming request is under TPM"
        );
        let b1 = r1.bytes().await.unwrap();
        assert!(
            !b1.is_empty(),
            "first stream must yield a non-empty SSE body that drains to completion; got empty"
        );

        // Second request in the same 60s window: prior tokens (160) now exceed TPM 30 → 429. This
        // proves the STREAM-end UsageSink charge landed (was the risk: streaming tokens stayed 0).
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
            "stream-recorded tokens must make TPM enforce on the next request (streaming charge path)"
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

        // limited lane: max_requests=2 lifetime cap (sets limited=true, budget=2).
        let app = TestApp::new()
            .lane(
                LaneSpec::new(
                    "glm-4.6",
                    crate::proto::Protocol::anthropic(),
                    &server.base_url(),
                )
                .provider("z")
                .budget(2),
            )
            .pool("pc", &[(0, 1)])
            .build();

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

    /// Regression: a pool's `failover.exclusions` must actually exclude the named member from the
    /// candidate set. Two backends (alpha, beta) in one pool; beta excluded → every response must
    /// come from alpha. Without the wiring, smooth weighted round-robin would return beta ~half
    /// the time.
    #[tokio::test]
    async fn test_failover_exclusions_remove_member_from_pool() {
        crate::metrics::init();
        let mk_server = |model: &'static str| async move {
            let state = Arc::new(MockServerState::new());
            for _ in 0..6 {
                state.push(MockResponse::Ok {
                    status: StatusCode::OK,
                    body: json!({
                        "role": "assistant",
                        "content": [{"type": "text", "text": "hi"}],
                        "model": model,
                        "stop_reason": "end_turn",
                        "usage": {"input_tokens": 1, "output_tokens": 1}
                    }),
                });
            }
            MockServer::new(state).await
        };
        let server_a = mk_server("alpha").await;
        let server_b = mk_server("beta").await;

        let app = TestApp::new()
            .lane(
                LaneSpec::new(
                    "alpha",
                    crate::proto::Protocol::anthropic(),
                    &server_a.base_url(),
                )
                .provider("p"),
            )
            .lane(
                LaneSpec::new(
                    "beta",
                    crate::proto::Protocol::anthropic(),
                    &server_b.base_url(),
                )
                .provider("p"),
            )
            .pool("pe", &[(0, 1), (1, 1)])
            .pool_runtime(
                "pe",
                crate::state::PoolRuntime {
                    failover: Some(crate::config::FailoverCfg {
                        deadline_secs: 120,
                        exclusions: Some(vec!["beta".to_string()]),
                        cap: 3,
                    }),
                    affinity: None,
                    breaker: None,
                },
            )
            .build();

        let cands = vec![
            crate::state::WeightedLane { idx: 0, weight: 1 },
            crate::state::WeightedLane { idx: 1, weight: 1 },
        ];
        let body = serde_json::to_vec(
            &json!({"model": "pe", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 10}),
        )
        .unwrap();

        use http_body_util::BodyExt as _;
        for n in 0..5 {
            let resp = forward_with_pool(
                app.clone(),
                cands.clone(),
                body.clone().into(),
                None,
                "pe",
                None,
                "anthropic",
                None,
            )
            .await;
            assert_eq!(resp.status().as_u16(), 200, "request {n}");
            let bytes = resp.into_body().collect().await.unwrap().to_bytes();
            let v: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(
                v["model"], "alpha",
                "excluded member 'beta' must never serve; request {n} got {v}"
            );
        }
        // beta was excluded → it served nothing.
        assert_eq!(
            app.store.snapshot(1, now()).ok,
            0,
            "excluded lane must have 0 successes"
        );
        server_a.shutdown().await;
        server_b.shutdown().await;
    }

    /// GET /metrics through the REAL router (route table + auth middleware) in `auth.mode=none`
    /// (open relay) returns the Prometheus exposition without a bearer token — `/metrics` is NOT
    /// auth-exempt; it is admitted here only because the mode is None, where `validate_token`
    /// returns `true` unconditionally. The sole always-open route is `/healthz` (auth.rs:331-333).
    /// The companion test `test_metrics_requires_auth_in_token_mode` asserts that a missing-token
    /// request to `/metrics` at `auth.mode=token` is rejected (401), covering the security fix that
    /// supersedes the 0.16.2 note describing `/metrics` as intentionally open.
    #[tokio::test]
    async fn test_metrics_admitted_in_open_relay_mode() {
        crate::metrics::init();
        metrics::counter!(crate::metrics::REQUESTS_TOTAL, "outcome" => "ok").increment(1);

        let app = TestApp::new().build();

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

    /// Companion to `test_metrics_admitted_in_open_relay_mode`: in `auth.mode=token`, a GET
    /// /metrics with NO bearer token is rejected with 401 — `/metrics` is auth-gated, NOT exempt
    /// like `/healthz`. This guards the [Unreleased] security fix that made `/metrics` auth-gated
    /// (superseding the 0.16.2 review note that described it as intentionally open): a regression
    /// that re-added `/metrics` to the always-open allowlist alongside `/healthz` (auth.rs:331-333)
    /// would let this unauthenticated scrape through and fail here. The same request WITH the
    /// configured token is admitted (200), proving the gate is token-based, not a blanket block.
    #[tokio::test]
    async fn test_metrics_requires_auth_in_token_mode() {
        crate::metrics::init();
        metrics::counter!(crate::metrics::REQUESTS_TOTAL, "outcome" => "ok").increment(1);

        let token = "sk-metrics-scrape";
        let auth_cfg = crate::config::AuthCfg {
            mode: "token".to_string(),
            client_tokens: vec![token.to_string()],
            _legacy_token: None,
        };
        let app = TestApp::new()
            .auth(Arc::new(AuthMiddleware::new(&auth_cfg)))
            .build();

        let router = crate::build_router(app);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let client = reqwest::Client::new();
        let url = format!("http://{addr}/metrics");

        // No bearer token in token mode → /metrics is auth-gated, so the middleware rejects (401).
        let unauthed = client
            .get(&url)
            .send()
            .await
            .expect("GET /metrics no token");
        assert_eq!(
            unauthed.status().as_u16(),
            401,
            "/metrics must require auth in token mode; a 200 means it was re-exempted like /healthz"
        );

        // With the configured token, the scrape is admitted (200) — the gate is token-based.
        let authed = client
            .get(&url)
            .bearer_auth(token)
            .send()
            .await
            .expect("GET /metrics with token");
        assert_eq!(
            authed.status().as_u16(),
            200,
            "/metrics with the configured token must be admitted"
        );
        let body = authed.text().await.unwrap();
        assert!(
            body.contains(crate::metrics::REQUESTS_TOTAL),
            "authed exposition should contain a metric; got:\n{body}"
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

        let app = TestApp::new().governance(gov).build();

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

    /// a virtual key over its budget is rejected (429 for body/Anthropic ingress) before forwarding.
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
        store.add_usage("kb", 0, 250, 0, true).unwrap();
        let gov = Arc::new(GovState::new(store, 1, 0, None).unwrap());

        let app = TestApp::new().governance(gov).build();

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
            429,
            "over-budget key → 429 (native quota status; no vendor returns 402 here)"
        );
        // The rejection must carry the NATIVE Anthropic error envelope with the CANONICAL quota
        // `error.type` ("insufficient_quota"), not merely the right status code. A regression that
        // reverted the budget kind to the non-canonical `billing_error` token (which the writers pass
        // through verbatim) would still be a 429 but would emit an `error.type` an SDK's typed
        // exception mapping does not recognize — a router-side tell this assertion guards.
        assert_eq!(
            r.headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|h| h.to_str().ok()),
            Some("application/json"),
            "budget rejection is application/json"
        );
        let body: serde_json::Value = r.json().await.unwrap();
        assert_eq!(
            body.get("type").and_then(|t| t.as_str()),
            Some("error"),
            "anthropic over-budget envelope has top-level type:error; got {body}"
        );
        assert_eq!(
            body.get("error")
                .and_then(|e| e.get("type"))
                .and_then(|t| t.as_str()),
            Some("insufficient_quota"),
            "anthropic over-budget carries canonical insufficient_quota error.type; got {body}"
        );

        handle.abort();
    }

    /// Build a router whose ONLY virtual key is already over its (total-window) budget, so every
    /// request is rejected with a 402 by `budget_check` before any forwarding. Returns the bound
    /// address, the serve handle, and the secret to present. Shared by the per-protocol 402
    /// envelope tests below: the rejection fires before resolution, so no lane/pool/backend is
    /// needed — only a parseable body that carries `model` where the protocol expects it.
    async fn over_budget_router() -> (
        std::net::SocketAddr,
        tokio::task::JoinHandle<()>,
        &'static str,
    ) {
        use crate::governance::{GovState, SqliteStore, Store, VirtualKey};

        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let secret = "sk-vk-broke-multi";
        store
            .put_key(&VirtualKey {
                id: "kbm".to_string(),
                key_hash: crate::sigv4::sha256_hex(secret.as_bytes()),
                name: "broke-multi".to_string(),
                allowed_pools: vec![], // all pools
                max_budget_cents: Some(100),
                budget_period: "total".to_string(),
                rpm_limit: None,
                tpm_limit: None,
                enabled: true,
                created_at: 0,
            })
            .unwrap();
        store.add_usage("kbm", 0, 250, 0, true).unwrap();
        let gov = Arc::new(GovState::new(store, 1, 0, None).unwrap());

        let app = TestApp::new().governance(gov).build();
        let router = crate::build_router(app);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        (addr, handle, secret)
    }

    /// OpenAI ingress (`/v1/chat/completions`): an over-budget 402 must carry the native OpenAI error
    /// envelope (`error.type == "insufficient_quota"`).
    #[tokio::test]
    async fn test_budget_402_openai_envelope() {
        crate::metrics::init();
        let (addr, handle, secret) = over_budget_router().await;

        let r = reqwest::Client::new()
            .post(format!("http://{addr}/v1/chat/completions"))
            .bearer_auth(secret)
            .body(json!({"model": "anything", "messages": []}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 429, "openai over-budget → 429");
        assert_eq!(
            r.headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|h| h.to_str().ok()),
            Some("application/json"),
        );
        let body: serde_json::Value = r.json().await.unwrap();
        assert_eq!(
            body.get("error")
                .and_then(|e| e.get("type"))
                .and_then(|t| t.as_str()),
            Some("insufficient_quota"),
            "openai 402 carries insufficient_quota error.type; got {body}"
        );
        handle.abort();
    }

    /// Responses ingress (`/v1/responses`): an over-budget 402 must carry the native Responses error
    /// envelope (`error.type == "insufficient_quota"`).
    #[tokio::test]
    async fn test_budget_402_responses_envelope() {
        crate::metrics::init();
        let (addr, handle, secret) = over_budget_router().await;

        let r = reqwest::Client::new()
            .post(format!("http://{addr}/v1/responses"))
            .bearer_auth(secret)
            .body(json!({"model": "anything", "input": "hi"}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 429, "responses over-budget → 429");
        let body: serde_json::Value = r.json().await.unwrap();
        assert_eq!(
            body.get("error")
                .and_then(|e| e.get("type"))
                .and_then(|t| t.as_str()),
            Some("insufficient_quota"),
            "responses over-budget carries insufficient_quota error.type; got {body}"
        );
        assert_eq!(
            body.get("error")
                .and_then(|e| e.get("code"))
                .and_then(|c| c.as_str()),
            Some("insufficient_quota"),
            "responses over-budget carries populated code=insufficient_quota (not null); got {body}"
        );
        handle.abort();
    }

    /// Cohere ingress (`/v2/chat`): an over-budget 402 must carry the native Cohere error envelope —
    /// a BARE top-level `message` with NO `error`/`type` wrapper.
    #[tokio::test]
    async fn test_budget_402_cohere_envelope() {
        crate::metrics::init();
        let (addr, handle, secret) = over_budget_router().await;

        let r = reqwest::Client::new()
            .post(format!("http://{addr}/v2/chat"))
            .bearer_auth(secret)
            .body(json!({"model": "anything", "messages": []}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 429, "cohere over-budget → 429");
        let body: serde_json::Value = r.json().await.unwrap();
        assert!(
            body.get("message").and_then(|m| m.as_str()).is_some(),
            "cohere 402 envelope carries a bare top-level message; got {body}"
        );
        assert!(
            body.get("error").is_none() && body.get("type").is_none(),
            "cohere 402 envelope has NO error/type wrapper (native Cohere shape); got {body}"
        );
        handle.abort();
    }

    /// Gemini ingress (`/v1beta/models/x:generateContent`): an over-budget rejection must carry the
    /// native Gemini quota envelope — `error.code == 429` and `error.status == "RESOURCE_EXHAUSTED"`
    /// (the canonical quota shape; the old 402 yielded a mismatched INVALID_ARGUMENT status).
    #[tokio::test]
    async fn test_budget_402_gemini_envelope() {
        crate::metrics::init();
        let (addr, handle, secret) = over_budget_router().await;

        let r = reqwest::Client::new()
            .post(format!(
                "http://{addr}/v1beta/models/anything:generateContent"
            ))
            .bearer_auth(secret)
            .body(json!({"contents": []}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 429, "gemini over-budget → 429");
        let body: serde_json::Value = r.json().await.unwrap();
        assert_eq!(
            body.get("error")
                .and_then(|e| e.get("code"))
                .and_then(|c| c.as_u64()),
            Some(429),
            "gemini over-budget envelope carries error.code == 429; got {body}"
        );
        assert_eq!(
            body.get("error")
                .and_then(|e| e.get("status"))
                .and_then(|s| s.as_str()),
            Some("RESOURCE_EXHAUSTED"),
            "gemini over-budget envelope carries the native RESOURCE_EXHAUSTED status; got {body}"
        );
        handle.abort();
    }

    /// Bedrock ingress (`/model/x/converse`): an over-budget rejection must carry the native AWS
    /// JSON-1.1 error envelope (`__type == "ServiceQuotaExceededException"`) at a 400-class status
    /// (the native AWS shape for ServiceQuotaExceededException — NOT 429/402) AND the
    /// `x-amzn-errortype` / `x-amzn-RequestId` headers a native Bedrock runtime response carries.
    #[tokio::test]
    async fn test_budget_402_bedrock_envelope() {
        crate::metrics::init();
        let (addr, handle, secret) = over_budget_router().await;

        let r = reqwest::Client::new()
            .post(format!("http://{addr}/model/anything/converse"))
            .bearer_auth(secret)
            .body(json!({"messages": []}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 400, "bedrock over-budget → 400");
        // Headers: a native Bedrock error always carries x-amzn-RequestId and x-amzn-errortype.
        let errortype_hdr = r
            .headers()
            .get("x-amzn-errortype")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string());
        assert_eq!(
            errortype_hdr.as_deref(),
            Some("ServiceQuotaExceededException"),
            "bedrock over-budget carries x-amzn-errortype header matching __type"
        );
        assert!(
            r.headers().get("x-amzn-requestid").is_some(),
            "bedrock over-budget carries an x-amzn-RequestId header"
        );
        let body: serde_json::Value = r.json().await.unwrap();
        assert_eq!(
            body.get("__type").and_then(|t| t.as_str()),
            Some("ServiceQuotaExceededException"),
            "bedrock over-budget envelope carries __type == ServiceQuotaExceededException; got {body}"
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

        let app = TestApp::new().governance(gov).build();

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

    /// Build a router whose ONLY virtual key has `rpm_limit: Some(0)`, so EVERY request is
    /// rate-limited (429) by `rate_check` before any forwarding (`check_rate` rejects on the first
    /// request when `requests >= rpm` with `rpm == 0`). Returns the bound address, the serve handle,
    /// and the secret to present. The 429 mirror of `over_budget_router`: shared by the per-protocol
    /// `test_rate_limit_429_*_native_envelope` tests below — the rejection fires before resolution, so
    /// no lane/pool/backend is needed, only a parseable body that carries `model` where the protocol
    /// expects it. `allowed_pools: vec![]` admits every pool so the ACL never short-circuits the rate
    /// gate.
    async fn over_rpm_router() -> (
        std::net::SocketAddr,
        tokio::task::JoinHandle<()>,
        &'static str,
    ) {
        use crate::governance::{GovState, SqliteStore, Store, VirtualKey};

        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let secret = "sk-vk-rl-multi";
        store
            .put_key(&VirtualKey {
                id: "krlm".to_string(),
                key_hash: crate::sigv4::sha256_hex(secret.as_bytes()),
                name: "rl-multi".to_string(),
                allowed_pools: vec![], // all pools
                max_budget_cents: None,
                budget_period: "total".to_string(),
                rpm_limit: Some(0), // 0 ⇒ rate-limited on the first request
                tpm_limit: None,
                enabled: true,
                created_at: 0,
            })
            .unwrap();
        let gov = Arc::new(GovState::new(store, 0, 0, None).unwrap());

        let app = TestApp::new().governance(gov).build();
        let router = crate::build_router(app);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        (addr, handle, secret)
    }

    /// OpenAI ingress (`/v1/chat/completions`): an over-RPM 429 must carry the native OpenAI error
    /// envelope (`error.type == "rate_limit_error"`) and the `Retry-After` header.
    #[tokio::test]
    async fn test_rate_limit_429_openai_native_envelope() {
        crate::metrics::init();
        let (addr, handle, secret) = over_rpm_router().await;

        let r = reqwest::Client::new()
            .post(format!("http://{addr}/v1/chat/completions"))
            .bearer_auth(secret)
            .body(json!({"model": "anything", "messages": []}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 429, "openai over-RPM → 429");
        assert_eq!(
            r.headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|h| h.to_str().ok()),
            Some("application/json"),
            "429 rejection is application/json",
        );
        assert!(
            r.headers().get(reqwest::header::RETRY_AFTER).is_some(),
            "openai 429 carries Retry-After"
        );
        let body: serde_json::Value = r.json().await.unwrap();
        assert_eq!(
            body.get("error")
                .and_then(|e| e.get("type"))
                .and_then(|t| t.as_str()),
            Some("rate_limit_error"),
            "openai 429 carries rate_limit_error error.type; got {body}"
        );
        handle.abort();
    }

    /// Responses ingress (`/v1/responses`): an over-RPM 429 must carry the native Responses error
    /// envelope (`error.type == "rate_limit_error"`).
    #[tokio::test]
    async fn test_rate_limit_429_responses_native_envelope() {
        crate::metrics::init();
        let (addr, handle, secret) = over_rpm_router().await;

        let r = reqwest::Client::new()
            .post(format!("http://{addr}/v1/responses"))
            .bearer_auth(secret)
            .body(json!({"model": "anything", "input": "hi"}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 429, "responses over-RPM → 429");
        assert!(
            r.headers().get(reqwest::header::RETRY_AFTER).is_some(),
            "responses 429 carries Retry-After"
        );
        let body: serde_json::Value = r.json().await.unwrap();
        assert_eq!(
            body.get("error")
                .and_then(|e| e.get("type"))
                .and_then(|t| t.as_str()),
            Some("rate_limit_error"),
            "responses 429 carries rate_limit_error error.type; got {body}"
        );
        handle.abort();
    }

    /// Cohere ingress (`/v2/chat`): an over-RPM 429 must carry the native Cohere error envelope —
    /// a BARE top-level `message` with NO `error`/`type` wrapper.
    #[tokio::test]
    async fn test_rate_limit_429_cohere_native_envelope() {
        crate::metrics::init();
        let (addr, handle, secret) = over_rpm_router().await;

        let r = reqwest::Client::new()
            .post(format!("http://{addr}/v2/chat"))
            .bearer_auth(secret)
            .body(json!({"model": "anything", "messages": []}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 429, "cohere over-RPM → 429");
        assert!(
            r.headers().get(reqwest::header::RETRY_AFTER).is_some(),
            "cohere 429 carries Retry-After"
        );
        let body: serde_json::Value = r.json().await.unwrap();
        assert!(
            body.get("message").and_then(|m| m.as_str()).is_some(),
            "cohere 429 envelope carries a bare top-level message; got {body}"
        );
        assert!(
            body.get("error").is_none() && body.get("type").is_none(),
            "cohere 429 envelope has NO error/type wrapper (native Cohere shape); got {body}"
        );
        handle.abort();
    }

    /// Gemini ingress (`/v1beta/models/x:generateContent`): an over-RPM 429 must carry the native
    /// Gemini error envelope — `error.code == 429` and `error.status == "RESOURCE_EXHAUSTED"`.
    #[tokio::test]
    async fn test_rate_limit_429_gemini_native_envelope() {
        crate::metrics::init();
        let (addr, handle, secret) = over_rpm_router().await;

        let r = reqwest::Client::new()
            .post(format!(
                "http://{addr}/v1beta/models/anything:generateContent"
            ))
            .bearer_auth(secret)
            .body(json!({"contents": []}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 429, "gemini over-RPM → 429");
        assert!(
            r.headers().get(reqwest::header::RETRY_AFTER).is_some(),
            "gemini 429 carries Retry-After"
        );
        let body: serde_json::Value = r.json().await.unwrap();
        assert_eq!(
            body.get("error")
                .and_then(|e| e.get("code"))
                .and_then(|c| c.as_u64()),
            Some(429),
            "gemini 429 envelope carries error.code == 429; got {body}"
        );
        assert_eq!(
            body.get("error")
                .and_then(|e| e.get("status"))
                .and_then(|s| s.as_str()),
            Some("RESOURCE_EXHAUSTED"),
            "gemini 429 envelope carries error.status == RESOURCE_EXHAUSTED; got {body}"
        );
        handle.abort();
    }

    /// Bedrock ingress (`/model/x/converse`): an over-RPM 429 must carry the native AWS JSON-1.1
    /// error envelope (`__type == "ThrottlingException"`) AND the `x-amzn-errortype` /
    /// `x-amzn-RequestId` headers a native Bedrock runtime response always carries.
    #[tokio::test]
    async fn test_rate_limit_429_bedrock_native_envelope() {
        crate::metrics::init();
        let (addr, handle, secret) = over_rpm_router().await;

        let r = reqwest::Client::new()
            .post(format!("http://{addr}/model/anything/converse"))
            .bearer_auth(secret)
            .body(json!({"messages": []}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 429, "bedrock over-RPM → 429");
        assert!(
            r.headers().get(reqwest::header::RETRY_AFTER).is_some(),
            "bedrock 429 carries Retry-After"
        );
        // Headers: a native Bedrock error always carries x-amzn-RequestId and x-amzn-errortype.
        let errortype_hdr = r
            .headers()
            .get("x-amzn-errortype")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string());
        assert_eq!(
            errortype_hdr.as_deref(),
            Some("ThrottlingException"),
            "bedrock 429 carries x-amzn-errortype header matching __type"
        );
        assert!(
            r.headers().get("x-amzn-requestid").is_some(),
            "bedrock 429 carries an x-amzn-RequestId header"
        );
        let body: serde_json::Value = r.json().await.unwrap();
        assert_eq!(
            body.get("__type").and_then(|t| t.as_str()),
            Some("ThrottlingException"),
            "bedrock 429 envelope carries __type == ThrottlingException; got {body}"
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

        let app = TestApp::new().governance(gov).build();

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
        let app = TestApp::new()
            .lane(LaneSpec::new(
                "test-model",
                crate::proto::Protocol::anthropic(),
                &server.base_url(),
            ))
            .pool("default", &[(0, 1)])
            .build();

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

    /// Regression: `MockResponse::Sse` must terminate a completed stream with the
    /// SSE-compliant `data: [DONE]\n\n` frame (matching real OpenAI), NOT a bare
    /// `[DONE]\n\n` that is missing the required `data: ` field prefix.
    /// Fails against the old code which pushed `"[DONE]\n\n"`.
    #[tokio::test]
    async fn test_sse_done_terminator_has_data_prefix() {
        let state = Arc::new(MockServerState::new());
        let events: Vec<String> = vec!["chunk-0".to_string(), "chunk-1".to_string()];
        state.push(MockResponse::Sse {
            events,
            abort_at_index: None,
        });

        let server = MockServer::new(state.clone()).await;
        let app = TestApp::new()
            .lane(LaneSpec::new(
                "test-model",
                crate::proto::Protocol::anthropic(),
                &server.base_url(),
            ))
            .pool("default", &[(0, 1)])
            .build();

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
        let collected_bytes = response.into_body().collect().await.unwrap().to_bytes();
        let text = String::from_utf8_lossy(&collected_bytes);

        assert!(
            text.contains("data: [DONE]\n\n"),
            "SSE terminator must carry the `data: ` prefix, got: {text}"
        );
        // The terminator must not appear in the bare, prefix-less form.
        assert!(
            !text.contains("\n\n[DONE]\n\n") && !text.starts_with("[DONE]"),
            "SSE terminator must not be emitted as a bare `[DONE]` frame, got: {text}"
        );
        server.shutdown().await;
    }

    /// Regression: raw event payloads handed to `MockResponse::Sse` are prefixed with
    /// exactly one `data: ` field. A double-prefixed `data: data: ...` frame must never
    /// be produced. Fails against the old tests that pre-prefixed their event strings.
    #[tokio::test]
    async fn test_sse_events_single_data_prefix() {
        let state = Arc::new(MockServerState::new());
        let events: Vec<String> = vec!["event-0".to_string(), "event-1".to_string()];
        state.push(MockResponse::Sse {
            events,
            abort_at_index: None,
        });

        let server = MockServer::new(state.clone()).await;
        let app = TestApp::new()
            .lane(LaneSpec::new(
                "test-model",
                crate::proto::Protocol::anthropic(),
                &server.base_url(),
            ))
            .pool("default", &[(0, 1)])
            .build();

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
        let collected_bytes = response.into_body().collect().await.unwrap().to_bytes();
        let text = String::from_utf8_lossy(&collected_bytes);

        assert!(
            !text.contains("data: data:"),
            "SSE frames must carry exactly one `data: ` prefix, got: {text}"
        );
        assert!(
            text.contains("data: event-0\n\n") && text.contains("data: event-1\n\n"),
            "each raw event must be wrapped in exactly one `data: ` frame, got: {text}"
        );
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
        let app = TestApp::new()
            .lane(
                LaneSpec::new(
                    "test-model",
                    crate::proto::Protocol::anthropic(),
                    &server.base_url(),
                )
                .max(1)
                .sem(sem.clone()),
            )
            .pool("default", &[(0, 1)])
            .build();

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
        // Raw event payloads; MockResponse::Sse adds the `data: ` SSE prefix.
        let events = vec![
            "event-0".to_string(),
            "event-1".to_string(),
            "event-2".to_string(),
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

        let app = TestApp::new()
            .lane(LaneSpec::new(
                "lane0",
                crate::proto::Protocol::anthropic(),
                &server.base_url(),
            ))
            .lane(LaneSpec::new(
                "lane1",
                crate::proto::Protocol::anthropic(),
                &server.base_url(),
            ))
            .pool("default", &[(0, 1), (1, 1)])
            .build();

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
        // Raw event payload; MockResponse::Sse adds the `data: ` SSE prefix.
        let events_lane1 = vec!["lane1-ok".to_string()];
        state.push(MockResponse::Sse {
            events: events_lane1,
            abort_at_index: None,
        });

        // Lane 0: sends 1 event then abruptly ends (no [DONE]) to simulate mid-stream abort
        // Raw event payloads; MockResponse::Sse adds the `data: ` SSE prefix.
        let events = vec![
            "event-0".to_string(),
            "event-1".to_string(),
            "event-2".to_string(),
            "event-3".to_string(),
            "event-4".to_string(),
        ];
        state.push(MockResponse::Sse {
            events,
            abort_at_index: Some(1), // send only index 0 (1 event) then end abruptly
        });

        let server = MockServer::new(state.clone()).await;

        let app = TestApp::new()
            .lane(LaneSpec::new(
                "lane0",
                crate::proto::Protocol::anthropic(),
                &server.base_url(),
            ))
            .lane(LaneSpec::new(
                "lane1",
                crate::proto::Protocol::anthropic(),
                &server.base_url(),
            ))
            .pool("default", &[(0, 1), (1, 1)])
            .build();

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
        let auth_cfg_passthrough = AuthCfg {
            mode: "passthrough".to_string(),
            client_tokens: vec![],
            _legacy_token: None,
        };
        let app_passthrough = TestApp::new()
            .lane(
                LaneSpec::new(
                    "test-model",
                    crate::proto::Protocol::anthropic(),
                    &server.base_url(),
                )
                .api_key("busbar-key"),
            )
            .pool("default", &[(0, 1)])
            .auth(Arc::new(AuthMiddleware::new(&auth_cfg_passthrough)))
            .build();

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

        let auth_cfg_token = AuthCfg {
            mode: "token".to_string(),
            client_tokens: vec!["caller-token-123".to_string()],
            _legacy_token: None,
        };
        let app_token = TestApp::new()
            .lane(
                LaneSpec::new(
                    "test-model",
                    crate::proto::Protocol::anthropic(),
                    &server.base_url(),
                )
                .api_key("busbar-key"),
            )
            .pool("default", &[(0, 1)])
            .auth(Arc::new(AuthMiddleware::new(&auth_cfg_token)))
            .build();

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

        let auth_cfg_passthrough = AuthCfg {
            mode: "passthrough".to_string(),
            client_tokens: vec![],
            _legacy_token: None,
        };
        let app = TestApp::new()
            .lane(
                LaneSpec::new(
                    "test-model",
                    crate::proto::Protocol::anthropic(),
                    &server.base_url(),
                )
                .api_key("busbar-central-key"),
            )
            .pool("default", &[(0, 1)])
            .auth(Arc::new(AuthMiddleware::new(&auth_cfg_passthrough)))
            .build();

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

        let app = TestApp::new()
            .lane(LaneSpec::new(
                "lane0",
                crate::proto::Protocol::anthropic(),
                &server.base_url(),
            ))
            .lane(LaneSpec::new(
                "lane1",
                crate::proto::Protocol::anthropic(),
                &server.base_url(),
            ))
            .pool("default", &[(0, 1), (1, 1)])
            .build();

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

        // Verify the EXACT attempt count, not a loose upper bound. The failover loop runs
        // `0..=max_cap` (max_cap=3, so up to 4 hops), but each picked lane is excluded for
        // subsequent hops (`request_ctx.exclude(i)`), so with only 2 distinct lanes the loop
        // can dispatch at most 2 real upstream attempts: hop 0 picks one lane, hop 1 picks the
        // other, hop 2 finds the candidate set exhausted → exhaustion handler → 503. Each
        // dispatched attempt records exactly one `err` (transient 500). The cap (4) never binds
        // here because the candidate pool drains first; the binding invariant is "no lane is
        // retried within a request", which yields EXACTLY one error per lane.
        //
        // A regression that reused/re-picked an already-tried lane (broken exclusion), or that
        // ran the loop past the cap, would push this above 2 and fail the assertion.
        let t = now();
        let total_errs: u64 = (0..2).map(|i| app.store.snapshot(i, t).err).sum();
        assert_eq!(
            total_errs, 2,
            "expected exactly 2 upstream attempts (one per distinct lane, no retry), got {}",
            total_errs
        );

        server.shutdown().await;
    }

    /// Failover cap test.
    /// All lanes return TransientUpstream → max_failover attempts capped, then 503.
    #[tokio::test]
    async fn test_failover_cap() {
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

        let app = TestApp::new()
            .lane(LaneSpec::new(
                "lane0",
                crate::proto::Protocol::anthropic(),
                &server.base_url(),
            ))
            .lane(LaneSpec::new(
                "lane1",
                crate::proto::Protocol::anthropic(),
                &server.base_url(),
            ))
            .lane(LaneSpec::new(
                "lane2",
                crate::proto::Protocol::anthropic(),
                &server.base_url(),
            ))
            .pool("default", &[(0, 1), (1, 1), (2, 1)])
            .build();

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

        // Verify the EXACT attempt count, not a loose upper bound. With 3 distinct lanes and
        // max_cap=3, the failover loop dispatches exactly 3 real upstream attempts: hops 0,1,2
        // each pick a fresh lane (each is excluded after pick via `request_ctx.exclude(i)`), and
        // the final loop turn finds the candidate set exhausted → exhaustion handler → 503. Each
        // dispatched attempt records exactly one `err` (transient 500). This is the boundary case
        // where lane count == cap, so BOTH invariants (cap and no-retry) pin the count to 3.
        //
        // A regression that ran the loop past `max_cap`, or that re-picked an already-tried lane,
        // would push this above 3 and fail the assertion.
        let t = now();
        let total_errs: u64 = (0..3).map(|i| app.store.snapshot(i, t).err).sum();
        assert_eq!(
            total_errs, 3,
            "expected exactly 3 upstream attempts (one per distinct lane, capped at max_cap=3), got {}",
            total_errs
        );

        server.shutdown().await;
    }

    /// Failover deadline test.
    /// Deadline computed once at start; verify default behavior works correctly with normal flow.
    #[tokio::test]
    async fn test_failover_deadline() {
        let state = Arc::new(MockServerState::new());

        // Push success response - should succeed within deadline.
        // Raw event payload; MockResponse::Sse adds the `data: ` SSE prefix.
        let events = vec!["success".to_string()];
        state.push(MockResponse::Sse {
            events,
            abort_at_index: None,
        });

        let server = MockServer::new(state.clone()).await;

        // default failover config: deadline=120s, cap=3
        let app = TestApp::new()
            .lane(LaneSpec::new(
                "lane0",
                crate::proto::Protocol::anthropic(),
                &server.base_url(),
            ))
            .lane(LaneSpec::new(
                "lane1",
                crate::proto::Protocol::anthropic(),
                &server.base_url(),
            ))
            .pool("default", &[(0, 1), (1, 1)])
            .failover(crate::config::FailoverCfg {
                deadline_secs: 120,
                exclusions: None,
                cap: 3,
            })
            .build();

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
        use crate::forward::UsageTap;

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
                "output_tokens": 5
            }
        });
        let delta_str = serde_json::to_string(&delta_json).unwrap();
        tap.feed(&Bytes::from(delta_str));

        // Assert: input/output token fields extracted correctly. A clean message_delta (normal
        // stop_reason, no error frame) must NOT set terminal_error — that's the signal the
        // stream-end arm uses to distinguish a clean close from an aborted one.
        assert_eq!(tap.input_tokens, Some(10), "input_tokens should be 10");
        assert_eq!(tap.output_tokens, Some(5), "output_tokens should be 5");
        assert!(
            tap.terminal_error.is_none(),
            "a clean stream (no error frame) must leave terminal_error None"
        );
        assert!(tap.has_usage(), "tap should have usage data");

        // A genuine SSE error frame DOES set terminal_error (the abnormal-end signal).
        let mut err_tap = UsageTap::new();
        err_tap.feed(&Bytes::from(
            r#"{"type":"error","error":{"message":"boom","source":"upstream"}}"#,
        ));
        assert_eq!(
            err_tap.terminal_error.as_deref(),
            Some("boom"),
            "an SSE error frame must populate terminal_error"
        );

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

        // Test 3: Byte-identical stream forwarding (integration test with mock)
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

        // MockResponse::Sse adds `data: [DONE]` at the end when abort_at_index is None
        let mut expected_text: String = usage_events
            .iter()
            .map(|e| format!("data: {}\n\n", e))
            .collect();
        expected_text.push_str("data: [DONE]\n\n");

        // Push events in reverse order (LIFO means last pushed comes out first)
        state.push(MockResponse::Sse {
            events: usage_events,
            abort_at_index: None,
        });

        let server = MockServer::new(state.clone()).await;

        let app = TestApp::new()
            .lane(LaneSpec::new(
                "test-model",
                crate::proto::Protocol::anthropic(),
                &server.base_url(),
            ))
            .pool("default", &[(0, 1)])
            .build();

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
                retry_after_secs: None,
            };
            let sig = normalize_raw_error(&raw, &error_map);
            assert_eq!(sig.class, crate::breaker::StatusClass::Billing);

            // Different code not in map → fallback to HTTP status classification
            let raw2 = RawUpstreamError {
                http_status: 500,
                provider_code: Some("9999".to_string()),
                structured_type: None,
                retry_after_secs: None,
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
                retry_after_secs: None,
            };
            let sig = normalize_raw_error(&raw, &error_map);
            assert_eq!(sig.class, crate::breaker::StatusClass::Auth);

            // HTTP 429 → RateLimit (universal spec)
            let raw2 = RawUpstreamError {
                http_status: 429,
                provider_code: None,
                structured_type: None,
                retry_after_secs: None,
            };
            let sig2 = normalize_raw_error(&raw2, &error_map);
            assert_eq!(sig2.class, crate::breaker::StatusClass::RateLimit);

            // HTTP 500 → ServerError (universal spec)
            let raw3 = RawUpstreamError {
                http_status: 500,
                provider_code: None,
                structured_type: None,
                retry_after_secs: None,
            };
            let sig3 = normalize_raw_error(&raw3, &error_map);
            assert_eq!(sig3.class, crate::breaker::StatusClass::ServerError);

            // HTTP 400 → ClientError (universal spec)
            let raw4 = RawUpstreamError {
                http_status: 400,
                provider_code: None,
                structured_type: None,
                retry_after_secs: None,
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
            let mut error_map = HashMap::new();
            error_map.insert("1113".to_string(), "billing".to_string());
            error_map.insert("1302".to_string(), "rate_limit".to_string());
            let app = TestApp::new()
                .lane(
                    LaneSpec::new(
                        "test-model",
                        crate::proto::Protocol::anthropic(),
                        &server.base_url(),
                    )
                    .provider("z.ai")
                    .error_map(error_map),
                )
                .pool("default", &[(0, 1)])
                .build();

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
            let mut error_map = HashMap::new();
            error_map.insert("1113".to_string(), "billing".to_string());
            error_map.insert("1302".to_string(), "rate_limit".to_string());
            let app = TestApp::new()
                .lane(
                    LaneSpec::new(
                        "test-model",
                        crate::proto::Protocol::anthropic(),
                        &server.base_url(),
                    )
                    .provider("z.ai")
                    .error_map(error_map),
                )
                .pool("default", &[(0, 1)])
                .build();

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
                retry_after: None,
            });

            let server = MockServer::new(state.clone()).await;
            let mut error_map = HashMap::new();
            error_map.insert("1113".to_string(), "billing".to_string());
            error_map.insert("1302".to_string(), "rate_limit".to_string());
            let app = TestApp::new()
                .lane(
                    LaneSpec::new(
                        "test-model",
                        crate::proto::Protocol::anthropic(),
                        &server.base_url(),
                    )
                    .provider("z.ai")
                    .error_map(error_map),
                )
                .pool("default", &[(0, 1)])
                .build();

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
                retry_after: None,
            });

            let server = MockServer::new(state.clone()).await;
            let mut error_map = HashMap::new();
            error_map.insert("1113".to_string(), "billing".to_string());
            error_map.insert("1302".to_string(), "rate_limit".to_string());
            let app = TestApp::new()
                .lane(
                    LaneSpec::new(
                        "test-model",
                        crate::proto::Protocol::anthropic(),
                        &server.base_url(),
                    )
                    .provider("z.ai")
                    .error_map(error_map),
                )
                .pool("default", &[(0, 1)])
                .build();

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
            let mut error_map = HashMap::new();
            error_map.insert("1113".to_string(), "billing".to_string());
            error_map.insert("1302".to_string(), "rate_limit".to_string());
            let app = TestApp::new()
                .lane(
                    LaneSpec::new(
                        "test-model",
                        crate::proto::Protocol::anthropic(),
                        &server.base_url(),
                    )
                    .provider("z.ai")
                    .error_map(error_map),
                )
                .pool("default", &[(0, 1)])
                .build();

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
            let mut error_map = HashMap::new();
            error_map.insert("1113".to_string(), "billing".to_string());
            error_map.insert("1302".to_string(), "rate_limit".to_string());
            let app = TestApp::new()
                .lane(
                    LaneSpec::new(
                        "test-model",
                        crate::proto::Protocol::anthropic(),
                        &server.base_url(),
                    )
                    .provider("z.ai")
                    .error_map(error_map),
                )
                .pool("default", &[(0, 1)])
                .build();

            let req_body = serde_json::to_vec(&json!({"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})).unwrap();
            let response = forward(
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

            // The non-passthrough auth-error response must NOT leak the upstream's verbatim
            // auth-rejection body (busbar's own credential context). It returns a normalized
            // envelope shaped to the INGRESS protocol's native error shape (here Anthropic, the
            // `forward` default) via `ingress_error` — not a hard-coded OpenAI-flavored shape, which
            // a native Anthropic/Bedrock/Gemini SDK could not decode (R2 conformance fix).
            assert_eq!(response.status().as_u16(), 401);
            use http_body_util::BodyExt as _;
            let body = response.into_body().collect().await.unwrap().to_bytes();
            let v: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
            assert_eq!(
                v["type"], "error",
                "Anthropic-native error envelope: top-level type"
            );
            assert_eq!(
                v["error"]["type"], "authentication_error",
                "non-passthrough auth error is a normalized native envelope, not the raw upstream body"
            );
            // The wire message is the VENDOR-PLAUSIBLE auth-failure copy for the ingress protocol
            // (here Anthropic → "invalid x-api-key"), NOT busbar-internal vocabulary. The previous
            // "upstream rejected the lane credential" leaked the internal "lane" concept — a word no
            // real vendor uses — which was a deterministic proxy tell (R7 indistinguishability fix).
            let msg = v["error"]["message"].as_str().unwrap_or("");
            assert_eq!(
                msg,
                crate::proto::vendor_auth_failure_message("anthropic"),
                "auth message must be vendor-plausible copy, not busbar-internal vocabulary: {v}"
            );
            assert!(
                !msg.contains("lane"),
                "auth message must never contain the busbar-internal word 'lane': {v}"
            );

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
            let mut error_map_1 = HashMap::new();
            error_map_1.insert("1113".to_string(), "billing".to_string());

            let app_1 = TestApp::new()
                .lane(
                    LaneSpec::new(
                        "test-model",
                        crate::proto::Protocol::anthropic(),
                        &server1.base_url(),
                    )
                    .provider("z.ai")
                    .api_key("test-key-1")
                    .error_map(error_map_1),
                )
                .pool("default", &[(0, 1)])
                .build();

            // Lane 2: NO mapping for any code → HTTP status classification only
            let app_2 = TestApp::new()
                .lane(
                    LaneSpec::new(
                        "test-model",
                        crate::proto::Protocol::anthropic(),
                        &server2.base_url(),
                    )
                    .provider("z.ai")
                    .api_key("test-key-2"),
                )
                .pool("default", &[(0, 1)])
                .build();

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
                default_max_tokens: None,
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
                retry_after_secs: None,
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

            let app = TestApp::new()
                .lane(
                    LaneSpec::new(
                        "test-model",
                        crate::proto::Protocol::anthropic(),
                        &server.base_url(),
                    )
                    .provider("anthropic"),
                )
                .pool("default", &[(0, 1)])
                .build();

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
            assert!(
                matches!(breaker_state, crate::store::BreakerState::Closed),
                "client fault must not trip breaker"
            );

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

            let app = TestApp::new()
                .lane(
                    LaneSpec::new(
                        "lane0",
                        crate::proto::Protocol::anthropic(),
                        &server0.base_url(),
                    )
                    .provider("anthropic"),
                )
                .lane(
                    LaneSpec::new(
                        "lane1",
                        crate::proto::Protocol::anthropic(),
                        &server1.base_url(),
                    )
                    .provider("anthropic"),
                )
                .pool("default", &[(0, 1), (1, 1)])
                .build();

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
                retry_after: None,
            });
        }

        let server = MockServer::new(state.clone()).await;

        let app = TestApp::new()
            .lane(LaneSpec::new(
                "lane0",
                crate::proto::Protocol::anthropic(),
                &server.base_url(),
            ))
            .lane(LaneSpec::new(
                "lane1",
                crate::proto::Protocol::anthropic(),
                &server.base_url(),
            ))
            .pool("default", &[(0, 1), (1, 1)])
            .build();

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
        let app = TestApp::new()
            .lane(
                LaneSpec::new(
                    "lane0",
                    crate::proto::Protocol::anthropic(),
                    &server0.base_url(),
                )
                .cooldown_until(t0 + 600) // far expiry
                .streak(3)
                .err(5),
            )
            .lane(
                LaneSpec::new(
                    "lane1",
                    crate::proto::Protocol::anthropic(),
                    &server1.base_url(),
                )
                .cooldown_until(t0 + 5) // SOONEST expiry → least-bad should pick this one
                .streak(3)
                .err(5),
            )
            .pool("leastbad", &[(0, 1), (1, 1)])
            .on_exhausted("leastbad", crate::config::OnExhausted::LeastBad)
            .build();

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

    /// Round-4 MEDIUM/correctness: `forward_once` (the LeastBad/FallbackPool helper) must record
    /// lane success AND spend budget on a 2xx, mirroring the main forward loop. Without it a HalfOpen
    /// lane served only via the degraded path never recovers and its `max_requests` budget never
    /// depletes. Route a budget-limited lane via LeastBad and assert `ok` incremented and `budget`
    /// decremented after one served request.
    #[tokio::test]
    async fn test_forward_once_records_success_and_spends_budget() {
        use crate::store::now as store_now;
        let state = Arc::new(MockServerState::new());
        state.push(MockResponse::Ok {
            status: StatusCode::OK,
            body: json!({ "content": [] }),
        });
        let server = MockServer::new(state.clone()).await;
        let t0 = store_now();
        let app = TestApp::new()
            .lane(
                LaneSpec::new(
                    "lane0",
                    crate::proto::Protocol::anthropic(),
                    &server.base_url(),
                )
                .cooldown_until(t0 + 600) // Open → normal selection finds nothing → LeastBad path
                .streak(3)
                .err(5)
                .budget(2), // limited lane: 2 lifetime requests remaining
            )
            .pool("leastbad", &[(0, 1)])
            .on_exhausted("leastbad", crate::config::OnExhausted::LeastBad)
            .build();

        let before = app.store.snapshot(0, store_now());
        assert_eq!(before.ok, 0, "precondition: no successes yet");
        assert_eq!(before.budget, 2, "precondition: budget 2");

        let req_body = serde_json::to_vec(&json!({"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})).unwrap();
        let response = forward_with_pool(
            app.clone(),
            vec![crate::state::WeightedLane { idx: 0, weight: 1 }],
            req_body.into(),
            None,
            "leastbad",
            None,
            "anthropic",
            None,
        )
        .await;
        assert_eq!(response.status().as_u16(), 200, "LeastBad serves 2xx");
        // Drain the body so any streaming completion settles (non-stream here, but keep it uniform).
        let _ = axum::body::to_bytes(response.into_body(), usize::MAX).await;

        let after = app.store.snapshot(0, store_now());
        assert_eq!(
            after.ok, 1,
            "forward_once must record_success on 2xx (was the bug: HalfOpen never recovers via fallback)"
        );
        assert_eq!(
            after.budget, 1,
            "forward_once must spend_budget on 2xx (was the bug: unlimited requests via fallback)"
        );
        server.shutdown().await;
    }

    /// REGRESSION (R7 MEDIUM, forward.rs gemini-json-array gating): a BODY-MODEL client (openai) that
    /// sends `__busbar_gemini_json_array:true` in its own fully-controlled body must NOT have its SSE
    /// stream reframed as a JSON array under `Content-Type: application/json`. The framing is gated on
    /// `ingress_protocol == "gemini"`, so an openai-ingress streaming response stays `text/event-stream`
    /// and the smuggled shim key never reaches the backend.
    #[tokio::test]
    async fn test_gemini_json_array_shim_ignored_for_body_model_ingress() {
        crate::metrics::init();
        let state = Arc::new(MockServerState::new());
        state.push(MockResponse::Sse {
            events: vec![
                json!({"id":"chatcmpl-1","object":"chat.completion.chunk","created":1,"model":"gpt","choices":[{"index":0,"delta":{"role":"assistant","content":"hi"},"finish_reason":null}]}).to_string(),
                json!({"id":"chatcmpl-1","object":"chat.completion.chunk","created":1,"model":"gpt","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}).to_string(),
            ],
            abort_at_index: None,
        });
        let server = MockServer::new(state.clone()).await;
        let app = TestApp::new()
            .lane(
                LaneSpec::new("gpt", crate::proto::Protocol::openai(), &server.base_url())
                    .provider("openai"),
            )
            .pool("p", &[(0, 1)])
            .build();

        // openai ingress; SAME-protocol (openai egress) so the response is a passthrough SSE stream.
        let req_body = serde_json::to_vec(&json!({
            "model": "p",
            "stream": true,
            "__busbar_gemini_json_array": true,
            "messages": [{"role": "user", "content": "hi"}]
        }))
        .unwrap();
        let response = forward_with_pool(
            app.clone(),
            vec![crate::state::WeightedLane { idx: 0, weight: 1 }],
            req_body.into(),
            None,
            "p",
            None,
            "openai",
            None,
        )
        .await;

        assert_eq!(response.status().as_u16(), 200);
        let ct = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .to_string();
        assert!(
            ct.starts_with("text/event-stream"),
            "openai SSE must NOT be reframed as application/json JSON-array by a smuggled shim key; got CT {ct}"
        );
        let _ = axum::body::to_bytes(response.into_body(), usize::MAX).await;

        // And the smuggled shim key must never reach the backend.
        let upstream = state.get_last_request_body().expect("upstream body");
        let uv: serde_json::Value = serde_json::from_slice(&upstream).unwrap();
        assert!(
            uv.get("__busbar_gemini_json_array").is_none(),
            "smuggled gemini array shim key must be stripped before forwarding; got {uv}"
        );
        server.shutdown().await;
    }

    /// REGRESSION (R7 MEDIUM, forward_once): the DEGRADED path (LeastBad/FallbackPool → `forward_once`)
    /// must shape a CROSS-protocol upstream 401/403 into the ingress protocol's native error envelope
    /// with the SAME kind the main `forward_with_pool` path uses — `authentication_error` for 401,
    /// `permission_error` for 403 — NOT the old degraded-path `invalid_request_error`. Anthropic
    /// ingress, OpenAI egress lane (cross-protocol), lane in cooldown so LeastBad routes through
    /// `forward_once`.
    #[tokio::test]
    async fn test_forward_once_cross_protocol_auth_kinds_match_main_path() {
        use crate::store::now as store_now;
        for (upstream_status, want_kind) in [
            (StatusCode::UNAUTHORIZED, "authentication_error"),
            (StatusCode::FORBIDDEN, "permission_error"),
        ] {
            let state = Arc::new(MockServerState::new());
            state.push(MockResponse::Auth {
                status: upstream_status,
            });
            let server = MockServer::new(state.clone()).await;
            let t0 = store_now();
            // Lane speaks OpenAI; ingress is Anthropic → cross-protocol. Lane in long cooldown so
            // normal selection finds nothing and LeastBad serves via forward_once.
            let app = TestApp::new()
                .lane(
                    LaneSpec::new(
                        "lane0",
                        crate::proto::Protocol::openai(),
                        &server.base_url(),
                    )
                    .provider("zai")
                    .cooldown_until(t0 + 600)
                    .streak(3)
                    .err(5),
                )
                .pool("leastbad", &[(0, 1)])
                .on_exhausted("leastbad", crate::config::OnExhausted::LeastBad)
                .build();

            let req_body = serde_json::to_vec(&json!({"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})).unwrap();
            let response = forward_with_pool(
                app.clone(),
                vec![crate::state::WeightedLane { idx: 0, weight: 1 }],
                req_body.into(),
                None,
                "leastbad",
                None,
                "anthropic",
                None,
            )
            .await;

            assert_eq!(
                response.status(),
                upstream_status,
                "degraded path preserves the upstream status ({upstream_status})"
            );
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let v: serde_json::Value =
                serde_json::from_slice(&body).expect("degraded cross-protocol error is JSON");
            // Anthropic-native envelope: top-level type "error", error.type the canonical kind.
            assert_eq!(v["type"], "error", "anthropic-native error envelope: {v}");
            assert_eq!(
                v["error"]["type"], want_kind,
                "degraded path {upstream_status} must map to {want_kind} (matching the main path), not invalid_request_error: {v}"
            );
            server.shutdown().await;
        }
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
        let tripped = |key: &str| {
            LaneSpec::new(
                "test-model",
                crate::proto::Protocol::anthropic(),
                &server.base_url(),
            )
            .api_key(key)
            .cooldown_until(t0 + 600)
            .streak(3)
            .err(5)
        };

        // A→B→A: pool_a falls back to pool_b, pool_b falls back to pool_a.
        //
        // For the cycle to genuinely re-enter an already-visited pool (and thereby exercise the
        // visited-set guard rather than the "fallback pool not configured" cascade), pool_a must
        // ALSO be registered in `fallback_pools` — `handle_fallback_pool` resolves targets via
        // `app.fallback_pools.get(...)`, not the primary `pools` map. With pool_a registered as a
        // fallback target the chain runs pool_a→pool_b(marked)→pool_a(marked)→pool_b DETECTED
        // VISITED → 503, so the visited-set is the terminating mechanism. Without that guard this
        // chain would recurse forever (regression coverage).
        let app = TestApp::new()
            .lane(tripped("key-a0"))
            .lane(tripped("key-a1"))
            .lane(tripped("key-b0"))
            .lane(tripped("key-b1"))
            .pool("pool_a", &[(0, 1), (1, 1)])
            .fallback_pool("pool_a", &[(0, 1), (1, 1)])
            .fallback_pool("pool_b", &[(2, 1), (3, 1)])
            .on_exhausted(
                "pool_a",
                crate::config::OnExhausted::FallbackPool("pool_b".to_string()),
            )
            .on_exhausted(
                "pool_b",
                crate::config::OnExhausted::FallbackPool("pool_a".to_string()),
            )
            .build();

        let req_body = serde_json::to_vec(&json!({"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})).unwrap();

        // pool_a (marked) → pool_b (marked) → pool_a re-entered (already visited) → 503 via guard.
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
        let tripped = |key: &str| {
            LaneSpec::new(
                "test-model",
                crate::proto::Protocol::anthropic(),
                &server.base_url(),
            )
            .api_key(key)
            .cooldown_until(t0 + 600)
            .streak(3)
            .err(5)
        };

        let app = TestApp::new()
            .lane(tripped("key-0"))
            .lane(tripped("key-1"))
            .lane(
                LaneSpec::new(
                    "test-model",
                    crate::proto::Protocol::anthropic(),
                    &server.base_url(),
                )
                .api_key("key-2")
                .ok(10),
            )
            .pool("primary", &[(0, 1), (1, 1)])
            .fallback_pool("backup", &[(2, 1)])
            .on_exhausted(
                "primary",
                crate::config::OnExhausted::FallbackPool("backup".to_string()),
            )
            .build();

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

        let mk_lane = |base_url: String, key: &str| {
            LaneSpec::new("test-model", crate::proto::Protocol::anthropic(), &base_url).api_key(key)
        };

        let app = TestApp::new()
            .lane(mk_lane(server0.base_url(), "test-key-0"))
            .lane(mk_lane(server1.base_url(), "test-key-1"))
            .lane(mk_lane(server2.base_url(), "test-key-2"))
            .pool("sticky-test", &[(0, 1), (1, 1), (2, 1)])
            .build();

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
    ///
    /// REGRESSION GUARD (R20 MED #19): this test must actually exercise the
    /// "sticky member's breaker is Open" branch of `pick_among`'s affinity fast
    /// path — i.e. the `usable_in(pool, sticky, t)` guard returning false and the
    /// pick falling through to SWRR over the healthy remainder. That requires TWO
    /// things to line up deterministically:
    ///
    ///   1. the session key must hash onto the TRIPPED member, and
    ///   2. the tripped member's breaker must actually be Open at selection time.
    ///
    /// `pick_among` computes `pos = stable_hash(key) % cands.len()` and treats
    /// `cands[pos].idx` as the sticky member. With `cands = [lane0, lane1]`,
    /// `cands.len() == 2`, so the sticky member is lane 0 iff `stable_hash(key)`
    /// is even. `stable_hash("session-abc") % 2 == 0` (verified against the FNV-1a
    /// constants in forward.rs), so the sticky member here is the TRIPPED lane 0 —
    /// NOT the healthy lane 1. (The previous revision used `"session-to-lane-0"`,
    /// whose hash is ODD → sticky member was lane 1, the *healthy* lane, so the
    /// affinity fast path simply succeeded and the tripped-member yield branch was
    /// never reached: the test was green for the wrong reason.)
    ///
    /// Lane 0 is parked Open via a future `cooldown_until` (the same idiom the
    /// LeastBad tests use) so `usable_in` returns false for it. If the affinity
    /// logic regressed to PIN the sticky member regardless of breaker health
    /// (dropping the `usable_in` guard), the request would route to tripped lane 0
    /// and the `contains("lane1")` / `!contains("lane0")` assertions below would
    /// fail.
    #[tokio::test]
    async fn test_sticky_yields_when_tripped() {
        use crate::store::now as store_now;

        // Separate mock servers for each lane, each returning a distinguishable body
        // so we can assert WHICH member served.
        let state0 = Arc::new(MockServerState::new());
        let server0 = MockServer::new(state0.clone()).await;
        // Lane 0 is the sticky-but-tripped member. It should NOT be selected; if it
        // ever is (affinity pinned past the Open breaker), this body unmasks the bug.
        state0.push(MockResponse::Ok {
            status: StatusCode::OK,
            body: json!({ "served_by": "lane0", "content": [] }),
        });

        let state1 = Arc::new(MockServerState::new());
        let server1 = MockServer::new(state1.clone()).await;
        state1.push(MockResponse::Ok {
            status: StatusCode::OK,
            body: json!({ "served_by": "lane1", "content": [] }),
        });

        // Lane 0 Open (future cooldown) → `usable_in(pool, 0, t)` is false, so the
        // sticky affinity fast path must skip it and fall through to SWRR. Lane 1 is
        // a fresh, healthy lane.
        let t0 = store_now();
        let app = TestApp::new()
            .lane(
                LaneSpec::new(
                    "test-model",
                    crate::proto::Protocol::anthropic(),
                    &server0.base_url(),
                )
                .api_key("test-key-0")
                .max(1)
                .cooldown_until(t0 + 600)
                .streak(3)
                .err(5),
            )
            .lane(
                LaneSpec::new(
                    "test-model",
                    crate::proto::Protocol::anthropic(),
                    &server1.base_url(),
                )
                .api_key("test-key-1")
                .max(1),
            )
            .pool("failover-test", &[(0, 1), (1, 1)])
            .build();

        let req_body = serde_json::to_vec(&json!({"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})).unwrap();

        // `stable_hash("session-abc") % 2 == 0` → sticky member is cands[0] == lane 0
        // (the TRIPPED lane). This is the case the test name claims to cover.
        let response = forward_with_pool(
            app.clone(),
            vec![
                crate::state::WeightedLane { idx: 0, weight: 1 },
                crate::state::WeightedLane { idx: 1, weight: 1 },
            ],
            req_body.into(),
            None,
            "failover-test",
            Some("session-abc"),
            "anthropic",
            None,
        )
        .await;

        // Should succeed by yielding to lane 1 (healthy), since the sticky member
        // (lane 0) is tripped.
        assert_eq!(response.status().as_u16(), 200);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8_lossy(&body);

        // Served by lane 1, NOT the tripped sticky member lane 0 (affinity is a
        // preference, not a pin: a tripped sticky member yields).
        assert!(
            body_str.contains("lane1"),
            "sticky member (lane 0) is tripped → must yield to healthy lane 1; got: {body_str}"
        );
        assert!(
            !body_str.contains("lane0"),
            "must NOT route to the tripped sticky member (lane 0); got: {body_str}"
        );

        server0.shutdown().await;
        server1.shutdown().await;
    }

    /// Active health probe: a 2xx response to the probe recovers a tripped lane (→ Closed).
    #[tokio::test]
    async fn test_health_probe_recovers_tripped_lane() {
        let state0 = Arc::new(MockServerState::new());
        let server0 = MockServer::new(state0.clone()).await;
        state0.push(MockResponse::Ok {
            status: StatusCode::OK,
            body: json!({ "content": [] }),
        });

        let app = TestApp::new()
            .lane(
                LaneSpec::new(
                    "test-model",
                    crate::proto::Protocol::anthropic(),
                    &server0.base_url(),
                )
                .provider("p")
                .api_key("test-key")
                .health(crate::config::HealthCfg {
                    mode: crate::config::HealthMode::Dead,
                    interval_secs: None,
                    timeout_secs: None,
                }),
            )
            .build();

        // Trip the lane out of band (hard-down → Open with a sticky cooldown).
        app.store.record_hard_down(0, "test trip");
        assert_ne!(
            app.store.breaker_state(0),
            crate::store::BreakerState::Closed,
            "lane should be tripped before the probe"
        );

        crate::health::probe_lane(&app, 0, Duration::from_secs(5)).await;

        assert_eq!(
            app.store.breaker_state(0),
            crate::store::BreakerState::Closed,
            "a 2xx health probe must recover the tripped lane"
        );
        server0.shutdown().await;
    }

    /// Active health probe: a failing probe records a transient error against the lane.
    #[tokio::test]
    async fn test_health_probe_failure_records_transient() {
        let state0 = Arc::new(MockServerState::new());
        let server0 = MockServer::new(state0.clone()).await;
        state0.push(MockResponse::ServerError {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            body: json!({ "error": "down" }),
        });

        let app = TestApp::new()
            .lane(
                LaneSpec::new(
                    "test-model",
                    crate::proto::Protocol::anthropic(),
                    &server0.base_url(),
                )
                .provider("p")
                .api_key("test-key")
                .health(crate::config::HealthCfg {
                    mode: crate::config::HealthMode::Active,
                    interval_secs: None,
                    timeout_secs: None,
                }),
            )
            .build();

        let before = app.store.snapshot(0, crate::store::now()).err;
        crate::health::probe_lane(&app, 0, Duration::from_secs(5)).await;
        let after = app.store.snapshot(0, crate::store::now()).err;
        assert_eq!(
            after,
            before + 1,
            "a failing health probe must record a transient error"
        );
        server0.shutdown().await;
    }

    /// Test 3: No header → system block hash for affinity.
    #[tokio::test]
    async fn test_sticky_from_system_block() {
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

        let app = TestApp::new()
            .lane(
                LaneSpec::new(
                    "test-model",
                    crate::proto::Protocol::anthropic(),
                    &server0.base_url(),
                )
                .api_key("test-key-0"),
            )
            .lane(
                LaneSpec::new(
                    "test-model",
                    crate::proto::Protocol::anthropic(),
                    &server1.base_url(),
                )
                .api_key("test-key-1"),
            )
            .pool("system-test", &[(0, 1), (1, 1)])
            .build();

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
        let app = TestApp::new()
            .lane(
                LaneSpec::new(
                    "test-model",
                    crate::proto::Protocol::openai(),
                    &server.base_url(),
                )
                .provider("openai-mock")
                .api_key("test-key"),
            )
            .build();

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
            axum::extract::Extension(crate::auth::CallerToken::default()),
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
        let app = TestApp::new().build();

        // Missing "model" field in body
        let req_body = serde_json::json!({
            "messages": [{"role": "user", "content": "hi"}]
        });
        let body_bytes = Bytes::from(serde_json::to_vec(&req_body).unwrap());

        let response = route::openai_ingress(
            State(app),
            axum::extract::Extension(crate::governance::GovCtx::default()),
            axum::extract::Extension(crate::auth::CallerToken::default()),
            HeaderMap::new(),
            body_bytes,
        )
        .await;

        assert_eq!(response.status().as_u16(), 400);
    }

    /// Security (SSRF): the ad-hoc `/:provider/:model` route only reaches CONFIGURED lanes — a
    /// caller cannot coerce busbar to an arbitrary upstream. Unknown model → 404; known model on a
    /// mismatched provider → 400. Both reject BEFORE any upstream call (and before any metric is
    /// emitted, so caller path segments can't inflate `/metrics` cardinality).
    #[tokio::test]
    async fn test_adhoc_rejects_unconfigured_provider_model() {
        use crate::route;

        let app = TestApp::new()
            .lane(
                LaneSpec::new(
                    "test-model",
                    crate::proto::Protocol::openai(),
                    "https://configured.example.com",
                )
                .provider("openai")
                .max(1),
            )
            .build();

        let body = Bytes::from_static(b"{\"messages\":[]}");

        // Attacker-chosen provider/model that isn't configured → 404, no upstream reached.
        let resp = route::adhoc(
            State(app.clone()),
            axum::extract::Path(("evil.example.com".to_string(), "../secret".to_string())),
            axum::extract::Extension(crate::governance::GovCtx::default()),
            axum::extract::Extension(crate::auth::CallerToken::default()),
            body.clone(),
        )
        .await;
        assert_eq!(
            resp.status().as_u16(),
            404,
            "unknown provider/model must 404"
        );

        // Configured model but WRONG provider → 400 (must match the lane's provider).
        let resp2 = route::adhoc(
            State(app),
            axum::extract::Path(("wrong-provider".to_string(), "test-model".to_string())),
            axum::extract::Extension(crate::governance::GovCtx::default()),
            axum::extract::Extension(crate::auth::CallerToken::default()),
            body,
        )
        .await;
        assert_eq!(
            resp2.status().as_u16(),
            400,
            "model on a mismatched provider must be rejected"
        );
    }

    /// OpenAI ingress unknown model → 404.
    #[tokio::test]
    async fn test_openai_ingress_unknown_model() {
        use crate::route;
        use axum::http::HeaderMap;

        // Build a minimal App with no "nope" model
        let app = TestApp::new().build();

        // Unknown model in body
        let req_body = serde_json::json!({
            "model": "nope",
            "messages": [{"role": "user", "content": "hi"}]
        });
        let body_bytes = Bytes::from(serde_json::to_vec(&req_body).unwrap());

        let response = route::openai_ingress(
            State(app),
            axum::extract::Extension(crate::governance::GovCtx::default()),
            axum::extract::Extension(crate::auth::CallerToken::default()),
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
        let state = Arc::new(MockServerState::new());

        // Mock receives the translated Anthropic-shaped body and returns a NATIVE Anthropic response
        // (so the cross-protocol RESPONSE translation back to OpenAI succeeds — a malformed dummy
        // body now correctly yields an ingress-native 500 instead of leaking a foreign-format body).
        state.push(MockResponse::Ok {
            status: StatusCode::OK,
            body: json!({
                "id": "msg_x",
                "type": "message",
                "role": "assistant",
                "content": [{"type": "text", "text": "translated"}],
                "model": "m",
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 5, "output_tokens": 2}
            }),
        });

        let server = MockServer::new(state.clone()).await;

        let app = TestApp::new()
            .lane(
                LaneSpec::new("m", crate::proto::Protocol::anthropic(), &server.base_url())
                    .provider("anthropic"),
            )
            .build();

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

        // Model is in by_model but NOT in any pool — the branch the bug lived in.
        let app = TestApp::new()
            .lane(
                LaneSpec::new(
                    "glm-4.5",
                    crate::proto::Protocol::anthropic(),
                    &server.base_url(),
                )
                .provider("z.ai"),
            )
            .build();

        let body = json!({"model": "glm-4.5", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 15});
        let resp = route::openai_ingress(
            State(app),
            axum::extract::Extension(crate::governance::GovCtx::default()),
            axum::extract::Extension(crate::auth::CallerToken::default()),
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

    /// Drive an OpenAI-ingress request (single-model, no-pool route) at an Anthropic backend and
    /// return the body the upstream actually received, so `max_tokens`-injection regressions can be
    /// asserted on the wire. `lane_default` is the lane's configured `default_max_tokens`.
    async fn forwarded_openai_to_anthropic(
        lane_default: Option<u32>,
        request_body: serde_json::Value,
    ) -> serde_json::Value {
        use crate::route;

        let state = Arc::new(MockServerState::new());
        state.push(MockResponse::Ok {
            status: StatusCode::OK,
            body: json!({
                "id": "msg_1",
                "type": "message",
                "role": "assistant",
                "content": [{"type": "text", "text": "ok"}],
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 1, "output_tokens": 1}
            }),
        });
        let server = MockServer::new(state.clone()).await;

        let mut spec = LaneSpec::new(
            "glm-4.5",
            crate::proto::Protocol::anthropic(),
            &server.base_url(),
        )
        .provider("z.ai");
        if let Some(d) = lane_default {
            spec = spec.default_max_tokens(d);
        }
        let app = TestApp::new().lane(spec).build();

        let resp = route::openai_ingress(
            State(app),
            axum::extract::Extension(crate::governance::GovCtx::default()),
            axum::extract::Extension(crate::auth::CallerToken::default()),
            axum::http::HeaderMap::new(),
            Bytes::from(request_body.to_string()),
        )
        .await;
        assert_eq!(
            resp.status().as_u16(),
            200,
            "translation route must succeed"
        );

        let received = state
            .get_last_request_body()
            .expect("mock should have recorded the upstream request body");
        let got: serde_json::Value =
            serde_json::from_slice(&received).expect("upstream body is JSON");
        server.shutdown().await;
        got
    }

    /// Regression (max_tokens translation contract): an OpenAI request that legally OMITS
    /// `max_tokens`, routed to an Anthropic backend, must reach the upstream WITH a `max_tokens`
    /// (Anthropic 400s without it). With no per-lane default, the conservative fallback is injected.
    #[tokio::test]
    async fn test_openai_omits_max_tokens_injects_fallback_for_anthropic() {
        let got = forwarded_openai_to_anthropic(
            None,
            json!({"model": "glm-4.5", "messages": [{"role": "user", "content": "hi"}]}),
        )
        .await;
        assert_eq!(
            got.get("max_tokens").and_then(|v| v.as_u64()),
            Some(crate::proto::DEFAULT_MAX_TOKENS as u64),
            "absent max_tokens must be backfilled with the fallback on →anthropic translation; got: {got}"
        );
    }

    /// The per-lane configured `default_max_tokens` overrides the constant fallback when the source
    /// omits `max_tokens`.
    #[tokio::test]
    async fn test_openai_omits_max_tokens_uses_configured_lane_default() {
        let got = forwarded_openai_to_anthropic(
            Some(1234),
            json!({"model": "glm-4.5", "messages": [{"role": "user", "content": "hi"}]}),
        )
        .await;
        assert_eq!(
            got.get("max_tokens").and_then(|v| v.as_u64()),
            Some(1234),
            "configured lane default_max_tokens must be injected; got: {got}"
        );
    }

    /// An explicit `max_tokens` from the client is preserved verbatim — injection only fills a gap,
    /// it never overrides a caller-supplied value (even when a lane default is configured).
    #[tokio::test]
    async fn test_openai_explicit_max_tokens_preserved_over_lane_default() {
        let got = forwarded_openai_to_anthropic(
            Some(1234),
            json!({"model": "glm-4.5", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 7}),
        )
        .await;
        assert_eq!(
            got.get("max_tokens").and_then(|v| v.as_u64()),
            Some(7),
            "caller-supplied max_tokens must survive translation untouched; got: {got}"
        );
    }

    /// Same-protocol request passthrough test.
    /// anthropic ingress → anthropic lane (ingress_protocol="anthropic") → mock receives body with model rewritten, NO translation applied.
    #[tokio::test]
    async fn test_same_protocol_anthropic_passthrough() {
        let state = Arc::new(MockServerState::new());

        // Mock will receive the anthropic body as-is (with model rewritten) and return 200
        state.push(MockResponse::Ok {
            status: StatusCode::OK,
            body: json!({ "content": ["ok"], "model": "m", "stop": [] }),
        });

        let server = MockServer::new(state.clone()).await;

        let app = TestApp::new()
            .lane(
                LaneSpec::new("m", crate::proto::Protocol::anthropic(), &server.base_url())
                    .provider("anthropic")
                    .api_key("test-key"),
            )
            .build();

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

        let app = TestApp::new()
            .lane(
                LaneSpec::new("m", crate::proto::Protocol::openai(), &server.base_url())
                    .provider("openai-provider"),
            )
            .build();

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

        let app = TestApp::new()
            .lane(
                LaneSpec::new("m", crate::proto::Protocol::openai(), &server.base_url())
                    .provider("openai-provider"),
            )
            .build();

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

        let mk_lane = |key: &str| {
            LaneSpec::new("m", crate::proto::Protocol::anthropic(), &server.base_url())
                .provider("anthropic")
                .api_key(key)
        };
        let app = TestApp::new()
            .lane(mk_lane("k0"))
            .lane(mk_lane("k1"))
            .build();

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
        let state = Arc::new(MockServerState::new());

        // LIFO: push success (lane 1) first, then context-length error (lane 0)
        // Lane 1 should succeed with 200.
        // Raw event payload; MockResponse::Sse adds the `data: ` SSE prefix.
        let events = vec!["event-0".to_string()];
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

        let app = TestApp::new()
            .lane(
                LaneSpec::new(
                    "small-model",
                    crate::proto::Protocol::anthropic(),
                    &server.base_url(),
                )
                .api_key("test-key-0")
                .context_max(8000), // Small context limit
            )
            .lane(
                LaneSpec::new(
                    "large-model",
                    crate::proto::Protocol::anthropic(),
                    &server.base_url(),
                )
                .api_key("test-key-1")
                .context_max(200000), // Large context limit
            )
            .pool("default", &[(0, 1), (1, 1)])
            .build();

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
        let state = Arc::new(MockServerState::new());

        // Both lanes return context-length errors (LIFO: lane 1, then lane 0)
        for _i in 0..2 {
            state.push(MockResponse::ServerError {
                status: StatusCode::BAD_REQUEST,
                body: json!({ "error": { "type": "invalid_request_error", "message": "prompt is too long: 250000 tokens > 8000 maximum" } }),
            });
        }

        let server = MockServer::new(state.clone()).await;

        let mk_lane = |key: &str| {
            LaneSpec::new(
                "model-8k",
                crate::proto::Protocol::anthropic(),
                &server.base_url(),
            )
            .api_key(key)
            .context_max(8000) // Same limit on both lanes
        };
        let app = TestApp::new()
            .lane(mk_lane("test-key-0"))
            .lane(mk_lane("test-key-1"))
            .pool("default", &[(0, 1), (1, 1)])
            .build();

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

    /// Regression (CRITICAL): a CLEAN SSE stream end records SUCCESS, not a failure. Serving several
    /// back-to-back successful streams must NOT trip the lane's breaker — the old `Poll::Ready(None)`
    /// arm recorded a spurious failure on every completed stream, tripping healthy streaming lanes.
    #[tokio::test]
    async fn test_clean_sse_end_records_success_not_failure() {
        crate::metrics::init();
        let state = Arc::new(MockServerState::new());

        // Push several clean SSE responses (each ends normally with message_stop + [DONE]).
        const STREAMS: usize = 8;
        for _ in 0..STREAMS {
            state.push(MockResponse::Sse {
                events: vec![
                    r#"{"type":"message_start"}"#.to_string(),
                    r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hi"}}"#.to_string(),
                    r#"{"type":"message_delta","usage":{"input_tokens":3,"output_tokens":2}}"#.to_string(),
                    r#"{"type":"message_stop"}"#.to_string(),
                ],
                abort_at_index: None,
            });
        }
        let server = MockServer::new(state.clone()).await;

        let app = TestApp::new()
            .lane(LaneSpec::new(
                "test-model",
                crate::proto::Protocol::anthropic(),
                &server.base_url(),
            ))
            .pool("default", &[(0, 1)])
            .build();

        use http_body_util::BodyExt as _;
        for _ in 0..STREAMS {
            let req_body = serde_json::to_vec(&json!({"model": "test-model", "stream": true, "messages": [{"role": "user", "content": "hi"}], "max_tokens": 50})).unwrap();
            let resp = forward(
                app.clone(),
                vec![crate::state::WeightedLane { idx: 0, weight: 1 }],
                req_body.into(),
                None,
                None,
            )
            .await;
            assert_eq!(resp.status().as_u16(), 200);
            // Fully drain the stream so FirstByteBody reaches Poll::Ready(None).
            let _ = resp.into_body().collect().await.unwrap().to_bytes();
        }

        let t = now();
        let snap = app.store.snapshot(0, t);
        assert_eq!(
            snap.err, 0,
            "clean SSE stream ends must NOT record breaker failures (got err={})",
            snap.err
        );
        assert_eq!(
            snap.ok, STREAMS as u64,
            "each clean stream must record exactly one success"
        );
        assert!(
            app.store.usable(0, t),
            "the lane must remain usable after {STREAMS} successful streams (not tripped)"
        );
        server.shutdown().await;
    }

    /// Regression (HIGH): an upstream 429 with `Retry-After: N` flowing through forward() must set a
    /// cooldown floor of at least N seconds on the lane. Exercises the end-to-end extraction path
    /// (header parsed in forward → RawUpstreamError.retry_after_secs → CanonicalSignal.retry_after →
    /// store cooldown floor) that no test previously covered — the header was silently dropped.
    #[tokio::test]
    async fn test_429_retry_after_header_sets_cooldown_floor() {
        crate::metrics::init();
        let state = Arc::new(MockServerState::new());
        // Single lane; a 429 with Retry-After: 45. streak=0 → computed backoff is the base (15s),
        // so a floor of 45 must dominate, proving the header was honored end-to-end.
        state.push(MockResponse::RateLimit {
            status: StatusCode::TOO_MANY_REQUESTS,
            provider_signal: None,
            retry_after: Some(45),
        });
        let server = MockServer::new(state.clone()).await;

        let app = TestApp::new()
            .lane(LaneSpec::new(
                "test-model",
                crate::proto::Protocol::anthropic(),
                &server.base_url(),
            ))
            .pool("default", &[(0, 1)])
            .build();

        let req_body = serde_json::to_vec(&json!({"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 50})).unwrap();
        let resp = forward_with_pool(
            app.clone(),
            vec![crate::state::WeightedLane { idx: 0, weight: 1 }],
            req_body.into(),
            None,
            "default",
            None,
            "anthropic",
            None,
        )
        .await;
        // Only lane was rate-limited → 503 exhaustion.
        assert_eq!(resp.status().as_u16(), 503);

        let t = now();
        let remaining = app.store.cooldown_remaining_in("default", 0, t);
        assert!(
            remaining >= 45,
            "the upstream Retry-After: 45 must set a cooldown floor of >= 45s (got {remaining}s)"
        );
        server.shutdown().await;
    }

    /// Regression (HIGH): when a lane's concurrency permits are saturated, pick_among (inside
    /// forward) must NOT spin forever — once the request deadline passes it must give up and the
    /// request must resolve (503), bounded by the failover deadline. Previously the permit-wait was
    /// an unbounded 1ms spin-loop with no deadline check (a head-of-line-blocking DoS surface).
    #[tokio::test]
    async fn test_saturated_lane_respects_deadline_no_infinite_spin() {
        crate::metrics::init();
        let state = Arc::new(MockServerState::new());
        let server = MockServer::new(state.clone()).await;

        // Single lane, max_concurrent = 1. Hold its only permit for the whole test so pick_among
        // can never acquire one.
        let app = TestApp::new()
            .lane(
                LaneSpec::new(
                    "busy-model",
                    crate::proto::Protocol::anthropic(),
                    &server.base_url(),
                )
                .max(1),
            )
            .pool("default", &[(0, 1)])
            // 1s failover deadline so the test is fast but still exercises the bounded wait.
            .failover(crate::config::FailoverCfg {
                deadline_secs: 1,
                cap: 0,
                exclusions: None,
            })
            .build();

        // Take the lane's only permit and hold it.
        let held = app.store.try_acquire(0).expect("first permit acquires");

        let req_body = serde_json::to_vec(&json!({"model": "busy-model", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 50})).unwrap();
        let started = std::time::Instant::now();
        let resp = forward_with_pool(
            app.clone(),
            vec![crate::state::WeightedLane { idx: 0, weight: 1 }],
            req_body.into(),
            None,
            "default",
            None,
            "anthropic",
            None,
        )
        .await;
        let elapsed = started.elapsed();

        // Must give up (not hang) once the deadline passes — bounded by a few seconds, not forever.
        assert_eq!(
            resp.status().as_u16(),
            503,
            "a saturated lane past its deadline must 503, not spin forever"
        );
        assert!(
            elapsed < Duration::from_secs(10),
            "pick_among must honor the deadline and not block indefinitely (took {elapsed:?})"
        );
        drop(held);
        server.shutdown().await;
    }

    /// Fixture invariant: `LaneSpec::sem()` must wire the *shared* semaphore handle into the built
    /// lane's `LaneData` (not a fresh one), so a test can observe permit acquisition/release across
    /// a request. This is the override `test_permit_lifetime_during_stream` relies on.
    #[test]
    fn test_lanespec_sem_override_is_shared() {
        let sem = Arc::new(tokio::sync::Semaphore::new(1));
        let app = TestApp::new()
            .lane(
                LaneSpec::new(
                    "m",
                    crate::proto::Protocol::anthropic(),
                    "http://127.0.0.1:0",
                )
                .max(1)
                .sem(sem.clone()),
            )
            .build();

        // The lane's runtime semaphore is the SAME handle we passed in: acquiring a permit through
        // our clone must be visible to the lane (and vice-versa).
        let permit = sem.clone().try_acquire_owned();
        assert!(permit.is_ok(), "our clone should hold the only permit");
        // With our clone holding the single permit, the lane's store-side semaphore is exhausted.
        let lane_sem = app.store.lane_semaphore(0);
        assert!(
            lane_sem.try_acquire().is_err(),
            "lane semaphore must be the shared handle (already exhausted by our clone)"
        );
        drop(permit);
        assert!(
            lane_sem.try_acquire().is_ok(),
            "releasing our clone's permit must free the shared lane semaphore"
        );
    }

    /// Fixture invariant: per-lane runtime-state setters on `LaneSpec` must actually land in the
    /// built `App` (store snapshot + lane view), so migrated tests inherit the state they ask for
    /// instead of silent zero-values.
    #[test]
    fn test_lanespec_runtime_state_setters_land_in_built_app() {
        let app = TestApp::new()
            .lane(
                LaneSpec::new(
                    "m",
                    crate::proto::Protocol::anthropic(),
                    "http://127.0.0.1:0",
                )
                .cooldown_until(now() + 600)
                .streak(3)
                .err(5)
                .context_max(8000)
                .default_max_tokens(1234),
            )
            .build();

        let snap = app.store.snapshot(0, now());
        assert_eq!(snap.streak, 3, "streak setter must propagate");
        assert_eq!(snap.err, 5, "err setter must propagate");
        assert!(
            snap.cooldown_remaining_s > 0,
            "a future cooldown_until must leave the lane in cooldown"
        );
        assert_eq!(
            app.lanes[0].context_max,
            Some(8000),
            "context_max setter must propagate to the Lane view"
        );
        assert_eq!(
            app.lanes[0].default_max_tokens,
            Some(1234),
            "default_max_tokens setter must propagate to the Lane view"
        );
    }
}
