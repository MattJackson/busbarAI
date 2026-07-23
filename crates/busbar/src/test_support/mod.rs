// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

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
    last_request_path: std::sync::Mutex<Option<String>>,
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

    /// Record the received request path (for translation / on-the-wire assertions).
    pub(crate) fn record_request_path(&self, path: &str) {
        *self.last_request_path.lock().unwrap() = Some(path.to_string());
    }

    /// Get the last received request path.
    pub(crate) fn get_last_request_path(&self) -> Option<String> {
        self.last_request_path.lock().unwrap().clone()
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

    // Record the request path for upstream-path assertions.
    state.record_request_path(parts.uri.path());

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
                // Safety: SSE_DONE_FRAME is a valid UTF-8 literal.
                result.push(
                    std::str::from_utf8(crate::proto::SSE_DONE_FRAME)
                        .unwrap()
                        .to_owned(),
                );
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
    path_base: Option<String>,
    auth: Option<String>,
    health: Option<crate::config::HealthCfg>,
    default_max_tokens: Option<u32>,
    upstream_model: Option<String>,
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
            path_base: None,
            auth: None,
            health: None,
            default_max_tokens: None,
            upstream_model: None,
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
    pub(crate) fn path_base(mut self, p: &str) -> Self {
        self.path_base = Some(p.into());
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
    pub(crate) fn upstream_model(mut self, n: &str) -> Self {
        self.upstream_model = Some(n.into());
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
        let auth = self.auth.as_deref().map(|a| match a {
            "api-key" => crate::config::ProviderAuth::ApiKey,
            "bearer" => crate::config::ProviderAuth::Bearer,
            other => panic!("unexpected test auth style in LaneSpec: {other}"),
        });
        crate::state::Lane {
            reasoning: false,
            prompt_caching: false,
            credential: crate::egress_auth::resolve(self.protocol.name(), auth),
            model: self.model.clone(),
            provider: self.provider.clone(),
            signing_host: crate::proxy::host_from_base(&self.base_url),
            base_url: self.base_url.clone(),
            api_key: self.api_key.clone(),
            protocol: self.protocol.clone(),
            max: self.max,
            error_map: std::sync::Arc::new(self.error_map.clone()),
            context_max: self.context_max,
            path: self.path.clone(),
            path_base: self.path_base.clone(),
            health: self.health.clone(),
            default_max_tokens: self.default_max_tokens,
            upstream_model: self.upstream_model.clone(),
            attempt_timeout_ms: None,
        }
    }
    fn to_lane_data(&self) -> crate::store::LaneData {
        crate::store::LaneData {
            reasoning: false,
            prompt_caching: false,
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
            upstream_model: self.upstream_model.clone(),
            attempt_timeout_ms: None,
        }
    }
}

#[allow(dead_code)]
pub(crate) struct TestApp {
    lanes: Vec<LaneSpec>,
    pools: std::collections::HashMap<String, Vec<crate::state::WeightedLane>>,
    auth: Option<std::sync::Arc<crate::auth::AuthMiddleware>>,
    governance: Option<std::sync::Arc<crate::governance::GovState>>,
    cost: Option<std::sync::Arc<crate::cost::CostModel>>,
    failover_cfg: Option<crate::config::FailoverCfg>,
    pool_runtime: std::collections::HashMap<String, crate::state::PoolRuntime>,
    fallback_pools: std::collections::HashMap<String, Vec<crate::state::WeightedLane>>,
    on_exhausted_cfgs: std::collections::HashMap<String, crate::config::OnExhausted>,
    hook_registry: std::collections::HashMap<String, crate::config::HookCfg>,
    global_hooks: Vec<String>,
    base_hook_names: std::collections::HashSet<String>,
    overlay_path: Option<std::path::PathBuf>,
    plugins_dir: Option<std::path::PathBuf>,
    plugins_cfg: Option<crate::config::PluginsCfg>,
}

#[allow(dead_code)]
impl TestApp {
    pub(crate) fn new() -> Self {
        Self {
            lanes: Vec::new(),
            pools: std::collections::HashMap::new(),
            auth: None,
            governance: None,
            cost: None,
            failover_cfg: None,
            pool_runtime: std::collections::HashMap::new(),
            fallback_pools: std::collections::HashMap::new(),
            on_exhausted_cfgs: std::collections::HashMap::new(),
            hook_registry: std::collections::HashMap::new(),
            global_hooks: Vec::new(),
            base_hook_names: std::collections::HashSet::new(),
            overlay_path: None,
            plugins_dir: None,
            plugins_cfg: None,
        }
    }

    /// Point the plugin surface at a specific directory (for the Admin API plugin catalog / install /
    /// remove / reload tests). Defaults to `plugins` when unset.
    pub(crate) fn plugins_dir(mut self, path: std::path::PathBuf) -> Self {
        self.plugins_dir = Some(path);
        self
    }
    /// Set the whole `plugins.*` posture (for install re-verification tests). Defaults to the
    /// strict disabled default.
    pub(crate) fn plugins_cfg(mut self, cfg: crate::config::PluginsCfg) -> Self {
        self.plugins_cfg = Some(cfg);
        self
    }

    /// Enable config-overlay persistence at `path` (for testing runtime-change durability).
    pub(crate) fn overlay_path(mut self, path: std::path::PathBuf) -> Self {
        self.overlay_path = Some(path);
        self
    }
    /// Register a hook definition in the `hooks:` registry (for the Admin API v1 hooks read surface).
    pub(crate) fn hook(mut self, name: &str, cfg: crate::config::HookCfg) -> Self {
        self.hook_registry.insert(name.into(), cfg);
        self
    }
    /// Register a BASE-config-defined hook (registry AND `base_hook_names`) so the API's base-hook
    /// read-only guards (register/put/patch/delete return 409) can be exercised.
    pub(crate) fn base_hook(mut self, name: &str, cfg: crate::config::HookCfg) -> Self {
        self.hook_registry.insert(name.into(), cfg);
        self.base_hook_names.insert(name.into());
        self
    }
    /// Add a name to the `global_hooks:` list (globally-wired hooks).
    pub(crate) fn global_hook(mut self, name: &str) -> Self {
        self.global_hooks.push(name.into());
        self
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
    /// Install an `AuthMiddleware` with an EMPTY chain (open front door) and the given upstream-
    /// credential mode — driving the egress credential-selection path. `Own` = the old `mode: none`;
    /// `Passthrough` = the old `mode: passthrough`. Tests needing a `tokens`-chain ingress gate should
    /// use `.auth(...)` with an explicit middleware; calling both is last-wins.
    pub(crate) fn upstream_creds(mut self, uc: crate::auth::UpstreamCreds) -> Self {
        // Struct-update from `default_none()` (empty chain, empty client_tokens) so we only override
        // the upstream-credential mode and stay forward-compatible with future `AuthCfg` fields.
        let cfg = crate::config::AuthCfg {
            upstream_credentials: uc,
            ..crate::config::AuthCfg::default_none()
        };
        self.auth = Some(std::sync::Arc::new(crate::auth::AuthMiddleware::new(&cfg)));
        self
    }
    pub(crate) fn auth(mut self, a: std::sync::Arc<crate::auth::AuthMiddleware>) -> Self {
        self.auth = Some(a);
        self
    }
    /// Install a resolved cost model (rate card / budget groups / flat fee) for tests exercising
    /// the derived-spend enforcement. Default: `CostModel::flat(1)` - no rate card, no groups,
    /// the production default 1-cent flat fee.
    pub(crate) fn cost(mut self, c: crate::cost::CostModel) -> Self {
        self.cost = Some(std::sync::Arc::new(c));
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
        let app = std::sync::Arc::new(crate::state::App {
            lanes,
            store: std::sync::Arc::new(crate::store::InMemoryStore::new(lane_data)),
            by_model,
            pools: self.pools,
            client: reqwest::Client::builder().build().unwrap(),
            auth,
            rewrite_hooks: Vec::new(),
            tap_hooks: Vec::new(),
            tap_hooks_route: Vec::new(),
            tap_hooks_attempt: Vec::new(),
            tap_hooks_completion: Vec::new(),
            global_gates: Vec::new(),
            hook_registry: self.hook_registry,
            global_hooks: self.global_hooks,
            versions: std::sync::Arc::new(crate::admin::versions::VersionLog::new()),
            mutation_limiter: std::sync::Arc::new(crate::admin::rate::MutationLimiter::new()),
            idempotency_cache: std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::HashMap::new(),
            )),
            base_hook_names: self.base_hook_names,
            admin_chain: vec!["admin-tokens".to_string()],
            credential_cache: std::sync::Arc::new(crate::auth_cache::CredentialCache::new()),
            auth_scope_caps: std::collections::HashMap::new(),
            role_bindings: crate::config::RoleBindings::new(),
            config_path: None,
            providers_path: None,
            overlay_path: self.overlay_path,
            config_version: 0,
            failover_cfg: self.failover_cfg,
            pool_runtime: self.pool_runtime,
            fallback_pools: self.fallback_pools,
            on_exhausted_cfgs: self.on_exhausted_cfgs,
            governance: self.governance,
            secret_resolver: std::sync::Arc::new(
                crate::config::secret::SecretResolver::builtins_only(),
            ),
            cost: self
                .cost
                .unwrap_or_else(|| std::sync::Arc::new(crate::cost::CostModel::flat(1))),
            plugins_dir: self
                .plugins_dir
                .unwrap_or_else(|| std::path::PathBuf::from("plugins")),
            plugins_cfg: self.plugins_cfg.unwrap_or_default(),
            default_max_tokens: crate::config::DEFAULT_DEFAULT_MAX_TOKENS,
            reasoning_effort_budgets: [1024, 4096, 8192, 16384],
        });
        // Mirror main's boot-version floor so rollback tests have a v0 to restore.
        app.versions
            .record(0, "system", "boot", &app.hook_registry, &app.global_hooks);
        app
    }
}

/// THE METRICS RECORDER HARNESS: sum every exposition sample of `name` whose label set contains
/// ALL the given `key="value"` pairs, read from a fresh scrape of the process-global recorder
/// (`metrics::init` + `render` internally — callers never touch the recorder directly).
///
/// The global recorder is shared by every test in the process, so absolute values are meaningless;
/// assert STRICT DELTAS across the action under test (`before`/`after`), and give the test its own
/// pool/lane label values so parallel tests can't contribute to the matched sample. Matching is by
/// exact metric name (the char after the name must open the label set / value, so a name never
/// matches a longer neighbor it happens to prefix).
pub(crate) fn metric_sum(name: &str, labels: &[(&str, &str)]) -> f64 {
    crate::metrics::init();
    let frags: Vec<String> = labels.iter().map(|(k, v)| format!("{k}=\"{v}\"")).collect();
    crate::metrics::render()
        .lines()
        .filter(|l| {
            l.strip_prefix(name)
                .is_some_and(|rest| rest.starts_with('{') || rest.starts_with(' '))
        })
        .filter(|l| frags.iter().all(|f| l.contains(f.as_str())))
        .filter_map(|l| l.rsplit(' ').next())
        .filter_map(|v| v.trim().parse::<f64>().ok())
        .sum()
}

fn weighted(members: &[(usize, u32)]) -> Vec<crate::state::WeightedLane> {
    members
        .iter()
        .map(|&(idx, weight)| crate::state::WeightedLane {
            reasoning: None,
            idx,
            weight,
            attempt_timeout_ms: None,
        })
        .collect()
}

#[cfg(test)]
#[path = "tests/tests.rs"]
mod tests;
