// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::{body::Body, http::header::CONTENT_TYPE, response::IntoResponse, response::Response};
use bytes::Bytes;
use futures::Stream;
use reqwest::StatusCode;
use serde_json::Value;

use crate::breaker::{classify as classify_disposition, normalize_raw_error, Disposition};
use crate::config::OnExhausted;
use crate::proto::{convert_headers, StatusClass};
use crate::state::{App, WeightedLane};
use crate::store::{now, Permit};

/// Non-buffering stream inspection tap for Anthropic SSE usage parsing.
///
/// This accumulator extracts the final `message_delta` / `message_stop` usage object
/// from a streaming Anthropic response without buffering the entire body. It maintains
/// only small parsed fields and a bounded carry buffer for frame reassembly across chunks.
#[derive(Debug, Clone, Default)]
pub(crate) struct UsageTap {
    /// Extracted input tokens (from message_delta.usage.input_tokens or message_stop.usage.input_tokens)
    pub input_tokens: Option<u64>,
    /// Extracted output tokens (from message_delta.usage.output_tokens or message_stop.usage.output_tokens)
    pub output_tokens: Option<u64>,
    /// Extracted cache_creation_input_tokens if present in usage object
    pub cache_creation_input_tokens: Option<u64>,
    /// Extracted cache_read_input_tokens if present in usage object
    pub cache_read_input_tokens: Option<u64>,
    /// Terminal error frame captured from message_delta or message_stop
    pub terminal_error: Option<String>,
}

impl UsageTap {
    /// Create a new empty tap
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Feed a chunk to the tap and extract any usage fields.
    ///
    /// This is a bounded operation: it only scans for JSON objects within each chunk,
    /// never accumulating more than the carry buffer size (MAX_CARRY_BYTES).
    pub(crate) fn feed(&mut self, chunk: &Bytes) {
        let mut pos = 0;
        while pos < chunk.len() {
            if let Some(delta_idx) = find_json_start(&chunk[pos..]) {
                let start = pos + delta_idx;
                if let Some(end) = find_matching_brace(&chunk[start..]) {
                    let json_bytes = &chunk[start..start + end];
                    if let Ok(obj) = serde_json::from_slice::<Value>(json_bytes) {
                        self.extract_usage_from_delta(&obj);
                        self.extract_usage_from_stop(&obj);
                        self.extract_usage_any(&obj);
                    }
                    pos = start + end;
                } else {
                    break;
                }
            } else {
                break;
            }
        }
    }

    /// Extract usage fields from a message_delta event object.
    fn extract_usage_from_delta(&mut self, obj: &Value) {
        if obj.get("type").and_then(|t| t.as_str()) != Some("message_delta") {
            return;
        }
        let usage = obj.get("usage");
        if let Some(u) = usage {
            if let Some(v) = u.get("input_tokens").and_then(|v| v.as_u64()) {
                self.input_tokens = Some(v);
            }
            if let Some(v) = u.get("output_tokens").and_then(|v| v.as_u64()) {
                self.output_tokens = Some(v);
            }
            if let Some(v) = u
                .get("cache_creation_input_tokens")
                .and_then(|v| v.as_u64())
            {
                self.cache_creation_input_tokens = Some(v);
            }
            if let Some(v) = u.get("cache_read_input_tokens").and_then(|v| v.as_u64()) {
                self.cache_read_input_tokens = Some(v);
            }
        }
        // Capture terminal error from message_delta.reason if present
        if let Some(reason) = obj.get("delta").and_then(|d| d.get("stop_reason")) {
            if reason.is_string() || reason.is_null() {
                self.terminal_error = reason.as_str().map(String::from);
            }
        }
    }

    /// Extract usage fields from a message_stop event object (fallback).
    fn extract_usage_from_stop(&mut self, obj: &Value) {
        if obj.get("type").and_then(|t| t.as_str()) != Some("message_stop") {
            return;
        }
        let usage = obj.get("usage");
        if let Some(u) = usage {
            if let Some(v) = u.get("input_tokens").and_then(|v| v.as_u64()) {
                self.input_tokens = Some(v);
            }
            if let Some(v) = u.get("output_tokens").and_then(|v| v.as_u64()) {
                self.output_tokens = Some(v);
            }
            if let Some(v) = u
                .get("cache_creation_input_tokens")
                .and_then(|v| v.as_u64())
            {
                self.cache_creation_input_tokens = Some(v);
            }
            if let Some(v) = u.get("cache_read_input_tokens").and_then(|v| v.as_u64()) {
                self.cache_read_input_tokens = Some(v);
            }
        }
    }

    /// Protocol-agnostic usage extraction: recognizes the `usage` / `usageMetadata` shapes across
    /// all wire protocols, in both streamed final frames and whole non-stream bodies. This is what
    /// makes token-based budget accounting work for every protocol (not just Anthropic SSE).
    ///   - Anthropic / OpenAI Responses: usage.input_tokens / output_tokens
    ///   - OpenAI chat completions:       usage.prompt_tokens / completion_tokens
    ///   - AWS Bedrock (Converse):        usage.inputTokens / outputTokens
    ///   - Google Gemini:                 usageMetadata.promptTokenCount / candidatesTokenCount
    fn extract_usage_any(&mut self, obj: &Value) {
        if let Some(u) = obj.get("usage") {
            for k in ["input_tokens", "prompt_tokens", "inputTokens"] {
                if let Some(v) = u.get(k).and_then(|v| v.as_u64()) {
                    self.input_tokens = Some(v);
                    break;
                }
            }
            for k in ["output_tokens", "completion_tokens", "outputTokens"] {
                if let Some(v) = u.get(k).and_then(|v| v.as_u64()) {
                    self.output_tokens = Some(v);
                    break;
                }
            }
        }
        if let Some(u) = obj.get("usageMetadata") {
            if let Some(v) = u.get("promptTokenCount").and_then(|v| v.as_u64()) {
                self.input_tokens = Some(v);
            }
            if let Some(v) = u.get("candidatesTokenCount").and_then(|v| v.as_u64()) {
                self.output_tokens = Some(v);
            }
        }
    }

    /// Check if any usage data was extracted (test-only assertion helper).
    #[cfg(test)]
    pub(crate) fn has_usage(&self) -> bool {
        self.input_tokens.is_some() || self.output_tokens.is_some()
    }
}

/// Find the start of a JSON object (opening brace) in bytes.
fn find_json_start(chunk: &[u8]) -> Option<usize> {
    chunk.iter().position(|&b| b == b'{')
}

/// Find the matching closing brace for an opening brace, returning byte offset from start.
/// Returns None if braces are unbalanced or not found.
fn find_matching_brace(chunk: &[u8]) -> Option<usize> {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escape = false;

    for (i, &b) in chunk.iter().enumerate() {
        if escape {
            escape = false;
            continue;
        }
        match b {
            b'\\' if in_string => escape = true,
            b'"' => in_string = !in_string,
            b'{' if !in_string => depth += 1,
            b'}' if !in_string => {
                depth -= 1;
                if depth == 0 {
                    return Some(i + 1);
                }
            }
            // All other byte values don't affect brace matching
            _other => {}
        }
    }
    None
}

/// Body wrapper that implements the before-first-byte failover boundary.
/// Tracks when the first byte is sent and handles mid-stream errors by emitting
/// SSE error events instead of allowing failover. Also holds the permit until stream ends.
///
/// Where to charge a request's token usage when its response stream completes (the resolved virtual
/// key + its budget period + the governance store). `None` when governance is off or no key resolved.
pub(crate) struct UsageSink {
    pub gov: Arc<crate::governance::GovState>,
    pub key_id: String,
    pub period: String,
}

/// Integrated UsageTap for non-buffering usage extraction from streaming responses.
struct FirstByteBody<S, P> {
    inner: S,
    first_byte_sent: Arc<AtomicBool>,
    is_sse: bool,
    permit: Option<P>,
    app: Option<Arc<App>>,
    lane_idx: usize,
    /// Resolved breaker config for the routing pool, so a mid-stream failure trips this lane using
    /// the same thresholds the synchronous path used (defaults on the degraded path).
    breaker_cfg: Arc<crate::store::BreakerCfg>,
    /// Routing pool name, so a mid-stream failure trips this lane's per-pool breaker cell (empty on
    /// the degraded path → the lane-default cell).
    pool: Box<str>,
    /// Usage tap for extracting Anthropic SSE usage without buffering full body
    tap: UsageTap,
    /// when Some, translate each egress SSE chunk to the caller's ingress protocol.
    /// None = native passthrough (same-protocol or non-SSE).
    translate: Option<crate::proto::StreamTranslate>,
    /// When set, the token usage tapped from this response is charged to a virtual key's budget at
    /// stream end (token-accurate accounting). Taken (fired) exactly once when the stream completes.
    usage_sink: Option<UsageSink>,
    /// Set once the stream has fully ended (after any translation terminator), so a later poll
    /// returns None instead of re-polling a finished inner stream.
    ended: bool,
}

impl<S, P> FirstByteBody<S, P>
where
    S: Stream<Item = Result<Bytes, reqwest::Error>> + Send + 'static,
{
    #[allow(clippy::too_many_arguments)]
    fn new(
        inner: S,
        is_sse: bool,
        permit: P,
        app: Arc<App>,
        lane_idx: usize,
        breaker_cfg: Arc<crate::store::BreakerCfg>,
        pool: &str,
        translate: Option<crate::proto::StreamTranslate>,
        usage_sink: Option<UsageSink>,
    ) -> Self {
        Self {
            inner,
            first_byte_sent: Arc::new(AtomicBool::new(false)),
            is_sse,
            permit: Some(permit),
            app: Some(app),
            lane_idx,
            breaker_cfg,
            pool: Box::from(pool),
            tap: UsageTap::new(),
            translate,
            usage_sink,
            ended: false,
        }
    }
}

impl<S, P> Stream for FirstByteBody<S, P>
where
    S: Stream<Item = Result<Bytes, reqwest::Error>> + Unpin + Send + 'static,
    P: Send + Unpin + 'static,
{
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.ended {
            return Poll::Ready(None);
        }
        // Loop so a translated chunk that yields no complete frame yet (partial) re-polls the
        // inner stream instead of emitting an empty chunk to the client.
        loop {
            match Pin::new(&mut this.inner).poll_next(cx) {
                Poll::Ready(Some(Ok(chunk))) => {
                    if !this.first_byte_sent.load(Ordering::Relaxed) {
                        this.first_byte_sent.store(true, Ordering::Relaxed);
                    }
                    // Feed chunk to tap for usage extraction (non-buffering)
                    this.tap.feed(&chunk);
                    // cross-protocol → translate egress SSE bytes to the ingress format.
                    if let Some(t) = this.translate.as_mut() {
                        let out = t.feed(&chunk);
                        if out.is_empty() {
                            continue; // only a partial frame buffered; poll inner again
                        }
                        return Poll::Ready(Some(Ok(Bytes::from(out))));
                    }
                    return Poll::Ready(Some(Ok(chunk)));
                }
                Poll::Ready(Some(Err(e))) => {
                    let had_first = this.first_byte_sent.load(Ordering::Relaxed);
                    if had_first && this.is_sse {
                        // Mid-stream failure after first byte in SSE mode: record breaker failure then emit SSE error event
                        if let Some(ref app) = this.app {
                            app.store.record_transient_in(
                                &this.pool,
                                this.lane_idx,
                                "mid-stream",
                                &this.breaker_cfg,
                                None,
                            );
                        }
                        let err_json = serde_json::json!({
                            "type": "error",
                            "error": {
                                "message": e.to_string(),
                                "source": "upstream"
                            }
                        });
                        let sse_error = format!("event: error\ndata: {}\n\n", err_json);
                        return Poll::Ready(Some(Ok(Bytes::from(sse_error))));
                    } else {
                        // Before first byte or non-SSE: propagate error (allows failover at caller level)
                        return Poll::Ready(Some(Err(std::io::Error::other(e.to_string()))));
                    }
                }
                Poll::Ready(None) => {
                    // Stream ended - for SSE streams that sent at least one byte, record the failure
                    if this.is_sse && this.first_byte_sent.load(Ordering::Relaxed) {
                        if let Some(ref app) = this.app {
                            app.store.record_transient_in(
                                &this.pool,
                                this.lane_idx,
                                "mid-stream-end",
                                &this.breaker_cfg,
                                None,
                            );
                        }
                    }
                    // emit the ingress terminator (e.g. OpenAI `data: [DONE]`) before close.
                    let done = this
                        .translate
                        .as_mut()
                        .map(|t| t.finish())
                        .unwrap_or_default();
                    drop(this.permit.take());
                    this.ended = true;
                    // Charge this request's token usage to the virtual key's budget (once).
                    if let Some(sink) = this.usage_sink.take() {
                        let tokens = this.tap.input_tokens.unwrap_or(0)
                            + this.tap.output_tokens.unwrap_or(0);
                        sink.gov
                            .record_tokens(&sink.key_id, &sink.period, now(), tokens);
                    }
                    if !done.is_empty() {
                        return Poll::Ready(Some(Ok(Bytes::from(done))));
                    }
                    return Poll::Ready(None);
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S, P> FirstByteBody<S, P> {
    fn into_body(self) -> Body
    where
        S: Stream<Item = Result<Bytes, reqwest::Error>> + Unpin + Send + 'static,
        P: Send + Unpin + 'static,
    {
        Body::from_stream(self)
    }
}

/// Context for request lifecycle: deadline, accumulated exclusions, and visited pools.
#[derive(Debug, Clone)]
struct RequestCtx {
    /// Computed once at start; each hop checks remaining time against this.
    deadline: u64,
    /// Accumulated excluded lane indices across hops (already tried).
    excluded: std::collections::HashSet<usize>,
    /// Visited pool names for loop prevention in fallback chains (e.g., A→B→A).
    visited_pools: std::collections::HashSet<String>,
}

impl RequestCtx {
    fn new(deadline_secs: u64) -> Self {
        let start = now();
        Self {
            deadline: start.saturating_add(deadline_secs),
            excluded: std::collections::HashSet::new(),
            visited_pools: std::collections::HashSet::new(),
        }
    }

    /// Check if deadline has been exceeded.
    fn expired(&self, now: u64) -> bool {
        now >= self.deadline
    }

    /// Remaining time until deadline in seconds.
    fn remaining(&self, now: u64) -> u64 {
        self.deadline.saturating_sub(now)
    }

    /// Add a lane to the exclusion set (mark as already tried).
    fn exclude(&mut self, idx: usize) {
        self.excluded.insert(idx);
    }

    /// Get candidate indices minus exclusions.
    fn filter_candidates<'a>(&self, cands: &'a [WeightedLane]) -> Vec<&'a WeightedLane> {
        cands
            .iter()
            .filter(|wl| !self.excluded.contains(&wl.idx))
            .collect()
    }

    /// Mark a pool as visited for loop prevention.
    fn mark_pool_visited(&mut self, pool_name: &str) {
        self.visited_pools.insert(pool_name.to_string());
    }

    /// Check if a pool has already been visited (loop detection).
    fn is_pool_visited(&self, pool_name: &str) -> bool {
        self.visited_pools.contains(pool_name)
    }
}

/// / /: pick_among using weighted selection (SWRR) over healthy subset.
/// `cands` is now Vec<WeightedLane> where each lane has its weight from config.
/// `request_ctx` provides accumulated exclusions to avoid retrying failed lanes.
/// `_affinity_key` enables sticky routing as a preference (not a hard constraint).
async fn pick_among(
    app: &Arc<App>,
    cands: &[WeightedLane],
    request_ctx: &mut RequestCtx,
    _affinity_key: Option<&str>,
    pool_name: &str,
) -> Option<(usize, Permit)> {
    let t = now();

    // Session affinity preference - try sticky lane first if usable (in this pool's breaker view)
    if let Some(k) = _affinity_key {
        if !cands.is_empty() {
            let mut h = DefaultHasher::new();
            k.hash(&mut h);
            let pos = (h.finish() as usize) % cands.len();
            let sticky = cands[pos].idx;

            if !request_ctx.excluded.contains(&sticky) && app.store.usable_in(pool_name, sticky, t)
            {
                if let Some(p) = app.store.try_acquire(sticky) {
                    return Some((sticky, p));
                }
            }
        }
    }

    // Filter out already-tried lanes (accumulated exclusions across hops)
    let filtered_cands = request_ctx.filter_candidates(cands);

    if filtered_cands.is_empty() {
        return None;
    }

    // Extract lane indices and weights for select_weighted call
    let candidates: Vec<usize> = filtered_cands.iter().map(|wl| wl.idx).collect();
    let weights: Vec<u32> = filtered_cands.iter().map(|wl| wl.weight).collect();

    // Use SWRR selection over healthy members only (per this pool's breaker cells)
    let picked_lane_idx = app
        .store
        .select_weighted_in(pool_name, &candidates, &weights, t)?;

    // Try to acquire the selected lane immediately
    if let Some(p) = app.store.try_acquire(picked_lane_idx) {
        return Some((picked_lane_idx, p));
    }

    // If acquisition fails, await until first free (concurrency-aware fallback)
    loop {
        if let Some(p) = app.store.try_acquire(picked_lane_idx) {
            return Some((picked_lane_idx, p));
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(1)).await;
    }
}

/// Original forward function without pool context - uses default Status503 mode.
/// True for content types that carry an incremental streamed response: SSE (text/event-stream,
/// used by Anthropic/OpenAI/Gemini-SSE) and AWS event-stream (Bedrock ConverseStream,). Both
/// must engage the streaming body path rather than being buffered.
fn is_streaming_content_type(ct: &str) -> bool {
    ct.starts_with("text/event-stream") || ct.starts_with("application/vnd.amazon.eventstream")
}

/// extract the host (no scheme, no trailing slash) from a base URL, for SigV4's signed `host`
/// header. base_urls are already trailing-slash-trimmed and carry no path.
pub(crate) fn host_from_base(base: &str) -> String {
    base.strip_prefix("https://")
        .or_else(|| base.strip_prefix("http://"))
        .unwrap_or(base)
        .to_string()
}

/// Build outbound auth headers for a lane. Defaults to the protocol's native auth via
/// `sign_request` (bearer for openai/anthropic/responses, `x-goog-api-key` for gemini, per-request
/// SigV4 for bedrock). When the provider declares `auth: api-key` (Azure OpenAI), send an
/// `api-key: <key>` header instead — the deployment and `?api-version=` live in the provider's
/// `path` override, so no new protocol is needed. An un-encodable key yields no auth header (the
/// upstream then rejects with 401, classified by the breaker like any other auth failure).
pub(crate) fn lane_auth_headers(
    lane: &crate::state::Lane,
    key: &str,
    ctx: &crate::proto::SigningContext,
) -> Vec<(axum::http::HeaderName, axum::http::HeaderValue)> {
    match lane.auth.as_deref() {
        Some("api-key") => match axum::http::HeaderValue::from_str(key) {
            Ok(v) => vec![(axum::http::HeaderName::from_static("api-key"), v)],
            Err(_) => Vec::new(),
        },
        _ => lane.protocol.writer().sign_request(key, ctx),
    }
}

/// Charge a non-streaming response's token usage to the virtual key's budget. The streaming path
/// taps tokens incrementally inside `FirstByteBody`; buffered (non-streaming) responses have no
/// such wrapper, so without this the per-key token counter (and any TPM limit derived from it)
/// silently stays at zero. Taps the raw upstream body, which carries the real usage in whatever
/// protocol shape the backend speaks (the same protocol-agnostic extraction the stream tap uses).
fn record_nonstream_usage(upstream_body: &[u8], usage_sink: &Option<UsageSink>) {
    if let Some(sink) = usage_sink {
        let mut tap = UsageTap::new();
        tap.feed(&Bytes::copy_from_slice(upstream_body));
        let tokens = tap.input_tokens.unwrap_or(0) + tap.output_tokens.unwrap_or(0);
        if tokens > 0 {
            sink.gov
                .record_tokens(&sink.key_id, &sink.period, now(), tokens);
        }
    }
}

pub(crate) async fn forward(
    app: Arc<App>,
    cands: Vec<WeightedLane>,
    body: Bytes,
    caller_token: Option<&str>,
    usage_sink: Option<UsageSink>,
) -> Response {
    // Empty pool name → the lane-default breaker cell (shared by all direct/ad-hoc routes and
    // surfaced by /stats and /healthz). Named pools route via forward_with_pool with their own cells.
    forward_with_pool(
        app,
        cands,
        body,
        caller_token,
        "",
        None,
        "anthropic",
        usage_sink,
    )
    .await
}

/// Forward with pool name context for on_exhausted config lookup.
// Plumbing function: each parameter is an independent request input (state, candidates, body,
// caller token, pool name, affinity key, ingress protocol, usage sink) with no natural grouping.
#[allow(clippy::too_many_arguments)]
#[tracing::instrument(
    name = "forward",
    skip_all,
    fields(pool = %pool_name, ingress = %ingress_protocol)
)]
pub(crate) async fn forward_with_pool(
    app: Arc<App>,
    cands: Vec<WeightedLane>,
    body: Bytes,
    caller_token: Option<&str>,
    pool_name: &str,
    affinity_key: Option<&str>,
    ingress_protocol: &str,
    usage_sink: Option<UsageSink>,
) -> Response {
    let mut v: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, format!("router: bad json: {e}")).into_response()
        }
    };

    // capture the caller's stream intent from the ingress body BEFORE any cross-protocol
    // translation rewrites `v` (Gemini routes streaming requests to a different upstream endpoint).
    let wants_stream = v.get("stream").and_then(|s| s.as_bool()).unwrap_or(false);

    // Derive affinity key early (before any mutations to v)
    let _affinity_key_str: Option<String> = if let Some(k) = affinity_key {
        Some(k.to_string())
    } else {
        v.get("system")
            .and_then(|s| s.as_str())
            .filter(|s| !s.is_empty())
            .map(String::from)
    };

    // Before-first-byte failover boundary:
    // Failover is allowed ONLY until the first upstream byte reaches the client.
    // After that point, an upstream failure must NOT trigger failover because
    // the client already has a partial response. Instead:
    // - For SSE streams: emit an SSE `error` event and terminate the stream
    // - Record the breaker failure for that lane (the member tripped)
    // The client must restart the request itself after receiving the error event.

    // Failover config: prefer this pool's own settings, fall back to the global default.
    let pool_failover = app
        .pool_runtime
        .get(pool_name)
        .and_then(|r| r.failover.as_ref())
        .or(app.failover_cfg.as_ref());
    let (deadline_secs, max_cap) = match pool_failover {
        Some(f) => (f.deadline_secs, f.cap),
        None => (120, 3), // defaults: deadline_s=120, max_failover=3
    };

    // Breaker config: prefer this pool's own settings, fall back to ADR-0002 defaults. Resolved
    // once and shared (Arc) so the streaming guard can record mid-stream failures with the same
    // thresholds the synchronous path used.
    let breaker_cfg: std::sync::Arc<crate::store::BreakerCfg> = std::sync::Arc::new(
        app.pool_runtime
            .get(pool_name)
            .and_then(|r| r.breaker.clone())
            .unwrap_or_default(),
    );

    let mut request_ctx = RequestCtx::new(deadline_secs);

    // Apply configured failover exclusions: members named here are excluded from this pool's
    // candidate set (never selected, primary or failover) — a per-pool member blocklist.
    if let Some(excl) = pool_failover.and_then(|f| f.exclusions.as_ref()) {
        for wl in &cands {
            if excl.iter().any(|m| m == &app.lanes[wl.idx].model) {
                request_ctx.exclude(wl.idx);
            }
        }
    }

    for _attempt in 0..=max_cap {
        // Check deadline first (propagated across hops)
        if request_ctx.expired(now()) {
            return (StatusCode::SERVICE_UNAVAILABLE, "router: deadline exceeded").into_response();
        }

        let (i, permit) = match pick_among(
            &app,
            &cands,
            &mut request_ctx,
            _affinity_key_str.as_deref(),
            pool_name,
        )
        .await
        {
            Some(x) => x,
            None => {
                if cands.is_empty() {
                    // Pool has no members at all — nothing to do.
                    return (StatusCode::SERVICE_UNAVAILABLE, "router: no usable lane")
                        .into_response();
                }
                // No usable lane — whether the members were tripped before this request
                // arrived or excluded during its failover attempts, apply the configured
                // exhaustion mode (Status503 / FallbackPool / LeastBad) with loop prevention.
                return handle_exhaustion_for_pool(
                    app.clone(),
                    &cands,
                    now(),
                    pool_name,
                    body,
                    caller_token,
                    &mut request_ctx,
                )
                .await;
            }
        };

        // Mark this lane as excluded for future attempts in this request
        request_ctx.exclude(i);

        // count this upstream attempt (re-entrant across failover hops — each is a real attempt).
        metrics::counter!(
            crate::metrics::UPSTREAM_ATTEMPTS_TOTAL,
            "pool" => pool_name.to_string(),
            "lane" => app.lanes[i].model.clone()
        )
        .increment(1);
        tracing::debug!(pool = %pool_name, lane = %app.lanes[i].model, "upstream attempt");

        let egress_name = app.lanes[i].protocol.name();
        if ingress_protocol != egress_name {
            // one cross-protocol translation hop for this request.
            metrics::counter!(
                crate::metrics::TRANSLATIONS_TOTAL,
                "from" => ingress_protocol.to_string(),
                "to" => egress_name.to_string()
            )
            .increment(1);
            // Cross-protocol: translate the request body through the superset IR.
            let Some(ingress_proto) = crate::proto::protocol_for(ingress_protocol) else {
                return (
                    StatusCode::BAD_REQUEST,
                    format!("router: unknown ingress protocol '{ingress_protocol}'"),
                )
                    .into_response();
            };
            match ingress_proto.reader().read_request(&v) {
                Ok(ir) => {
                    v = app.lanes[i].protocol.writer().write_request(&ir);
                }
                Err(_) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        "router: request translation failed",
                    )
                        .into_response();
                }
            }
        }
        // existing rewrite_model sets the lane's model on the (possibly translated) body:
        app.lanes[i]
            .protocol
            .writer()
            .rewrite_model(&mut v, &app.lanes[i].model);
        let payload = serde_json::to_vec(&v).unwrap();
        let base = &app.lanes[i].base_url;

        // Mode-aware key selection: passthrough uses caller token, others use lane's api_key
        let key = match app.auth_mode {
            crate::auth::AuthMode::Passthrough => caller_token.unwrap_or(&app.lanes[i].api_key),
            crate::auth::AuthMode::Token | crate::auth::AuthMode::None => &app.lanes[i].api_key,
        };

        // per-request auth (SigV4 for Bedrock; static for others) needs the host/path/body.
        let writer = app.lanes[i].protocol.writer();
        let url_path = match &app.lanes[i].path {
            // Provider-configured path override (e.g. version-in-base-url providers).
            Some(p) => p.clone(),
            None => writer.upstream_path_for_stream(&app.lanes[i].model, wants_stream),
        };
        let signing_ctx = crate::proto::SigningContext {
            host: host_from_base(base),
            canonical_uri: crate::sigv4::uri_encode_path(
                url_path.split('?').next().unwrap_or(&url_path),
            ),
            body: &payload,
            timestamp_epoch: now(),
        };
        let auth = lane_auth_headers(&app.lanes[i], key, &signing_ctx);

        let res = app
            .client
            .post(format!("{base}{url_path}"))
            .headers(convert_headers(auth))
            .header(CONTENT_TYPE, "application/json")
            .timeout(std::time::Duration::from_secs(
                request_ctx.remaining(now()).max(1),
            )) // min 1s timeout
            .body(payload)
            .send()
            .await;

        match res {
            Err(e) => {
                // Pre-response error: classify and potentially failover
                let err_type = if e.is_timeout() { "timeout" } else { "connect" };
                app.store
                    .record_transient_in(pool_name, i, err_type, &breaker_cfg, None);
                metrics::counter!(
                    crate::metrics::UPSTREAM_FAILURES_TOTAL,
                    "pool" => pool_name.to_string(),
                    "lane" => app.lanes[i].model.clone(),
                    "disposition" => "transient_upstream"
                )
                .increment(1);
                metrics::counter!(
                    crate::metrics::FAILOVERS_TOTAL,
                    "pool" => pool_name.to_string(),
                    "reason" => err_type.to_string()
                )
                .increment(1);
                drop(permit);
                continue;
            }
            Ok(r) => {
                let status = r.status();

                // For non-2xx responses, read the body to classify (failover allowed)
                if !status.is_success() {
                    // caveat: passthrough 401/403 is caller's key failing, not busbar's
                    // Do NOT trip breaker / change member health; relay verbatim to caller
                    let auth_mode = app.auth_mode;
                    let is_passthrough_40x = auth_mode == crate::auth::AuthMode::Passthrough
                        && (status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN);

                    // Clone headers before consuming r with bytes()
                    let ct = r.headers().get(CONTENT_TYPE).cloned();
                    let bytes = r.bytes().await.unwrap_or_default();

                    if is_passthrough_40x {
                        use axum::body::Body;
                        let mut rb = Response::builder().status(status);
                        if let Some(ct) = ct {
                            rb = rb.header(CONTENT_TYPE, ct);
                        }
                        // Re-create response from bytes for passthrough relay
                        return rb.body(Body::from(bytes)).unwrap();
                    }

                    // Two-stage pipeline: Stage 1a (proto.extract_error) → RawUpstreamError
                    //                     Stage 1b (normalize_raw_error + error_map) → CanonicalSignal
                    //                     Stage 2 (breaker::classify_disposition) → Disposition
                    let raw = app.lanes[i].protocol.reader().extract_error(status, &bytes);
                    let sig = normalize_raw_error(&raw, &app.lanes[i].error_map);
                    let disposition = classify_disposition(&sig);

                    // Exhaustive match on Disposition - NO _ => allowed per requirements
                    match disposition {
                        Disposition::ClientFault => {
                            // ADR-0002: Client fault (caller's bad input) → relay verbatim, no penalty
                            // Track client_fault separately from upstream err
                            app.store.record_client_fault(i);
                            use axum::body::Body;
                            let mut rb = Response::builder().status(status);
                            if let Some(ct) = ct {
                                rb = rb.header(CONTENT_TYPE, ct);
                            }
                            return rb.body(Body::from(bytes)).unwrap();
                        }
                        Disposition::TransientUpstream => {
                            // Transient upstream failure → cooldown + err counter
                            // Record based on specific error type (exhaustive over remaining variants)
                            if matches!(sig.class, StatusClass::RateLimit) {
                                app.store.record_rate_limit_in(
                                    pool_name,
                                    i,
                                    now(),
                                    &breaker_cfg,
                                    sig.retry_after,
                                );
                            } else {
                                let what = match sig.class {
                                    StatusClass::ServerError => "5xx",
                                    StatusClass::Timeout => "timeout",
                                    StatusClass::Network => "network",
                                    StatusClass::Overloaded => "overloaded",
                                    // Exhaustive: these variants cannot reach HardDown or ClientFault arms
                                    StatusClass::Auth => unreachable!(),
                                    StatusClass::Billing => unreachable!(),
                                    StatusClass::ClientError => unreachable!(),
                                    StatusClass::ContextLength => unreachable!(),
                                    StatusClass::RateLimit => {
                                        // Should have been handled above but Rust needs exhaustive match
                                        "rate_limit"
                                    }
                                };
                                app.store.record_transient_in(
                                    pool_name,
                                    i,
                                    what,
                                    &breaker_cfg,
                                    sig.retry_after,
                                );
                            }
                            metrics::counter!(
                                crate::metrics::UPSTREAM_FAILURES_TOTAL,
                                "pool" => pool_name.to_string(),
                                "lane" => app.lanes[i].model.clone(),
                                "disposition" => "transient_upstream"
                            )
                            .increment(1);
                            metrics::counter!(
                                crate::metrics::FAILOVERS_TOTAL,
                                "pool" => pool_name.to_string(),
                                "reason" => "transient_upstream"
                            )
                            .increment(1);
                            drop(permit);
                            continue;
                        }
                        Disposition::HardDown => {
                            // Hard down → permanent dead state (with probe recovery per)
                            // Only Billing and Auth reach this arm per breaker::classify
                            let reason = match sig.class {
                                StatusClass::Billing => {
                                    "billing / insufficient balance".to_string()
                                }
                                StatusClass::Auth => {
                                    format!("auth rejected (HTTP {})", status.as_u16())
                                }
                                // Exhaustive: these variants cannot reach HardDown arm
                                StatusClass::RateLimit => unreachable!(),
                                StatusClass::Overloaded => unreachable!(),
                                StatusClass::ServerError => unreachable!(),
                                StatusClass::Timeout => unreachable!(),
                                StatusClass::Network => unreachable!(),
                                StatusClass::ClientError => unreachable!(),
                                StatusClass::ContextLength => unreachable!(),
                            };
                            app.store.record_hard_down_in(pool_name, i, &reason);
                            // a hard-down is a breaker trip for this lane.
                            metrics::counter!(
                                crate::metrics::BREAKER_TRIPS_TOTAL,
                                "pool" => pool_name.to_string(),
                                "lane" => app.lanes[i].model.clone()
                            )
                            .increment(1);
                            tracing::warn!(pool = %pool_name, lane = %app.lanes[i].model, reason = %reason, "lane hard-down (breaker trip)");
                            metrics::counter!(
                                crate::metrics::UPSTREAM_FAILURES_TOTAL,
                                "pool" => pool_name.to_string(),
                                "lane" => app.lanes[i].model.clone(),
                                "disposition" => "hard_down"
                            )
                            .increment(1);
                            drop(permit);

                            // For auth failures: return error to caller
                            if matches!(sig.class, StatusClass::Auth) {
                                use axum::body::Body;
                                let mut rb = Response::builder().status(status);
                                if let Some(ct) = ct {
                                    rb = rb.header(CONTENT_TYPE, ct);
                                }
                                return rb.body(Body::from(bytes)).unwrap();
                            }

                            // For billing hard downs: continue to next lane (failover)
                            metrics::counter!(
                                crate::metrics::FAILOVERS_TOTAL,
                                "pool" => pool_name.to_string(),
                                "reason" => "hard_down"
                            )
                            .increment(1);
                            continue;
                        }
                        Disposition::ContextLength => {
                            // the request is too large for THIS model's context window.
                            // exclude from this request any candidate lane whose context_max
                            // is Some(c) with c <= failed_lane_context_max (and the failed lane itself).
                            // Rationale: those lanes share or undercut the limit that just failed,
                            // so don't waste attempts on them — failover lands on a larger-context
                            // (or unknown-context) member. If failed lane's context_max is None,
                            // exclude only the failed lane.
                            let failed_context_max = app.lanes[i].context_max;

                            // Exclude candidates that cannot handle this request due to context limits.
                            for cand in &cands {
                                if let Some(cand_context_max) = app.lanes[cand.idx].context_max {
                                    // If this candidate has a known limit <= failed lane's limit, exclude it.
                                    if let Some(failed_limit) = failed_context_max {
                                        if cand_context_max <= failed_limit {
                                            request_ctx.exclude(cand.idx);
                                        }
                                    }
                                }
                            }

                            metrics::counter!(
                                crate::metrics::UPSTREAM_FAILURES_TOTAL,
                                "pool" => pool_name.to_string(),
                                "lane" => app.lanes[i].model.clone(),
                                "disposition" => "context_length"
                            )
                            .increment(1);
                            metrics::counter!(
                                crate::metrics::FAILOVERS_TOTAL,
                                "pool" => pool_name.to_string(),
                                "reason" => "context_length"
                            )
                            .increment(1);
                            drop(permit);
                            continue;
                        }
                    }
                }

                // SUCCESS case: the upstream served a 2xx. Record the success for this lane (feeds
                // the per-lane `ok` counter and the breaker's success window) and consume one unit
                // of its lifetime request budget (the `max_requests` cost cap; `usable()` stops
                // admitting the lane once it reaches 0).
                app.store.record_success_in(pool_name, i);
                app.store.spend_budget(i);

                // stream the response body incrementally with first-byte boundary tracking
                let ct = r.headers().get(CONTENT_TYPE).cloned();
                let is_sse = ct
                    .as_ref()
                    .map(|h| is_streaming_content_type(h.to_str().unwrap_or("")))
                    .unwrap_or(false);

                // non-streaming cross-protocol response → buffer the whole JSON and
                // translate egress.read_response → IR → ingress.write_response. (Streaming
                // cross-protocol is handled in FirstByteBody below; same-protocol passes through.)
                if ingress_protocol != app.lanes[i].protocol.name() && !is_sse {
                    let bytes = r.bytes().await.unwrap_or_default();
                    drop(permit); // upstream call complete; a non-streamed response holds no permit
                                  // Token accounting: no FirstByteBody on this buffered path, so tap here.
                    record_nonstream_usage(&bytes, &usage_sink);
                    if let Ok(v) = serde_json::from_slice::<Value>(&bytes) {
                        if let Ok(ir) = app.lanes[i].protocol.reader().read_response(&v) {
                            if let Some(ingress_proto) =
                                crate::proto::protocol_for(ingress_protocol)
                            {
                                let translated = ingress_proto.writer().write_response(&ir);
                                return Response::builder()
                                    .status(status)
                                    .header(CONTENT_TYPE, "application/json")
                                    .body(Body::from(translated.to_string()))
                                    .unwrap();
                            }
                        }
                    }
                    // Not translatable (non-JSON / unexpected shape / unknown ingress): relay verbatim.
                    let mut rb = Response::builder().status(status);
                    if let Some(ct) = ct {
                        rb = rb.header(CONTENT_TYPE, ct);
                    }
                    return rb.body(Body::from(bytes)).unwrap();
                }

                // Use FirstByteBody wrapper to track first byte and emit SSE error events on mid-stream failures
                // on a cross-protocol SSE response, translate egress frames → ingress frames.
                let translate = if is_sse {
                    crate::proto::StreamTranslate::new(
                        ingress_protocol,
                        app.lanes[i].protocol.name(),
                    )
                } else {
                    None
                };
                let upstream_stream = r.bytes_stream();
                let guarded_body = FirstByteBody::new(
                    upstream_stream,
                    is_sse,
                    permit,
                    app.clone(),
                    i,
                    breaker_cfg.clone(),
                    pool_name,
                    translate,
                    usage_sink,
                );
                let axum_body = guarded_body.into_body();

                let mut rb = Response::builder().status(status);
                if let Some(ct) = ct {
                    rb = rb.header(CONTENT_TYPE, ct);
                }
                return rb.body(axum_body).unwrap();
            }
        }
    }

    handle_exhaustion_for_pool(
        app.clone(),
        &cands,
        now(),
        pool_name,
        body,
        caller_token,
        &mut request_ctx,
    )
    .await
}

/// Find the lane index with the soonest cooldown expiry among candidates.
fn find_soonest_cooldown(
    store: &Arc<dyn crate::store::StateStore>,
    cands: &[WeightedLane],
    now: u64,
    pool: &str,
) -> Option<usize> {
    let mut soonest_idx = None;
    let mut soonest_remaining = u64::MAX;

    for wl in cands {
        let remaining = store.cooldown_remaining_in(pool, wl.idx, now);
        if remaining < soonest_remaining {
            soonest_remaining = remaining;
            soonest_idx = Some(wl.idx);
        }
    }

    soonest_idx
}

/// Handle pool exhaustion based on configured mode for a specific pool.
async fn handle_exhaustion_for_pool(
    app: Arc<App>,
    cands: &[WeightedLane],
    now: u64,
    pool_name: &str,
    body: Bytes,
    caller_token: Option<&str>,
    request_ctx: &mut RequestCtx,
) -> Response {
    // Look up pool-specific on_exhausted config, default to Status503 for unknown pools.
    let mode = app
        .on_exhausted_cfgs
        .get(pool_name)
        .cloned()
        .unwrap_or(OnExhausted::Status503);

    match mode {
        OnExhausted::Status503 => handle_status_503(&app, cands, now, pool_name),
        OnExhausted::FallbackPool(ref fallback_pool) => {
            handle_fallback_pool(app.clone(), body, caller_token, fallback_pool, request_ctx).await
        }
        OnExhausted::LeastBad => {
            handle_least_bad(
                &app,
                cands,
                now,
                &body,
                caller_token,
                request_ctx,
                pool_name,
            )
            .await
        }
    }
}

/// Status503 mode: return 503 with Retry-After header.
fn handle_status_503(app: &Arc<App>, cands: &[WeightedLane], now: u64, pool: &str) -> Response {
    let soonest_remaining = find_soonest_cooldown(&app.store, cands, now, pool)
        .map(|idx| app.store.cooldown_remaining_in(pool, idx, now))
        .unwrap_or(1);

    let retry_after = soonest_remaining.max(1); // Ensure at least 1 second

    (
        StatusCode::SERVICE_UNAVAILABLE,
        [
            (axum::http::header::RETRY_AFTER, retry_after.to_string()),
            (axum::http::header::CONTENT_TYPE, "text/plain".to_string()),
        ],
        format!("router: all lanes exhausted; retry after {}s", retry_after),
    )
        .into_response()
}

/// Forward one request to a specific lane and relay the response. Shared by the degraded
/// last-resort exhaustion paths (FallbackPool routing + LeastBad). Unlike the main forward
/// loop these paths do NOT apply breaker disposition/failover classification — they relay
/// whatever the upstream returns verbatim. On a pre-response transport error the lane's
/// transient counter is recorded and `Err(())` is returned so the caller can try another
/// candidate (or give up). The concurrency `permit` is held for the lifetime of a streamed
/// success body (invariant) and dropped on error.
/// NOTE: Cross-protocol request translation on this degraded path is deferred to.
#[tracing::instrument(name = "forward_once", skip_all, fields(lane = i))]
async fn forward_once(
    app: &Arc<App>,
    i: usize,
    permit: Permit,
    body: &Bytes,
    caller_token: Option<&str>,
    timeout_secs: u64,
) -> Result<Response, ()> {
    // Re-parse body for per-lane model rewriting.
    let mut v: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => {
            return Ok((StatusCode::BAD_REQUEST, format!("router: bad json: {e}")).into_response());
        }
    };

    // stream intent for the stream-aware upstream path (Gemini).
    let wants_stream = v.get("stream").and_then(|s| s.as_bool()).unwrap_or(false);

    app.lanes[i]
        .protocol
        .writer()
        .rewrite_model(&mut v, &app.lanes[i].model);
    let payload = serde_json::to_vec(&v).unwrap();
    let base = &app.lanes[i].base_url;

    // Mode-aware key selection: passthrough uses caller token, others use lane's api_key.
    let key = match app.auth_mode {
        crate::auth::AuthMode::Passthrough => caller_token.unwrap_or(&app.lanes[i].api_key),
        crate::auth::AuthMode::Token | crate::auth::AuthMode::None => &app.lanes[i].api_key,
    };

    // per-request auth (SigV4 for Bedrock; static otherwise).
    let writer = app.lanes[i].protocol.writer();
    let url_path = match &app.lanes[i].path {
        Some(p) => p.clone(),
        None => writer.upstream_path_for_stream(&app.lanes[i].model, wants_stream),
    };
    let signing_ctx = crate::proto::SigningContext {
        host: host_from_base(base),
        canonical_uri: crate::sigv4::uri_encode_path(
            url_path.split('?').next().unwrap_or(&url_path),
        ),
        body: &payload,
        timestamp_epoch: now(),
    };
    let auth = lane_auth_headers(&app.lanes[i], key, &signing_ctx);

    let res = app
        .client
        .post(format!("{base}{url_path}"))
        .headers(convert_headers(auth))
        .header(CONTENT_TYPE, "application/json")
        .timeout(std::time::Duration::from_secs(timeout_secs.max(1)))
        .body(payload)
        .send()
        .await;

    match res {
        Ok(r) => {
            let status = r.status();
            let ct = r.headers().get(CONTENT_TYPE).cloned();

            if !status.is_success() {
                // Degraded path: relay the upstream error verbatim (no classification).
                let bytes = r.bytes().await.unwrap_or_default();
                let mut rb = Response::builder().status(status);
                if let Some(ct) = ct {
                    rb = rb.header(CONTENT_TYPE, ct);
                }
                return Ok(rb.body(Body::from(bytes)).unwrap());
            }

            // SUCCESS: stream the response body incrementally (permit held for stream life).
            let is_sse = ct
                .as_ref()
                .map(|h| is_streaming_content_type(h.to_str().unwrap_or("")))
                .unwrap_or(false);
            let upstream_stream = r.bytes_stream();
            // Degraded fallback/least-bad path: no cross-protocol translation here (scope), and no
            // pool context to resolve per-pool breaker config — use ADR-0002 defaults.
            let guarded_body = FirstByteBody::new(
                upstream_stream,
                is_sse,
                permit,
                app.clone(),
                i,
                Arc::new(crate::store::BreakerCfg::default()),
                "", // degraded path: lane-default breaker cell
                None,
                None,
            );
            let mut rb = Response::builder().status(status);
            if let Some(ct) = ct {
                rb = rb.header(CONTENT_TYPE, ct);
            }
            Ok(rb.body(guarded_body.into_body()).unwrap())
        }
        Err(e) => {
            // Pre-response transport error: record transient, drop permit, signal "try next".
            // Degraded path has no pool context — use default breaker thresholds.
            let err_type = if e.is_timeout() { "timeout" } else { "connect" };
            app.store
                .record_transient(i, err_type, &crate::store::BreakerCfg::default(), None);
            drop(permit);
            Err(())
        }
    }
}

/// FallbackPool mode: actually route the request to a configured fallback pool's healthy
/// member. Supports multi-level chains (A→B→C): when the fallback pool is itself exhausted
/// it consults THAT pool's own `on_exhausted` config and re-enters. The `visited_pools` set
/// in `RequestCtx` is the loop guard — a chain that cycles back to an already-visited pool
/// (A→B→A) terminates with 503 instead of recursing forever.
async fn handle_fallback_pool(
    app: Arc<App>,
    body: Bytes,
    caller_token: Option<&str>,
    pool_name: &str,
    request_ctx: &mut RequestCtx,
) -> Response {
    // Deadline propagated across hops.
    if request_ctx.expired(now()) {
        return (StatusCode::SERVICE_UNAVAILABLE, "router: deadline exceeded").into_response();
    }

    // Loop guard: if this request already routed through this pool, stop (A→B→A).
    if request_ctx.is_pool_visited(pool_name) {
        return handle_status_503(&app, &[], now(), pool_name);
    }

    let Some(fallback_cands) = app.fallback_pools.get(pool_name).cloned() else {
        // Fallback pool not configured — cascade to Status503.
        return handle_status_503(&app, &[], now(), pool_name);
    };

    // Mark before re-entering so a cycle back to this pool is detected.
    request_ctx.mark_pool_visited(pool_name);

    // Try the fallback pool's members (concurrency-aware, accumulating exclusions across hops).
    loop {
        if request_ctx.expired(now()) {
            return (StatusCode::SERVICE_UNAVAILABLE, "router: deadline exceeded").into_response();
        }

        let Some((i, permit)) =
            pick_among(&app, &fallback_cands, request_ctx, None, pool_name).await
        else {
            // Fallback pool itself exhausted — consult ITS on_exhausted config (multi-level
            // chains). The visited-set guarantees this recursion terminates.
            return Box::pin(handle_exhaustion_for_pool(
                app.clone(),
                &fallback_cands,
                now(),
                pool_name,
                body,
                caller_token,
                request_ctx,
            ))
            .await;
        };

        request_ctx.exclude(i);

        match forward_once(
            &app,
            i,
            permit,
            &body,
            caller_token,
            request_ctx.remaining(now()),
        )
        .await
        {
            Ok(resp) => return resp,
            Err(()) => continue, // transient transport error → try next member
        }
    }
}

/// LeastBad mode: actually route to the soonest-cooldown member even though it is Open
/// ("least-bad last resort"). Bypasses the breaker's usability check and acquires the
/// member's concurrency permit directly, then makes a single attempt (no failover from a
/// last-resort path). Logs loudly that this is a degraded route. Falls back to Status503 if
/// there is no candidate, the permit is unavailable, or the upstream is unreachable.
async fn handle_least_bad(
    app: &Arc<App>,
    cands: &[WeightedLane],
    now: u64,
    body: &Bytes,
    caller_token: Option<&str>,
    request_ctx: &RequestCtx,
    pool: &str,
) -> Response {
    let Some(soonest_idx) = find_soonest_cooldown(&app.store, cands, now, pool) else {
        // No candidates at all - fall back to Status503.
        return handle_status_503(app, cands, now, pool);
    };

    eprintln!(
        "[WARN] LEAST-BAD MODE — routing to degraded member {} (cooldown {}s remaining)",
        soonest_idx,
        app.store.cooldown_remaining_in(pool, soonest_idx, now)
    );

    // Bypass breaker usability for the last-resort path; grab the concurrency permit directly.
    let Some(permit) = app.store.try_acquire(soonest_idx) else {
        return handle_status_503(app, cands, now, pool);
    };

    match forward_once(
        app,
        soonest_idx,
        permit,
        body,
        caller_token,
        request_ctx.remaining(now),
    )
    .await
    {
        Ok(resp) => resp,
        Err(()) => handle_status_503(app, cands, now, pool),
    }
}

#[cfg(test)]
mod usage_tap_tests {
    use super::UsageTap;
    use bytes::Bytes;

    #[test]
    fn test_tap_extracts_usage_across_protocols() {
        // OpenAI chat completions: prompt_tokens / completion_tokens.
        let mut t = UsageTap::new();
        t.feed(&Bytes::from(
            r#"{"usage":{"prompt_tokens":10,"completion_tokens":5}}"#,
        ));
        assert_eq!(t.input_tokens, Some(10));
        assert_eq!(t.output_tokens, Some(5));

        // Anthropic / OpenAI Responses: input_tokens / output_tokens.
        let mut t = UsageTap::new();
        t.feed(&Bytes::from(
            r#"{"usage":{"input_tokens":8,"output_tokens":4}}"#,
        ));
        assert_eq!(t.input_tokens, Some(8));
        assert_eq!(t.output_tokens, Some(4));

        // AWS Bedrock Converse: inputTokens / outputTokens.
        let mut t = UsageTap::new();
        t.feed(&Bytes::from(
            r#"{"usage":{"inputTokens":6,"outputTokens":2}}"#,
        ));
        assert_eq!(t.input_tokens, Some(6));
        assert_eq!(t.output_tokens, Some(2));

        // Gemini: usageMetadata.promptTokenCount / candidatesTokenCount.
        let mut t = UsageTap::new();
        t.feed(&Bytes::from(
            r#"{"usageMetadata":{"promptTokenCount":7,"candidatesTokenCount":3}}"#,
        ));
        assert_eq!(t.input_tokens, Some(7));
        assert_eq!(t.output_tokens, Some(3));
    }
}

#[cfg(test)]
mod auth_style_tests {
    use super::lane_auth_headers;
    use crate::proto::{Protocol, SigningContext};
    use crate::state::Lane;
    use std::collections::HashMap;
    use std::sync::Arc;

    fn lane_with_auth(auth: Option<&str>) -> Lane {
        Lane {
            model: "gpt-4o".to_string(),
            provider: "azure".to_string(),
            base_url: "https://res.openai.azure.com".to_string(),
            api_key: "SECRETKEY".to_string(),
            protocol: Arc::new(Protocol::openai()),
            max: 1,
            error_map: Arc::new(HashMap::new()),
            context_max: None,
            path: Some(
                "/openai/deployments/gpt-4o/chat/completions?api-version=2024-06-01".to_string(),
            ),
            auth: auth.map(String::from),
            health: None,
        }
    }

    fn ctx<'a>(body: &'a [u8]) -> SigningContext<'a> {
        SigningContext {
            host: "res.openai.azure.com".to_string(),
            canonical_uri: "/openai/deployments/gpt-4o/chat/completions".to_string(),
            body,
            timestamp_epoch: 0,
        }
    }

    #[test]
    fn test_api_key_auth_sends_api_key_header() {
        // Azure-style: `auth: api-key` sends `api-key: <key>`, NOT a bearer Authorization header.
        let lane = lane_with_auth(Some("api-key"));
        let headers = lane_auth_headers(&lane, "SECRETKEY", &ctx(b"{}"));
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0.as_str(), "api-key");
        assert_eq!(headers[0].1.to_str().unwrap(), "SECRETKEY");
    }

    #[test]
    fn test_default_auth_falls_back_to_protocol_bearer() {
        // No/`bearer` auth override uses the protocol's native sign_request (openai → bearer).
        for auth in [None, Some("bearer")] {
            let lane = lane_with_auth(auth);
            let headers = lane_auth_headers(&lane, "SECRETKEY", &ctx(b"{}"));
            assert_eq!(headers.len(), 1);
            assert_eq!(headers[0].0.as_str(), "authorization");
            assert_eq!(headers[0].1.to_str().unwrap(), "Bearer SECRETKEY");
        }
    }
}

#[cfg(test)]
mod on_exhausted_tests {
    use crate::config;

    #[test]
    fn test_config_parsing_status_503() {
        let result = config::OnExhausted::parse("reject").unwrap();
        assert!(matches!(result, config::OnExhausted::Status503));
    }

    #[test]
    fn test_config_parsing_least_bad() {
        let result = config::OnExhausted::parse("least_bad").unwrap();
        assert!(matches!(result, config::OnExhausted::LeastBad));
    }

    #[test]
    fn test_config_parsing_fallback_pool() {
        let result = config::OnExhausted::parse("fallback_pool:drain").unwrap();
        if let config::OnExhausted::FallbackPool(name) = result {
            assert_eq!(name, "drain");
        } else {
            panic!("Expected FallbackPool variant");
        }
    }

    #[test]
    fn test_config_parsing_unknown_fails() {
        let result = config::OnExhausted::parse("invalid");
        assert!(result.is_err(), "Unknown action should fail parsing");
    }
}
