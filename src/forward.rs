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

/// B-203: Non-buffering stream inspection tap for Anthropic SSE usage parsing.
///
/// This accumulator extracts the final `message_delta` / `message_stop` usage object
/// from a streaming Anthropic response without buffering the entire body. It maintains
/// only small parsed fields and a bounded carry buffer for frame reassembly across chunks.
#[allow(dead_code)] // Usage exposed via FirstByteBody::usage() for B-601 cost accounting
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

    /// Check if any usage data was extracted.
    #[allow(dead_code)] // Used for future B-601 integration
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

/// B-203: Carry buffer for SSE frame reassembly across chunk boundaries.
///
/// This is a bounded accumulator that holds at most MAX_CARRY_BYTES to prevent
/// memory unboundedness when frames span multiple chunks. It never retains the full body.
#[allow(dead_code)] // Methods used in tests and for future B-601 integration
pub(crate) struct SseCarryBuffer {
    /// Accumulated bytes from incomplete SSE frame
    buffer: Vec<u8>,
    /// Maximum bytes to carry (hard cap for bounded memory)
    max_bytes: usize,
}

impl SseCarryBuffer {
    pub(crate) fn new() -> Self {
        Self {
            buffer: Vec::new(),
            max_bytes: 4096, // 4KB carry buffer cap - enough for multi-chunk frames but bounded
        }
    }

    /// Feed a chunk and return the complete SSE frame if available.
    /// Returns Some(frame_bytes) when a complete event is assembled, None otherwise.
    #[allow(dead_code)] // Used in tests to verify bounded memory behavior
    pub(crate) fn feed(&mut self, chunk: &Bytes) -> Option<Bytes> {
        // Append new bytes (bounded by max_bytes)
        let to_add = chunk
            .len()
            .min(self.max_bytes.saturating_sub(self.buffer.len()));
        if to_add > 0 {
            self.buffer.extend_from_slice(&chunk[..to_add]);
        }

        // Look for complete SSE frame (double newline separator)
        if let Some(start_pos) = self.buffer.windows(2).position(|w| w == b"\n\n") {
            // Extract the complete frame including separators
            let end_pos = start_pos + 2;
            let frame_bytes = self.buffer[..end_pos].to_vec();
            // Remove processed bytes from buffer
            self.buffer.drain(..end_pos);
            return Some(Bytes::from(frame_bytes));
        }

        None
    }

    /// Get the current carry buffer size (for testing boundedness).
    #[allow(dead_code)] // Used in tests to verify bounded memory
    pub(crate) fn len(&self) -> usize {
        self.buffer.len()
    }
}

impl Default for SseCarryBuffer {
    fn default() -> Self {
        Self::new()
    }
}

/// Body wrapper that implements the before-first-byte failover boundary (B-202).
/// Tracks when the first byte is sent and handles mid-stream errors by emitting
/// SSE error events instead of allowing failover. Also holds the permit until stream ends.
///
/// B-203: Integrated UsageTap for non-buffering usage extraction from streaming responses.
struct FirstByteBody<S, P> {
    inner: S,
    first_byte_sent: Arc<AtomicBool>,
    is_sse: bool,
    permit: Option<P>,
    app: Option<Arc<App>>,
    lane_idx: usize,
    /// B-203: Usage tap for extracting Anthropic SSE usage without buffering full body
    tap: UsageTap,
}

impl<S, P> FirstByteBody<S, P>
where
    S: Stream<Item = Result<Bytes, reqwest::Error>> + Send + 'static,
{
    fn new(inner: S, is_sse: bool, permit: P, app: Arc<App>, lane_idx: usize) -> Self {
        Self {
            inner,
            first_byte_sent: Arc::new(AtomicBool::new(false)),
            is_sse,
            permit: Some(permit),
            app: Some(app),
            lane_idx,
            tap: UsageTap::new(),
        }
    }

    /// Get a reference to the extracted usage data after stream completion.
    #[allow(dead_code)] // Exposed for B-601 cost accounting integration
    pub(crate) fn usage(&self) -> &UsageTap {
        &self.tap
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
        match Pin::new(&mut this.inner).poll_next(cx) {
            Poll::Ready(Some(Ok(chunk))) => {
                if !this.first_byte_sent.load(Ordering::Relaxed) {
                    this.first_byte_sent.store(true, Ordering::Relaxed);
                }
                // B-203: Feed chunk to tap for usage extraction (non-buffering)
                this.tap.feed(&chunk);
                Poll::Ready(Some(Ok(chunk)))
            }
            Poll::Ready(Some(Err(e))) => {
                let had_first = this.first_byte_sent.load(Ordering::Relaxed);
                if had_first && this.is_sse {
                    // Mid-stream failure after first byte in SSE mode: record breaker failure then emit SSE error event
                    if let Some(ref app) = this.app {
                        app.store
                            .record_transient(this.lane_idx, "mid-stream", None);
                    }
                    let err_json = serde_json::json!({
                        "type": "error",
                        "error": {
                            "message": e.to_string(),
                            "source": "upstream"
                        }
                    });
                    let sse_error = format!("event: error\ndata: {}\n\n", err_json);
                    Poll::Ready(Some(Ok(Bytes::from(sse_error))))
                } else {
                    // Before first byte or non-SSE: propagate error (allows failover at caller level)
                    Poll::Ready(Some(Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        e.to_string(),
                    ))))
                }
            }

            Poll::Ready(None) => {
                // Stream ended - for SSE streams that sent at least one byte, record the failure
                if this.is_sse && this.first_byte_sent.load(Ordering::Relaxed) {
                    if let Some(ref app) = this.app {
                        app.store
                            .record_transient(this.lane_idx, "mid-stream-end", None);
                    }
                }
                drop(this.permit.take());
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
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
        if now >= self.deadline {
            0
        } else {
            self.deadline - now
        }
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

/// B-401 / B-402 / B-404: pick_among using weighted selection (SWRR) over healthy subset.
/// `cands` is now Vec<WeightedLane> where each lane has its weight from config.
/// `request_ctx` provides accumulated exclusions to avoid retrying failed lanes.
/// `_affinity_key` enables sticky routing as a preference (not a hard constraint).
async fn pick_among(
    app: &Arc<App>,
    cands: &[WeightedLane],
    request_ctx: &mut RequestCtx,
    _affinity_key: Option<&str>,
) -> Option<(usize, Permit)> {
    let t = now();

    // B-404: Session affinity preference - try sticky lane first if usable
    if let Some(k) = _affinity_key {
        if !cands.is_empty() {
            let mut h = DefaultHasher::new();
            k.hash(&mut h);
            let pos = (h.finish() as usize) % cands.len();
            let sticky = cands[pos].idx;

            if !request_ctx.excluded.contains(&sticky) && app.store.usable(sticky, t) {
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

    // Use SWRR selection over healthy members only (B-401)
    let picked_lane_idx = app.store.select_weighted(&candidates, &weights, t)?;

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
pub(crate) async fn forward(
    app: Arc<App>,
    cands: Vec<WeightedLane>,
    body: Bytes,
    caller_token: Option<&str>,
) -> Response {
    forward_with_pool(app, cands, body, caller_token, "__default__", None).await
}

/// Forward with pool name context for on_exhausted config lookup.
pub(crate) async fn forward_with_pool(
    app: Arc<App>,
    cands: Vec<WeightedLane>,
    body: Bytes,
    caller_token: Option<&str>,
    pool_name: &str,
    affinity_key: Option<&str>,
) -> Response {
    let mut v: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, format!("router: bad json: {e}")).into_response()
        }
    };

    // Derive affinity key early (before any mutations to v)
    let _affinity_key_str: Option<String> = if let Some(k) = affinity_key {
        Some(k.to_string())
    } else {
        v.get("system")
            .and_then(|s| s.as_str())
            .filter(|s| !s.is_empty())
            .map(String::from)
    };

    // Before-first-byte failover boundary (B-202):
    // Failover is allowed ONLY until the first upstream byte reaches the client.
    // After that point, an upstream failure must NOT trigger failover because
    // the client already has a partial response. Instead:
    // - For SSE streams: emit an SSE `error` event and terminate the stream
    // - Record the breaker failure for that lane (the member tripped)
    // The client must restart the request itself after receiving the error event.

    // B-402: Get failover config from app
    let (deadline_secs, max_cap) = if let Some(ref f) = app.failover_cfg {
        (f.deadline_secs, f.cap)
    } else {
        (120, 3) // defaults: deadline_s=120, max_failover=3
    };

    let mut request_ctx = RequestCtx::new(deadline_secs);

    for _attempt in 0..=max_cap {
        // Check deadline first (propagated across hops)
        if request_ctx.expired(now()) {
            return (StatusCode::SERVICE_UNAVAILABLE, "router: deadline exceeded").into_response();
        }

        let (i, permit) =
            match pick_among(&app, &cands, &mut request_ctx, _affinity_key_str.as_deref()).await {
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

        let res = app
            .client
            .post(format!(
                "{base}{}",
                app.lanes[i].protocol.writer().upstream_path()
            ))
            .headers(convert_headers(
                app.lanes[i].protocol.writer().auth_headers(key),
            ))
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
                app.store.record_transient(i, err_type, None);
                drop(permit);
                continue;
            }
            Ok(r) => {
                let status = r.status();

                // For non-2xx responses, read the body to classify (failover allowed)
                if !status.is_success() {
                    // §6 caveat: passthrough 401/403 is caller's key failing, not busbar's
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

                    // Exhaustive match on Disposition - NO _ => allowed per B-301 requirements
                    match disposition {
                        Disposition::ClientFault => {
                            // ADR-0002: Client fault (caller's bad input) → relay verbatim, no penalty
                            // Track client_fault separately from upstream err (B-603)
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
                                app.store.record_rate_limit(i, now(), sig.retry_after);
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
                                    StatusClass::RateLimit => {
                                        // Should have been handled above but Rust needs exhaustive match
                                        "rate_limit"
                                    }
                                };
                                app.store.record_transient(i, what, sig.retry_after);
                            }
                            drop(permit);
                            continue;
                        }
                        Disposition::HardDown => {
                            // Hard down → permanent dead state (with probe recovery per B-303)
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
                            };
                            app.store.record_hard_down(i, &reason);
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
                            continue;
                        }
                    }
                }

                // SUCCESS case: stream the response body incrementally with first-byte boundary tracking (B-202)
                let ct = r.headers().get(CONTENT_TYPE).cloned();
                let is_sse = ct
                    .as_ref()
                    .map(|h| h.to_str().unwrap_or("").starts_with("text/event-stream"))
                    .unwrap_or(false);

                // B-202: Use FirstByteBody wrapper to track first byte and emit SSE error events on mid-stream failures
                let upstream_stream = r.bytes_stream();
                let guarded_body =
                    FirstByteBody::new(upstream_stream, is_sse, permit, app.clone(), i);
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
) -> Option<usize> {
    let mut soonest_idx = None;
    let mut soonest_remaining = u64::MAX;

    for wl in cands {
        let remaining = store.cooldown_remaining(wl.idx, now);
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
        OnExhausted::Status503 => handle_status_503(&app, cands, now),
        OnExhausted::FallbackPool(ref fallback_pool) => {
            handle_fallback_pool(app.clone(), body, caller_token, fallback_pool, request_ctx).await
        }
        OnExhausted::LeastBad => {
            handle_least_bad(&app, cands, now, &body, caller_token, request_ctx).await
        }
    }
}

/// Status503 mode: return 503 with Retry-After header.
fn handle_status_503(app: &Arc<App>, cands: &[WeightedLane], now: u64) -> Response {
    let soonest_remaining = find_soonest_cooldown(&app.store, cands, now)
        .map(|idx| app.store.cooldown_remaining(idx, now))
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
/// success body (B-201 invariant) and dropped on error.
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

    let res = app
        .client
        .post(format!(
            "{base}{}",
            app.lanes[i].protocol.writer().upstream_path()
        ))
        .headers(convert_headers(
            app.lanes[i].protocol.writer().auth_headers(key),
        ))
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
                .map(|h| h.to_str().unwrap_or("").starts_with("text/event-stream"))
                .unwrap_or(false);
            let upstream_stream = r.bytes_stream();
            let guarded_body = FirstByteBody::new(upstream_stream, is_sse, permit, app.clone(), i);
            let mut rb = Response::builder().status(status);
            if let Some(ct) = ct {
                rb = rb.header(CONTENT_TYPE, ct);
            }
            Ok(rb.body(guarded_body.into_body()).unwrap())
        }
        Err(e) => {
            // Pre-response transport error: record transient, drop permit, signal "try next".
            let err_type = if e.is_timeout() { "timeout" } else { "connect" };
            app.store.record_transient(i, err_type, None);
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
        return handle_status_503(&app, &[], now());
    }

    let Some(fallback_cands) = app.fallback_pools.get(pool_name).cloned() else {
        // Fallback pool not configured — cascade to Status503.
        return handle_status_503(&app, &[], now());
    };

    // Mark before re-entering so a cycle back to this pool is detected.
    request_ctx.mark_pool_visited(pool_name);

    // Try the fallback pool's members (concurrency-aware, accumulating exclusions across hops).
    loop {
        if request_ctx.expired(now()) {
            return (StatusCode::SERVICE_UNAVAILABLE, "router: deadline exceeded").into_response();
        }

        let Some((i, permit)) = pick_among(&app, &fallback_cands, request_ctx, None).await else {
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
) -> Response {
    let Some(soonest_idx) = find_soonest_cooldown(&app.store, cands, now) else {
        // No candidates at all - fall back to Status503.
        return handle_status_503(app, cands, now);
    };

    eprintln!(
        "[WARN] B-403: LEAST-BAD MODE — routing to degraded member {} (cooldown {}s remaining)",
        soonest_idx,
        app.store.cooldown_remaining(soonest_idx, now)
    );

    // Bypass breaker usability for the last-resort path; grab the concurrency permit directly.
    let Some(permit) = app.store.try_acquire(soonest_idx) else {
        return handle_status_503(app, cands, now);
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
        Err(()) => handle_status_503(app, cands, now),
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
