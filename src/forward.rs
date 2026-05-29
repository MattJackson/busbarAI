// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::{body::Body, http::header::CONTENT_TYPE, response::IntoResponse, response::Response};
use bytes::Bytes;
use futures::Stream;
use reqwest::StatusCode;
use serde_json::Value;

use crate::proto::{convert_headers, CanonicalSignal};
use crate::state::App;
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
            _ => {}
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
                        app.store.record_transient(this.lane_idx, "mid-stream");
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
                        app.store.record_transient(this.lane_idx, "mid-stream-end");
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

async fn pick_among(app: &Arc<App>, cands: &[usize]) -> Option<(usize, Permit)> {
    let t = now();
    let usable: Vec<usize> = cands
        .iter()
        .copied()
        .filter(|&i| app.store.usable(i, t))
        .collect();
    if usable.is_empty() {
        return None;
    }
    let start = app.rr.fetch_add(1, Ordering::Relaxed);
    let order: Vec<usize> = (0..usable.len())
        .map(|k| usable[(start + k) % usable.len()])
        .collect();
    for &i in &order {
        if let Some(p) = app.store.try_acquire(i) {
            return Some((i, p));
        }
    }
    let futs: Vec<_> = order
        .iter()
        .map(|&i| {
            let store = app.store.clone();
            Box::pin(async move {
                loop {
                    if let Some(p) = store.try_acquire(i) {
                        return (i, p);
                    }
                    tokio::time::sleep(tokio::time::Duration::from_millis(1)).await;
                }
            })
        })
        .collect();
    let ((i, p), _, _) = futures::future::select_all(futs).await;
    Some((i, p))
}

pub(crate) async fn forward(
    app: Arc<App>,
    cands: Vec<usize>,
    body: Bytes,
    caller_token: Option<&str>,
) -> Response {
    let mut v: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, format!("router: bad json: {e}")).into_response()
        }
    };

    // Before-first-byte failover boundary (B-202):
    // Failover is allowed ONLY until the first upstream byte reaches the client.
    // After that point, an upstream failure must NOT trigger failover because
    // the client already has a partial response. Instead:
    // - For SSE streams: emit an SSE `error` event and terminate the stream
    // - Record the breaker failure for that lane (the member tripped)
    // The client must restart the request itself after receiving the error event.

    let attempts = cands.len() + 2;
    for _attempt in 0..attempts {
        let (i, permit) = match pick_among(&app, &cands).await {
            Some(x) => x,
            None => {
                return (StatusCode::SERVICE_UNAVAILABLE, "router: no usable lane").into_response()
            }
        };

        let proto = &app.lanes[i].protocol;
        proto.rewrite_model(&mut v, &app.lanes[i].model);
        let payload = serde_json::to_vec(&v).unwrap();
        let base = &app.lanes[i].base_url;

        // Mode-aware key selection: passthrough uses caller token, others use lane's api_key
        let key = match app.auth_mode {
            crate::auth::AuthMode::Passthrough => caller_token.unwrap_or(&app.lanes[i].api_key),
            crate::auth::AuthMode::Token | crate::auth::AuthMode::None => &app.lanes[i].api_key,
        };

        let res = app
            .client
            .post(format!("{base}{}", proto.upstream_path()))
            .headers(convert_headers(proto.auth_headers(key)))
            .header(CONTENT_TYPE, "application/json")
            .body(payload)
            .send()
            .await;

        match res {
            Err(e) => {
                // Pre-response error: classify and potentially failover
                let err_type = if e.is_timeout() { "timeout" } else { "connect" };
                app.store.record_transient(i, err_type);
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

                    match proto.classify(status, &bytes) {
                        CanonicalSignal {
                            class: "billing", ..
                        } => {
                            app.store
                                .record_hard_down(i, "billing / insufficient balance (1113)");
                            drop(permit);
                            continue;
                        }
                        CanonicalSignal { class: "auth", .. } => {
                            // In Token/None mode: busbar's key failed → kill lane and return error
                            // In Passthrough mode: already handled above (early return)
                            app.store.record_hard_down(
                                i,
                                &format!("auth rejected (HTTP {})", status.as_u16()),
                            );
                            drop(permit);

                            // Return the 401/403 response to caller instead of continuing
                            use axum::body::Body;
                            let mut rb = Response::builder().status(status);
                            if let Some(ct) = ct {
                                rb = rb.header(CONTENT_TYPE, ct);
                            }
                            return rb.body(Body::from(bytes)).unwrap();
                        }
                        CanonicalSignal {
                            class: "rate_limit",
                            ..
                        } => {
                            app.store.record_rate_limit(i, now(), None);
                            drop(permit);
                            continue;
                        }
                        CanonicalSignal {
                            class: "transient", ..
                        } => {
                            app.store.record_transient(i, "5xx");
                            drop(permit);
                            continue;
                        }
                        CanonicalSignal { class, .. } => {
                            app.store.record_transient(i, &format!("unknown-{class}"));
                            drop(permit);
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

    (
        StatusCode::SERVICE_UNAVAILABLE,
        "router: all lanes exhausted",
    )
        .into_response()
}
