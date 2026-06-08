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

use crate::breaker::{classify as classify_disposition, normalize_raw_error, Disposition};
use crate::config::OnExhausted;
use crate::proto::{convert_headers, StatusClass};
use crate::state::{App, Lane, WeightedLane};
use crate::store::{now, Permit};

/// At a cross-protocol translation boundary, ensure the IR carries `max_tokens` when the egress
/// protocol REQUIRES one (Anthropic Messages) but the source request omitted it (legal for OpenAI).
/// Without this the upstream 400s with `max_tokens: Field required`. Uses the lane's configured
/// `default_max_tokens`, falling back to `crate::proto::DEFAULT_MAX_TOKENS`. No-op when the IR
/// already carries a value or the egress protocol treats `max_tokens` as optional.
fn apply_required_max_tokens(ir: &mut crate::ir::IrRequest, lane: &Lane) {
    if ir.max_tokens.is_none() && lane.protocol.writer().requires_max_tokens() {
        ir.max_tokens = Some(
            lane.default_max_tokens
                .unwrap_or(crate::proto::DEFAULT_MAX_TOKENS),
        );
    }
}

/// Build a native-format error response for the CLIENT. Every forward-layer error that is returned
/// to the caller goes through here so the body is the INGRESS protocol's native error envelope
/// (`application/json`) rather than `text/plain`, which an official SDK cannot decode (it raises a
/// generic JSON-decode error — a deterministic proxy tell, design §8.1). The status code is
/// preserved exactly; only the body shape changes. `kind` is the protocol-agnostic error category
/// (e.g. `"invalid_request_error"`, `"overloaded"`); `msg` is the human-readable detail.
/// When `ingress` does not resolve to a known protocol, falls back to the generic default envelope
/// via the OpenAI writer (`protocol_for` only fails for an unknown literal, which is itself a 400
/// the caller still needs shaped).
fn ingress_error(ingress: &str, status: StatusCode, kind: &str, msg: &str) -> Response {
    let envelope = match crate::proto::protocol_for(ingress) {
        Some(p) => p.writer().write_error(status.as_u16(), kind, msg),
        None => crate::proto::Protocol::openai()
            .writer()
            .write_error(status.as_u16(), kind, msg),
    };
    let body = serde_json::to_string(&envelope).unwrap_or_else(|_| {
        // Envelope is built from serde_json::json! values and always serializes; this fallback only
        // exists to avoid an unwrap on the request path.
        format!("{{\"error\":{{\"message\":{msg:?},\"type\":{kind:?}}}}}")
    });
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap_or_else(|_| status.into_response())
}

/// Remove the router-internal shim keys the route layer injects into the request body for PATH-MODEL
/// ingress protocols (`gemini`, `bedrock`), where the native wire carries the model in the URL and
/// stream intent in the path, not the body. The shared resolve/forward plumbing reads `model` and
/// `stream` from the body, so the route layer injects them; they must NOT reach the backend on the
/// same-protocol passthrough path (a Bedrock Converse request rejects an unexpected `model`/`stream`,
/// and either way it is an indistinguishability leak). No-op for body-model protocols (openai etc.),
/// whose `model`/`stream` are GENUINE caller fields.
fn strip_router_shim_keys(v: &mut Value, ingress_protocol: &str) {
    if matches!(ingress_protocol, "gemini" | "bedrock") {
        if let Some(obj) = v.as_object_mut() {
            obj.remove("model");
            obj.remove("stream");
        }
    }
}

/// Upper bound on a buffered UPSTREAM response body (error 4xx/5xx bodies and buffered cross-protocol
/// non-stream JSON). Any error envelope or single non-stream completion is far smaller than this; the
/// cap stops a hostile or misconfigured upstream from forcing an unbounded heap allocation per
/// in-flight non-2xx/non-stream response (the inbound request body is already capped separately).
const MAX_UPSTREAM_BUFFERED_BYTES: usize = 256 * 1024;

/// Read an upstream response body, buffering at most [`MAX_UPSTREAM_BUFFERED_BYTES`] and discarding
/// the rest. Streams chunks with a running byte counter rather than `r.bytes()` (which would buffer
/// the entire — possibly multi-gigabyte — body before any cap could apply). A truncated body still
/// classifies/relays correctly: error envelopes and completions are well under the cap, and a body
/// that overruns it can only be malformed/hostile.
async fn read_capped_body(r: reqwest::Response) -> Bytes {
    let mut buf: Vec<u8> = Vec::new();
    let mut r = r;
    loop {
        match r.chunk().await {
            Ok(Some(chunk)) => {
                let remaining = MAX_UPSTREAM_BUFFERED_BYTES.saturating_sub(buf.len());
                if remaining == 0 {
                    // Cap reached — stop reading; the connection is dropped when `r` falls out of
                    // scope. We keep exactly the capped prefix.
                    break;
                }
                let take = remaining.min(chunk.len());
                buf.extend_from_slice(&chunk[..take]);
                if take < chunk.len() {
                    break; // this chunk filled the cap
                }
            }
            Ok(None) => break, // end of body
            Err(_) => break, // transport error mid-body — keep what we have (was unwrap_or_default)
        }
    }
    Bytes::from(buf)
}

/// Map the classified `StatusClass` of a CLIENT-fault upstream 4xx to a protocol-agnostic error
/// `kind` for `ingress_error` (the per-protocol writer maps it to its native error type/category).
/// Exhaustive over `StatusClass` — no `_` wildcard (the no-catch-all rule for disposition matches).
fn client_fault_kind(class: StatusClass) -> &'static str {
    match class {
        StatusClass::ContextLength => "context_length_exceeded",
        StatusClass::ClientError => "invalid_request_error",
        // The other classes are not reached on the ClientFault arm (they classify as
        // TransientUpstream / HardDown / ContextLength), but the match must be exhaustive; treat
        // them as a generic invalid-request shape rather than panicking on the request path.
        StatusClass::RateLimit
        | StatusClass::Overloaded
        | StatusClass::ServerError
        | StatusClass::Timeout
        | StatusClass::Network
        | StatusClass::Auth
        | StatusClass::Billing => "invalid_request_error",
    }
}

/// Best-effort human-readable message from an upstream error body, across the vendor error shapes
/// (`error.message`, top-level `message`, Gemini `error.message`). Returns `None` when the body is
/// not JSON or carries no recognizable message field, so the caller substitutes a generic detail
/// rather than leaking the raw foreign body.
fn extract_error_message(bytes: &[u8]) -> Option<String> {
    let v: Value = serde_json::from_slice(bytes).ok()?;
    v.get("error")
        .and_then(|e| e.get("message"))
        .and_then(|m| m.as_str())
        .or_else(|| v.get("message").and_then(|m| m.as_str()))
        .map(|s| s.to_string())
}

/// Build the bytes for a mid-stream error to send to the CLIENT, framed in the INGRESS protocol.
///
/// After the first byte has reached the client, failover is no longer possible, so an upstream
/// transport failure must terminate the stream with an in-band error in the client's own framing:
///   - Bedrock ingress (native AWS SDK, binary `application/vnd.amazon.eventstream`): a real
///     modeled-exception frame (`:message-type: exception`, `:exception-type: InternalServerException`)
///     with valid CRC32. Writing SSE `event:`/`data:` text into a binary eventstream body produces an
///     undecodable prelude/CRC for the SDK's decoder — the bug this guards against.
///   - SSE ingress (openai/anthropic/gemini/cohere/responses): an `event: error` SSE frame whose
///     `data:` payload is the ingress protocol's NATIVE error envelope, so the official SDK decodes
///     it rather than seeing a foreign (previously always Anthropic-shaped) body.
fn mid_stream_error_bytes(
    ingress_protocol: &str,
    ingress_eventstream: bool,
    message: &str,
) -> Vec<u8> {
    if ingress_eventstream {
        // Bedrock binary eventstream client: a transient mid-stream upstream failure maps to the
        // generic internal-server exception (a real AWS Converse exception name).
        let exc = crate::proto::error_kind_to_bedrock_type("api_error");
        return crate::eventstream::encode_exception_frame(exc, message);
    }
    // SSE client: shape the error body to the ingress protocol's native envelope.
    let envelope = match crate::proto::protocol_for(ingress_protocol) {
        Some(p) => p.writer().write_error(
            StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            "api_error",
            message,
        ),
        None => crate::proto::Protocol::openai().writer().write_error(
            StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            "api_error",
            message,
        ),
    };
    let data = serde_json::to_string(&envelope).unwrap_or_else(|_| {
        format!("{{\"error\":{{\"message\":{message:?},\"type\":\"api_error\"}}}}")
    });
    format!("event: error\ndata: {data}\n\n").into_bytes()
}

/// Non-buffering stream inspection tap for usage parsing.
///
/// Extracts the final usage object from a streaming response without buffering the body: it scans
/// each chunk for complete JSON objects and keeps only the small parsed usage fields. A JSON object
/// split across chunk boundaries is simply not parsed in that chunk (no unbounded state is kept).
#[derive(Debug, Clone, Default)]
pub(crate) struct UsageTap {
    /// Extracted input tokens (from message_delta.usage.input_tokens or message_stop.usage.input_tokens)
    pub input_tokens: Option<u64>,
    /// Extracted output tokens (from message_delta.usage.output_tokens or message_stop.usage.output_tokens)
    pub output_tokens: Option<u64>,
    /// A genuine terminal ERROR frame seen mid-stream (an SSE `{"type":"error", ...}` event). This
    /// is the signal that gates breaker failure recording at stream end: a clean stream ends with a
    /// normal terminator (`message_stop` / `[DONE]`) and leaves this `None` (→ success, already
    /// recorded synchronously), whereas a stream that carried an explicit error frame ended
    /// abnormally (→ record one breaker failure). Holds the error message for observability.
    pub terminal_error: Option<String>,
}

impl UsageTap {
    /// Create a new empty tap
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Feed a chunk to the tap and extract any usage fields. Bounded: it only scans complete JSON
    /// objects within this chunk and keeps no cross-chunk buffer.
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
                        self.extract_terminal_error(&obj);
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
        if let Some(u) = obj.get("usage") {
            if let Some(v) = u.get("input_tokens").and_then(|v| v.as_u64()) {
                self.input_tokens = Some(v);
            }
            if let Some(v) = u.get("output_tokens").and_then(|v| v.as_u64()) {
                self.output_tokens = Some(v);
            }
        }
    }

    /// Extract usage fields from a message_stop event object (fallback).
    fn extract_usage_from_stop(&mut self, obj: &Value) {
        if obj.get("type").and_then(|t| t.as_str()) != Some("message_stop") {
            return;
        }
        if let Some(u) = obj.get("usage") {
            if let Some(v) = u.get("input_tokens").and_then(|v| v.as_u64()) {
                self.input_tokens = Some(v);
            }
            if let Some(v) = u.get("output_tokens").and_then(|v| v.as_u64()) {
                self.output_tokens = Some(v);
            }
        }
    }

    /// Detect a genuine terminal ERROR frame: an SSE event object of the form
    /// `{"type":"error", "error": {...}}`. Sets `terminal_error` to the error message (or a generic
    /// marker) so stream-end failure recording can distinguish a clean close from an aborted one.
    fn extract_terminal_error(&mut self, obj: &Value) {
        if obj.get("type").and_then(|t| t.as_str()) != Some("error") {
            return;
        }
        let msg = obj
            .get("error")
            .and_then(|e| e.get("message"))
            .and_then(|m| m.as_str())
            .unwrap_or("upstream stream error");
        self.terminal_error = Some(msg.to_string());
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

/// Deterministic FNV-1a hash of a string — stable across processes/restarts (unlike the
/// std `DefaultHasher`, whose seed is randomized), so session affinity pins consistently.
fn stable_hash(s: &str) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = FNV_OFFSET;
    for &byte in s.as_bytes() {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
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
                // Guard against a closing brace with no matching opener (malformed/adversarial
                // upstream bytes): `depth` is unsigned, so `depth -= 1` here would underflow.
                if depth == 0 {
                    return None;
                }
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
    /// True when the upstream body is an incremental stream (SSE or AWS event-stream). Drives the
    /// after-first-byte error-emission behavior (vs. propagating the error for pre-first-byte
    /// failover). Derived from the UPSTREAM Content-Type.
    is_sse: bool,
    /// The INGRESS protocol the CLIENT speaks (NOT the upstream/egress protocol). A mid-stream error
    /// is emitted in THIS protocol's framing so a native client SDK can decode it — keying the
    /// framing decision off the upstream CT (which on a cross-protocol reframe describes the egress,
    /// not the client) was the bug.
    ingress_protocol: Box<str>,
    /// True when the INGRESS client decodes a binary `application/vnd.amazon.eventstream` body (a
    /// native AWS SDK Bedrock client). A mid-stream error must then be a BINARY exception frame, not
    /// an SSE `event: error` text frame — writing SSE text into a binary eventstream body yields an
    /// undecodable prelude/CRC for the SDK's decoder. Independent of `is_sse` (which reflects the
    /// upstream CT) so a bedrock-ingress → SSE-egress reframe is handled correctly.
    ingress_eventstream: bool,
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
        ingress_protocol: &str,
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
            ingress_eventstream: ingress_protocol == "bedrock",
            ingress_protocol: Box::from(ingress_protocol),
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
                        // Mark the stream ended so the subsequent `Poll::Ready(None)` arm returns
                        // early instead of re-recording this same failure (the inner stream closes
                        // with `None` right after the error). Without this, one mid-stream transport
                        // failure double-counted against the breaker.
                        drop(this.permit.take());
                        this.ended = true;
                        // Emit the error in the INGRESS protocol's framing, NOT a hard-coded SSE
                        // text frame. For a bedrock-ingress client (binary eventstream) this is a
                        // valid AWS exception frame; for SSE clients it is shaped to the ingress
                        // protocol's native error envelope. Keying off `is_sse` (the upstream CT)
                        // alone would inject SSE text into a binary eventstream body on a
                        // bedrock-ingress → SSE-egress reframe — an undecodable frame for the SDK.
                        let err_bytes = mid_stream_error_bytes(
                            &this.ingress_protocol,
                            this.ingress_eventstream,
                            &e.to_string(),
                        );
                        return Poll::Ready(Some(Ok(Bytes::from(err_bytes))));
                    } else {
                        // Before first byte or non-SSE: propagate error (allows failover at caller level)
                        return Poll::Ready(Some(Err(std::io::Error::other(e.to_string()))));
                    }
                }
                Poll::Ready(None) => {
                    // Stream ended. A clean `Poll::Ready(None)` is the NORMAL termination for both
                    // clean and truncated streams and is NOT a failure — success was already
                    // recorded synchronously (record_success_in) before streaming began. Only record
                    // a breaker failure here if the tap actually saw a terminal ERROR frame
                    // (`{"type":"error", ...}`) mid-stream. Previously this arm recorded a failure on
                    // EVERY completed SSE stream, so healthy streaming lanes tripped after a handful
                    // of successful requests.
                    if this.is_sse && this.first_byte_sent.load(Ordering::Relaxed) {
                        if let (Some(app), Some(_err)) =
                            (this.app.as_ref(), this.tap.terminal_error.as_ref())
                        {
                            app.store.record_transient_in(
                                &this.pool,
                                this.lane_idx,
                                "stream-terminal-error",
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

/// Pick a lane from `cands` using session affinity (if any) then weighted selection (SWRR) over
/// the healthy subset, returning the chosen lane index and its acquired concurrency permit.
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

    // Session affinity preference - try sticky lane first if usable (in this pool's breaker view).
    // Uses a stable hash (NOT DefaultHasher, whose seed is randomized per process) so a session
    // pins to the same lane across restarts.
    if let Some(k) = _affinity_key {
        if !cands.is_empty() {
            let pos = (stable_hash(k) as usize) % cands.len();
            let sticky = cands[pos].idx;

            if !request_ctx.excluded.contains(&sticky) && app.store.usable_in(pool_name, sticky, t)
            {
                if let Some(p) = app.store.try_acquire(sticky) {
                    return Some((sticky, p));
                }
            }
        }
    }

    // Filter out already-tried lanes (accumulated exclusions across hops). A locally-tracked
    // exclusion set lets us skip a lane we selected but couldn't probe-acquire (HalfOpen race),
    // without mutating the caller's RequestCtx for what is a within-pick retry.
    let mut local_excluded: std::collections::HashSet<usize> = std::collections::HashSet::new();

    loop {
        // Deadline guard: never spin or re-select past the request deadline.
        if request_ctx.expired(now()) {
            return None;
        }

        let filtered_cands: Vec<&WeightedLane> = request_ctx
            .filter_candidates(cands)
            .into_iter()
            .filter(|wl| !local_excluded.contains(&wl.idx))
            .collect();
        if filtered_cands.is_empty() {
            return None;
        }

        // Extract lane indices and weights for select_weighted call
        let candidates: Vec<usize> = filtered_cands.iter().map(|wl| wl.idx).collect();
        let weights: Vec<u32> = filtered_cands.iter().map(|wl| wl.weight).collect();

        // SWRR selection (side-effect-free filter) over healthy members only, per this pool's cells.
        let picked_lane_idx =
            match app
                .store
                .select_weighted_in(pool_name, &candidates, &weights, now())
            {
                Some(i) => i,
                None => return None,
            };

        // The dispatched lane does the breaker probe acquisition exactly once here (Open→HalfOpen
        // CAS). If it lost the single-flight probe race, drop it locally and re-select another lane.
        if !app
            .store
            .acquire_for_dispatch_in(pool_name, picked_lane_idx, now())
        {
            local_excluded.insert(picked_lane_idx);
            continue;
        }

        // Try to acquire the concurrency permit immediately.
        if let Some(p) = app.store.try_acquire(picked_lane_idx) {
            return Some((picked_lane_idx, p));
        }

        // Permits saturated: park (not busy-spin) until a slot frees OR the deadline passes. A
        // bounded `timeout` acquire yields the task efficiently and guarantees we never block past
        // the request deadline (unbounded spinning here was a head-of-line-blocking DoS surface).
        let remaining = request_ctx.remaining(now());
        if remaining == 0 {
            return None;
        }
        let sem = app.store.lane_semaphore(picked_lane_idx);
        match tokio::time::timeout(
            tokio::time::Duration::from_secs(remaining),
            sem.acquire_owned(),
        )
        .await
        {
            // Got a permit before the deadline.
            Ok(Ok(permit)) => return Some((picked_lane_idx, Permit::new(permit))),
            // Semaphore closed (shutdown) — treat as no lane available.
            Ok(Err(_)) => return None,
            // Deadline hit while waiting for a permit — give up so the caller can 503/failover.
            Err(_) => return None,
        }
    }
}

/// Original forward function without pool context - uses default Status503 mode.
/// True for content types that carry an incremental streamed response: SSE (text/event-stream,
/// used by Anthropic/OpenAI/Gemini-SSE) and AWS event-stream (Bedrock ConverseStream,). Both
/// must engage the streaming body path rather than being buffered.
fn is_streaming_content_type(ct: &str) -> bool {
    ct.starts_with("text/event-stream") || ct.starts_with("application/vnd.amazon.eventstream")
}

/// The streaming `Content-Type` the INGRESS client expects, by ingress protocol. On a cross-protocol
/// reframe the streamed body is re-encoded into the client's framing, so the response header must
/// describe the CLIENT's wire format — copying the upstream CT verbatim would mislabel the body
/// (e.g. a Bedrock-egress `application/vnd.amazon.eventstream` reaching an SSE client, or vice
/// versa). SSE protocols (openai/anthropic/gemini/cohere/responses) get `text/event-stream`; bedrock
/// ingress gets `application/vnd.amazon.eventstream` — and this CT now describes a fully reframed
/// BINARY body: the encoder is implemented and wired (`StreamTranslate` sets `ingress_eventstream`
/// and packs each event into a CRC-valid frame via `eventstream::encode_frame`). Returns `None` for
/// an unrecognized literal so the caller keeps the upstream CT rather than guessing.
fn ingress_stream_content_type(ingress: &str) -> Option<&'static str> {
    match ingress {
        "openai" | "anthropic" | "gemini" | "cohere" | "responses" => Some("text/event-stream"),
        "bedrock" => Some("application/vnd.amazon.eventstream"),
        _ => None,
    }
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
            return ingress_error(
                ingress_protocol,
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                &format!("router: bad json: {e}"),
            )
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
        None => (
            crate::config::DEFAULT_FAILOVER_DEADLINE_SECS,
            crate::config::DEFAULT_FAILOVER_CAP,
        ),
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
            return ingress_error(
                ingress_protocol,
                StatusCode::SERVICE_UNAVAILABLE,
                "overloaded",
                "router: deadline exceeded",
            );
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
                    return ingress_error(
                        ingress_protocol,
                        StatusCode::SERVICE_UNAVAILABLE,
                        "overloaded",
                        "router: no usable lane",
                    );
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
                    ingress_protocol,
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
                return ingress_error(
                    ingress_protocol,
                    StatusCode::BAD_REQUEST,
                    "invalid_request_error",
                    &format!("router: unknown ingress protocol '{ingress_protocol}'"),
                );
            };
            match ingress_proto.reader().read_request(&v) {
                Ok(mut ir) => {
                    apply_required_max_tokens(&mut ir, &app.lanes[i]);
                    v = app.lanes[i].protocol.writer().write_request(&ir);
                }
                Err(_) => {
                    return ingress_error(
                        ingress_protocol,
                        StatusCode::BAD_REQUEST,
                        "invalid_request_error",
                        "router: request translation failed",
                    );
                }
            }
        }
        // existing rewrite_model sets the lane's model on the (possibly translated) body:
        app.lanes[i]
            .protocol
            .writer()
            .rewrite_model(&mut v, &app.lanes[i].model);
        // Same-protocol passthrough for a PATH-MODEL ingress (gemini/bedrock): the route layer
        // injected `model`/`stream` shim keys into the body so the shared resolve/forward plumbing
        // (which reads both from the body) works. Cross-protocol rebuilds `v` via read/write_request
        // so the shims are already gone there, but the same-protocol branch would forward them to the
        // backend — a router-internal leak (and, for Bedrock, an invalid Converse request). Strip them.
        if ingress_protocol == egress_name {
            strip_router_shim_keys(&mut v, ingress_protocol);
        }
        let payload = match serde_json::to_vec(&v) {
            Ok(p) => p,
            // Re-serializing a Value that was parsed from valid JSON and only rewritten with
            // serde_json values is effectively infallible; return a shaped 500 rather than panic a
            // worker on the request path (the layer's no-unwrap/expect rule).
            Err(_) => {
                drop(permit);
                return ingress_error(
                    ingress_protocol,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "api_error",
                    "router: failed to serialize request body",
                );
            }
        };
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

                    // Clone headers before consuming r with bytes(). The upstream `Retry-After`
                    // header (whole seconds) must be captured here — the per-protocol
                    // `extract_error` only sees the body, so the cooldown floor would otherwise be
                    // silently dropped on a 429 carrying an explicit retry hint.
                    let ct = r.headers().get(CONTENT_TYPE).cloned();
                    let retry_after_secs = r
                        .headers()
                        .get(axum::http::header::RETRY_AFTER)
                        .and_then(|v| v.to_str().ok())
                        .and_then(|s| s.trim().parse::<u64>().ok());
                    // Size-capped read: a hostile/misconfigured upstream must not force an unbounded
                    // heap allocation for a non-2xx body before the breaker classification runs.
                    let bytes = read_capped_body(r).await;

                    if is_passthrough_40x {
                        use axum::body::Body;
                        let mut rb = Response::builder().status(status);
                        if let Some(ct) = ct {
                            rb = rb.header(CONTENT_TYPE, ct);
                        }
                        // Re-create response from bytes for passthrough relay
                        return rb
                            .body(Body::from(bytes))
                            .unwrap_or_else(|_| status.into_response());
                    }

                    // Two-stage pipeline: Stage 1a (proto.extract_error) → RawUpstreamError
                    //                     Stage 1b (normalize_raw_error + error_map) → CanonicalSignal
                    //                     Stage 2 (breaker::classify_disposition) → Disposition
                    let mut raw = app.lanes[i].protocol.reader().extract_error(status, &bytes);
                    // Inject the Retry-After header (which the body-only extract_error can't see) so
                    // normalize_raw_error propagates it into CanonicalSignal.retry_after and the
                    // store honors it as a cooldown floor.
                    raw.retry_after_secs = retry_after_secs;
                    let sig = normalize_raw_error(&raw, &app.lanes[i].error_map);
                    let disposition = classify_disposition(&sig);

                    // Exhaustive match on Disposition - NO _ => allowed per requirements
                    match disposition {
                        Disposition::ClientFault => {
                            // ADR-0002: Client fault (caller's bad input) → no breaker penalty.
                            // Track client_fault separately from upstream err.
                            app.store.record_client_fault(i);
                            // Same-protocol passthrough relays the upstream 4xx body + CT verbatim
                            // (it is already in the client's native shape). Cross-protocol must
                            // RESHAPE the error into the ingress protocol's native envelope —
                            // relaying the EGRESS protocol's error body to a different-protocol
                            // client is an immediate proxy tell (e.g. an OpenAI-shaped 400 reaching
                            // an Anthropic SDK). The human message is lifted from the upstream body
                            // where available; the kind is derived from the classified StatusClass.
                            if ingress_protocol != egress_name {
                                let kind = client_fault_kind(sig.class);
                                let msg = extract_error_message(&bytes)
                                    .unwrap_or_else(|| "upstream rejected the request".to_string());
                                return ingress_error(ingress_protocol, status, kind, &msg);
                            }
                            use axum::body::Body;
                            let mut rb = Response::builder().status(status);
                            if let Some(ct) = ct {
                                rb = rb.header(CONTENT_TYPE, ct);
                            }
                            return rb
                                .body(Body::from(bytes))
                                .unwrap_or_else(|_| status.into_response());
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

                            // For auth failures: return error to caller. In NON-passthrough mode the
                            // rejected credential is busbar's OWN configured lane key, so the
                            // upstream's auth-rejection body is busbar-internal context (account
                            // ids, internal request ids, key hints) — do NOT leak it to an external
                            // caller. Return a normalized envelope instead. (Passthrough 401/403 is
                            // the caller's own key and is relayed verbatim earlier, before this.)
                            if matches!(sig.class, StatusClass::Auth) {
                                // Route through ingress_error so the body is the INGRESS protocol's
                                // NATIVE error envelope (Bedrock `{"__type":"AccessDeniedException",...}`,
                                // Gemini `{"error":{"status":"UNAUTHENTICATED",...}}`, etc.), not a
                                // hard-coded OpenAI-shaped body. The generic message still avoids
                                // leaking busbar's internal upstream auth-rejection body.
                                return ingress_error(
                                    ingress_protocol,
                                    status,
                                    "authentication_error",
                                    "upstream rejected the lane credential",
                                );
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
                    // Size-capped buffer: a non-stream completion body is far under the cap; this
                    // bounds a hostile/misconfigured upstream's allocation on the buffered path.
                    let bytes = read_capped_body(r).await;
                    drop(permit); // upstream call complete; a non-streamed response holds no permit
                                  // Token accounting: no FirstByteBody on this buffered path, so tap here.
                    record_nonstream_usage(&bytes, &usage_sink);
                    if let Ok(v) = serde_json::from_slice::<Value>(&bytes) {
                        if let Ok(mut ir) = app.lanes[i].protocol.reader().read_response(&v) {
                            if let Some(ingress_proto) =
                                crate::proto::protocol_for(ingress_protocol)
                            {
                                // Cross-protocol reframe: strip the backend's NATIVE-FORMAT identity
                                // so the ingress writer mints values in the CLIENT's format. Without
                                // this an OpenAI backend's `chatcmpl-...` id (or its opaque
                                // `system_fingerprint` / a matched `stop_sequence`) would leak
                                // verbatim to e.g. an Anthropic client — a foreign-format id is an
                                // immediate proxy tell (§8.2). This seam only runs when ingress !=
                                // egress; same-protocol passthrough never reaches here, so native ids
                                // are preserved there.
                                //
                                // `created` is deliberately LEFT INTACT: it is a plain unix-epoch int
                                // (no protocol-specific format to leak), and the ingress writers use
                                // "is `created` populated?" as the signal that this response crossed a
                                // protocol boundary and therefore SHOULD synthesize a native id
                                // (anthropic `write_response` mints `msg_…` only when `created` is
                                // `Some`). Clearing it here would suppress that synthesis and emit an
                                // id-less body — the opposite of the goal. The anthropic writer omits
                                // `created` from its wire shape entirely; the openai writer re-emits
                                // it as an int, which is format-neutral.
                                ir.id = None;
                                ir.system_fingerprint = None;
                                ir.stop_sequence = None;
                                let translated = ingress_proto.writer().write_response(&ir);
                                // Content-Type is the INGRESS JSON CT, not the upstream's — the body
                                // is now in the client's native non-stream shape (§8.4).
                                return Response::builder()
                                    .status(status)
                                    .header(CONTENT_TYPE, "application/json")
                                    .body(Body::from(translated.to_string()))
                                    .unwrap_or_else(|_| status.into_response());
                            }
                        }
                    }
                    // Not translatable (non-JSON / unexpected shape / unknown ingress): relay verbatim.
                    let mut rb = Response::builder().status(status);
                    if let Some(ct) = ct {
                        rb = rb.header(CONTENT_TYPE, ct);
                    }
                    return rb
                        .body(Body::from(bytes))
                        .unwrap_or_else(|_| status.into_response());
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
                    ingress_protocol,
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
                // Cross-protocol streaming: the body is reframed to the client's format, so the CT
                // must be the ingress client's, not the upstream's. Same-protocol passthrough keeps
                // the upstream CT verbatim. §8.4.
                let cross_protocol = ingress_protocol != app.lanes[i].protocol.name();
                match (cross_protocol && is_sse)
                    .then(|| ingress_stream_content_type(ingress_protocol))
                    .flatten()
                {
                    Some(client_ct) => {
                        rb = rb.header(CONTENT_TYPE, client_ct);
                    }
                    None => {
                        if let Some(ct) = ct {
                            rb = rb.header(CONTENT_TYPE, ct);
                        }
                    }
                }
                return rb
                    .body(axum_body)
                    .unwrap_or_else(|_| status.into_response());
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
        ingress_protocol,
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
#[allow(clippy::too_many_arguments)] // plumbing: each arg is an independent request input
async fn handle_exhaustion_for_pool(
    app: Arc<App>,
    cands: &[WeightedLane],
    now: u64,
    pool_name: &str,
    body: Bytes,
    caller_token: Option<&str>,
    request_ctx: &mut RequestCtx,
    ingress_protocol: &str,
) -> Response {
    // Look up pool-specific on_exhausted config, default to Status503 for unknown pools.
    let mode = app
        .on_exhausted_cfgs
        .get(pool_name)
        .cloned()
        .unwrap_or(OnExhausted::Status503);

    match mode {
        OnExhausted::Status503 => handle_status_503(&app, cands, now, pool_name, ingress_protocol),
        OnExhausted::FallbackPool(ref fallback_pool) => {
            handle_fallback_pool(
                app.clone(),
                body,
                caller_token,
                fallback_pool,
                request_ctx,
                ingress_protocol,
            )
            .await
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
                ingress_protocol,
            )
            .await
        }
    }
}

/// Status503 mode: return 503 with Retry-After header. The body is the ingress protocol's native
/// JSON error envelope (not `text/plain`) so an official SDK can decode it; the `Retry-After`
/// header is preserved so rate-aware clients still back off.
fn handle_status_503(
    app: &Arc<App>,
    cands: &[WeightedLane],
    now: u64,
    pool: &str,
    ingress_protocol: &str,
) -> Response {
    let soonest_remaining = find_soonest_cooldown(&app.store, cands, now, pool)
        .map(|idx| app.store.cooldown_remaining_in(pool, idx, now))
        .unwrap_or(1);

    let retry_after = soonest_remaining.max(1); // Ensure at least 1 second

    let mut resp = ingress_error(
        ingress_protocol,
        StatusCode::SERVICE_UNAVAILABLE,
        "overloaded",
        &format!("router: all lanes exhausted; retry after {}s", retry_after),
    );
    if let Ok(v) = axum::http::HeaderValue::from_str(&retry_after.to_string()) {
        resp.headers_mut()
            .insert(axum::http::header::RETRY_AFTER, v);
    }
    resp
}

/// Forward one request to a specific lane and relay the response. Shared by the degraded
/// last-resort exhaustion paths (FallbackPool routing + LeastBad). Unlike the main forward
/// loop these paths do NOT apply breaker disposition/failover classification — they relay
/// whatever the upstream returns verbatim. On a pre-response transport error the lane's
/// transient counter is recorded and `Err(())` is returned so the caller can try another
/// candidate (or give up). The concurrency `permit` is held for the lifetime of a streamed
/// success body (invariant) and dropped on error.
///
/// Limitation: this degraded path (least-bad / fallback-pool routing) forwards the request body
/// as-is and does not translate between protocols, so it is only correct for same-protocol
/// targets. Cross-protocol routing goes through the main `forward_with_pool` path.
#[tracing::instrument(name = "forward_once", skip_all, fields(lane = i))]
async fn forward_once(
    app: &Arc<App>,
    i: usize,
    permit: Permit,
    body: &Bytes,
    caller_token: Option<&str>,
    timeout_secs: u64,
    ingress_protocol: &str,
) -> Result<Response, ()> {
    // Re-parse body for per-lane model rewriting.
    let mut v: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => {
            return Ok(ingress_error(
                ingress_protocol,
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                &format!("router: bad json: {e}"),
            ));
        }
    };

    // stream intent for the stream-aware upstream path (Gemini).
    let wants_stream = v.get("stream").and_then(|s| s.as_bool()).unwrap_or(false);

    // Cross-protocol translation through the superset IR — same as the main path — so this degraded
    // route is correct when the chosen lane speaks a different protocol than the caller.
    let egress_name = app.lanes[i].protocol.name();
    if ingress_protocol != egress_name {
        let Some(ingress_proto) = crate::proto::protocol_for(ingress_protocol) else {
            return Ok(ingress_error(
                ingress_protocol,
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                &format!("router: unknown ingress protocol '{ingress_protocol}'"),
            ));
        };
        match ingress_proto.reader().read_request(&v) {
            Ok(mut ir) => {
                apply_required_max_tokens(&mut ir, &app.lanes[i]);
                v = app.lanes[i].protocol.writer().write_request(&ir);
            }
            Err(_) => {
                return Ok(ingress_error(
                    ingress_protocol,
                    StatusCode::BAD_REQUEST,
                    "invalid_request_error",
                    "router: request translation failed",
                ))
            }
        }
    }

    app.lanes[i]
        .protocol
        .writer()
        .rewrite_model(&mut v, &app.lanes[i].model);
    // Strip router-internal shim keys on the same-protocol passthrough path (see forward_with_pool).
    if ingress_protocol == egress_name {
        strip_router_shim_keys(&mut v, ingress_protocol);
    }
    let payload = match serde_json::to_vec(&v) {
        Ok(p) => p,
        // Effectively infallible (Value parsed from valid JSON); return a shaped 500 rather than
        // panic a worker on the request path.
        Err(_) => {
            return Ok(ingress_error(
                ingress_protocol,
                StatusCode::INTERNAL_SERVER_ERROR,
                "api_error",
                "router: failed to serialize request body",
            ))
        }
    };
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
                // Degraded path: relay the upstream error verbatim (no classification). Size-capped
                // read bounds a hostile/misconfigured upstream's allocation.
                let bytes = read_capped_body(r).await;
                let mut rb = Response::builder().status(status);
                if let Some(ct) = ct {
                    rb = rb.header(CONTENT_TYPE, ct);
                }
                return Ok(rb
                    .body(Body::from(bytes))
                    .unwrap_or_else(|_| status.into_response()));
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
                ingress_protocol,
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
            Ok(rb
                .body(guarded_body.into_body())
                .unwrap_or_else(|_| status.into_response()))
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
    ingress_protocol: &str,
) -> Response {
    // Deadline propagated across hops.
    if request_ctx.expired(now()) {
        return ingress_error(
            ingress_protocol,
            StatusCode::SERVICE_UNAVAILABLE,
            "overloaded",
            "router: deadline exceeded",
        );
    }

    // Loop guard: if this request already routed through this pool, stop (A→B→A).
    if request_ctx.is_pool_visited(pool_name) {
        return handle_status_503(&app, &[], now(), pool_name, ingress_protocol);
    }

    let Some(fallback_cands) = app.fallback_pools.get(pool_name).cloned() else {
        // Fallback pool not configured — cascade to Status503.
        return handle_status_503(&app, &[], now(), pool_name, ingress_protocol);
    };

    // Mark before re-entering so a cycle back to this pool is detected.
    request_ctx.mark_pool_visited(pool_name);

    // Try the fallback pool's members (concurrency-aware, accumulating exclusions across hops).
    loop {
        if request_ctx.expired(now()) {
            return ingress_error(
                ingress_protocol,
                StatusCode::SERVICE_UNAVAILABLE,
                "overloaded",
                "router: deadline exceeded",
            );
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
                ingress_protocol,
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
            ingress_protocol,
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
#[allow(clippy::too_many_arguments)] // plumbing: each arg is an independent request input
async fn handle_least_bad(
    app: &Arc<App>,
    cands: &[WeightedLane],
    now: u64,
    body: &Bytes,
    caller_token: Option<&str>,
    request_ctx: &RequestCtx,
    pool: &str,
    ingress_protocol: &str,
) -> Response {
    let Some(soonest_idx) = find_soonest_cooldown(&app.store, cands, now, pool) else {
        // No candidates at all - fall back to Status503.
        return handle_status_503(app, cands, now, pool, ingress_protocol);
    };

    tracing::warn!(
        pool = %pool,
        lane = %app.lanes[soonest_idx].model,
        cooldown_remaining_s = app.store.cooldown_remaining_in(pool, soonest_idx, now),
        "least-bad mode: routing to a degraded member (pool exhausted)"
    );

    // Bypass breaker usability for the last-resort path; grab the concurrency permit directly.
    let Some(permit) = app.store.try_acquire(soonest_idx) else {
        return handle_status_503(app, cands, now, pool, ingress_protocol);
    };

    match forward_once(
        app,
        soonest_idx,
        permit,
        body,
        caller_token,
        request_ctx.remaining(now),
        ingress_protocol,
    )
    .await
    {
        Ok(resp) => resp,
        Err(()) => handle_status_503(app, cands, now, pool, ingress_protocol),
    }
}

#[cfg(test)]
mod usage_tap_tests {
    use super::{find_matching_brace, stable_hash, UsageTap};
    use bytes::Bytes;

    #[test]
    fn test_find_matching_brace_underflow_safe() {
        // A closing brace with no opener must return None, not underflow/panic (hostile upstream).
        assert_eq!(find_matching_brace(b"}"), None);
        assert_eq!(find_matching_brace(b"}}}}"), None);
        // Balanced object still parses to its end.
        assert_eq!(find_matching_brace(br#"{"a":1}tail"#), Some(7));
        // A `}` inside a string is ignored.
        assert_eq!(find_matching_brace(br#"{"a":"}"}"#), Some(9));
        // Feeding such bytes through the tap must not panic.
        let mut t = UsageTap::new();
        t.feed(&Bytes::from_static(b"}}} garbage {not json"));
    }

    #[test]
    fn test_stable_hash_is_deterministic() {
        // Stable across calls (unlike DefaultHasher) so session affinity survives restarts.
        assert_eq!(stable_hash("session-abc"), stable_hash("session-abc"));
        assert_ne!(stable_hash("session-abc"), stable_hash("session-xyz"));
    }

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
            default_max_tokens: None,
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

#[cfg(test)]
mod mid_stream_error_tests {
    use super::{
        client_fault_kind, extract_error_message, mid_stream_error_bytes, strip_router_shim_keys,
    };
    use crate::proto::StatusClass;
    use serde_json::{json, Value};

    /// HIGH (forward.rs:353-380 / 372-380): a mid-stream upstream failure on a BEDROCK-ingress stream
    /// (the client decodes binary `application/vnd.amazon.eventstream`) MUST be emitted as a valid
    /// binary exception frame — never an SSE `event: error` text frame, which would inject ASCII into
    /// a binary body and produce an undecodable prelude/CRC for the AWS SDK's eventstream decoder.
    #[test]
    fn test_bedrock_ingress_mid_stream_error_is_binary_exception_frame() {
        let bytes = mid_stream_error_bytes("bedrock", true, "connection reset by peer");
        // Must NOT be SSE text.
        assert!(
            !bytes.starts_with(b"event:") && !bytes.starts_with(b"data:"),
            "bedrock ingress error must be a binary frame, not SSE text"
        );
        // Must decode as a valid event-stream message with the AWS exception markers + JSON payload.
        let total_len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        assert_eq!(total_len, bytes.len(), "valid total_len (CRC-framed)");
        let prelude_crc = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        assert_eq!(
            prelude_crc,
            crc32fast::hash(&bytes[..8]),
            "real prelude CRC"
        );
        let len = bytes.len();
        let msg_crc = u32::from_be_bytes([
            bytes[len - 4],
            bytes[len - 3],
            bytes[len - 2],
            bytes[len - 1],
        ]);
        assert_eq!(
            msg_crc,
            crc32fast::hash(&bytes[..len - 4]),
            "real message CRC"
        );
        let headers_len = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;
        let headers = String::from_utf8_lossy(&bytes[12..12 + headers_len]);
        assert!(headers.contains(":message-type"));
        assert!(headers.contains("exception"));
        assert!(headers.contains(":exception-type"));
        // Generic transient failure maps to a real AWS Converse exception name.
        assert!(headers.contains("InternalServerException"));
        let payload = &bytes[12 + headers_len..len - 4];
        let v: Value = serde_json::from_slice(payload).expect("valid JSON payload");
        assert_eq!(v["message"], "connection reset by peer");
    }

    /// An SSE ingress client (e.g. OpenAI) must receive an `event: error` SSE frame whose `data:`
    /// payload is the INGRESS protocol's native error envelope — not the previously hard-coded
    /// Anthropic shape, and not a binary frame.
    #[test]
    fn test_sse_ingress_mid_stream_error_is_native_sse() {
        let bytes = mid_stream_error_bytes("openai", false, "boom");
        let text = String::from_utf8(bytes).expect("SSE error is utf-8 text");
        assert!(
            text.starts_with("event: error\n"),
            "SSE error frame; got: {text}"
        );
        let data = text
            .lines()
            .find_map(|l| l.strip_prefix("data: "))
            .expect("a data: line");
        let v: Value = serde_json::from_str(data).expect("native JSON envelope");
        // OpenAI native error envelope shape.
        assert!(v.get("error").is_some(), "OpenAI envelope: {v}");
        assert_eq!(v["error"]["type"], "api_error");
    }

    /// `client_fault_kind` maps the classified 4xx to a protocol-agnostic kind, exhaustively.
    #[test]
    fn test_client_fault_kind_mapping() {
        assert_eq!(
            client_fault_kind(StatusClass::ContextLength),
            "context_length_exceeded"
        );
        assert_eq!(
            client_fault_kind(StatusClass::ClientError),
            "invalid_request_error"
        );
    }

    /// `extract_error_message` pulls the human message across vendor shapes, and returns None for a
    /// non-JSON / message-less body so the caller substitutes a generic detail (no foreign leak).
    #[test]
    fn test_extract_error_message() {
        assert_eq!(
            extract_error_message(br#"{"error":{"message":"bad param"}}"#).as_deref(),
            Some("bad param")
        );
        assert_eq!(
            extract_error_message(br#"{"message":"flat"}"#).as_deref(),
            Some("flat")
        );
        assert_eq!(extract_error_message(b"not json"), None);
        assert_eq!(extract_error_message(br#"{"foo":1}"#), None);
    }

    /// PATH-MODEL ingress (gemini/bedrock) must have the router-injected `model`/`stream` shim keys
    /// stripped before same-protocol forwarding; body-model ingress (openai) keeps them (genuine).
    #[test]
    fn test_strip_router_shim_keys() {
        let mut v = json!({"model": "p", "stream": true, "messages": []});
        strip_router_shim_keys(&mut v, "bedrock");
        assert!(v.get("model").is_none(), "bedrock: model shim stripped");
        assert!(v.get("stream").is_none(), "bedrock: stream shim stripped");
        assert!(v.get("messages").is_some(), "real fields retained");

        let mut v = json!({"model": "p", "stream": true});
        strip_router_shim_keys(&mut v, "gemini");
        assert!(v.get("model").is_none() && v.get("stream").is_none());

        // OpenAI is a BODY-MODEL protocol: model/stream are genuine caller fields, never stripped.
        let mut v = json!({"model": "gpt-4o", "stream": true});
        strip_router_shim_keys(&mut v, "openai");
        assert_eq!(
            v["model"], "gpt-4o",
            "openai model is genuine, not stripped"
        );
        assert_eq!(v["stream"], true);
    }
}

#[cfg(test)]
mod ingress_indistinguishability_tests {
    use super::{forward_with_pool, ingress_error, ingress_stream_content_type};
    use crate::test_support::{LaneSpec, MockResponse, MockServer, MockServerState, TestApp};
    use reqwest::StatusCode;
    use serde_json::{json, Value};
    use std::sync::Arc;

    /// A forward-layer error returned to the CLIENT must carry the INGRESS protocol's native JSON
    /// error envelope (not `text/plain`), with the status code preserved. For an Anthropic ingress
    /// the shape is `{"type":"error","error":{"type",...,"message"}}` — what `anthropic.APIStatusError`
    /// decodes. (§8.1)
    #[tokio::test]
    async fn test_ingress_error_emits_native_envelope_with_status() {
        use http_body_util::BodyExt as _;
        let resp = ingress_error(
            "anthropic",
            StatusCode::BAD_REQUEST,
            "invalid_request_error",
            "router: bad json: trailing comma",
        );
        assert_eq!(resp.status().as_u16(), 400, "status code is preserved");
        assert_eq!(
            resp.headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json"),
            "native error envelope is served as application/json, never text/plain"
        );
        // Body is the Anthropic-native error shape.
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            v["type"], "error",
            "Anthropic error envelope: top-level type"
        );
        assert_eq!(
            v["error"]["type"], "invalid_request_error",
            "Anthropic typed error kind"
        );
        assert!(
            v["error"]["message"]
                .as_str()
                .unwrap_or("")
                .contains("bad json"),
            "human-readable detail preserved: {v}"
        );

        // OpenAI ingress gets the OpenAI envelope shape instead, same status.
        let oai = ingress_error(
            "openai",
            StatusCode::SERVICE_UNAVAILABLE,
            "overloaded",
            "router: all lanes exhausted; retry after 3s",
        );
        assert_eq!(oai.status().as_u16(), 503);
        assert_eq!(
            oai.headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json")
        );
    }

    /// The streaming response Content-Type is driven by the ingress protocol, not the upstream:
    /// SSE protocols → `text/event-stream`; bedrock → `application/vnd.amazon.eventstream`. (§8.4)
    #[test]
    fn test_ingress_stream_content_type_by_protocol() {
        for p in ["openai", "anthropic", "gemini", "cohere", "responses"] {
            assert_eq!(ingress_stream_content_type(p), Some("text/event-stream"));
        }
        assert_eq!(
            ingress_stream_content_type("bedrock"),
            Some("application/vnd.amazon.eventstream")
        );
        assert_eq!(ingress_stream_content_type("nonsense"), None);
    }

    /// Cross-protocol non-stream response: an OpenAI backend whose body carries a `chatcmpl-` id
    /// must NOT leak that foreign id to an Anthropic client. The translation seam strips the IR
    /// identity before the ingress writer runs, so the writer mints a NATIVE `msg_` id, and the
    /// response is served with the INGRESS Content-Type (`application/json`). (§8.2, §8.4)
    #[tokio::test]
    async fn test_cross_protocol_response_carries_ingress_ct_and_native_id() {
        crate::metrics::init();
        let state = Arc::new(MockServerState::new());
        // OpenAI-shaped backend response with a foreign `chatcmpl-` id + created + fingerprint.
        state.push(MockResponse::Ok {
            status: StatusCode::OK,
            body: json!({
                "id": "chatcmpl-LEAK123",
                "object": "chat.completion",
                "created": 1234567890,
                "system_fingerprint": "fp_backend",
                "model": "glm-4.5",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "Hi"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 7, "completion_tokens": 3}
            }),
        });
        let server = MockServer::new(state.clone()).await;

        // Lane speaks OpenAI; ingress is Anthropic → cross-protocol translation hop.
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
        // Ingress-driven Content-Type for a non-stream cross-protocol response.
        assert_eq!(
            resp.headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json"),
            "non-stream cross-protocol response uses the ingress JSON Content-Type"
        );

        use http_body_util::BodyExt as _;
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        // Native Anthropic message shape.
        assert_eq!(v["type"], "message", "Anthropic message envelope");
        let id = v["id"].as_str().unwrap_or("");
        assert!(
            id.starts_with("msg_"),
            "Anthropic client must receive a NATIVE msg_ id, got: {id}"
        );
        assert!(
            !id.contains("chatcmpl-"),
            "the OpenAI backend's chatcmpl- id must NOT leak to the Anthropic client; got: {id}"
        );
        // The whole serialized body must be free of the leaked backend identity.
        let raw = String::from_utf8_lossy(&bytes);
        assert!(
            !raw.contains("chatcmpl-LEAK123"),
            "no foreign id anywhere in the translated response: {raw}"
        );
        assert!(
            !raw.contains("fp_backend"),
            "backend system_fingerprint must not leak across protocols: {raw}"
        );
        server.shutdown().await;
    }

    /// HIGH (forward.rs:987-996): a cross-protocol CLIENT-fault 4xx must be RESHAPED into the ingress
    /// protocol's native error envelope, not relayed with the EGRESS protocol's foreign error body.
    /// An OpenAI backend returning a 400 with an OpenAI-shaped error must reach an Anthropic client as
    /// the Anthropic error shape (`{"type":"error","error":{...}}`), with no OpenAI fields leaking.
    #[tokio::test]
    async fn test_cross_protocol_client_fault_reshapes_error_envelope() {
        crate::metrics::init();
        let state = Arc::new(MockServerState::new());
        // OpenAI-shaped 400 client-fault error body from the backend.
        state.push(MockResponse::Ok {
            status: StatusCode::BAD_REQUEST,
            body: json!({
                "error": {
                    "message": "Invalid 'max_tokens': must be positive",
                    "type": "invalid_request_error",
                    "param": "max_tokens",
                    "code": "invalid_value"
                }
            }),
        });
        let server = MockServer::new(state.clone()).await;
        let app = TestApp::new()
            .lane(
                LaneSpec::new(
                    "glm-4.5",
                    crate::proto::Protocol::openai(),
                    &server.base_url(),
                )
                .provider("zai"),
            )
            .pool("pc", &[(0, 1)])
            .build();

        let body = serde_json::to_vec(
            &json!({"model": "pc", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 50}),
        )
        .unwrap();
        let resp = forward_with_pool(
            app.clone(),
            vec![crate::state::WeightedLane { idx: 0, weight: 1 }],
            body.into(),
            None,
            "pc",
            None,
            "anthropic",
            None,
        )
        .await;
        assert_eq!(resp.status().as_u16(), 400, "client-fault status preserved");
        assert_eq!(
            resp.headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json")
        );
        use http_body_util::BodyExt as _;
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        // Anthropic-native error envelope, NOT the OpenAI shape.
        assert_eq!(v["type"], "error", "Anthropic top-level error type");
        assert_eq!(v["error"]["type"], "invalid_request_error");
        let raw = String::from_utf8_lossy(&bytes);
        assert!(
            !raw.contains("\"param\"") && !raw.contains("\"code\""),
            "OpenAI-specific error fields must not leak to an Anthropic client: {raw}"
        );
        // The human message is carried through.
        assert!(
            v["error"]["message"]
                .as_str()
                .unwrap_or("")
                .contains("max_tokens"),
            "upstream message surfaced: {v}"
        );
        server.shutdown().await;
    }

    /// A forward error path through the real `forward_with_pool` (empty candidate pool → exhaustion)
    /// returns the ingress protocol's native JSON envelope with the right status. (§8.1)
    #[tokio::test]
    async fn test_forward_error_path_returns_native_envelope() {
        use http_body_util::BodyExt as _;
        crate::metrics::init();
        let app = TestApp::new().build();
        // No candidates → "no usable lane" 503, shaped to the ingress (OpenAI) envelope.
        let resp = forward_with_pool(
            app.clone(),
            vec![],
            serde_json::to_vec(&json!({"model": "x", "messages": []}))
                .unwrap()
                .into(),
            None,
            "missingpool",
            None,
            "openai",
            None,
        )
        .await;
        assert_eq!(resp.status().as_u16(), 503, "no usable lane → 503");
        assert_eq!(
            resp.headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json"),
            "forward error envelope is JSON, not text/plain"
        );
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        assert!(
            v.get("error").is_some(),
            "OpenAI-native error envelope has a top-level error object: {v}"
        );
    }
}
