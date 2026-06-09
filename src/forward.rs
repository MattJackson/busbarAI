// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::{
    body::Body,
    http::header::{CONTENT_TYPE, USER_AGENT},
    response::IntoResponse,
    response::Response,
};
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
/// Current unix time in whole seconds, or 0 if the system clock predates the epoch. Never panics —
/// it is on the request path, where a clock error must degrade (a `created: 0` is still a valid int
/// every SDK accepts) rather than abort. Mirrors the per-protocol `unix_now_secs` helpers; used at
/// the cross-protocol seam to stamp a synthesized `created` so an identity-empty egress reader's IR
/// (e.g. Bedrock) trips the writers' `created`-based boundary signal.
fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn apply_required_max_tokens(ir: &mut crate::ir::IrRequest, lane: &Lane) {
    if ir.max_tokens.is_none() && lane.protocol.writer().requires_max_tokens() {
        ir.max_tokens = Some(
            lane.default_max_tokens
                .unwrap_or(crate::proto::DEFAULT_MAX_TOKENS),
        );
    }
}

/// Attach the `x-amzn-RequestId` header to a SUCCESS response builder when the ingress client is a
/// native AWS Bedrock SDK. A genuine Bedrock `Converse`/`ConverseStream` 2xx ALWAYS carries this
/// header (the SDK surfaces it via `*Output::request_id()`); omitting it on the proxied success path
/// makes `request_id()` return `None`, which is impossible with a real endpoint and a deterministic
/// proxy tell. The error path already synthesizes it (`route::attach_bedrock_error_headers`,
/// `auth::unauthorized_response`); this closes the SUCCESS gap so every bedrock-ingress response —
/// success and error, stream and non-stream — carries the id. No-op for non-bedrock ingress (those
/// protocols never emit an `x-amzn-*` header). Best-effort: if entropy or header encoding fails the
/// header is simply omitted (never panics on the request path).
fn maybe_attach_bedrock_amzn_id(
    rb: axum::http::response::Builder,
    ingress_protocol: &str,
) -> axum::http::response::Builder {
    if ingress_protocol != "bedrock" {
        return rb;
    }
    match crate::proto::synth_amzn_request_id() {
        Some(id) => rb.header("x-amzn-requestid", id),
        None => rb,
    }
}

/// Attach the `request-id` RESPONSE HEADER to an anthropic-ingress 2xx/relay response. A real
/// Anthropic endpoint ALWAYS sends `request-id`, and the official SDK reads it into
/// `APIError.request_id` / `Message._request_id` (the body `request_id` is NOT what the SDK uses on
/// the read path), so omitting it left the SDK's `request_id == None` on every busbar anthropic
/// response — impossible against the real API and a deterministic proxy tell. No-op for non-anthropic
/// ingress (mirroring `maybe_attach_bedrock_amzn_id`'s proto guard, so other protocols never get a
/// spurious anthropic header). Forwards the captured UPSTREAM id verbatim on a same-protocol
/// passthrough; synthesizes a shape-correct `req_…` id otherwise. Synthesis failure (no entropy)
/// simply OMITS the header rather than panicking on the request path.
fn maybe_attach_anthropic_request_id(
    rb: axum::http::response::Builder,
    ingress_protocol: &str,
    upstream_request_id: Option<&str>,
) -> axum::http::response::Builder {
    if ingress_protocol != "anthropic" {
        return rb;
    }
    match upstream_request_id
        .map(|s| s.to_string())
        .or_else(crate::proto::synth_anthropic_request_id)
    {
        Some(id) => rb.header("request-id", id),
        None => rb,
    }
}

/// The CANONICAL per-protocol error-response builder. Every forward-layer error returned to the
/// caller goes through here so the body is the INGRESS protocol's native error envelope
/// (`application/json`) rather than `text/plain`, which an official SDK cannot decode (it raises a
/// generic JSON-decode error — a deterministic proxy tell, design §8.1). The status code is
/// preserved exactly; only the body shape changes. `kind` is the protocol-agnostic error category
/// (e.g. `"invalid_request_error"`, `"overloaded"`, `"authentication_error"`); `msg` is the
/// human-readable detail. When `ingress` does not resolve to a known protocol, falls back to the
/// generic default envelope via the OpenAI writer (`protocol_for` only fails for an unknown literal,
/// which is itself a 400 the caller still needs shaped).
///
/// `pub(crate)` and the single source of truth for native error shaping: it attaches the
/// protocol-appropriate headers (Bedrock `x-amzn-RequestId` / `x-amzn-errortype` via the shared
/// `proto::attach_bedrock_error_headers`; Gemini code/status ride the body envelope the writer
/// builds). `route.rs::ingress_error` and `auth.rs::unauthorized_response` keep wire-identical
/// private copies pending their migration to this function next round — once they call it, the
/// degraded path, the main path, and the auth/route paths cannot diverge on error shape or headers.
pub(crate) fn ingress_error(ingress: &str, status: StatusCode, kind: &str, msg: &str) -> Response {
    let envelope = match crate::proto::protocol_for(ingress) {
        Some(p) => p.writer().write_error(status.as_u16(), kind, msg),
        None => crate::proto::Protocol::openai()
            .writer()
            .write_error(status.as_u16(), kind, msg),
    };
    let body = serde_json::to_string(&envelope).unwrap_or_else(|_| {
        // Envelope is built from serde_json::json! values and always serializes; this fallback only
        // exists to avoid an unwrap on the request path. Build it with `json!` (correct JSON string
        // escaping) rather than interpolating Rust `{:?}` Debug formatting, which is NOT guaranteed
        // valid JSON escaping for all inputs (e.g. it differs on `/` and some control sequences).
        serde_json::json!({ "error": { "message": msg, "type": kind } }).to_string()
    });
    let mut resp = Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap_or_else(|_| status.into_response());
    // Bedrock ingress: a real AWS Bedrock runtime response ALWAYS carries `x-amzn-RequestId` (the
    // only request-id surface the AWS SDK exposes via `*Output::request_id()`) and an
    // `x-amzn-errortype` header equal to the body `__type`. A forward-layer error that omitted both
    // was distinguishable from native Bedrock and left the SDK's request id empty — the most-
    // exercised error surface under failover. Attach them via the shared helper so this path cannot
    // drift from `route.rs`/`auth.rs`.
    if ingress == "bedrock" {
        crate::proto::attach_bedrock_error_headers(resp.headers_mut(), kind);
    }
    // Anthropic ingress: a real Anthropic response ALWAYS carries the request id in the `request-id`
    // RESPONSE HEADER (the official SDK reads `request-id` into `APIError.request_id` /
    // `Message._request_id`, NOT the body), so an anthropic error that omitted the header left
    // `err.request_id == None` on every response — impossible against the real API and a deterministic
    // tell. The writer already mints a top-level body `request_id`; mirror it into the header so body
    // and header AGREE and the SDK populates `request_id`.
    if ingress == "anthropic" {
        if let Some(rid) = envelope.get("request_id").and_then(|v| v.as_str()) {
            if let Ok(hv) = axum::http::HeaderValue::from_str(rid) {
                resp.headers_mut().insert("request-id", hv);
            }
        }
    }
    resp
}

/// CANONICAL mapping from an upstream HTTP status to the protocol-agnostic error `kind`, for shaping
/// a CROSS-PROTOCOL non-2xx upstream response into the ingress protocol's native error envelope.
/// Shared by BOTH the main forward loop (`forward_with_pool`) and the degraded last-resort path
/// (`forward_once`) so they cannot drift on which kind a given status maps to (the bug this closes:
/// the degraded path labeled a 401/403 `invalid_request_error` while the main path correctly used
/// `authentication_error`/`permission_error`, an SDK-visible typed-exception mismatch and an
/// indistinguishability leak). The mapping mirrors the native discriminant a real vendor uses for
/// each status.
fn cross_protocol_error_kind(status: StatusCode) -> &'static str {
    if status == StatusCode::UNAUTHORIZED {
        "authentication_error"
    } else if status == StatusCode::FORBIDDEN {
        "permission_error"
    } else if status == StatusCode::TOO_MANY_REQUESTS {
        "rate_limit_error"
    } else if status.is_server_error() {
        "api_error"
    } else {
        "invalid_request_error"
    }
}

/// Shared finalizer for a cross-protocol NON-2xx upstream response, used by BOTH `forward_with_pool`
/// and `forward_once`. Lifts the upstream's human message where present, maps the status to the
/// canonical ingress `kind` (`cross_protocol_error_kind`), and reshapes into the ingress protocol's
/// native error envelope via `ingress_error`. Relaying the EGRESS provider's native error body to a
/// different-protocol client is a foreign-format leak (§8.2) the SDK cannot decode into its typed
/// exception — an immediate proxy tell — so a crossed boundary NEVER relays verbatim.
fn shape_cross_protocol_error(
    ingress_protocol: &str,
    status: StatusCode,
    bytes: &[u8],
) -> Response {
    let kind = cross_protocol_error_kind(status);
    let msg = extract_error_message(bytes).unwrap_or_else(|| GENERIC_REJECTED_DETAIL.to_string());
    ingress_error(ingress_protocol, status, kind, &msg)
}

/// Remove the router-internal SHIM KEYS the route layer injects into the request body for PATH-MODEL
/// ingress protocols (`gemini`, `bedrock`), where the native wire carries the model in the URL and
/// stream intent in the path, not the body. Two keys, handled differently relative to `rewrite_model`
/// because their correct egress treatment differs:
///
///   - The gemini JSON-array key is NEVER a native egress body field for ANY backend (it only
///     influences RESPONSE framing), so it is stripped UNCONDITIONALLY on every branch and for every
///     egress.
///   - `stream` is a body field only for the BODY-MODEL protocols (openai/anthropic/cohere/responses),
///     where the egress writer authoritatively writes `"stream": <ir.stream>` and the backend reads it
///     to decide streaming. It is a PATH shim only for the PATH-MODEL egress protocols
///     (`gemini`/`bedrock`), whose native wire conveys stream intent via the URL/path, never the body.
///     So `stream` is stripped iff the EGRESS is gemini/bedrock — NOT based on the ingress. The old
///     ingress-gated strip deleted the writer-authored `"stream": true` on a gemini/bedrock-ingress →
///     body-model-egress streaming hop, so the backend saw no stream flag, answered non-streaming, and
///     the client got a wrong (buffered / mis-framed) response. Gating on egress keeps the writer's
///     authoritative `stream` for body-model backends and still strips it for path-model backends
///     (where the URL carries the intent and a body `stream` would be a router fingerprint).
///   - `model` is stripped ONLY on the same-protocol branch (by [`strip_same_protocol_model_shim`],
///     after `rewrite_model`), never cross-protocol: a body-model egress REQUIRES `model` and
///     `rewrite_model` installs the authoritative one.
///
/// The gemini array key is stripped for body-model ingress too (it is never native to any protocol).
fn strip_router_shim_keys(v: &mut Value, egress_protocol: &str) {
    if let Some(obj) = v.as_object_mut() {
        // The gemini JSON-array key is never native to ANY protocol → strip unconditionally (also
        // closes the leak where a body-model client smuggles the key in its own controlled body).
        obj.remove(GEMINI_JSON_ARRAY_SHIM_KEY);
        // `stream` is a path-model shim for the EGRESS protocols gemini/bedrock (stream intent rides
        // the URL there); for body-model egress it is the writer-authored field the backend needs to
        // start streaming, so it must be PRESERVED. Gate on egress, never ingress.
        if matches!(egress_protocol, "gemini" | "bedrock") {
            obj.remove("stream");
        }
    }
}

/// Remove the SHIM `model` key on the SAME-PROTOCOL gemini/bedrock passthrough path, AFTER
/// `rewrite_model` has run. On same-protocol gemini/bedrock the model rides the URL, not the body, so
/// a native Converse / generateContent backend must NOT see a body `model`; but the gemini writer's
/// `rewrite_model` re-inserts one, so this strip must run AFTER it to remove both the route layer's
/// shim and the re-inserted copy. NEVER call this on the cross-protocol branch: there the body-model
/// egress requires the `model` that `rewrite_model` installed. No-op for body-model ingress.
fn strip_same_protocol_model_shim(v: &mut Value, ingress_protocol: &str) {
    if matches!(ingress_protocol, "gemini" | "bedrock") {
        if let Some(obj) = v.as_object_mut() {
            obj.remove("model");
        }
    }
}

/// Router-internal shim key the gemini ingress route injects into the request body when the client
/// sent a streaming `:streamGenerateContent` request WITHOUT `?alt=sse` (so the response must be the
/// JSON-array streaming format, not SSE). Defined once in `proto` and re-exported here so the route
/// injection, this strip, and the Gemini reader's `modeled_keys` exclusion all share one literal.
use crate::proto::GEMINI_JSON_ARRAY_SHIM_KEY;

/// True when the body carries the gemini JSON-array shim key set to `true` (see
/// [`GEMINI_JSON_ARRAY_SHIM_KEY`]).
fn wants_gemini_json_array(v: &Value) -> bool {
    v.get(GEMINI_JSON_ARRAY_SHIM_KEY)
        .and_then(|b| b.as_bool())
        .unwrap_or(false)
}

/// The SINGLE source of truth for shaping an ingress request body into the bytes sent to one egress
/// lane. Both the hot path ([`forward_with_pool`], per failover hop) and the degraded last-resort
/// path ([`forward_once`], FallbackPool/LeastBad) call THIS function so the two cannot drift apart on
/// any translation step — historically they did (R8 added `ir.extra.clear()` to the hot path only;
/// R9 found `forward_once` lacked it, leaking OpenAI `logprobs`/`top_logprobs`/`n` onto an Anthropic
/// or Gemini backend). Unifying the seam makes that whole class of "one path is missing a step"
/// regressions structurally impossible: there is now exactly one step list.
///
/// `body` is the per-hop parsed request `Value` (the caller owns deriving it fresh from the pristine
/// body so a failover hop never re-translates a previous hop's egress-shaped body). It is consumed
/// and the shaped egress bytes are returned. The full step list, in order:
///   1. CROSS-protocol only (`ingress_protocol != egress`): read_request → `apply_required_max_tokens`
///      → `ir.extra.clear()` → egress `write_request`. Clearing `extra` at this single seam, before
///      any writer runs, is what stops every source-protocol-only passthrough key from leaking to a
///      foreign backend — no individual writer can miss it.
///   2. Strip the never-native router shim keys (gemini JSON-array key always; `stream` for path-model
///      EGRESS) on every branch.
///   3. `rewrite_model` installs the authoritative lane model.
///   4. SAME-protocol only: strip the body `model` shim (path-model gemini/bedrock carry the model in
///      the URL; a body `model` there is an indistinguishability leak).
///   5. Serialize to bytes.
///
/// Returns `Err(Response)` — an ingress-native error envelope with the right status — on the only two
/// shaping failures (unknown ingress protocol, request translation error) and on the effectively
/// infallible re-serialization, so neither caller can panic on the request path.
pub(crate) fn translate_request_cross_protocol(
    app: &Arc<App>,
    i: usize,
    ingress_protocol: &str,
    mut body: Value,
) -> Result<Vec<u8>, Box<Response>> {
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
            return Err(Box::new(ingress_error(
                ingress_protocol,
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                "We received an unexpected internal error. Please try again.",
            )));
        };
        match ingress_proto.reader().read_request(&body) {
            Ok(mut ir) => {
                apply_required_max_tokens(&mut ir, &app.lanes[i]);
                // CROSS-PROTOCOL extra-key leak guard (the structural class fix). Every reader sweeps
                // unmodeled top-level request keys into `ir.extra`; on a SAME-protocol round-trip the
                // egress writer re-emits them verbatim (lossless passthrough, the intended behavior).
                // But on a CROSS-protocol hop those keys are source-protocol-only passthrough fields,
                // and the foreign egress writer would merge them onto the backend body — leaking e.g.
                // OpenAI `logprobs`/`top_logprobs`/`n` onto an Anthropic or Gemini backend (a §8.2
                // foreign-format leak and a deterministic proxy tell). Clear `extra` ONCE here, at the
                // single shared translate seam, BEFORE handing the IR to the egress `write_request`, so
                // no individual writer can leak them and the fix cannot be missed on any one path.
                // Same-protocol passthrough never enters this branch, so its `extra` stays intact.
                ir.extra.clear();
                body = app.lanes[i].protocol.writer().write_request(&ir);
            }
            Err(_) => {
                return Err(Box::new(ingress_error(
                    ingress_protocol,
                    StatusCode::BAD_REQUEST,
                    "invalid_request_error",
                    "We could not process the content of your request.",
                )));
            }
        }
    }
    // Remove the never-native shim keys (gemini JSON-array key on every protocol; `stream` for
    // path-model EGRESS) on EVERY branch — same- AND cross-protocol. `model` is handled below,
    // ordered relative to `rewrite_model`.
    strip_router_shim_keys(&mut body, egress_name);
    // `rewrite_model` installs the authoritative lane model. ORDERING (critical): on a cross-protocol
    // hop to a BODY-MODEL egress (gemini/bedrock → openai/anthropic/cohere/responses) the backend
    // REQUIRES this `model` body field, so `model` is stripped ONLY on the same-protocol passthrough
    // (below), where the model rides the URL and a body `model` is an indistinguishability leak.
    app.lanes[i]
        .protocol
        .writer()
        .rewrite_model(&mut body, &app.lanes[i].model);
    if ingress_protocol == egress_name {
        strip_same_protocol_model_shim(&mut body, ingress_protocol);
    }
    match serde_json::to_vec(&body) {
        Ok(p) => Ok(p),
        // Re-serializing a Value parsed from valid JSON and rewritten only with serde_json values is
        // effectively infallible; return a shaped 500 rather than panic a worker on the request path
        // (the layer's no-unwrap/expect rule).
        Err(_) => Err(Box::new(ingress_error(
            ingress_protocol,
            StatusCode::INTERNAL_SERVER_ERROR,
            "api_error",
            "We received an unexpected internal error. Please try again.",
        ))),
    }
}

/// Upper bound on a buffered UPSTREAM ERROR body (4xx/5xx envelopes). Any error envelope is far
/// smaller than this; the cap stops a hostile or misconfigured upstream from forcing an unbounded
/// heap allocation per in-flight non-2xx response (the inbound request body is already capped
/// separately). This is the TIGHT cap — it is deliberately NOT reused for buffering a legitimate
/// cross-protocol 2xx completion (see [`MAX_TRANSLATED_BODY_BYTES`]).
const MAX_UPSTREAM_BUFFERED_BYTES: usize = 256 * 1024;

/// Upper bound on a buffered cross-protocol non-stream SUCCESS (2xx) body that must be parsed and
/// translated egress→IR→ingress. A real completion (large `max_tokens` output, big tool-call
/// arguments, embedded content) can far exceed the tight error-body cap; truncating it would make
/// `serde_json` parsing fail and the request would be reported to the client as a spurious 500 for
/// what was actually an upstream success (the caller may even have been token-charged). This cap is
/// aligned with the inbound request-body limit (32 MiB) so any completion the gateway would accept
/// inbound can also be buffered for translation, while still bounding the per-response allocation.
const MAX_TRANSLATED_BODY_BYTES: usize = 32 * 1024 * 1024;

/// Read an upstream response body, buffering at most `cap` bytes. Streams chunks with a running byte
/// counter rather than `r.bytes()` (which would buffer the entire — possibly multi-gigabyte — body
/// before any cap could apply). Returns the buffered prefix and whether the body was TRUNCATED (more
/// bytes remained at the cap), so a caller that must parse the whole body (cross-protocol 2xx
/// translation) can distinguish "too large to translate" from "genuinely unparseable" instead of
/// silently mis-reporting a truncated success as an untranslatable error.
/// Why a [`read_capped`] read stopped — distinguishes a body that arrived in full from one that
/// was cut short, so the buffered cross-protocol translate path can avoid mis-accounting a
/// half-received completion as a clean success (recording breaker success + charging tokens on a
/// body that is in fact a truncated/corrupt fragment of a failed transfer).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadEnd {
    /// The upstream signalled end-of-body (`Ok(None)`): the buffer holds the complete response.
    Complete,
    /// The body overran `cap` before EOF: the buffer holds a prefix, more bytes existed.
    Truncated,
    /// The transport failed mid-body (`Err(_)` from `chunk()`): the buffer holds an incomplete,
    /// possibly-corrupt fragment of a transfer that never finished. NOT a clean completion.
    TransportError,
}

async fn read_capped(r: reqwest::Response, cap: usize) -> (Bytes, ReadEnd) {
    let mut buf: Vec<u8> = Vec::new();
    let mut r = r;
    let mut end = ReadEnd::Complete;
    loop {
        match r.chunk().await {
            Ok(Some(chunk)) => {
                let remaining = cap.saturating_sub(buf.len());
                if remaining == 0 {
                    // Cap already full but more bytes arrived — the body overran the cap. Stop
                    // reading; the connection is dropped when `r` falls out of scope.
                    end = ReadEnd::Truncated;
                    break;
                }
                let take = remaining.min(chunk.len());
                buf.extend_from_slice(&chunk[..take]);
                if take < chunk.len() {
                    end = ReadEnd::Truncated; // this chunk filled the cap with bytes left over
                    break;
                }
            }
            Ok(None) => break, // clean end of body — buffer is complete
            Err(_) => {
                // Transport error mid-body. Keep what we have for any best-effort error relay, but
                // flag it so the buffered translate path does NOT treat a half-received body as a
                // clean 2xx completion (which would record breaker success and charge tokens on a
                // corrupt fragment). (Was previously indistinguishable from clean EOF.)
                end = ReadEnd::TransportError;
                break;
            }
        }
    }
    (Bytes::from(buf), end)
}

/// Read an upstream ERROR / verbatim-relay body under the tight [`MAX_UPSTREAM_BUFFERED_BYTES`] cap.
/// A truncated error body still classifies/relays correctly (error envelopes are well under the cap,
/// and a body that overruns it can only be malformed/hostile), so the truncation flag is discarded.
async fn read_capped_body(r: reqwest::Response) -> Bytes {
    read_capped(r, MAX_UPSTREAM_BUFFERED_BYTES).await.0
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

/// Vendor-neutral, infrastructure-free detail used for EVERY client-facing mid-stream / pre-first-byte
/// transport-error frame. The raw `reqwest::Error` Display embeds hyper/reqwest/tokio internals and the
/// egress backend URL (hostname, region, port) — both a protocol-indistinguishability tell (no native
/// AI vendor emits hyper/reqwest strings) and an infrastructure-disclosure leak. The real cause is
/// logged server-side via `tracing`; only this static string ever reaches the client. Single source of
/// truth so a future edit cannot reintroduce `e.to_string()` at one site unnoticed.
///
/// The phrasing must also be VENDOR-PLAUSIBLE: the word "upstream" (and "proxy"/"gateway"/"backend"/
/// "lane") is itself busbar-internal reverse-proxy vocabulary that a native vendor SDK would never
/// emit in an error body or stream exception frame. A real Bedrock `ConverseStream` exception, an
/// SSE `error` event, or a Gemini `google.rpc.Status` element carries generic service phrasing, never
/// the word "upstream" — leaking it is a protocol-indistinguishability tell on the most-exercised
/// cross-protocol error path. Keep this generic and free of any intermediary/translation vocabulary.
pub(crate) const MID_STREAM_GENERIC_DETAIL: &str = "The response stream was interrupted.";

/// Vendor-neutral fallback `error.message` for a NON-2xx response whose body carried no extractable
/// human message. Rendered into the CLIENT's native error envelope via `ingress_error`, so it must
/// read like copy a real single-vendor API would emit — NOT reverse-proxy vocabulary like "upstream".
/// The real status/cause is logged server-side; only this generic string reaches the client.
pub(crate) const GENERIC_REJECTED_DETAIL: &str = "The request could not be processed.";

/// Vendor-neutral fallback detail for a cross-protocol response that could not be relayed (a body
/// transfer failure mid-read, an over-cap body, or an untranslatable shape). Rendered into the
/// client's native error envelope, so it must NOT disclose the existence of a translating
/// intermediary ("translate"/"untranslatable") or proxy vocabulary ("upstream"); a native vendor
/// returns a generic internal-error message here. The precise cause is logged server-side.
pub(crate) const GENERIC_RESPONSE_ERROR_DETAIL: &str =
    "An internal error occurred while processing the response.";

/// Build the bytes for a mid-stream error to send to the CLIENT, framed in the INGRESS protocol.
///
/// After the first byte has reached the client, failover is no longer possible, so an upstream
/// transport failure must terminate the stream with an in-band error in the client's own framing:
///   - Bedrock ingress (native AWS SDK, binary `application/vnd.amazon.eventstream`): a real
///     modeled-exception frame (`:message-type: exception`, `:exception-type: InternalServerException`)
///     with valid CRC32. Writing SSE `event:`/`data:` text into a binary eventstream body produces an
///     undecodable prelude/CRC for the SDK's decoder — the bug this guards against.
///   - SSE ingress (openai/anthropic/gemini/cohere/responses): the ingress writer's OWN streaming
///     error event (`write_response_event(&IrStreamEvent::Error(..))`), framed exactly as the
///     happy-path SSE framer does — bare `data:` for openai/cohere/gemini (no `event:` line, which
///     native streams of those protocols never emit), `event: error` for anthropic, and
///     `event: response.failed` for responses whose payload is the SDK-required
///     `{"response":{...,"error":{...}}}` STREAM shape (NOT the non-stream `{"error":...}` HTTP
///     envelope), so the official SDK's stream decoder finds `event.response` instead of crashing.
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
    // SSE client: build the terminal error frame through the ingress protocol writer's STREAMING
    // error path (`write_response_event(&IrStreamEvent::Error(..))`), NOT the non-stream
    // `write_error()` HTTP envelope. The two are genuinely different shapes for some protocols and a
    // native SDK decodes the STREAM event, not the HTTP body:
    //   - Responses: the stream `response.failed` event wraps the error in a `response` object
    //     (`{"response":{...,"error":{...}}}`); the HTTP envelope is a top-level `{"error":...}` the
    //     SDK's stream decoder cannot locate via `event.response` (it would crash / silently swallow).
    //   - Anthropic: the stream `error` event is `{"type":"error","error":{...}}` (no HTTP-only
    //     `request_id`); the writer's event arm produces exactly that.
    //   - OpenAI/Cohere/Gemini: bare `data:` frame in each protocol's native in-band error shape.
    // The writer returns `(event_type, data)`; we frame it identically to the happy-path SSE framer
    // (`proto::reframe_sse`): a non-empty `event_type` becomes an `event:` line, an empty one is a
    // bare `data:` frame. This guarantees the mid-stream error is byte-for-byte the same framing the
    // ingress protocol uses for every other event. The error carries `StatusClass::ServerError`
    // (mid-stream transport failure ≈ internal/5xx) with the human detail as `provider_signal`, which
    // each writer maps to its native error `type`/`message`.
    let err = crate::proto::IrError {
        class: crate::breaker::StatusClass::ServerError,
        provider_signal: Some(message.to_string()),
        retry_after: None,
    };
    let ev = crate::ir::IrStreamEvent::Error(err);
    // Bind the Protocol so the writer borrow outlives the call (an unknown ingress falls back to the
    // OpenAI writer, mirroring `ingress_error`).
    let proto =
        crate::proto::protocol_for(ingress_protocol).unwrap_or_else(crate::proto::Protocol::openai);
    // Every SSE-framed writer (openai/anthropic/gemini/cohere/responses) returns `Some` for an
    // `Error` event; the `None` fallback only guards a hypothetical future writer that declines to
    // frame errors in-band, in which case we still emit a decodable bare `data:` error.
    match proto.writer().write_response_event(&ev) {
        Some((event_type, data)) => {
            let data = serde_json::to_string(&data).unwrap_or_else(|_| {
                serde_json::json!({ "error": { "message": message, "type": "api_error" } })
                    .to_string()
            });
            if event_type.is_empty() {
                format!("data: {data}\n\n").into_bytes()
            } else {
                format!("event: {event_type}\ndata: {data}\n\n").into_bytes()
            }
        }
        None => {
            let data = serde_json::json!({ "error": { "message": message, "type": "api_error" } })
                .to_string();
            format!("data: {data}\n\n").into_bytes()
        }
    }
}

/// Wrap a SINGLE non-stream `IrResponse` into a Bedrock ConverseStream binary `eventstream` byte
/// sequence (`application/vnd.amazon.eventstream`), for the case where a bedrock-ingress client
/// requested `ConverseStream` (`wants_stream`) but the cross-protocol upstream answered with a
/// BUFFERED (non-SSE) 2xx. Returning that single response as `application/json` + a non-stream
/// Converse body is undecodable by the AWS SDK's eventstream decoder (it expects framed
/// `messageStart`/`contentBlockDelta`/…/`messageStop`/`metadata` events) — a hard functional failure
/// and a deterministic proxy tell on the headline bedrock-ingress surface. This synthesizes the
/// native frame sequence a real ConverseStream emits for the same completion: one `messageStart`,
/// then per content block a `contentBlockStart` + its `contentBlockDelta`(s) + `contentBlockStop`,
/// then `messageStop` (carrying the stop reason) and a trailing `metadata` frame (carrying token
/// usage) — matching the two-frame stop/usage split the Bedrock writer's `MessageDelta` arm expects.
/// Each event is rendered through the SAME `bedrock` writer used on the live streaming path and
/// encoded via `eventstream::encode_frame`, so the bytes are byte-for-byte what a native stream sends.
/// Never panics on the request path: a frame whose payload fails to serialize is skipped.
fn bedrock_response_to_eventstream(ir: &crate::ir::IrResponse, elapsed_ms: Option<u64>) -> Vec<u8> {
    use crate::ir::{IrBlock, IrBlockMeta, IrDelta, IrStreamEvent, IrUsage};
    let writer = crate::proto::Protocol::bedrock();
    let writer = writer.writer();
    let mut out: Vec<u8> = Vec::new();
    // Render one IR stream event through the bedrock writer and append the encoded frame (if the
    // writer maps it to a native frame; some IR events have no Bedrock analog and yield None).
    let push = |ev: &IrStreamEvent, out: &mut Vec<u8>| {
        if let Some((event_type, mut payload)) = writer.write_response_event(ev) {
            // A native ConverseStream `metadata` frame ALWAYS carries a `metrics.latencyMs` (the SDK
            // surfaces it via `ConverseStreamMetadataEvent::metrics()`); the bedrock writer's
            // `MessageDelta` arm deliberately omits `metrics`, and the LIVE StreamTranslate path injects
            // it there (`proto::mod.rs`). On this BUFFERED synthesis path StreamTranslate is bypassed,
            // so inject it HERE too — otherwise `metrics == None`, which a real endpoint never returns
            // (a deterministic proxy tell). Use the request's elapsed wall-clock, consistent with the
            // live path; if timing is unavailable OMIT `metrics` rather than emit a tell-tale `0`.
            if event_type == "metadata" {
                if let (Some(ms), Some(obj)) = (elapsed_ms, payload.as_object_mut()) {
                    obj.insert(
                        "metrics".to_string(),
                        serde_json::json!({ "latencyMs": ms }),
                    );
                }
            }
            if let Ok(bytes) = serde_json::to_vec(&payload) {
                out.extend_from_slice(&crate::eventstream::encode_frame(&event_type, &bytes));
            }
        }
    };

    // messageStart
    push(
        &IrStreamEvent::MessageStart {
            role: ir.role,
            usage: None,
            id: None,
            created: None,
            model: ir.model.clone(),
        },
        &mut out,
    );

    // Per content block: contentBlockStart → contentBlockDelta(s) → contentBlockStop. Mirror the
    // live streaming fan-out (`read_response_events`) so the SDK sees the same per-block framing.
    for (index, block) in ir.content.iter().enumerate() {
        match block {
            IrBlock::Text { text, .. } => {
                push(
                    &IrStreamEvent::BlockStart {
                        index,
                        block: IrBlockMeta::Text,
                    },
                    &mut out,
                );
                push(
                    &IrStreamEvent::BlockDelta {
                        index,
                        delta: IrDelta::TextDelta(text.clone()),
                    },
                    &mut out,
                );
                push(&IrStreamEvent::BlockStop { index }, &mut out);
            }
            IrBlock::ToolUse { id, name, input } => {
                push(
                    &IrStreamEvent::BlockStart {
                        index,
                        block: IrBlockMeta::ToolUse {
                            id: id.clone(),
                            name: name.clone(),
                        },
                    },
                    &mut out,
                );
                push(
                    &IrStreamEvent::BlockDelta {
                        index,
                        delta: IrDelta::InputJsonDelta(input.to_string()),
                    },
                    &mut out,
                );
                push(&IrStreamEvent::BlockStop { index }, &mut out);
            }
            // Thinking/ToolResult/Image blocks have no native ConverseStream content-delta frame on
            // this synthesized path (the Bedrock writer maps their start/delta to None); skip them
            // rather than emit an orphaned/empty frame. These are enumerated EXPLICITLY (no `_`
            // catch-all) so that adding a future `IrBlock` variant (e.g. a document or
            // redacted-thinking block) is a COMPILE error here rather than silent data loss in the
            // synthesized ConverseStream output — this is the newest, least-tested encoder path.
            IrBlock::Thinking { .. } | IrBlock::ToolResult { .. } | IrBlock::Image { .. } => {}
        }
    }

    // messageStop (stop reason) then metadata (usage) — the writer's `MessageDelta` arm maps a
    // stop_reason-bearing delta to `messageStop` and a usage-only delta to `metadata`, exactly the
    // two native frames a real ConverseStream ends with.
    push(
        &IrStreamEvent::MessageDelta {
            stop_reason: ir
                .stop_reason
                .clone()
                .or_else(|| Some("end_turn".to_string())),
            usage: IrUsage {
                input_tokens: 0,
                output_tokens: 0,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
            stop_sequence: None,
        },
        &mut out,
    );
    push(
        &IrStreamEvent::MessageDelta {
            stop_reason: None,
            usage: ir.usage.clone(),
            stop_sequence: None,
        },
        &mut out,
    );
    out
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
    /// Cross-chunk reassembly buffer for the BINARY `application/vnd.amazon.eventstream` body of a
    /// same-protocol bedrock→bedrock passthrough (`feed_eventstream`). The JSON `feed` path keeps no
    /// cross-chunk state (it scans complete objects per chunk), but binary eventstream frames carry a
    /// u32 length prefix + CRCs and routinely span chunk boundaries, so the terminal `metadata` /
    /// `exception` frame must be reassembled across polls. Bounded by `drain_frames`' MAX_FRAME_BYTES.
    eventstream_buf: Vec<u8>,
}

impl UsageTap {
    /// Create a new empty tap
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Feed a chunk to the tap and extract any usage fields. Bounded: it only scans complete JSON
    /// objects within this chunk and keeps no cross-chunk buffer.
    pub(crate) fn feed(&mut self, chunk: &Bytes) {
        // Bound per-poll scan time: `feed` runs synchronously inside the stream `poll_next`, so an
        // O(n) brace-scan over a pathological multi-MiB single chunk would block the Tokio worker for
        // its duration. Most SSE backends send one small event per chunk, but a buffering reverse
        // proxy or an aggregating backend can coalesce many events (incl. the terminal usage frame)
        // into one larger chunk — so the cap is set high enough (512 KiB) to still scan a realistically
        // coalesced terminal flush rather than silently drop its usage and undercharge the key's
        // TPM/spend budget. A chunk still larger than this is skipped (the worst-case poll-latency
        // guard), but now with a `warn!` so the accounting gap is OBSERVABLE in production instead of
        // invisible — ops can raise the cap or investigate the upstream's chunking if it fires.
        const MAX_SCAN_BYTES: usize = 512 * 1024;
        if chunk.len() > MAX_SCAN_BYTES {
            tracing::warn!(
                chunk_len = chunk.len(),
                cap = MAX_SCAN_BYTES,
                "usage tap skipped an oversized stream chunk; if it carried the terminal usage frame, \
                 this request's tokens are undercounted (TPM/spend may be undercharged)"
            );
            return;
        }
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

    /// Feed a chunk of a BINARY `application/vnd.amazon.eventstream` body (a same-protocol
    /// bedrock→bedrock passthrough). The JSON `feed` scanner cannot be used here: the eventstream
    /// frames carry u32 length prefixes, header blocks and CRC32 trailers, so a stray `{` byte inside
    /// a prelude/CRC/payload would mislead the brace scanner into parsing garbage or a partial object
    /// (wrong/zero token counts, non-deterministic terminal-error detection). Instead, reassemble
    /// complete frames across chunk boundaries with `drain_frames` and inspect each by event type:
    ///   - a `metadata` frame carries the native Converse `usage.{inputTokens,outputTokens}` — the
    ///     only place per-request token usage appears on a ConverseStream — so TPM / spend budget can
    ///     be charged for passthrough traffic (otherwise always zero);
    ///   - an `*Exception` frame (`:message-type: exception`, surfaced by `event_type_for_frame` as a
    ///     `…Exception` union-member token) is an in-band terminal error AWS delivers while the HTTP
    ///     response stays 200 and closes cleanly — set `terminal_error` so the stream-end breaker arm
    ///     records a failure (otherwise the lane looks healthy after every in-band bedrock error).
    pub(crate) fn feed_eventstream(&mut self, chunk: &Bytes) {
        // Same MAX_SCAN_BYTES guard as `feed`: `drain_frames` itself caps a single frame at
        // MAX_FRAME_BYTES, but a chunk far larger than a realistically coalesced terminal flush is
        // skipped to bound per-poll scan time on the Tokio worker, with a warn so the accounting gap
        // is observable rather than silent.
        const MAX_SCAN_BYTES: usize = 512 * 1024;
        if self.eventstream_buf.len().saturating_add(chunk.len()) > MAX_SCAN_BYTES {
            tracing::warn!(
                buffered = self.eventstream_buf.len(),
                chunk_len = chunk.len(),
                cap = MAX_SCAN_BYTES,
                "usage tap skipped an oversized eventstream chunk; if it carried the terminal \
                 metadata/exception frame, tokens are undercounted or an in-band error is missed"
            );
            // Drop the partial buffer too: it can no longer be completed within the cap.
            self.eventstream_buf.clear();
            return;
        }
        self.eventstream_buf.extend_from_slice(chunk);
        for (event_type, payload) in crate::eventstream::drain_frames(&mut self.eventstream_buf) {
            if event_type == "metadata" {
                if let Ok(obj) = serde_json::from_slice::<Value>(&payload) {
                    // Native Converse usage shape (inputTokens / outputTokens) — handled by the
                    // protocol-agnostic extractor, which already recognizes the bedrock keys.
                    self.extract_usage_any(&obj);
                }
            } else if event_type.ends_with("Exception") {
                // In-band modeled exception (e.g. internalServerException, modelStreamErrorException,
                // throttlingException). Record it as the terminal error so the stream-end breaker arm
                // trips this lane. Lift the payload `message` for observability where present.
                let msg = serde_json::from_slice::<Value>(&payload)
                    .ok()
                    .and_then(|v| {
                        v.get("message")
                            .and_then(|m| m.as_str())
                            .map(|s| s.to_string())
                    })
                    .unwrap_or_else(|| event_type.clone());
                self.terminal_error = Some(msg);
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

    /// Detect a genuine terminal ERROR frame across the wire shapes a streamed mid-stream error can
    /// take, so stream-end breaker recording can distinguish a clean close from an aborted one:
    ///   - Anthropic SSE: a `{"type":"error", "error": {...}}` event. Also covers a CROSS-protocol
    ///     stream reframed to Anthropic by `StreamTranslate` (the tap is fed the Anthropic-shaped
    ///     output there).
    ///   - OpenAI (and OpenAI-compatible) SAME-protocol passthrough: an in-band bare `data:` frame of
    ///     the form `{"error":{...}}` with NO `type` discriminant. A native OpenAI stream never tags
    ///     its in-band error with `"type":"error"` (that is the Anthropic shape), so the Anthropic
    ///     branch above never fires for it; without this branch an OpenAI backend that emits an in-band
    ///     `{"error":{...}}` terminal event and THEN closes the stream cleanly would not trip the
    ///     breaker for that lane (the `Poll::Ready(None)` arm only records when `terminal_error` is
    ///     set). This recognizes that shape so the per-lane breaker trip count is accurate for those
    ///     backends too.
    ///
    /// Sets `terminal_error` to the error message (or a generic marker).
    fn extract_terminal_error(&mut self, obj: &Value) {
        let is_anthropic_error = obj.get("type").and_then(|t| t.as_str()) == Some("error");
        // OpenAI-style in-band error: a top-level `error` object with no `type` discriminant. Gate on
        // the ABSENCE of `type` so a normal typed OpenAI chunk that merely carries a nested `error:
        // null` (or any non-error event that happens to include an `error` key) does not false-trip;
        // a real terminal error frame is `{"error":{...}}` alone.
        let is_openai_error =
            obj.get("type").is_none() && obj.get("error").map(|e| !e.is_null()).unwrap_or(false);
        if !is_anthropic_error && !is_openai_error {
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
        // Cohere v2 native streaming terminal frame:
        // `{"type":"message-end","delta":{"usage":{"tokens":{"input_tokens":N,"output_tokens":M}}}}`.
        // The token counts are nested under `delta.usage.tokens`, NOT the top-level `usage` the loops
        // above scan, so without this arm a same-protocol Cohere→Cohere streaming passthrough reports
        // zero tokens and the virtual key's TPM/spend budget is silently undercharged. Descend the
        // delta.usage.tokens path explicitly.
        if let Some(tokens) = obj
            .get("delta")
            .and_then(|d| d.get("usage"))
            .and_then(|u| u.get("tokens"))
        {
            if let Some(v) = tokens.get("input_tokens").and_then(|v| v.as_u64()) {
                self.input_tokens = Some(v);
            }
            if let Some(v) = tokens.get("output_tokens").and_then(|v| v.as_u64()) {
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
#[derive(Clone)]
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
    /// When set (gemini ingress streaming WITHOUT `?alt=sse`), the SSE bytes — whether from a
    /// same-protocol passthrough or the cross-protocol `translate` stage above, both of which are
    /// gemini SSE here — are reframed into the JSON-array streaming format the native non-`alt=sse`
    /// `:streamGenerateContent` request expects (`[{...},{...}]`). Runs AFTER `translate`.
    json_array: Option<crate::proto::GeminiJsonArrayFramer>,
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
        json_array: Option<crate::proto::GeminiJsonArrayFramer>,
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
            json_array,
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
                    // cross-protocol → translate egress SSE bytes to the ingress format.
                    if let Some(t) = this.translate.as_mut() {
                        let out = t.feed(&chunk);
                        let out_bytes = Bytes::from(out);
                        // Feed the tap with JSON TEXT, never binary frames. For the five SSE ingress
                        // protocols the translated `out` IS the JSON-bearing SSE text the tap's
                        // `{`-scanner is built for. But for BEDROCK ingress the translated `out` is
                        // binary `application/vnd.amazon.eventstream` framing (u32 length prefixes,
                        // CRC32s, header blocks whose stray `{` bytes would mislead the scanner into
                        // parsing garbage or zeroing usage). On that path read the pre-encode JSON the
                        // translator captured (`take_tap_json`) instead, so token accounting is
                        // reliable. (A same-protocol passthrough — translate=None — feeds the raw chunk
                        // below, already the right shape there.)
                        if t.ingress_is_eventstream() {
                            let tap_json = t.take_tap_json();
                            if !tap_json.is_empty() {
                                this.tap.feed(&Bytes::from(tap_json));
                            }
                        } else {
                            this.tap.feed(&out_bytes);
                        }
                        // Gemini non-`alt=sse` ingress: reframe the (now gemini-SSE) bytes into the
                        // JSON-array streaming shape. Run AFTER tap+translate so accounting is
                        // unaffected.
                        if let Some(framer) = this.json_array.as_mut() {
                            let framed = framer.feed(&out_bytes);
                            if framed.is_empty() {
                                continue; // no complete object yet; poll inner again
                            }
                            return Poll::Ready(Some(Ok(Bytes::from(framed))));
                        }
                        if out_bytes.is_empty() {
                            continue; // only a partial frame buffered; poll inner again
                        }
                        return Poll::Ready(Some(Ok(out_bytes)));
                    }
                    // Passthrough (same-protocol): the raw chunk is already in the client's shape.
                    // BUT on a SAME-PROTOCOL bedrock→bedrock passthrough that chunk is binary
                    // `application/vnd.amazon.eventstream` framing (u32 length prefixes, CRC32s, header
                    // blocks) — feeding it to the tap's `{`-brace JSON scanner makes stray `{` bytes
                    // inside CRCs/preludes/payloads mislead it into parsing garbage or a partial object,
                    // so `extract_usage_*` lands on wrong/zero token counts and terminal-error detection
                    // over binary frames is non-deterministic. This is the SAME hazard the cross-protocol
                    // branch above guards by reading `take_tap_json()` instead of the binary bytes; mirror
                    // that discipline here by NOT scanning the binary chunk. (Token accounting for a
                    // native bedrock ConverseStream passthrough is best handled off the JSON tap.) Every
                    // other same-protocol passthrough (the five SSE protocols) IS JSON-bearing text, so
                    // it still feeds the tap as before.
                    if this.ingress_eventstream {
                        // Binary `application/vnd.amazon.eventstream` passthrough: scan the native
                        // frames for the `metadata` usage frame and any in-band `*Exception` frame so
                        // bedrock→bedrock streaming is token-accounted AND in-band errors trip the
                        // breaker — neither of which the JSON `feed` scanner can do over binary frames.
                        this.tap.feed_eventstream(&chunk);
                    } else {
                        this.tap.feed(&chunk);
                    }
                    // Gemini same-protocol passthrough WITHOUT `?alt=sse`: the upstream chunk is
                    // gemini SSE (busbar always requests `?alt=sse` upstream); reframe it into the
                    // JSON-array streaming shape the native client expects.
                    if let Some(framer) = this.json_array.as_mut() {
                        let framed = framer.feed(&chunk);
                        if framed.is_empty() {
                            continue; // no complete object yet; poll inner again
                        }
                        return Poll::Ready(Some(Ok(Bytes::from(framed))));
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
                        // The raw reqwest/transport error (`e`) must NEVER reach the client body: its
                        // Display embeds hyper/reqwest/tokio internals and the egress backend URL
                        // (hostname, region, port) — a protocol-indistinguishability tell (no native
                        // AI vendor emits hyper/reqwest strings) AND an infrastructure-disclosure leak.
                        // Log the real cause server-side for operator observability, then put only a
                        // static, vendor-neutral detail into the client-facing frame. A native vendor
                        // mid-stream interruption carries a generic message, never a backend URL.
                        tracing::warn!(
                            ingress = %this.ingress_protocol,
                            error = %e,
                            "mid-stream upstream transport error; returning generic interruption to client"
                        );
                        // Gemini JSON-array ingress (non-`alt=sse`): the client has been receiving a
                        // streaming JSON ARRAY (`[obj,obj`), so the in-band error MUST be a valid
                        // trailing array element followed by the closing `]` — NOT the SSE text frame
                        // `mid_stream_error_bytes` produces. Emitting `event: error\ndata:{...}` into a
                        // JSON-array body splices non-JSON into the array (unparseable) and is a
                        // protocol tell (a native Gemini JSON-array stream never contains SSE framing).
                        // Route the error through the framer instead: a Gemini `google.rpc.Status`
                        // element + `]`.
                        if let Some(framer) = this.json_array.as_mut() {
                            let err_bytes = framer.finish_with_error(
                                500,
                                "INTERNAL",
                                MID_STREAM_GENERIC_DETAIL,
                            );
                            return Poll::Ready(Some(Ok(Bytes::from(err_bytes))));
                        }
                        // Emit the error in the INGRESS protocol's framing, NOT a hard-coded SSE
                        // text frame. For a bedrock-ingress client (binary eventstream) this is a
                        // valid AWS exception frame; for SSE clients it is shaped to the ingress
                        // protocol's native error envelope. Keying off `is_sse` (the upstream CT)
                        // alone would inject SSE text into a binary eventstream body on a
                        // bedrock-ingress → SSE-egress reframe — an undecodable frame for the SDK.
                        let err_bytes = mid_stream_error_bytes(
                            &this.ingress_protocol,
                            this.ingress_eventstream,
                            MID_STREAM_GENERIC_DETAIL,
                        );
                        return Poll::Ready(Some(Ok(Bytes::from(err_bytes))));
                    } else {
                        // Before first byte or non-SSE: terminate the body stream with an error. The
                        // raw reqwest error (with its embedded backend URL / hyper internals) must not
                        // ride out on the io::Error either — log the real cause server-side and surface
                        // only a generic, vendor-neutral message on the stream item.
                        tracing::warn!(
                            ingress = %this.ingress_protocol,
                            error = %e,
                            "pre-first-byte upstream transport error; terminating body stream generically"
                        );
                        return Poll::Ready(Some(Err(std::io::Error::other(
                            MID_STREAM_GENERIC_DETAIL,
                        ))));
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
                    // emit the ingress terminator before close. For a gemini JSON-array stream the
                    // terminator is the closing `]` from the framer; the SSE `translate.finish()`
                    // terminator (e.g. OpenAI `data: [DONE]`) must NOT be emitted into a JSON-array
                    // body — drain the translate buffer (so its decode side-effects run) but discard
                    // its SSE terminator bytes, then append the framer close.
                    let done = if let Some(framer) = this.json_array.as_mut() {
                        let _ = this.translate.as_mut().map(|t| t.finish());
                        framer.finish()
                    } else {
                        this.translate
                            .as_mut()
                            .map(|t| t.finish())
                            .unwrap_or_default()
                    };
                    // Bedrock ingress: `finish()` may emit a deferred terminal `metadata` frame (the
                    // default-OpenAI-streaming case carries usage there). Tap its pre-encode JSON so
                    // end-of-stream token usage is still captured — the binary `done` bytes would not
                    // be scannable by the tap's `{`-scanner.
                    if let Some(t) = this.translate.as_mut() {
                        if t.ingress_is_eventstream() {
                            let tap_json = t.take_tap_json();
                            if !tap_json.is_empty() {
                                this.tap.feed(&Bytes::from(tap_json));
                            }
                        }
                    }
                    drop(this.permit.take());
                    this.ended = true;
                    // Charge this request's token usage to the virtual key's budget (once) — but ONLY
                    // for a cleanly-terminated stream. A stream that emitted a mid-stream terminal
                    // ERROR frame (`tap.terminal_error` set) delivered a partial/aborted response the
                    // caller cannot use, and billing it contradicts the flat-fee-only-on-success
                    // policy (`route::finish` charges the per-request fee only on 2xx). Mirror that
                    // here: a failed stream is not token-billed.
                    if let Some(sink) = this.usage_sink.take() {
                        if this.tap.terminal_error.is_none() {
                            let tokens = this.tap.input_tokens.unwrap_or(0)
                                + this.tap.output_tokens.unwrap_or(0);
                            sink.gov
                                .record_tokens(&sink.key_id, &sink.period, now(), tokens);
                        }
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
                // CLASS GUARD (single-flight recovery probe), sticky fast path: `usable_in` →
                // `cell_acquire_breaker` transitions an expired-Open lane to HalfOpen and CAS-wins
                // the single-flight `probe_in_flight` flag as a SIDE EFFECT. If we then fail to get a
                // concurrency permit, NO request is dispatched on this lane, so neither
                // `record_success` (→ cell_closed) nor a failure (→ cell_open) ever runs to clear the
                // probe. Falling through to the SWRR loop without releasing it would leave the lane
                // wedged HalfOpen + probe_in_flight, benching it until the slow out-of-band prober
                // resets it — the SAME leak the main loop guards below. So: keep the probe only on the
                // dispatch (try_acquire success); release it on every other exit before falling through.
                if let Some(p) = app.store.try_acquire(sticky) {
                    return Some((sticky, p));
                } else {
                    app.store.release_probe_in(pool_name, sticky);
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

        // CLASS GUARD (single-flight recovery probe): from here on we have WON the probe
        // (`acquire_for_dispatch_in` returned true, leaving the cell HalfOpen + `probe_in_flight ==
        // true`). The probe is normally released only when an outcome is recorded (`record_success`
        // → cell_closed, or a failure → cell_open). EVERY early return below this point abandons the
        // probe WITHOUT recording an outcome, so each one MUST release it — otherwise the flag stays
        // `true`, the cell stays HalfOpen, and `usable_for` benches the lane until the slow
        // out-of-band prober resets it (the HIGH this fixes). The only paths that legitimately keep
        // the probe are the two that actually DISPATCH a request: the immediate `try_acquire`
        // success and the `Ok(Ok(permit))` permit-wait success below.

        // Try to acquire the concurrency permit immediately.
        if let Some(p) = app.store.try_acquire(picked_lane_idx) {
            return Some((picked_lane_idx, p));
        }

        // Permits saturated: park (not busy-spin) until a slot frees OR the deadline passes. A
        // bounded `timeout` acquire yields the task efficiently and guarantees we never block past
        // the request deadline (unbounded spinning here was a head-of-line-blocking DoS surface).
        let remaining = request_ctx.remaining(now());
        if remaining == 0 {
            // Deadline already passed before we could even park — release the won-but-undispatched
            // probe so the lane stays re-probeable.
            app.store.release_probe_in(pool_name, picked_lane_idx);
            return None;
        }
        let sem = app.store.lane_semaphore(picked_lane_idx);
        match tokio::time::timeout(
            tokio::time::Duration::from_secs(remaining),
            sem.acquire_owned(),
        )
        .await
        {
            // Got a permit before the deadline — this is a genuine dispatch; keep the probe (the
            // request itself will record the success/failure that releases it).
            Ok(Ok(permit)) => return Some((picked_lane_idx, Permit::new(permit))),
            // Semaphore closed (shutdown) — no request dispatched; release the probe before bailing.
            Ok(Err(_)) => {
                app.store.release_probe_in(pool_name, picked_lane_idx);
                return None;
            }
            // Deadline hit while waiting for a permit — no request dispatched; release the probe so
            // the recovered lane isn't permanently benched, then give up so the caller can
            // 503/failover.
            Err(_) => {
                app.store.release_probe_in(pool_name, picked_lane_idx);
                return None;
            }
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

/// extract the host (no scheme, no trailing slash, no userinfo) from a base URL, for SigV4's signed
/// `host` header. base_urls are already trailing-slash-trimmed and carry no path.
///
/// A `base_url` carrying an embedded `user:pass@` userinfo component (accidental misconfiguration)
/// must NOT leak into the signed `host` value: the HTTP stack sends `Host: host.example.com` while
/// SigV4 would otherwise sign `host: user:pass@host.example.com`, producing a signature mismatch
/// (every Bedrock request fails) AND embedding the credential in the signed string (which may surface
/// in request logs/traces). Strip any userinfo (everything up to and including the last `@` in the
/// authority) so the signed host always matches what the HTTP layer transmits.
pub(crate) fn host_from_base(base: &str) -> String {
    let no_scheme = base
        .strip_prefix("https://")
        .or_else(|| base.strip_prefix("http://"))
        .unwrap_or(base);
    // The authority ends at the first `/`, `?`, or `#`; userinfo (if any) precedes the LAST `@`
    // within that authority. Split on the authority boundary first so an `@` appearing later in a
    // path/query (not userinfo) is never mistaken for a userinfo delimiter.
    let authority_end = no_scheme.find(['/', '?', '#']).unwrap_or(no_scheme.len());
    let (authority, rest) = no_scheme.split_at(authority_end);
    let host_authority = match authority.rfind('@') {
        Some(at) => &authority[at + 1..],
        None => authority,
    };
    format!("{host_authority}{rest}")
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

/// Plausible native-SDK `User-Agent` for the chosen EGRESS protocol. reqwest sends NO default
/// User-Agent unless one is set, so without this every proxied upstream request reaches the backend
/// with no UA at all — a trivial backend-side fingerprint distinguishing busbar-proxied traffic from
/// a native vendor SDK (which always sends a recognizable UA). Returned strings mirror the shape a
/// real first-party SDK emits for that provider's API. (Backend-facing only; does not affect client
/// indistinguishability.)
fn egress_user_agent(egress_protocol: &str) -> &'static str {
    match egress_protocol {
        // Anthropic Python SDK UA shape (api.anthropic.com).
        "anthropic" => "anthropic-sdk-python/0.39.0",
        // OpenAI Python SDK shape; the Responses API is served by the same SDK/UA.
        "openai" | "responses" => "OpenAI/Python 1.54.0",
        // Google GenAI SDK shape (generativelanguage.googleapis.com).
        "gemini" => "google-genai-sdk/0.8.0 gl-python/3.11",
        // AWS Bedrock is reached via boto3/botocore.
        "bedrock" => "Boto3/1.35.0 md/Botocore#1.35.0",
        // Cohere Python SDK shape (api.cohere.com).
        "cohere" => "cohere-python/5.11.0",
        // Unknown/foreign egress protocol: a generic-but-present UA still beats sending none (no UA
        // at all is the most distinctive tell). Enumerated default, not a wildcard on a disposition
        // match — this is a UA-string lookup, not a breaker/disposition decision.
        _ => "okhttp/4.12.0",
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
    // The PRISTINE parsed request body. Never mutated after this point: each failover hop derives a
    // fresh per-hop `hop_v` from this clone before translating/rewriting, so a cross-protocol hop
    // never re-translates a body already rewritten into a previous egress lane's shape (the bug:
    // mutating a shared `v` in place made hop N+1 read hop N's egress-shaped body with the ingress
    // reader, misparsing or skipping translation entirely on a mixed-protocol pool).
    let v: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return ingress_error(
                ingress_protocol,
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                &format!("We could not parse the JSON body of your request: {e}"),
            )
        }
    };

    // capture the caller's stream intent from the ingress body BEFORE any cross-protocol
    // translation rewrites `v` (Gemini routes streaming requests to a different upstream endpoint).
    let wants_stream = v.get("stream").and_then(|s| s.as_bool()).unwrap_or(false);

    // Gemini ingress streaming WITHOUT `?alt=sse`: the native client expects a JSON-array streamed
    // body, not SSE. The route layer signals this via a router shim key (read here; stripped from the
    // body unconditionally before forwarding). GATED on `ingress_protocol == "gemini"`: only a
    // genuine Gemini client can want JSON-array response framing. Without the gate a body-model client
    // (openai/cohere/responses) that sent `{"__busbar_gemini_json_array":true}` in its own
    // fully-controlled body would have its SSE stream silently reframed as a JSON array under
    // `Content-Type: application/json` — undecodable by the official SDK and a router behavior no
    // native backend exhibits. False for every other protocol and for the `?alt=sse` gemini variant.
    let gemini_json_array = ingress_protocol == "gemini" && wants_gemini_json_array(&v);

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
                "The request timed out. Please retry shortly.",
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
                        "The service is temporarily overloaded. Please retry shortly.",
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
                    usage_sink.clone(),
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
        // Derive a FRESH per-hop body for translation. Each failover hop must translate/rewrite
        // starting from the ORIGINAL request, never from a previous hop's egress-shaped body. Re-PARSE
        // from the pristine `Bytes` (Arc-backed, so cheap to retain) rather than deep-cloning the
        // parsed `Value` tree per hop: a single JSON parse is far cheaper in time and peak heap than
        // an O(n) `Value::clone` of a large request (long histories / base64 images / big tool
        // schemas), which under sustained failover compounded to O(n × max_cap) allocations.
        let hop_v: Value = match serde_json::from_slice(&body) {
            Ok(v) => v,
            // `body` already parsed once successfully into `v` above; this re-parse is infallible.
            Err(_) => {
                drop(permit);
                return ingress_error(
                    ingress_protocol,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "api_error",
                    "We received an unexpected internal error. Please try again.",
                );
            }
        };
        // SINGLE shared cross-protocol request-shaping seam (shared verbatim with `forward_once`'s
        // degraded path): read→clear-extra→write, shim-key strip, model rewrite, serialize. Both
        // paths route through `translate_request_cross_protocol` so neither can carry a translation
        // step the other lacks (the recurring drift class this round's unification ends).
        let payload = match translate_request_cross_protocol(&app, i, ingress_protocol, hop_v) {
            Ok(p) => p,
            Err(resp) => {
                drop(permit);
                return *resp;
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

        let mut req = app
            .client
            .post(format!("{base}{url_path}"))
            .headers(convert_headers(auth))
            .header(CONTENT_TYPE, "application/json")
            // Native-SDK User-Agent for the egress protocol. The shared client sets none, so without
            // this the backend sees a UA-less request — a proxy fingerprint (see egress_user_agent).
            .header(USER_AGENT, egress_user_agent(egress_name))
            .body(payload);
        // reqwest's per-request `.timeout()` bounds the ENTIRE request lifecycle, INCLUDING reading
        // the response body. For a STREAMING response that body is a long-lived generation stream
        // (SSE / Bedrock eventstream) that a real vendor holds open for as long as the model emits
        // tokens — routinely far beyond the failover deadline (~120s). Applying the failover deadline
        // here would force-terminate a healthy long stream at that wall-clock, truncating the
        // completion, recording a SPURIOUS mid-stream breaker failure against an otherwise-healthy
        // lane, and producing a deterministic ~120s cut a native SDK never sees (an indistinguishability
        // tell). So: bound only the NON-streaming request with the failover deadline (time-to-first-byte
        // / failover selection). A streaming request runs under the shared client-level ceiling
        // (`UPSTREAM_REQUEST_TIMEOUT_SECS`, 300s) instead, letting the body run to natural completion.
        if !wants_stream {
            req = req.timeout(std::time::Duration::from_secs(
                request_ctx.remaining(now()).max(1),
            )); // min 1s timeout
        }
        // Wall-clock start of the upstream call, for the `metrics.latencyMs` a native bedrock
        // ConverseStream `metadata` frame carries on the buffered-synthesis path below.
        let upstream_started = std::time::Instant::now();
        let res = req.send().await;

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
                    // A real AWS Bedrock endpoint sends `x-amzn-requestid` and `x-amzn-errortype` on
                    // EVERY response, including 4xx. First-party AWS SDKs read `x-amzn-errortype`
                    // BEFORE the body `__type` for typed-exception dispatch; their absence on a
                    // same-protocol Bedrock→Bedrock error relay is a detectable indistinguishability
                    // tell. Capture them here (before `r` is consumed) so the same-protocol passthrough
                    // branches below can forward them verbatim on a bedrock-ingress relay.
                    let upstream_amzn_headers: Vec<(
                        axum::http::HeaderName,
                        axum::http::HeaderValue,
                    )> = if ingress_protocol == "bedrock" {
                        ["x-amzn-requestid", "x-amzn-errortype"]
                            .iter()
                            .filter_map(|name| {
                                let v = r.headers().get(*name)?.clone();
                                let n = axum::http::HeaderName::from_static(name);
                                Some((n, v))
                            })
                            .collect()
                    } else {
                        Vec::new()
                    };
                    // Size-capped read: a hostile/misconfigured upstream must not force an unbounded
                    // heap allocation for a non-2xx body before the breaker classification runs.
                    let bytes = read_capped_body(r).await;

                    if is_passthrough_40x {
                        // Verbatim relay of the upstream 401/403 body+CT is correct ONLY on the
                        // same-protocol path, where the upstream error is already in the client's
                        // native shape. On a CROSS-protocol boundary (e.g. an Anthropic-ingress client
                        // routed to an OpenAI backend that 401s) relaying the egress provider's native
                        // error envelope and Content-Type to a different-protocol SDK is a
                        // foreign-format leak (§8.2) — the SDK fails to decode it into its typed
                        // exception, an immediate proxy tell. Reshape into the ingress protocol's
                        // native envelope instead, deriving the kind from the status (the sibling
                        // ClientFault branch does the same). The passthrough breaker invariant is
                        // unchanged either way: no breaker penalty for a caller-key auth failure.
                        if ingress_protocol != egress_name {
                            // Reshape via the shared finalizer so the kind→native-envelope mapping
                            // (401→authentication_error, 403→permission_error, …) is identical on the
                            // main path, the degraded path, and the ClientFault branch below.
                            return shape_cross_protocol_error(ingress_protocol, status, &bytes);
                        }
                        use axum::body::Body;
                        let mut rb = Response::builder().status(status);
                        if let Some(ct) = ct {
                            rb = rb.header(CONTENT_TYPE, ct);
                        }
                        // Forward the upstream's `x-amzn-requestid` / `x-amzn-errortype` on a
                        // bedrock-ingress same-protocol relay so the SDK's header-first typed-exception
                        // dispatch and `request_id()` match a native Bedrock 4xx (empty for non-bedrock).
                        for (name, value) in &upstream_amzn_headers {
                            rb = rb.header(name, value);
                        }
                        // Re-create response from bytes for same-protocol passthrough relay
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
                                    .unwrap_or_else(|| GENERIC_REJECTED_DETAIL.to_string());
                                return ingress_error(ingress_protocol, status, kind, &msg);
                            }
                            use axum::body::Body;
                            let mut rb = Response::builder().status(status);
                            if let Some(ct) = ct {
                                rb = rb.header(CONTENT_TYPE, ct);
                            }
                            // Same as the passthrough-40x branch: preserve the native Bedrock error
                            // headers on a bedrock same-protocol client-fault relay (empty otherwise).
                            for (name, value) in &upstream_amzn_headers {
                                rb = rb.header(name, value);
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
                                    StatusClass::RateLimit => {
                                        // Should have been handled above but Rust needs exhaustive match
                                        "rate_limit"
                                    }
                                    // No-panic-on-request-path invariant: `breaker::classify` does not
                                    // currently map Auth/Billing/ClientError/ContextLength to
                                    // TransientUpstream, but encoding that as `unreachable!()` would
                                    // panic a Tokio worker (dropping every in-flight request on it) the
                                    // first time a future classifier change made one of them reachable.
                                    // Record a generic transient label instead — correct under today's
                                    // mapping and graceful if it ever changes.
                                    StatusClass::Auth
                                    | StatusClass::Billing
                                    | StatusClass::ClientError
                                    | StatusClass::ContextLength => "transient",
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
                                // No-panic-on-request-path invariant: `breaker::classify` only maps
                                // Auth/Billing to HardDown today, but `unreachable!()` here would panic
                                // the worker the first time a classifier change routed another class to
                                // HardDown. Fall back to a generic reason (carrying the HTTP status for
                                // diagnostics) instead — graceful and robust to future mapping changes.
                                StatusClass::RateLimit
                                | StatusClass::Overloaded
                                | StatusClass::ServerError
                                | StatusClass::Timeout
                                | StatusClass::Network
                                | StatusClass::ClientError
                                | StatusClass::ContextLength => {
                                    format!("request rejected (HTTP {})", status.as_u16())
                                }
                            };
                            // A hard-down (auth rejection / billing exhaustion) is a property of the
                            // SHARED upstream, not of one routing pool: trip the lane in EVERY cell
                            // (default "" cell that `named`/`adhoc`/direct routes read AND every
                            // per-pool cell), mirroring `recover_lane`'s all-cells reach. Tripping
                            // only `pool_name`'s cell left the same dead upstream Closed in the other
                            // cells, so legacy/cross-protocol routes kept hammering it until the
                            // out-of-band prober caught it (the asymmetry this fixes).
                            app.store.record_hard_down_all_cells(i, &reason);
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
                                // hard-coded OpenAI-shaped body. The wire MESSAGE is the
                                // vendor-plausible auth-failure copy for the ingress protocol — NOT
                                // busbar-internal vocabulary. The previous "upstream rejected the lane
                                // credential" leaked the internal "lane" concept (no real vendor uses
                                // that word), a deterministic proxy tell; and in non-passthrough mode
                                // the rejected key is busbar's OWN, so the upstream's auth-rejection
                                // body must never be relayed either. The native error kind carries the
                                // auth signal; the message just reads like the real vendor's copy.
                                // Pass the INGRESS-protocol-native auth-failure status and kind, NOT
                                // the upstream's raw HTTP status. A real Bedrock auth failure is HTTP
                                // 403 AccessDeniedException and a real Gemini bad-key is HTTP 400
                                // INVALID_ARGUMENT — neither vendor ever returns 401 for auth. Echoing
                                // the egress backend's raw `status` (e.g. an Anthropic backend's 401)
                                // to a Bedrock/Gemini ingress client is a protocol-distinguishability
                                // tell and breaks SDK auth-retry/credential-refresh logic that keys off
                                // the native status. The canonical mapping lives in `auth.rs`
                                // (`auth_failure_status_and_kind`) so this path cannot drift from the
                                // pre-routing auth path.
                                let (auth_status, auth_kind) =
                                    crate::auth::auth_failure_status_and_kind(ingress_protocol);
                                return ingress_error(
                                    ingress_protocol,
                                    auth_status,
                                    auth_kind,
                                    crate::proto::vendor_auth_failure_message(ingress_protocol),
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
                // Discard intentional: the post-success spend is the COST accounting, not the
                // admission gate (that was `lane_admissible`/`usable` before dispatch). The CAS-based
                // `spend_budget` can no longer over-spend; a `false` here only means this lane was
                // already at 0, which the next admission check rejects. Explicit `let _ =` per
                // `#[must_use]`.
                let _ = app.store.spend_budget(i);

                // stream the response body incrementally with first-byte boundary tracking
                let ct = r.headers().get(CONTENT_TYPE).cloned();
                // Capture the upstream's `x-amzn-RequestId` (if any) BEFORE consuming `r` into the
                // body stream. On a SAME-PROTOCOL bedrock streaming passthrough we forward the real
                // upstream id verbatim (a native ConverseStream response carries it); on a
                // CROSS-PROTOCOL bedrock-ingress stream the backend supplied none, so we synthesize
                // one below. Either way a bedrock-ingress stream must carry the header (matching a
                // real endpoint and the error path).
                let upstream_amzn_id = r
                    .headers()
                    .get("x-amzn-requestid")
                    .and_then(|h| h.to_str().ok())
                    .map(|s| s.to_string());
                // Anthropic-ingress: capture the upstream `request-id` so a same-protocol passthrough
                // forwards it verbatim; cross-protocol/synthetic cases mint one in the attach helper.
                let upstream_request_id = r
                    .headers()
                    .get("request-id")
                    .and_then(|h| h.to_str().ok())
                    .map(|s| s.to_string());
                let is_sse = ct
                    .as_ref()
                    .map(|h| is_streaming_content_type(h.to_str().unwrap_or("")))
                    .unwrap_or(false);

                // non-streaming cross-protocol response → buffer the whole JSON and
                // translate egress.read_response → IR → ingress.write_response. (Streaming
                // cross-protocol is handled in FirstByteBody below; same-protocol passes through.)
                if ingress_protocol != app.lanes[i].protocol.name() && !is_sse {
                    // Size-capped buffer under the COMPLETION cap (not the tight error-body cap): a
                    // legitimate 2xx completion can far exceed 256 KiB and must be buffered WHOLE to
                    // parse+translate. `truncated` distinguishes "too large to translate" from
                    // "genuinely unparseable" so a too-large success is not mis-reported as a 500.
                    let (bytes, read_end) = read_capped(r, MAX_TRANSLATED_BODY_BYTES).await;
                    drop(permit); // upstream call complete; a non-streamed response holds no permit
                    if read_end == ReadEnd::TransportError {
                        // The transfer failed mid-body. We optimistically recorded breaker success +
                        // spent the budget on the 2xx HEADERS above (shared with the streaming path),
                        // but the BODY never arrived intact: do NOT charge tokens for a corrupt
                        // fragment, record a compensating transient failure so the breaker sees the
                        // transfer as failed (a clean 2xx success followed by a truncated body is an
                        // upstream failure, not a completion), AND refund the request budget unit spent
                        // on the headers — no usable response was delivered, so a failed body transfer
                        // must not permanently drain the lane's `max_requests` budget (which would
                        // stealthily remove capacity under sustained post-headers transport failures).
                        // Return an ingress-native error.
                        tracing::warn!(
                            ingress = %ingress_protocol,
                            egress = %app.lanes[i].protocol.name(),
                            "cross-protocol non-stream upstream body failed mid-transfer; \
                             not recording success/usage, refunding budget, returning ingress-native error"
                        );
                        app.store.record_transient_in(
                            pool_name,
                            i,
                            "transport",
                            &breaker_cfg,
                            None,
                        );
                        app.store.refund_budget(i);
                        return ingress_error(
                            ingress_protocol,
                            StatusCode::BAD_GATEWAY,
                            "api_error",
                            GENERIC_RESPONSE_ERROR_DETAIL,
                        );
                    }
                    // Token accounting: no FirstByteBody on this buffered path, so tap here.
                    record_nonstream_usage(&bytes, &usage_sink);
                    if read_end == ReadEnd::Truncated {
                        tracing::warn!(
                            ingress = %ingress_protocol,
                            egress = %app.lanes[i].protocol.name(),
                            cap = MAX_TRANSLATED_BODY_BYTES,
                            "cross-protocol non-stream success body exceeded the translation cap; \
                             cannot translate, returning ingress-native error"
                        );
                        return ingress_error(
                            ingress_protocol,
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "api_error",
                            GENERIC_RESPONSE_ERROR_DETAIL,
                        );
                    }
                    if let Ok(rv) = serde_json::from_slice::<Value>(&bytes) {
                        if let Ok(mut ir) = app.lanes[i].protocol.reader().read_response(&rv) {
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
                                // CROSS-PROTOCOL BOUNDARY SIGNAL (class fix). Some egress readers
                                // return an identity-EMPTY IR — notably Bedrock, whose Converse body
                                // carries no body-level `id`/`created`/`model` (its `read_response`
                                // returns all three `None`). After the strip above such an IR is
                                // indistinguishable, AT THE WRITER, from a MINIMAL SAME-protocol body
                                // that legitimately omitted identity. Writers that gate identity
                                // emission on the boundary signal `created.is_some() ||
                                // model.is_some()` (the Gemini writer) therefore emitted NEITHER a
                                // synthesized `responseId` NOR `usageMetadata.totalTokenCount` for a
                                // Bedrock→Gemini hop, so a google-genai client read
                                // `response_id`/`total_token_count` as absent — a token-accounting gap
                                // and a distinguishability tell.
                                //
                                // Fix the CLASS at the seam, not per-writer: this code runs ONLY when
                                // ingress != egress (same-protocol passthrough relays the raw upstream
                                // body and never reaches a writer), so a populated `created` here is an
                                // unambiguous, protocol-AGNOSTIC marker that a translation occurred.
                                // Stamp a synthesized unix-epoch `created` whenever the egress reader
                                // left it empty, so EVERY identity-empty egress (Bedrock today; any
                                // future one) trips the same boundary signal and every ingress writer
                                // emits full native identity. `created` is format-neutral on the wire
                                // (anthropic omits it; openai/responses re-emit it as an int they would
                                // otherwise synthesize anyway; gemini/cohere never serialize it), so
                                // stamping it changes no wire shape beyond turning identity emission
                                // back ON. The same-protocol minimal roundtrip is unaffected because it
                                // never enters this seam.
                                if ir.created.is_none() {
                                    ir.created = Some(unix_now_secs());
                                }
                                // Bedrock ingress that requested ConverseStream (`wants_stream`) but
                                // got a BUFFERED (non-SSE) 2xx upstream: a native AWS SDK
                                // ConverseStream decoder expects binary `eventstream` frames, NOT an
                                // `application/json` Converse (non-stream) body. Emitting JSON here is
                                // a hard SDK-decode failure and a deterministic proxy tell. Synthesize
                                // the native frame sequence from the single translated response and
                                // emit it under `application/vnd.amazon.eventstream` instead. (Only
                                // bedrock ingress has a binary stream wire; every other ingress
                                // protocol streams SSE, which the FirstByteBody path handles when the
                                // upstream is SSE — a non-SSE upstream to an SSE-stream request still
                                // returns the translated JSON body, which their SDKs accept.)
                                if ingress_protocol == "bedrock" && wants_stream {
                                    let elapsed_ms =
                                        u64::try_from(upstream_started.elapsed().as_millis()).ok();
                                    let frames = bedrock_response_to_eventstream(&ir, elapsed_ms);
                                    let rb = Response::builder()
                                        .status(status)
                                        .header(CONTENT_TYPE, "application/vnd.amazon.eventstream");
                                    let rb = maybe_attach_bedrock_amzn_id(rb, ingress_protocol);
                                    return rb
                                        .body(Body::from(frames))
                                        .unwrap_or_else(|_| status.into_response());
                                }
                                let translated = ingress_proto.writer().write_response(&ir);
                                // Gemini JSON-array streaming (`:streamGenerateContent` WITHOUT
                                // `?alt=sse`, so `gemini_json_array`) answered by a BUFFERED non-SSE 2xx:
                                // the native non-`alt=sse` endpoint returns a JSON ARRAY of chunk objects
                                // (`[{...}]`), so a single bare `{...}` is undecodable by a Gemini SDK
                                // parsing the body as an array — a functional break and a proxy tell.
                                // Mirror the bedrock special-case above: wrap the single translated
                                // object in a one-element array under `application/json`. (Only reached on
                                // a cross-protocol non-SSE hop; the SSE path uses GeminiJsonArrayFramer.)
                                if gemini_json_array && wants_stream {
                                    let arr = Value::Array(vec![translated]);
                                    return Response::builder()
                                        .status(status)
                                        .header(CONTENT_TYPE, "application/json")
                                        .body(Body::from(arr.to_string()))
                                        .unwrap_or_else(|_| status.into_response());
                                }
                                // Content-Type is the INGRESS JSON CT, not the upstream's — the body
                                // is now in the client's native non-stream shape (§8.4). A
                                // bedrock-ingress 2xx also carries `x-amzn-RequestId` (matching a real
                                // Converse response and the error path).
                                let rb = Response::builder()
                                    .status(status)
                                    .header(CONTENT_TYPE, "application/json");
                                let rb = maybe_attach_bedrock_amzn_id(rb, ingress_protocol);
                                // Anthropic-ingress 2xx carries `request-id`. This is the
                                // CROSS-protocol translate path (ingress != egress), so there is no
                                // upstream anthropic id to forward — synthesize one.
                                let rb =
                                    maybe_attach_anthropic_request_id(rb, ingress_protocol, None);
                                return rb
                                    .body(Body::from(translated.to_string()))
                                    .unwrap_or_else(|_| status.into_response());
                            }
                        }
                    }
                    // Not translatable (non-JSON / unexpected-but-valid shape / unknown ingress).
                    // We reached this block only because ingress != egress, so relaying the upstream
                    // body+Content-Type verbatim would leak the EGRESS provider's native wire format
                    // to a different-protocol client — a foreign-format response is an immediate proxy
                    // tell (§8.2) and a functional failure (the client's SDK cannot decode it). Return
                    // an ingress-native 500 instead. (Same-protocol passthrough never enters this
                    // block — it streams through FirstByteBody / the buffered same-protocol path — so
                    // a legitimate verbatim relay is never suppressed here.)
                    tracing::warn!(
                        ingress = %ingress_protocol,
                        egress = %app.lanes[i].protocol.name(),
                        status = status.as_u16(),
                        "cross-protocol response not translatable; returning ingress-native error \
                         instead of leaking the upstream's native body"
                    );
                    return ingress_error(
                        ingress_protocol,
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "api_error",
                        GENERIC_RESPONSE_ERROR_DETAIL,
                    );
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
                // Gemini non-`alt=sse` ingress: engage the JSON-array framer (only when this is in
                // fact a streamed SSE response — a same-protocol non-stream gemini response never
                // reaches the streaming builder).
                let json_array =
                    (gemini_json_array && is_sse).then(crate::proto::GeminiJsonArrayFramer::new);
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
                    json_array,
                    usage_sink,
                );
                let axum_body = guarded_body.into_body();

                let mut rb = Response::builder().status(status);
                // Cross-protocol streaming: the body is reframed to the client's format, so the CT
                // must be the ingress client's, not the upstream's. Same-protocol passthrough keeps
                // the upstream CT verbatim. §8.4.
                let cross_protocol = ingress_protocol != app.lanes[i].protocol.name();
                if gemini_json_array && is_sse {
                    // JSON-array streaming body: a `[ {...}, {...} ]` document, not SSE.
                    rb = rb.header(CONTENT_TYPE, "application/json");
                } else {
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
                }
                // Bedrock-ingress streaming 2xx must carry `x-amzn-RequestId` (a real ConverseStream
                // always does). Prefer the upstream's real id when this is a same-protocol bedrock
                // passthrough (it captured one); otherwise synthesize. Non-bedrock ingress: omit.
                if ingress_protocol == "bedrock" {
                    if let Some(id) = upstream_amzn_id.or_else(crate::proto::synth_amzn_request_id)
                    {
                        rb = rb.header("x-amzn-requestid", id);
                    }
                }
                // Anthropic-ingress streaming 2xx must carry `request-id` (a real Anthropic stream
                // always does; the SDK reads it into `Message._request_id`).
                rb = maybe_attach_anthropic_request_id(
                    rb,
                    ingress_protocol,
                    upstream_request_id.as_deref(),
                );
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
        usage_sink,
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
    usage_sink: Option<UsageSink>,
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
                usage_sink,
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
                usage_sink,
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
        "The service is temporarily overloaded. Please retry shortly.",
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
/// Cross-protocol translation: this degraded path translates BOTH directions symmetrically with the
/// main `forward_with_pool` path — the request body is translated egress-side (via the superset IR)
/// and the 2xx response is translated back to the ingress protocol (buffered for non-stream, framed
/// via `StreamTranslate` for SSE). Non-2xx responses are reshaped to the ingress error envelope on a
/// crossed boundary. Same-protocol targets pass through verbatim.
#[allow(clippy::too_many_arguments)] // plumbing: each arg is an independent request input
#[tracing::instrument(name = "forward_once", skip_all, fields(lane = i))]
async fn forward_once(
    app: &Arc<App>,
    i: usize,
    permit: Permit,
    body: &Bytes,
    caller_token: Option<&str>,
    timeout_secs: u64,
    ingress_protocol: &str,
    usage_sink: Option<UsageSink>,
) -> Result<Response, ()> {
    // Re-parse body for per-lane model rewriting.
    let v: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => {
            return Ok(ingress_error(
                ingress_protocol,
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                &format!("We could not parse the JSON body of your request: {e}"),
            ));
        }
    };

    // stream intent for the stream-aware upstream path (Gemini).
    let wants_stream = v.get("stream").and_then(|s| s.as_bool()).unwrap_or(false);
    // Gemini ingress streaming WITHOUT `?alt=sse` → JSON-array streamed body (see main path). GATED
    // on `ingress_protocol == "gemini"` so a body-model client cannot smuggle the shim key to force
    // JSON-array reframing of its SSE stream.
    let gemini_json_array = ingress_protocol == "gemini" && wants_gemini_json_array(&v);
    let egress_name = app.lanes[i].protocol.name();

    // Cross-protocol request shaping through the SINGLE shared seam (read→clear-extra→write, shim-key
    // strip, model rewrite, serialize) — the SAME function the hot `forward_with_pool` path uses, so
    // this degraded route cannot drift from it. This unification is what fixes the R9 high (this path
    // previously lacked the `ir.extra.clear()` the hot path had, leaking source-only keys like OpenAI
    // `logprobs`/`top_logprobs`/`n` to a foreign backend): the clear now lives in the one shared fn,
    // so neither path can be missing it.
    let payload = match translate_request_cross_protocol(app, i, ingress_protocol, v) {
        Ok(p) => p,
        Err(resp) => return Ok(*resp),
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

    let mut req = app
        .client
        .post(format!("{base}{url_path}"))
        .headers(convert_headers(auth))
        .header(CONTENT_TYPE, "application/json")
        // Native-SDK User-Agent for the egress protocol (mirrors the main forward path).
        .header(USER_AGENT, egress_user_agent(egress_name))
        .body(payload);
    // See the main forward path: reqwest's `.timeout()` bounds the whole body read, so applying the
    // failover deadline to a STREAMING request truncates a healthy long generation at that wall-clock
    // and trips a spurious mid-stream breaker failure. Bound only the non-streaming request; a stream
    // runs under the shared client-level ceiling (`UPSTREAM_REQUEST_TIMEOUT_SECS`).
    if !wants_stream {
        req = req.timeout(std::time::Duration::from_secs(timeout_secs.max(1)));
    }
    // Wall-clock start of the upstream call, for the `metrics.latencyMs` a native bedrock
    // ConverseStream `metadata` frame carries on the buffered-synthesis path below.
    let upstream_started = std::time::Instant::now();
    let res = req.send().await;

    match res {
        Ok(r) => {
            let status = r.status();
            let ct = r.headers().get(CONTENT_TYPE).cloned();
            // Capture the upstream `x-amzn-RequestId` before `r` is consumed (same-protocol bedrock
            // passthrough forwards the real one; cross-protocol bedrock ingress synthesizes below).
            let upstream_amzn_id = r
                .headers()
                .get("x-amzn-requestid")
                .and_then(|h| h.to_str().ok())
                .map(|s| s.to_string());
            // Anthropic-ingress `request-id` (same-protocol degraded relay forwards it verbatim;
            // cross-protocol synthesizes). See `maybe_attach_anthropic_request_id`.
            let upstream_request_id = r
                .headers()
                .get("request-id")
                .and_then(|h| h.to_str().ok())
                .map(|s| s.to_string());
            let cross_protocol = ingress_protocol != egress_name;

            if !status.is_success() {
                let bytes = read_capped_body(r).await;
                // Cross-protocol: relaying the EGRESS provider's native error body+Content-Type to a
                // different-protocol client is a foreign-format leak (§8.2). Reshape to the ingress
                // protocol's native error envelope, lifting the upstream's human message where
                // present. Same-protocol passthrough relays verbatim (already the client's shape).
                if cross_protocol {
                    // Shared finalizer: the kind→native-envelope mapping (401→authentication_error,
                    // 403→permission_error, 429→rate_limit_error, 5xx→api_error, else
                    // invalid_request_error) is now IDENTICAL to the main `forward_with_pool` path, so
                    // this degraded route can no longer drift (the bug it fixes: a 401/403 on the
                    // degraded path was labeled `invalid_request_error`, the wrong typed-exception
                    // discriminant for an Anthropic SDK and a proxy tell).
                    return Ok(shape_cross_protocol_error(ingress_protocol, status, &bytes));
                }
                // Same-protocol degraded path: relay the upstream error verbatim (no classification).
                let mut rb = Response::builder().status(status);
                if let Some(ct) = ct {
                    rb = rb.header(CONTENT_TYPE, ct);
                }
                // Anthropic-ingress same-protocol error relay: forward the upstream `request-id`
                // verbatim (a native Anthropic error always carries it; the SDK reads it into
                // `APIError.request_id`).
                rb = maybe_attach_anthropic_request_id(
                    rb,
                    ingress_protocol,
                    upstream_request_id.as_deref(),
                );
                return Ok(rb
                    .body(Body::from(bytes))
                    .unwrap_or_else(|_| status.into_response()));
            }

            // SUCCESS: the degraded path served a 2xx. Mirror the main forward loop
            // (forward_with_pool) — record the lane success (feeds the breaker success window so a
            // HalfOpen lane served via fallback/least-bad recovers to Closed) and consume one unit of
            // its lifetime request budget. No pool context here, so use the bare-lane forms. Without
            // these, a HalfOpen lane that ONLY ever serves traffic through the exhaustion paths never
            // self-recovers and its `max_requests` budget never depletes.
            app.store.record_success(i);
            // Discard intentional (see the main path): post-success cost accounting, not admission;
            // the CAS spend can't over-spend. Explicit `let _ =` per `#[must_use]`.
            let _ = app.store.spend_budget(i);

            // SUCCESS: stream the response body incrementally (permit held for stream life).
            let is_sse = ct
                .as_ref()
                .map(|h| is_streaming_content_type(h.to_str().unwrap_or("")))
                .unwrap_or(false);

            // Non-streaming cross-protocol response: buffer + translate egress→IR→ingress, mirroring
            // the main forward_with_pool path so this degraded route does not leak the egress wire
            // format to a different-protocol client.
            if cross_protocol && !is_sse {
                // COMPLETION cap (not the tight error-body cap): a legitimate 2xx can far exceed
                // 256 KiB and must be buffered whole to translate; `truncated` lets us return a
                // clear error instead of mis-reporting a too-large success as untranslatable.
                let (bytes, read_end) = read_capped(r, MAX_TRANSLATED_BODY_BYTES).await;
                drop(permit); // a buffered (non-streamed) response holds no permit
                if read_end == ReadEnd::TransportError {
                    // Body failed mid-transfer after an optimistic success/budget recording on the
                    // 2xx headers (see the main forward path): don't charge tokens for a corrupt
                    // fragment, record a compensating transient failure, refund the request budget
                    // unit spent on the headers (no usable response was delivered, so a failed body
                    // transfer must not permanently drain the lane's `max_requests` budget), and
                    // return an ingress-native error. No pool context on the degraded path, so use the
                    // bare-lane forms.
                    tracing::warn!(
                        ingress = %ingress_protocol,
                        egress = %egress_name,
                        "cross-protocol non-stream upstream body failed mid-transfer; \
                         not recording success/usage, refunding budget, returning ingress-native error"
                    );
                    app.store.record_transient(
                        i,
                        "transport",
                        &crate::store::BreakerCfg::default(),
                        None,
                    );
                    app.store.refund_budget(i);
                    return Ok(ingress_error(
                        ingress_protocol,
                        StatusCode::BAD_GATEWAY,
                        "api_error",
                        GENERIC_RESPONSE_ERROR_DETAIL,
                    ));
                }
                // Token accounting: no FirstByteBody on this buffered path, so tap the usage here and
                // charge it to the key's budget (mirrors the main path).
                record_nonstream_usage(&bytes, &usage_sink);
                if read_end == ReadEnd::Truncated {
                    tracing::warn!(
                        ingress = %ingress_protocol,
                        egress = %egress_name,
                        cap = MAX_TRANSLATED_BODY_BYTES,
                        "cross-protocol non-stream success body exceeded the translation cap; \
                         cannot translate, returning ingress-native error"
                    );
                    return Ok(ingress_error(
                        ingress_protocol,
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "api_error",
                        GENERIC_RESPONSE_ERROR_DETAIL,
                    ));
                }
                if let Ok(rv) = serde_json::from_slice::<Value>(&bytes) {
                    if let Ok(mut ir) = app.lanes[i].protocol.reader().read_response(&rv) {
                        if let Some(ingress_proto) = crate::proto::protocol_for(ingress_protocol) {
                            // Strip the backend's native-format identity so the ingress writer mints
                            // values in the CLIENT's format (see the main path for the rationale).
                            ir.id = None;
                            ir.system_fingerprint = None;
                            ir.stop_sequence = None;
                            // Cross-protocol boundary signal for an identity-empty egress (Bedrock):
                            // stamp a synthesized `created` so the ingress writers trip their
                            // `created`-based identity gate, exactly as on the main forward path above.
                            if ir.created.is_none() {
                                ir.created = Some(unix_now_secs());
                            }
                            // Bedrock ConverseStream request answered by a buffered (non-SSE) 2xx:
                            // emit the native binary eventstream frame sequence, not an
                            // `application/json` Converse body the SDK's stream decoder cannot parse
                            // (mirrors the main forward path; see `bedrock_response_to_eventstream`).
                            if ingress_protocol == "bedrock" && wants_stream {
                                let elapsed_ms =
                                    u64::try_from(upstream_started.elapsed().as_millis()).ok();
                                let frames = bedrock_response_to_eventstream(&ir, elapsed_ms);
                                let rb = Response::builder()
                                    .status(status)
                                    .header(CONTENT_TYPE, "application/vnd.amazon.eventstream");
                                let rb = maybe_attach_bedrock_amzn_id(rb, ingress_protocol);
                                return Ok(rb
                                    .body(Body::from(frames))
                                    .unwrap_or_else(|_| status.into_response()));
                            }
                            let translated = ingress_proto.writer().write_response(&ir);
                            // Gemini JSON-array streaming answered by a buffered non-SSE 2xx: wrap the
                            // single translated object in a one-element JSON array, matching the native
                            // non-`alt=sse` `streamGenerateContent` array framing (see the main path).
                            if gemini_json_array && wants_stream {
                                let arr = Value::Array(vec![translated]);
                                return Ok(Response::builder()
                                    .status(status)
                                    .header(CONTENT_TYPE, "application/json")
                                    .body(Body::from(arr.to_string()))
                                    .unwrap_or_else(|_| status.into_response()));
                            }
                            // Bedrock-ingress 2xx carries `x-amzn-RequestId` (matching a real
                            // Converse response and the error path).
                            let rb = Response::builder()
                                .status(status)
                                .header(CONTENT_TYPE, "application/json");
                            let rb = maybe_attach_bedrock_amzn_id(rb, ingress_protocol);
                            // Cross-protocol degraded translate (ingress != egress): no upstream
                            // anthropic id to forward — synthesize the `request-id` header.
                            let rb = maybe_attach_anthropic_request_id(rb, ingress_protocol, None);
                            return Ok(rb
                                .body(Body::from(translated.to_string()))
                                .unwrap_or_else(|_| status.into_response()));
                        }
                    }
                }
                // Untranslatable across a protocol boundary: return an ingress-native error rather
                // than leaking the upstream body verbatim.
                tracing::warn!(
                    ingress = %ingress_protocol,
                    egress = %egress_name,
                    "degraded cross-protocol response not translatable; returning ingress-native error"
                );
                return Ok(ingress_error(
                    ingress_protocol,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "api_error",
                    GENERIC_RESPONSE_ERROR_DETAIL,
                ));
            }

            // Streaming (or same-protocol non-stream): stream with first-byte boundary tracking. On a
            // cross-protocol SSE response, translate egress frames → ingress frames, matching the main
            // path. No pool context here → ADR-0002 default breaker config + lane-default cell.
            let translate = if is_sse && cross_protocol {
                crate::proto::StreamTranslate::new(ingress_protocol, egress_name)
            } else {
                None
            };
            let json_array =
                (gemini_json_array && is_sse).then(crate::proto::GeminiJsonArrayFramer::new);
            let upstream_stream = r.bytes_stream();
            let guarded_body = FirstByteBody::new(
                upstream_stream,
                is_sse,
                ingress_protocol,
                permit,
                app.clone(),
                i,
                Arc::new(crate::store::BreakerCfg::default()),
                "", // degraded path: lane-default breaker cell
                translate,
                json_array,
                usage_sink,
            );
            let mut rb = Response::builder().status(status);
            // Cross-protocol streaming: the body is reframed to the client's format, so the CT must
            // describe the ingress client's wire, not the upstream's. Same-protocol keeps the upstream
            // CT verbatim.
            if gemini_json_array && is_sse {
                rb = rb.header(CONTENT_TYPE, "application/json");
            } else {
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
            }
            // Bedrock-ingress streaming 2xx carries `x-amzn-RequestId`: forward the upstream's real
            // id on same-protocol passthrough, else synthesize. Non-bedrock ingress: omit.
            if ingress_protocol == "bedrock" {
                if let Some(id) = upstream_amzn_id.or_else(crate::proto::synth_amzn_request_id) {
                    rb = rb.header("x-amzn-requestid", id);
                }
            }
            // Anthropic-ingress 2xx carries `request-id`: forward the upstream's verbatim on a
            // same-protocol passthrough, else synthesize. Non-anthropic ingress: omit.
            rb = maybe_attach_anthropic_request_id(
                rb,
                ingress_protocol,
                upstream_request_id.as_deref(),
            );
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
#[allow(clippy::too_many_arguments)] // plumbing: each arg is an independent request input
async fn handle_fallback_pool(
    app: Arc<App>,
    body: Bytes,
    caller_token: Option<&str>,
    pool_name: &str,
    request_ctx: &mut RequestCtx,
    ingress_protocol: &str,
    usage_sink: Option<UsageSink>,
) -> Response {
    // Deadline propagated across hops.
    if request_ctx.expired(now()) {
        return ingress_error(
            ingress_protocol,
            StatusCode::SERVICE_UNAVAILABLE,
            "overloaded",
            "The request timed out. Please retry shortly.",
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
                "The request timed out. Please retry shortly.",
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
                usage_sink,
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
            // Clone per attempt: a transient transport failure retries the next member, so the sink
            // must survive into the next loop iteration; only a successful stream consumes it.
            usage_sink.clone(),
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
    usage_sink: Option<UsageSink>,
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
        usage_sink,
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

        // Cohere v2 native streaming terminal frame: token counts nested under
        // `delta.usage.tokens`, NOT the top-level `usage`. Before the dedicated arm this reported
        // zero tokens on a same-protocol Cohere passthrough, silently undercharging the key's
        // TPM/spend budget.
        let mut t = UsageTap::new();
        t.feed(&Bytes::from(
            r#"{"type":"message-end","delta":{"usage":{"tokens":{"input_tokens":11,"output_tokens":9}}}}"#,
        ));
        assert_eq!(t.input_tokens, Some(11));
        assert_eq!(t.output_tokens, Some(9));
    }

    #[test]
    fn test_tap_detects_terminal_error_across_shapes() {
        // Anthropic SSE error event: {"type":"error", "error":{...}}.
        let mut t = UsageTap::new();
        t.feed(&Bytes::from(
            r#"{"type":"error","error":{"type":"overloaded_error","message":"boom"}}"#,
        ));
        assert_eq!(t.terminal_error.as_deref(), Some("boom"));

        // OpenAI / OpenAI-compatible in-band terminal error: bare {"error":{...}} with NO `type`
        // discriminant. Previously undetected on a SAME-protocol OpenAI passthrough, so a backend
        // that emitted this then closed cleanly never tripped the breaker.
        let mut t = UsageTap::new();
        t.feed(&Bytes::from(
            r#"{"error":{"message":"upstream exploded","type":"server_error"}}"#,
        ));
        assert_eq!(t.terminal_error.as_deref(), Some("upstream exploded"));

        // A normal OpenAI chunk (no top-level `error`) must NOT be flagged as terminal.
        let mut t = UsageTap::new();
        t.feed(&Bytes::from(
            r#"{"id":"chatcmpl-1","object":"chat.completion.chunk","choices":[{"delta":{"content":"hi"}}]}"#,
        ));
        assert_eq!(t.terminal_error, None);

        // A chunk that merely carries `error: null` must NOT false-trip.
        let mut t = UsageTap::new();
        t.feed(&Bytes::from(r#"{"choices":[],"error":null}"#));
        assert_eq!(t.terminal_error, None);
    }

    /// MEDIUM (forward.rs same-protocol bedrock passthrough): a bedrock→bedrock streaming passthrough
    /// is BINARY `application/vnd.amazon.eventstream`, so the JSON `feed` scanner is skipped. The
    /// bedrock-aware `feed_eventstream` must instead reassemble the native frames and (a) charge the
    /// `metadata` frame's `usage.{inputTokens,outputTokens}` so TPM/spend governance is not silently
    /// bypassed, and (b) flag an in-band `*Exception` frame as `terminal_error` so the stream-end
    /// breaker arm trips the lane even though the HTTP response was a clean 200.
    #[test]
    fn test_eventstream_tap_counts_usage_and_detects_exception() {
        use crate::eventstream::{encode_exception_frame, encode_frame};

        // A `metadata` frame carrying the native Converse usage shape → tokens are counted.
        let mut t = UsageTap::new();
        let meta = encode_frame(
            "metadata",
            br#"{"usage":{"inputTokens":42,"outputTokens":13}}"#,
        );
        t.feed_eventstream(&Bytes::from(meta));
        assert_eq!(t.input_tokens, Some(42));
        assert_eq!(t.output_tokens, Some(13));
        // A clean stream (no exception frame) leaves terminal_error unset → no breaker trip.
        assert_eq!(t.terminal_error, None);

        // An in-band modeled exception frame → terminal_error set (breaker trips at stream end).
        let mut t = UsageTap::new();
        let exc = encode_exception_frame(
            "InternalServerException",
            "An internal error occurred during request processing.",
        );
        t.feed_eventstream(&Bytes::from(exc));
        assert_eq!(
            t.terminal_error.as_deref(),
            Some("An internal error occurred during request processing.")
        );

        // Frames split across chunk boundaries must still be reassembled: feed the metadata frame one
        // byte at a time, then assert the usage was extracted only once the final byte completes it.
        let mut t = UsageTap::new();
        let meta = encode_frame(
            "metadata",
            br#"{"usage":{"inputTokens":5,"outputTokens":7}}"#,
        );
        let split = meta.len();
        for (idx, b) in meta.iter().enumerate() {
            t.feed_eventstream(&Bytes::copy_from_slice(&[*b]));
            if idx + 1 < split {
                assert_eq!(t.input_tokens, None, "must not parse a partial frame");
            }
        }
        assert_eq!(t.input_tokens, Some(5));
        assert_eq!(t.output_tokens, Some(7));
    }
}

#[cfg(test)]
mod cross_protocol_extra_tests {
    use crate::proto::Protocol;

    /// Structural class fix: on a CROSS-protocol request hop the source-protocol-only passthrough
    /// keys swept into `IrRequest.extra` (e.g. OpenAI `logprobs`/`top_logprobs`/`n`) must NOT reach
    /// the foreign egress backend body. The seam in `forward_with_pool` clears `ir.extra` before the
    /// egress `write_request`; this mirrors that exact sequence (reader → clear → writer).
    #[test]
    fn cross_protocol_strips_source_only_extra_keys() {
        let body = serde_json::json!({
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "hi"}],
            "max_tokens": 16,
            "logprobs": true,
            "top_logprobs": 5,
            "n": 3
        });
        let openai = Protocol::openai();
        let mut ir = openai.reader().read_request(&body).expect("read");
        // Sanity: the reader DID sweep the source-only keys into extra.
        assert!(ir.extra.contains_key("logprobs"));
        assert!(ir.extra.contains_key("n"));

        // The cross-protocol seam clears extra before handing to the foreign writer.
        ir.extra.clear();
        let anthropic = Protocol::anthropic();
        let out = anthropic.writer().write_request(&ir);
        let obj = out.as_object().expect("object body");
        assert!(
            !obj.contains_key("logprobs"),
            "OpenAI logprobs must not leak onto an Anthropic backend body"
        );
        assert!(!obj.contains_key("top_logprobs"));
        assert!(!obj.contains_key("n"));
        // The modeled fields still translate across.
        assert!(obj.contains_key("messages"));
    }

    /// SAME-protocol passthrough keeps `extra` intact (lossless): the seam only clears on a
    /// cross-protocol hop, so an openai→openai round-trip must still carry `logprobs`.
    #[test]
    fn same_protocol_passthrough_preserves_extra_keys() {
        let body = serde_json::json!({
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "hi"}],
            "logprobs": true,
            "n": 3
        });
        let openai = Protocol::openai();
        let ir = openai.reader().read_request(&body).expect("read");
        // No clear() here — same-protocol passthrough never hits the cross-protocol seam.
        let out = openai.writer().write_request(&ir);
        let obj = out.as_object().expect("object body");
        assert_eq!(
            obj.get("logprobs"),
            Some(&serde_json::json!(true)),
            "same-protocol openai→openai must preserve logprobs (lossless passthrough)"
        );
        assert_eq!(obj.get("n"), Some(&serde_json::json!(3)));
    }
}

#[cfg(test)]
mod bedrock_eventstream_tests {
    use super::bedrock_response_to_eventstream;
    use crate::ir::{IrBlock, IrResponse, IrRole, IrUsage};

    /// A bedrock-ingress ConverseStream request answered by a BUFFERED (non-SSE) 2xx is rewrapped
    /// into the native binary eventstream frame sequence — not an `application/json` Converse body
    /// the AWS SDK's stream decoder cannot parse. Assert the synthesized bytes decode into the
    /// expected native ConverseStream frame sequence (messageStart … messageStop, metadata).
    #[test]
    fn buffered_response_wraps_into_converse_stream_frames() {
        let ir = IrResponse {
            role: IrRole::Assistant,
            content: vec![IrBlock::Text {
                text: "hello world".to_string(),
                cache_control: None,
                citations: Vec::new(),
            }],
            stop_reason: Some("end_turn".to_string()),
            usage: IrUsage {
                input_tokens: 11,
                output_tokens: 7,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
            model: Some("anthropic.claude-3".to_string()),
            id: None,
            created: None,
            system_fingerprint: None,
            stop_sequence: None,
        };
        let mut bytes = bedrock_response_to_eventstream(&ir, Some(42));
        assert!(!bytes.is_empty(), "must emit eventstream frames");

        // Decode the frames using the same decoder the wire uses.
        let frames = crate::eventstream::drain_frames(&mut bytes);
        let names: Vec<&str> = frames.iter().map(|(t, _)| t.as_str()).collect();
        assert_eq!(names.first(), Some(&"messageStart"));
        assert!(names.contains(&"contentBlockStart"));
        assert!(names.contains(&"contentBlockDelta"));
        assert!(names.contains(&"contentBlockStop"));
        assert!(names.contains(&"messageStop"));
        // The trailing metadata frame carries token usage.
        let metadata = frames
            .iter()
            .find(|(t, _)| t == "metadata")
            .expect("metadata frame");
        let payload: serde_json::Value = serde_json::from_slice(&metadata.1).expect("json");
        assert_eq!(payload["usage"]["inputTokens"], 11);
        assert_eq!(payload["usage"]["outputTokens"], 7);
        assert_eq!(payload["usage"]["totalTokens"], 18);
        // HIGH (R9): a real ConverseStream `metadata` event ALWAYS carries `metrics.latencyMs`
        // (the SDK surfaces it via `ConverseStreamMetadataEvent::metrics()`). The buffered-synthesis
        // path must inject it too — `None` here would be a deterministic proxy tell. Mirrors the
        // live StreamTranslate path assertion in proto/mod.rs.
        assert_eq!(
            payload["metrics"]["latencyMs"].as_u64(),
            Some(42),
            "buffered metadata frame must carry metrics.latencyMs like the live path: {payload}"
        );
    }

    /// MEDIUM (R9, forward.rs:429-448): the `IrBlock::ToolUse` arm of `bedrock_response_to_eventstream`
    /// must synthesize native ConverseStream tool-use framing — a `contentBlockStart` carrying
    /// `start.toolUse.{toolUseId,name}` and a `contentBlockDelta` carrying `delta.toolUse.input` — so a
    /// native AWS SDK ConverseStream client receiving a buffered cross-protocol tool-call completion can
    /// decode it. The happy-path test only exercises a `Text` block; this covers the tool arm.
    #[test]
    fn buffered_tool_use_wraps_into_converse_stream_tool_frames() {
        let ir = IrResponse {
            role: IrRole::Assistant,
            content: vec![IrBlock::ToolUse {
                id: "toolu_abc123".to_string(),
                name: "get_weather".to_string(),
                input: serde_json::json!({"city": "Paris"}),
            }],
            stop_reason: Some("tool_use".to_string()),
            usage: IrUsage {
                input_tokens: 5,
                output_tokens: 9,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
            model: Some("anthropic.claude-3".to_string()),
            id: None,
            created: None,
            system_fingerprint: None,
            stop_sequence: None,
        };
        let mut bytes = bedrock_response_to_eventstream(&ir, Some(7));
        let frames = crate::eventstream::drain_frames(&mut bytes);

        // contentBlockStart must carry the tool identity nested under start.toolUse.
        let start = frames
            .iter()
            .find(|(t, _)| t == "contentBlockStart")
            .expect("contentBlockStart frame");
        let start_payload: serde_json::Value =
            serde_json::from_slice(&start.1).expect("json contentBlockStart");
        assert_eq!(
            start_payload["start"]["toolUse"]["toolUseId"], "toolu_abc123",
            "tool start carries toolUseId: {start_payload}"
        );
        assert_eq!(
            start_payload["start"]["toolUse"]["name"], "get_weather",
            "tool start carries name: {start_payload}"
        );

        // contentBlockDelta must carry the serialized tool input under delta.toolUse.input.
        let delta = frames
            .iter()
            .find(|(t, _)| t == "contentBlockDelta")
            .expect("contentBlockDelta frame");
        let delta_payload: serde_json::Value =
            serde_json::from_slice(&delta.1).expect("json contentBlockDelta");
        let input_str = delta_payload["delta"]["toolUse"]["input"]
            .as_str()
            .expect("tool input is a serialized JSON string");
        let input: serde_json::Value =
            serde_json::from_str(input_str).expect("input decodes to JSON");
        assert_eq!(
            input["city"], "Paris",
            "tool input round-trips through the delta: {delta_payload}"
        );
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

    #[test]
    fn test_host_from_base_strips_scheme_and_userinfo() {
        use super::host_from_base;
        // Plain host: scheme stripped, nothing else touched.
        assert_eq!(
            host_from_base("https://bedrock-runtime.us-east-1.amazonaws.com"),
            "bedrock-runtime.us-east-1.amazonaws.com"
        );
        assert_eq!(host_from_base("http://localhost:8080"), "localhost:8080");
        // No scheme: returned unchanged.
        assert_eq!(host_from_base("example.com"), "example.com");
        // Embedded userinfo MUST be stripped so the SigV4-signed `host` matches the `Host` header
        // the HTTP stack actually transmits (otherwise: signature mismatch + credential in the
        // signed string). The host (and port) survive; the credential is gone.
        assert_eq!(
            host_from_base("https://user:pass@host.example.com"),
            "host.example.com"
        );
        assert_eq!(
            host_from_base("https://user:pass@host.example.com:443"),
            "host.example.com:443"
        );
        // An `@` later in a path/query is NOT userinfo and must not be treated as one.
        assert_eq!(
            host_from_base("https://host.example.com/x@y"),
            "host.example.com/x@y"
        );
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
        strip_same_protocol_model_shim, GEMINI_JSON_ARRAY_SHIM_KEY, MID_STREAM_GENERIC_DETAIL,
    };
    use crate::proto::StatusClass;
    use serde_json::{json, Value};

    /// HIGH (forward.rs:~1108 gemini JSON-array path, + the SSE/eventstream + pre-first-byte twins):
    /// the client-facing mid-stream transport-error detail MUST be a static, vendor-neutral string —
    /// NEVER the raw `reqwest::Error` Display, which embeds hyper/reqwest internals and the egress
    /// backend URL (a protocol tell + infrastructure leak). All three call sites pass the single
    /// `MID_STREAM_GENERIC_DETAIL` const; pin that the const itself carries no leak markers, and that
    /// both error-framing helpers it feeds emit a body free of them.
    #[test]
    fn test_mid_stream_generic_detail_has_no_leak_markers() {
        // Markers: transport/infrastructure tells (URLs, hyper/reqwest internals) AND busbar-internal
        // reverse-proxy VOCABULARY ("upstream"/"proxy"/"gateway"/"backend"/"lane"/"translate"). A
        // native vendor SDK never emits the latter in an error body or stream exception frame, so the
        // word "upstream" was itself a protocol-indistinguishability tell — pin it out here so it
        // cannot creep back into any client-facing fallback constant.
        const LEAK_MARKERS: &[&str] = &[
            "http://",
            "https://",
            "reqwest",
            "hyper",
            "tcp",
            "dns",
            "connect",
            "amazonaws",
            "url",
            "error sending request",
            "upstream",
            "proxy",
            "gateway",
            "backend",
            "lane",
            "translat", // matches "translate" / "translation" / "untranslatable"
        ];
        // Every client-facing fallback string, not just the mid-stream detail: all are rendered into
        // a native error envelope / stream frame and must read like a real single-vendor API.
        for detail in [
            MID_STREAM_GENERIC_DETAIL,
            super::GENERIC_REJECTED_DETAIL,
            super::GENERIC_RESPONSE_ERROR_DETAIL,
        ] {
            for marker in LEAK_MARKERS {
                assert!(
                    !detail.to_ascii_lowercase().contains(marker),
                    "client-facing fallback must not contain leak marker {marker:?}: {detail:?}"
                );
            }
        }
        // The Gemini JSON-array path (the HIGH finding): a `google.rpc.Status` element whose message
        // is exactly the generic detail, with no transport/URL markers spliced in.
        let mut framer = crate::proto::GeminiJsonArrayFramer::new();
        let arr = framer.finish_with_error(500, "INTERNAL", MID_STREAM_GENERIC_DETAIL);
        let arr_text = String::from_utf8_lossy(&arr);
        assert!(arr_text.contains(MID_STREAM_GENERIC_DETAIL));
        for marker in ["https://", "reqwest", "hyper", "amazonaws"] {
            assert!(
                !arr_text.contains(marker),
                "gemini json-array error body leaked {marker:?}: {arr_text}"
            );
        }
        // The SSE ingress twins carry the same generic detail in their native error envelope.
        for proto in ["openai", "anthropic", "gemini", "cohere", "responses"] {
            let bytes = mid_stream_error_bytes(proto, false, MID_STREAM_GENERIC_DETAIL);
            let text = String::from_utf8_lossy(&bytes);
            assert!(
                text.contains(MID_STREAM_GENERIC_DETAIL),
                "{proto} mid-stream error must carry the generic detail; got {text}"
            );
        }
    }

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

    /// HIGH/conformance (forward.rs:~190): the SSE mid-stream error frame must be the ingress
    /// writer's OWN STREAMING error event (`write_response_event(&Error)`), framed exactly as the
    /// happy path — NOT the non-stream `write_error()` HTTP envelope. Bare-`data:` protocols
    /// (openai/cohere/gemini, whose native streams emit `data:`-only frames) get NO `event:` line;
    /// anthropic gets `event: error`; responses gets `event: response.failed` with the SDK-required
    /// `{"response":{...,"error":{...}}}` STREAM shape.
    #[test]
    fn test_sse_ingress_mid_stream_error_uses_native_framing() {
        // openai / cohere / gemini: bare `data:`, NO event line, native JSON envelope. (Gemini's
        // native streaming error is a bare `data:` frame — its writer returns an empty event name —
        // NOT `event: error`; emitting an event line for gemini was the pre-fix bug.)
        for proto in ["openai", "cohere", "gemini"] {
            let bytes = mid_stream_error_bytes(proto, false, "boom");
            let text = String::from_utf8(bytes).expect("SSE error is utf-8 text");
            assert!(
                text.starts_with("data: "),
                "{proto}: bare data: frame (no event: line); got: {text}"
            );
            assert!(
                !text.contains("event:"),
                "{proto}: native stream never emits an event: line mid-stream; got: {text}"
            );
            let data = text
                .lines()
                .find_map(|l| l.strip_prefix("data: "))
                .expect("a data: line");
            let v: Value = serde_json::from_str(data).expect("native JSON envelope");
            // OpenAI/Gemini wrap in `error`; Cohere uses a flat `type`+`message`. Either way the
            // detail is carried in the protocol's native streaming-error shape.
            let has_native_shape = v.get("error").is_some() || v.get("message").is_some();
            assert!(has_native_shape, "{proto} native envelope: {v}");
        }

        // anthropic: named `event: error`, payload `{"type":"error","error":{"type","message"}}`.
        let bytes = mid_stream_error_bytes("anthropic", false, "boom");
        let text = String::from_utf8(bytes).expect("SSE error is utf-8 text");
        assert!(
            text.starts_with("event: error\n"),
            "anthropic: named event: error frame; got: {text}"
        );
        let data = text
            .lines()
            .find_map(|l| l.strip_prefix("data: "))
            .expect("a data: line");
        let v: Value = serde_json::from_str(data).expect("native JSON envelope");
        // The `error` discriminant is the SSE event NAME (`event: error`); the data payload is
        // `{"error":{"type","message"}}` (the native Anthropic in-stream error event body).
        assert!(
            v["error"]["message"].is_string(),
            "anthropic error.message present: {v}"
        );

        // responses: terminal error event is `response.failed`, and the payload MUST be the STREAM
        // shape `{"response":{...,"error":{...}}}` (the SDK reads `event.response`), NOT the
        // non-stream `{"error":{...}}` HTTP envelope. This is the core of the finding.
        let bytes = mid_stream_error_bytes("responses", false, "boom");
        let text = String::from_utf8(bytes).expect("SSE error is utf-8 text");
        assert!(
            text.starts_with("event: response.failed\n"),
            "responses: event: response.failed frame; got: {text}"
        );
        let data = text
            .lines()
            .find_map(|l| l.strip_prefix("data: "))
            .expect("a data: line");
        let v: Value = serde_json::from_str(data).expect("native JSON envelope");
        assert!(
            v.get("response").is_some(),
            "responses stream error MUST wrap in a `response` object (SDK reads event.response), \
             not a top-level `error`; got: {v}"
        );
        assert_eq!(
            v["response"]["status"], "failed",
            "responses failed-event status: {v}"
        );
        assert!(
            v["response"]["error"]["message"].is_string(),
            "responses error.message present inside response object: {v}"
        );
        assert!(
            v.get("error").is_none(),
            "responses stream error must NOT carry a top-level `error` (that is the HTTP envelope, \
             which the stream decoder cannot locate): {v}"
        );
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

    /// `strip_router_shim_keys` removes the NEVER-NATIVE shim keys on every branch: the gemini
    /// JSON-array key for ALL egress, and `stream` for path-model gemini/bedrock EGRESS (R9 HIGH: gated
    /// on egress, not ingress, so the writer-authored `stream` survives for a body-model backend). It
    /// does NOT remove `model` (that is `strip_same_protocol_model_shim`'s job, on the same-protocol
    /// branch only) so a cross-protocol hop keeps the authoritative model `rewrite_model` installs.
    #[test]
    fn test_strip_router_shim_keys() {
        let mut v =
            json!({"model": "p", "stream": true, GEMINI_JSON_ARRAY_SHIM_KEY: true, "messages": []});
        strip_router_shim_keys(&mut v, "bedrock");
        assert_eq!(
            v["model"], "p",
            "model NOT stripped here (rewrite_model owns it)"
        );
        assert!(v.get("stream").is_none(), "bedrock: stream shim stripped");
        assert!(
            v.get(GEMINI_JSON_ARRAY_SHIM_KEY).is_none(),
            "gemini array shim key stripped on every protocol"
        );
        assert!(v.get("messages").is_some(), "real fields retained");

        let mut v = json!({"stream": true, GEMINI_JSON_ARRAY_SHIM_KEY: true});
        strip_router_shim_keys(&mut v, "gemini");
        assert!(v.get("stream").is_none() && v.get(GEMINI_JSON_ARRAY_SHIM_KEY).is_none());

        // OpenAI is a BODY-MODEL protocol: model/stream are genuine caller fields, never stripped —
        // but the gemini array key is never native to ANY protocol, so a client-smuggled copy is
        // still removed (closes the body-model framing-smuggle leak).
        let mut v = json!({"model": "gpt-4o", "stream": true, GEMINI_JSON_ARRAY_SHIM_KEY: true});
        strip_router_shim_keys(&mut v, "openai");
        assert_eq!(
            v["model"], "gpt-4o",
            "openai model is genuine, not stripped"
        );
        assert_eq!(v["stream"], true, "openai stream is genuine, not stripped");
        assert!(
            v.get(GEMINI_JSON_ARRAY_SHIM_KEY).is_none(),
            "gemini array key stripped even for body-model ingress"
        );
    }

    /// `strip_same_protocol_model_shim` removes the body `model` for same-protocol gemini/bedrock
    /// passthrough (model rides the URL there), and is a no-op for body-model ingress.
    #[test]
    fn test_strip_same_protocol_model_shim() {
        let mut v = json!({"model": "p", "messages": []});
        strip_same_protocol_model_shim(&mut v, "gemini");
        assert!(
            v.get("model").is_none(),
            "gemini same-protocol: model stripped"
        );
        assert!(v.get("messages").is_some());

        let mut v = json!({"model": "gpt-4o"});
        strip_same_protocol_model_shim(&mut v, "openai");
        assert_eq!(v["model"], "gpt-4o", "openai model never stripped");
    }

    /// REGRESSION (R7 CRITICAL, forward.rs shim-strip ordering): a PATH-MODEL ingress (gemini/bedrock)
    /// crossing to a BODY-MODEL egress (openai/anthropic/cohere/responses) must reach the backend WITH
    /// the authoritative egress `model`. The bug: `rewrite_model` ran, then an UNCONDITIONAL strip
    /// removed `model`, so the cross-protocol body hit the backend with no `model` (a guaranteed 400).
    /// This exercises the exact strip→rewrite ordering on a value, asserting the cross-protocol body
    /// keeps `model` and (R9 HIGH) keeps the writer-authored `stream` for a BODY-MODEL egress, while
    /// the array key is gone; and the same-protocol path drops `model` and (path-model egress) `stream`.
    #[test]
    fn test_shim_strip_ordering_cross_protocol_keeps_model() {
        // Cross-protocol gemini→openai: strip (never-native keys, gated on EGRESS) → rewrite_model
        // installs the lane model → NO same-protocol model strip. Body must carry the egress model AND
        // keep the writer-authored `stream` (R9 HIGH: openai is a body-model egress, so the backend
        // reads `stream` from the body — stripping it made it answer non-streaming).
        let mut v = json!({"model": "router-placeholder", "stream": true, GEMINI_JSON_ARRAY_SHIM_KEY: true});
        let ingress = "gemini";
        let egress = "openai";
        strip_router_shim_keys(&mut v, egress);
        crate::proto::Protocol::openai()
            .writer()
            .rewrite_model(&mut v, "gpt-4o");
        if ingress == egress {
            strip_same_protocol_model_shim(&mut v, ingress);
        }
        assert_eq!(
            v["model"], "gpt-4o",
            "cross-protocol egress body MUST carry the authoritative model (the critical fix)"
        );
        assert_eq!(
            v["stream"], true,
            "R9 HIGH: writer-authored `stream` MUST survive for a body-model egress (gated on egress)"
        );
        assert!(
            v.get(GEMINI_JSON_ARRAY_SHIM_KEY).is_none(),
            "gemini array key stripped cross-protocol"
        );

        // Same-protocol gemini→gemini: model rides the URL, so the body must NOT carry `model` even
        // though the gemini writer's rewrite_model re-inserts one — the same-protocol strip runs after.
        // `stream` IS stripped here because the EGRESS is gemini (path-model: stream rides the URL).
        let mut v = json!({"model": "router-placeholder", "stream": true, "contents": []});
        let ingress = "gemini";
        let egress = "gemini";
        strip_router_shim_keys(&mut v, egress);
        crate::proto::Protocol::gemini()
            .writer()
            .rewrite_model(&mut v, "gemini-1.5-pro");
        if ingress == egress {
            strip_same_protocol_model_shim(&mut v, ingress);
        }
        assert!(
            v.get("model").is_none(),
            "same-protocol gemini passthrough must NOT leak a body model (rides the URL)"
        );
        assert!(
            v.get("stream").is_none(),
            "shim stream stripped for path-model (gemini) egress"
        );
    }
}

#[cfg(test)]
mod ingress_indistinguishability_tests {
    use super::{
        cross_protocol_error_kind, forward_with_pool, ingress_error, ingress_stream_content_type,
        shape_cross_protocol_error,
    };
    use crate::test_support::{LaneSpec, MockResponse, MockServer, MockServerState, TestApp};
    use reqwest::StatusCode;
    use serde_json::{json, Value};
    use std::sync::Arc;

    /// CANONICAL status→kind mapping shared by the main and degraded cross-protocol error shaping.
    /// REGRESSION (R7 MEDIUM, forward_once): a 401/403 must map to authentication_error/
    /// permission_error, NOT invalid_request_error (the degraded-path bug). Exhaustive over the
    /// status arms the mapping distinguishes.
    #[test]
    fn test_cross_protocol_error_kind_mapping() {
        assert_eq!(
            cross_protocol_error_kind(StatusCode::UNAUTHORIZED),
            "authentication_error"
        );
        assert_eq!(
            cross_protocol_error_kind(StatusCode::FORBIDDEN),
            "permission_error"
        );
        assert_eq!(
            cross_protocol_error_kind(StatusCode::TOO_MANY_REQUESTS),
            "rate_limit_error"
        );
        assert_eq!(
            cross_protocol_error_kind(StatusCode::INTERNAL_SERVER_ERROR),
            "api_error"
        );
        assert_eq!(
            cross_protocol_error_kind(StatusCode::BAD_GATEWAY),
            "api_error"
        );
        assert_eq!(
            cross_protocol_error_kind(StatusCode::BAD_REQUEST),
            "invalid_request_error"
        );
        assert_eq!(
            cross_protocol_error_kind(StatusCode::NOT_FOUND),
            "invalid_request_error"
        );
    }

    /// `shape_cross_protocol_error` (the shared finalizer used by BOTH `forward_with_pool` and
    /// `forward_once`) reshapes a crossed-boundary non-2xx into the ingress-native envelope with the
    /// canonical kind. REGRESSION: a 401 from an OpenAI backend reaching an Anthropic client must be
    /// `authentication_error`, a 403 `permission_error` — matching the main path, not the old
    /// degraded-path `invalid_request_error`.
    #[tokio::test]
    async fn test_shape_cross_protocol_error_auth_kinds() {
        use http_body_util::BodyExt as _;
        for (status, want_kind) in [
            (StatusCode::UNAUTHORIZED, "authentication_error"),
            (StatusCode::FORBIDDEN, "permission_error"),
        ] {
            let resp =
                shape_cross_protocol_error("anthropic", status, br#"{"error":{"message":"nope"}}"#);
            assert_eq!(resp.status(), status, "status preserved");
            let bytes = resp.into_body().collect().await.unwrap().to_bytes();
            let v: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(
                v["error"]["type"], want_kind,
                "cross-protocol {status} must map to {want_kind} (matches the main path)"
            );
            assert_eq!(
                v["error"]["message"], "nope",
                "upstream human message is lifted into the native envelope"
            );
        }
    }

    /// REGRESSION (R7 HIGH, forward.rs ingress_error): a Bedrock-ingress forward-layer error must
    /// carry BOTH `x-amzn-RequestId` and `x-amzn-errortype` (mirroring the body `__type`), exactly
    /// like a real AWS Bedrock runtime error and like route.rs/auth.rs. Non-bedrock ingress must NOT
    /// carry them.
    #[test]
    fn test_ingress_error_bedrock_amzn_headers() {
        let resp = ingress_error(
            "bedrock",
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limit_error",
            "slow down",
        );
        assert!(
            resp.headers().get("x-amzn-requestid").is_some(),
            "bedrock error must carry x-amzn-RequestId"
        );
        let errtype = resp
            .headers()
            .get("x-amzn-errortype")
            .and_then(|h| h.to_str().ok());
        assert_eq!(
            errtype,
            Some(crate::proto::error_kind_to_bedrock_type("rate_limit_error")),
            "x-amzn-errortype mirrors the body __type"
        );

        // Non-bedrock ingress: no amzn headers.
        let oai = ingress_error(
            "openai",
            StatusCode::BAD_REQUEST,
            "invalid_request_error",
            "x",
        );
        assert!(
            oai.headers().get("x-amzn-requestid").is_none()
                && oai.headers().get("x-amzn-errortype").is_none(),
            "non-bedrock ingress error must NOT carry x-amzn-* headers"
        );
    }

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
        // OpenAI ingress must NOT receive the anthropic-only `request-id` header.
        assert!(
            oai.headers().get("request-id").is_none(),
            "non-anthropic ingress must not carry an anthropic request-id header"
        );
    }

    /// MEDIUM/conformance (forward.rs:73-101): the anthropic-ingress error `request-id` HEADER equals
    /// the body `request_id`, and non-anthropic ingress carries no such header.
    #[tokio::test]
    async fn test_anthropic_ingress_error_request_id_header_matches_body() {
        use http_body_util::BodyExt as _;
        let resp = ingress_error(
            "anthropic",
            StatusCode::BAD_REQUEST,
            "invalid_request_error",
            "bad json",
        );
        let header_rid = resp
            .headers()
            .get("request-id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .expect("anthropic error must carry a request-id header");
        assert!(
            header_rid.starts_with("req_"),
            "request-id header carries the Anthropic req_ shape; got {header_rid}"
        );
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            v["request_id"].as_str(),
            Some(header_rid.as_str()),
            "the request-id header MUST equal the body request_id so they agree"
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

    /// CLASS regression (forward.rs cross-protocol seam): a Bedrock backend returns an
    /// identity-EMPTY non-stream IR (`read_response` yields `id`/`created`/`model` all `None`, since
    /// a Converse body carries no body-level identity). On a Bedrock→Gemini hop the Gemini writer
    /// gates `usageMetadata.totalTokenCount` and a synthesized `responseId` on the cross-protocol
    /// BOUNDARY signal (`created.is_some() || model.is_some()`); before the seam stamped a synthesized
    /// `created`, that signal never fired for Bedrock and a google-genai client read
    /// `total_token_count`/`response_id` as ABSENT (a token-accounting gap + distinguishability tell).
    /// This asserts both are now present on the translated Gemini body.
    #[tokio::test]
    async fn test_cross_protocol_bedrock_to_gemini_carries_total_tokens_and_response_id() {
        crate::metrics::init();
        let state = Arc::new(MockServerState::new());
        // Native AWS Converse (non-stream) 2xx: NO body-level id/created/model — only output,
        // stopReason, and usage. This is exactly the identity-empty shape the Bedrock reader returns.
        state.push(MockResponse::Ok {
            status: StatusCode::OK,
            body: json!({
                "output": {"message": {"role": "assistant", "content": [{"text": "Hi"}]}},
                "stopReason": "end_turn",
                "usage": {"inputTokens": 7, "outputTokens": 3}
            }),
        });
        let server = MockServer::new(state.clone()).await;
        // Lane speaks Bedrock; ingress is Gemini → cross-protocol translation hop.
        let app = TestApp::new()
            .lane(
                LaneSpec::new(
                    "claude-bedrock",
                    crate::proto::Protocol::bedrock(),
                    &server.base_url(),
                )
                .provider("aws"),
            )
            .pool("pg", &[(0, 1)])
            .build();
        // Native Gemini generateContent (non-stream) request body.
        let body =
            serde_json::to_vec(&json!({"contents": [{"role": "user", "parts": [{"text": "hi"}]}]}))
                .unwrap();
        let resp = forward_with_pool(
            app.clone(),
            vec![crate::state::WeightedLane { idx: 0, weight: 1 }],
            body.into(),
            None,
            "pg",
            None,
            "gemini",
            None,
        )
        .await;
        assert_eq!(resp.status().as_u16(), 200);
        assert_eq!(
            resp.headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json"),
            "non-stream cross-protocol response uses the ingress (Gemini) JSON Content-Type"
        );
        use http_body_util::BodyExt as _;
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        // totalTokenCount = promptTokenCount + candidatesTokenCount (7 + 3); a strict google-genai
        // client reads this for billing/accounting. Absent before the seam fix.
        assert_eq!(
            v["usageMetadata"]["totalTokenCount"],
            json!(10u64),
            "Bedrock→Gemini must carry usageMetadata.totalTokenCount; body: {v}"
        );
        assert_eq!(v["usageMetadata"]["promptTokenCount"], json!(7u64));
        assert_eq!(v["usageMetadata"]["candidatesTokenCount"], json!(3u64));
        // responseId is synthesized (Gemini-shaped, no foreign prefix) so the SDK's
        // GenerateContentResponse.response_id is always populated. Absent before the seam fix.
        let rid = v["responseId"].as_str().unwrap_or("");
        assert!(
            !rid.is_empty(),
            "Bedrock→Gemini must carry a synthesized responseId; body: {v}"
        );
        // No foreign-format identity leaked (Converse has none, but guard the contract anyway).
        let raw = String::from_utf8_lossy(&bytes);
        assert!(
            !raw.contains("chatcmpl-") && !raw.contains("msg_"),
            "no foreign-format id may appear in the Gemini body: {raw}"
        );
        server.shutdown().await;
    }

    /// HIGH/conformance (forward.rs:1539): a Bedrock-INGRESS 2xx (non-stream, cross-protocol) must
    /// carry `x-amzn-RequestId` — a real Converse response always does (the AWS SDK reads it via
    /// `request_id()`); the error path already synthesizes it, this closes the SUCCESS gap.
    #[tokio::test]
    async fn test_bedrock_ingress_success_carries_amzn_request_id() {
        crate::metrics::init();
        let state = Arc::new(MockServerState::new());
        // OpenAI-shaped backend 2xx; ingress is bedrock → cross-protocol translation to Converse.
        state.push(MockResponse::Ok {
            status: StatusCode::OK,
            body: json!({
                "id": "chatcmpl-ok",
                "object": "chat.completion",
                "created": 1234567890,
                "model": "glm-4.5",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "Hi"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 7, "completion_tokens": 3}
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
            .pool("pa", &[(0, 1)])
            .build();
        let body = serde_json::to_vec(
            &json!({"model": "pa", "messages": [{"role": "user", "content": [{"text": "hi"}]}]}),
        )
        .unwrap();
        let resp = forward_with_pool(
            app.clone(),
            vec![crate::state::WeightedLane { idx: 0, weight: 1 }],
            body.into(),
            None,
            "pa",
            None,
            "bedrock",
            None,
        )
        .await;
        assert_eq!(resp.status().as_u16(), 200);
        let amzn = resp
            .headers()
            .get("x-amzn-requestid")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            !amzn.is_empty(),
            "bedrock-ingress 2xx MUST carry a non-empty x-amzn-RequestId (matching a real Converse \
             response and the error path); got: {amzn:?}"
        );
        // UUID-v4 shaped: 36 chars, 8-4-4-4-12.
        assert_eq!(amzn.len(), 36, "x-amzn-RequestId is a UUID; got {amzn}");
        server.shutdown().await;
    }

    /// MEDIUM/conformance (forward.rs:73-101, relay paths): an anthropic-INGRESS 2xx must carry a
    /// `request-id` RESPONSE HEADER — a real Anthropic response always does (the SDK reads it into
    /// `Message._request_id`). On this CROSS-protocol hop (OpenAI backend → Anthropic client) there is
    /// no upstream anthropic id to forward, so busbar must SYNTHESIZE a shape-correct `req_…` one.
    #[tokio::test]
    async fn test_anthropic_ingress_success_carries_request_id_header() {
        crate::metrics::init();
        let state = Arc::new(MockServerState::new());
        state.push(MockResponse::Ok {
            status: StatusCode::OK,
            body: json!({
                "id": "chatcmpl-ok",
                "object": "chat.completion",
                "created": 1234567890,
                "model": "glm-4.5",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "Hi"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 7, "completion_tokens": 3}
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
        let rid = resp
            .headers()
            .get("request-id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            rid.starts_with("req_"),
            "anthropic-ingress 2xx MUST carry a synthesized `request-id` header in the native req_ \
             shape; got {rid:?}"
        );
        server.shutdown().await;
    }

    /// MEDIUM/test-coverage (forward.rs:66-81, STREAMING branch at forward.rs:2377): an anthropic-
    /// INGRESS STREAMING 2xx must ALSO carry the `request-id` response header. The non-streaming test
    /// above exercises only the buffered builder; the streaming builder is a separate code path, so a
    /// regression on the stream branch alone would otherwise pass CI. The official SDK reads
    /// `request-id` into `Message._request_id` on streamed responses too — an absent header is a proxy
    /// tell. Same-protocol anthropic stream (no upstream id supplied by the mock) → synthesized `req_`.
    #[tokio::test]
    async fn test_anthropic_ingress_streaming_carries_request_id_header() {
        crate::metrics::init();
        let state = Arc::new(MockServerState::new());
        // A minimal anthropic-shaped SSE stream (the mock serves `text/event-stream`, driving the
        // streaming branch). The header attachment is independent of the event payloads.
        state.push(MockResponse::Sse {
            events: vec![
                r#"event: message_start
data: {"type":"message_start","message":{"id":"msg_x","role":"assistant","content":[],"usage":{"input_tokens":3,"output_tokens":0}}}"#
                    .to_string(),
                r#"event: message_stop
data: {"type":"message_stop"}"#
                    .to_string(),
            ],
            abort_at_index: None,
        });
        let server = MockServer::new(state.clone()).await;
        let app = TestApp::new()
            .lane(
                LaneSpec::new(
                    "claude-x",
                    crate::proto::Protocol::anthropic(),
                    &server.base_url(),
                )
                .provider("anthropic"),
            )
            .pool("ps", &[(0, 1)])
            .build();
        let body = serde_json::to_vec(&json!({
            "model": "ps",
            "messages": [{"role": "user", "content": "hi"}],
            "max_tokens": 50,
            "stream": true
        }))
        .unwrap();
        let resp = forward_with_pool(
            app.clone(),
            vec![crate::state::WeightedLane { idx: 0, weight: 1 }],
            body.into(),
            None,
            "ps",
            None,
            "anthropic",
            None,
        )
        .await;
        assert_eq!(resp.status().as_u16(), 200);
        let rid = resp
            .headers()
            .get("request-id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            rid.starts_with("req_"),
            "anthropic-ingress STREAMING 2xx MUST carry a `request-id` header in the native req_ \
             shape (forward.rs:2377 path); got {rid:?}"
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

    /// HEADLINE R9 (the unification): the DEGRADED `forward_once` path (LeastBad/FallbackPool) must
    /// NOT leak source-protocol-only passthrough keys onto a foreign backend. Both forward paths now
    /// route request shaping through the single `translate_request_cross_protocol` seam (which clears
    /// `ir.extra` before the egress writer), so the clear cannot be missing on one path. This drives
    /// an OpenAI ingress request carrying `logprobs`/`top_logprobs`/`n` through `forward_once`
    /// (lane in cooldown → LeastBad) to a mock ANTHROPIC lane and asserts none of those keys appear in
    /// the egress body the backend actually received.
    #[tokio::test]
    async fn test_forward_once_cross_protocol_strips_source_only_extra_keys() {
        use crate::store::now as store_now;
        crate::metrics::init();
        let state = Arc::new(MockServerState::new());
        // Anthropic-shaped 2xx so the degraded path serves a success (it relays the body verbatim;
        // we only care about what the backend RECEIVED, captured below).
        state.push(MockResponse::Ok {
            status: StatusCode::OK,
            body: json!({
                "id": "msg_x",
                "type": "message",
                "role": "assistant",
                "content": [{"type": "text", "text": "hi"}],
                "model": "claude-3",
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 3, "output_tokens": 2}
            }),
        });
        let server = MockServer::new(state.clone()).await;
        let t0 = store_now();
        // Lane speaks ANTHROPIC; ingress is OpenAI → cross-protocol. Lane in long cooldown so normal
        // selection finds nothing and LeastBad serves via forward_once (the degraded path).
        let app = TestApp::new()
            .lane(
                LaneSpec::new(
                    "claude-3",
                    crate::proto::Protocol::anthropic(),
                    &server.base_url(),
                )
                .provider("anthropic")
                .cooldown_until(t0 + 600)
                .streak(3)
                .err(5),
            )
            .pool("leastbad", &[(0, 1)])
            .on_exhausted("leastbad", crate::config::OnExhausted::LeastBad)
            .build();

        let req_body = serde_json::to_vec(&json!({
            "model": "leastbad",
            "messages": [{"role": "user", "content": "hi"}],
            "max_tokens": 16,
            "logprobs": true,
            "top_logprobs": 5,
            "n": 3
        }))
        .unwrap();
        let resp = forward_with_pool(
            app.clone(),
            vec![crate::state::WeightedLane { idx: 0, weight: 1 }],
            req_body.into(),
            None,
            "leastbad",
            None,
            "openai",
            None,
        )
        .await;
        assert_eq!(resp.status().as_u16(), 200, "LeastBad serves the 2xx");

        // The egress body the Anthropic backend ACTUALLY received: the OpenAI-only passthrough keys
        // must be absent (cleared at the shared translate seam), proving the degraded path no longer
        // diverges from the hot path.
        let egress = state
            .get_last_request_body()
            .expect("backend received a request body");
        let ev: Value = serde_json::from_slice(&egress).expect("egress body is JSON");
        let obj = ev.as_object().expect("egress body is an object");
        assert!(
            !obj.contains_key("logprobs"),
            "forward_once must NOT leak OpenAI `logprobs` onto an Anthropic backend: {ev}"
        );
        assert!(
            !obj.contains_key("top_logprobs"),
            "forward_once must NOT leak OpenAI `top_logprobs`: {ev}"
        );
        assert!(
            !obj.contains_key("n"),
            "forward_once must NOT leak OpenAI `n`: {ev}"
        );
        // Modeled fields still translated across.
        assert!(obj.contains_key("messages"), "messages translated: {ev}");
        server.shutdown().await;
    }

    /// HIGH/conformance (R9, forward.rs error sites): no forward-layer error body returned to a client
    /// may begin with the wire-visible internal `router:` prefix — a deterministic proxy tell no native
    /// endpoint emits. The route-layer regression test never reaches the forward layer; this drives the
    /// most-exercised forward-layer error surfaces (overload 503 via empty-pool exhaustion, and the
    /// Status503 retry body) for every ingress protocol and asserts the body is free of `router:`.
    #[tokio::test]
    async fn test_forward_layer_errors_carry_no_router_prefix() {
        use http_body_util::BodyExt as _;
        crate::metrics::init();
        for ingress in [
            "openai",
            "anthropic",
            "gemini",
            "cohere",
            "responses",
            "bedrock",
        ] {
            let app = TestApp::new().build();
            // Empty candidate pool → "no usable lane" / Status503 overload 503 through the forward
            // layer (forward_with_pool → handle_exhaustion_for_pool → handle_status_503).
            let resp = forward_with_pool(
                app.clone(),
                vec![],
                serde_json::to_vec(&json!({"model": "x", "messages": []}))
                    .unwrap()
                    .into(),
                None,
                "missingpool",
                None,
                ingress,
                None,
            )
            .await;
            let status = resp.status().as_u16();
            let bytes = resp.into_body().collect().await.unwrap().to_bytes();
            let body = String::from_utf8_lossy(&bytes);
            assert!(
                !body.contains("router:"),
                "forward-layer error body for ingress {ingress} (status {status}) leaked the \
                 `router:` tell: {body}"
            );
        }
    }

    /// HIGH/test-coverage (R9, forward.rs:2004 area): a native AWS SDK ConverseStream request answered
    /// by a buffered (non-SSE) `application/json` 2xx from a CROSS-protocol OpenAI lane must be emitted
    /// at the HTTP boundary as `application/vnd.amazon.eventstream`, decode into the native frame
    /// sequence, AND carry a UUID `x-amzn-RequestId`. The existing coverage tests only the synthesis
    /// fn directly; this asserts the response-builder wiring (CT, frames, amzn id) on a real Response.
    #[tokio::test]
    async fn test_bedrock_converse_stream_buffered_cross_protocol_emits_binary_eventstream() {
        use http_body_util::BodyExt as _;
        crate::metrics::init();
        let state = Arc::new(MockServerState::new());
        // NON-SSE buffered OpenAI 2xx (no SSE) to a cross-protocol bedrock-ingress ConverseStream.
        state.push(MockResponse::Ok {
            status: StatusCode::OK,
            body: json!({
                "id": "chatcmpl-buf",
                "object": "chat.completion",
                "created": 1234567890,
                "model": "glm-4.5",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "Hi"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 7, "completion_tokens": 3}
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
            .pool("pb", &[(0, 1)])
            .build();
        // `stream: true` → bedrock ConverseStream intent; cross-protocol to an OpenAI lane that
        // answers with a buffered (non-SSE) body → bedrock_response_to_eventstream synthesis path.
        let body = serde_json::to_vec(&json!({
            "model": "pb",
            "messages": [{"role": "user", "content": [{"text": "hi"}]}],
            "stream": true
        }))
        .unwrap();
        let resp = forward_with_pool(
            app.clone(),
            vec![crate::state::WeightedLane { idx: 0, weight: 1 }],
            body.into(),
            None,
            "pb",
            None,
            "bedrock",
            None,
        )
        .await;
        assert_eq!(resp.status().as_u16(), 200);
        // (a) Content-Type is the native binary eventstream CT.
        assert_eq!(
            resp.headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/vnd.amazon.eventstream"),
            "buffered cross-protocol ConverseStream must be the native binary CT, not application/json"
        );
        // (c) UUID-v4 x-amzn-RequestId present.
        let amzn = resp
            .headers()
            .get("x-amzn-requestid")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        assert_eq!(amzn.len(), 36, "x-amzn-RequestId is a UUID; got {amzn:?}");
        // (b) body decodes into the native frame sequence.
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let mut buf = bytes.to_vec();
        let frames = crate::eventstream::drain_frames(&mut buf);
        let names: Vec<&str> = frames.iter().map(|(t, _)| t.as_str()).collect();
        assert_eq!(names.first(), Some(&"messageStart"), "frames: {names:?}");
        assert!(names.contains(&"contentBlockDelta"), "frames: {names:?}");
        assert!(names.contains(&"messageStop"), "frames: {names:?}");
        assert!(names.contains(&"metadata"), "frames: {names:?}");
        server.shutdown().await;
    }
}
