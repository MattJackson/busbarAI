// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::{
    body::Body,
    http::header::{ACCEPT, CONTENT_TYPE, USER_AGENT},
    response::IntoResponse,
    response::Response,
};
use bytes::Bytes;
use futures::Stream;
use reqwest::StatusCode;
use serde_json::Value;

use crate::breaker::{classify as classify_disposition, normalize_raw_error, Disposition};
use crate::config::OnExhausted;
use crate::proto::{
    convert_headers, openai_family, StatusClass, PROTO_BEDROCK, PROTO_GEMINI, PROTO_RESPONSES,
};
use crate::state::{App, WeightedLane};
use crate::store::{now, Permit};

// NOTE: cross-protocol max-tokens defaulting lives in `IrReq::prepare_for_egress` — the IR owns its
// cross-protocol semantics; the engine is operation-blind. Precedence unit tests drive the IR method.

/// The two `x-busbar-*` TRANSPARENCY response headers stamped when a non-default routing policy
/// chose the target lane: the policy name and the chosen lane's model. Hoisted to consts so the
/// emit site and any future readers cannot drift on spelling.
const HDR_ROUTE_POLICY: &str = "x-busbar-route-policy";
const HDR_ROUTE_TARGET: &str = "x-busbar-route-target";

/// The `application/json` media type — the default `Content-Type`/`Accept` for the JSON REST
/// surfaces. Hoisted to one const so the literal isn't repeated across egress/health/observability.
pub(crate) const APPLICATION_JSON: &str = "application/json";

/// Streaming MIME type for SSE (Server-Sent Events) responses — the `Content-Type` value that
/// signals an open event-stream to the client. Placed next to `APPLICATION_JSON` so all
/// protocol-boundary content-types are declared in one spot.
pub(crate) const TEXT_EVENT_STREAM: &str = "text/event-stream";

/// Canonical error-KIND tokens: produced by `cross_protocol_error_kind` / passed to
/// `ingress_error` as the `kind` argument. Each string is the protocol-agnostic discriminant that
/// the per-protocol writer maps to its native error category (e.g. Bedrock `__type`, Gemini
/// `error.status`). Values shared with the OpenAI-family/anthropic/admin vocabularies alias their
/// canonical home in `proto::openai_family`; only the two forward-specific tokens (`overloaded`,
/// `timeout`) are defined here.
pub(crate) const KIND_AUTHENTICATION: &str = openai_family::ERR_TYPE_AUTHENTICATION;
pub(crate) const KIND_PERMISSION: &str = openai_family::ERR_TYPE_PERMISSION;
pub(crate) const KIND_RATE_LIMIT: &str = openai_family::ERR_TYPE_RATE_LIMIT;
pub(crate) const KIND_INVALID_REQUEST: &str = openai_family::ERR_TYPE_INVALID_REQUEST;
pub(crate) const KIND_NOT_FOUND: &str = openai_family::ERR_TYPE_NOT_FOUND;
pub(crate) const KIND_API_ERROR: &str = openai_family::ERR_TYPE_API_ERROR;
/// Bare `overloaded` — DELIBERATELY distinct from `openai_family::ERR_TYPE_OVERLOADED`
/// ("overloaded_error", the Anthropic wire spelling): this is busbar's own agnostic kind for a
/// relayed upstream 503.
pub(crate) const KIND_OVERLOADED: &str = "overloaded";
/// Bare `timeout` — distinct from the Anthropic wire's `timeout_error` spelling.
pub(crate) const KIND_TIMEOUT: &str = "timeout";
pub(crate) const KIND_INSUFFICIENT_QUOTA: &str = openai_family::ERR_TYPE_INSUFFICIENT_QUOTA;
pub(crate) const KIND_SERVER_ERROR: &str = openai_family::ERR_TYPE_SERVER_ERROR;
pub(crate) const KIND_REQUEST_TOO_LARGE: &str = openai_family::ERR_TYPE_REQUEST_TOO_LARGE;

/// Network-transient `err_type` values passed to `record_transient_in`.  These are distinct from
/// the error-KIND tokens above: they label the *category* of network failure recorded in the
/// breaker store, not the protocol-level error kind surfaced to the caller.
const ERR_NET_CONNECT: &str = "connect";
const ERR_NET_TIMEOUT: &str = "timeout";
const ERR_NET_TRANSPORT: &str = "transport";
/// `err_type` recorded when a HalfOpen probe's degraded forward returns a non-2xx (bumps cooldown).
const ERR_DEGRADED_NON2XX: &str = "degraded-non2xx";

/// Metric-label values for the `disposition` dimension on `UPSTREAM_FAILURES_TOTAL` and the
/// `reason` dimension on `FAILOVERS_TOTAL`.
const DISPOSITION_TRANSIENT: &str = "transient_upstream";
/// A single attempt's budget-clamped transport timeout fired (retryable within the request).
const DISPOSITION_ATTEMPT_TIMEOUT: &str = "attempt_timeout";
const DISPOSITION_HARD_DOWN: &str = "hard_down";
const DISPOSITION_CONTEXT_LENGTH: &str = "context_length";

/// Bounded `pool` metric-label sentinel used for every pre-routing failure (malformed body,
/// unresolved model, governance rejection) so the label space stays finite (metrics.rs).
pub(crate) const POOL_LABEL_UNRESOLVED: &str = "unresolved";

/// Provider error-code token emitted when a request exceeds the model's context-window limit.
/// Returned by `client_fault_kind` for `StatusClass::ContextLength` and drives the per-protocol
/// writer to emit the native context-length error category.
pub(crate) const PROVIDER_CODE_CONTEXT_LENGTH: &str = "context_length_exceeded";

tokio::task_local! {
    /// Per-request slot the `server_timing` middleware reads to compute Busbar's INTERNAL
    /// processing time (= total request wall-clock − upstream round-trip), reported as a
    /// `Server-Timing: busbar;dur=<ms>` response header. Set via `.scope()` by the middleware;
    /// written by `record_upstream_rtt` when an upstream call returns. Microseconds; the
    /// `u64::MAX` sentinel means "no upstream hop on this request" (admin/health/early error),
    /// in which case the middleware reports the full request time.
    pub(crate) static UPSTREAM_RTT_US: std::sync::Arc<std::sync::atomic::AtomicU64>;
}

/// Record the upstream round-trip (to response headers) for the current request so the
/// `server_timing` middleware can subtract it from the total and report Busbar's own added latency.
/// On failover the LAST attempt's value wins (recorded after every `send`, before success/error
/// classification) — so a success overwrites a prior failed hop; on an all-hops-fail exhaustion the
/// last failed hop's (typically short) RTT is what remains, which can mildly inflate the reported
/// `busbar;dur` on that error response. Telemetry only; never affects translation. No-op outside the
/// unit tests and the admin/health routes that never dispatch upstream simply don't record one.
fn record_upstream_rtt(rtt: std::time::Duration) {
    let us = u64::try_from(rtt.as_micros()).unwrap_or(u64::MAX);
    let _ = UPSTREAM_RTT_US.try_with(|slot| slot.store(us, std::sync::atomic::Ordering::Relaxed));
}

/// Attach the protocol's request-id RESPONSE HEADER to a SUCCESS / relay response builder, dispatched
/// through `ProtocolWriter::ingress_response_request_id` so the agnostic forward path names no
/// protocol module for request-id synthesis. A genuine Bedrock 2xx ALWAYS carries `x-amzn-RequestId`
/// (the SDK surfaces it via `*Output::request_id()`); a genuine Anthropic response ALWAYS carries
/// `request-id` (the official SDK reads it into `APIError.request_id` / `Message._request_id`, NOT the
/// body). Omitting either makes the SDK's id `None` — impossible against the real API and a
/// deterministic proxy tell. The writer forwards the captured UPSTREAM id verbatim on a same-protocol
/// passthrough and synthesizes otherwise; protocols that emit no such header return `None` (no-op).
/// Best-effort: if synthesis (entropy) fails the header is simply omitted (never panics on the request
/// path).
fn maybe_attach_response_request_id(
    rb: axum::http::response::Builder,
    ingress_protocol: &str,
    upstream_request_id: Option<&str>,
) -> axum::http::response::Builder {
    match crate::proto::protocol_for(ingress_protocol)
        .and_then(|p| p.writer().ingress_response_request_id(upstream_request_id))
    {
        Some((name, id)) => rb.header(name, id),
        None => rb,
    }
}

/// True when `ingress_protocol`'s writer signals that EVERY response — 2xx, streaming, and error —
/// must carry `x-amzn-RequestId` (and, on error paths, `x-amzn-errortype`). Dispatches through the
/// `ProtocolWriter::ingress_relays_amzn_headers()` vtable instead of branching on the provider name
/// `"bedrock"`, so the agnostic forward path never contains a hard-coded protocol string for this
/// decision. Unknown protocols fall back to `false` (no `x-amzn-*` headers emitted).
fn ingress_relays_amzn_headers(ingress_protocol: &str) -> bool {
    crate::proto::protocol_for(ingress_protocol)
        .map(|p| p.writer().ingress_relays_amzn_headers())
        .unwrap_or(false)
}

/// The UPSTREAM response header NAMES this ingress protocol forwards VERBATIM on a same-protocol
/// passthrough — read from the upstream response and re-emitted on the client response (Bedrock's
/// `x-amzn-requestid` + `x-amzn-errortype`; Anthropic's `request-id`). Dispatched through the
/// `ProtocolWriter::ingress_relayed_response_header_names()` vtable so the agnostic forward path reads
/// and forwards these by NAME without naming any protocol module. Unknown protocols: `&[]`.
fn ingress_relayed_response_header_names(ingress_protocol: &str) -> &'static [&'static str] {
    crate::proto::protocol_for(ingress_protocol)
        .map(|p| p.writer().ingress_relayed_response_header_names())
        .unwrap_or(&[])
}

/// TRANSPARENCY: stamp which routing POLICY chose which TARGET onto a successful response, mirroring
/// the `x-busbar-*` header convention (e.g. the bedrock/anthropic request-id headers above):
/// `x-busbar-route-policy: <policy name>` and `x-busbar-route-target: <chosen lane model>`. Emitted
/// ONLY when a non-default policy actually produced the order (`policy_name == Some`); a default
/// `route: weighted` pool (or a policy that Abstained → SWRR) attaches NOTHING, so the zero-cost path
/// adds no header. Both values are bounded, operator-defined strings (a fixed policy enumeration + a
/// configured model name), never request-derived data.
fn maybe_attach_route_policy(
    rb: axum::http::response::Builder,
    policy_name: Option<&'static str>,
    target_model: &str,
) -> axum::http::response::Builder {
    match policy_name {
        Some(name) => rb
            .header(HDR_ROUTE_POLICY, name)
            .header(HDR_ROUTE_TARGET, target_model),
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
/// protocol-appropriate headers (Bedrock `x-amzn-RequestId` / `x-amzn-errortype` via the
/// `ProtocolWriter::attach_error_response_headers` vtable method (BedrockWriter delegates to its
/// private helper); Gemini code/status ride the body envelope the writer builds). `route.rs::ingress_error` and `auth.rs::unauthorized_response` now both DELEGATE to THIS
/// function (the migration is complete — they hold no private copies), so the degraded path, the main
/// path, and the auth/route paths cannot diverge on error shape or headers.
pub(crate) fn ingress_error(ingress: &str, status: StatusCode, kind: &str, msg: &str) -> Response {
    // Resolve the ingress protocol's vtable ONCE (fall back to OpenAI's generic envelope for an
    // unknown name — unreachable for the 6 validated ingress protocols). All provider-specific error
    // shape (the body envelope AND any response headers) flows through trait methods on this writer,
    // so the agnostic error path carries no `if ingress == "<name>"` branch.
    let protocol =
        crate::proto::protocol_for(ingress).unwrap_or_else(crate::proto::Protocol::openai);
    let envelope = protocol.writer().write_error(status.as_u16(), kind, msg);
    let body = crate::json::to_string(&envelope).unwrap_or_else(|_| {
        // Envelope is built from serde_json::json! values and always serializes; this fallback only
        // exists to avoid an unwrap on the request path. Build it with `json!` (correct JSON string
        // escaping) rather than interpolating Rust `{:?}` Debug formatting, which is NOT guaranteed
        // valid JSON escaping for all inputs (e.g. it differs on `/` and some control sequences).
        serde_json::json!({ "error": { "message": msg, "type": kind } }).to_string()
    });
    let mut resp = Response::builder()
        .status(status)
        .header(CONTENT_TYPE, APPLICATION_JSON)
        .body(Body::from(body))
        .unwrap_or_else(|_| status.into_response());
    // Provider-specific error RESPONSE HEADERS (Bedrock `x-amzn-RequestId`/`x-amzn-errortype`;
    // Anthropic `request-id` mirrored from the body) — dispatched via the writer vtable so the main,
    // degraded, auth, and route error paths cannot drift on header shape.
    protocol
        .writer()
        .attach_error_response_headers(resp.headers_mut(), kind, &envelope);
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
        KIND_AUTHENTICATION
    } else if status == StatusCode::FORBIDDEN {
        KIND_PERMISSION
    } else if status == StatusCode::TOO_MANY_REQUESTS {
        KIND_RATE_LIMIT
    } else if status == StatusCode::SERVICE_UNAVAILABLE {
        // A genuine upstream 503 carries the unavailable/overloaded distinction — collapsing it into
        // `api_error` would emit, on a bedrock ingress, the status(503)/InternalServerException
        // pairing the real AWS runtime NEVER produces (503 pairs with ServiceUnavailableException).
        // Use `overloaded` — the SAME kind busbar already uses for its OWN 503s, mapping to
        // ServiceUnavailableException (bedrock) / UNAVAILABLE (gemini).
        KIND_OVERLOADED
    } else if status == StatusCode::GATEWAY_TIMEOUT {
        // 504 maps to the timeout class (bedrock ModelTimeoutException), not a generic server error.
        KIND_TIMEOUT
    } else if status.is_server_error() {
        KIND_API_ERROR
    } else {
        KIND_INVALID_REQUEST
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
///
/// Returns whether the body actually CHANGED (a key was present and removed). This is invalidation
/// set entries #1 (gemini JSON-array key) and #2 (`stream` for path-model egress) of the request
/// short-circuit safety contract: a `true` here makes a same-protocol request NON-pristine. A
/// same-proto request that carries NEITHER of these keys is left byte-for-byte untouched and can
/// short-circuit to its retained original bytes.
fn strip_router_shim_keys(v: &mut Value, egress_protocol: &str) -> bool {
    let mut changed = false;
    if let Some(obj) = v.as_object_mut() {
        // A protocol's array-stream shim key is never native to ANY backend wire → strip every
        // registered protocol's key unconditionally (also closes the leak where a body-model client
        // smuggles a key in its own controlled body). Iterating the cached registry set keeps this
        // strip from naming any shim-key literal (and from re-sweeping `protocol_for` per request).
        // `remove` returns the previous value iff the key was present → a real mutation (#1).
        for &key in crate::proto::array_stream_shim_keys() {
            if obj.remove(key).is_some() {
                changed = true;
            }
        }
        // `stream` is a path-model shim for the EGRESS protocols gemini/bedrock (stream intent and
        // model both ride the URL there; `has_model_in_url()` covers both). For body-model egress
        // `stream` is the writer-authored field the backend needs to start streaming, so it must be
        // PRESERVED. Gate on egress, never ingress.
        if crate::proto::protocol_for(egress_protocol)
            .map(|p| p.writer().has_model_in_url())
            .unwrap_or(false)
            && obj.remove("stream").is_some()
        {
            // #2: `stream` was present AND the egress is path-model → real mutation.
            changed = true;
        }
    }
    changed
}

/// Remove the SHIM `model` key on the SAME-PROTOCOL gemini/bedrock passthrough path, AFTER
/// `rewrite_model` has run. On same-protocol gemini/bedrock the model rides the URL, not the body, so
/// a native Converse / generateContent backend must NOT see a body `model`; but the gemini writer's
/// `rewrite_model` re-inserts one, so this strip must run AFTER it to remove both the route layer's
/// shim and the re-inserted copy. NEVER call this on the cross-protocol branch: there the body-model
/// egress requires the `model` that `rewrite_model` installed. No-op for body-model ingress.
///
/// Thin wrapper: dispatches through `ProtocolWriter::has_model_in_url` so the per-protocol decision
/// (gemini/bedrock → strip; all others → keep) lives in the writer vtable, not in this agnostic
/// function. An unknown future url-model protocol only needs an override in its writer.
///
/// Returns whether the body actually CHANGED (a `model` key was present and removed). This is
/// invalidation set entry #4 of the request short-circuit safety contract: on a same-protocol
/// gemini/bedrock passthrough a body that carried `model` is made NON-pristine (the retained
/// original carries a `model` the native backend must not see). A same-proto path-model request that
/// arrived without a body `model` is left untouched and stays pristine.
fn strip_same_protocol_model_shim(v: &mut Value, ingress_protocol: &str) -> bool {
    let model_in_url = crate::proto::protocol_for(ingress_protocol)
        .map(|p| p.writer().has_model_in_url())
        .unwrap_or(false);
    if model_in_url {
        if let Some(obj) = v.as_object_mut() {
            return obj.remove("model").is_some();
        }
    }
    false
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
///   1. CROSS-protocol only (`ingress_protocol != egress`): read_request → `IrReq::prepare_for_egress`
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
#[allow(clippy::too_many_arguments)]
fn translate_request_cross_protocol(
    app: &Arc<App>,
    i: usize,
    ingress_protocol: &str,
    op: crate::handlers::Op,
    body: Option<Value>,
    req_content_type: &str,
    // The EFFECTIVE per-lane reasoning capability for this attempt (pool-member override wins over
    // the model flag) — computed by the caller because only it holds the candidate rows. Gates the
    // reasoning ask at `prepare_for_egress`; see `ModelCfg::reasoning`.
    reasoning_allowed: bool,
    // The PRISTINE source bytes `body` was parsed from THIS hop (the retained original). On a
    // same-protocol passthrough where no same-proto-reachable mutation fired (the request short-
    // circuit, Change B step 1), these exact bytes are re-emitted verbatim instead of re-serializing
    // the `Value` — keeping the upstream payload byte-identical and skipping the serialize hot spot.
    hop_bytes: &[u8],
) -> Result<Vec<u8>, Box<Response>> {
    let egress_name = app.lanes[i].protocol.name();
    // OPAQUE ingress body (multipart/binary — `None`): translate at the BYTE level through the
    // operation codecs (cross-protocol) or relay the pristine bytes verbatim (same-protocol) —
    // exactly the contract the JSON branch below implements at the Value level.
    let Some(mut body) = body else {
        if ingress_protocol != egress_name {
            let ingress_handler = crate::handlers::request_handler(ingress_protocol)
                .and_then(|rh| rh.operation_handler(op.operation));
            let egress_handler = crate::handlers::request_handler(egress_name)
                .and_then(|rh| rh.operation_handler(op.operation));
            let (Some(ih), Some(eh)) = (ingress_handler, egress_handler) else {
                return Err(Box::new(ingress_error(
                    ingress_protocol,
                    StatusCode::NOT_FOUND,
                    KIND_NOT_FOUND,
                    DETAIL_MODEL_UNSUPPORTED_OPERATION,
                )));
            };
            let mut ir_req = match ih.read_request(hop_bytes, req_content_type) {
                Ok(ir) => ir,
                Err(_) => {
                    return Err(Box::new(ingress_error(
                        ingress_protocol,
                        StatusCode::BAD_REQUEST,
                        KIND_INVALID_REQUEST,
                        "We could not process the content of your request.",
                    )))
                }
            };
            ir_req.prepare_for_egress(&crate::ir::variant::EgressPrep {
                ingress_protocol,
                egress_requires_max_tokens: app.lanes[i].protocol.writer().requires_max_tokens(),
                lane_default_max_tokens: app.lanes[i].default_max_tokens,
                global_default_max_tokens: app.default_max_tokens,
                reasoning_allowed,
                reasoning_budgets: app.reasoning_effort_budgets,
                // The cache twin of `reasoning_allowed`: a lane whose writer's cache marker is
                // model-gated (Bedrock) must assert `prompt_caching` to receive breakpoints.
                prompt_caching_allowed: app.lanes[i].prompt_caching
                    || !app.lanes[i].protocol.writer().cache_markers_model_gated(),
            });
            ir_req.set_model(app.lanes[i].wire_model());
            return Ok(eh.write_request(&ir_req).to_vec());
        }
        return Ok(hop_bytes.to_vec());
    };
    // Request short-circuit pristine-tracking (Change B). Starts true; flips false the moment ANY
    // same-protocol-reachable mutation actually changes the body. The cross-protocol branch below
    // always rebuilds the body from the IR (read_request → write_request), so it is never pristine.
    // The invalidation contract is EXACTLY entries #1-#4 of the design table — strip_router_shim_keys
    // (#1,#2), rewrite_model_if_needed (#3), strip_same_protocol_model_shim (#4) — each of which now
    // reports whether it truly changed the body.
    let mut pristine = true;
    if ingress_protocol != egress_name {
        // one cross-protocol translation hop for this request.
        metrics::counter!(
            crate::metrics::TRANSLATIONS_TOTAL,
            "from" => ingress_protocol.to_string(),
            "to" => egress_name.to_string()
        )
        .increment(1);
        // Cross-protocol: translate the request body through the superset IR.
        let Some(_ingress_proto) = crate::proto::protocol_for(ingress_protocol) else {
            return Err(Box::new(ingress_error(
                ingress_protocol,
                StatusCode::BAD_REQUEST,
                KIND_INVALID_REQUEST,
                DETAIL_INTERNAL_ERROR,
            )));
        };
        // OPERATION-BLIND translate: the INGRESS operation handler parses its dialect into the
        // neutral IR; the IR applies its own cross-protocol semantics (`prepare_for_egress` — chat's
        // max-tokens default, tool-id decode, and the §8.2 extra-key leak guard live INSIDE the IR,
        // not here); the EGRESS handler writes its dialect. The engine names no operation.
        // Codec roles resolve from PROTOCOL IDENTITY, not from the threaded handle: the ingress
        // dialect is (ingress_protocol, operation)'s handler; the egress dialect is the lane's.
        // (`op` supplies the operation tag + capabilities; its instance is registry-identical to
        // this lookup on every production path.)
        let ingress_handler = crate::handlers::request_handler(ingress_protocol)
            .and_then(|rh| rh.operation_handler(op.operation));
        let egress_handler = crate::handlers::request_handler(egress_name)
            .and_then(|rh| rh.operation_handler(op.operation));
        let Some(ingress_handler) = ingress_handler else {
            return Err(Box::new(ingress_error(
                ingress_protocol,
                StatusCode::NOT_FOUND,
                KIND_NOT_FOUND,
                DETAIL_ENDPOINT_UNSUPPORTED_OPERATION,
            )));
        };
        match ingress_handler.read_request_value(&body) {
            Ok(mut ir_req) => {
                ir_req.prepare_for_egress(&crate::ir::variant::EgressPrep {
                    ingress_protocol,
                    egress_requires_max_tokens: app.lanes[i]
                        .protocol
                        .writer()
                        .requires_max_tokens(),
                    lane_default_max_tokens: app.lanes[i].default_max_tokens,
                    global_default_max_tokens: app.default_max_tokens,
                    reasoning_allowed,
                    reasoning_budgets: app.reasoning_effort_budgets,
                    prompt_caching_allowed: app.lanes[i].prompt_caching
                        || !app.lanes[i].protocol.writer().cache_markers_model_gated(),
                });
                let Some(eh) = egress_handler else {
                    return Err(Box::new(ingress_error(
                        ingress_protocol,
                        StatusCode::NOT_FOUND,
                        KIND_NOT_FOUND,
                        DETAIL_MODEL_UNSUPPORTED_OPERATION,
                    )));
                };
                match eh.write_request_value(&ir_req) {
                    Some(written) => body = written,
                    None => {
                        // The EGRESS wire is not JSON (multipart transcription): the IR carries the
                        // resolved model in-band, and the JSON-only post-shaping below (shim strips,
                        // model rewrite) does not apply — emit the handler's bytes directly.
                        ir_req.set_model(app.lanes[i].wire_model());
                        return Ok(eh.write_request(&ir_req).to_vec());
                    }
                }
                // The body was fully rebuilt from the IR (read_request → write_request), so it bears
                // no fixed relationship to `hop_bytes` — a cross-protocol hop is NEVER pristine and
                // must serialize the rewritten `Value`, never short-circuit to the original bytes.
                pristine = false;
            }
            Err(_) => {
                return Err(Box::new(ingress_error(
                    ingress_protocol,
                    StatusCode::BAD_REQUEST,
                    KIND_INVALID_REQUEST,
                    "We could not process the content of your request.",
                )));
            }
        }
    }
    // Remove the never-native shim keys (gemini JSON-array key on every protocol; `stream` for
    // path-model EGRESS) on EVERY branch — same- AND cross-protocol. `model` is handled below,
    // ordered relative to `rewrite_model`. Each helper reports whether it ACTUALLY changed the body;
    // any true makes a same-protocol hop non-pristine (`&` accumulates into `pristine`). This is the
    // structural coupling: a future same-proto-reachable mutation added to these helpers automatically
    // invalidates the short-circuit (it cannot be silently missed).
    pristine &= !strip_router_shim_keys(&mut body, egress_name); // invalidators #1, #2
                                                                 // `rewrite_model_if_needed` installs the authoritative lane model. ORDERING (critical): on a
                                                                 // cross-protocol hop to a BODY-MODEL egress (gemini/bedrock → openai/anthropic/cohere/responses)
                                                                 // the backend REQUIRES this `model` body field, so `model` is stripped ONLY on the same-protocol
                                                                 // passthrough (below), where the model rides the URL and a body `model` is an indistinguishability
                                                                 // leak. Reports a change only when the written model differs from the body's existing one (#3).
    pristine &= !app.lanes[i]
        .protocol
        .writer()
        .rewrite_model_if_needed(&mut body, app.lanes[i].wire_model()); // invalidator #3
    if ingress_protocol == egress_name {
        pristine &= !strip_same_protocol_model_shim(&mut body, ingress_protocol);
        // invalidator #4
    }
    // Request SHORT-CIRCUIT (Change B step 1): a same-protocol passthrough that triggered none of the
    // invalidators #1-#4 left `body` byte-for-byte equivalent to the retained `hop_bytes`, so re-emit
    // those exact bytes verbatim — byte-identical to the old re-serialize path, minus the serialize
    // cost (and minus any key-ordering / float-formatting drift a round-trip could introduce). Cross-
    // protocol hops set `pristine = false` above and always fall through to the serialize arm.
    if ingress_protocol == egress_name && pristine {
        return Ok(hop_bytes.to_vec());
    }
    // sonic-rs: SIMD serialize of the (large, string-heavy) upstream body — the request-path hot spot.
    match crate::json::to_vec(&body) {
        Ok(p) => Ok(p),
        // Re-serializing a Value parsed from valid JSON and rewritten only with serde_json values is
        // effectively infallible; return a shaped 500 rather than panic a worker on the request path
        // (the layer's no-unwrap/expect rule).
        Err(_) => Err(Box::new(ingress_error(
            ingress_protocol,
            StatusCode::INTERNAL_SERVER_ERROR,
            KIND_API_ERROR,
            DETAIL_INTERNAL_ERROR,
        ))),
    }
}

/// Upper bound on a buffered UPSTREAM ERROR body (4xx/5xx envelopes). Any error envelope is far
/// smaller than this; the cap stops a hostile or misconfigured upstream from forcing an unbounded
/// heap allocation per in-flight non-2xx response (the inbound request body is already capped
/// separately). This is the TIGHT cap — it is deliberately NOT reused for buffering a legitimate
/// cross-protocol 2xx completion (see [`max_translated_body_bytes`]).
///
/// Operator-tunable via `limits.upstream_error_body_max_bytes` (defaults to 256 KiB). A function (not
/// a `const`) so the process-wide installed value is read at each use site; falls back to the
/// historical default when the limits aren't installed (e.g. unit tests).
fn max_upstream_buffered_bytes() -> usize {
    crate::limits::upstream_error_body_max_bytes()
}

/// Upper bound on a buffered cross-protocol non-stream SUCCESS (2xx) body that must be parsed and
/// translated egress→IR→ingress. A real completion (large `max_tokens` output, big tool-call
/// arguments, embedded content) can far exceed the tight error-body cap; truncating it would make
/// `serde_json` parsing fail and the request would be reported to the client as a spurious 500 for
/// what was actually an upstream success (the caller may even have been token-charged). This cap is
/// COUPLED with the inbound request-body limit so any completion the gateway would accept inbound
/// can also be buffered for translation, while still bounding the per-response allocation. ONE knob
/// (`limits.request_body_max_bytes`) drives BOTH the inbound `DefaultBodyLimit` and this egress cap
/// (`crate::limits::translate_body_max_bytes` returns the same value), so they can never diverge.
/// A function (not a `const`) so the installed value is read at each use site; falls back to the
/// historical 32 MiB default when the limits aren't installed (e.g. unit tests).
fn max_translated_body_bytes() -> usize {
    crate::limits::translate_body_max_bytes()
}

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
    // Pre-reserve a BOUNDED initial capacity so the per-chunk `extend_from_slice` below does not
    // reallocate-and-copy the buffer through a geometric growth series as it climbs toward `cap`.
    // Bounded two ways so this never becomes an allocation-amplification lever: (a) capped at `cap`
    // itself (the 256 KiB upstream-buffer cap, or 32 MiB translate cap — never larger), and (b)
    // ceilinged at `READ_CAPPED_RESERVE_CEILING` so a 32 MiB-cap read does not eagerly commit 32 MiB
    // for a response that is, in practice, a few KiB. The cap ENFORCEMENT is unchanged — `cap` still
    // bounds every write below and an over-cap body is still rejected/Truncated; this only changes the
    // starting allocation, never how many bytes are admitted.
    const READ_CAPPED_RESERVE_CEILING: usize = 64 * 1024;
    let mut buf: Vec<u8> = Vec::with_capacity(cap.min(READ_CAPPED_RESERVE_CEILING));
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

/// Read an upstream ERROR / verbatim-relay body under the tight [`max_upstream_buffered_bytes()`] cap.
/// A truncated error body still classifies/relays correctly (error envelopes are well under the cap,
/// and a body that overruns it can only be malformed/hostile), so the truncation flag is discarded.
async fn read_capped_body(r: reqwest::Response) -> Bytes {
    read_capped(r, max_upstream_buffered_bytes()).await.0
}

/// Map the classified `StatusClass` of a CLIENT-fault upstream 4xx to a protocol-agnostic error
/// `kind` for `ingress_error` (the per-protocol writer maps it to its native error type/category).
/// Exhaustive over `StatusClass` — no `_` wildcard (the no-catch-all rule for disposition matches).
fn client_fault_kind(class: StatusClass) -> &'static str {
    match class {
        StatusClass::ContextLength => PROVIDER_CODE_CONTEXT_LENGTH,
        StatusClass::ClientError => KIND_INVALID_REQUEST,
        // The other classes are not reached on the ClientFault arm (they classify as
        // TransientUpstream / HardDown / ContextLength), but the match must be exhaustive; treat
        // them as a generic invalid-request shape rather than panicking on the request path.
        StatusClass::RateLimit
        | StatusClass::Overloaded
        | StatusClass::ServerError
        | StatusClass::Timeout
        | StatusClass::Network
        | StatusClass::Auth
        | StatusClass::Billing => KIND_INVALID_REQUEST,
    }
}

/// Best-effort human-readable message from an upstream error body, across the vendor error shapes
/// (`error.message`, top-level `message`, Gemini `error.message`). Returns `None` when the body is
/// not JSON or carries no recognizable message field, so the caller substitutes a generic detail
/// rather than leaking the raw foreign body.
fn extract_error_message(bytes: &[u8]) -> Option<String> {
    let v: Value = crate::json::parse(bytes).ok()?;
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
const MID_STREAM_GENERIC_DETAIL: &str = crate::proto::STREAM_ABORT_DETAIL;

/// Vendor-neutral fallback `error.message` for a NON-2xx response whose body carried no extractable
/// human message. Rendered into the CLIENT's native error envelope via `ingress_error`, so it must
/// read like copy a real single-vendor API would emit — NOT reverse-proxy vocabulary like "upstream".
/// The real status/cause is logged server-side; only this generic string reaches the client.
const GENERIC_REJECTED_DETAIL: &str = "The request could not be processed.";

/// Client-visible fallback `detail` strings each repeated across several ingress-error sites —
/// hoisted so the copy cannot drift between them. Same vendor-neutral rules as
/// `GENERIC_REJECTED_DETAIL`: generic service phrasing, no proxy/translation vocabulary.
const DETAIL_INTERNAL_ERROR: &str = "We received an unexpected internal error. Please try again.";
const DETAIL_MODEL_UNSUPPORTED_OPERATION: &str = "This model does not support that operation.";
const DETAIL_ENDPOINT_UNSUPPORTED_OPERATION: &str =
    "This endpoint does not support that operation.";
const DETAIL_REQUEST_TIMEOUT: &str = "The request timed out. Please retry shortly.";

/// Vendor-neutral fallback detail for a cross-protocol response that could not be relayed (a body
/// transfer failure mid-read, an over-cap body, or an untranslatable shape). Rendered into the
/// client's native error envelope, so it must NOT disclose the existence of a translating
/// intermediary ("translate"/"untranslatable") or proxy vocabulary ("upstream"); a native vendor
/// returns a generic internal-error message here. The precise cause is logged server-side.
const GENERIC_RESPONSE_ERROR_DETAIL: &str =
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
    // The error is a mid-stream transport failure ≈ internal/5xx. Resolve the ingress protocol once;
    // an unknown ingress falls back to the OpenAI writer (mirrors `ingress_error`).
    let err = crate::proto::IrError {
        class: crate::breaker::StatusClass::ServerError,
        provider_signal: Some(message.to_string()),
        retry_after: None,
    };
    let proto =
        crate::proto::protocol_for(ingress_protocol).unwrap_or_else(crate::proto::Protocol::openai);
    if ingress_eventstream {
        // Binary eventstream client (a native AWS SDK): a mid-stream failure is a MODELED-EXCEPTION
        // frame, not an SSE event. The exception NAME comes from the ingress writer's vtable
        // (`write_response_exception`) — so forward.rs names no protocol's wire shape;
        // `encode_exception_frame` is the generic binary framer. A protocol that reports
        // `ingress_is_eventstream` but declines an exception mapping (a contradiction) falls through.
        if let Some((exc_name, msg)) = proto.writer().write_response_exception(&err) {
            return crate::eventstream::encode_exception_frame(&exc_name, &msg);
        }
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
    let ev = crate::ir::IrStreamEvent::Error(err);
    // Every SSE-framed writer (openai/anthropic/gemini/cohere/responses) returns `Some` for an
    // `Error` event; the `None` fallback only guards a hypothetical future writer that declines to
    // frame errors in-band, in which case we still emit a decodable bare `data:` error.
    match proto.writer().write_response_event(&ev) {
        Some((event_type, data)) => {
            let data = crate::json::to_string(&data).unwrap_or_else(|_| {
                serde_json::json!({ "error": { "message": message, "type": KIND_API_ERROR } })
                    .to_string()
            });
            if event_type.is_empty() {
                format!("data: {data}\n\n").into_bytes()
            } else {
                format!("event: {event_type}\ndata: {data}\n\n").into_bytes()
            }
        }
        None => {
            let data =
                serde_json::json!({ "error": { "message": message, "type": KIND_API_ERROR } })
                    .to_string();
            format!("data: {data}\n\n").into_bytes()
        }
    }
}

/// Deterministic FNV-1a hash of a string — stable across processes/restarts (unlike the
/// std `DefaultHasher`, whose seed is randomized), so session affinity pins consistently.
fn stable_hash(s: &str) -> u64 {
    crate::store::fnv1a_u64(s)
}

/// Where to charge a request's token usage when its response stream completes (the resolved virtual
/// key + its budget period + the governance store). `None` when governance is off or no key resolved.
#[derive(Clone)]
pub(crate) struct UsageSink {
    pub(crate) gov: Arc<crate::governance::GovState>,
    pub(crate) key_id: String,
    pub(crate) period: String,
    /// Wall-clock epoch (seconds) captured ONCE at header-arrival time for this request. Both the
    /// flat per-request fee (`ingress::budget_check` → `try_charge_request_within_budget`) and the token fee (`record_tokens`,
    /// fired at stream end / on the buffered path) are attributed to the window this epoch implies,
    /// so a single streaming request whose stream completes in a later rate-limit/budget window than
    /// its headers arrived cannot split its two charges across two windows (#29). Without it, the two
    /// calls read the clock independently and could land in different 60s rate windows / budget
    /// periods, mis-attributing spend and TPM.
    pub(crate) charged_at: u64,
}

/// Body wrapper that drives IR-based usage extraction, billing, and mid-stream error handling for
/// streaming responses.
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
    /// The operation this response belongs to. Drives whether the non-stream body is buffered for
    /// usage extraction (`taps_nonstream_usage`) and how usage is read from it (`extract_usage`).
    /// Chat reads the egress reader's IR usage; a flat-fee op taps nothing.
    op: crate::handlers::Op,
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
    /// when Some, translate each egress SSE chunk to the caller's ingress protocol.
    /// None = native passthrough (same-protocol or non-SSE).
    translate: Option<crate::proto::StreamTranslate>,
    /// When set (gemini ingress streaming WITHOUT `?alt=sse`), the SSE bytes — whether from a
    /// same-protocol passthrough or the cross-protocol `translate` stage above, both of which are
    /// gemini SSE here — are reframed into the JSON-array streaming format the native non-`alt=sse`
    /// `:streamGenerateContent` request expects (`[{...},{...}]`). Runs AFTER `translate`.
    json_array: Option<Box<dyn crate::proto::JsonArrayFramer>>,
    /// When set, the token usage tapped from this response is charged to a virtual key's budget at
    /// stream end (token-accurate accounting). Taken (fired) exactly once when the stream completes.
    usage_sink: Option<UsageSink>,
    /// True when the 2xx-headers `spend_budget(lane_idx)` on this request actually decremented the
    /// lane's `max_requests` budget. A pre-first-byte upstream transport failure on the streaming
    /// path delivers NO usable body, so it must refund that unit — symmetric with the buffered
    /// `ReadEnd::TransportError` path (#21). Guarding the refund on this flag keeps `refund_budget`
    /// (an unconditional `fetch_add`) from raising the budget above its cap when the spend was a
    /// no-op (unlimited lane, or budget already 0). Cleared once a refund fires so it happens once.
    budget_spent: bool,
    /// Set once the stream has fully ended (after any translation terminator), so a later poll
    /// returns None instead of re-polling a finished inner stream.
    ended: bool,
    /// Bounded reassembly buffer for a SAME-PROTOCOL NON-STREAM (`!is_sse`, `translate == None`)
    /// `application/json` body that reqwest delivers across multiple transport frames. This is the
    /// non-stream analog of Change B's read-for-IR-emit-verbatim: the body is relayed to the client
    /// byte-for-byte (each chunk passes through unchanged), but a bounded copy is retained here so the
    /// stream-end arm can run the EGRESS READER over the reassembled body and source `IrUsage` for
    /// billing (Change A path #4). Same-proto means egress == ingress, so the body is in the ingress
    /// protocol's native shape and `ingress_protocol`'s reader decodes it. Capped at
    /// `MAX_TRANSLATED_BODY_BYTES` (dropping past the cap with a warn like the buffered guards). The
    /// SSE / translation paths never touch this (they bill via `translate.usage()`).
    nonstream_buf: Vec<u8>,
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
        op: crate::handlers::Op,
        permit: P,
        app: Arc<App>,
        lane_idx: usize,
        breaker_cfg: Arc<crate::store::BreakerCfg>,
        pool: &str,
        translate: Option<crate::proto::StreamTranslate>,
        json_array: Option<Box<dyn crate::proto::JsonArrayFramer>>,
        usage_sink: Option<UsageSink>,
        budget_spent: bool,
    ) -> Self {
        Self {
            inner,
            first_byte_sent: Arc::new(AtomicBool::new(false)),
            is_sse,
            // Resolve the ingress protocol's writer ONCE to determine whether the client expects a
            // binary event-stream body (Bedrock) rather than SSE text. Dispatches through the
            // `ingress_is_eventstream` vtable method so this constructor carries no `== "bedrock"`
            // branch — a future protocol with a binary framing just overrides the method.
            ingress_eventstream: crate::proto::protocol_for(ingress_protocol)
                .map(|p| p.writer().ingress_is_eventstream())
                .unwrap_or(false),
            ingress_protocol: Box::from(ingress_protocol),
            op,
            permit: Some(permit),
            app: Some(app),
            lane_idx,
            breaker_cfg,
            pool: Box::from(pool),
            translate,
            json_array,
            usage_sink,
            budget_spent,
            ended: false,
            nonstream_buf: Vec::new(),
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
                    // cross-protocol → translate egress SSE bytes to the ingress format. SAME-protocol
                    // (Change B) → `t.feed` returns the VERBATIM original frame bytes. Billing now reads
                    // the IR-derived `t.usage()` at stream end (Change A) — there is no longer a byte-
                    // scanner tap on this path, so `feed` is the single usage source for both modes.
                    if let Some(t) = this.translate.as_mut() {
                        let out = t.feed(&chunk);
                        let out_bytes = Bytes::from(out);
                        // Gemini non-`alt=sse` ingress: reframe the (now gemini-SSE) bytes into the
                        // JSON-array streaming shape. Run AFTER translate so accounting is unaffected.
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
                    // Passthrough: the raw chunk is already in the client's shape. This branch is reached
                    // only for (a) a SAME-PROTOCOL NON-STREAM (`!is_sse`) `application/json` body — the
                    // streaming SSE/eventstream same-proto path always builds a `Some(translate)` now —
                    // and (b) the unknown-protocol fallback (`new_same_proto` returned `None`), which has
                    // no reader to drive the IR and therefore no usage source. The bytes always stream to
                    // the client unchanged; for (a) we retain a bounded copy for IR-based billing below.
                    // Only buffer when the operation actually taps usage from the body. Chat and the
                    // token-billed ops do; a flat-fee op (or a large-binary response) skips the copy
                    // entirely — the bytes still relay verbatim below, unbuffered.
                    if !this.is_sse && this.op.taps_nonstream_usage() {
                        // SAME-PROTOCOL NON-STREAM `application/json` passthrough (Change A path #4): the
                        // non-stream analog of B's read-for-IR-emit-verbatim. The body relays verbatim,
                        // but a bounded copy is retained so the stream-end arm can run the egress reader
                        // (`ingress_protocol`'s reader — same-proto, so egress == ingress) over the
                        // reassembled body and source `IrUsage` for billing. Cap at
                        // `MAX_TRANSLATED_BODY_BYTES`; past the cap, drop the overflow with a warn
                        // (matching the buffered `read_capped` guards) — the tail `usage` may then be
                        // missed, but the gap is observable, not a memory leak.
                        if this.nonstream_buf.len() < max_translated_body_bytes() {
                            let remaining = max_translated_body_bytes() - this.nonstream_buf.len();
                            if chunk.len() <= remaining {
                                this.nonstream_buf.extend_from_slice(&chunk);
                            } else {
                                this.nonstream_buf.extend_from_slice(&chunk[..remaining]);
                                // Fires once per response (the next chunk sees buf == cap and skips
                                // this arm). Count it so the undercount is alertable on a dashboard,
                                // not just visible in a log line an operator has to be watching for.
                                metrics::counter!(crate::metrics::BILLING_TRUNCATED_TOTAL)
                                    .increment(1);
                                tracing::warn!(
                                    buffered = this.nonstream_buf.len(),
                                    cap = max_translated_body_bytes(),
                                    "same-protocol non-stream body exceeded the usage-tap reassembly \
                                     cap; if the tail usage frame fell past the cap, this request's \
                                     tokens are undercounted (TPM/spend may be undercharged)"
                                );
                            }
                        }
                    }
                    // Gemini same-protocol passthrough WITHOUT `?alt=sse` on the unknown-protocol
                    // fallback: the upstream chunk is gemini SSE (busbar always requests `?alt=sse`
                    // upstream); reframe it into the JSON-array streaming shape the native client
                    // expects. (The known-protocol gemini same-proto path runs through `translate`.)
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
                            let tripped = app.store.record_transient_in(
                                &this.pool,
                                this.lane_idx,
                                "mid-stream",
                                &this.breaker_cfg,
                                None,
                            );
                            // A mid-stream failure that drives a Closed→Open trip is a breaker trip
                            // for this (pool, lane) — emit BREAKER_TRIPS_TOTAL once (#29).
                            if tripped {
                                emit_breaker_trip(app, &this.pool, this.lane_idx);
                            }
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
                            // The framer owns the wire status/code shape (Gemini → 500/`INTERNAL`); the
                            // agnostic core supplies only the generic message.
                            let err_bytes =
                                framer.finish_with_server_error(MID_STREAM_GENERIC_DETAIL);
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
                        // Mid-BODY transport failure AFTER the first byte on a NON-SSE same-protocol
                        // passthrough (e.g. OpenAI→OpenAI /chat/completions, content-type
                        // application/json): the 2xx headers already recorded an optimistic breaker
                        // SUCCESS (via `record_success_in`), but the body never arrived intact, so that
                        // success is wrong — exactly the case the SSE if-branch above and BOTH buffered
                        // `ReadEnd::TransportError` paths compensate. The SSE
                        // branch couldn't fire here (this path is reached only when `!this.is_sse`), and
                        // without this the optimistic success is NEVER reversed → repeated mid-body
                        // failures accumulate as successes and the lane never trips. Record a compensating
                        // transient. Gate on `had_first`: a PRE-first-byte failure (had_first == false) is
                        // the original symmetric-with-#21 refund-only case (no streamed body content was
                        // ever emitted to the client) and must NOT additionally record a transient — that
                        // would be a sibling over-broad fix. Only a post-first-byte mid-body failure both
                        // refunds budget AND records the failed transfer.
                        if had_first {
                            if let Some(ref app) = this.app {
                                let tripped = app.store.record_transient_in(
                                    &this.pool,
                                    this.lane_idx,
                                    "mid-body-transport",
                                    &this.breaker_cfg,
                                    None,
                                );
                                // A threshold-based Closed→Open trip here is a breaker trip (#29).
                                if tripped {
                                    emit_breaker_trip(app, &this.pool, this.lane_idx);
                                }
                            }
                        }
                        // Symmetric with the buffered `ReadEnd::TransportError` path (#21): the 2xx
                        // headers already spent one `max_requests` budget unit on this lane, but a
                        // pre-first-byte body transport failure delivers NO usable response — so refund
                        // that unit, or sustained streaming transport failures would permanently drain
                        // the lane's serving-capacity budget one unit at a time (MED #3). The streaming
                        // path previously refunded nothing here while the buffered paths did. Refund
                        // ONLY when the headers-spend actually decremented (`budget_spent`): a no-op
                        // spend (unlimited lane, or budget already 0) must not be refunded, since
                        // `refund_budget` is an unconditional `fetch_add` that would otherwise push the
                        // budget above its cap. Mark the stream ended and clear the flag so the inner
                        // stream's trailing `Poll::Ready(None)` neither double-refunds nor token-bills.
                        if this.budget_spent {
                            if let Some(ref app) = this.app {
                                app.store.refund_budget(this.lane_idx);
                            }
                            this.budget_spent = false;
                        }
                        drop(this.permit.take());
                        this.ended = true;
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
                    //
                    // Hoist the TRANSLATE-side abort flag ONCE, at the top of this arm, BEFORE
                    // `finish()` consumes the translate below. A cross-protocol `StreamTranslate`
                    // that overflowed `MAX_BUF` (>16MiB without a frame terminator) or hit a
                    // malformed egress prelude calls `abort()` and stops feeding the body — but it
                    // leaves `tap.terminal_error` clear (no in-band `{"type":"error"}` frame was ever
                    // scanned). That is the SIBLING condition to the R25 mid-body terminal-error fix:
                    // both deliver a partial/aborted response the caller cannot use, so BOTH must be
                    // treated as a failed stream by ALL THREE downstream gates (breaker, token
                    // billing, json-array byte-shaping). The json-array close path below previously
                    // read `aborted()` locally for its own byte-shaping; that single read is hoisted
                    // here and reused so the three gates can never diverge.
                    let translate_aborted = this
                        .translate
                        .as_ref()
                        .map(|t| t.aborted())
                        .unwrap_or(false);
                    // A stream is FAILED for breaker purposes when EITHER a reader-emitted terminal ERROR
                    // event was seen (the IR-sourced `translate.terminal_error()`, Change A — replacing
                    // the deleted `UsageTap::terminal_error` byte-scan) OR the cross-protocol translate
                    // aborted mid-flight. Every same-proto/cross-proto SSE+eventstream stream now flows
                    // through `translate`, so the terminal error is observable at this point in the arm
                    // for all of them; the billing gate re-evaluates the same predicate AFTER the bedrock
                    // deferred `finish()` below (whose `metadata` frame can surface usage/error at end).
                    let stream_terminal_error = this
                        .translate
                        .as_ref()
                        .and_then(|t| t.terminal_error())
                        .is_some();
                    let breaker_failed = stream_terminal_error || translate_aborted;
                    if this.is_sse && this.first_byte_sent.load(Ordering::Relaxed) && breaker_failed
                    {
                        if let Some(app) = this.app.as_ref() {
                            // Distinguish the two failure lineages in the recorded reason so the
                            // R25 terminal-error path and this R26 translate-abort sibling remain
                            // separable in breaker telemetry.
                            let reason = if stream_terminal_error {
                                "stream-terminal-error"
                            } else {
                                // translate_aborted must hold here (breaker_failed && no
                                // terminal_error) — name the sibling lineage explicitly.
                                "stream-translate-abort"
                            };
                            let tripped = app.store.record_transient_in(
                                &this.pool,
                                this.lane_idx,
                                reason,
                                &this.breaker_cfg,
                                None,
                            );
                            // A terminal-error frame OR translate abort that drives a Closed→Open
                            // trip is a breaker trip for this (pool, lane) — emit BREAKER_TRIPS_TOTAL
                            // once (#29). This is the arm the `response.failed` recognition (#H2) now
                            // reaches for a streaming Responses FAILURE that previously recorded as
                            // success.
                            if tripped {
                                emit_breaker_trip(app, &this.pool, this.lane_idx);
                            }
                        }
                    }
                    // emit the ingress terminator before close. For a gemini JSON-array stream the
                    // terminator is the closing `]` from the framer; the SSE `translate.finish()`
                    // terminator (e.g. OpenAI `data: [DONE]`) must NOT be emitted into a JSON-array
                    // body — drain the translate buffer (so its decode side-effects run) but discard
                    // its SSE terminator bytes, then append the framer close.
                    let done = if let Some(framer) = this.json_array.as_mut() {
                        // The TRANSLATE-side abort flag was hoisted at the top of this arm (BEFORE any
                        // `finish()` drains the translate): a cross-protocol StreamTranslate that
                        // overflowed `MAX_BUF` (or hit a malformed egress prelude) stopped feeding this
                        // framer, and its SSE terminal-error frame cannot ride inside a JSON-array body,
                        // so the framer's own `aborted` flag stays clear. Route the close through
                        // `finish_for_translate(translate_aborted)` so an aborted gemini-json-array
                        // stream surfaces a NATIVE error element + `]` instead of a bare `]` (a silent
                        // truncation indistinguishable from a short success). Drain the translate's SSE
                        // terminator for its decode side-effects but discard those bytes — the
                        // JSON-array terminator is the framer close. Reuse the single hoisted read so
                        // the breaker, billing, and byte-shaping gates can never diverge.
                        let _ = this.translate.as_mut().map(|t| t.finish());
                        framer.finish_for_translate(translate_aborted)
                    } else {
                        this.translate
                            .as_mut()
                            .map(|t| t.finish())
                            .unwrap_or_default()
                    };
                    // Bedrock ingress: `finish()` may emit a deferred terminal `metadata` frame (the
                    // default-OpenAI-streaming case carries usage there). Its usage is folded into the
                    // translator's `last_usage` A-tap by `finish()` itself, so `translate.usage()` below
                    // already reflects it — no separate tap-feed of the binary `done` bytes is needed.
                    drop(this.permit.take());
                    this.ended = true;
                    // Token usage for billing, sourced from the IR (Change A):
                    //   - STREAMING (SSE / eventstream, same- or cross-proto): `translate.usage()` — the
                    //     terminal `IrUsage` the readers accumulated, post Anthropic start-usage backfill.
                    //   - SAME-PROTOCOL NON-STREAM (`!is_sse`, `translate == None`): run the EGRESS reader
                    //     (`ingress_protocol`'s reader — same-proto, egress == ingress) over the
                    //     reassembled `nonstream_buf` body and read `ir.usage` (Change A path #4). The body
                    //     was relayed verbatim; this is the read-for-IR side-channel for billing.
                    // The unknown-protocol fallback passthrough has no reader and yields `None` (no usage
                    // source — same as before; an unknown protocol cannot be metered).
                    let ir_usage: Option<crate::ir::IrUsage> =
                        if let Some(t) = this.translate.as_ref() {
                            t.usage().cloned()
                        } else if !this.is_sse && !this.nonstream_buf.is_empty() {
                            // Same-protocol non-stream body relayed verbatim; the operation reads
                            // usage from the reassembled bytes. Chat runs the egress reader and
                            // reports IR usage (byte-identical to the previous inline read); a
                            // flat-fee op returns None and bills nothing.
                            let buf = std::mem::take(&mut this.nonstream_buf);
                            this.op.extract_usage(&this.ingress_protocol, &buf)
                        } else {
                            None
                        };
                    // Charge this request's token usage to the virtual key's budget (once) — but ONLY
                    // for a cleanly-terminated stream. A stream that saw a reader-emitted terminal ERROR
                    // event (`translate.terminal_error()`) OR whose cross-protocol translate aborted
                    // mid-flight (`translate_aborted`) delivered a partial/aborted response the caller
                    // cannot use, and billing it contradicts the flat-fee-only-on-success policy (the
                    // per-request fee is charged at admission by
                    // `ingress::budget_check`→`try_charge_request_within_budget`, and `ingress::finish`
                    // REFUNDS it on a non-2xx, so the net flat fee lands only on a 2xx). Mirror that
                    // here with the SAME `failed` predicate the breaker gate above uses: a failed
                    // stream is not token-billed, covering BOTH the SSE-ingress and json-array close
                    // paths (the json-array path previously fell through and billed an aborted
                    // stream's partial tokens). A same-proto non-stream body has no terminal-error/abort
                    // path here (it is `!is_sse`), so `billing_failed` is false there.
                    if let Some(sink) = this.usage_sink.take() {
                        // Re-read the terminal error AFTER the deferred bedrock `finish()` above (whose
                        // `metadata`/exception frame can surface an error only at stream end), OR'd with
                        // the hoisted translate-abort flag — keeping the SAME failed semantics the breaker
                        // gate used. An aborted translate's `feed` is a no-op, so the `translate_aborted`
                        // snapshot taken at the top of the arm is still authoritative.
                        let billing_failed = this
                            .translate
                            .as_ref()
                            .and_then(|t| t.terminal_error())
                            .is_some()
                            || translate_aborted;
                        if !billing_failed {
                            // billed tokens = the normalized billable total (A2): uncached input +
                            // cache_read + cache_creation + output. Readers normalize `input_tokens`
                            // to UNCACHED and keep the cache fields ADDITIVE, so this single sum is
                            // correct provider-agnostically — OpenAI-family stay at prompt_total+output
                            // (no double-count), Anthropic/Bedrock now correctly include their
                            // additive cache reads/writes. `billable_tokens` saturates internally
                            // (counts are UPSTREAM-CONTROLLED) rather than risking a request-path panic.
                            let tokens =
                                ir_usage.as_ref().map(|u| u.billable_tokens()).unwrap_or(0);
                            // Attribute the token fee to the SAME window the flat per-request fee was
                            // charged in (`sink.charged_at`, the header-arrival epoch), not the
                            // stream-end clock — otherwise a stream that completes in a later window
                            // than its headers arrived would split its two charges across two windows
                            // (#29).
                            sink.gov.record_tokens(
                                &sink.key_id,
                                &sink.period,
                                sink.charged_at,
                                tokens,
                            );
                            // Metering (raw per-model consumption series, token SPLIT preserved):
                            // attribute to the SERVING lane — `lane_idx` is the lane that actually
                            // answered, post-failover. Same pinned epoch as the budget charges (#29).
                            if let Some(lane) =
                                this.app.as_ref().and_then(|a| a.lanes.get(this.lane_idx))
                            {
                                sink.gov.record_metering(
                                    &sink.key_id,
                                    &lane.model,
                                    &lane.provider,
                                    ir_usage.as_ref(),
                                    sink.charged_at,
                                );
                            }
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

impl<S, P> Drop for FirstByteBody<S, P> {
    fn drop(&mut self) {
        // Token-fee billing normally fires in `Poll::Ready(None)` (natural stream end), which TAKES
        // `usage_sink`. So a `None` here means "already billed" and this Drop is a no-op — no
        // double-charge. A `Some` means the body was DROPPED MID-STREAM (client disconnect /
        // cancellation) before the natural end, so the token-fee site never ran and the tokens already
        // generated + delivered would go unbilled (the under-billing the audit flagged). Bill the
        // tokens the readers accumulated up to the drop point instead.
        //
        // Best-effort: the provider's terminal usage frame may not have arrived before the cancel, so
        // `translate.usage()` may be partial or absent — partial/zero usage bills partial/zero
        // (`record_tokens` no-ops on 0 tokens). Only the streaming `translate.usage()` source is
        // consulted; a partially-buffered same-proto non-stream body cannot be reliably parsed for
        // usage, so it is not billed on a mid-buffer drop.
        let Some(sink) = self.usage_sink.take() else {
            return;
        };
        // Mirror the `Poll::Ready(None)` failed-gate EXACTLY: do not bill a stream that surfaced a
        // terminal reader error OR whose cross-protocol translate aborted mid-flight (buffer overflow
        // etc.) — both delivered a partial/aborted response the caller cannot use, and billing either
        // contradicts the no-bill-on-failure policy (asserted by
        // `test_streaming_translate_abort_trips_breaker_and_skips_billing`).
        let translate = self.translate.as_ref();
        if translate.and_then(|t| t.terminal_error()).is_some()
            || translate.map(|t| t.aborted()).unwrap_or(false)
        {
            return;
        }
        let usage = self.translate.as_ref().and_then(|t| t.usage()).cloned();
        let tokens = usage.as_ref().map(|u| u.billable_tokens()).unwrap_or(0);
        if tokens > 0 {
            sink.gov
                .record_tokens(&sink.key_id, &sink.period, sink.charged_at, tokens);
            // Meter the delivered-then-dropped partial too (same serving-lane attribution as the
            // natural-end site) — the tokens were really consumed against this model.
            if let Some(lane) = self.app.as_ref().and_then(|a| a.lanes.get(self.lane_idx)) {
                sink.gov.record_metering(
                    &sink.key_id,
                    &lane.model,
                    &lane.provider,
                    usage.as_ref(),
                    sink.charged_at,
                );
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

/// A compliance restrict captured on the PRIMARY pool that must persist across every failover hop —
/// including a `fallback_pool` spill to an independent pool. `tags_any` is the eligible tag set,
/// `on_empty` decides what happens when a hop's candidates carry none of them (fail-closed reject vs
/// advisory weighted-escape), and `name` is the gate name for logs/metrics.
#[derive(Debug, Clone)]
struct RestrictConstraint {
    tags_any: Vec<String>,
    on_empty: crate::config::PolicyOnError,
    name: &'static str,
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
    /// Compliance restricts in force for this request (captured at the primary pool's gate
    /// reconcile). Re-applied on every downstream hop so a `Restrict` gate's "only these lanes,
    /// ever" guarantee holds across a `fallback_pool` spill — see [`RequestCtx::enforce_restricts`].
    active_restricts: Vec<RestrictConstraint>,
}

impl RequestCtx {
    fn new(deadline_secs: u64) -> Self {
        let start = now();
        Self {
            deadline: start.saturating_add(deadline_secs),
            excluded: std::collections::HashSet::new(),
            visited_pools: std::collections::HashSet::new(),
            active_restricts: Vec::new(),
        }
    }

    /// Re-apply the captured compliance restricts against a DOWNSTREAM pool's candidate set, keyed by
    /// THAT pool's own member tags (lane `idx` are global; `pool_runtime.members` is idx-keyed). The
    /// primary-pool gate reconcile shrinks `cands` in place, which keeps the restriction across
    /// in-pool failover — but a `fallback_pool` hop rebuilds candidates from an INDEPENDENT pool's
    /// full membership, so without re-applying here a compliance (e.g. BAA-only) restrict would be
    /// silently dropped at the pool boundary. Mirrors Reconcile-2 exactly: a `Weighted` on_empty is an
    /// advisory escape (skip this restrict on this hop); the fail-closed default returns `Err(name)`
    /// so the caller REJECTS rather than spilling to an ineligible lane. (found: audit c1r13.)
    fn enforce_restricts(
        &self,
        app: &App,
        pool_name: &str,
        cands: Vec<WeightedLane>,
    ) -> Result<Vec<WeightedLane>, &'static str> {
        let mut cands = cands;
        for r in &self.active_restricts {
            let members = app.pool_runtime.get(pool_name).map(|rt| &rt.members);
            let restricted: Vec<WeightedLane> = cands
                .iter()
                .filter(|wl| {
                    members.and_then(|m| m.get(&wl.idx)).is_some_and(|meta| {
                        meta.tags.iter().any(|t| r.tags_any.iter().any(|w| w == t))
                    })
                })
                .cloned()
                .collect();
            if restricted.is_empty() {
                if matches!(r.on_empty, crate::config::PolicyOnError::Weighted) {
                    continue; // advisory escape — skip this restrict on this hop
                }
                return Err(r.name); // fail closed — no eligible lane satisfies a required restrict
            }
            cands = restricted;
        }
        Ok(cands)
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

    /// Fill `out` with candidates minus exclusions (clears `out` first).
    fn fill_candidates<'a>(&self, cands: &'a [WeightedLane], out: &mut Vec<&'a WeightedLane>) {
        out.clear();
        out.extend(cands.iter().filter(|wl| !self.excluded.contains(&wl.idx)));
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

/// RAII release for a WON-but-UNDISPATCHED single-flight recovery probe.
///
/// Once `acquire_for_dispatch_in` wins the probe the cell is HalfOpen + `probe_in_flight == true`; the
/// flag is normally cleared only when a request records an outcome. Every path between winning the
/// probe and actually dispatching a request must release it, INCLUDING the implicit path where the
/// `pick_among` future is DROPPED (client disconnect) while parked at the `timeout(sem.acquire_owned())`
/// await — no early-return runs on drop, so without this guard the cell stays HalfOpen+probe_in_flight
/// and the lane is benched until the slow out-of-band prober resets it (the HIGH this fixes).
///
/// `Drop` calls the idempotent `release_probe_in` (CAS HalfOpen→Open + clear flag) while `armed`. The
/// two paths that hand a LIVE permit to a dispatched request DISARM the guard first, because the
/// dispatched request now owns the probe and releases it via its recorded outcome.
struct ProbeGuard<'a> {
    store: &'a dyn crate::store::StateStore,
    pool: &'a str,
    lane: usize,
    armed: bool,
}

impl Drop for ProbeGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.store.release_probe_in(self.pool, self.lane);
        }
    }
}

/// Pick a lane from `cands` using session affinity (if any) then weighted selection (SWRR) over
/// the healthy subset, returning the chosen lane index and its acquired concurrency permit.
/// `cands` is a `&[WeightedLane]` slice where each lane carries its configured weight.
/// `request_ctx` provides accumulated exclusions to avoid retrying failed lanes.
/// `affinity_key` enables sticky routing as a preference (not a hard constraint).
async fn pick_among(
    app: &Arc<App>,
    cands: &[WeightedLane],
    request_ctx: &mut RequestCtx,
    affinity_key: Option<&str>,
    pool_name: &str,
    // The routing policy's ranked preference for this request, resolved ONCE before the failover loop
    // (see the ROUTING-POLICY SEAM in `forward_with_pool`). `None` is the ZERO-COST default: pure
    // SWRR, byte-identical to pre-feature behavior. `Some(order)` makes selection walk the ranked
    // lanes through the unchanged breaker filter instead of the blind SWRR pick (see SELECTION below).
    policy_order: Option<&[usize]>,
) -> Option<(usize, Permit)> {
    let t = now();

    // Session affinity preference - try sticky lane first if usable (in this pool's breaker view).
    // Uses a stable hash (NOT DefaultHasher, whose seed is randomized per process) so a session
    // pins to the same lane across restarts.
    if let Some(k) = affinity_key {
        if !cands.is_empty() {
            let pos = (stable_hash(k) as usize) % cands.len();
            let sticky = cands[pos].idx;

            // DRAIN (`weight: 0`): an operator weights a member to 0 to bleed it off before
            // decommission. SWRR (`select_weighted_for`) and the routing-policy preferred walk both
            // already exclude a 0-weight candidate; this sticky fast-path must too, else a session
            // whose hash lands on a drained-but-breaker-healthy member keeps pinning to it on the
            // NORMAL path — silently defeating drain. `usable_in`/`lane_admissible` only consult
            // dead/budget/breaker, never weight, so gate on the candidate's weight here.
            if cands[pos].weight != 0
                && !request_ctx.excluded.contains(&sticky)
                && app.store.usable_in(pool_name, sticky, t)
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

    // Hoisted out of the retry loop and pre-sized to the candidate count: the loop body re-runs on
    // every within-pick retry hop (HalfOpen-probe race), so reusing these buffers (`.clear()` +
    // re-`.extend()` each iteration) avoids both per-iteration allocation AND growth reallocation.
    // The filter can only DROP entries, so `cands.len()` is an upper bound (capacity, not fill);
    // selection semantics are unchanged. `filtered_cands` borrows `cands`, which outlives the loop.
    let mut filtered_cands: Vec<&WeightedLane> = Vec::with_capacity(cands.len());
    let mut candidates: Vec<usize> = Vec::with_capacity(cands.len());
    let mut weights: Vec<u32> = Vec::with_capacity(cands.len());

    loop {
        // Deadline guard: never spin or re-select past the request deadline.
        if request_ctx.expired(now()) {
            return None;
        }

        request_ctx.fill_candidates(cands, &mut filtered_cands);
        filtered_cands.retain(|wl| !local_excluded.contains(&wl.idx));
        if filtered_cands.is_empty() {
            return None;
        }

        // Extract lane indices and weights for select_weighted call
        candidates.clear();
        candidates.extend(filtered_cands.iter().map(|wl| wl.idx));
        weights.clear();
        weights.extend(filtered_cands.iter().map(|wl| wl.weight));

        // SELECTION. Two paths, and ONLY two:
        //
        //  • `policy_order == None` (the ZERO-COST DEFAULT, `route: weighted` / absent): byte-identical
        //    to pre-feature behavior — a single `select_weighted_in` call, the unchanged inline SWRR.
        //
        //  • `policy_order == Some(order)` (a routing policy returned `Prefer`): an ORDERED WALK.
        //    Honor EXACTLY the same health filter SWRR honors — `select_weighted_in` admits a candidate
        //    iff it is lane-admissible (not dead / in budget) AND its per-pool breaker cell is ready
        //    (the side-effect-FREE `ready_in`, the SAME predicate SWRR's filter uses). So: pick the
        //    FIRST lane in the policy's ranked `order` that is (a) still in this hop's candidate set
        //    (`candidates` is already exclusions- and local_excluded-filtered) and (b) `ready_in`. A
        //    preferred lane that is tripped / dead / excluded / at-capacity-by-breaker fails this check
        //    and we walk to the next. If NO ranked lane qualifies — every preferred lane is
        //    unhealthy/excluded, OR the policy ranked only a subset and those are exhausted — we fall
        //    THROUGH to `select_weighted_in` over the same candidate set, which both (i) preserves the
        //    contract's "an omitted/unranked candidate is lowest-priority but still REACHABLE, never
        //    stranded" guarantee, and (ii) keeps `Abstain` ⇒ today's SWRR exact (Abstain resolves to
        //    `policy_order == None`, so it never reaches this arm at all).
        //
        // The walk only ORDERS. It does NOT touch the breaker/probe/failover machinery: `ready_in` is
        // a read-only peek (no Open→HalfOpen transition, no single-flight probe CAS), and the SOLE
        // mutating admission — `acquire_for_dispatch_in` below — still runs EXACTLY ONCE on the chosen
        // lane, identically to the SWRR path. A preferred lane that then loses the HalfOpen probe race
        // is `local_excluded` + re-walked just like an SWRR pick, so it falls to the next preferred
        // lane (or to SWRR) with no change to breaker, failover, or translation behavior.
        let picked_lane_idx = match policy_order {
            Some(order) => {
                let now_t = now();
                // First ranked lane that is in this hop's candidate set, NOT drained, AND breaker-ready.
                //
                // C2 (weight:0 drain): SWRR's `select_weighted_in` skips `weight == 0` members (the
                // operator drain signal — see store.rs). The side-effect-free `ready_in` does NOT
                // check weight, so without this filter the ordered walk could rank a DRAINED lane #1
                // and dispatch to it, violating operator drain intent. Mirror SWRR here: a candidate
                // weighted to 0 is excluded from the preferred walk. It still falls through to
                // `select_weighted_in` below if no ranked lane qualifies — which itself re-skips
                // weight-0 — so a fully-drained candidate set strands nothing it shouldn't.
                let preferred = order.iter().copied().find(|idx| {
                    candidates
                        .iter()
                        .position(|c| c == idx)
                        .is_some_and(|pos| weights[pos] != 0)
                        && app.store.ready_in(pool_name, *idx, now_t)
                });
                match preferred {
                    Some(idx) => idx,
                    // No ranked lane qualifies: fall through to SWRR over the same candidates so an
                    // unranked-but-healthy lane is still reachable (never stranded by the policy).
                    None => {
                        match app
                            .store
                            .select_weighted_in(pool_name, &candidates, &weights, now_t)
                        {
                            Some(i) => i,
                            None => return None,
                        }
                    }
                }
            }
            // Zero-cost default: today's exact inline SWRR, one predictable branch.
            None => match app
                .store
                .select_weighted_in(pool_name, &candidates, &weights, now())
            {
                Some(i) => i,
                None => return None,
            },
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
        // → cell_closed, or a failure → cell_open). EVERY abandon of the probe below — explicit early
        // return OR an IMPLICIT future-drop while parked on the permit await — must release it, else
        // the flag stays `true`, the cell stays HalfOpen, and `usable_for` benches the lane until the
        // slow out-of-band prober resets it (the HIGH this fixes). `ProbeGuard` enforces that on Drop;
        // the only paths that legitimately keep the probe are the two that actually DISPATCH a request
        // (the immediate `try_acquire` hit and the `Ok(Ok(permit))` permit-wait success), which DISARM
        // the guard before returning the live permit — the dispatched request then owns the probe and
        // releases it via its recorded outcome.
        let mut probe_guard = ProbeGuard {
            store: app.store.as_ref(),
            pool: pool_name,
            lane: picked_lane_idx,
            armed: true,
        };

        // Try to acquire the concurrency permit immediately.
        if let Some(p) = app.store.try_acquire(picked_lane_idx) {
            // Live permit → dispatched request owns the probe; disarm so Drop is a no-op.
            probe_guard.armed = false;
            return Some((picked_lane_idx, p));
        }

        // Permits saturated: park (not busy-spin) until a slot frees OR the deadline passes. A
        // bounded `timeout` acquire yields the task efficiently and guarantees we never block past
        // the request deadline (unbounded spinning here was a head-of-line-blocking DoS surface).
        let remaining = request_ctx.remaining(now());
        if remaining == 0 {
            // Deadline already passed before we could even park — `probe_guard` drops here and
            // releases the won-but-undispatched probe so the lane stays re-probeable.
            return None;
        }
        let sem = app.store.lane_semaphore(picked_lane_idx);
        // If this future is DROPPED while parked on the await below (client disconnect), `probe_guard`
        // drops with it and releases the probe — the leak A1 fixes.
        match tokio::time::timeout(
            tokio::time::Duration::from_secs(remaining),
            sem.acquire_owned(),
        )
        .await
        {
            // Got a permit before the deadline — a genuine dispatch; disarm the guard (the request
            // itself will record the success/failure that releases the probe).
            Ok(Ok(permit)) => {
                probe_guard.armed = false;
                return Some((picked_lane_idx, permit));
            }
            // Semaphore closed (shutdown) — no request dispatched; `probe_guard` drops and releases.
            Ok(Err(_)) => return None,
            // Deadline hit while waiting for a permit — no request dispatched; `probe_guard` drops and
            // releases so the recovered lane isn't permanently benched, then give up so the caller can
            // 503/failover.
            Err(_) => return None,
        }
    }
}

/// True for content types that carry an incremental streamed response: SSE (text/event-stream,
/// used by Anthropic/OpenAI/Gemini-SSE) and AWS event-stream (Bedrock ConverseStream). Both
/// must engage the streaming body path rather than being buffered.
fn is_streaming_content_type(ct: &str) -> bool {
    // Read the cached streaming-CT set instead of re-sweeping the registry per request: a CT is
    // "streaming" iff it is the streaming `Content-Type` of SOME registered protocol's writer (SSE
    // protocols → `text/event-stream`; Bedrock → `application/vnd.amazon.eventstream`). The cache
    // (`proto::streaming_content_types`) reads those MIMEs from the writer vtable, so naming no
    // protocol/MIME literal here keeps the agnostic core clean. The detected set is unchanged:
    // `text/event-stream` + `application/vnd.amazon.eventstream`.
    crate::proto::streaming_content_types()
        .iter()
        .any(|p| ct.starts_with(p))
}

/// The streaming `Content-Type` the INGRESS client expects, by ingress protocol. On a cross-protocol
/// reframe the streamed body is re-encoded into the client's framing, so the response header must
/// describe the CLIENT's wire format — copying the upstream CT verbatim would mislabel the body
/// (e.g. a Bedrock-egress `application/vnd.amazon.eventstream` reaching an SSE client, or vice
/// versa). Returns `None` for an unrecognized protocol name so the caller keeps the upstream CT
/// rather than guessing.
///
/// Dispatches through `ProtocolWriter::streaming_content_type` (SSE protocols → `text/event-stream`;
/// Bedrock → `application/vnd.amazon.eventstream`) so this function carries no `"bedrock"` branch —
/// the CT is a property of the writer vtable, not the name string.
fn ingress_stream_content_type(ingress: &str) -> Option<&'static str> {
    crate::proto::protocol_for(ingress).map(|p| p.writer().streaming_content_type())
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
///
/// Returns the AUTHORITY ONLY (`host[:port]`) — never any path/query/fragment. The HTTP stack always
/// transmits `Host: <authority>` regardless of any path in `base_url`, so a `host` value that
/// included a path (e.g. a misconfigured `https://bedrock.../prefix`) would be signed but never sent,
/// yielding a silent `SignatureDoesNotMatch` on every request. Stripping the path here makes the
/// signed `host` equal to the transmitted `Host` byte-for-byte even if config validation is bypassed.
pub(crate) fn host_from_base(base: &str) -> String {
    let no_scheme = base
        .strip_prefix("https://")
        .or_else(|| base.strip_prefix("http://"))
        .unwrap_or(base);
    // Normalize backslash → forward slash BEFORE locating the authority boundary. The WHATWG URL
    // parser the `url` crate (and thus reqwest) uses treats `\` as an authority/path delimiter
    // exactly like `/`, so reqwest connects to the host that ENDS at the first backslash. Splitting
    // here only on `/?#` (a backslash-blind split, the SAME defect `ssrf_blocked_host` had) would
    // make this function read PAST the backslash: e.g. `https://evil.example.com\@victim.example/`
    // connects to `evil.example.com` on the wire, but a `/?#`-only split yields authority
    // `evil.example.com\@victim.example` whose `rfind('@')` returns `victim.example` — a signed
    // `Host` that DESYNCS from the host actually contacted (SigV4 signs one host, the TCP/TLS layer
    // dials another). Folding `\`→`/` first makes the authority boundary — and the returned signed
    // host — match what reqwest dials, byte-for-byte.
    let no_scheme = no_scheme.replace('\\', "/");
    let no_scheme = no_scheme.as_str();
    // The authority ends at the first `/`, `?`, or `#`; userinfo (if any) precedes the LAST `@`
    // within that authority. Split on the authority boundary first so an `@` appearing later in a
    // path/query (not userinfo) is never mistaken for a userinfo delimiter. Only the authority is
    // returned — the path/query/fragment (`rest`) is intentionally discarded (see doc above).
    let authority_end = no_scheme.find(['/', '?', '#']).unwrap_or(no_scheme.len());
    let authority = &no_scheme[..authority_end];
    match authority.rfind('@') {
        Some(at) => authority[at + 1..].to_string(),
        None => authority.to_string(),
    }
}

/// Produce the path that is BOTH signed (as the SigV4 canonical URI) and sent on the wire, so the
/// two can never diverge. Only the path component (before any `?`) is URI-encoded — reserved chars
/// in a Bedrock modelId such as `:` become `%3A`; the query string (if any) is preserved verbatim
/// (encoding `?`/`=`/`&` would corrupt it). The percent-encoded `%XX` sequences pass through the
/// `url` crate's path parser unchanged, so the transmitted request path equals the signed canonical
/// path byte-for-byte and AWS cannot reject with SignatureDoesNotMatch over a path-encoding mismatch.
pub(crate) fn sign_and_wire_path(url_path: &str) -> String {
    sign_and_wire_path_parts(url_path).0
}

/// Like [`sign_and_wire_path`] but ALSO returns the SigV4 `canonical_uri` (the encoded path with the
/// query stripped) so callers that need both don't re-split the wire path and allocate a SECOND
/// `String` for the canonical URI. On the common no-query path the encoded path IS the canonical URI,
/// so it is reused for both fields and only the wire path is (cheaply) cloned; with a query the wire
/// path is `canonical?query`. Output is byte-identical to the previous split-and-`to_string` form.
fn sign_and_wire_path_parts(url_path: &str) -> (String, String) {
    // The wire path is single-URI-encoded (what actually goes on the request line). The SigV4
    // CANONICAL path is DOUBLE-URI-encoded for every service except S3 (Bedrock included): AWS
    // re-encodes the already-encoded path it receives before recomputing the signature, so the
    // signature must be taken over the double-encoded form. Using the single-encoded path for BOTH
    // (as before) makes any path with an encodable char — every Bedrock model id has a `:` — fail
    // with SignatureDoesNotMatch (403). The signature-blind mock cannot catch this; only a real
    // upstream does, so it was invisible to the harness. For paths with no encodable chars
    // (openai/anthropic `/v1/...`) `uri_encode_path` is a no-op and canonical == wire, unchanged.
    let (path, query) = match url_path.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (url_path, None),
    };
    let wire_path = crate::sigv4::uri_encode_path(path);
    let canonical = crate::sigv4::uri_encode_path(&wire_path); // double-encode (non-S3 SigV4 rule)
    let wire = match query {
        Some(q) => format!("{wire_path}?{q}"),
        None => wire_path,
    };
    (wire, canonical)
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
    match lane.auth {
        Some(crate::config::ProviderAuth::ApiKey) => match axum::http::HeaderValue::from_str(key) {
            Ok(v) => vec![(axum::http::HeaderName::from_static("api-key"), v)],
            Err(_) => Vec::new(),
        },
        _ => lane.protocol.writer().sign_request(key, ctx),
    }
}

// ─── EGRESS User-Agent strings — RELEASE-CHECKLIST AUDIT SURFACE ──────────────────────────────────
//
// These mirror the `User-Agent` a real first-party SDK emits for each provider's API. They embed
// PINNED SDK VERSION NUMBERS that drift from upstream as those SDKs publish new releases (the OpenAI
// Python SDK alone ships several times per quarter). A backend that logs/filters by UA version can
// eventually observe a frozen, implausible version and separate busbar traffic from native traffic —
// a silent decay of the backend-facing indistinguishability guarantee.
//
// CONTAINMENT (no config/CI feature added here, per the 1.0 hardening scope): every pinned string is
// hoisted into a single named-constant block so the drift hazard lives on ONE auditable surface
// instead of being scattered as inline literals across `egress_user_agent`, and `egress_ua_versions_*`
// tests pin each protocol's UA to its constant so any silent edit/drift trips a test that forces a
// CONSCIOUS update. **RELEASE OBLIGATION:** before each busbar release, re-verify every version below
// against the latest published SDK release (PyPI / Crates.io / etc.) and bump as needed; the test
// guard ensures this block can never change unnoticed.
//
// Anthropic Python SDK UA shape (api.anthropic.com). The official SDK is Stainless-generated and
// emits `<Title>/Python <ver>` — `Anthropic/Python <ver>` — the SAME grammar as the OpenAI SDK below,
// NOT a `anthropic-sdk-python/<ver>` shape (which no released Anthropic SDK has ever sent). Emitting
// the wrong shape was a wire tell that distinguished busbar-proxied traffic from a native client on
// the User-Agent alone — the egress-UA tests now also assert the shared `<Title>/Python <ver>` grammar.
pub(crate) const EGRESS_UA_ANTHROPIC: &str = "Anthropic/Python 0.39.0";
// OpenAI Python SDK shape; the Responses API is served by the same SDK/UA.
pub(crate) const EGRESS_UA_OPENAI: &str = "OpenAI/Python 1.54.0";
// Google GenAI SDK shape (generativelanguage.googleapis.com).
pub(crate) const EGRESS_UA_GEMINI: &str = "google-genai-sdk/0.8.0 gl-python/3.11";
// AWS Bedrock is reached via boto3/botocore.
pub(crate) const EGRESS_UA_BEDROCK: &str = "Boto3/1.35.0 md/Botocore#1.35.0";
// Cohere Python SDK shape (api.cohere.com).
pub(crate) const EGRESS_UA_COHERE: &str = "cohere-python/5.11.0";
// Unknown/foreign egress protocol: a generic-but-present UA still beats sending none.
pub(crate) const EGRESS_UA_DEFAULT: &str = "okhttp/4.12.0";

/// Plausible native-SDK `User-Agent` for the chosen EGRESS protocol. reqwest sends NO default
/// User-Agent unless one is set, so without this every proxied upstream request reaches the backend
/// with no UA at all — a trivial backend-side fingerprint distinguishing busbar-proxied traffic from
/// a native vendor SDK (which always sends a recognizable UA). (Backend-facing only; does not affect
/// client indistinguishability.) The version numbers are PINNED and drift over time — see the
/// `EGRESS_UA_*` constant block above for the release-time audit obligation that keeps them current.
///
/// Thin wrapper: dispatches through `ProtocolWriter::egress_user_agent` so the name-match lives in
/// the per-protocol writer, not in this agnostic function. Call sites that already hold a resolved
/// writer (`writer.egress_user_agent()`) bypass this wrapper; it exists for test-code paths that
/// look up by name.
pub(crate) fn egress_user_agent(egress_protocol: &str) -> &'static str {
    crate::proto::protocol_for(egress_protocol)
        .map(|p| p.writer().egress_user_agent())
        .unwrap_or(EGRESS_UA_DEFAULT)
}

/// The `Accept` header a native SDK for `egress_protocol` sends, given the caller's stream intent.
/// `accept` is NOT part of SigV4 SignedHeaders, so adding it never affects a Bedrock signature — but
/// a native SDK ALWAYS sends one, so omitting it is a deterministic backend-side proxy fingerprint
/// (a busbar-proxied request carries none where a native one does). Set to what the real SDK emits so
/// the backend cannot separate busbar traffic from native traffic on this header.
///
/// Thin wrapper: dispatches through `ProtocolWriter::egress_accept` so the per-protocol logic (Bedrock
/// → eventstream/json; all others → text/event-stream/json) lives in the writer vtable, not in this
/// agnostic function. Call sites that already hold a resolved writer (`writer.egress_accept(stream)`)
/// bypass this wrapper; it exists for test-code paths that look up by name.
pub(crate) fn egress_accept(egress_protocol: &str, wants_stream: bool) -> &'static str {
    crate::proto::protocol_for(egress_protocol)
        .map(|p| p.writer().egress_accept(wants_stream))
        .unwrap_or(if wants_stream {
            TEXT_EVENT_STREAM
        } else {
            APPLICATION_JSON
        })
}

/// Charge a non-streaming response's token usage to the virtual key's budget, sourced from the IR
/// (Change A). The streaming path bills from `translate.usage()` inside `FirstByteBody`; buffered
/// (non-streaming) cross-protocol responses already decode the egress body egress→IR→ingress, so the
/// terminal `IrUsage` is available WITHOUT a separate byte-scan — bill straight from `ir.usage`.
///
/// Billed tokens = the normalized billable total (A2): `uncached_input + cache_read +
/// cache_creation + output` (see [`crate::ir::IrUsage::billable_tokens`]). Readers normalize
/// `input_tokens` to UNCACHED and keep the cache fields ADDITIVE, so this sum is correct
/// provider-agnostically. This matches the streaming billing arm.
/// OPERATION-BLIND usage recording: project the response IR's neutral `Billing` and record token
/// meters through the existing sink (identical numbers for chat — the Billing round-trip preserves
/// the additive-cache convention). Non-token meters (duration/characters/images/flat) are carried in
/// the client-visible body today and priced by the 1.3 engine; nothing to record here yet.
fn record_resp_usage(
    ir: &crate::ir::variant::IrResp,
    usage_sink: &Option<UsageSink>,
    lane: Option<(&str, &str)>,
) {
    if let Some(crate::billing::Billing::Tokens(t)) = ir.usage() {
        let usage = crate::ir::IrUsage {
            input_tokens: t.input,
            output_tokens: t.output,
            cache_creation_input_tokens: t.cache_creation,
            cache_read_input_tokens: t.cache_read,
        };
        record_ir_usage(&usage, usage_sink, lane);
    } else if let Some(sink) = usage_sink {
        // A delivered response with NO token usage (a flat-fee op, e.g. moderations) still METERS as
        // one request against the serving model — FinOps consumers count requests per model even
        // when nothing token-bills.
        if let Some((model, provider)) = lane {
            sink.gov
                .record_metering(&sink.key_id, model, provider, None, sink.charged_at);
        }
    }
}

/// `lane` is the SERVING lane's `(model, provider)` — the per-model metering attribution. `None`
/// (an unknown/unresolvable lane) still bills the budget but records no metering row.
fn record_ir_usage(
    usage: &crate::ir::IrUsage,
    usage_sink: &Option<UsageSink>,
    lane: Option<(&str, &str)>,
) {
    if let Some(sink) = usage_sink {
        // `billable_tokens` saturates internally — operands are UPSTREAM-CONTROLLED token counts, so
        // an unchecked `+` could panic on overflow in debug / wrap in release (#18). Saturates to
        // `u64::MAX`, matching the streaming path and the saturating `record_tokens` downstream.
        let tokens = usage.billable_tokens();
        if tokens > 0 {
            // Same window as the flat per-request fee (`sink.charged_at`, header-arrival epoch), so
            // the buffered-path token fee and the per-request fee never split across windows (#29).
            sink.gov
                .record_tokens(&sink.key_id, &sink.period, sink.charged_at, tokens);
        }
        // Metering (raw per-model consumption series) records the SPLIT — even a zero-token
        // delivered response counts its request. Same pinned epoch as the budget charges (#29).
        if let Some((model, provider)) = lane {
            sink.gov
                .record_metering(&sink.key_id, model, provider, Some(usage), sink.charged_at);
        }
    }
}

/// The bounded `pool` LABEL for an UPSTREAM/breaker metric (LOW #25).
///
/// The breaker-CELL key (`pool_name`) is `""` for the lane-default cell shared by every
/// direct/ad-hoc (single-model) route — that empty string is the correct CELL key and must NOT be
/// repointed (the cell identity drives breaker state, /stats, /healthz). But emitting it verbatim
/// as the `pool` metric LABEL mislabels all model-routed upstream traffic under an empty-string
/// series, whereas `REQUESTS_TOTAL` (via `ingress::pool_label`) labels the SAME request stream with
/// the MODEL name. That split makes upstream metrics impossible to correlate with the request
/// counter for non-pool traffic. Resolve the metric label to the routed lane's model name when the
/// cell key is empty, leaving named-pool traffic labeled by its pool name. This decouples the metric
/// label from the cell key WITHOUT touching the cell key itself.
fn metric_pool_label<'a>(app: &'a Arc<App>, pool_name: &'a str, i: usize) -> &'a str {
    if pool_name.is_empty() {
        app.lanes[i].model.as_str()
    } else {
        pool_name
    }
}

/// Emit `BREAKER_TRIPS_TOTAL` once for a logical Closed→Open trip on a (pool, lane) cell. Called from
/// the organic forward path's failure-record sites whenever `record_transient_in`/`record_rate_limit_in`
/// reports a fresh trip, mirroring the HardDown arm so threshold-based trips are counted too (#29). The
/// `pool` label is the bounded, operator-controlled canonical pool name, or the routed model name for
/// the default (`""`) cell (LOW #25; see `metric_pool_label`) so it correlates with REQUESTS_TOTAL.
fn emit_breaker_trip(app: &Arc<App>, pool_name: &str, i: usize) {
    metrics::counter!(
        crate::metrics::BREAKER_TRIPS_TOTAL,
        "pool" => metric_pool_label(app, pool_name, i).to_owned(),
        "lane" => app.lanes[i].model.clone()
    )
    .increment(1);
    tracing::warn!(pool = %pool_name, lane = %app.lanes[i].model, "lane breaker tripped (Closed→Open)");
}

/// The effective per-attempt time-to-response-headers cap for pool member `i`: the pool-member
/// override wins over the model-level default (`None` = uncapped). This is the layering the
/// feature promises — the SAME model can be `attempt_timeout_ms: 10000` in a batch pool and
/// `50` in a latency-critical pool, with the model-level value as the fallback for pools (and
/// the default `""` cell) that don't override it.
fn effective_attempt_timeout_ms(
    cands: &[crate::state::WeightedLane],
    i: usize,
    lane_default: Option<u64>,
) -> Option<u64> {
    cands
        .iter()
        .find(|w| w.idx == i)
        .and_then(|w| w.attempt_timeout_ms)
        .or(lane_default)
}

/// The effective per-lane reasoning capability for pool member `i`: the pool-member override wins
/// over the model-level flag (same layering as `effective_attempt_timeout_ms`), default false —
/// a lane never receives thinking params unless some level of config claimed the capability.
fn effective_reasoning(cands: &[crate::state::WeightedLane], i: usize, lane_default: bool) -> bool {
    cands
        .iter()
        .find(|w| w.idx == i)
        .and_then(|w| w.reasoning)
        .unwrap_or(lane_default)
}

/// Floor an `attempt_timeout_ms` cap by the request's remaining wall-clock budget (whole seconds),
/// so a per-attempt cap can never grant MORE time than the request has left — mirroring how the
/// reqwest transport timeout is budget-clamped. `.max(1)` keeps the cap non-zero on a nearly
/// exhausted budget (a zero-duration timeout would fail the attempt before it is even tried).
fn attempt_cap(ms: u64, remaining_secs: u64) -> std::time::Duration {
    std::time::Duration::from_millis(ms.min(remaining_secs.saturating_mul(1000).max(1)))
}

/// The coerced result of running a routing policy at the seam — what the ordered walk should do.
enum PolicyOutcome {
    /// Use this ranked order (the policy returned `Prefer`, or `on_error == first` produced the
    /// config member order). `name` is the policy/transport name for the transparency header.
    Order {
        order: Vec<usize>,
        name: &'static str,
    },
    /// Fall through to today's SWRR (the policy Abstained, or an error coerced to `on_error: weighted`).
    Weighted,
    /// Fail closed with a 503 (`on_error: reject` and the policy errored / timed out).
    Reject,
    /// The policy DELIBERATELY rejected the request (the hook's `reject` verb — a guardrail said
    /// no). Distinct from `Reject` above: that is a degraded "policy unavailable" 503, this is a
    /// first-class 4xx decision. `status` is clamped and `message` sanitized AT THE SEAM that
    /// constructs this variant (`decide_policy_order`'s mapping arm), so the guarantee holds for
    /// every producer of a rejection — wire-backed or direct-constructed.
    RejectRequest {
        status: u16,
        message: String,
        name: &'static str,
    },
    /// The hook's RESTRICT verb: the failover candidate set must be intersected with members carrying
    /// one of `tags_any` BEFORE selection, and that restriction persists across hops. An EMPTY
    /// intersection is fail-closed (`on_empty` default reject) — never allow-all. `tags_any` may be
    /// empty (a fail-closed-normalized malformed restrict), which forces the empty intersection.
    Restrict {
        tags_any: Vec<String>,
        name: &'static str,
        /// Behavior when the intersection is empty: `Reject` (default, fail-closed 503) or `Weighted`
        /// (advisory escape — SWRR over the FULL pool). `First` is treated as `Reject` (a restrict
        /// with no eligible member has no "first" to fall to).
        on_empty: crate::config::PolicyOnError,
    },
}

/// Apply a hook's `rewrite` reply to the INGRESS body, rendered PER DIALECT (the reply carries
/// `{role, content}` messages in body form; each ingress protocol frames conversation content
/// differently). Fail-safe throughout: a body without the dialect's conversation container, or a
/// rewrite message whose content isn't plain text where the dialect needs re-framing, leaves the
/// body untouched and returns `false` — never a corrupted request.
///
/// Dialect rendering:
/// - openai / anthropic / cohere: `messages: [{role, content}]` — inserted verbatim (all three
///   accept string content). Abstract `tools` injection applies here only (their tool shapes are
///   compatible enough to append; the other dialects' tool framings differ — deferred, fail-safe).
/// - bedrock (Converse): `messages: [{role, content: [{text}]}]` — each rewrite message is
///   RE-FRAMED into a one-block text content list (a verbatim insert would corrupt the block
///   shape — bedrock also has a `messages` key, so this arm is load-bearing, not cosmetic).
/// - gemini: `contents: [{role, parts: [{text}]}]` — re-framed, with the role mapping gemini
///   requires (`assistant` → `model`; everything else → `user`).
/// - responses: `input: [{role, content}]` — re-framed into the EasyInputMessage list (string
///   content is accepted); a string `input` is replaced by the list.
fn apply_rewrite_to_body(
    v: &mut Value,
    rewrite: &crate::hooks::wire::RewriteReply,
    ingress_protocol: &str,
) -> bool {
    if rewrite.messages.is_empty() {
        return false;
    }
    let Some(obj) = v.as_object_mut() else {
        return false;
    };
    // Extract (role, text) pairs when a dialect needs re-framing. `None` = a message without
    // plain-string content — abort untouched (fail-safe).
    let as_text_pairs = || -> Option<Vec<(String, String)>> {
        rewrite
            .messages
            .iter()
            .map(|m| {
                let role = m.get("role").and_then(Value::as_str)?.to_string();
                let text = m.get("content").and_then(Value::as_str)?.to_string();
                Some((role, text))
            })
            .collect()
    };
    match ingress_protocol {
        PROTO_BEDROCK => {
            if !obj.get("messages").is_some_and(Value::is_array) {
                return false;
            }
            let Some(pairs) = as_text_pairs() else {
                return false;
            };
            let framed: Vec<Value> = pairs
                .into_iter()
                .map(|(role, text)| {
                    serde_json::json!({ "role": role, "content": [{ "text": text }] })
                })
                .collect();
            obj.insert("messages".to_string(), Value::Array(framed));
            true
        }
        PROTO_GEMINI => {
            if !obj.get("contents").is_some_and(Value::is_array) {
                return false;
            }
            let Some(pairs) = as_text_pairs() else {
                return false;
            };
            let framed: Vec<Value> = pairs
                .into_iter()
                .map(|(role, text)| {
                    // Accept BOTH the canonical `assistant` AND the gemini-native `model` on the
                    // hook's reply — a hook that echoes the role it was PROJECTED (see the
                    // gemini-role canonicalization in build_prompt_projection) or one written to the
                    // gemini vocabulary must both round-trip to `model`, not silently fall through to
                    // `user` and corrupt every assistant turn. (found: audit c1r14.)
                    let g_role = if role == "assistant" || role == "model" {
                        "model"
                    } else {
                        "user"
                    };
                    serde_json::json!({ "role": g_role, "parts": [{ "text": text }] })
                })
                .collect();
            obj.insert("contents".to_string(), Value::Array(framed));
            true
        }
        PROTO_RESPONSES => {
            if obj.get("input").is_none() {
                return false;
            }
            let Some(pairs) = as_text_pairs() else {
                return false;
            };
            let framed: Vec<Value> = pairs
                .into_iter()
                .map(|(role, text)| serde_json::json!({ "role": role, "content": text }))
                .collect();
            obj.insert("input".to_string(), Value::Array(framed));
            true
        }
        // openai / anthropic / cohere: the reply IS the dialect's message shape.
        _ => {
            if !obj.get("messages").is_some_and(Value::is_array) {
                return false;
            }
            obj.insert(
                "messages".to_string(),
                Value::Array(rewrite.messages.clone()),
            );
            if !rewrite.tools.is_empty() {
                match obj.get_mut("tools").and_then(Value::as_array_mut) {
                    Some(existing) => existing.extend(rewrite.tools.iter().cloned()),
                    None => {
                        obj.insert("tools".to_string(), Value::Array(rewrite.tools.clone()));
                    }
                }
            }
            true
        }
    }
}

/// Build the request projection a rewrite (`prompt: rw`) gate receives. The prompt is ALWAYS sent (a
/// rewrite hook is a content hook); identity is omitted (rewrite operates on content, not caller
/// identity — the `user` grant projection for rewrite hooks is a follow-up). Borrows from `v`.
fn build_rewrite_request<'a>(
    v: &'a Value,
    pool_name: &'a str,
    ingress_protocol: &'a str,
    wants_stream: bool,
    with_prompt: bool,
) -> crate::hooks::RoutingRequest<'a> {
    let system_chars = system_text_chars(v, ingress_protocol);
    crate::hooks::RoutingRequest {
        pool: pool_name,
        ingress_protocol,
        requested_model: v.get("model").and_then(|m| m.as_str()),
        message_count: turn_count(v, ingress_protocol),
        tool_count: v
            .get("tools")
            .and_then(|t| t.as_array())
            .map(|a| a.len())
            .unwrap_or(0),
        has_tools: v
            .get("tools")
            .and_then(|t| t.as_array())
            .is_some_and(|a| !a.is_empty()),
        total_chars: total_text_chars(v, ingress_protocol, system_chars),
        system_chars,
        max_tokens: max_tokens_for(v, ingress_protocol),
        stream: wants_stream,
        // A `prompt: rw` rewrite gate needs the prompt content (`with_prompt`). A TAP gets the
        // shape-only default bucket (`with_prompt == false`) — a per-grant prompt projection for
        // `prompt: ro` taps is a follow-up; shape-only never OVER-shares, so the grant holds.
        prompt: with_prompt.then(|| build_prompt_projection(v, ingress_protocol)),
        identity: None,
    }
}

/// The GLOBAL REWRITE (transform) pass: fire each `prompt: rw` gate in PRIORITY order, each seeing the
/// prior gate's output (the projection is rebuilt from the CURRENT body every iteration — a true
/// transform chain), and apply its rewrite to the body in place. FAIL-SAFE end to end: a hook that
/// errors/times out/abstains yields `None` (`transform`) and is skipped; `apply_rewrite_to_body` only
/// touches a chat-shaped body. Zero cost when no rewrite hook is configured (the caller guards on the
/// empty list before calling).
/// Returns `Ok(applied)` — whether ANY rewrite actually committed to the body (the caller must
/// then invalidate every retained copy of the ORIGINAL bytes: the same-protocol pristine
/// short-circuit and the failover re-parse both read them, or the rewrite silently vanishes on
/// those paths) — or `Err((status, message))` when a hook REJECTED the request (audit W-H1:
/// reject > rewrite > abstain on the transform path too; a rw gate that also screens must be able
/// to stop the request — dropping its reject was fail-OPEN from the author's view).
async fn apply_global_rewrites(
    rewrite_hooks: &[(
        std::time::Duration,
        std::sync::Arc<dyn crate::hooks::RoutingPolicy>,
    )],
    v: &mut Value,
    pool_name: &str,
    ingress_protocol: &str,
    wants_stream: bool,
) -> Result<bool, (u16, String)> {
    let mut applied = false;
    for (timeout, hook) in rewrite_hooks {
        // Rebuild the projection from the current body so a later hook sees the earlier rewrite.
        let req = build_rewrite_request(v, pool_name, ingress_protocol, wants_stream, true);
        let outcome = hook.transform(&req, *timeout).await;
        drop(req); // end the immutable borrow of `v` before mutating it
        match outcome {
            busbar_api::TransformOutcome::Rewrite(rw) => {
                applied |= apply_rewrite_to_body(v, &rw, ingress_protocol);
            }
            busbar_api::TransformOutcome::Reject { status, message } => {
                // Already status-clamped + message-sanitized at the wire seam.
                return Err((status, message));
            }
            busbar_api::TransformOutcome::Abstain => {}
        }
    }
    Ok(applied)
}

/// The ingress body's conversation-turn array, DIALECT-AWARE — the READ-side mirror of
/// `apply_rewrite_to_body`'s write dialects: gemini carries turns in `contents`
/// (`{role, parts: [{text}]}`), the Responses API in a list `input` (`{role, content}`), and
/// every other protocol in `messages`. Reading only `messages` here made every projection
/// (rewrite request, `send_prompt`, stage-tap shape) EMPTY on gemini/responses ingress — a
/// rewrite gate saw `message_count: 0` and no prompt, so it abstained and silently no-oped.
fn conversation_turns<'a>(v: &'a Value, ingress_protocol: &str) -> Option<&'a Vec<Value>> {
    let key = match ingress_protocol {
        PROTO_GEMINI => "contents",
        PROTO_RESPONSES => "input",
        _ => "messages",
    };
    v.get(key).and_then(|m| m.as_array())
}

/// Dialect-aware conversation-turn count. The Responses API also allows a bare-string `input`
/// (one implicit user turn) — counted as 1 so the SIZE signal matches what the hook projection
/// yields for the same body.
fn turn_count(v: &Value, ingress_protocol: &str) -> usize {
    match conversation_turns(v, ingress_protocol) {
        Some(turns) => turns.len(),
        None => usize::from(
            ingress_protocol == PROTO_RESPONSES && v.get("input").and_then(Value::as_str).is_some(),
        ),
    }
}

/// Dialect-aware max-output-tokens SIZE signal from the pristine ingress body. The OpenAI Responses
/// API names this field `max_output_tokens` (see `proto::openai_responses`), NOT `max_tokens`, and a
/// pure responses-ingress body never carries `max_tokens` — so reading `max_tokens` unconditionally
/// projected `None` for EVERY responses request, silently blinding any routing policy or tap hook
/// that keys on the size signal. Mirrors the other dialect-aware projections (`turn_count`,
/// `system_text_chars`). Saturating narrow: an absurd cap (> u32::MAX) still signals "huge ask"
/// rather than wrapping to a small number.
fn max_tokens_for(v: &Value, ingress_protocol: &str) -> Option<u32> {
    let key = if ingress_protocol == PROTO_RESPONSES {
        "max_output_tokens"
    } else {
        "max_tokens"
    };
    v.get(key)
        .and_then(|m| m.as_u64())
        .map(|n| u32::try_from(n).unwrap_or(u32::MAX))
}

/// Sum the chars of every `parts[].text` string in a gemini Content object (`systemInstruction`
/// or a `contents[]` turn). Non-text parts (inlineData, functionCall, …) contribute 0.
fn gemini_parts_chars(content: &Value) -> usize {
    content
        .get("parts")
        .and_then(|p| p.as_array())
        .map(|parts| {
            parts
                .iter()
                .filter_map(|p| p.get("text").and_then(|t| t.as_str()))
                .map(|t| t.chars().count())
                .sum()
        })
        .unwrap_or(0)
}

/// Chars of the request's system prompt, DIALECT-AWARE: `system` as a bare string or a block
/// array (Anthropic allows both; blocks keyed on the `text` field's presence, not on `type`),
/// gemini's `systemInstruction` (`{parts: [{text}]}`), or the Responses API's bare-string
/// `instructions`. The SAME shapes `build_prompt_projection` flattens, so the SIZE signal and
/// the opt-in content projection never diverge. Cheap v1 SIZE signal (NOT a token count).
fn system_text_chars(v: &Value, ingress_protocol: &str) -> usize {
    match ingress_protocol {
        PROTO_GEMINI => v
            .get("systemInstruction")
            .map(gemini_parts_chars)
            .unwrap_or(0),
        PROTO_RESPONSES => v
            .get("instructions")
            .and_then(|i| i.as_str())
            .map(|s| s.chars().count())
            .unwrap_or(0),
        _ => match v.get("system") {
            Some(Value::String(s)) => s.chars().count(),
            Some(Value::Array(blocks)) => blocks
                .iter()
                .filter_map(|b| b.get("text").and_then(|t| t.as_str()))
                .map(|t| t.chars().count())
                .sum(),
            _ => 0,
        },
    }
}

/// Total chars across the system prompt + every conversation turn's text content, DIALECT-AWARE.
/// `content` is a bare string or an array of blocks carrying `text` (Anthropic text blocks,
/// Bedrock `[{text}]`, or Responses `input_text` blocks NESTED inside a message's `content[]`);
/// gemini turns carry `parts[].text` instead. The Responses API ALSO allows a TOP-LEVEL typed item
/// directly in `input[]` (`{type: "input_text", text: "…"}`, no `content` key) — that text lives at
/// the item root, so a responses turn with no `content` falls back to its own `text` key (mirroring
/// the proto reader). A best-effort projection over the pristine ingress body — never fails.
fn total_text_chars(v: &Value, ingress_protocol: &str, system_chars: usize) -> usize {
    let mut total = system_chars;
    if let Some(turns) = conversation_turns(v, ingress_protocol) {
        for m in turns {
            if ingress_protocol == PROTO_GEMINI {
                total += gemini_parts_chars(m);
                continue;
            }
            match m.get("content") {
                Some(Value::String(s)) => total += s.chars().count(),
                Some(Value::Array(blocks)) => {
                    for b in blocks {
                        if let Some(t) = b.get("text").and_then(|t| t.as_str()) {
                            total += t.chars().count();
                        }
                    }
                }
                // A top-level Responses `input_text`/`output_text` item carries its text at the
                // item root, not under `content` — count it so the SIZE signal is not blinded.
                _ if ingress_protocol == PROTO_RESPONSES => {
                    if let Some(t) = m.get("text").and_then(Value::as_str) {
                        total += t.chars().count();
                    }
                }
                _ => {}
            }
        }
    } else if ingress_protocol == PROTO_RESPONSES {
        // Bare-string `input` = one implicit user turn.
        if let Some(s) = v.get("input").and_then(Value::as_str) {
            total += s.chars().count();
        }
    }
    total
}

/// Map a hook-chosen reject status to the closest dialect error KIND, so an SDK caller catches the
/// right typed exception: a hook 429 must surface as a rate-limit error, not a permission error.
/// Statuses without a natural kind (400, 422, 451, ...) read as invalid-request; 403 (the reject
/// default) stays a permission error.
fn reject_kind_for_status(status: u16) -> &'static str {
    match status {
        401 => KIND_AUTHENTICATION,
        403 => KIND_PERMISSION,
        404 => KIND_NOT_FOUND,
        408 => KIND_TIMEOUT,
        429 => KIND_RATE_LIMIT,
        _ => KIND_INVALID_REQUEST,
    }
}

/// The request body's end-user identifier, dialect-aware: `user` (OpenAI) first, then
/// `metadata.user_id` (Anthropic). An empty string means "no user id" in EITHER position — an
/// empty `user: ""` falls through to a populated `metadata.user_id` rather than shadowing it,
/// and empty-everywhere coalesces to `None`. Part of the `policy.send_user` identity projection.
fn body_end_user(v: &Value) -> Option<String> {
    v.get("user")
        .and_then(|u| u.as_str())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            v.get("metadata")
                .and_then(|m| m.get("user_id"))
                .and_then(|u| u.as_str())
                .filter(|s| !s.is_empty())
        })
        .map(str::to_string)
}

/// Flatten the ingress body's prompt content into the opt-in hook projection
/// (`policy.send_prompt`). The same content shapes as the SIZE signals (`total_text_chars` /
/// `system_text_chars`) — bare-string content and blocks carrying a `text` string (keyed on the
/// `text` field's presence, not on `type`) — but collecting
/// the text instead of counting the chars. (The flattened text joins blocks with a newline, so
/// its length can exceed the `total_chars` SIZE signal by one char per block boundary — the
/// signal counts text, not separators.) Non-text blocks (images, documents, tool results)
/// contribute NO text, but the message ENTRY is kept (possibly with empty text and, for a
/// malformed body, an empty role): entries stay index-aligned with the body's `messages` and with
/// `message_count`, so a screening hook sees every turn — a media-only turn reads as
/// `{role, text: ""}`, never silently vanishes. Bare-string content BORROWS from the parsed body
/// (`Cow::Borrowed`, the common case); only block arrays allocate a joined string. Runs ONLY
/// behind the per-pool opt-in, so even that cost never touches a default pool.
fn build_prompt_projection<'a>(
    v: &'a Value,
    ingress_protocol: &str,
) -> crate::hooks::PromptProjection<'a> {
    use std::borrow::Cow;
    // A content value is a bare string (borrowed as-is) or an array of blocks (text blocks joined
    // by newline into an owned string).
    fn flatten_content(c: Option<&Value>) -> Cow<'_, str> {
        match c {
            Some(Value::String(s)) => Cow::Borrowed(s.as_str()),
            Some(Value::Array(blocks)) => {
                let mut out = String::new();
                for b in blocks {
                    if let Some(t) = b.get("text").and_then(|t| t.as_str()) {
                        if !out.is_empty() {
                            out.push('\n');
                        }
                        out.push_str(t);
                    }
                }
                Cow::Owned(out)
            }
            _ => Cow::Borrowed(""),
        }
    }
    // A gemini Content object: join `parts[].text` with newlines (mirrors `gemini_parts_chars`,
    // which counts what this flattens). Borrows a lone text part (the common case).
    fn flatten_gemini_parts(c: &Value) -> Cow<'_, str> {
        match c.get("parts").and_then(|p| p.as_array()) {
            Some(parts) => {
                let mut texts = parts
                    .iter()
                    .filter_map(|p| p.get("text").and_then(|t| t.as_str()))
                    .peekable();
                match texts.next() {
                    Some(first) if texts.peek().is_none() => Cow::Borrowed(first),
                    Some(first) => {
                        let mut out = String::from(first);
                        for t in texts {
                            out.push('\n');
                            out.push_str(t);
                        }
                        Cow::Owned(out)
                    }
                    None => Cow::Borrowed(""),
                }
            }
            None => Cow::Borrowed(""),
        }
    }
    let system = match ingress_protocol {
        PROTO_GEMINI => v.get("systemInstruction").map(flatten_gemini_parts),
        PROTO_RESPONSES => v
            .get("instructions")
            .and_then(|i| i.as_str())
            .map(Cow::Borrowed),
        _ => v.get("system").map(|s| flatten_content(Some(s))),
    }
    .filter(|s| !s.is_empty());
    let messages = match conversation_turns(v, ingress_protocol) {
        Some(turns) => turns
            .iter()
            .map(|m| {
                let text = if ingress_protocol == PROTO_GEMINI {
                    flatten_gemini_parts(m)
                } else if ingress_protocol == PROTO_RESPONSES && m.get("content").is_none() {
                    // A top-level Responses typed item (`{type: "input_text"/"output_text", text}`)
                    // carries its text at the item root, not under `content`.
                    m.get("text")
                        .and_then(Value::as_str)
                        .map_or(Cow::Borrowed(""), Cow::Borrowed)
                } else {
                    flatten_content(m.get("content"))
                };
                let role: Cow<'_, str> = match m.get("role").and_then(|r| r.as_str()) {
                    // CANONICALIZE the gemini-native assistant role `model` → `assistant` so a
                    // `prompt: rw` hook sees the SAME canonical-IR vocabulary on every dialect (the
                    // hook contract promises normalized IR). Without this a hook that echoes the role
                    // it received emitted `model`, which the gemini write-back then mapped to `user`,
                    // silently corrupting assistant turns. Mirrors the responses arm below. (c1r14.)
                    Some("model") if ingress_protocol == PROTO_GEMINI => Cow::Borrowed("assistant"),
                    Some(r) => Cow::Borrowed(r),
                    // Top-level typed item without a `role`: infer from its `type` so a `prompt: rw`
                    // hook sees the correct speaker (`output_text` = assistant, else user).
                    None if ingress_protocol == PROTO_RESPONSES => {
                        match m.get("type").and_then(Value::as_str) {
                            Some("output_text") => Cow::Borrowed("assistant"),
                            _ => Cow::Borrowed("user"),
                        }
                    }
                    None => Cow::Borrowed(""),
                };
                (role, text)
            })
            .collect(),
        // The Responses API's bare-string `input` = one implicit user turn.
        None if ingress_protocol == PROTO_RESPONSES => v
            .get("input")
            .and_then(Value::as_str)
            .map(|s| vec![(Cow::Borrowed("user"), Cow::Borrowed(s))])
            .unwrap_or_default(),
        None => Vec::new(),
    };
    crate::hooks::PromptProjection { system, messages }
}

/// Build the routing projection (request + candidates + context) and run the resolved policy ONCE,
/// bounded by its configured timeout, coercing the result to a `PolicyOutcome` per `on_error`.
///
/// This runs ONLY for a pool with a non-default `route:` — the zero-cost default path never calls it
/// and never constructs any of these projection types. Every signal is REAL data: `cost_per_mtok`
/// from member config, `latency_ms` from the per-lane EWMA, `available_concurrency` from the lane
/// semaphore, `budget_remaining` from the lane budget, and `rate_headroom` from the caller key's
/// governance rate window. A policy error/timeout NEVER reaches the client: it degrades per `on_error`
/// (weighted / reject / first).
#[allow(clippy::too_many_arguments)]
async fn decide_policy_order(
    app: &Arc<App>,
    resolved: &crate::hooks::ResolvedPolicy,
    cands: &[WeightedLane],
    request_ctx: &RequestCtx,
    v: &Value,
    pool_name: &str,
    ingress_protocol: &str,
    wants_stream: bool,
    caller_token: Option<&str>,
    resolved_gov_key: Option<&crate::governance::VirtualKey>,
) -> PolicyOutcome {
    use crate::hooks::{
        Candidate, ResolvedPolicy, RoutingContext, RoutingDecision, RoutingRequest,
    };

    // A weighted/default pool resolves to `None` at config load (no policy object is constructed), so
    // the only `ResolvedPolicy` that can reach this seam is a constructed `Policy`.
    let (policy, on_error, on_error_chain, timeout, send_prompt, send_user, on_empty) =
        match resolved {
            ResolvedPolicy::Policy {
                policy,
                on_error,
                on_error_chain,
                timeout,
                send_prompt,
                send_user,
                on_empty,
            } => (
                policy,
                on_error,
                on_error_chain,
                *timeout,
                *send_prompt,
                *send_user,
                on_empty,
            ),
        };

    // The candidate set the policy ranks over = this pool's members MINUS the already-excluded ones
    // (configured exclusions). `idx` is the stable lane handle the ordered walk speaks.
    let mut live_buf: Vec<&WeightedLane> = Vec::with_capacity(cands.len());
    request_ctx.fill_candidates(cands, &mut live_buf);
    let live = &live_buf;
    if live.is_empty() {
        // Nothing to rank — let the loop's exhaustion handling take over (SWRR will also find none).
        return PolicyOutcome::Weighted;
    }

    // ONE governance key serves both consumers: the per-key rate headroom (always, same value
    // across candidates today — rate limits are per-key; see `Candidate.rate_headroom`) and, behind
    // `policy.send_user`, the caller identity projection. A virtual-key caller resolves via
    // `lookup` (which CONSUMES the secret; only the returned key RECORD flows forward — nothing
    // downstream sees the token). A GROUP/SSO principal's token is NOT a virtual-key secret, so
    // `lookup` misses — fall back to the key the auth layer already SYNTHESIZED for it (carried in
    // `GovCtx.key`, threaded here as `resolved_gov_key`). Without this fallback `rate_headroom` and
    // `identity` were silently `None` for every group principal, blinding usage/identity policies.
    let gov = app.governance.as_ref();
    let gov_key = match (gov, caller_token) {
        (Some(g), Some(tok)) => g.lookup(tok),
        _ => None,
    }
    .or_else(|| resolved_gov_key.cloned());
    let rate_headroom: Option<f64> = match (gov, gov_key.as_ref()) {
        (Some(g), Some(key)) => g.rate_headroom(key, now()),
        _ => None,
    };

    // `policy.send_user` opt-in (default off): project the caller identity — the virtual key's
    // id/name (from the resolved record, NEVER the token) plus the body's end-user field (`user` in
    // the OpenAI dialect, `metadata.user_id` in the Anthropic dialect).
    let identity = if send_user {
        let body_user = body_end_user(v);
        Some(crate::hooks::CallerIdentity {
            key_id: gov_key.as_ref().map(|k| k.id.clone()),
            key_name: gov_key.as_ref().map(|k| k.name.clone()),
            user: body_user,
        })
    } else {
        None
    };

    // `policy.send_prompt` opt-in (default off): flatten the prompt content for the hook. The
    // allocation cost lives entirely behind the flag — a shape-only pool never runs this.
    let prompt = if send_prompt {
        Some(build_prompt_projection(v, ingress_protocol))
    } else {
        None
    };

    let member_meta = app.pool_runtime.get(pool_name).map(|r| &r.members);

    // Count the system prompt's chars ONCE: it feeds both `total_chars` (via `total_text_chars`) and
    // `system_chars`, so computing it inline twice would run the O(n) UTF-8 scan over the system block
    // twice. Off the zero-cost default path (only non-default route policies reach here).
    let system_chars = system_text_chars(v, ingress_protocol);

    let req = RoutingRequest {
        pool: pool_name,
        ingress_protocol,
        requested_model: v.get("model").and_then(|m| m.as_str()),
        message_count: turn_count(v, ingress_protocol),
        tool_count: v
            .get("tools")
            .and_then(|t| t.as_array())
            .map(|a| a.len())
            .unwrap_or(0),
        has_tools: v
            .get("tools")
            .and_then(|t| t.as_array())
            .is_some_and(|a| !a.is_empty()),
        total_chars: total_text_chars(v, ingress_protocol, system_chars),
        system_chars,
        // Saturating narrow (in `max_tokens_for`): an absurd caller cap (> u32::MAX) still signals
        // "huge ask" to the policy instead of wrapping to a small number. A SIZE signal, not a limit.
        max_tokens: max_tokens_for(v, ingress_protocol),
        stream: wants_stream,
        prompt,
        identity,
    };

    let candidates: Vec<Candidate> = live
        .iter()
        .map(|wl| {
            let lane = &app.lanes[wl.idx];
            let meta = member_meta.and_then(|m| m.get(&wl.idx));
            Candidate {
                idx: wl.idx,
                model: &lane.model,
                provider: &lane.provider,
                weight: wl.weight,
                context_max: lane.context_max,
                tier: meta.and_then(|m| m.tier.as_deref()),
                cost_per_mtok: meta.and_then(|m| m.cost_per_mtok),
                tags: meta.map(|m| m.tags.as_slice()).unwrap_or(&[]),
                latency_ms: app.store.lane_latency_ms(wl.idx),
                available_concurrency: app.store.available_permits(wl.idx),
                budget_remaining: app.store.lane_budget_remaining(wl.idx),
                rate_headroom,
            }
        })
        .collect();

    let ctx = RoutingContext {
        pool: pool_name,
        // The per-key governance BUDGET is intentionally NOT fed to the routing seam: budget is an
        // admission concern (enforced upstream of routing), not a lane-selection signal, so exposing
        // it here would let a policy reshape traffic on a quantity that does not describe lane health.
        // The per-key RATE signal IS surfaced — as each lane's `rate_headroom` above (the RPM/TPM
        // fraction remaining), which is a legitimate "is this key near its limit" routing input.
        budget_remaining: None,
    };

    // Run the decision under a HARD wall-clock timeout (the policy is also asked to respect `budget`).
    // A timeout or an `Err` is coerced to `on_error`; an impl that simply has no opinion returns
    // `Ok(Abstain)`. The decision NEVER blocks past `timeout` and NEVER propagates an error to the
    // client.
    let decision: RoutingDecision = match tokio::time::timeout(
        timeout,
        policy.decide(&req, &candidates, &ctx, timeout),
    )
    .await
    {
        Ok(Ok(d)) => d,
        // Policy errored: apply on_error — but LOG the error first. A hook binary that is down,
        // deadline-exceeded, or replying garbage would otherwise fail silently on every request
        // (the pool degrades to on_error with no operator-visible signal that the hook is broken).
        Ok(Err(e)) => {
            tracing::warn!(
                policy = policy.name(),
                pool = pool_name,
                error = %e,
                "routing policy failed; applying on_error fallback"
            );
            return run_on_error_chain(
                on_error_chain,
                on_error,
                &req,
                &candidates,
                &ctx,
                policy.name(),
                pool_name,
            )
            .await;
        }
        // Timed out at the seam's own hard deadline: same fallback, same visibility. The policy/
        // transport stays cancel-safe — a dropped future on timeout is fine.
        Err(_) => {
            tracing::warn!(
                policy = policy.name(),
                pool = pool_name,
                timeout_ms = timeout.as_millis() as u64,
                "routing policy deadline exceeded; applying on_error fallback"
            );
            return run_on_error_chain(
                on_error_chain,
                on_error,
                &req,
                &candidates,
                &ctx,
                policy.name(),
                pool_name,
            )
            .await;
        }
    };

    map_decision(decision, policy.name(), &candidates, on_empty)
}

/// Walk a failed gate's resolved `on_error` fallback CHAIN: fire each fallback in order (bounded by
/// ITS deadline, projected per ITS grants — a fallback never sees prompt/identity its own grants
/// don't allow), and let the FIRST one that answers decide, exactly as a primary decision would.
/// Every link failing lands on the chain's reserved TERMINAL (weighted/reject/first). The common
/// case — `on_error: weighted` etc. — has an EMPTY chain and goes straight to the terminal.
async fn run_on_error_chain(
    chain: &[crate::hooks::FallbackHook],
    terminal: &crate::config::PolicyOnError,
    req: &crate::hooks::RoutingRequest<'_>,
    candidates: &[crate::hooks::Candidate<'_>],
    ctx: &crate::hooks::RoutingContext<'_>,
    failed_policy_name: &'static str,
    pool_name: &str,
) -> PolicyOutcome {
    for fb in chain {
        // Re-project per the FALLBACK's grants: it may see at most what the primary projection
        // built AND its own grants allow (never over-shares; a fallback with a grant the primary
        // lacked gets shape-only — the projection was never built).
        let fb_req = crate::hooks::RoutingRequest {
            prompt: if fb.send_prompt {
                req.prompt.clone()
            } else {
                None
            },
            identity: if fb.send_user {
                req.identity.clone()
            } else {
                None
            },
            ..req.clone()
        };
        match tokio::time::timeout(
            fb.timeout,
            fb.policy.decide(&fb_req, candidates, ctx, fb.timeout),
        )
        .await
        {
            Ok(Ok(decision)) => {
                tracing::info!(
                    policy = failed_policy_name,
                    fallback = fb.policy.name(),
                    pool = pool_name,
                    "on_error fallback hook answered for the failed gate"
                );
                return map_decision(decision, fb.policy.name(), candidates, &fb.on_empty);
            }
            // This link failed too — follow the chain to the next (its own on_error was flattened
            // into this chain at resolution).
            Ok(Err(e)) => {
                tracing::warn!(
                    fallback = fb.policy.name(),
                    pool = pool_name,
                    error = %e,
                    "on_error fallback hook failed; continuing down the chain"
                );
            }
            Err(_) => {
                tracing::warn!(
                    fallback = fb.policy.name(),
                    pool = pool_name,
                    timeout_ms = fb.timeout.as_millis() as u64,
                    "on_error fallback hook deadline exceeded; continuing down the chain"
                );
            }
        }
    }
    coerce_on_error(terminal, candidates, failed_policy_name)
}

/// Map a policy's `RoutingDecision` to the seam's `PolicyOutcome` — shared by the primary decision
/// and every on_error fallback, so a fallback's reject/restrict/order carries the same clamping,
/// sanitizing, and normalization guarantees as a primary's.
fn map_decision(
    decision: crate::hooks::RoutingDecision,
    policy_name: &'static str,
    candidates: &[crate::hooks::Candidate<'_>],
    on_empty: &crate::config::PolicyOnError,
) -> PolicyOutcome {
    use crate::hooks::RoutingDecision;

    match decision {
        RoutingDecision::Prefer(order) => {
            // Normalize against the valid candidate idxs (drop unknown, dedup). An empty result is
            // Abstain — fall through to SWRR.
            let valid: std::collections::HashSet<usize> =
                candidates.iter().map(|c| c.idx).collect();
            match RoutingDecision::from_ranked(order, &valid) {
                RoutingDecision::Prefer(o) => PolicyOutcome::Order {
                    order: o,
                    name: policy_name,
                },
                RoutingDecision::Abstain => PolicyOutcome::Weighted,
                // `from_ranked` only ever produces Prefer/Abstain — it normalizes an order, it
                // cannot invent a rejection or a restriction.
                RoutingDecision::Reject { .. } => unreachable!("from_ranked never rejects"),
                RoutingDecision::Restrict { .. } => {
                    unreachable!("from_ranked never restricts")
                }
            }
        }
        // Abstain is the clean "no opinion" — today's exact SWRR (NOT coerced via on_error).
        RoutingDecision::Abstain => PolicyOutcome::Weighted,
        // The hook's reject verb: a deliberate first-class decision (a guardrail said no), NOT an
        // error — `on_error` does not apply. The shipped transports produce Reject only through
        // `wire::normalize` (clamped + sanitized), but the trait lets ANY policy impl construct
        // the variant directly — so the seam re-clamps the status to 400..=499 (else 403) AND
        // re-sanitizes the message (same shared sanitizer, idempotent on already-clean input) as
        // defense in depth: no policy, present or future, can mint a success/redirect/5xx or a
        // log/client-injecting message through this path.
        RoutingDecision::Reject { status, message } => PolicyOutcome::RejectRequest {
            status: crate::hooks::wire::clamp_reject_status(status),
            message: crate::hooks::wire::sanitize_reject_message(&message),
            name: policy_name,
        },
        // The hook's RESTRICT verb: keep only candidates carrying one of `tags_any` (a compliance
        // gate). The intersection + on_empty are applied at the failover-set seam in `forward_with_
        // pool`; here we just carry the tag set through. An empty `tags_any` (malformed restrict,
        // normalized fail-closed) forces the empty intersection → on_empty, never allow-all.
        RoutingDecision::Restrict { tags_any } => PolicyOutcome::Restrict {
            tags_any,
            name: policy_name,
            on_empty: on_empty.clone(),
        },
    }
}

/// Coerce an `on_error` fallback into a `PolicyOutcome` when the policy errored / timed out:
/// `weighted` ⇒ SWRR, `first` ⇒ the config member order (a deterministic degraded pick), `reject`
/// ⇒ a 503. `first` advertises the policy name so the degraded pick is still observable.
fn coerce_on_error(
    on_error: &crate::config::PolicyOnError,
    candidates: &[crate::hooks::Candidate<'_>],
    policy_name: &'static str,
) -> PolicyOutcome {
    use crate::config::PolicyOnError;
    match on_error {
        PolicyOnError::Weighted => PolicyOutcome::Weighted,
        PolicyOnError::Reject => PolicyOutcome::Reject,
        PolicyOnError::First => PolicyOutcome::Order {
            order: candidates.iter().map(|c| c.idx).collect(),
            name: policy_name,
        },
    }
}

/// Shape scalars captured ONCE per request for the STAGE tap payloads (route/attempt/completion).
/// All owned/`'static`-free scalars except the pool/protocol names (which outlive the request), so
/// the capture survives `v` being consumed by the first dispatch hop. Stage taps are SHAPE-ONLY in
/// this increment: the default signal bucket plus the stage object — never prompt content or caller
/// identity, regardless of grant (never over-shares; a granted tap still gets content at the
/// `request` stage).
pub(crate) struct StageShape<'a> {
    pool: &'a str,
    ingress_protocol: &'a str,
    message_count: usize,
    has_tools: bool,
    total_chars: usize,
    max_tokens: Option<u32>,
    stream: bool,
}

/// Capture the stage-tap shape from the parsed body (`None` = an opaque/binary body: zeroed shape).
pub(crate) fn capture_stage_shape<'a>(
    v: Option<&Value>,
    pool: &'a str,
    ingress_protocol: &'a str,
    stream: bool,
) -> StageShape<'a> {
    let (message_count, has_tools, total_chars, max_tokens) = match v {
        Some(v) => {
            let system_chars = system_text_chars(v, ingress_protocol);
            (
                turn_count(v, ingress_protocol),
                v.get("tools")
                    .and_then(|t| t.as_array())
                    .is_some_and(|a| !a.is_empty()),
                total_text_chars(v, ingress_protocol, system_chars),
                max_tokens_for(v, ingress_protocol),
            )
        }
        None => (0, false, 0, None),
    };
    StageShape {
        pool,
        ingress_protocol,
        message_count,
        has_tools,
        total_chars,
        max_tokens,
        stream,
    }
}

/// Fire one STAGE's taps (route/attempt/completion) fire-and-forget: serialize the shape-only
/// projection + stage object ONCE, then spawn one detached task per tap. A tap can never delay,
/// reorder, or fail the request; a serialization failure silently skips the fire (observation is
/// best-effort). ZERO COST when the stage has no taps (first-line empty check).
pub(crate) fn fire_stage_taps(
    taps: &[(
        std::time::Duration,
        bool,
        Arc<dyn crate::hooks::RoutingPolicy>,
    )],
    shape: &StageShape<'_>,
    stage: crate::hooks::wire::HookStageProjection<'_>,
) {
    if taps.is_empty() {
        return;
    }
    let hook_req = crate::hooks::wire::HookRequest {
        op: crate::hooks::wire::OP_NOTIFY,
        request: crate::hooks::wire::HookReqProjection {
            pool: shape.pool,
            ingress_protocol: shape.ingress_protocol,
            message_count: shape.message_count,
            has_tools: shape.has_tools,
            total_chars: shape.total_chars,
            max_tokens: shape.max_tokens,
            stream: shape.stream,
            system: None,
            messages: None,
            user: None,
        },
        candidates: Vec::new(),
        context: crate::hooks::wire::HookContext {
            budget_remaining: None,
        },
        stage: Some(stage),
    };
    let Ok(bytes) = serde_json::to_vec(&hook_req) else {
        return;
    };
    let bytes = std::sync::Arc::new(bytes);
    for (timeout, _send_prompt, hook) in taps {
        let policy = hook.clone();
        let budget = *timeout;
        let proj = bytes.clone();
        tokio::spawn(async move { policy.notify(&proj, budget).await });
    }
}

/// Response-extension marker set by every GATE-produced rejection return, so the completion-stage
/// taps can report the SYNTHETIC `rejected_by_gate` outcome (audit taps see denials) instead of a
/// generic `failed`.
#[derive(Clone)]
struct GateRejected;

/// Tag a gate-produced rejection response with the [`GateRejected`] marker.
fn gate_rejected(mut resp: Response) -> Response {
    resp.extensions_mut().insert(GateRejected);
    resp
}

/// Forward with pool name context for on_exhausted config lookup.
/// Thin wrapper: parse the body ONCE for callers that only hold bytes (tests, ad-hoc routes), then
/// delegate. The ingress hot path (`ingress::forward_resolved`) instead calls
/// [`forward_with_pool_parsed`] directly with the `Value` it ALREADY parsed to resolve the model —
/// so a normal request parses the body once across the route+forward layers, not twice.
///
/// Carries NO pre-resolved governance key — a virtual-key caller still resolves via the token
/// `lookup` inside `decide_policy_order`. Real ingress routes that hold a `GovCtx` (whose key may be
/// a SYNTHESIZED group/SSO principal key the token can't resolve to) must call
/// [`forward_with_pool_keyed`] and pass `gov.key.as_ref()` so the routing-signal path is not blind.
///
/// Test-only convenience now: every production ingress route holds a `GovCtx` and goes through
/// [`forward_with_pool_keyed`]; this bytes-only, key-less form survives solely for the many tests
/// that construct a request from raw bytes.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn forward_with_pool(
    app: Arc<App>,
    cands: Vec<WeightedLane>,
    body: Bytes,
    caller_token: Option<&str>,
    pool_name: &str,
    affinity_key: Option<&str>,
    ingress_protocol: &str,
    op: crate::handlers::Op,
    usage_sink: Option<UsageSink>,
) -> Response {
    forward_with_pool_keyed(
        app,
        cands,
        body,
        caller_token,
        None,
        pool_name,
        affinity_key,
        ingress_protocol,
        op,
        usage_sink,
    )
    .await
}

/// [`forward_with_pool`] plus the caller's pre-resolved governance key (`GovCtx.key`). The named /
/// ad-hoc anthropic-dialect routes use this so a GROUP/SSO principal — whose bearer token is not a
/// virtual-key secret and so never resolves via the `lookup` fallback — still projects
/// `rate_headroom` / `identity` into a pool's routing policy, matching the universal dispatch path.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn forward_with_pool_keyed(
    app: Arc<App>,
    cands: Vec<WeightedLane>,
    body: Bytes,
    caller_token: Option<&str>,
    resolved_gov_key: Option<&crate::governance::VirtualKey>,
    pool_name: &str,
    affinity_key: Option<&str>,
    ingress_protocol: &str,
    op: crate::handlers::Op,
    usage_sink: Option<UsageSink>,
) -> Response {
    let v: Value = match crate::json::parse(&body) {
        Ok(v) => v,
        Err(_) => {
            tracing::debug!(detail = %crate::json::parse_err_log(body.len()), "request body JSON parse failed");
            return ingress_error(
                ingress_protocol,
                StatusCode::BAD_REQUEST,
                KIND_INVALID_REQUEST,
                "We could not parse the JSON body of your request.",
            );
        }
    };
    forward_with_pool_parsed(
        app,
        cands,
        body,
        Some(v),
        APPLICATION_JSON,
        caller_token,
        resolved_gov_key,
        pool_name,
        affinity_key,
        ingress_protocol,
        op,
        usage_sink,
    )
    .await
}

/// The forward implementation. `v` is the request body ALREADY parsed by the caller (the ingress
/// layer parses it to resolve the model; tests/ad-hoc go through [`forward_with_pool`] which parses).
/// The retained `body` bytes are re-parsed only on failover hops 2+, preserving the per-hop pristine
/// re-parse the mixed-protocol-pool correctness depends on.
//
// Plumbing function: each parameter is an independent request input (state, candidates, body, parsed
// body, caller token, pool name, affinity key, ingress protocol, usage sink) with no natural grouping.
#[allow(clippy::too_many_arguments)]
#[tracing::instrument(
    name = "forward",
    skip_all,
    fields(pool = %pool_name, ingress = %ingress_protocol, op = op.name())
)]
pub(crate) async fn forward_with_pool_parsed(
    app: Arc<App>,
    cands: Vec<WeightedLane>,
    body: Bytes,
    v: Option<Value>,
    req_content_type: &str,
    caller_token: Option<&str>,
    resolved_gov_key: Option<&crate::governance::VirtualKey>,
    pool_name: &str,
    affinity_key: Option<&str>,
    ingress_protocol: &str,
    op: crate::handlers::Op,
    usage_sink: Option<UsageSink>,
) -> Response {
    // ── STAGE TAPS: completion ── capture the shape BEFORE `v` moves into the dispatch core, fire
    // AFTER the response head is known. `outcome`: a gate-produced rejection (marker extension) is
    // the SYNTHETIC `rejected_by_gate`; else 2xx = `ok`, anything else = `failed`. For a STREAMING
    // response this fires at response-HEAD time (status known, body still flowing) — stream-tail
    // outcomes are a later increment. ZERO COST when no completion tap is configured.
    let completion_shape = if app.tap_hooks_completion.is_empty() {
        None
    } else {
        Some(capture_stage_shape(
            v.as_ref(),
            pool_name,
            ingress_protocol,
            v.as_ref()
                .and_then(|b| b.get("stream"))
                .and_then(|s| s.as_bool())
                .unwrap_or(false),
        ))
    };
    let completion_app = app.clone();
    let resp = forward_with_pool_parsed_inner(
        app,
        cands,
        body,
        v,
        req_content_type,
        caller_token,
        resolved_gov_key,
        pool_name,
        affinity_key,
        ingress_protocol,
        op,
        usage_sink,
    )
    .await;
    if let Some(shape) = completion_shape {
        let outcome = if resp.extensions().get::<GateRejected>().is_some() {
            "rejected_by_gate"
        } else if resp.status().is_success() {
            "ok"
        } else {
            "failed"
        };
        fire_stage_taps(
            &completion_app.tap_hooks_completion,
            &shape,
            crate::hooks::wire::HookStageProjection {
                at: "completion",
                model: None,
                attempt_number: None,
                remaining_candidates: None,
                previous_failure: None,
                outcome: Some(outcome),
                status: Some(resp.status().as_u16()),
            },
        );
    }
    resp
}

/// The dispatch core behind [`forward_with_pool_parsed`] (the thin wrapper exists only to fire the
/// completion-stage taps around the whole request).
//
// Plumbing function: same parameter set as the public wrapper.
#[allow(clippy::too_many_arguments)]
async fn forward_with_pool_parsed_inner(
    app: Arc<App>,
    cands: Vec<WeightedLane>,
    mut body: Bytes,
    // The request body parsed ONCE by the caller for JSON-body operations; `None` for an OPAQUE
    // ingress body (multipart transcription, binary) — those relay/translate at the BYTE level via
    // the operation codecs and skip every JSON-only read below. `mut` so the global rewrite pass can
    // mutate it before dispatch.
    mut v: Option<Value>,
    // The ingress request Content-Type — the byte-level codec's parse hint (multipart boundary).
    req_content_type: &str,
    caller_token: Option<&str>,
    // The key the auth layer already resolved/synthesized for this caller (`GovCtx.key`) — used as
    // the routing-signal source when the token is not a virtual-key secret (group/SSO principals).
    resolved_gov_key: Option<&crate::governance::VirtualKey>,
    pool_name: &str,
    affinity_key: Option<&str>,
    ingress_protocol: &str,
    // A request's identity is (operation, protocol): `ingress_protocol` is the wire language,
    // `op` is the kind of work. Everything below is the engine carrying that pair through pool
    // selection, failover, the breaker, and billing. The engine reads only capabilities off the
    // spec, never its identity; `crate::handlers::CHAT` reproduces today's behavior byte-for-byte.
    op: crate::handlers::Op,
    usage_sink: Option<UsageSink>,
) -> Response {
    // EGRESS deletion switch (design §3, same contract as `forward_operation`): every candidate
    // lane's protocol must HOLD this operation's handler. A protocol whose handler was deleted is
    // not a valid egress for the operation — a clean no-handler 404 in the CALLER's dialect, never a
    // silent dispatch. Dormant while all six protocols serve chat; load-bearing the moment one is
    // removed (the deletion test).
    let mut cands: Vec<WeightedLane> = {
        let (kept, dropped): (Vec<WeightedLane>, Vec<WeightedLane>) =
            cands.into_iter().partition(|wl| {
                crate::handlers::request_handler(app.lanes[wl.idx].protocol.name())
                    .and_then(|rh| rh.operation_handler(op.operation))
                    .is_some()
            });
        if kept.is_empty() && !dropped.is_empty() {
            return ingress_error(
                ingress_protocol,
                StatusCode::NOT_FOUND,
                KIND_NOT_FOUND,
                DETAIL_MODEL_UNSUPPORTED_OPERATION,
            );
        }
        kept
    };
    // `v` is the PRISTINE parsed request body (parsed once by the caller). Never mutated after this
    // point: each failover hop derives a fresh per-hop `hop_v` (the first hop consumes `v`; hops 2+
    // re-parse the retained `body` bytes) before translating/rewriting, so a cross-protocol hop never
    // re-translates a body already rewritten into a previous egress lane's shape (the bug: mutating a
    // shared `v` in place made hop N+1 read hop N's egress-shaped body with the ingress reader,
    // misparsing or skipping translation entirely on a mixed-protocol pool).

    // capture the caller's stream intent from the ingress body BEFORE any cross-protocol
    // translation rewrites `v` (Gemini routes streaming requests to a different upstream endpoint).
    // Delegated to the operation: chat reads the OpenAI-family `stream` boolean (byte-identical to
    // the previous inline read); a non-streaming op always returns false.
    let wants_stream = v.as_ref().map(|v| op.wants_stream(v)).unwrap_or(false);

    // ── GLOBAL REWRITE (transform) PASS ─────────────────────────────────────────────────────────
    // Fire the global `prompt: rw` gates (compression/redaction) BEFORE dispatch AND before the
    // routing decision, so the decision + upstream both see the rewritten body. Priority-ordered
    // transform chain; fail-safe throughout (a broken hook is skipped, a non-chat body is untouched).
    // ZERO COST when no rewrite hook is configured — the common case is a single always-false branch.
    // The pool's own rewrite chain (rw gates in its `hooks: [...]` list) fires AFTER the globals —
    // each chain internally priority-ordered, globals always first.
    let pool_rewrites: &[(
        std::time::Duration,
        std::sync::Arc<dyn crate::hooks::RoutingPolicy>,
    )] = app
        .pool_runtime
        .get(pool_name)
        .map(|r| r.rewrite_hooks.as_slice())
        .unwrap_or(&[]);
    if !app.rewrite_hooks.is_empty() || !pool_rewrites.is_empty() {
        if let Some(parsed) = v.as_mut() {
            // A rewrite hook's REJECT stops the request here — the same client shaping a decide-
            // path gate rejection gets (clamped status, sanitized message, native envelope).
            let reject = |status: u16, message: String| {
                tracing::info!(
                    pool = pool_name,
                    status,
                    message = %message,
                    "rewrite gate rejected the request"
                );
                gate_rejected(ingress_error(
                    ingress_protocol,
                    StatusCode::from_u16(status).unwrap_or(StatusCode::FORBIDDEN),
                    reject_kind_for_status(status),
                    &message,
                ))
            };
            let mut applied = match apply_global_rewrites(
                &app.rewrite_hooks,
                parsed,
                pool_name,
                ingress_protocol,
                wants_stream,
            )
            .await
            {
                Ok(a) => a,
                Err((status, message)) => return reject(status, message),
            };
            applied |= match apply_global_rewrites(
                pool_rewrites,
                parsed,
                pool_name,
                ingress_protocol,
                wants_stream,
            )
            .await
            {
                Ok(a) => a,
                Err((status, message)) => return reject(status, message),
            };
            // A committed rewrite makes the RETAINED bytes stale: the same-protocol pristine
            // short-circuit re-emits them verbatim, and failover hops 2+ re-parse them — either
            // path would silently discard the rewrite. Re-serialize the rewritten body as the new
            // retained bytes so every downstream reader of `body` sees the effective request.
            // Cost only on the rewrite path (a no-op request never reaches this serialize).
            if applied {
                match crate::json::to_vec(parsed) {
                    Ok(bytes) => body = Bytes::from(bytes),
                    // Serialization of a Value we just built cannot realistically fail; if it
                    // somehow does, keep the original bytes (the pre-rewrite request is still a
                    // valid request — fail-safe, never a corrupted body).
                    Err(e) => {
                        tracing::warn!(error = %e, "re-serializing rewritten body failed; keeping the original bytes");
                    }
                }
            }
        }
    }

    // ── GLOBAL TAP (observe) FIRE ────────────────────────────────────────────────────────────────
    // Fire the global request-stage `kind: tap` hooks FIRE-AND-FORGET: serialize the projection(s) to
    // owned bytes ONCE, then spawn one detached task per tap. A tap gets a write-only send with its
    // own deadline; its reply (if any) is ignored, its errors swallowed — a tap can NEVER delay,
    // reorder, or fail the request. Runs AFTER the rewrite pass so a tap observes the effective
    // (post-compression) body. Each tap receives the projection its GRANT allows: a `prompt: ro` tap
    // gets the prompt-content projection, a `prompt: no` (default) tap gets shape-only — so a tap
    // never over-shares. At most TWO projections are built (shape-only + with-prompt), regardless of
    // tap count. ZERO COST when no tap is configured (empty-list branch).
    if !app.tap_hooks.is_empty() {
        if let Some(body) = v.as_ref() {
            let ctx = crate::hooks::RoutingContext {
                pool: pool_name,
                budget_remaining: None,
            };
            let build_proj = |with_prompt: bool| {
                let req = build_rewrite_request(
                    body,
                    pool_name,
                    ingress_protocol,
                    wants_stream,
                    with_prompt,
                );
                serde_json::to_vec(&crate::hooks::wire::build(
                    crate::hooks::wire::OP_NOTIFY,
                    &req,
                    &[],
                    &ctx,
                ))
                .ok()
                .map(std::sync::Arc::new)
            };
            // Shape-only is needed whenever any tap lacks the prompt grant; the prompt projection only
            // when at least one tap holds `prompt: ro`. Build each at most once.
            let any_prompt = app.tap_hooks.iter().any(|(_, send_prompt, _)| *send_prompt);
            let any_shape = app
                .tap_hooks
                .iter()
                .any(|(_, send_prompt, _)| !*send_prompt);
            let shape_proj = if any_shape { build_proj(false) } else { None };
            let prompt_proj = if any_prompt { build_proj(true) } else { None };
            for (timeout, send_prompt, hook) in &app.tap_hooks {
                // A granted tap prefers the prompt projection; fall back to shape-only if it failed to
                // serialize (never over-share, always safe).
                let proj = if *send_prompt {
                    prompt_proj.clone().or_else(|| shape_proj.clone())
                } else {
                    shape_proj.clone()
                };
                if let Some(proj) = proj {
                    let policy = hook.clone();
                    let budget = *timeout;
                    tokio::spawn(async move { policy.notify(&proj, budget).await });
                }
            }
        }
    }

    // Gemini ingress streaming WITHOUT `?alt=sse`: the native client expects a JSON-array streamed
    // body, not SSE. The route layer signals this via a router shim key (read here; stripped from the
    // body unconditionally before forwarding). GATED on `uses_array_stream_shim()` (true only for
    // GeminiWriter): only a genuine Gemini client can want JSON-array response framing. Without the
    // gate a body-model client (openai/cohere/responses) that sent `{"__busbar_gemini_json_array":true}`
    // in its own fully-controlled body would have its SSE stream silently reframed as a JSON array
    // under `Content-Type: application/json` — undecodable by the official SDK and a router behavior
    // no native backend exhibits. False for every other protocol and for the `?alt=sse` gemini variant.
    // Additionally gated on `op.streaming()`: a non-streaming operation never frames a JSON-array
    // stream (chat streams, so this is a no-op for chat — `true && x == x`).
    let gemini_json_array = op.streaming()
        && crate::proto::protocol_for(ingress_protocol)
            .map(|p| {
                p.writer().uses_array_stream_shim()
                    && v.as_ref()
                        .map(|v| p.writer().wants_array_stream(v))
                        .unwrap_or(false)
            })
            .unwrap_or(false);

    // Derive affinity key early (before any mutations to v). When no affinity header was supplied,
    // fall back to the operation's body-derived key: chat uses the top-level `system` string
    // (byte-identical to the previous inline read); other ops default to no body affinity.
    let affinity_key_str: Option<String> = if let Some(k) = affinity_key {
        Some(k.to_string())
    } else {
        v.as_ref()
            .and_then(|v| op.body_affinity_key(v))
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
        Some(f) => (f.timeout_secs, f.max_hops),
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

    // ── ROUTING-POLICY SEAM ───────────────────────────────────────────────────────────────────────
    // Resolve this pool's routing policy ONCE, here, before the failover loop. The policy (when
    // present) produces a ranked member preference that the loop's `pick_among` walks instead of the
    // blind SWRR pick — composing with the unchanged breaker filter + already-tried exclusion.
    //
    // ZERO-COST DEFAULT: a `route: weighted` (default / absent) pool has `policy == None`, so this is
    // a single predictable always-false branch — no `RoutingRequest`/`Candidate` projection is built,
    // no async policy is entered, and `policy_order` stays `None`, leaving the loop on today's exact
    // inline `select_weighted_in` path. The projection + async decision + ordered-walk only ever run
    // for a pool that resolved a non-default policy.
    //
    // `chosen_policy_name` is the policy that actually produced `policy_order` (for the
    // `x-busbar-route-policy` transparency header). It stays `None` on the default path AND when a
    // configured policy Abstains / errors-to-weighted (both fall through to SWRR, which is not a
    // "policy choice" worth advertising).
    // ── PHASE-2 DECISION GATES (concurrent at t0) ───────────────────────────────────────────────
    // Fire the GLOBAL decision gates and this pool's OWN gates for a verdict on this request,
    // BEFORE pool routing. All gates fire CONCURRENTLY against the same t0 candidate set — reject
    // and restrict COMMUTE (veto; intersect), and an order is re-validated against the FINAL
    // (post-restrict) set — then the outcomes reconcile deterministically over ONE chain, sorted by
    // ascending `priority` (stable: globals before pool gates on ties, then config order):
    //   1. any reject ⇒ reject wins. The FIRST rejecting gate in chain order (the priority
    //      tie-break) supplies the surfacing status/message; nothing is dispatched.
    //   2. else restricts INTERSECT, applied in chain order; a gate whose intersection empties the
    //      set applies ITS `on_empty` (weighted = advisory escape, that gate's restriction is
    //      skipped; the fail-closed default rejects with a 503).
    //   3. else the LAST ordering gate in the chain wins, filtered to the surviving candidate set
    //      (an order captured at t0 may name members a restrict excluded — the filter is what makes
    //      the concurrent firing sound). Empty after filtering = abstain (the pool's base ordering
    //      below applies).
    // The restriction persists across failover (hops select from the shrunk `cands`). ZERO COST
    // when no gate is configured (both sources empty ⇒ the pass is skipped).
    let pool_gates: &[(u16, crate::hooks::ResolvedPolicy)] = app
        .pool_runtime
        .get(pool_name)
        .map(|r| r.gates.as_slice())
        .unwrap_or(&[]);
    let mut gate_order: Option<(Vec<usize>, &'static str)> = None;
    if !app.global_gates.is_empty() || !pool_gates.is_empty() {
        // The chain: globals (pre-sorted ascending by priority) then pool gates (config order),
        // stable-sorted by priority — ties keep globals-first, then config order.
        let mut chain: Vec<&(u16, crate::hooks::ResolvedPolicy)> =
            app.global_gates.iter().chain(pool_gates.iter()).collect();
        chain.sort_by_key(|(p, _)| *p);
        // Every concurrently-firing gate borrows the same parsed body; the shared Null stands in
        // for a non-JSON body (the same projection the sequential path used).
        static NULL_BODY: Value = Value::Null;
        let gate_body: &Value = v.as_ref().unwrap_or(&NULL_BODY);
        let outcomes: Vec<PolicyOutcome> =
            futures::future::join_all(chain.iter().map(|(_, gate)| {
                decide_policy_order(
                    &app,
                    gate,
                    &cands,
                    &request_ctx,
                    gate_body,
                    pool_name,
                    ingress_protocol,
                    wants_stream,
                    caller_token,
                    resolved_gov_key,
                )
            }))
            .await;

        // Reconcile 1: REJECT WINS. The first rejecting gate in chain order surfaces — that is the
        // `priority` tie-break when several gates reject at once. A deliberate RejectRequest was
        // status-clamped 400..=499 + message-sanitized at the producing seam; a fail-closed errored
        // gate (`on_error: reject`) is a 503, never a silent proceed — it was declared load-bearing.
        for outcome in &outcomes {
            match outcome {
                PolicyOutcome::RejectRequest {
                    status,
                    message,
                    name,
                } => {
                    metrics::counter!(
                        crate::metrics::ROUTE_POLICY_REJECTIONS_TOTAL,
                        "policy" => *name,
                        "pool" => pool_name.to_string(),
                        "status" => status.to_string(),
                    )
                    .increment(1);
                    tracing::info!(
                        policy = name,
                        pool = pool_name,
                        status,
                        message = %message,
                        "decision gate rejected the request"
                    );
                    return gate_rejected(ingress_error(
                        ingress_protocol,
                        StatusCode::from_u16(*status).unwrap_or(StatusCode::FORBIDDEN),
                        reject_kind_for_status(*status),
                        message,
                    ));
                }
                PolicyOutcome::Reject => {
                    return gate_rejected(ingress_error(
                        ingress_protocol,
                        StatusCode::SERVICE_UNAVAILABLE,
                        KIND_OVERLOADED,
                        "A required gate could not complete. Please retry shortly.",
                    ));
                }
                _ => {}
            }
        }

        // Reconcile 2: RESTRICTS INTERSECT, in chain order (intersection commutes — the final set
        // is order-independent; the chain order only decides WHOSE on_empty applies first when the
        // set empties). Shrinking `cands` makes the restriction persist across every failover hop
        // and keeps any ordering — gate or base — inside the eligible set.
        for outcome in &outcomes {
            if let PolicyOutcome::Restrict {
                tags_any,
                name,
                on_empty,
            } = outcome
            {
                // Capture this restrict so it PERSISTS across a `fallback_pool` hop (which rebuilds
                // candidates from an independent pool). Recorded for every restrict regardless of
                // whether it narrows here — the fail-closed reject case returns below before any
                // fallback, so a stray record is harmless. (found: audit c1r13.)
                request_ctx.active_restricts.push(RestrictConstraint {
                    tags_any: tags_any.clone(),
                    on_empty: on_empty.clone(),
                    name,
                });
                let members = app.pool_runtime.get(pool_name).map(|r| &r.members);
                let restricted: Vec<WeightedLane> = cands
                    .iter()
                    .filter(|wl| {
                        members.and_then(|m| m.get(&wl.idx)).is_some_and(|meta| {
                            meta.tags.iter().any(|t| tags_any.iter().any(|w| w == t))
                        })
                    })
                    .cloned()
                    .collect();
                if restricted.is_empty() {
                    if matches!(on_empty, crate::config::PolicyOnError::Weighted) {
                        tracing::info!(
                            policy = name,
                            pool = pool_name,
                            "decision gate restrict left no eligible lane; on_empty: weighted \
                             escape — this gate's restriction is skipped"
                        );
                        // leave `cands` unchanged and continue reconciling the next restrict.
                    } else {
                        metrics::counter!(
                            crate::metrics::ROUTE_POLICY_REJECTIONS_TOTAL,
                            "policy" => *name,
                            "pool" => pool_name.to_string(),
                            "status" => "503".to_string(),
                        )
                        .increment(1);
                        tracing::info!(
                            policy = name,
                            pool = pool_name,
                            "decision gate restrict left no eligible lane (on_empty: reject)"
                        );
                        return gate_rejected(ingress_error(
                            ingress_protocol,
                            StatusCode::SERVICE_UNAVAILABLE,
                            KIND_OVERLOADED,
                            "No upstream satisfies a required gate's restriction. Please retry \
                             shortly.",
                        ));
                    }
                } else {
                    cands = restricted;
                    metrics::counter!(
                        crate::metrics::ROUTE_POLICY_SELECTIONS_TOTAL,
                        "policy" => *name,
                        "pool" => pool_name.to_string(),
                    )
                    .increment(1);
                }
            }
        }

        // Reconcile 3: ORDER — LAST in the chain wins, re-validated against the FINAL candidate
        // set (the t0 order may name members a restrict excluded). An order that filters to empty
        // abstains — the pool's base ordering below applies.
        let surviving: std::collections::HashSet<usize> = cands.iter().map(|wl| wl.idx).collect();
        for outcome in outcomes {
            if let PolicyOutcome::Order { order, name } = outcome {
                let filtered: Vec<usize> = order
                    .into_iter()
                    .filter(|i| surviving.contains(i))
                    .collect();
                if !filtered.is_empty() {
                    gate_order = Some((filtered, name));
                }
            }
        }
        if let Some((_, name)) = &gate_order {
            metrics::counter!(
                crate::metrics::ROUTE_POLICY_SELECTIONS_TOTAL,
                "policy" => *name,
                "pool" => pool_name.to_string(),
            )
            .increment(1);
        }
    }

    let mut chosen_policy_name: Option<&'static str> = None;
    let policy_order: Option<Vec<usize>> = if let Some((order, name)) = gate_order {
        // A phase-2 gate ORDERED: it overrides the pool's base ordering (a gate's abstain was the
        // reconciled fall-through to the base, handled above).
        chosen_policy_name = Some(name);
        Some(order)
    } else {
        match app
            .pool_runtime
            .get(pool_name)
            .and_then(|r| r.policy.as_ref())
        {
            // Default fast path: no policy ⇒ SWRR, byte-identical to pre-feature behavior. NOTHING below
            // this arm runs — no projection, no async, one predictable branch.
            None => None,
            // A non-default policy is configured: build the projection, run the decision (bounded by its
            // timeout), and coerce the outcome to a ranked order (or `None` ⇒ SWRR) per `on_error`.
            Some(resolved) => {
                let outcome = decide_policy_order(
                    &app,
                    resolved,
                    &cands,
                    &request_ctx,
                    v.as_ref().unwrap_or(&Value::Null),
                    pool_name,
                    ingress_protocol,
                    wants_stream,
                    caller_token,
                    resolved_gov_key,
                )
                .await;
                match outcome {
                    // The policy returned a usable ranked order — record its name (for the
                    // `x-busbar-route-policy` header + the metric) and hand the order to the ordered walk.
                    PolicyOutcome::Order { order, name } => {
                        chosen_policy_name = Some(name);
                        metrics::counter!(
                            crate::metrics::ROUTE_POLICY_SELECTIONS_TOTAL,
                            "policy" => name,
                            "pool" => pool_name.to_string(),
                        )
                        .increment(1);
                        Some(order)
                    }
                    // Abstain / error-coerced-to-weighted: fall through to today's exact SWRR.
                    PolicyOutcome::Weighted => None,
                    // on_error == reject (and the policy errored/timed out / saturated): fail closed with a
                    // 503 rather than silently degrading. Never strands as a hang — a clean rejection.
                    PolicyOutcome::Reject => {
                        return gate_rejected(ingress_error(
                            ingress_protocol,
                            StatusCode::SERVICE_UNAVAILABLE,
                            KIND_OVERLOADED,
                            "The routing policy could not select an upstream. Please retry \
                             shortly.",
                        ));
                    }
                    // The hook's REJECT verb: a deliberate, first-class policy decision (a guardrail /
                    // PII screen said no) — a 4xx to the caller, no upstream dispatched, and an
                    // operator-visible counter. `status` was clamped to 400..=499 and `message`
                    // sanitized at the seam that constructed the outcome (for every producer, wire or
                    // direct), so this arm can trust both.
                    PolicyOutcome::RejectRequest {
                        status,
                        message,
                        name,
                    } => {
                        // The `status` label is hook-influenced but BOUNDED: the seam that built this
                        // outcome clamps it to 400..=499 for every producer, so the worst-case series
                        // fan-out is 100 per (policy, pool).
                        metrics::counter!(
                            crate::metrics::ROUTE_POLICY_REJECTIONS_TOTAL,
                            "policy" => name,
                            "pool" => pool_name.to_string(),
                            "status" => status.to_string(),
                        )
                        .increment(1);
                        // The message is safe to log: the seam that built this outcome sanitized it
                        // (control/invisible chars stripped, length capped — for EVERY producer, not
                        // just the wire transports), and it is the exact string the CLIENT receives.
                        tracing::info!(
                            policy = name,
                            pool = pool_name,
                            status,
                            message = %message,
                            "routing policy rejected the request"
                        );
                        return gate_rejected(ingress_error(
                            ingress_protocol,
                            StatusCode::from_u16(status).unwrap_or(StatusCode::FORBIDDEN),
                            reject_kind_for_status(status),
                            &message,
                        ));
                    }
                    // The hook's RESTRICT verb: intersect the failover candidate set with members
                    // carrying one of `tags_any`, then let SWRR pick among the survivors. Shrinking
                    // `cands` here makes the restriction PERSIST across every failover hop (each hop
                    // selects from this set) — the compliance guarantee ("only these lanes, ever"). An
                    // EMPTY intersection is fail-closed (`on_empty` default reject), never allow-all;
                    // an empty `tags_any` (fail-closed-normalized malformed restrict) forces it.
                    PolicyOutcome::Restrict {
                        tags_any,
                        name,
                        on_empty,
                    } => {
                        // Capture this restrict so it PERSISTS across a `fallback_pool` hop, exactly
                        // as the GATE reconcile arm does. Shrinking `cands` below only covers in-pool
                        // failover; the fallback pool rebuilds candidates independently and consults
                        // `enforce_restricts`. The gate arm was the c1r13 fix; this BASE routing-policy
                        // arm (pool `route:` hook) is the sibling path that was still leaking a
                        // compliance restrict at the pool boundary. (found: audit c1r14.)
                        request_ctx.active_restricts.push(RestrictConstraint {
                            tags_any: tags_any.clone(),
                            on_empty: on_empty.clone(),
                            name,
                        });
                        let members = app.pool_runtime.get(pool_name).map(|r| &r.members);
                        // Filter into a temp so the ORIGINAL `cands` survives for a weighted on_empty
                        // escape; only commit the restriction when the intersection is non-empty.
                        let restricted: Vec<WeightedLane> = cands
                            .iter()
                            .filter(|wl| {
                                members.and_then(|m| m.get(&wl.idx)).is_some_and(|meta| {
                                    meta.tags.iter().any(|t| tags_any.iter().any(|w| w == t))
                                })
                            })
                            .cloned()
                            .collect();
                        if restricted.is_empty() {
                            // Empty intersection → the gate's `on_empty`. `Weighted` is the advisory escape
                            // (leave `cands` as the full pool → SWRR); default (and `First`, which has no
                            // eligible "first") is fail-closed reject.
                            if matches!(on_empty, crate::config::PolicyOnError::Weighted) {
                                tracing::info!(
                                policy = name,
                                pool = pool_name,
                                "routing policy restrict left no eligible lane; on_empty: weighted \
                                 escape to full-pool SWRR"
                            );
                                None
                            } else {
                                metrics::counter!(
                                    crate::metrics::ROUTE_POLICY_REJECTIONS_TOTAL,
                                    "policy" => name,
                                    "pool" => pool_name.to_string(),
                                    "status" => "503".to_string(),
                                )
                                .increment(1);
                                tracing::info!(
                                policy = name,
                                pool = pool_name,
                                "routing policy restrict left no eligible lane (on_empty: reject)"
                            );
                                return gate_rejected(ingress_error(
                                    ingress_protocol,
                                    StatusCode::SERVICE_UNAVAILABLE,
                                    KIND_OVERLOADED,
                                    "No upstream satisfies the routing policy's restriction. \
                                     Please retry shortly.",
                                ));
                            }
                        } else {
                            // Commit the restriction: shrink `cands` to the survivors so it PERSISTS
                            // across every failover hop, then let SWRR pick among them.
                            cands = restricted;
                            chosen_policy_name = Some(name);
                            metrics::counter!(
                                crate::metrics::ROUTE_POLICY_SELECTIONS_TOTAL,
                                "policy" => name,
                                "pool" => pool_name.to_string(),
                            )
                            .increment(1);
                            None
                        }
                    }
                }
            }
        }
    };

    // The pristine `v` is consumed by the FIRST hop (it is unmutated after the field reads above), so
    // the common no-failover path parses the body ONCE, not twice. Failover hops (2+) re-parse from
    // the retained `body` bytes — never from a previous hop's egress-shaped Value — preserving the
    // mixed-protocol-pool correctness the per-hop re-parse was introduced for.
    let body_is_json = v.is_some();
    // ── STAGE TAPS: route + attempt shape ── captured ONCE (scalars only, so it survives `v`
    // moving into the first hop). Fire the `route` taps now: the decision reconcile + base ordering
    // above produced the FINAL candidate set for dispatch. ZERO COST when no stage tap is configured.
    let stage_shape = if app.tap_hooks_route.is_empty() && app.tap_hooks_attempt.is_empty() {
        None
    } else {
        Some(capture_stage_shape(
            v.as_ref(),
            pool_name,
            ingress_protocol,
            wants_stream,
        ))
    };
    if let Some(shape) = &stage_shape {
        fire_stage_taps(
            &app.tap_hooks_route,
            shape,
            crate::hooks::wire::HookStageProjection {
                at: "route",
                model: None,
                attempt_number: None,
                remaining_candidates: Some(cands.len()),
                previous_failure: None,
                outcome: None,
                status: None,
            },
        );
    }
    // Why the PREVIOUS attempt failed — feeds the attempt-stage tap payload (the failover story).
    let mut last_failure: Option<&'static str> = None;

    let mut first_hop_v = v;
    for attempt in 0..=max_cap {
        // Check deadline first (propagated across hops)
        if request_ctx.expired(now()) {
            return ingress_error(
                ingress_protocol,
                StatusCode::SERVICE_UNAVAILABLE,
                KIND_OVERLOADED,
                DETAIL_REQUEST_TIMEOUT,
            );
        }

        let (i, permit) = match pick_among(
            &app,
            &cands,
            &mut request_ctx,
            affinity_key_str.as_deref(),
            pool_name,
            policy_order.as_deref(),
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
                        KIND_OVERLOADED,
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
                    op,
                    req_content_type,
                    usage_sink.clone(),
                )
                .await;
            }
        };

        // Mark this lane as excluded for future attempts in this request
        request_ctx.exclude(i);

        // ── STAGE TAPS: attempt ── the full failover story, per dispatch attempt: which lane,
        // which attempt number, how many candidates remain untried, and why the previous attempt
        // failed (None on the first).
        if let Some(shape) = &stage_shape {
            let remaining = cands
                .iter()
                .filter(|wl| !request_ctx.excluded.contains(&wl.idx))
                .count();
            fire_stage_taps(
                &app.tap_hooks_attempt,
                shape,
                crate::hooks::wire::HookStageProjection {
                    at: "attempt",
                    model: Some(&app.lanes[i].model),
                    attempt_number: Some(
                        u32::try_from(attempt.saturating_add(1)).unwrap_or(u32::MAX),
                    ),
                    remaining_candidates: Some(remaining),
                    previous_failure: last_failure,
                    outcome: None,
                    status: None,
                },
            );
        }

        // The bounded `pool` LABEL for THIS hop's upstream/failover/breaker metrics (LOW #25).
        // Resolves to the routed lane's model name on the default (`""`) cell so these series
        // correlate with REQUESTS_TOTAL (which labels model-routed traffic by model, not `""`);
        // the breaker-cell key below stays `pool_name` (`""`) — only the metric LABEL is decoupled.
        // Held as a borrow (no up-front allocation); each metric emit owns it (`.to_owned()`) only on
        // the branch that actually fires, so an attempt allocates the label once per emitted series
        // instead of eagerly building a `String` and cloning it at every (mostly-unreached) site.
        let metric_pool: &str = metric_pool_label(&app, pool_name, i);

        // count this upstream attempt (re-entrant across failover hops — each is a real attempt).
        metrics::counter!(
            crate::metrics::UPSTREAM_ATTEMPTS_TOTAL,
            "pool" => metric_pool.to_owned(),
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
        let hop_v: Option<Value> = if !body_is_json {
            None // opaque ingress body: byte-level relay/translate; nothing to re-parse.
        } else {
            Some(match first_hop_v.take() {
                // First hop: reuse the pristine parse from above (no second parse on the common path).
                Some(v) => v,
                // Failover hops: re-parse from the retained pristine bytes (sonic-rs: SIMD parse).
                None => match crate::json::parse(&body) {
                    Ok(v) => v,
                    // `body` already parsed once successfully above; this re-parse is infallible.
                    Err(_) => {
                        // Probe class guard: this lane may have CAS-won the single-flight recovery probe in
                        // `pick_among`. We bail BEFORE dispatching any request, so no outcome will be
                        // recorded to clear `probe_in_flight` — release it here or the recovering lane stays
                        // wedged HalfOpen until the slow out-of-band prober resets it.
                        app.store.release_probe_in(pool_name, i);
                        drop(permit);
                        return ingress_error(
                            ingress_protocol,
                            StatusCode::INTERNAL_SERVER_ERROR,
                            KIND_API_ERROR,
                            DETAIL_INTERNAL_ERROR,
                        );
                    }
                },
            })
        };
        // SINGLE shared cross-protocol request-shaping seam (shared verbatim with `forward_once`'s
        // degraded path): read→clear-extra→write, shim-key strip, model rewrite, serialize. Both
        // paths route through `translate_request_cross_protocol` so neither can carry a translation
        // step the other lacks (the recurring drift class this round's unification ends).
        let payload = match translate_request_cross_protocol(
            &app,
            i,
            ingress_protocol,
            op,
            hop_v,
            req_content_type,
            effective_reasoning(&cands, i, app.lanes[i].reasoning),
            &body,
        ) {
            Ok(p) => p,
            Err(resp) => {
                // Probe class guard: a translation failure also bails before dispatch, so release
                // the (possibly won) single-flight probe before returning — same wedged-HalfOpen
                // leak as the re-parse path above.
                app.store.release_probe_in(pool_name, i);
                drop(permit);
                return *resp;
            }
        };
        let base = &app.lanes[i].base_url;

        // Mode-aware key selection: passthrough uses caller token, others use lane's api_key
        let key = match app.upstream_creds() {
            // Passthrough forwards the CALLER's credential upstream. When the caller presents NO
            // credential, fall back to an EMPTY credential — NOT the lane operator's `api_key`
            // (LOW #15 SECURITY): borrowing the operator key would let an unauthenticated caller
            // silently spend on the operator's upstream account. An empty credential makes the
            // provider return its own 401/403, attributed to the caller (a client-auth fault, no
            // lane penalty), matching the documented passthrough contract. No-op in canonical
            // keyless passthrough (lane.api_key already empty); only changes the misconfigured
            // passthrough+configured-key case.
            crate::auth::UpstreamCreds::Passthrough => caller_token.unwrap_or(""),
            crate::auth::UpstreamCreds::Own => &app.lanes[i].api_key,
        };

        // per-request auth (SigV4 for Bedrock; static for others) needs the host/path/body.
        let writer = app.lanes[i].protocol.writer();
        // The operation resolves its own upstream path from this lane: chat delegates to the
        // writer's stream-aware default (honoring any provider `path` override) — byte-identical to
        // the previous inline logic. `None` means this lane's protocol does not speak this
        // operation; unreachable for chat (every protocol speaks it), and impossible once the
        // router filters candidates by operation support, but the engine still bails safely rather
        // than dispatch to a wrong path — releasing any single-flight probe this lane won so it
        // cannot wedge HalfOpen (same contract as the re-parse/translate guards above).
        let url_path = match op.upstream_path(&app.lanes[i], wants_stream) {
            Some(p) => p,
            None => {
                app.store.release_probe_in(pool_name, i);
                drop(permit);
                return ingress_error(
                    ingress_protocol,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    KIND_API_ERROR,
                    DETAIL_INTERNAL_ERROR,
                );
            }
        };
        // SigV4 signs over the URI-encoded canonical path, so the wire request MUST be sent over the
        // SAME encoding or AWS rejects with SignatureDoesNotMatch (e.g. a Bedrock modelId carrying
        // reserved chars like `:` signs `%3A` but a raw send transmits `:`). Encode the path ONCE and
        // use it for both signing and the wire URL — the percent-encoded `%XX` sequences pass through
        // the `url` crate's path parser unchanged, so transmitted path == signed canonical path.
        let (wire_path, canonical_uri) = sign_and_wire_path_parts(&url_path);
        let signing_ctx = crate::proto::SigningContext {
            host: host_from_base(base),
            canonical_uri,
            body: &payload,
            timestamp_epoch: now(),
            upstream_creds: app.upstream_creds(),
        };
        let auth = lane_auth_headers(&app.lanes[i], key, &signing_ctx);

        // Egress request Content-Type: JSON bodies stay JSON (chat byte-identical). An OPAQUE body
        // relays the caller's own CT same-protocol (multipart boundary preserved verbatim) and uses
        // the EGRESS operation handler's declared wire CT cross-protocol (its write_request built
        // that wire — e.g. openai transcription's fixed-boundary multipart).
        let egress_ct: &str = if body_is_json {
            APPLICATION_JSON
        } else if ingress_protocol == egress_name {
            req_content_type
        } else {
            crate::handlers::request_handler(egress_name)
                .and_then(|rh| rh.operation_handler(op.operation))
                .map(|h| h.egress_request_content_type())
                .unwrap_or(APPLICATION_JSON)
        };
        let mut req = app
            .client
            .post(format!("{base}{wire_path}"))
            .headers(convert_headers(auth))
            .header(CONTENT_TYPE, egress_ct)
            // Native-SDK User-Agent for the egress protocol. The shared client sets none, so without
            // this the backend sees a UA-less request — a proxy fingerprint. Dispatched through the
            // writer vtable (`ProtocolWriter::egress_user_agent`) — `writer` is already resolved above.
            .header(USER_AGENT, writer.egress_user_agent())
            // Native-SDK Accept for the egress protocol (eventstream/json/SSE by stream intent). A
            // native SDK always sends one; omitting it is a backend-side proxy fingerprint. The
            // operation chooses it: chat defers to the writer vtable (`ProtocolWriter::egress_accept`,
            // byte-identical to before) so no `"bedrock"` branch lives here; an op with a non-JSON
            // response chooses its own. Not part of SigV4 SignedHeaders, so no signature impact.
            .header(ACCEPT, op.egress_accept(writer, wants_stream))
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
        // PER-ATTEMPT time-to-response-headers cap (`attempt_timeout_ms` — the hang detector). The
        // pool-member override wins over the model-level value; either is floored by the remaining
        // request budget. `send()` resolves when RESPONSE HEADERS arrive, so wrapping it bounds the
        // hang (connect + headers) without bounding a healthy long stream's BODY — the stream
        // rationale above is untouched. Expiry maps to the same transport-error arm as any reqwest
        // timeout: transient → breaker failure → fail over to the next member WITHIN this request.
        let attempt_ms = effective_attempt_timeout_ms(&cands, i, app.lanes[i].attempt_timeout_ms);
        let res = match attempt_ms {
            Some(ms) => {
                let cap = attempt_cap(ms, request_ctx.remaining(now()));
                match tokio::time::timeout(cap, req.send()).await {
                    Ok(r) => r,
                    Err(_elapsed) => {
                        // Mirror the reqwest transport-timeout arm below EXACTLY (breaker record,
                        // trip emit, failure + failover metrics, permit drop) — the only deltas are
                        // the distinct `attempt_timeout` disposition/reason labels so operators can
                        // see hang-hops as their own series, and the warn naming the cap.
                        record_upstream_rtt(upstream_started.elapsed());
                        let tripped = app.store.record_transient_in(
                            pool_name,
                            i,
                            ERR_NET_TIMEOUT,
                            &breaker_cfg,
                            None,
                        );
                        if tripped {
                            emit_breaker_trip(&app, pool_name, i);
                        }
                        metrics::counter!(
                            crate::metrics::UPSTREAM_FAILURES_TOTAL,
                            "pool" => metric_pool.to_owned(),
                            "lane" => app.lanes[i].model.clone(),
                            "disposition" => DISPOSITION_ATTEMPT_TIMEOUT
                        )
                        .increment(1);
                        metrics::counter!(
                            crate::metrics::FAILOVERS_TOTAL,
                            "pool" => metric_pool.to_owned(),
                            "reason" => DISPOSITION_ATTEMPT_TIMEOUT
                        )
                        .increment(1);
                        tracing::warn!(
                            pool = %pool_name,
                            lane = %app.lanes[i].model,
                            attempt_timeout_ms = ms,
                            "no response headers within the attempt cap; failing over"
                        );
                        last_failure = Some(DISPOSITION_ATTEMPT_TIMEOUT);
                        drop(permit);
                        continue;
                    }
                }
            }
            None => req.send().await,
        };
        record_upstream_rtt(upstream_started.elapsed());

        match res {
            Err(e) => {
                // Pre-response error: classify and potentially failover
                let err_type = if e.is_timeout() {
                    ERR_NET_TIMEOUT
                } else {
                    ERR_NET_CONNECT
                };
                let tripped =
                    app.store
                        .record_transient_in(pool_name, i, err_type, &breaker_cfg, None);
                // A threshold-based Closed→Open trip is a breaker trip for this (pool, lane) — emit
                // BREAKER_TRIPS_TOTAL once, mirroring the HardDown arm (#29). `record_transient_in`
                // returns `true` only on a logical trip (not a HalfOpen reopen or already-Open no-op),
                // so the counter is not multi-counted per cell or per cooldown bump.
                if tripped {
                    emit_breaker_trip(&app, pool_name, i);
                }
                metrics::counter!(
                    crate::metrics::UPSTREAM_FAILURES_TOTAL,
                    "pool" => metric_pool.to_owned(),
                    "lane" => app.lanes[i].model.clone(),
                    "disposition" => DISPOSITION_TRANSIENT
                )
                .increment(1);
                metrics::counter!(
                    crate::metrics::FAILOVERS_TOTAL,
                    "pool" => metric_pool.to_owned(),
                    "reason" => err_type.to_string()
                )
                .increment(1);
                last_failure = Some(err_type);
                drop(permit);
                continue;
            }
            Ok(r) => {
                let status = r.status();

                // For non-2xx responses, read the body to classify (failover allowed)
                if !status.is_success() {
                    // caveat: passthrough 401/403 is caller's key failing, not busbar's
                    // Do NOT trip breaker / change member health; relay verbatim to caller
                    let is_passthrough_40x = app.upstream_creds()
                        == crate::auth::UpstreamCreds::Passthrough
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
                    )> = if ingress_relays_amzn_headers(ingress_protocol) {
                        ingress_relayed_response_header_names(ingress_protocol)
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
                    // For a NON-amzn same-protocol error relay (anthropic), capture the upstream's
                    // PRIMARY relayed id (`request-id`) so it can be forwarded verbatim — or synthesized
                    // if the upstream omitted it — mirroring `forward_once`'s same-proto error relay.
                    // Empty for protocols with no relayed header name.
                    let upstream_error_relay_id: Option<String> =
                        ingress_relayed_response_header_names(ingress_protocol)
                            .first()
                            .and_then(|name| r.headers().get(*name))
                            .and_then(|h| h.to_str().ok())
                            .map(|s| s.to_string());
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
                            // Probe class guard: a passthrough 401/403 is the CALLER's own key
                            // failing — no breaker penalty — so no failure outcome is recorded to
                            // clear `probe_in_flight`. If this lane won the recovery probe, release
                            // it before relaying or the lane stays wedged HalfOpen.
                            app.store.release_probe_in(pool_name, i);
                            // Reshape via the shared finalizer so the kind→native-envelope mapping
                            // (401→authentication_error, 403→permission_error, …) is identical on the
                            // main path, the degraded path, and the ClientFault branch below.
                            return shape_cross_protocol_error(ingress_protocol, status, &bytes);
                        }
                        // Probe class guard (same-protocol passthrough 401/403): caller-key auth
                        // failure carries no breaker penalty, so nothing clears `probe_in_flight`.
                        // Release the won probe before the verbatim relay or the lane wedges HalfOpen.
                        app.store.release_probe_in(pool_name, i);
                        use axum::body::Body;
                        let mut rb = Response::builder().status(status);
                        if let Some(ct) = ct {
                            rb = rb.header(CONTENT_TYPE, ct);
                        }
                        // Forward the native response request-id header(s) on a same-protocol relay so
                        // the SDK's `request_id()` matches a real endpoint. Bedrock: both
                        // `x-amzn-requestid` + `x-amzn-errortype` VERBATIM. Anthropic: `request-id`
                        // upstream-or-synth (a native Anthropic 4xx always carries it). Mirrors forward_once.
                        if ingress_relays_amzn_headers(ingress_protocol) {
                            for (name, value) in &upstream_amzn_headers {
                                rb = rb.header(name, value);
                            }
                        } else {
                            rb = maybe_attach_response_request_id(
                                rb,
                                ingress_protocol,
                                upstream_error_relay_id.as_deref(),
                            );
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
                            // Probe class guard: `record_client_fault` only bumps an observability
                            // counter — it does NOT clear `probe_in_flight`. If this lane CAS-won the
                            // single-flight recovery probe in `pick_among`, both ClientFault exits
                            // below (cross-protocol reshape and same-protocol verbatim relay) return
                            // without recording any breaker outcome, so neither would release the
                            // probe — leaving the recovering lane wedged HalfOpen until the slow
                            // out-of-band prober resets it. Release it once here, before either exit,
                            // so the lane is immediately re-probeable on the next cooldown.
                            app.store.release_probe_in(pool_name, i);
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
                            // Same as the passthrough-40x branch: preserve the native response
                            // request-id header on a same-protocol client-fault relay — bedrock's
                            // `x-amzn-*` verbatim, anthropic's `request-id` upstream-or-synth.
                            if ingress_relays_amzn_headers(ingress_protocol) {
                                for (name, value) in &upstream_amzn_headers {
                                    rb = rb.header(name, value);
                                }
                            } else {
                                rb = maybe_attach_response_request_id(
                                    rb,
                                    ingress_protocol,
                                    upstream_error_relay_id.as_deref(),
                                );
                            }
                            return rb
                                .body(Body::from(bytes))
                                .unwrap_or_else(|_| status.into_response());
                        }
                        Disposition::TransientUpstream => {
                            // Transient upstream failure → cooldown + err counter
                            // Record based on specific error type (exhaustive over remaining variants)
                            let tripped = if matches!(sig.class, StatusClass::RateLimit) {
                                app.store.record_rate_limit_in(
                                    pool_name,
                                    i,
                                    now(),
                                    &breaker_cfg,
                                    sig.retry_after,
                                )
                            } else {
                                let what = match sig.class {
                                    StatusClass::ServerError => "5xx",
                                    StatusClass::Timeout => ERR_NET_TIMEOUT,
                                    StatusClass::Network => "network",
                                    StatusClass::Overloaded => KIND_OVERLOADED,
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
                                )
                            };
                            // A threshold-based Closed→Open trip is a breaker trip for this (pool,
                            // lane) — emit BREAKER_TRIPS_TOTAL once, mirroring the HardDown arm (#29).
                            if tripped {
                                emit_breaker_trip(&app, pool_name, i);
                            }
                            metrics::counter!(
                                crate::metrics::UPSTREAM_FAILURES_TOTAL,
                                "pool" => metric_pool.to_owned(),
                                "lane" => app.lanes[i].model.clone(),
                                "disposition" => DISPOSITION_TRANSIENT
                            )
                            .increment(1);
                            metrics::counter!(
                                crate::metrics::FAILOVERS_TOTAL,
                                "pool" => metric_pool.to_owned(),
                                "reason" => DISPOSITION_TRANSIENT
                            )
                            .increment(1);
                            last_failure = Some(DISPOSITION_TRANSIENT);
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
                            let newly_tripped = app.store.record_hard_down_all_cells(i, &reason);
                            // A hard-down is a breaker trip for this lane — but only count a LOGICAL
                            // Closed→Open trip. A persistently-dead auth/billing lane re-enters this arm
                            // on every recovery-probe cycle (a HalfOpen reopen, not a fresh trip); gating
                            // on `newly_tripped` stops BREAKER_TRIPS_TOTAL inflating once per cooldown
                            // for a stuck lane (the metric's "once per logical trip" contract).
                            if newly_tripped {
                                metrics::counter!(
                                    crate::metrics::BREAKER_TRIPS_TOTAL,
                                    "pool" => metric_pool.to_owned(),
                                    "lane" => app.lanes[i].model.clone()
                                )
                                .increment(1);
                            }
                            tracing::warn!(pool = %pool_name, lane = %app.lanes[i].model, reason = %reason, "lane hard-down (breaker trip)");
                            metrics::counter!(
                                crate::metrics::UPSTREAM_FAILURES_TOTAL,
                                "pool" => metric_pool.to_owned(),
                                "lane" => app.lanes[i].model.clone(),
                                "disposition" => DISPOSITION_HARD_DOWN
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
                                "pool" => metric_pool.to_owned(),
                                "reason" => DISPOSITION_HARD_DOWN
                            )
                            .increment(1);
                            last_failure = Some(DISPOSITION_HARD_DOWN);
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
                                "pool" => metric_pool.to_owned(),
                                "lane" => app.lanes[i].model.clone(),
                                "disposition" => DISPOSITION_CONTEXT_LENGTH
                            )
                            .increment(1);
                            metrics::counter!(
                                crate::metrics::FAILOVERS_TOTAL,
                                "pool" => metric_pool.to_owned(),
                                "reason" => DISPOSITION_CONTEXT_LENGTH
                            )
                            .increment(1);
                            // Probe class guard: ContextLength is a client-fault variant (the request
                            // is too large for THIS lane's window) — no breaker penalty, so nothing
                            // records an outcome to clear `probe_in_flight`. If this lane won the
                            // recovery probe, this `continue` would abandon it set, wedging the lane
                            // HalfOpen until the slow out-of-band prober rescues it. Release it so the
                            // lane is immediately probe-eligible again for normal-size requests.
                            app.store.release_probe_in(pool_name, i);
                            last_failure = Some(DISPOSITION_CONTEXT_LENGTH);
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
                // Fold this request's time-to-headers into the lane's latency EWMA (the routing
                // `fastest` signal). Measured to the upstream RESPONSE HEADERS (`req.send().await`
                // completion) — a cheap, bounded proxy that does NOT wait out an unbounded streaming
                // body. Lane-global + off the selection path; a no-op unless a `route: fastest` (or a
                // webhook/script policy reading `latency_ms`) consults it.
                app.store.record_latency_in(
                    pool_name,
                    i,
                    upstream_started.elapsed().as_secs_f64() * 1000.0,
                );
                // BIND the spend result (#21): the post-success spend is COST accounting, not the
                // admission gate (that was `lane_admissible`/`usable` before dispatch). It can no
                // longer over-spend; `false` means this lane was already at 0 (the next admission
                // check rejects it) OR that the spend was a no-op. The paired post-headers body
                // TransportError below refunds the budget, but `refund_budget` UNCONDITIONALLY
                // fetch_adds — so a refund of a no-op spend would push the budget ABOVE its cap. Guard
                // the refund on this bool. `budget_spent` is `true` for an unlimited lane (the spend
                // is a no-op success there) and `refund_budget` is likewise a no-op there, so an
                // unlimited lane neither over-counts nor under-counts.
                let budget_spent = app.store.spend_budget(i);

                // stream the response body incrementally with first-byte boundary tracking
                let ct = r.headers().get(CONTENT_TYPE).cloned();
                // Capture the upstream PRIMARY relayed id (if any) BEFORE consuming `r` into the body
                // stream, keyed off the ingress writer's `ingress_relayed_response_header_names` (so
                // this names no protocol module). On a SAME-PROTOCOL streaming passthrough we forward
                // the real upstream id verbatim — `x-amzn-RequestId` for bedrock (a native
                // ConverseStream response carries it), `request-id` for anthropic; on a CROSS-PROTOCOL
                // stream the backend supplied none, so the attach helper synthesizes one below. Either
                // way a bedrock/anthropic-ingress stream must carry the header (matching a real
                // endpoint and the error path).
                let upstream_relay_id = ingress_relayed_response_header_names(ingress_protocol)
                    .first()
                    .and_then(|name| r.headers().get(*name))
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
                    let (bytes, read_end) = read_capped(r, max_translated_body_bytes()).await;
                    // Re-record the upstream RTT now that the WHOLE body has arrived. On this buffered
                    // cross-protocol path Busbar awaits the entire upstream response before it can
                    // parse+translate, so the body-download time is part of the upstream cost, not
                    // Busbar's. The earlier (post-headers) record captured only time-to-headers, which
                    // would mis-attribute the body-download (a real-WAN cost) to Busbar in the
                    // `Server-Timing` figure. Overwrite it with the full send→body-complete span so the
                    // reported `dur` is the parse/translate/serialize work alone. (Streaming and
                    // same-protocol passthrough keep the time-to-headers value: there Busbar does not
                    // buffer the body, so the stream time is not Busbar's.)
                    record_upstream_rtt(upstream_started.elapsed());
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
                        let tripped = app.store.record_transient_in(
                            pool_name,
                            i,
                            ERR_NET_TRANSPORT,
                            &breaker_cfg,
                            None,
                        );
                        // A threshold-based Closed→Open trip here is a breaker trip too (#29).
                        if tripped {
                            emit_breaker_trip(&app, pool_name, i);
                        }
                        // Refund ONLY if the headers-spend actually decremented (#21): `refund_budget`
                        // is an unconditional fetch_add, so refunding a no-op spend would raise the
                        // budget above its cap.
                        if budget_spent {
                            app.store.refund_budget(i);
                        }
                        return ingress_error(
                            ingress_protocol,
                            StatusCode::BAD_GATEWAY,
                            KIND_API_ERROR,
                            GENERIC_RESPONSE_ERROR_DETAIL,
                        );
                    }
                    if read_end == ReadEnd::Truncated {
                        // The upstream body exceeded OUR translation cap, so we cannot translate it
                        // and the client receives a 500 with NO completion. Token accounting is
                        // therefore deliberately NOT done here (it lives after this guard): charging
                        // the key's TPM/spend budget for a completion the client never received is
                        // incorrect, and would also be inconsistent with the TransportError branch
                        // above (which likewise charges no tokens for an undelivered body). Unlike
                        // TransportError this is OUR cap, not an upstream fault: the upstream genuinely
                        // succeeded, so the optimistic breaker success recorded on the 2xx headers
                        // stands and the request budget unit is NOT refunded (the lane DID serve a
                        // request; refunding would mis-credit capacity for our own size limit).
                        tracing::warn!(
                            ingress = %ingress_protocol,
                            egress = %app.lanes[i].protocol.name(),
                            cap = max_translated_body_bytes(),
                            "cross-protocol non-stream success body exceeded the translation cap; \
                             cannot translate, not charging tokens, returning ingress-native error"
                        );
                        return ingress_error(
                            ingress_protocol,
                            StatusCode::INTERNAL_SERVER_ERROR,
                            KIND_API_ERROR,
                            GENERIC_RESPONSE_ERROR_DETAIL,
                        );
                    }
                    // Token accounting deferred to the delivery seam below (#2). A 2xx body whose
                    // usage block parses but whose content shape is unmodeled (e.g. empty `choices`,
                    // or an unknown ingress protocol that fails `protocol_for`) does NOT reach the
                    // `if let Some(ingress_proto)` translate+return block: it falls through to the
                    // ingress-native 500 below, delivering NO completion. Charging here — before
                    // translation is proven to succeed — would bill the key's TPM/spend for a
                    // completion the client never receives, exactly the inconsistency the Truncated
                    // and TransportError branches above deliberately avoid. So tap usage ONLY once we
                    // are inside the block that actually mints and returns a translated response.
                    let egress_op = crate::handlers::request_handler(app.lanes[i].protocol.name())
                        .and_then(|rh| rh.operation_handler(op.operation));
                    // OPAQUE (non-JSON) egress body — e.g. binary speech audio: bridge at the BYTE
                    // level through the operation codecs and relay the ingress handler's WireBody
                    // (bytes + ITS content-type) verbatim. JSON bodies take the Value path below.
                    // Parse the 2xx body ONCE, then branch on JSON vs opaque (binary). A prior version
                    // probed with a throwaway parse here and re-parsed the same bytes for the JSON path
                    // below, doubling the parse cost of every cross-protocol JSON completion.
                    let body_json = crate::json::parse::<Value>(&bytes);
                    if body_json.is_err() {
                        let decoded = egress_op.map(|h| h.read_response(&bytes));
                        if let Some(Err(ref e)) = decoded {
                            // A binary/opaque upstream body the egress codec cannot decode: log the
                            // CodecError so a repeated wall of 500s has a visible root cause instead of
                            // only the generic 'not translatable' warn below.
                            tracing::warn!(
                                ingress = %ingress_protocol,
                                egress = %app.lanes[i].protocol.name(),
                                error = ?e,
                                "cross-protocol binary response failed the egress codec (read_response); returning ingress-native 500",
                            );
                        }
                        if let Some(Ok(mut ir)) = decoded {
                            record_resp_usage(
                                &ir,
                                &usage_sink,
                                Some((&app.lanes[i].model, &app.lanes[i].provider)),
                            );
                            ir.prepare_for_ingress(ingress_protocol, now());
                            if let Some(wire) = crate::handlers::request_handler(ingress_protocol)
                                .and_then(|rh| rh.operation_handler(op.operation))
                                .map(|h| h.write_response(&ir))
                            {
                                let rb = Response::builder()
                                    .status(status)
                                    .header(CONTENT_TYPE, wire.content_type);
                                let rb =
                                    maybe_attach_response_request_id(rb, ingress_protocol, None);
                                let rb = maybe_attach_route_policy(
                                    rb,
                                    chosen_policy_name,
                                    &app.lanes[i].model,
                                );
                                return rb
                                    .body(Body::from(wire.bytes))
                                    .unwrap_or_else(|_| status.into_response());
                            }
                        }
                    }
                    if let Ok(rv) = &body_json {
                        let decoded = egress_op.map(|h| h.read_response_value(rv));
                        if let Some(Err(ref e)) = decoded {
                            // A JSON 2xx whose shape the egress codec rejects (e.g. a missing
                            // `embedding` array): log the CodecError before the generic 500 so the
                            // operator can tell a broken upstream from a new/renamed response field.
                            tracing::warn!(
                                ingress = %ingress_protocol,
                                egress = %app.lanes[i].protocol.name(),
                                error = ?e,
                                "cross-protocol JSON response failed the egress codec (read_response_value); returning ingress-native 500",
                            );
                        }
                        if let Some(Ok(mut ir)) = decoded {
                            if let Some(ingress_proto) =
                                crate::proto::protocol_for(ingress_protocol)
                            {
                                // Token accounting: we are now committed to translating and
                                // delivering this body (every exit from this block is a delivered
                                // response). No FirstByteBody on this buffered path, so bill here —
                                // straight from the IR usage the egress reader just decoded (Change A).
                                record_resp_usage(
                                    &ir,
                                    &usage_sink,
                                    Some((&app.lanes[i].model, &app.lanes[i].provider)),
                                );
                                // OPERATION-BLIND ingress preparation: the IR reshapes ITSELF for
                                // delivery in the caller's dialect (chat: native-identity strip, the
                                // protocol-agnostic `created` boundary signal, tool-id remap — see
                                // `IrResp::prepare_for_ingress` for the full rationale, relocated
                                // verbatim from this seam).
                                ir.prepare_for_ingress(ingress_protocol, now());
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
                                if wants_stream {
                                    let elapsed_ms =
                                        u64::try_from(upstream_started.elapsed().as_millis()).ok();
                                    if let Some(frames) = ir
                                        .wrap_buffered_as_stream(ingress_proto.writer(), elapsed_ms)
                                    {
                                        let rb = Response::builder().status(status).header(
                                            CONTENT_TYPE,
                                            ingress_proto.writer().streaming_content_type(),
                                        );
                                        let rb = maybe_attach_response_request_id(
                                            rb,
                                            ingress_protocol,
                                            None,
                                        );
                                        let rb = maybe_attach_route_policy(
                                            rb,
                                            chosen_policy_name,
                                            &app.lanes[i].model,
                                        );
                                        return rb
                                            .body(Body::from(frames))
                                            .unwrap_or_else(|_| status.into_response());
                                    }
                                }
                                // The INGRESS operation handler writes its dialect (chat's
                                // delegates to the same writer vtable — byte-identical).
                                let ingress_op = crate::handlers::request_handler(ingress_protocol)
                                    .and_then(|rh| rh.operation_handler(op.operation));
                                let Some(ingress_op) = ingress_op else {
                                    return ingress_error(
                                        ingress_protocol,
                                        StatusCode::NOT_FOUND,
                                        KIND_NOT_FOUND,
                                        DETAIL_ENDPOINT_UNSUPPORTED_OPERATION,
                                    );
                                };
                                let mut translated = match ingress_op.write_response_value(&ir) {
                                    Some(t) => t,
                                    None => {
                                        // The ingress dialect's response is NOT JSON (binary
                                        // speech): relay the WireBody — bytes + its content-type.
                                        let wire = ingress_op.write_response(&ir);
                                        let rb = Response::builder()
                                            .status(status)
                                            .header(CONTENT_TYPE, wire.content_type);
                                        let rb = maybe_attach_response_request_id(
                                            rb,
                                            ingress_protocol,
                                            None,
                                        );
                                        let rb = maybe_attach_route_policy(
                                            rb,
                                            chosen_policy_name,
                                            &app.lanes[i].model,
                                        );
                                        return rb
                                            .body(Body::from(wire.bytes))
                                            .unwrap_or_else(|_| status.into_response());
                                    }
                                };
                                // A native AWS Bedrock Converse (non-stream) response ALWAYS populates
                                // `metrics.latencyMs` (the SDK surfaces it via
                                // `ConverseOutput::metrics().latencyMs()`); the bedrock writer's
                                // `write_response` deliberately emits only output/stopReason/usage, so a
                                // bedrock-ingress non-stream client would read `metrics == None` — the
                                // same proxy tell the streaming path already injects against. Mirror the
                                // streaming policy: inject the real request elapsed wall-clock here, and
                                // OMIT `metrics` rather than fabricate a tell-tale `0` if timing is
                                // unavailable.
                                ingress_proto.writer().inject_response_metrics(
                                    &mut translated,
                                    u64::try_from(upstream_started.elapsed().as_millis()).ok(),
                                );
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
                                    let rb = Response::builder()
                                        .status(status)
                                        .header(CONTENT_TYPE, APPLICATION_JSON);
                                    let rb = maybe_attach_route_policy(
                                        rb,
                                        chosen_policy_name,
                                        &app.lanes[i].model,
                                    );
                                    return rb
                                        .body(Body::from(
                                            crate::json::to_vec(&arr)
                                                .unwrap_or_else(|_| arr.to_string().into_bytes()),
                                        ))
                                        .unwrap_or_else(|_| status.into_response());
                                }
                                // Content-Type is the INGRESS JSON CT, not the upstream's — the body
                                // is now in the client's native non-stream shape (§8.4). A
                                // bedrock-ingress 2xx also carries `x-amzn-RequestId` (matching a real
                                // Converse response and the error path).
                                let rb = Response::builder()
                                    .status(status)
                                    .header(CONTENT_TYPE, APPLICATION_JSON);
                                // The ingress writer's vtable attaches its native response request-id
                                // header (bedrock `x-amzn-RequestId`, anthropic `request-id`). This is
                                // the CROSS-protocol translate path (ingress != egress), so there is no
                                // upstream id to forward — `None` makes the writer synthesize one. ONE
                                // call dispatches per protocol; a second call would APPEND a duplicate
                                // header (axum `header()` appends, not replaces).
                                let rb =
                                    maybe_attach_response_request_id(rb, ingress_protocol, None);
                                let rb = maybe_attach_route_policy(
                                    rb,
                                    chosen_policy_name,
                                    &app.lanes[i].model,
                                );
                                // sonic-rs: SIMD serialize of the translated client body (the
                                // response-path hot spot); fall back to serde_json on the
                                // effectively-impossible serialize error.
                                let body_bytes = crate::json::to_vec(&translated)
                                    .unwrap_or_else(|_| translated.to_string().into_bytes());
                                return rb
                                    .body(Body::from(body_bytes))
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
                        KIND_API_ERROR,
                        GENERIC_RESPONSE_ERROR_DETAIL,
                    );
                }

                // Use FirstByteBody wrapper to track first byte and emit SSE error events on mid-stream failures
                // on a cross-protocol SSE response, translate egress frames → ingress frames.
                let egress_name_for_translate = app.lanes[i].protocol.name();
                let translate = if is_sse {
                    if ingress_protocol == egress_name_for_translate {
                        // SAME-PROTOCOL SSE/event-stream (Change B, now permanent): always run the
                        // verbatim same-proto translator (byte-exact re-emit + IR usage A-tap). The
                        // universal path is unconditional — billing now sources `translate.usage()`, so
                        // there is no longer a passthrough that bypasses the IR. `new_same_proto` is
                        // `None` only for an unknown protocol, where there is no reader to drive the IR;
                        // that falls back to the legacy raw-chunk passthrough (`None`).
                        crate::proto::StreamTranslate::new_same_proto(ingress_protocol)
                    } else {
                        crate::proto::StreamTranslate::new(
                            ingress_protocol,
                            egress_name_for_translate,
                        )
                    }
                } else {
                    None
                };
                // Gemini non-`alt=sse` ingress: engage the JSON-array framer (only when this is in
                // fact a streamed SSE response — a same-protocol non-stream gemini response never
                // reaches the streaming builder).
                let json_array = (gemini_json_array && is_sse)
                    .then(|| {
                        crate::proto::protocol_for(ingress_protocol)
                            .and_then(|p| p.writer().make_array_stream_framer())
                    })
                    .flatten();
                let upstream_stream = r.bytes_stream();
                let guarded_body = FirstByteBody::new(
                    upstream_stream,
                    is_sse,
                    ingress_protocol,
                    op,
                    permit,
                    app.clone(),
                    i,
                    breaker_cfg.clone(),
                    pool_name,
                    translate,
                    json_array,
                    usage_sink,
                    budget_spent,
                );
                let axum_body = guarded_body.into_body();

                let mut rb = Response::builder().status(status);
                // Cross-protocol streaming: the body is reframed to the client's format, so the CT
                // must be the ingress client's, not the upstream's. Same-protocol passthrough keeps
                // the upstream CT verbatim. §8.4.
                let cross_protocol = ingress_protocol != app.lanes[i].protocol.name();
                if gemini_json_array && is_sse {
                    // JSON-array streaming body: a `[ {...}, {...} ]` document, not SSE.
                    rb = rb.header(CONTENT_TYPE, APPLICATION_JSON);
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
                // always does, preferring the captured same-protocol upstream id else synthesizing);
                // anthropic-ingress streaming 2xx must carry `request-id` (the SDK reads it into
                // `Message._request_id`). The writer vtable selects the correct header+value per
                // protocol from the captured upstream id; non-relaying ingress: omit.
                rb = maybe_attach_response_request_id(
                    rb,
                    ingress_protocol,
                    upstream_relay_id.as_deref(),
                );
                // TRANSPARENCY: stamp which routing policy chose this target (no-op on the default
                // path / when the policy Abstained). Covers same-protocol passthrough + all streaming.
                rb = maybe_attach_route_policy(rb, chosen_policy_name, &app.lanes[i].model);
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
        op,
        req_content_type,
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
    op: crate::handlers::Op,
    req_content_type: &str,
    usage_sink: Option<UsageSink>,
) -> Response {
    // Cycle-guard fix (LOW #22): mark the ORIGINATING pool visited here, BEFORE the mode lookup —
    // this is the single point every pool's exhaustion handling flows through. The loop guard in
    // `handle_fallback_pool` only checks/marks the FALLBACK pool name, so an A->B->A chain was not
    // caught on the second hop: when A exhausted it jumped straight to `handle_fallback_pool(B)`
    // (marking only B), and when B then fell back to A, the guard saw A as unvisited and recursed
    // into A's members again before terminating. Marking A here means a later hop back to A is
    // recognized as a cycle and terminates via the guard. Idempotent (set insert); harmless on the
    // non-cyclic single-hop case where A is never revisited.
    request_ctx.mark_pool_visited(pool_name);

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
                op,
                req_content_type,
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
                op,
                req_content_type,
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
        KIND_OVERLOADED,
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
    // The routing POOL cell this degraded attempt was selected against (fallback-pool member or
    // least-bad member). ALL breaker recordings here (success/transient) must target THIS cell, not
    // the default `""` cell: the degraded callers select via the POOL cell and (for fallback) CAS-win
    // a single-flight HalfOpen probe on it, so recording on `""` left the pool cell wedged HalfOpen +
    // `probe_in_flight` forever. An empty `pool` means the lane-default cell (direct/ad-hoc routes).
    pool: &str,
    op: crate::handlers::Op,
    req_content_type: &str,
    usage_sink: Option<UsageSink>,
    // The selected pool member's `reasoning` override (`WeightedLane.reasoning`), resolved by the
    // caller from its candidate slice. `None` = no member override → fall back to the lane flag. The
    // degraded path has no `cands` in scope, so the caller passes the already-resolved override here
    // (mirrors the hot path's `effective_reasoning`). (found: audit c2r3.)
    reasoning_override: Option<bool>,
) -> Result<Response, ()> {
    // Re-parse body for per-lane model rewriting. An OPAQUE (non-JSON) body — multipart/binary
    // operations — parses to `None` and relays/translates at the byte level, exactly like the main
    // path; only a JSON-Content-Type body that FAILS to parse is the caller's 400.
    let v: Option<Value> = match crate::json::parse(body) {
        Ok(v) => Some(v),
        Err(_) if !req_content_type.starts_with(APPLICATION_JSON) => None,
        Err(_) => {
            // See the main forward path: log a sanitized note for operators; never the parser's raw
            // error (with sonic-rs it embeds a fragment of the input body — secrets/PII) nor leak it
            // into the client 400 body.
            tracing::debug!(detail = %crate::json::parse_err_log(body.len()), "request body JSON parse failed");
            // Probe-leak guard (HIGH #1): a fallback-pool caller CAS-won a single-flight HalfOpen
            // probe on the POOL cell in `pick_among` before entering here, and the contract is that
            // EVERY early return out of `forward_once` releases it. This is a pre-dispatch bail (no
            // breaker outcome recorded), so without an explicit release the cell stays HalfOpen +
            // `probe_in_flight`, benching the lane forever. `release_probe_in` is idempotent and a
            // no-op on the default `""` cell / a non-HalfOpen cell, so it is safe on every path.
            app.store.release_probe_in(pool, i);
            return Ok(ingress_error(
                ingress_protocol,
                StatusCode::BAD_REQUEST,
                KIND_INVALID_REQUEST,
                "We could not parse the JSON body of your request.",
            ));
        }
    };

    // stream intent for the stream-aware upstream path (Gemini).
    let wants_stream = v
        .as_ref()
        .and_then(|v| v.get("stream"))
        .and_then(|s| s.as_bool())
        .unwrap_or(false);
    // Gemini ingress streaming WITHOUT `?alt=sse` → JSON-array streamed body (see main path). GATED
    // on `uses_array_stream_shim()` (true only for GeminiWriter) so a body-model client cannot
    // smuggle the shim key to force JSON-array reframing of its SSE stream.
    let gemini_json_array = crate::proto::protocol_for(ingress_protocol)
        .map(|p| {
            p.writer().uses_array_stream_shim()
                && v.as_ref()
                    .map(|v| p.writer().wants_array_stream(v))
                    .unwrap_or(false)
        })
        .unwrap_or(false);
    let egress_name = app.lanes[i].protocol.name();

    // Breaker config for THIS degraded attempt's routing pool cell — resolved the same way the main
    // forward path resolves `breaker_cfg` (per-pool settings, ADR-0002 default fallback). All breaker
    // recordings below target the `pool` cell with this cfg so the degraded path trips/cools the pool
    // cell against its own thresholds, not a one-size default. Wrapped in an `Arc` so the streaming
    // `FirstByteBody` guard can record mid-stream failures with the SAME thresholds the synchronous
    // path used (mirrors `forward_with_pool`).
    let forward_once_cfg: std::sync::Arc<crate::store::BreakerCfg> = std::sync::Arc::new(
        app.pool_runtime
            .get(pool)
            .and_then(|r| r.breaker.clone())
            .unwrap_or_default(),
    );

    // Cross-protocol request shaping through the SINGLE shared seam (read→clear-extra→write, shim-key
    // strip, model rewrite, serialize) — the SAME function the hot `forward_with_pool` path uses, so
    // this degraded route cannot drift from it. This unification is what fixes the R9 high (this path
    // previously lacked the `ir.extra.clear()` the hot path had, leaking source-only keys like OpenAI
    // `logprobs`/`top_logprobs`/`n` to a foreign backend): the clear now lives in the one shared fn,
    // so neither path can be missing it.
    let body_is_json = v.is_some();
    let payload = match translate_request_cross_protocol(
        app,
        i,
        ingress_protocol,
        op,
        v,
        req_content_type,
        // Honor the pool member's `reasoning` override (as the hot path does via
        // `effective_reasoning`), falling back to the lane-level flag. (found: audit c2r3.)
        reasoning_override.unwrap_or(app.lanes[i].reasoning),
        body,
    ) {
        Ok(p) => p,
        Err(resp) => {
            // Probe-leak guard (HIGH #1): release the POOL-cell single-flight probe this
            // fallback attempt CAS-won before bailing on a translation failure (a pre-dispatch
            // early return — no breaker outcome recorded). Idempotent; no-op off a HalfOpen cell.
            app.store.release_probe_in(pool, i);
            return Ok(*resp);
        }
    };
    let base = &app.lanes[i].base_url;

    // Mode-aware key selection: passthrough uses caller token, others use lane's api_key.
    let key = match app.upstream_creds() {
        // Passthrough forwards the CALLER's credential upstream. When the caller presents NO
        // credential, fall back to an EMPTY credential — NOT the lane operator's `api_key`
        // (LOW #15 SECURITY): borrowing the operator key would let an unauthenticated caller
        // silently spend on the operator's upstream account. An empty credential makes the
        // provider return its own 401/403, attributed to the caller (a client-auth fault, no
        // lane penalty), matching the documented passthrough contract. No-op in canonical
        // keyless passthrough (lane.api_key already empty); only changes the misconfigured
        // passthrough+configured-key case.
        crate::auth::UpstreamCreds::Passthrough => caller_token.unwrap_or(""),
        crate::auth::UpstreamCreds::Own => &app.lanes[i].api_key,
    };

    // per-request auth (SigV4 for Bedrock; static otherwise).
    let writer = app.lanes[i].protocol.writer();
    let url_path = match op.upstream_path(&app.lanes[i], wants_stream) {
        Some(p) => p,
        None => {
            // Unreachable for chat; the router filters unsupported lanes before the degraded path
            // is reached. Bail safely, releasing any single-flight probe this lane won (same probe
            // contract as forward_once's other pre-dispatch guards).
            app.store.release_probe_in(pool, i);
            return Ok(ingress_error(
                ingress_protocol,
                StatusCode::INTERNAL_SERVER_ERROR,
                KIND_API_ERROR,
                DETAIL_INTERNAL_ERROR,
            ));
        }
    };
    // Sign and send the SAME path encoding — see `sign_and_wire_path_parts` (mirrors the main forward
    // path): it returns the SigV4 canonical_uri (query stripped) alongside the wire path, so the
    // degraded path no longer re-splits and allocates a second String for the canonical URI.
    let (wire_path, canonical_uri) = sign_and_wire_path_parts(&url_path);
    let signing_ctx = crate::proto::SigningContext {
        host: host_from_base(base),
        canonical_uri,
        body: &payload,
        timestamp_epoch: now(),
        upstream_creds: app.upstream_creds(),
    };
    let auth = lane_auth_headers(&app.lanes[i], key, &signing_ctx);

    // Egress Content-Type — mirror the main forward path exactly (it was hardcoded APPLICATION_JSON
    // here, which sent an opaque multipart transcription / binary body upstream as application/json,
    // a guaranteed 400). JSON body -> JSON; same-protocol opaque -> the caller's own CT (boundary
    // preserved); cross-protocol opaque -> the egress operation handler's declared wire CT.
    let egress_ct: &str = if body_is_json {
        APPLICATION_JSON
    } else if ingress_protocol == egress_name {
        req_content_type
    } else {
        crate::handlers::request_handler(egress_name)
            .and_then(|rh| rh.operation_handler(op.operation))
            .map(|h| h.egress_request_content_type())
            .unwrap_or(APPLICATION_JSON)
    };
    let mut req = app
        .client
        .post(format!("{base}{wire_path}"))
        .headers(convert_headers(auth))
        .header(CONTENT_TYPE, egress_ct)
        // Native-SDK User-Agent for the egress protocol (mirrors the main forward path). Dispatched
        // through the writer vtable (`ProtocolWriter::egress_user_agent`) — writer resolved above.
        .header(USER_AGENT, writer.egress_user_agent())
        // Native-SDK Accept for the egress protocol (mirrors the main forward path). Dispatched
        // through the writer vtable (`ProtocolWriter::egress_accept`) — no `"bedrock"` branch here.
        .header(ACCEPT, op.egress_accept(writer, wants_stream))
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
    // Per-attempt time-to-headers cap on the DEGRADED path too (lane-level only: this path selects
    // by pool cell, not a member row, so the member override does not apply here). Expiry = the same
    // transport-timeout handling as the reqwest error below.
    let res = match app.lanes[i].attempt_timeout_ms {
        Some(ms) => {
            let cap = attempt_cap(ms, timeout_secs);
            match tokio::time::timeout(cap, req.send()).await {
                Ok(r) => r,
                Err(_elapsed) => {
                    record_upstream_rtt(upstream_started.elapsed());
                    tracing::warn!(
                        pool = %pool,
                        lane = %app.lanes[i].model,
                        attempt_timeout_ms = ms,
                        "no response headers within the attempt cap (degraded path)"
                    );
                    // Mirror the transport-error handling: record transient on the POOL cell and
                    // signal the caller to try the next degraded candidate.
                    let tripped = app.store.record_transient_in(
                        pool,
                        i,
                        ERR_NET_TIMEOUT,
                        forward_once_cfg.as_ref(),
                        None,
                    );
                    if tripped {
                        emit_breaker_trip(app, pool, i);
                    }
                    app.store.release_probe_in(pool, i);
                    metrics::counter!(
                        crate::metrics::UPSTREAM_FAILURES_TOTAL,
                        "pool" => pool.to_string(),
                        "lane" => app.lanes[i].model.clone(),
                        "disposition" => DISPOSITION_ATTEMPT_TIMEOUT
                    )
                    .increment(1);
                    // Parity with the organic path: a degraded-path attempt-timeout is a failover
                    // (the caller tries the next candidate), so count it under FAILOVERS_TOTAL too.
                    metrics::counter!(
                        crate::metrics::FAILOVERS_TOTAL,
                        "pool" => pool.to_string(),
                        "reason" => DISPOSITION_ATTEMPT_TIMEOUT
                    )
                    .increment(1);
                    return Err(());
                }
            }
        }
        None => req.send().await,
    };
    record_upstream_rtt(upstream_started.elapsed());

    match res {
        Ok(r) => {
            let status = r.status();
            let ct = r.headers().get(CONTENT_TYPE).cloned();
            // Capture the upstream relayed request-id-class headers before `r` is consumed, keyed off
            // the ingress writer's `ingress_relayed_response_header_names` so this names no protocol
            // module. For a bedrock ingress this captures `x-amzn-requestid` (the PRIMARY id —
            // forwarded verbatim on a same-protocol passthrough, or replaced by a synthesized id
            // cross-protocol below) followed by `x-amzn-errortype` (a native ConverseStream/Converse
            // error always carries it; AWS SDKs dispatch the typed exception from this header FIRST,
            // before the body `__type`; its absence is a detectable proxy tell). For an anthropic
            // ingress it captures `request-id` (the primary id). Empty for non-relaying ingress.
            let bedrock_relay_headers: Vec<(&'static str, String)> =
                ingress_relayed_response_header_names(ingress_protocol)
                    .iter()
                    .filter_map(|name| {
                        let v = r.headers().get(*name)?.to_str().ok()?.to_string();
                        Some((*name, v))
                    })
                    .collect();
            // The PRIMARY relayed id is the FIRST relayed header (x-amzn-requestid for bedrock,
            // request-id for anthropic); the writer vtable picks the correct response header to attach
            // it under on the 2xx success path. The bedrock-only second header (`x-amzn-errortype`) is
            // forwarded verbatim alongside it from `bedrock_relay_headers` on the error relay below.
            let upstream_relay_id = bedrock_relay_headers.first().map(|(_, v)| v.clone());
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
                    // Probe-leak guard (HIGH #1): a non-2xx response carries no breaker recording
                    // on this degraded relay path (it relays verbatim, no disposition), so the
                    // single-flight HalfOpen probe this fallback attempt CAS-won on the POOL cell
                    // is still in flight. Release it before returning or the cell stays HalfOpen +
                    // `probe_in_flight` forever. Idempotent; no-op off a HalfOpen / default cell.
                    //
                    // Cooldown-backoff fix: record a transient failure BEFORE releasing the probe, so
                    // a non-2xx on a HalfOpen probe bumps the cooldown (exponential backoff) exactly
                    // like the MAIN forward path's non-2xx branch. Releasing alone left the cooldown
                    // at its original expiry, so the lane re-probed at the base interval with no
                    // backoff. No `record_transient_in` exists on this branch today, so this does not
                    // double-record. A threshold re-trip here is a breaker trip too (#29).
                    let tripped = app.store.record_transient_in(
                        pool,
                        i,
                        ERR_DEGRADED_NON2XX,
                        forward_once_cfg.as_ref(),
                        None,
                    );
                    if tripped {
                        emit_breaker_trip(app, pool, i);
                    }
                    app.store.release_probe_in(pool, i);
                    return Ok(shape_cross_protocol_error(ingress_protocol, status, &bytes));
                }
                // Same-protocol degraded path: relay the upstream error verbatim (no classification).
                let mut rb = Response::builder().status(status);
                if let Some(ct) = ct {
                    rb = rb.header(CONTENT_TYPE, ct);
                }
                if ingress_relays_amzn_headers(ingress_protocol) {
                    // Bedrock-ingress same-protocol error relay: forward BOTH `x-amzn-requestid` and
                    // `x-amzn-errortype` VERBATIM (no synth), mirroring the main `forward_with_pool`
                    // path. Without them a native AWS SDK's `request_id()` returns None and the
                    // typed-exception dispatch falls back from header-first to body `__type` — both
                    // detectable tells. (This degraded route previously captured the id but never
                    // attached it, and dropped the errortype.) The header NAMES + VALUES come from the
                    // vtable-keyed `bedrock_relay_headers` capture, so this names no protocol module.
                    for (name, value) in &bedrock_relay_headers {
                        rb = rb.header(*name, value);
                    }
                } else {
                    // Anthropic-ingress same-protocol error relay: forward the upstream `request-id`
                    // (a native Anthropic error always carries it; the SDK reads it into
                    // `APIError.request_id`), synthesizing one if the upstream omitted it. The writer
                    // vtable selects the `request-id` header name and the upstream-or-synth value.
                    rb = maybe_attach_response_request_id(
                        rb,
                        ingress_protocol,
                        upstream_relay_id.as_deref(),
                    );
                }
                // Probe-leak guard (HIGH #1): same as the cross-protocol non-2xx branch above —
                // a verbatim same-protocol error relay records no breaker outcome, so release the
                // POOL-cell single-flight probe this fallback attempt CAS-won before returning, or
                // the cell stays HalfOpen + `probe_in_flight` forever. Idempotent; no-op off a
                // HalfOpen / default cell.
                //
                // Cooldown-backoff fix: record a transient failure BEFORE releasing the probe, so a
                // non-2xx on a HalfOpen probe bumps the cooldown (exponential backoff) like the MAIN
                // forward path's non-2xx branch. Without it the cooldown stayed at its original expiry
                // and the lane re-probed at the base interval with no backoff. No `record_transient_in`
                // exists on this branch today, so this does not double-record. A threshold re-trip
                // here is a breaker trip too (#29).
                let tripped = app.store.record_transient_in(
                    pool,
                    i,
                    ERR_DEGRADED_NON2XX,
                    forward_once_cfg.as_ref(),
                    None,
                );
                if tripped {
                    emit_breaker_trip(app, pool, i);
                }
                app.store.release_probe_in(pool, i);
                return Ok(rb
                    .body(Body::from(bytes))
                    .unwrap_or_else(|_| status.into_response()));
            }

            // SUCCESS: the degraded path served a 2xx. Mirror the main forward loop
            // (forward_with_pool) — record the lane success against the ROUTING POOL cell (feeds the
            // breaker success window so a HalfOpen lane served via fallback/least-bad recovers the
            // POOL cell to Closed and clears its single-flight probe) and consume one unit of its
            // lifetime request budget. The degraded callers select via the pool cell, so recording on
            // the default `""` cell left the pool cell wedged HalfOpen + probe_in_flight forever.
            app.store.record_success_in(pool, i);
            // Mirror the main path: fold time-to-headers into the lane's latency EWMA (routing
            // `fastest` signal). Lane-global; off the selection path.
            app.store
                .record_latency_in(pool, i, upstream_started.elapsed().as_secs_f64() * 1000.0);
            // BIND the spend result (#21): a paired post-headers body TransportError below refunds the
            // budget, but `refund_budget` UNCONDITIONALLY fetch_adds — so refunding a spend that was a
            // no-op (budget already 0) would raise the budget ABOVE its cap. Only refund if this spend
            // actually decremented. `budget_spent` is `true` for an unlimited lane (spend is a no-op
            // success there), so an unlimited lane never refunds (refund_budget is also a no-op there).
            let budget_spent = app.store.spend_budget(i);

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
                let (bytes, read_end) = read_capped(r, max_translated_body_bytes()).await;
                // Re-record the upstream RTT through full-body receipt (see the main forward path):
                // on the buffered cross-protocol path the body-download is upstream cost, not Busbar's,
                // so the `Server-Timing` figure must exclude it.
                record_upstream_rtt(upstream_started.elapsed());
                drop(permit); // a buffered (non-streamed) response holds no permit
                if read_end == ReadEnd::TransportError {
                    // Body failed mid-transfer after an optimistic success/budget recording on the
                    // 2xx headers (see the main forward path): don't charge tokens for a corrupt
                    // fragment, record a compensating transient failure against the ROUTING POOL cell
                    // (so the pool cell — not the default `""` cell — sees the failed transfer), refund
                    // the request budget unit spent on the headers (no usable response was delivered,
                    // so a failed body transfer must not permanently drain the lane's `max_requests`
                    // budget), and return an ingress-native error. Refund ONLY if the spend actually
                    // decremented (#21) — `refund_budget` is an unconditional fetch_add, so refunding a
                    // no-op spend would push the budget above its cap.
                    tracing::warn!(
                        ingress = %ingress_protocol,
                        egress = %egress_name,
                        "cross-protocol non-stream upstream body failed mid-transfer; \
                         not recording success/usage, refunding budget, returning ingress-native error"
                    );
                    let tripped = app.store.record_transient_in(
                        pool,
                        i,
                        ERR_NET_TRANSPORT,
                        forward_once_cfg.as_ref(),
                        None,
                    );
                    // A threshold-based Closed→Open trip here is a breaker trip too (#29); emit the
                    // metric, mirroring the main forward path — otherwise BREAKER_TRIPS_TOTAL
                    // undercounts trips on this degraded (FallbackPool/LeastBad) path.
                    if tripped {
                        emit_breaker_trip(app, pool, i);
                    }
                    if budget_spent {
                        app.store.refund_budget(i);
                    }
                    return Ok(ingress_error(
                        ingress_protocol,
                        StatusCode::BAD_GATEWAY,
                        KIND_API_ERROR,
                        GENERIC_RESPONSE_ERROR_DETAIL,
                    ));
                }
                if read_end == ReadEnd::Truncated {
                    // Upstream body exceeded OUR translation cap → client gets a 500 with no
                    // completion, so tokens are NOT charged here (accounting lives after this guard),
                    // matching the TransportError branch and the main forward path. This is our own
                    // size limit, not an upstream fault, so the optimistic breaker success stands and
                    // the budget unit is NOT refunded.
                    tracing::warn!(
                        ingress = %ingress_protocol,
                        egress = %egress_name,
                        cap = max_translated_body_bytes(),
                        "cross-protocol non-stream success body exceeded the translation cap; \
                         cannot translate, not charging tokens, returning ingress-native error"
                    );
                    return Ok(ingress_error(
                        ingress_protocol,
                        StatusCode::INTERNAL_SERVER_ERROR,
                        KIND_API_ERROR,
                        GENERIC_RESPONSE_ERROR_DETAIL,
                    ));
                }
                // Token accounting deferred to the delivery seam below (#2), mirroring the main
                // forward path: a 2xx whose usage parses but whose content shape is unmodeled (or
                // whose ingress protocol fails `protocol_for`) falls through to the ingress-native
                // 500 below with NO completion delivered, so charging before translation is proven
                // would bill the key for a body the client never receives.
                let egress_op = crate::handlers::request_handler(app.lanes[i].protocol.name())
                    .and_then(|rh| rh.operation_handler(op.operation));
                // Parse the body ONCE, then branch on JSON vs opaque (binary) — mirrors the main
                // forward path. Without the binary arm, a cross-protocol speech/transcription response
                // (raw audio bytes) failed the JSON parse and fell straight through to the generic 500
                // below, so every binary-body cross-protocol op on a fallback/least-bad lane 500'd
                // even though the main path serves it correctly.
                let body_json = crate::json::parse::<Value>(&bytes);
                if body_json.is_err() {
                    let decoded = egress_op.map(|h| h.read_response(&bytes));
                    if let Some(Err(ref e)) = decoded {
                        tracing::warn!(
                            ingress = %ingress_protocol,
                            egress = %egress_name,
                            error = ?e,
                            "cross-protocol binary response failed the egress codec (read_response, degraded path); returning ingress-native 500",
                        );
                    }
                    if let Some(Ok(mut ir)) = decoded {
                        record_resp_usage(
                            &ir,
                            &usage_sink,
                            Some((&app.lanes[i].model, &app.lanes[i].provider)),
                        );
                        ir.prepare_for_ingress(ingress_protocol, now());
                        if let Some(wire) = crate::handlers::request_handler(ingress_protocol)
                            .and_then(|rh| rh.operation_handler(op.operation))
                            .map(|h| h.write_response(&ir))
                        {
                            let rb = Response::builder()
                                .status(status)
                                .header(CONTENT_TYPE, wire.content_type);
                            let rb = maybe_attach_response_request_id(rb, ingress_protocol, None);
                            return Ok(rb
                                .body(Body::from(wire.bytes))
                                .unwrap_or_else(|_| status.into_response()));
                        }
                    }
                }
                if let Ok(rv) = &body_json {
                    let decoded = egress_op.map(|h| h.read_response_value(rv));
                    if let Some(Err(ref e)) = decoded {
                        // Degraded/fallback path: same swallowed-CodecError gap as the main forward
                        // path — log the codec error before the generic 500 so repeated failures on a
                        // fallback lane have a visible root cause.
                        tracing::warn!(
                            ingress = %ingress_protocol,
                            egress = %app.lanes[i].protocol.name(),
                            error = ?e,
                            "cross-protocol JSON response failed the egress codec (read_response_value, degraded path); returning ingress-native 500",
                        );
                    }
                    if let Some(Ok(mut ir)) = decoded {
                        if let Some(ingress_proto) = crate::proto::protocol_for(ingress_protocol) {
                            // Token accounting: committed to translating and delivering this body
                            // (every exit below is a delivered response). No FirstByteBody on this
                            // buffered path, so bill from the IR usage just decoded (Change A,
                            // mirrors the main path).
                            record_resp_usage(
                                &ir,
                                &usage_sink,
                                Some((&app.lanes[i].model, &app.lanes[i].provider)),
                            );
                            // OPERATION-BLIND ingress preparation (identity strip, `created`
                            // boundary signal, tool-id remap) — the SAME seam transform the main
                            // path applies; relocated verbatim into `IrResp::prepare_for_ingress`.
                            ir.prepare_for_ingress(ingress_protocol, now());
                            // Bedrock ConverseStream request answered by a buffered (non-SSE) 2xx:
                            // emit the native binary eventstream frame sequence, not an
                            // `application/json` Converse body the SDK's stream decoder cannot parse
                            // (mirrors the main forward path; dispatches through writer vtable).
                            if wants_stream {
                                let elapsed_ms =
                                    u64::try_from(upstream_started.elapsed().as_millis()).ok();
                                if let Some(frames) =
                                    ir.wrap_buffered_as_stream(ingress_proto.writer(), elapsed_ms)
                                {
                                    let rb = Response::builder().status(status).header(
                                        CONTENT_TYPE,
                                        ingress_proto.writer().streaming_content_type(),
                                    );
                                    let rb = maybe_attach_response_request_id(
                                        rb,
                                        ingress_protocol,
                                        None,
                                    );
                                    return Ok(rb
                                        .body(Body::from(frames))
                                        .unwrap_or_else(|_| status.into_response()));
                                }
                            }
                            let ingress_op = crate::handlers::request_handler(ingress_protocol)
                                .and_then(|rh| rh.operation_handler(op.operation));
                            let Some(ingress_op) = ingress_op else {
                                return Ok(ingress_error(
                                    ingress_protocol,
                                    StatusCode::NOT_FOUND,
                                    KIND_NOT_FOUND,
                                    DETAIL_ENDPOINT_UNSUPPORTED_OPERATION,
                                ));
                            };
                            let mut translated = match ingress_op.write_response_value(&ir) {
                                Some(t) => t,
                                None => {
                                    // Binary ingress dialect: relay the WireBody verbatim.
                                    let wire = ingress_op.write_response(&ir);
                                    let rb = Response::builder()
                                        .status(status)
                                        .header(CONTENT_TYPE, wire.content_type);
                                    let rb = maybe_attach_response_request_id(
                                        rb,
                                        ingress_protocol,
                                        None,
                                    );
                                    return Ok(rb
                                        .body(Body::from(wire.bytes))
                                        .unwrap_or_else(|_| status.into_response()));
                                }
                            };
                            // Inject `metrics.latencyMs` for a bedrock-ingress non-stream Converse — a
                            // native AWS Converse always populates it, so its absence is a proxy tell
                            // (mirrors the streaming path and the buffered cross-protocol path above).
                            // OMIT rather than fabricate `0` if timing is unavailable.
                            ingress_proto.writer().inject_response_metrics(
                                &mut translated,
                                u64::try_from(upstream_started.elapsed().as_millis()).ok(),
                            );
                            // Gemini JSON-array streaming answered by a buffered non-SSE 2xx: wrap the
                            // single translated object in a one-element JSON array, matching the native
                            // non-`alt=sse` `streamGenerateContent` array framing (see the main path).
                            if gemini_json_array && wants_stream {
                                let arr = Value::Array(vec![translated]);
                                return Ok(Response::builder()
                                    .status(status)
                                    .header(CONTENT_TYPE, APPLICATION_JSON)
                                    .body(Body::from(
                                        crate::json::to_vec(&arr)
                                            .unwrap_or_else(|_| arr.to_string().into_bytes()),
                                    ))
                                    .unwrap_or_else(|_| status.into_response()));
                            }
                            // The ingress writer's vtable attaches its native response request-id
                            // header (bedrock `x-amzn-RequestId`, anthropic `request-id`). Cross-protocol
                            // degraded translate (ingress != egress): no upstream id to forward, so
                            // `None` synthesizes one. ONE call per protocol — a second would APPEND a
                            // duplicate header.
                            let rb = Response::builder()
                                .status(status)
                                .header(CONTENT_TYPE, APPLICATION_JSON);
                            let rb = maybe_attach_response_request_id(rb, ingress_protocol, None);
                            let body_bytes = crate::json::to_vec(&translated)
                                .unwrap_or_else(|_| translated.to_string().into_bytes());
                            return Ok(rb
                                .body(Body::from(body_bytes))
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
                    KIND_API_ERROR,
                    GENERIC_RESPONSE_ERROR_DETAIL,
                ));
            }

            // Streaming (or same-protocol non-stream): stream with first-byte boundary tracking. On a
            // cross-protocol SSE response, translate egress frames → ingress frames, matching the main
            // path. Mid-stream breaker failures must record against the ROUTING POOL cell with this
            // pool's resolved breaker cfg (mirrors `forward_with_pool`) — NOT the default `""` cell —
            // so a fallback/least-bad stream that fails mid-flight reopens the pool cell it was
            // selected against, never the unrelated default cell.
            let translate = if is_sse && cross_protocol {
                crate::proto::StreamTranslate::new(ingress_protocol, egress_name)
            } else if is_sse && !cross_protocol {
                // SAME-PROTOCOL SSE/event-stream (Change B, now permanent) on the degraded path: mirror
                // the main `forward_with_pool` wiring — the verbatim same-proto translator (byte-exact
                // re-emit + IR usage A-tap). `None` for an unknown protocol → legacy passthrough.
                crate::proto::StreamTranslate::new_same_proto(ingress_protocol)
            } else {
                None
            };
            let json_array = (gemini_json_array && is_sse)
                .then(|| {
                    crate::proto::protocol_for(ingress_protocol)
                        .and_then(|p| p.writer().make_array_stream_framer())
                })
                .flatten();
            let upstream_stream = r.bytes_stream();
            let guarded_body = FirstByteBody::new(
                upstream_stream,
                is_sse,
                ingress_protocol,
                op,
                permit,
                app.clone(),
                i,
                forward_once_cfg.clone(),
                pool, // degraded path: the routing pool's breaker cell
                translate,
                json_array,
                usage_sink,
                budget_spent,
            );
            let mut rb = Response::builder().status(status);
            // Cross-protocol streaming: the body is reframed to the client's format, so the CT must
            // describe the ingress client's wire, not the upstream's. Same-protocol keeps the upstream
            // CT verbatim.
            if gemini_json_array && is_sse {
                rb = rb.header(CONTENT_TYPE, APPLICATION_JSON);
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
            // Bedrock-ingress 2xx carries `x-amzn-RequestId`; anthropic-ingress 2xx carries
            // `request-id`: forward the captured upstream id verbatim on a same-protocol passthrough,
            // else synthesize. The writer vtable selects the correct header name + upstream-or-synth
            // value per protocol; non-relaying ingress: omit.
            rb = maybe_attach_response_request_id(
                rb,
                ingress_protocol,
                upstream_relay_id.as_deref(),
            );
            Ok(rb
                .body(guarded_body.into_body())
                .unwrap_or_else(|_| status.into_response()))
        }
        Err(e) => {
            // Pre-response transport error: record transient against the ROUTING POOL cell, drop the
            // permit, signal "try next". The degraded callers selected via the pool cell (fallback CAS
            // -wins a HalfOpen probe on it), so this transport failure must reopen the POOL cell — not
            // the default `""` cell, which would leave the pool cell wedged HalfOpen forever.
            // BREAKER_TRIPS_TOTAL is emitted here too, gated on the trip bool, mirroring the sibling
            // degraded arms (non-2xx at ~3925/3977, post-headers transport at ~4046) so a logical
            // Closed→Open trip is counted exactly once regardless of which degraded failure shape hit
            // it. (`tripped` is false for a HalfOpen reopen / already-Open no-op, so it is not
            // inflated.) Closes the cross-arm counter asymmetry the audit flagged.
            let err_type = if e.is_timeout() {
                ERR_NET_TIMEOUT
            } else {
                ERR_NET_CONNECT
            };
            let tripped =
                app.store
                    .record_transient_in(pool, i, err_type, forward_once_cfg.as_ref(), None);
            if tripped {
                emit_breaker_trip(app, pool, i);
            }
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
    op: crate::handlers::Op,
    req_content_type: &str,
    usage_sink: Option<UsageSink>,
) -> Response {
    // Deadline propagated across hops.
    if request_ctx.expired(now()) {
        return ingress_error(
            ingress_protocol,
            StatusCode::SERVICE_UNAVAILABLE,
            KIND_OVERLOADED,
            DETAIL_REQUEST_TIMEOUT,
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

    // Re-apply any compliance restrict from the primary pool against THIS fallback pool's own member
    // tags — the fallback pool is an independent membership, so without this the "restrictions hold
    // across failover" guarantee would break at the pool boundary. Fail closed (503) if a required
    // restrict leaves no eligible fallback lane. (found: audit c1r13.)
    let fallback_cands = match request_ctx.enforce_restricts(&app, pool_name, fallback_cands) {
        Ok(c) => c,
        Err(name) => {
            tracing::info!(
                policy = name,
                pool = pool_name,
                "compliance restrict left no eligible lane in the fallback pool; fail closed \
                 rather than spill to an ineligible upstream"
            );
            return gate_rejected(ingress_error(
                ingress_protocol,
                StatusCode::SERVICE_UNAVAILABLE,
                KIND_OVERLOADED,
                "No upstream satisfies a required gate's restriction. Please retry shortly.",
            ));
        }
    };

    // Mark before re-entering so a cycle back to this pool is detected.
    request_ctx.mark_pool_visited(pool_name);

    // Try the fallback pool's members (concurrency-aware, accumulating exclusions across hops).
    loop {
        if request_ctx.expired(now()) {
            return ingress_error(
                ingress_protocol,
                StatusCode::SERVICE_UNAVAILABLE,
                KIND_OVERLOADED,
                DETAIL_REQUEST_TIMEOUT,
            );
        }

        let Some((i, permit)) =
            // Fallback-pool selection uses plain SWRR by design: routing POLICY applies to the PRIMARY
            // pool (where it shapes the normal-path lane choice); the fallback pool is the
            // already-degraded overflow path, so it deliberately selects with the unchanged inline SWRR
            // (`policy_order == None`) rather than re-running a policy over the spillover candidates.
            pick_among(&app, &fallback_cands, request_ctx, None, pool_name, None).await
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
                op,
                req_content_type,
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
            // The fallback pool's cell is the one `pick_among` selected this member against (and
            // CAS-won the single-flight HalfOpen probe on) — record this attempt's breaker outcome
            // against THAT cell, not the default `""` cell.
            pool_name,
            op,
            req_content_type,
            // Clone per attempt: a transient transport failure retries the next member, so the sink
            // must survive into the next loop iteration; only a successful stream consumes it.
            usage_sink.clone(),
            // The selected member's `reasoning` override from this fallback pool's candidate slice.
            fallback_cands
                .iter()
                .find(|w| w.idx == i)
                .and_then(|w| w.reasoning),
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
    op: crate::handlers::Op,
    req_content_type: &str,
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
        // The least-bad member was selected via this pool's cell (`find_soonest_cooldown` /
        // `cooldown_remaining_in(pool, …)`), so record its breaker outcome against the POOL cell.
        pool,
        op,
        req_content_type,
        usage_sink,
        // The least-bad member's `reasoning` override from this pool's candidate slice.
        cands
            .iter()
            .find(|w| w.idx == soonest_idx)
            .and_then(|w| w.reasoning),
    )
    .await
    {
        Ok(resp) => resp,
        Err(()) => handle_status_503(app, cands, now, pool, ingress_protocol),
    }
}

#[cfg(test)]
#[path = "tests/usage_tap_tests.rs"]
mod usage_tap_tests;

// Change A deleted the `UsageTap` byte-scanner and its unit tests (usage extraction across protocols,
// message_start input-token counting, feed_whole past-cap, terminal-error detection, eventstream
// metadata/exception). Their job was to prove the byte-scanner matched the wire usage shapes; billing
// now sources `IrUsage` directly from the per-protocol IR readers, which carry their OWN per-reader
// usage tests, plus the billing-parity tests cover all four {stream,non-stream}×{same,cross} combos.

#[cfg(test)]
#[path = "tests/cross_protocol_extra_tests.rs"]
mod cross_protocol_extra_tests;

#[cfg(test)]
#[path = "tests/bedrock_eventstream_tests.rs"]
mod bedrock_eventstream_tests;

#[cfg(test)]
#[path = "tests/auth_style_tests.rs"]
mod auth_style_tests;

#[cfg(test)]
#[path = "tests/attempt_timeout_precedence_tests.rs"]
mod attempt_timeout_precedence_tests;

#[cfg(test)]
#[path = "tests/max_tokens_precedence_tests.rs"]
mod max_tokens_precedence_tests;

#[cfg(test)]
#[path = "tests/on_exhausted_tests.rs"]
mod on_exhausted_tests;

/// Change B step 1 — REQUEST short-circuit. Proves that a same-protocol passthrough request whose
/// body triggers none of invalidators #1-#4 is re-emitted BYTE-IDENTICAL to the retained original
/// (`hop_bytes`), and that each invalidator individually forces NON-pristine and the correct
/// rewritten bytes. Cross-protocol behaviour is exercised elsewhere; here we pin the same-proto path.
#[cfg(test)]
#[path = "tests/request_short_circuit_tests.rs"]
mod request_short_circuit_tests;

/// Change A — BILLING PARITY GATE. Asserts the IR-derived A-tap usage (`StreamTranslate::usage()`,
/// the value Change A routes billing through) produces EXACTLY the billed (input, output) tokens for
/// every {streaming, non-stream} × {same-proto, cross-proto} path. The numbers asserted here are the
/// SAME numbers the deleted `UsageTap` byte-scanner produced for 5/6 protocols; Responses STREAMING
/// is the one CORRECTED case (the byte-scanner read a top-level `usage` that Responses nests under
/// `response.usage`, so it reported 0 and under-billed — the IR reader reads it correctly, so the
/// asserted number here is the new, higher, CORRECT value). The old shadow-check module that fed both
/// the A-tap and the live byte-scanner and asserted agreement has been retired — its job (prove the
/// A-tap matches the byte-scanner) is done, and the byte-scanner no longer exists.
#[cfg(test)]
#[path = "tests/billing_parity_tests.rs"]
mod billing_parity_tests;

#[cfg(test)]
#[path = "tests/mid_stream_error_tests.rs"]
mod mid_stream_error_tests;

#[cfg(test)]
#[path = "tests/ingress_indistinguishability_tests.rs"]
mod ingress_indistinguishability_tests;

#[cfg(test)]
#[path = "tests/forward_once_pool_cell_tests.rs"]
mod forward_once_pool_cell_tests;

#[cfg(test)]
#[path = "tests/ordered_walk_tests.rs"]
mod ordered_walk_tests;

#[cfg(test)]
#[path = "tests/probe_guard_tests.rs"]
mod probe_guard_tests;

#[cfg(test)]
#[path = "tests/hook_opt_in_projection_tests.rs"]
mod hook_opt_in_projection_tests;

#[cfg(test)]
#[path = "tests/hook_seam_tests.rs"]
mod hook_seam_tests;
