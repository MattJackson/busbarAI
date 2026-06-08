// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

use std::sync::Arc;
use std::time::Instant;

use axum::{
    body::Bytes,
    extract::{Path, RawQuery, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use serde_json::Value;

use crate::forward::forward_with_pool;
use crate::state::{App, WeightedLane};

/// enforce a virtual key's allowed-pools list against the resolved target pool. No-op
/// when governance is off (`gov.key` is None) or the key allows all pools. Returns a 403 response
/// to short-circuit when the key may not use this pool.
fn pool_authorized(gov: &crate::governance::GovCtx, pool: &str, proto: &str) -> Option<Response> {
    if let Some(key) = &gov.key {
        if !crate::governance::pool_allowed(key, pool) {
            // The client-facing body carries only vendor-plausible copy — never the internal key id
            // or governance vocabulary (a native vendor 403 never names an operator key or a pool).
            // The key id + pool are recorded server-side via tracing for operator diagnosis.
            tracing::info!(key_id = %key.id, pool = %pool, "governance: key not authorized for pool");
            return Some(ingress_error(
                proto,
                StatusCode::FORBIDDEN,
                "permission_error",
                "Your API key does not have permission to access this resource.",
            ));
        }
    }
    None
}

/// Build the token-usage sink for a request: when governance is on and a virtual key resolved, the
/// response stream charges its tapped token usage to that key's budget at completion (token-accurate
/// accounting). `None` disables it (governance off / no key).
fn usage_sink(
    app: &Arc<App>,
    gov: &crate::governance::GovCtx,
) -> Option<crate::forward::UsageSink> {
    match (&app.governance, &gov.key) {
        (Some(g), Some(key)) => Some(crate::forward::UsageSink {
            gov: g.clone(),
            key_id: key.id.clone(),
            period: key.budget_period.clone(),
        }),
        _ => None,
    }
}

/// The request header that pins a session to a lane for a pool. Defaults to `x-session-id`; a
/// pool's `affinity` config (mode `session`) may name a different header (e.g. `x-user-id`).
fn affinity_header_for<'a>(app: &'a Arc<App>, pool: &str) -> &'a str {
    match app.pool_runtime.get(pool).and_then(|r| r.affinity.as_ref()) {
        Some(a) if a.mode == "session" => a.header_name.as_deref().unwrap_or("x-session-id"),
        _ => "x-session-id",
    }
}

/// reject (402) before forwarding when the resolved virtual key is already over its
/// budget for the current window. No-op when governance is off or the key has no budget cap.
/// Async: the budget read is a (blocking) SQLite query offloaded to the blocking pool inside
/// `is_over_budget_async`, so the request path never stalls a Tokio worker thread.
async fn budget_check(
    app: &Arc<App>,
    gov: &crate::governance::GovCtx,
    proto: &str,
) -> Option<Response> {
    if let (Some(g), Some(key)) = (&app.governance, &gov.key) {
        if g.is_over_budget_async(key, crate::store::now()).await {
            // `insufficient_quota` is the canonical OpenAI/Responses quota error type (the OpenAI
            // writer passes it through verbatim as a real type; the Responses writer maps it
            // explicitly). The older `billing_error` token was not in either vocabulary, so it
            // leaked verbatim as a non-canonical `error.type` that an SDK's typed-exception mapping
            // did not recognize — a router-side tell on a 402.
            //
            // The client-facing message carries only vendor-plausible quota copy — never the
            // internal key id or governance vocabulary. The key id is recorded server-side.
            tracing::info!(key_id = %key.id, "governance: key over budget");
            return Some(ingress_error(
                proto,
                StatusCode::PAYMENT_REQUIRED,
                "insufficient_quota",
                "You have exceeded your current quota. Please check your plan and billing details.",
            ));
        }
    }
    None
}

/// Run the three governance guards (pool-allowed / over-budget / rate-limited) for a request that
/// is about to be forwarded. Returns the protocol-native rejection response (403/402/429) already
/// passed through `finish` — so a governance-rejected request still emits `REQUESTS_TOTAL`, the
/// `REQUEST_DURATION_SECONDS` histogram, and the request-log webhook (no flat-fee charge: `finish`
/// only bills 2xx). Returns `None` when every guard passes and the caller should proceed to
/// resolve+forward. Without this, the early returns from `forward_resolved`/`named`/`adhoc` made
/// every governance-rejected request invisible to Prometheus and the webhook (Round-3 finding).
async fn governance_guard(
    app: &Arc<App>,
    gov: &crate::governance::GovCtx,
    proto: &'static str,
    pool: &str,
    started: Instant,
) -> Option<Response> {
    if let Some(resp) = pool_authorized(gov, pool, proto) {
        return Some(finish(app, gov, proto, pool, started, resp));
    }
    if let Some(resp) = budget_check(app, gov, proto).await {
        return Some(finish(app, gov, proto, pool, started, resp));
    }
    if let Some(resp) = rate_check(app, gov, proto) {
        return Some(finish(app, gov, proto, pool, started, resp));
    }
    None
}

/// reject (429 + Retry-After) before forwarding when the resolved virtual key is over
/// its RPM/TPM for the current window. No-op when governance is off or the key has no rate cap.
fn rate_check(app: &Arc<App>, gov: &crate::governance::GovCtx, proto: &str) -> Option<Response> {
    if let (Some(g), Some(key)) = (&app.governance, &gov.key) {
        if let Err(retry) = g.check_rate(key, crate::store::now()) {
            // Native error envelope for the body, plus the standard `Retry-After` header so a
            // well-behaved SDK backs off the right amount. The client-facing message carries only
            // vendor-plausible rate-limit copy — never the internal key id or governance
            // vocabulary. The key id + retry window are recorded server-side via tracing.
            tracing::info!(key_id = %key.id, retry_after_secs = retry, "governance: key rate limited");
            let mut resp = ingress_error(
                proto,
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limit_error",
                "Rate limit exceeded. Please retry after the indicated time.",
            );
            if let Ok(hv) = axum::http::HeaderValue::from_str(&retry.to_string()) {
                resp.headers_mut()
                    .insert(axum::http::header::RETRY_AFTER, hv);
            }
            return Some(resp);
        }
    }
    None
}

/// The ingress boundary — emit per-request observability metrics (one client request =
/// one call here, unlike the re-entrant forward_with_pool) AND charge the request to the virtual
/// key's budget. Outcome is derived from the final status; duration is wall-clock.
fn finish(
    app: &Arc<App>,
    gov: &crate::governance::GovCtx,
    ingress_protocol: &str,
    pool: &str,
    started: Instant,
    resp: Response,
) -> Response {
    let outcome = match resp.status().as_u16() {
        200..=299 => "ok",
        503 => "exhausted",
        400..=499 => "client_error",
        _ => "error",
    };
    metrics::counter!(
        crate::metrics::REQUESTS_TOTAL,
        "ingress_protocol" => ingress_protocol.to_string(),
        "pool" => pool.to_string(),
        "outcome" => outcome
    )
    .increment(1);
    let elapsed = started.elapsed();
    metrics::histogram!(
        crate::metrics::REQUEST_DURATION_SECONDS,
        "ingress_protocol" => ingress_protocol.to_string(),
        "pool" => pool.to_string()
    )
    .record(elapsed.as_secs_f64());

    // best-effort request-log webhook (no-op unless configured).
    crate::observability::fire_request_log(crate::observability::build_request_log(
        crate::store::now(),
        ingress_protocol,
        pool,
        outcome,
        elapsed.as_millis() as u64,
    ));

    // Charge the flat per-request fee only for requests that produced a usable upstream result
    // (2xx). Router-side 503 exhaustion, upstream 5xx, and 4xx upstream errors produced nothing the
    // caller can use, so billing the flat fee for them would over-charge keys for failures outside
    // their control. (Token fees are likewise only charged on successful streams via UsageSink, so
    // this keeps the flat-fee and token-fee policies consistent.)
    let is_success = matches!(resp.status().as_u16(), 200..=299);
    if is_success {
        if let (Some(g), Some(key)) = (&app.governance, &gov.key) {
            g.record_request(key, crate::store::now(), 0);
        }
    }
    resp
}

/// Render a router-side error as the ingress protocol's NATIVE error envelope (design §8.1 /
/// Unit I — total indistinguishability). A client on a vendor's official SDK gets the typed
/// exception it expects (JSON envelope) instead of a plain-text body it cannot decode. `proto`
/// names the ingress protocol of the route that failed; `status` is the HTTP status; `kind` is a
/// protocol-appropriate error category; `message` is the human-readable detail.
///
/// Thin delegation to the CANONICAL `crate::forward::ingress_error` (Round-7 CORE made it the
/// single source of truth for native error shaping + per-protocol headers — Bedrock
/// `x-amzn-RequestId`/`x-amzn-errortype` via `proto::attach_bedrock_error_headers`, the generic
/// fallback envelope, etc.). Keeping route.rs on this one function rather than a private copy means
/// route/forward error shaping cannot drift. The route call sites (and the in-module tests) keep
/// the short `proto`/`message` parameter names; the canonical fn names them `ingress`/`msg`.
fn ingress_error(proto: &str, status: StatusCode, kind: &str, message: &str) -> Response {
    crate::forward::ingress_error(proto, status, kind, message)
}

/// Shared ingress core for the BODY-MODEL protocols (`openai`, `cohere`, `responses`): the model
/// lives in the request body's `"model"` field and stream intent in `"stream"`. Parses the body,
/// extracts the model, runs the governance guards (pool-allowed / budget / rate), resolves the
/// target against `app.pools` then `app.by_model`, and forwards through `forward_with_pool` with
/// the given ingress `proto` so cross-protocol translation (request + response) happens for free.
/// Factored out of `openai_ingress` so every body-model protocol shares one implementation — the
/// only difference between them is the `proto` literal and the native error envelope.
async fn ingress_body_model(
    app: &Arc<App>,
    gov: &crate::governance::GovCtx,
    caller: &crate::auth::CallerToken,
    headers: &HeaderMap,
    body: Bytes,
    proto: &'static str,
) -> Response {
    let caller_token = caller.0.as_deref();
    let started = Instant::now();
    let v: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return ingress_error(
                proto,
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                &format!("We could not parse the JSON body of your request: {e}"),
            )
        }
    };

    let model = match v.get("model").and_then(|m| m.as_str()) {
        Some(m) if !m.is_empty() => m.to_string(),
        _ => {
            return ingress_error(
                proto,
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                "Missing required parameter: 'model'.",
            )
        }
    };

    forward_resolved(
        app,
        gov,
        proto,
        &model,
        headers,
        body,
        caller_token,
        started,
    )
    .await
}

/// Shared ingress core for the PATH-MODEL protocols (`gemini`, `bedrock`): the model lives in the
/// URL path and stream intent in the path/route suffix, NOT the body. A native client body carries
/// neither, so this parses the body to a `Value`, INJECTS `"model"` (from the path) and `"stream"`
/// (from the route) into it, re-serializes to `Bytes`, then runs the same resolution + forward as
/// `ingress_body_model`. Both injected fields are consumed downstream: `forward_with_pool` reads
/// `"stream"` for the egress endpoint/translation and the per-protocol reader reads `"model"` for
/// the IR. This is the only piece of "new code" the path-model protocols need.
/// `gemini_json_array`: when `true` the route layer injects the gemini JSON-array streaming shim key
/// (`__busbar_gemini_json_array`) so the streaming response builder emits the JSON-array framing a
/// native non-`alt=sse` `:streamGenerateContent` request expects (instead of SSE). Always `false`
/// for bedrock and for non-streaming / `?alt=sse` gemini requests.
#[allow(clippy::too_many_arguments)]
async fn ingress_path_model(
    app: &Arc<App>,
    gov: &crate::governance::GovCtx,
    caller: &crate::auth::CallerToken,
    headers: &HeaderMap,
    body: Bytes,
    model: &str,
    stream: bool,
    gemini_json_array: bool,
    proto: &'static str,
) -> Response {
    let caller_token = caller.0.as_deref();
    let started = Instant::now();
    let mut v: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return ingress_error(
                proto,
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                &format!("We could not parse the JSON body of your request: {e}"),
            )
        }
    };

    // Inject model+stream so the shared resolution/forward plumbing (which reads both from the
    // body) works for protocols whose native wire carries them in the URL instead. A native client
    // body is always a JSON object; if it is not, return a protocol-shaped 400 rather than panic.
    match v.as_object_mut() {
        Some(obj) => {
            obj.insert("model".to_string(), Value::String(model.to_string()));
            obj.insert("stream".to_string(), Value::Bool(stream));
            // Gemini-only: signal a non-`alt=sse` streaming request so the response is framed as a
            // JSON array rather than SSE. The shim is stripped before the upstream call
            // (`forward::strip_router_shim_keys`); cross-protocol egress drops it via the IR.
            if gemini_json_array {
                obj.insert(
                    crate::proto::GEMINI_JSON_ARRAY_SHIM_KEY.to_string(),
                    Value::Bool(true),
                );
            }
        }
        None => {
            return ingress_error(
                proto,
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                "Request body must be a JSON object.",
            )
        }
    }

    let injected: Bytes = match serde_json::to_vec(&v) {
        Ok(b) => b.into(),
        Err(e) => {
            return ingress_error(
                proto,
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                &format!("The request body could not be processed: {e}"),
            )
        }
    };

    forward_resolved(
        app,
        gov,
        proto,
        model,
        headers,
        injected,
        caller_token,
        started,
    )
    .await
}

/// The common tail shared by both ingress cores: run the governance guards, resolve `model`
/// against `app.pools` then `app.by_model`, forward through `forward_with_pool` with `proto`, and
/// `finish`. A miss on both maps is a protocol-shaped 404.
#[allow(clippy::too_many_arguments)]
async fn forward_resolved(
    app: &Arc<App>,
    gov: &crate::governance::GovCtx,
    proto: &'static str,
    model: &str,
    headers: &HeaderMap,
    body: Bytes,
    caller_token: Option<&str>,
    started: Instant,
) -> Response {
    // Governance guards (pool-allowed / budget / rate). A rejection is finished through `finish`
    // so it is still counted in metrics and the request-log webhook.
    if let Some(resp) = governance_guard(app, gov, proto, model, started).await {
        return resp;
    }

    if let Some(cands) = app.pools.get(model) {
        let affinity_key = headers
            .get(affinity_header_for(app, model))
            .and_then(|v| v.to_str().ok());
        let resp = forward_with_pool(
            app.clone(),
            cands.clone(),
            body,
            caller_token,
            model,
            affinity_key,
            proto,
            usage_sink(app, gov),
        )
        .await;
        return finish(app, gov, proto, model, started, resp);
    }

    if let Some(&i) = app.by_model.get(model) {
        // Route through forward_with_pool with this ingress protocol so a request to a
        // different-protocol backend is translated both ways. (The `forward` wrapper assumes
        // Anthropic ingress, which is correct only for the /v1/messages routes — not here.)
        let resp = forward_with_pool(
            app.clone(),
            vec![WeightedLane { idx: i, weight: 1 }],
            body,
            caller_token,
            model,
            None,
            proto,
            usage_sink(app, gov),
        )
        .await;
        return finish(app, gov, proto, model, started, resp);
    }

    // `not_found_error` is the canonical token every writer maps (OpenAI, Responses, Anthropic →
    // their native not-found type; Gemini → NOT_FOUND). The older generic `not_found` leaked
    // verbatim through the OpenAI writer as a non-canonical `error.type`.
    ingress_error(
        proto,
        StatusCode::NOT_FOUND,
        "not_found_error",
        &format!("The model '{model}' does not exist or you do not have access to it."),
    )
}

// POST /v1/chat/completions — OpenAI-style ingress: model comes from the body. Routes through
// `forward_with_pool` with ingress protocol "openai", so a request whose model resolves to a
// non-OpenAI lane is translated both ways (request and response) via the IR — cross-protocol works.
#[tracing::instrument(name = "openai_ingress", skip_all)]
pub(crate) async fn openai_ingress(
    State(app): State<Arc<App>>,
    axum::extract::Extension(gov): axum::extract::Extension<crate::governance::GovCtx>,
    axum::extract::Extension(caller): axum::extract::Extension<crate::auth::CallerToken>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    ingress_body_model(&app, &gov, &caller, &headers, body, "openai").await
}

// POST /v2/chat — Cohere v2 ingress: model + stream live in the body, exactly like OpenAI.
#[tracing::instrument(name = "cohere_ingress", skip_all)]
pub(crate) async fn cohere_ingress(
    State(app): State<Arc<App>>,
    axum::extract::Extension(gov): axum::extract::Extension<crate::governance::GovCtx>,
    axum::extract::Extension(caller): axum::extract::Extension<crate::auth::CallerToken>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    ingress_body_model(&app, &gov, &caller, &headers, body, "cohere").await
}

// POST /v1/responses — OpenAI Responses-API ingress: model + stream live in the body.
#[tracing::instrument(name = "responses_ingress", skip_all)]
pub(crate) async fn responses_ingress(
    State(app): State<Arc<App>>,
    axum::extract::Extension(gov): axum::extract::Extension<crate::governance::GovCtx>,
    axum::extract::Extension(caller): axum::extract::Extension<crate::auth::CallerToken>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    ingress_body_model(&app, &gov, &caller, &headers, body, "responses").await
}

// POST /v1beta/models/*rest — Gemini ingress. The native path packs MODEL and ACTION into the last
// segment with a colon: `/v1beta/models/{model}:{action}`. axum cannot split on a `:` inside a
// segment, so we capture the whole tail with a wildcard (`*rest`) and split on the LAST `:`
// ourselves — model ids never contain `:` but the `:generateContent` separator always does, so the
// last colon is unambiguous. `streamGenerateContent` ⇒ stream, `generateContent` ⇒ non-stream; any
// other action is an unknown-or-unsupported native operation → a Gemini-shaped 404. Only the two
// generate actions are proxied by design: busbar is a generation gateway, so non-generate model
// methods on this surface (e.g. `countTokens`, `embedContent`, `batchGenerateContent`) are an
// intentional, documented limitation rather than a relayed call. They return the native NOT_FOUND
// envelope so the failure mode is at least Gemini-shaped.
#[tracing::instrument(name = "gemini_ingress", skip_all)]
pub(crate) async fn gemini_ingress(
    State(app): State<Arc<App>>,
    Path(rest): Path<String>,
    RawQuery(query): RawQuery,
    axum::extract::Extension(gov): axum::extract::Extension<crate::governance::GovCtx>,
    axum::extract::Extension(caller): axum::extract::Extension<crate::auth::CallerToken>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // `rest` is everything after `/v1beta/models/`, e.g. `foo:generateContent`. Split on the LAST
    // colon into (model, action). A missing colon means the client sent a malformed Gemini path.
    let (model, action) = match rest.rsplit_once(':') {
        Some((m, a)) if !m.is_empty() && !a.is_empty() => (m, a),
        _ => {
            return ingress_error(
                "gemini",
                StatusCode::NOT_FOUND,
                "NOT_FOUND",
                &format!(
                    "Invalid resource path: models/{rest} is not found for API version v1beta."
                ),
            )
        }
    };

    // Only the two generate actions are proxied (see the route doc above). Any other action —
    // including valid-but-unproxied Gemini methods such as `countTokens`/`embedContent` — is an
    // intentional limitation and returns the native NOT_FOUND envelope. No `_ =>` catch-all: the
    // two supported actions are listed explicitly, with the unsupported-action fallback handled
    // afterwards.
    let stream = match action {
        "streamGenerateContent" => true,
        "generateContent" => false,
        other => {
            return ingress_error(
                "gemini",
                StatusCode::NOT_FOUND,
                "NOT_FOUND",
                &format!(
                    "models/{model} is not found for API version v1beta, \
                     or is not supported for {other}."
                ),
            )
        }
    };

    // `?alt=sse` selects SSE framing for a STREAMING request; its ABSENCE means the native client
    // expects the JSON-array streaming format. `alt` is the documented Gemini query param; treat any
    // `alt=sse` token in the raw query as the SSE request (matching the Gemini SDKs, which append
    // exactly `?alt=sse`). The param is meaningless on a non-stream request, so only a streaming
    // request without `alt=sse` engages the JSON-array framing.
    let alt_sse = query.as_deref().map(query_has_alt_sse).unwrap_or(false);
    let gemini_json_array = stream && !alt_sse;

    ingress_path_model(
        &app,
        &gov,
        &caller,
        &headers,
        body,
        model,
        stream,
        gemini_json_array,
        "gemini",
    )
    .await
}

/// True when the raw query string carries an `alt=sse` pair (the Gemini SSE-streaming selector).
/// Scans `&`-separated `key=value` pairs so it is not fooled by another param whose value contains
/// the substring `alt=sse`.
fn query_has_alt_sse(query: &str) -> bool {
    query
        .split('&')
        .any(|pair| matches!(pair.split_once('='), Some(("alt", "sse"))))
}

// POST /model/:modelId/converse — Bedrock Converse ingress (non-streaming). The model lives in the
// path (URL-encoded — Bedrock model ids contain `.` and `:`), and the non-`-stream` endpoint means
// stream=false.
#[tracing::instrument(name = "bedrock_converse", skip_all)]
pub(crate) async fn bedrock_converse(
    State(app): State<Arc<App>>,
    Path(model_id): Path<String>,
    axum::extract::Extension(gov): axum::extract::Extension<crate::governance::GovCtx>,
    axum::extract::Extension(caller): axum::extract::Extension<crate::auth::CallerToken>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    bedrock_ingress(&app, &gov, &caller, &headers, body, &model_id, false).await
}

// POST /model/:modelId/converse-stream — Bedrock Converse ingress (streaming, stream=true). The
// upstream stream is re-encoded into binary `application/vnd.amazon.eventstream` frames (one
// CRC32-valid frame per event via `eventstream::encode_frame`, wired through
// `StreamTranslate::ingress_eventstream`) so a native AWS SDK Bedrock client decodes the response as
// ConverseStream.
#[tracing::instrument(name = "bedrock_converse_stream", skip_all)]
pub(crate) async fn bedrock_converse_stream(
    State(app): State<Arc<App>>,
    Path(model_id): Path<String>,
    axum::extract::Extension(gov): axum::extract::Extension<crate::governance::GovCtx>,
    axum::extract::Extension(caller): axum::extract::Extension<crate::auth::CallerToken>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    bedrock_ingress(&app, &gov, &caller, &headers, body, &model_id, true).await
}

/// Shared body for both Bedrock ingress routes: delegate to the path-model core with the
/// route-selected stream intent.
///
/// The `modelId` path segment arrives ALREADY percent-decoded: axum 0.7 runs
/// `PercentDecodedStr` on every `Path` param before the handler is called (axum-0.7.9
/// `src/routing/url_params.rs` → `util.rs`), so an AWS SDK's `%3A`-encoded colon is already a
/// literal `:` here. Re-decoding (the previous `percent_decode(model_id)` call) was wrong: it was a
/// harmless no-op for today's Bedrock id shapes (which contain `:`/`/`/`.` but no surviving `%`),
/// but a model id whose first (axum) decode legitimately yielded a literal `%XX` sequence would be
/// corrupted by a second pass. We therefore use axum's decoded value verbatim. (`percent_decode`
/// remains as a tested helper for any caller that holds a still-encoded segment.)
async fn bedrock_ingress(
    app: &Arc<App>,
    gov: &crate::governance::GovCtx,
    caller: &crate::auth::CallerToken,
    headers: &HeaderMap,
    body: Bytes,
    model_id: &str,
    stream: bool,
) -> Response {
    // Bedrock never uses the gemini JSON-array framing.
    ingress_path_model(
        app, gov, caller, headers, body, model_id, stream, false, "bedrock",
    )
    .await
}

/// Minimal percent-decoding for a single path segment (no external dependency). Decodes `%XX`
/// escapes as UTF-8; on any malformed escape it leaves the bytes as-is.
///
/// No longer on the request path: axum percent-decodes `Path` params before the handler runs, so
/// `bedrock_ingress` uses the already-decoded segment directly (decoding twice corrupts ids whose
/// first decode yields a literal `%XX`). Retained as a `#[cfg(test)]` helper documenting the
/// decode semantics and guarding against accidental reintroduction of a double-decode.
#[cfg(test)]
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

// POST /<name>/v1/messages   — name resolves to a pool (round-robin) or a single model
#[tracing::instrument(name = "named", skip_all, fields(pool = %name))]
pub(crate) async fn named(
    State(app): State<Arc<App>>,
    Path(name): Path<String>,
    axum::extract::Extension(gov): axum::extract::Extension<crate::governance::GovCtx>,
    axum::extract::Extension(caller): axum::extract::Extension<crate::auth::CallerToken>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // Caller's bearer token (for passthrough-mode forwarding); None falls back to the lane's key.
    let caller_token = caller.0.as_deref();
    // `started` is taken BEFORE the governance guards so a governance-rejected request still
    // records a (small) wall-clock duration and is counted via `finish`.
    let started = Instant::now();

    // Governance guards (pool-allowed / budget / rate); a rejection is finished through `finish`.
    if let Some(resp) = governance_guard(&app, &gov, "anthropic", &name, started).await {
        return resp;
    }

    if let Some(cands) = app.pools.get(&name) {
        let affinity_key = headers
            .get(affinity_header_for(&app, &name))
            .and_then(|v| v.to_str().ok());
        let resp = forward_with_pool(
            app.clone(),
            cands.clone(),
            body,
            caller_token,
            &name,
            affinity_key,
            "anthropic",
            usage_sink(&app, &gov),
        )
        .await;
        return finish(&app, &gov, "anthropic", &name, started, resp);
    }
    if let Some(&i) = app.by_model.get(&name) {
        // Use forward for model-based routing (no pool name context needed)
        let resp = crate::forward::forward(
            app.clone(),
            vec![WeightedLane { idx: i, weight: 1 }],
            body,
            caller_token,
            usage_sink(&app, &gov),
        )
        .await;
        return finish(&app, &gov, "anthropic", &name, started, resp);
    }

    // Model/pool miss: wrap the 404 in `finish` so it is still counted in REQUESTS_TOTAL /
    // REQUEST_DURATION_SECONDS and fires the request-log webhook — the same observability invariant
    // already enforced for governance rejections (a raw early-return made the miss invisible).
    finish(
        &app,
        &gov,
        "anthropic",
        &name,
        started,
        ingress_error(
            "anthropic",
            StatusCode::NOT_FOUND,
            "not_found_error",
            &format!("The model '{name}' does not exist or you do not have access to it."),
        ),
    )
}

// POST /<provider>/<model>/v1/messages — ad-hoc direct
#[tracing::instrument(name = "adhoc", skip_all, fields(provider = %provider, model = %model))]
pub(crate) async fn adhoc(
    State(app): State<Arc<App>>,
    Path((provider, model)): Path<(String, String)>,
    axum::extract::Extension(gov): axum::extract::Extension<crate::governance::GovCtx>,
    axum::extract::Extension(caller): axum::extract::Extension<crate::auth::CallerToken>,
    body: Bytes,
) -> Response {
    let caller_token = caller.0.as_deref();
    let started = Instant::now();

    // Governance guards (pool-allowed / budget / rate); a rejection is finished through `finish`.
    if let Some(resp) = governance_guard(&app, &gov, "anthropic", &model, started).await {
        return resp;
    }

    match app.by_model.get(&model) {
        Some(&i) if app.lanes[i].provider == provider => {
            // Single lane with weight=1 (default for ad-hoc routing) - use forward, not forward_with_pool
            let resp = crate::forward::forward(
                app.clone(),
                vec![WeightedLane { idx: i, weight: 1 }],
                body,
                caller_token,
                usage_sink(&app, &gov),
            )
            .await;
            finish(&app, &gov, "anthropic", &model, started, resp)
        }
        // Provider mismatch / model miss: wrap the 4xx in `finish` so the client error is counted
        // in REQUESTS_TOTAL / REQUEST_DURATION_SECONDS and fires the request-log webhook, matching
        // the success arm and the governance-rejection path (a raw early-return made it invisible).
        // The client-facing copy is vendor-plausible (an Anthropic 400 never names a busbar
        // "provider"); the actual provider mismatch is recorded server-side for operator diagnosis.
        Some(&i) => {
            tracing::info!(
                model = %model,
                requested_provider = %provider,
                actual_provider = %app.lanes[i].provider,
                "adhoc: model is on a different provider than the path requested"
            );
            finish(
                &app,
                &gov,
                "anthropic",
                &model,
                started,
                ingress_error(
                    "anthropic",
                    StatusCode::BAD_REQUEST,
                    "invalid_request_error",
                    &format!("The model '{model}' does not exist or you do not have access to it."),
                ),
            )
        }
        None => finish(
            &app,
            &gov,
            "anthropic",
            &model,
            started,
            ingress_error(
                "anthropic",
                StatusCode::NOT_FOUND,
                "not_found_error",
                &format!("The model '{model}' does not exist or you do not have access to it."),
            ),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // `IntoResponse` is no longer used by the (now-delegating) production code, but the in-module
    // tests build responses via `(StatusCode, body).into_response()`, which needs the trait in scope.
    use axum::response::IntoResponse;

    /// `query_has_alt_sse` recognizes the gemini SSE selector only as a genuine `alt=sse` pair, not
    /// a substring of another param's value, and ignores order / other params.
    #[test]
    fn test_query_has_alt_sse() {
        assert!(query_has_alt_sse("alt=sse"));
        assert!(query_has_alt_sse("key=abc&alt=sse"));
        assert!(query_has_alt_sse("alt=sse&key=abc"));
        assert!(!query_has_alt_sse("alt=json"));
        assert!(!query_has_alt_sse(""));
        // Not fooled by a different param whose VALUE merely contains "alt=sse".
        assert!(!query_has_alt_sse("foo=alt=sse"));
        // `alt` with no value is not the SSE selector.
        assert!(!query_has_alt_sse("alt"));
    }

    /// Minimal governance-off App for exercising `finish` in isolation.
    fn minimal_app() -> Arc<App> {
        Arc::new(App {
            lanes: vec![],
            store: Arc::new(crate::store::InMemoryStore::new(vec![])),
            by_model: std::collections::HashMap::new(),
            pools: std::collections::HashMap::new(),
            client: reqwest::Client::new(),
            auth: Arc::new(crate::auth::AuthMiddleware::new(
                &crate::config::AuthCfg::default_none(),
            )),
            auth_mode: crate::auth::AuthMode::None,
            failover_cfg: None,
            pool_runtime: std::collections::HashMap::new(),
            fallback_pools: std::collections::HashMap::new(),
            on_exhausted_cfgs: std::collections::HashMap::new(),
            governance: None,
        })
    }

    #[test]
    fn test_finish_emits_request_metrics() {
        crate::metrics::init();
        let resp = (StatusCode::OK, "ok").into_response();
        let out = finish(
            &minimal_app(),
            &crate::governance::GovCtx::default(),
            "openai",
            "mypool",
            Instant::now(),
            resp,
        );
        // finish must pass the response through unchanged.
        assert_eq!(out.status(), StatusCode::OK);

        let scrape = crate::metrics::render();
        assert!(
            scrape.contains(crate::metrics::REQUESTS_TOTAL),
            "finish should emit requests_total; got:\n{scrape}"
        );
        assert!(
            scrape.contains("outcome=\"ok\""),
            "a 2xx response maps to outcome=ok; got:\n{scrape}"
        );
        assert!(
            scrape.contains(crate::metrics::REQUEST_DURATION_SECONDS),
            "finish should emit the request-duration histogram; got:\n{scrape}"
        );
    }

    #[test]
    fn test_affinity_header_defaults_to_session_id() {
        // No pool_runtime entry → default header.
        let app = minimal_app();
        assert_eq!(affinity_header_for(&app, "anypool"), "x-session-id");
    }

    #[test]
    fn test_affinity_header_honors_configured_name() {
        let mut app = minimal_app();
        let mut pr = std::collections::HashMap::new();
        pr.insert(
            "tenant-pool".to_string(),
            crate::state::PoolRuntime {
                failover: None,
                affinity: Some(crate::config::AffinityCfg {
                    mode: "session".to_string(),
                    header_name: Some("x-user-id".to_string()),
                }),
                breaker: None,
            },
        );
        // App is behind Arc; rebuild with the populated map.
        let inner = Arc::get_mut(&mut app).expect("sole owner");
        inner.pool_runtime = pr;
        assert_eq!(affinity_header_for(&app, "tenant-pool"), "x-user-id");
        // A pool without an entry still falls back to the default.
        assert_eq!(affinity_header_for(&app, "other"), "x-session-id");
    }

    #[test]
    fn test_affinity_header_session_mode_without_name_uses_default() {
        let mut app = minimal_app();
        let mut pr = std::collections::HashMap::new();
        pr.insert(
            "p".to_string(),
            crate::state::PoolRuntime {
                failover: None,
                affinity: Some(crate::config::AffinityCfg {
                    mode: "session".to_string(),
                    header_name: None,
                }),
                breaker: None,
            },
        );
        let inner = Arc::get_mut(&mut app).expect("sole owner");
        inner.pool_runtime = pr;
        assert_eq!(affinity_header_for(&app, "p"), "x-session-id");
    }

    /// Build a governance-enabled App with a single budgeted key, plus return the key so the test
    /// can pass a matching GovCtx to `finish`. Runs without a Tokio runtime so the best-effort
    /// `record_request` charge executes inline (observable synchronously).
    fn governed_app_with_key() -> (Arc<App>, crate::governance::VirtualKey) {
        use crate::governance::{GovState, NewKeySpec, SqliteStore};
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        // 30 cents flat per request, no per-token fee.
        let gov = Arc::new(GovState::new(store, 30, 0, None).unwrap());
        let (key, _secret) = gov
            .create_key(
                NewKeySpec {
                    name: "k".to_string(),
                    allowed_pools: vec![],
                    max_budget_cents: Some(100_000),
                    budget_period: "total".to_string(),
                    rpm_limit: None,
                    tpm_limit: None,
                },
                1_700_000_000,
            )
            .unwrap();
        let mut app = minimal_app();
        Arc::get_mut(&mut app).expect("sole owner").governance = Some(gov);
        (app, key)
    }

    fn key_spend(app: &Arc<App>, key_id: &str) -> i64 {
        app.governance
            .as_ref()
            .unwrap()
            .usage_for(key_id, 1_700_000_000)
            .unwrap()
            .map(|u| u.spend_cents)
            .unwrap_or(0)
    }

    #[test]
    fn test_finish_charges_flat_fee_only_on_2xx() {
        crate::metrics::init();
        let (app, key) = governed_app_with_key();
        let gov = crate::governance::GovCtx {
            key: Some(key.clone()),
        };

        // A 200 response charges the flat fee.
        let resp = (StatusCode::OK, "ok").into_response();
        let _ = finish(&app, &gov, "openai", "p", Instant::now(), resp);
        assert_eq!(
            key_spend(&app, &key.id),
            30,
            "2xx charges the flat per-request fee"
        );

        // A 503 (router-side exhaustion) must NOT charge again.
        let resp = (StatusCode::SERVICE_UNAVAILABLE, "x").into_response();
        let _ = finish(&app, &gov, "openai", "p", Instant::now(), resp);
        assert_eq!(
            key_spend(&app, &key.id),
            30,
            "503 does not charge the flat fee"
        );

        // An upstream 500 must NOT charge.
        let resp = (StatusCode::INTERNAL_SERVER_ERROR, "x").into_response();
        let _ = finish(&app, &gov, "openai", "p", Instant::now(), resp);
        assert_eq!(
            key_spend(&app, &key.id),
            30,
            "5xx does not charge the flat fee"
        );

        // A 4xx upstream error must NOT charge.
        let resp = (StatusCode::BAD_REQUEST, "x").into_response();
        let _ = finish(&app, &gov, "openai", "p", Instant::now(), resp);
        assert_eq!(
            key_spend(&app, &key.id),
            30,
            "4xx does not charge the flat fee"
        );
    }

    #[test]
    fn test_finish_outcome_mapping_503_is_exhausted() {
        crate::metrics::init();
        let resp = (StatusCode::SERVICE_UNAVAILABLE, "x").into_response();
        let _ = finish(
            &minimal_app(),
            &crate::governance::GovCtx::default(),
            "anthropic",
            "p2",
            Instant::now(),
            resp,
        );
        assert!(
            crate::metrics::render().contains("outcome=\"exhausted\""),
            "503 maps to outcome=exhausted"
        );
    }

    // ---- universal-ingress routing tests (cohere/responses/gemini/bedrock) ----
    //
    // These exercise the new first-class ingress routes through the REAL router
    // (`build_router`) so the full route table + auth + body-limit layers are in play, exactly as
    // a native vendor SDK would hit busbar. Each test points the new ingress at a mock backend on
    // a DIFFERENT protocol so the cross-protocol IR translation (request + response) runs.

    use crate::test_support::{LaneSpec, MockResponse, MockServer, MockServerState, TestApp};
    use serde_json::json;
    use std::sync::Arc as StdArc;

    /// Spin up the real router over a loopback listener; returns (addr, abort-handle).
    async fn serve(app: StdArc<App>) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let router = crate::build_router(app);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        (addr, handle)
    }

    /// A canonical OpenAI chat-completion response body the mock backend returns, so the ingress
    /// writer has a full IR to translate back into the client's native shape.
    fn openai_ok_body() -> serde_json::Value {
        json!({
            "id": "chatcmpl-x",
            "object": "chat.completion",
            "model": "glm-4.5",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": "hi there"},
                "finish_reason": "stop"
            }],
            "usage": {"prompt_tokens": 5, "completion_tokens": 3}
        })
    }

    /// A canonical Anthropic message response body for an Anthropic backend.
    fn anthropic_ok_body() -> serde_json::Value {
        json!({
            "id": "msg_x",
            "type": "message",
            "role": "assistant",
            "model": "claude-x",
            "content": [{"type": "text", "text": "hi there"}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 5, "output_tokens": 3}
        })
    }

    /// Cohere client → OpenAI backend: a native Cohere `/v2/chat` request must round-trip through
    /// the IR to an OpenAI backend and back, returning a 2xx the Cohere SDK can parse.
    #[tokio::test]
    async fn test_cohere_ingress_to_openai_backend() {
        crate::metrics::init();
        let state = StdArc::new(MockServerState::new());
        state.push(MockResponse::Ok {
            status: StatusCode::OK,
            body: openai_ok_body(),
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
            .pool("co", &[(0, 1)])
            .build();
        let (addr, handle) = serve(app).await;

        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/v2/chat"))
            .bearer_auth("t")
            .body(
                json!({
                    "model": "co",
                    "messages": [{"role": "user", "content": "hello"}]
                })
                .to_string(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200, "cohere→openai round-trip 2xx");

        // The backend must have received a translated OpenAI chat-completion request.
        let upstream: serde_json::Value =
            serde_json::from_slice(&state.get_last_request_body().unwrap()).unwrap();
        assert!(
            upstream.get("messages").is_some(),
            "openai backend received an OpenAI-shaped body; got {upstream}"
        );
        handle.abort();
        server.shutdown().await;
    }

    /// Responses client → Anthropic backend: native `/v1/responses` request round-trips to an
    /// Anthropic backend and back.
    #[tokio::test]
    async fn test_responses_ingress_to_anthropic_backend() {
        crate::metrics::init();
        let state = StdArc::new(MockServerState::new());
        state.push(MockResponse::Ok {
            status: StatusCode::OK,
            body: anthropic_ok_body(),
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
            .pool("re", &[(0, 1)])
            .build();
        let (addr, handle) = serve(app).await;

        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/v1/responses"))
            .bearer_auth("t")
            .body(
                json!({
                    "model": "re",
                    "input": "hello",
                    "max_tokens": 16
                })
                .to_string(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status().as_u16(),
            200,
            "responses→anthropic round-trip 2xx"
        );
        let upstream: serde_json::Value =
            serde_json::from_slice(&state.get_last_request_body().unwrap()).unwrap();
        assert!(
            upstream.get("messages").is_some(),
            "anthropic backend received a messages array; got {upstream}"
        );
        handle.abort();
        server.shutdown().await;
    }

    /// Gemini path parsing: `/v1beta/models/foo:generateContent` must resolve model "foo" with
    /// stream=false, and `:streamGenerateContent` with stream=true. We assert the INJECTED body by
    /// routing gemini→openai backend and reading the request the backend received: the model must
    /// have resolved to the path model (the lane is named "foo") and a body that translated cleanly
    /// proves model+stream injection happened (resolution by path model can't happen otherwise).
    #[tokio::test]
    async fn test_gemini_path_resolves_model_and_stream() {
        crate::metrics::init();
        // Two backend responses: one for the non-stream call, one we won't reach (stream call uses
        // a fresh state below). Keep them separate for clarity.
        let state = StdArc::new(MockServerState::new());
        state.push(MockResponse::Ok {
            status: StatusCode::OK,
            body: openai_ok_body(),
        });
        let server = MockServer::new(state.clone()).await;

        // The lane MODEL is "foo" so that resolution via the path model proves the path parse.
        let app = TestApp::new()
            .lane(
                LaneSpec::new("foo", crate::proto::Protocol::openai(), &server.base_url())
                    .provider("zai"),
            )
            .pool("foo", &[(0, 1)])
            .build();
        let (addr, handle) = serve(app).await;

        // Non-stream action.
        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/v1beta/models/foo:generateContent"))
            .bearer_auth("t")
            .body(
                json!({
                    "contents": [{"role": "user", "parts": [{"text": "hello"}]}]
                })
                .to_string(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status().as_u16(),
            200,
            "gemini :generateContent resolves model 'foo' and 2xx round-trips to openai"
        );
        // The backend got a non-stream OpenAI request (no top-level stream:true in the translated
        // body — gemini's writer omits it on egress, but the point is the request resolved).
        let upstream: serde_json::Value =
            serde_json::from_slice(&state.get_last_request_body().unwrap()).unwrap();
        assert!(
            upstream.get("messages").is_some(),
            "non-stream gemini request reached the openai backend; got {upstream}"
        );
        handle.abort();
        server.shutdown().await;
    }

    /// Direct unit test of the injected body for the path-model core: the parsed gemini body must
    /// gain `model` (from the path) and `stream` (from the action). This is the §3 "body shim".
    #[test]
    fn test_path_model_injects_model_and_stream_into_body() {
        // Mirror the injection ingress_path_model performs (kept here as a focused assertion on the
        // exact body mutation, independent of the HTTP/forward plumbing).
        let mut v: Value = json!({"contents": [{"role": "user", "parts": [{"text": "x"}]}]});
        let obj = v.as_object_mut().expect("native body is a JSON object");
        obj.insert("model".to_string(), Value::String("foo".to_string()));
        obj.insert("stream".to_string(), Value::Bool(true));
        assert_eq!(v["model"], "foo");
        assert_eq!(v["stream"], true);
        // And stream=false for the generateContent action.
        let mut v2: Value = json!({"contents": []});
        let obj2 = v2.as_object_mut().unwrap();
        obj2.insert("model".to_string(), Value::String("bar".to_string()));
        obj2.insert("stream".to_string(), Value::Bool(false));
        assert_eq!(v2["model"], "bar");
        assert_eq!(v2["stream"], false);
    }

    /// Gemini unknown action ⇒ native 404 (not a 200, not a panic).
    #[tokio::test]
    async fn test_gemini_unknown_action_is_404() {
        crate::metrics::init();
        let app = TestApp::new().build();
        let (addr, handle) = serve(app).await;
        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/v1beta/models/foo:countTokens"))
            .bearer_auth("t")
            .body(json!({"contents": []}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status().as_u16(),
            404,
            "unknown gemini action ⇒ native 404"
        );
        let ct = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .to_string();
        assert!(
            ct.starts_with("application/json"),
            "gemini error envelope is JSON; got {ct}"
        );
        handle.abort();
    }

    /// Bedrock `/model/foo/converse` (stream=false) resolves model "foo", routes cross-protocol to
    /// an OpenAI backend, and returns native Converse JSON. The streaming binary-eventstream
    /// assertion lives in `test_bedrock_converse_stream_returns_binary_eventstream`.
    #[tokio::test]
    async fn test_bedrock_converse_routes_and_returns_json() {
        crate::metrics::init();
        let state = StdArc::new(MockServerState::new());
        state.push(MockResponse::Ok {
            status: StatusCode::OK,
            body: openai_ok_body(),
        });
        let server = MockServer::new(state.clone()).await;

        let app = TestApp::new()
            .lane(
                LaneSpec::new("foo", crate::proto::Protocol::openai(), &server.base_url())
                    .provider("zai"),
            )
            .pool("foo", &[(0, 1)])
            .build();
        let (addr, handle) = serve(app).await;

        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/model/foo/converse"))
            .bearer_auth("t")
            .body(
                json!({
                    "messages": [{"role": "user", "content": [{"text": "hello"}]}]
                })
                .to_string(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status().as_u16(),
            200,
            "bedrock /converse resolves model 'foo' and round-trips to openai"
        );
        let ct = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .to_string();
        assert!(
            ct.starts_with("application/json"),
            "non-stream bedrock returns JSON; got {ct}"
        );
        // The body must be the Bedrock Converse native shape produced by the bedrock writer.
        let body: serde_json::Value = resp.json().await.unwrap();
        assert!(
            body.get("output").is_some() || body.get("usage").is_some(),
            "bedrock Converse JSON shape returned; got {body}"
        );
        handle.abort();
        server.shutdown().await;
    }

    /// OpenAI-style streamed chat-completion chunks a mock backend emits (each wrapped as a `data:`
    /// SSE line by `MockResponse::Sse`). The OpenAI reader decodes bare `data:`-framed chunks without
    /// needing an `event:` line, so a cross-protocol ingress exercises the full reframe.
    fn openai_stream_events() -> Vec<String> {
        vec![
            r#"{"choices":[{"delta":{"role":"assistant"}}]}"#.to_string(),
            r#"{"choices":[{"delta":{"content":"hi"}}]}"#.to_string(),
            r#"{"choices":[{"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":3}}"#.to_string(),
        ]
    }

    /// HIGH/test-coverage: the `/model/:modelId/converse-stream` route (stream=true) must (a) resolve
    /// with stream intent, (b) return `Content-Type: application/vnd.amazon.eventstream`, and (c)
    /// produce a body that is a sequence of binary AWS event-stream frames `eventstream::drain_frames`
    /// can cleanly decode (buffer empties, frames carry the ConverseStream event names). Routes
    /// cross-protocol to a streaming OpenAI backend so the SSE→binary reframe path runs.
    #[tokio::test]
    async fn test_bedrock_converse_stream_returns_binary_eventstream() {
        crate::metrics::init();
        let state = StdArc::new(MockServerState::new());
        state.push(MockResponse::Sse {
            events: openai_stream_events(),
            abort_at_index: None,
        });
        let server = MockServer::new(state.clone()).await;

        // Bedrock ingress → OpenAI backend (cross-protocol) so the upstream SSE stream is re-encoded
        // into the client's native binary eventstream framing.
        let app = TestApp::new()
            .lane(
                LaneSpec::new("foo", crate::proto::Protocol::openai(), &server.base_url())
                    .provider("zai"),
            )
            .pool("foo", &[(0, 1)])
            .build();
        let (addr, handle) = serve(app).await;

        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/model/foo/converse-stream"))
            .bearer_auth("t")
            .body(
                json!({
                    "messages": [{"role": "user", "content": [{"text": "hello"}]}]
                })
                .to_string(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status().as_u16(),
            200,
            "bedrock /converse-stream resolves model 'foo' and 2xx round-trips"
        );
        let ct = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .to_string();
        assert!(
            ct.starts_with("application/vnd.amazon.eventstream"),
            "streaming bedrock ingress is binary eventstream; got {ct}"
        );

        // HIGH/test-coverage (forward.rs streaming-success header emission): a real AWS Bedrock
        // ConverseStream response ALWAYS carries `x-amzn-RequestId` (the only request-id surface the
        // AWS SDK exposes via `*Output::request_id()`); an absent header makes that return None,
        // which a native endpoint never does, and is a proxy tell on the most security-sensitive new
        // surface. Assert the streaming-success header is present and UUID-v4 shaped (8-4-4-4-12),
        // mirroring the non-stream `test_bedrock_ingress_success_carries_amzn_request_id`.
        let req_id = resp
            .headers()
            .get("x-amzn-requestid")
            .and_then(|h| h.to_str().ok())
            .expect("bedrock converse-stream success carries x-amzn-RequestId")
            .to_string();
        let segs: Vec<&str> = req_id.split('-').collect();
        assert_eq!(
            segs.iter().map(|s| s.len()).collect::<Vec<_>>(),
            vec![8, 4, 4, 4, 12],
            "x-amzn-RequestId is UUID-v4 shaped (8-4-4-4-12); got {req_id}"
        );
        assert!(
            req_id.chars().all(|c| c.is_ascii_hexdigit() || c == '-'),
            "x-amzn-RequestId is lowercase hex with dashes; got {req_id}"
        );

        // The body must decode as a clean sequence of binary AWS event-stream frames.
        let body = resp.bytes().await.unwrap();
        let mut buf = body.to_vec();
        let frames = crate::eventstream::drain_frames(&mut buf);
        assert!(
            !frames.is_empty(),
            "at least one binary eventstream frame must decode; body len {}",
            body.len()
        );
        assert!(
            buf.is_empty(),
            "the body must be a whole sequence of frames with no trailing partial bytes"
        );
        let event_types: Vec<&str> = frames.iter().map(|(t, _)| t.as_str()).collect();
        assert!(
            event_types.contains(&"messageStart"),
            "ConverseStream frames include messageStart; got {event_types:?}"
        );
        assert!(
            event_types.contains(&"contentBlockDelta"),
            "ConverseStream frames include contentBlockDelta; got {event_types:?}"
        );
        assert!(
            event_types.contains(&"messageStop"),
            "ConverseStream frames include messageStop; got {event_types:?}"
        );
        handle.abort();
        server.shutdown().await;
    }

    /// HIGH/test-coverage (forward.rs:496-526): a TRUE mid-stream transport failure on a
    /// bedrock-ingress cross-protocol stream must terminate the body with a CRC-valid BINARY
    /// `:message-type: exception` frame appended AFTER the real frames — never SSE `event:`/`data:`
    /// ASCII (which yields an undecodable prelude/CRC for the AWS SDK). `SseTransportError` drops the
    /// connection after the first frame, driving `FirstByteBody`'s `Poll::Ready(Some(Err))` arm — the
    /// wiring previously exercised only by the isolated `mid_stream_error_bytes` unit test.
    #[tokio::test]
    async fn test_bedrock_ingress_mid_stream_transport_error_appends_binary_exception() {
        crate::metrics::init();
        let state = StdArc::new(MockServerState::new());
        state.push(MockResponse::SseTransportError {
            ok_events: vec![r#"{"choices":[{"delta":{"role":"assistant"}}]}"#.to_string()],
        });
        let server = MockServer::new(state.clone()).await;
        let app = TestApp::new()
            .lane(
                LaneSpec::new("foo", crate::proto::Protocol::openai(), &server.base_url())
                    .provider("zai"),
            )
            .pool("foo", &[(0, 1)])
            .build();
        let (addr, handle) = serve(app).await;

        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/model/foo/converse-stream"))
            .bearer_auth("t")
            .body(
                json!({ "messages": [{"role": "user", "content": [{"text": "hi"}]}] }).to_string(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200);
        let body = resp.bytes().await.unwrap();
        // No SSE ASCII anywhere in the body — it must be pure binary frames.
        assert!(
            !body.windows(7).any(|w| w == b"event: ") && !body.windows(6).any(|w| w == b"data: "),
            "bedrock-ingress mid-stream error must NOT contain SSE ASCII; body: {body:?}"
        );
        // The body decodes as a sequence of binary frames, the LAST of which is an exception frame.
        let mut buf = body.to_vec();
        let frames = crate::eventstream::drain_frames(&mut buf);
        assert!(
            buf.is_empty(),
            "body must be a whole sequence of CRC-valid frames; {} bytes left",
            buf.len()
        );
        assert!(!frames.is_empty(), "at least the first real frame decodes");
        // The trailing exception frame carries no `:event-type` (drain_frames yields an empty event
        // type for it); re-scan the raw bytes to confirm an exception frame is present.
        let raw = body.to_vec();
        let raw_str = String::from_utf8_lossy(&raw);
        assert!(
            raw_str.contains(":exception-type"),
            "a binary exception frame must be appended after the real frames"
        );
        assert!(
            raw_str.contains("InternalServerException"),
            "the mid-stream transport failure maps to InternalServerException"
        );
        handle.abort();
        server.shutdown().await;
    }

    /// HIGH/test-coverage twin (forward.rs:186): the SSE-ingress (openai) mid-stream transport-failure
    /// path must append a BARE `data:` error frame (NO `event:` line — openai native streams never
    /// emit one mid-stream) whose `data:` is the native OpenAI error envelope.
    #[tokio::test]
    async fn test_openai_ingress_mid_stream_transport_error_appends_native_sse() {
        crate::metrics::init();
        let state = StdArc::new(MockServerState::new());
        state.push(MockResponse::SseTransportError {
            ok_events: vec![r#"{"choices":[{"delta":{"content":"hi"}}]}"#.to_string()],
        });
        let server = MockServer::new(state.clone()).await;
        let app = TestApp::new()
            .lane(
                LaneSpec::new(
                    "gpt-4o",
                    crate::proto::Protocol::openai(),
                    &server.base_url(),
                )
                .provider("openai"),
            )
            .pool("gpt-4o", &[(0, 1)])
            .build();
        let (addr, handle) = serve(app).await;

        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/v1/chat/completions"))
            .bearer_auth("t")
            .body(json!({ "model": "gpt-4o", "stream": true, "messages": [] }).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200);
        let body = resp.bytes().await.unwrap();
        let text = String::from_utf8_lossy(&body);
        // The trailing error frame is a bare `data:` envelope, with NO `event:` line.
        assert!(
            !text.contains("event:"),
            "openai mid-stream error must be a bare data: frame (no event: line); got:\n{text}"
        );
        // The last frame's data: payload is the native OpenAI error envelope.
        let frames: Vec<&str> = text
            .split("\n\n")
            .filter(|f| !f.trim().is_empty())
            .collect();
        let last_data = frames
            .last()
            .and_then(|f| f.lines().find_map(|l| l.strip_prefix("data: ")))
            .expect("a trailing data: error frame");
        let v: Value = serde_json::from_str(last_data).expect("native OpenAI JSON envelope");
        assert!(
            v.get("error").is_some(),
            "OpenAI native error envelope: {v}"
        );
        handle.abort();
        server.shutdown().await;
    }

    /// HIGH/conformance regression: a SAME-PROTOCOL bedrock-ingress → bedrock-backend passthrough must
    /// NOT leak the router shim keys (`model`/`stream`) that `ingress_path_model` injects into the
    /// body. `forward_with_pool` skips IR translation on same-protocol, so without the strip the
    /// injected keys would reach the backend (a native Bedrock Converse body carries neither, and the
    /// polluted body is what gets SigV4-signed). Asserts the body the backend RECEIVED has no
    /// top-level `model`/`stream`.
    #[tokio::test]
    async fn test_bedrock_same_protocol_passthrough_strips_shim_keys() {
        crate::metrics::init();
        let state = StdArc::new(MockServerState::new());
        // A minimal native-shaped Bedrock Converse response; same-protocol passthrough relays it
        // verbatim, so any 2xx body suffices for the round-trip.
        state.push(MockResponse::Ok {
            status: StatusCode::OK,
            body: json!({
                "output": {"message": {"role": "assistant", "content": [{"text": "hi"}]}},
                "usage": {"inputTokens": 5, "outputTokens": 3}
            }),
        });
        let server = MockServer::new(state.clone()).await;

        // The mock backend only routes `/v1/messages` + `/v1/chat/completions`; point the bedrock
        // lane's upstream path there so the same-protocol passthrough request reaches the handler
        // (the shim-strip under test is path-independent). Bedrock's native egress path is
        // `/model/{model}/converse`, which the mock does not serve.
        let app = TestApp::new()
            .lane(
                LaneSpec::new("foo", crate::proto::Protocol::bedrock(), &server.base_url())
                    .provider("aws")
                    .path("/v1/messages"),
            )
            .pool("foo", &[(0, 1)])
            .build();
        let (addr, handle) = serve(app).await;

        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/model/foo/converse"))
            .bearer_auth("t")
            .body(
                json!({
                    "messages": [{"role": "user", "content": [{"text": "hello"}]}]
                })
                .to_string(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status().as_u16(),
            200,
            "bedrock→bedrock 2xx round-trip"
        );

        let upstream: serde_json::Value =
            serde_json::from_slice(&state.get_last_request_body().unwrap()).unwrap();
        assert!(
            upstream.get("model").is_none(),
            "router shim key 'model' must not leak to the bedrock backend; got {upstream}"
        );
        assert!(
            upstream.get("stream").is_none(),
            "router shim key 'stream' must not leak to the bedrock backend; got {upstream}"
        );
        // The genuine native field must survive.
        assert!(
            upstream.get("messages").is_some(),
            "native bedrock body fields survive the passthrough; got {upstream}"
        );
        handle.abort();
        server.shutdown().await;
    }

    /// HIGH/conformance regression: same as above for gemini-ingress → gemini-backend. The Gemini
    /// writer's `rewrite_model` REINSERTS `model`, so the shim strip is the only thing keeping a
    /// top-level `model`/`stream` off the native generateContent body the backend receives.
    #[tokio::test]
    async fn test_gemini_same_protocol_passthrough_strips_shim_keys() {
        crate::metrics::init();
        let state = StdArc::new(MockServerState::new());
        state.push(MockResponse::Ok {
            status: StatusCode::OK,
            body: json!({
                "candidates": [{
                    "content": {"role": "model", "parts": [{"text": "hi"}]},
                    "finishReason": "STOP"
                }],
                "usageMetadata": {"promptTokenCount": 5, "candidatesTokenCount": 3}
            }),
        });
        let server = MockServer::new(state.clone()).await;

        // The mock backend only routes `/v1/messages` + `/v1/chat/completions`; point the gemini
        // lane's upstream path there so the same-protocol passthrough request reaches the handler
        // (the shim-strip under test is path-independent). Gemini's native egress path embeds the
        // model and action, which the mock does not serve.
        let app = TestApp::new()
            .lane(
                LaneSpec::new("foo", crate::proto::Protocol::gemini(), &server.base_url())
                    .provider("google")
                    .path("/v1/messages"),
            )
            .pool("foo", &[(0, 1)])
            .build();
        let (addr, handle) = serve(app).await;

        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/v1beta/models/foo:generateContent"))
            .bearer_auth("t")
            .body(
                json!({
                    "contents": [{"role": "user", "parts": [{"text": "hello"}]}]
                })
                .to_string(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200, "gemini→gemini 2xx round-trip");

        let upstream: serde_json::Value =
            serde_json::from_slice(&state.get_last_request_body().unwrap()).unwrap();
        assert!(
            upstream.get("stream").is_none(),
            "router shim key 'stream' must not leak to the gemini backend; got {upstream}"
        );
        assert!(
            upstream.get("model").is_none(),
            "router shim key 'model' must not leak to the gemini backend; got {upstream}"
        );
        assert!(
            upstream.get("contents").is_some(),
            "native gemini body fields survive the passthrough; got {upstream}"
        );
        handle.abort();
        server.shutdown().await;
    }

    /// MEDIUM/test-coverage: the `streamGenerateContent` action injects `stream:true` and routes to a
    /// streaming backend. WITH `?alt=sse` the gemini ingress contract is SSE (text/event-stream).
    /// Routes gemini→openai (cross-protocol) so the request reaches the backend and is reframed.
    #[tokio::test]
    async fn test_gemini_stream_generate_content_alt_sse_is_event_stream() {
        crate::metrics::init();
        let state = StdArc::new(MockServerState::new());
        state.push(MockResponse::Sse {
            events: openai_stream_events(),
            abort_at_index: None,
        });
        let server = MockServer::new(state.clone()).await;

        let app = TestApp::new()
            .lane(
                LaneSpec::new("foo", crate::proto::Protocol::openai(), &server.base_url())
                    .provider("zai"),
            )
            .pool("foo", &[(0, 1)])
            .build();
        let (addr, handle) = serve(app).await;

        let resp = reqwest::Client::new()
            .post(format!(
                "http://{addr}/v1beta/models/foo:streamGenerateContent?alt=sse"
            ))
            .bearer_auth("t")
            .body(
                json!({
                    "contents": [{"role": "user", "parts": [{"text": "hello"}]}]
                })
                .to_string(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status().as_u16(),
            200,
            "gemini :streamGenerateContent?alt=sse resolves and 2xx round-trips"
        );
        let ct = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .to_string();
        assert!(
            ct.starts_with("text/event-stream"),
            "gemini streaming ingress WITH ?alt=sse is SSE-framed; got {ct}"
        );
        handle.abort();
        server.shutdown().await;
    }

    /// HIGH/conformance: a native gemini `:streamGenerateContent` request WITHOUT `?alt=sse` must
    /// receive the JSON-ARRAY streaming format (`Content-Type: application/json`, a `[{...},{...}]`
    /// body), NOT SSE. Routes gemini→openai (cross-protocol) so the upstream SSE is reframed to
    /// gemini SSE by `StreamTranslate` and then to a JSON array by the framer; the body must parse
    /// as a JSON array whose elements are gemini `GenerateContentResponse` objects.
    #[tokio::test]
    async fn test_gemini_stream_generate_content_no_alt_sse_is_json_array() {
        crate::metrics::init();
        let state = StdArc::new(MockServerState::new());
        state.push(MockResponse::Sse {
            events: openai_stream_events(),
            abort_at_index: None,
        });
        let server = MockServer::new(state.clone()).await;

        let app = TestApp::new()
            .lane(
                LaneSpec::new("foo", crate::proto::Protocol::openai(), &server.base_url())
                    .provider("zai"),
            )
            .pool("foo", &[(0, 1)])
            .build();
        let (addr, handle) = serve(app).await;

        let resp = reqwest::Client::new()
            .post(format!(
                "http://{addr}/v1beta/models/foo:streamGenerateContent"
            ))
            .bearer_auth("t")
            .body(
                json!({
                    "contents": [{"role": "user", "parts": [{"text": "hello"}]}]
                })
                .to_string(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200, "no-alt=sse stream 2xx");
        let ct = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .to_string();
        assert!(
            ct.starts_with("application/json"),
            "gemini streaming ingress WITHOUT ?alt=sse is JSON-array framed; got {ct}"
        );
        let body = resp.text().await.unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&body)
            .unwrap_or_else(|e| panic!("JSON-array body must parse; got {body:?} ({e})"));
        let arr = parsed
            .as_array()
            .unwrap_or_else(|| panic!("body must be a JSON array; got {body:?}"));
        assert!(
            !arr.is_empty(),
            "array carries at least one chunk; got {body:?}"
        );
        // Each element is a gemini GenerateContentResponse (has `candidates`).
        assert!(
            arr.iter().any(|c| c.get("candidates").is_some()),
            "at least one chunk is a gemini GenerateContentResponse; got {body:?}"
        );
        handle.abort();
        server.shutdown().await;
    }

    /// Round-4 HIGH/correctness: a MID-STREAM transport failure on a gemini `:streamGenerateContent`
    /// request WITHOUT `?alt=sse` (the JSON-array framer is engaged) must terminate the body as a
    /// VALID JSON array — a trailing gemini-shaped error element + closing `]` — NOT raw SSE
    /// `event:`/`data:` text spliced into the array (the bug: `mid_stream_error_bytes` bypassed the
    /// framer, yielding an unparseable body and a protocol tell). Routes gemini→openai with
    /// `SseTransportError` so the upstream drops the connection after the first frame, driving
    /// `FirstByteBody`'s `Poll::Ready(Some(Err))` arm while `json_array` is active.
    #[tokio::test]
    async fn test_gemini_json_array_mid_stream_error_closes_array_no_sse() {
        crate::metrics::init();
        let state = StdArc::new(MockServerState::new());
        state.push(MockResponse::SseTransportError {
            ok_events: vec![r#"{"choices":[{"delta":{"content":"hi"}}]}"#.to_string()],
        });
        let server = MockServer::new(state.clone()).await;
        let app = TestApp::new()
            .lane(
                LaneSpec::new("foo", crate::proto::Protocol::openai(), &server.base_url())
                    .provider("zai"),
            )
            .pool("foo", &[(0, 1)])
            .build();
        let (addr, handle) = serve(app).await;

        let resp = reqwest::Client::new()
            .post(format!(
                "http://{addr}/v1beta/models/foo:streamGenerateContent"
            ))
            .bearer_auth("t")
            .body(
                json!({ "contents": [{"role": "user", "parts": [{"text": "hello"}]}] }).to_string(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200, "stream starts 2xx");
        let ct = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .to_string();
        assert!(
            ct.starts_with("application/json"),
            "JSON-array framed; got {ct}"
        );
        let body = resp.text().await.unwrap();
        // The whole body must still be a VALID JSON array (closing `]` present).
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap_or_else(|e| {
            panic!("mid-stream-error JSON-array body must still parse as JSON; got {body:?} ({e})")
        });
        let arr = parsed
            .as_array()
            .unwrap_or_else(|| panic!("body must be a JSON array; got {body:?}"));
        // No SSE framing anywhere — a native gemini JSON-array stream never contains `event:`/`data:`.
        assert!(
            !body.contains("event:") && !body.contains("data:"),
            "JSON-array error body must NOT contain SSE text; got {body:?}"
        );
        // The trailing element is the gemini-shaped `google.rpc.Status` error.
        assert!(
            arr.iter()
                .any(|el| el.get("error").and_then(|e| e.get("status")).is_some()),
            "array must carry a trailing gemini error element; got {body:?}"
        );
        handle.abort();
        server.shutdown().await;
    }

    /// Round-4 HIGH/conformance: the router-internal `__busbar_gemini_json_array` shim (and `stream`)
    /// must NEVER reach a CROSS-protocol backend. Routes gemini `:streamGenerateContent` (no
    /// `?alt=sse`) → an OpenAI backend and asserts the upstream-received body carries neither key (the
    /// bug: the gemini reader swept both into IR `extra` and the egress writer re-emitted the
    /// router fingerprint onto the foreign backend).
    #[tokio::test]
    async fn test_gemini_json_array_shim_not_leaked_cross_protocol() {
        crate::metrics::init();
        let state = StdArc::new(MockServerState::new());
        state.push(MockResponse::Sse {
            events: openai_stream_events(),
            abort_at_index: None,
        });
        let server = MockServer::new(state.clone()).await;
        let app = TestApp::new()
            .lane(
                LaneSpec::new("foo", crate::proto::Protocol::openai(), &server.base_url())
                    .provider("zai"),
            )
            .pool("foo", &[(0, 1)])
            .build();
        let (addr, handle) = serve(app).await;

        let resp = reqwest::Client::new()
            .post(format!(
                "http://{addr}/v1beta/models/foo:streamGenerateContent"
            ))
            .bearer_auth("t")
            .body(
                json!({ "contents": [{"role": "user", "parts": [{"text": "hello"}]}] }).to_string(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200);
        // Drain the body so the upstream request fully completes and its body is recorded.
        let _ = resp.bytes().await.unwrap();

        let upstream = state
            .get_last_request_body()
            .expect("upstream received a body");
        let upstream_v: serde_json::Value =
            serde_json::from_slice(&upstream).expect("upstream body is JSON");
        assert!(
            upstream_v.get("__busbar_gemini_json_array").is_none(),
            "router shim key must not leak to a foreign backend; got {upstream_v}"
        );
        assert!(
            upstream_v.get("stream").is_none(),
            "router-injected `stream` must not leak to a foreign backend; got {upstream_v}"
        );
        handle.abort();
        server.shutdown().await;
    }

    /// Round-4 HIGH/conformance: a CROSS-protocol stream to an Anthropic-SDK client must emit a FULL
    /// `message_start` skeleton — `id` (msg_-prefixed), `type:"message"`, `content:[]`,
    /// `stop_reason`/`stop_sequence` (null) — not the degenerate `{role,usage}` the
    /// `has_identity`-gated writer produced once `StreamTranslate` stripped the foreign id/model.
    /// Routes openai→anthropic and inspects the first `message_start` SSE frame.
    #[tokio::test]
    async fn test_anthropic_cross_protocol_message_start_full_skeleton() {
        crate::metrics::init();
        let state = StdArc::new(MockServerState::new());
        state.push(MockResponse::Sse {
            events: openai_stream_events(),
            abort_at_index: None,
        });
        let server = MockServer::new(state.clone()).await;
        // Anthropic ingress → OpenAI backend (cross-protocol): StreamTranslate reframes the upstream
        // OpenAI SSE into Anthropic SSE via the writer's `write_response_event`.
        let app = TestApp::new()
            .lane(
                LaneSpec::new("foo", crate::proto::Protocol::openai(), &server.base_url())
                    .provider("zai"),
            )
            .pool("foo", &[(0, 1)])
            .build();
        let (addr, handle) = serve(app).await;

        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/foo/v1/messages"))
            .bearer_auth("t")
            .body(
                json!({ "model": "foo", "stream": true, "messages": [], "max_tokens": 16 })
                    .to_string(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200);
        let body = resp.text().await.unwrap();
        // Extract the `message_start` event's `data:` JSON.
        let ms_data = body
            .split("\n\n")
            .find(|f| f.contains("event: message_start"))
            .and_then(|f| f.lines().find(|l| l.starts_with("data: ")))
            .map(|l| l.trim_start_matches("data: ").to_string())
            .unwrap_or_else(|| panic!("no message_start event in stream; got {body:?}"));
        let ev: serde_json::Value =
            serde_json::from_str(&ms_data).expect("message_start data parses");
        let msg = ev.get("message").expect("message object");
        assert!(
            msg.get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .starts_with("msg_"),
            "message_start.message.id must be a synthesized msg_ id; got {msg}"
        );
        assert_eq!(msg.get("type").and_then(|v| v.as_str()), Some("message"));
        assert!(
            msg.get("content").and_then(|c| c.as_array()).is_some(),
            "content[] must be present; got {msg}"
        );
        assert!(
            msg.get("stop_reason").map(|v| v.is_null()).unwrap_or(false),
            "stop_reason must be present (null); got {msg}"
        );
        assert!(
            msg.get("stop_sequence")
                .map(|v| v.is_null())
                .unwrap_or(false),
            "stop_sequence must be present (null); got {msg}"
        );
        handle.abort();
        server.shutdown().await;
    }

    /// Round-4 HIGH/conformance: a CROSS-protocol passthrough 401 must be RESHAPED into the ingress
    /// protocol's native error envelope, not relayed verbatim from the egress provider. Anthropic
    /// ingress → OpenAI backend that 401s in Passthrough mode: the client must see the Anthropic error
    /// shape (`{"type":"error","error":{"type":...}}`), not the OpenAI `{"error":{...}}` shape.
    #[tokio::test]
    async fn test_passthrough_401_cross_protocol_reshaped_to_ingress() {
        crate::metrics::init();
        let state = StdArc::new(MockServerState::new());
        state.push(MockResponse::Auth {
            status: StatusCode::UNAUTHORIZED,
        });
        let server = MockServer::new(state.clone()).await;
        let app = TestApp::new()
            .lane(
                LaneSpec::new("foo", crate::proto::Protocol::openai(), &server.base_url())
                    .provider("zai"),
            )
            .pool("foo", &[(0, 1)])
            .auth_mode(crate::auth::AuthMode::Passthrough)
            .build();
        let (addr, handle) = serve(app).await;

        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/foo/v1/messages"))
            .bearer_auth("caller-token")
            .body(json!({ "model": "foo", "messages": [], "max_tokens": 16 }).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status().as_u16(),
            401,
            "passthrough 401 status relayed"
        );
        let body: serde_json::Value = resp.json().await.unwrap();
        // Anthropic native error envelope: top-level `type:"error"` and `error.type`.
        assert_eq!(
            body.get("type").and_then(|v| v.as_str()),
            Some("error"),
            "cross-protocol 401 must be reshaped to the Anthropic error envelope; got {body}"
        );
        assert_eq!(
            body.get("error")
                .and_then(|e| e.get("type"))
                .and_then(|v| v.as_str()),
            Some("authentication_error"),
            "401 maps to authentication_error in the ingress envelope; got {body}"
        );
        handle.abort();
        server.shutdown().await;
    }

    /// MEDIUM/test-coverage: a Gemini path with NO colon (`/v1beta/models/gemini-flash`) hits the
    /// malformed-path branch and must return a Gemini-shaped 404 (not a 200, not a panic).
    #[tokio::test]
    async fn test_gemini_malformed_path_no_colon_is_404() {
        crate::metrics::init();
        let app = TestApp::new().build();
        let (addr, handle) = serve(app).await;
        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/v1beta/models/gemini-flash"))
            .bearer_auth("t")
            .body(json!({"contents": []}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status().as_u16(),
            404,
            "gemini path with no colon ⇒ native 404"
        );
        let ct = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .to_string();
        assert!(
            ct.starts_with("application/json"),
            "gemini error envelope is JSON; got {ct}"
        );
        handle.abort();
    }

    /// MEDIUM/test-coverage: an EMPTY model (`/v1beta/models/:generateContent`) is malformed (the
    /// pre-colon segment is empty) and must return a Gemini-shaped 404, not misroute.
    #[tokio::test]
    async fn test_gemini_empty_model_is_404() {
        crate::metrics::init();
        let app = TestApp::new().build();
        let (addr, handle) = serve(app).await;
        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/v1beta/models/:generateContent"))
            .bearer_auth("t")
            .body(json!({"contents": []}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status().as_u16(),
            404,
            "gemini empty model ⇒ native 404"
        );
        handle.abort();
    }

    /// MEDIUM/test-coverage: a model id that itself CONTAINS a colon must split on the LAST colon, so
    /// `tunedModels/abc:1:generateContent` resolves model `tunedModels/abc:1` (not the action). The
    /// lane is named with the colon-bearing id so a correct LAST-colon split is the only way it
    /// resolves and 2xx round-trips.
    #[tokio::test]
    async fn test_gemini_model_with_colon_splits_on_last_colon() {
        crate::metrics::init();
        let state = StdArc::new(MockServerState::new());
        state.push(MockResponse::Ok {
            status: StatusCode::OK,
            body: openai_ok_body(),
        });
        let server = MockServer::new(state.clone()).await;

        let app = TestApp::new()
            .lane(
                LaneSpec::new(
                    "tunedModels/abc:1",
                    crate::proto::Protocol::openai(),
                    &server.base_url(),
                )
                .provider("zai"),
            )
            .pool("tunedModels/abc:1", &[(0, 1)])
            .build();
        let (addr, handle) = serve(app).await;

        let resp = reqwest::Client::new()
            .post(format!(
                "http://{addr}/v1beta/models/tunedModels/abc:1:generateContent"
            ))
            .bearer_auth("t")
            .body(
                json!({
                    "contents": [{"role": "user", "parts": [{"text": "hello"}]}]
                })
                .to_string(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status().as_u16(),
            200,
            "colon-bearing model id splits on the LAST colon and resolves"
        );
        handle.abort();
        server.shutdown().await;
    }

    // ---- percent_decode unit tests (MEDIUM/test-coverage) ----

    /// `%3A` decodes to a literal colon.
    #[test]
    fn test_percent_decode_colon() {
        assert_eq!(percent_decode("%3A"), ":");
        assert_eq!(
            percent_decode("anthropic.claude-3%3A0"),
            "anthropic.claude-3:0"
        );
    }

    /// `%2E` decodes to a literal period, and an undecoded id passes through unchanged.
    #[test]
    fn test_percent_decode_period_and_plain() {
        assert_eq!(percent_decode("a%2Eb"), "a.b");
        assert_eq!(
            percent_decode("anthropic.claude-3-sonnet"),
            "anthropic.claude-3-sonnet"
        );
    }

    /// A malformed escape (`%` followed by non-hex digits) is left verbatim rather than dropped or
    /// panicking.
    #[test]
    fn test_percent_decode_malformed_escape_passes_through() {
        assert_eq!(percent_decode("%XY"), "%XY");
        assert_eq!(percent_decode("a%ZZb"), "a%ZZb");
    }

    /// A trailing `%` (or a `%` with too few following bytes) at end-of-string is safe — no
    /// out-of-bounds index, the bytes pass through.
    #[test]
    fn test_percent_decode_trailing_percent_is_safe() {
        assert_eq!(percent_decode("abc%"), "abc%");
        assert_eq!(percent_decode("abc%3"), "abc%3");
    }

    /// LOW/conformance regression: a 404 from `forward_resolved` (unknown model) carries the
    /// canonical `not_found_error` type for an OpenAI-ingress client, not the old non-canonical
    /// `not_found`. Drives the real router so the body-model ingress → resolution-miss path runs.
    #[tokio::test]
    async fn test_unknown_model_404_uses_canonical_openai_type() {
        crate::metrics::init();
        let app = TestApp::new().build();
        let (addr, handle) = serve(app).await;
        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/v1/chat/completions"))
            .bearer_auth("t")
            .body(json!({"model": "no-such-model", "messages": []}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 404, "unknown model ⇒ 404");
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(
            body.get("error")
                .and_then(|e| e.get("type"))
                .and_then(|t| t.as_str()),
            Some("not_found_error"),
            "404 carries the canonical OpenAI not_found_error type; got {body}"
        );
        handle.abort();
    }

    // ---- MEDIUM/correctness: governance-rejection requests must still be `finish`ed ----

    /// Build a governance-enabled App whose only key is allowed ONLY on pool `allowed-only` (so a
    /// request to any other pool is pool-rejected with 403). Returns the key for the GovCtx.
    fn governed_app_pool_restricted() -> (Arc<App>, crate::governance::VirtualKey) {
        use crate::governance::{GovState, NewKeySpec, SqliteStore};
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = Arc::new(GovState::new(store, 30, 0, None).unwrap());
        let (key, _secret) = gov
            .create_key(
                NewKeySpec {
                    name: "restricted".to_string(),
                    allowed_pools: vec!["allowed-only".to_string()],
                    max_budget_cents: Some(100_000),
                    budget_period: "total".to_string(),
                    rpm_limit: None,
                    tpm_limit: None,
                },
                1_700_000_000,
            )
            .unwrap();
        let mut app = minimal_app();
        Arc::get_mut(&mut app).expect("sole owner").governance = Some(gov);
        (app, key)
    }

    /// A pool-authorization rejection (403) must flow through `finish`, so it is counted in
    /// `REQUESTS_TOTAL` (as `outcome=client_error`) and the duration histogram — not silently
    /// early-returned. Regression for the Round-3 finding that governance rejections bypassed
    /// `finish` and were invisible to Prometheus / the request-log webhook.
    #[tokio::test]
    async fn test_governance_rejection_is_counted_via_finish() {
        crate::metrics::init();
        let (app, key) = governed_app_pool_restricted();
        let gov = crate::governance::GovCtx {
            key: Some(key.clone()),
        };

        // Request a pool the key is NOT allowed on → 403, and the guard returns Some(response).
        let rejected = governance_guard(&app, &gov, "openai", "denied-pool", Instant::now())
            .await
            .expect("a disallowed pool must be rejected by the governance guard");
        assert_eq!(
            rejected.status(),
            StatusCode::FORBIDDEN,
            "pool-not-allowed ⇒ 403"
        );

        // The rejection went through `finish`: a client_error outcome is now in the scrape.
        let scrape = crate::metrics::render();
        assert!(
            scrape.contains(crate::metrics::REQUESTS_TOTAL),
            "governance rejection still emits requests_total; got:\n{scrape}"
        );
        assert!(
            scrape.contains("outcome=\"client_error\""),
            "a 403 governance rejection maps to outcome=client_error; got:\n{scrape}"
        );
        assert!(
            scrape.contains(crate::metrics::REQUEST_DURATION_SECONDS),
            "governance rejection still emits the duration histogram; got:\n{scrape}"
        );

        // No flat fee is charged for a rejected (non-2xx) request.
        assert_eq!(
            key_spend(&app, &key.id),
            0,
            "a governance-rejected request charges no flat fee"
        );
    }

    /// When the key is allowed on the requested pool (and within budget/rate), the guard returns
    /// `None` so the caller proceeds to resolve+forward.
    #[tokio::test]
    async fn test_governance_guard_passes_when_allowed() {
        crate::metrics::init();
        let (app, key) = governed_app_pool_restricted();
        let gov = crate::governance::GovCtx {
            key: Some(key.clone()),
        };
        let passed = governance_guard(&app, &gov, "openai", "allowed-only", Instant::now()).await;
        assert!(
            passed.is_none(),
            "an allowed, in-budget, in-rate request is not rejected"
        );
    }

    /// Read a `Response`'s full body into a String (test helper for asserting error-envelope copy).
    async fn body_string(resp: Response) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("collect response body");
        String::from_utf8_lossy(&bytes).into_owned()
    }

    /// MEDIUM/security regression: the three governance rejection bodies (403 pool-not-allowed, 402
    /// over-budget, 429 rate-limited) must carry ONLY vendor-plausible copy — never the internal
    /// `virtual key` vocabulary, never the key id, never the pool name. A native vendor SDK parses
    /// these envelopes; leaking the key id / pool topology is both a proxy tell and an info leak.
    #[tokio::test]
    async fn test_governance_rejection_bodies_leak_no_internal_vocab() {
        crate::metrics::init();

        // --- 403: pool not allowed ---
        let (app, key) = governed_app_pool_restricted();
        let gov = crate::governance::GovCtx {
            key: Some(key.clone()),
        };
        let resp =
            pool_authorized(&gov, "denied-pool", "openai").expect("disallowed pool ⇒ 403 response");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body = body_string(resp).await;
        assert_leak_free(&body, &key.id, "denied-pool");

        // --- 402: over budget. A key with a zero budget cap is immediately over budget. ---
        let (app2, key2) = governed_app_over_budget();
        let gov2 = crate::governance::GovCtx {
            key: Some(key2.clone()),
        };
        let resp = budget_check(&app2, &gov2, "openai")
            .await
            .expect("zero-budget key ⇒ 402 response");
        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
        let body = body_string(resp).await;
        assert_leak_free(&body, &key2.id, "any-pool");

        // --- 429: rate limited. A key with rpm_limit=0 is rate-limited on the first request. ---
        let (app3, key3) = governed_app_rate_limited();
        let gov3 = crate::governance::GovCtx {
            key: Some(key3.clone()),
        };
        let resp = rate_check(&app3, &gov3, "openai").expect("rpm=0 key ⇒ 429 response");
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        // The Retry-After header must still be present (regression: copy change must not drop it).
        assert!(
            resp.headers()
                .get(axum::http::header::RETRY_AFTER)
                .is_some(),
            "429 still carries Retry-After"
        );
        let body = body_string(resp).await;
        assert_leak_free(&body, &key3.id, "any-pool");

        // Silence unused-binding warnings for the apps held only to keep gov state alive.
        let _ = (&app, &app2, &app3);
    }

    /// Assert a client-facing error body contains none of the operator-internal identifiers or
    /// governance vocabulary.
    fn assert_leak_free(body: &str, key_id: &str, pool: &str) {
        assert!(
            !body.contains("virtual key"),
            "error body must not contain the 'virtual key' vocabulary; got: {body}"
        );
        assert!(
            !body.contains(key_id),
            "error body must not contain the internal key id '{key_id}'; got: {body}"
        );
        assert!(
            !body.contains(pool),
            "error body must not contain the pool name '{pool}'; got: {body}"
        );
        assert!(
            !body.to_lowercase().contains("busbar"),
            "error body must not contain the product name; got: {body}"
        );
    }

    /// Governance-enabled App whose only key has a zero budget cap, so it is immediately over budget.
    fn governed_app_over_budget() -> (Arc<App>, crate::governance::VirtualKey) {
        use crate::governance::{GovState, NewKeySpec, SqliteStore};
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = Arc::new(GovState::new(store, 30, 0, None).unwrap());
        let (key, _secret) = gov
            .create_key(
                NewKeySpec {
                    name: "broke".to_string(),
                    allowed_pools: vec![],
                    max_budget_cents: Some(0),
                    budget_period: "total".to_string(),
                    rpm_limit: None,
                    tpm_limit: None,
                },
                1_700_000_000,
            )
            .unwrap();
        let mut app = minimal_app();
        Arc::get_mut(&mut app).expect("sole owner").governance = Some(gov);
        (app, key)
    }

    /// Governance-enabled App whose only key has `rpm_limit = 0`, so the first request is rate-limited.
    fn governed_app_rate_limited() -> (Arc<App>, crate::governance::VirtualKey) {
        use crate::governance::{GovState, NewKeySpec, SqliteStore};
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = Arc::new(GovState::new(store, 30, 0, None).unwrap());
        let (key, _secret) = gov
            .create_key(
                NewKeySpec {
                    name: "throttled".to_string(),
                    allowed_pools: vec![],
                    max_budget_cents: Some(100_000),
                    budget_period: "total".to_string(),
                    rpm_limit: Some(0),
                    tpm_limit: None,
                },
                1_700_000_000,
            )
            .unwrap();
        let mut app = minimal_app();
        Arc::get_mut(&mut app).expect("sole owner").governance = Some(gov);
        (app, key)
    }

    // ---- MEDIUM/conformance: bedrock ingress errors carry the x-amzn-* native headers ----

    /// `ingress_error("bedrock", ...)` must attach `x-amzn-RequestId` (a UUID-shaped value) and
    /// `x-amzn-errortype` (equal to the body `__type`), matching what a real AWS Bedrock runtime
    /// error response always carries. Regression for the finding that busbar-synthesized Bedrock
    /// errors had no `x-amzn-*` headers and left the SDK's request id empty.
    #[test]
    fn test_bedrock_ingress_error_has_amzn_headers() {
        let resp = ingress_error(
            "bedrock",
            StatusCode::NOT_FOUND,
            "not_found_error",
            "The model 'x' does not exist or you do not have access to it.",
        );
        let req_id = resp
            .headers()
            .get("x-amzn-requestid")
            .and_then(|h| h.to_str().ok())
            .expect("bedrock error carries x-amzn-RequestId");
        // UUID-v4 shape: 8-4-4-4-12 lowercase hex.
        let segs: Vec<&str> = req_id.split('-').collect();
        assert_eq!(segs.len(), 5, "request id is dash-grouped: {req_id}");
        assert_eq!(
            segs.iter().map(|s| s.len()).collect::<Vec<_>>(),
            vec![8, 4, 4, 4, 12],
            "request id is UUID-shaped: {req_id}"
        );
        assert!(
            req_id.chars().all(|c| c.is_ascii_hexdigit() || c == '-'),
            "request id is hex: {req_id}"
        );
        let errortype = resp
            .headers()
            .get("x-amzn-errortype")
            .and_then(|h| h.to_str().ok())
            .expect("bedrock error carries x-amzn-errortype");
        assert_eq!(
            errortype, "ResourceNotFoundException",
            "x-amzn-errortype maps not_found_error → ResourceNotFoundException"
        );
    }

    /// The `x-amzn-errortype` header must agree with the body `__type` for the kinds this router
    /// emits, and a NON-bedrock protocol must NOT get the `x-amzn-*` headers (they are a Bedrock
    /// tell only).
    #[test]
    fn test_bedrock_errortype_header_matches_body_and_others_omit() {
        for (kind, status, expected) in [
            (
                "invalid_request_error",
                StatusCode::BAD_REQUEST,
                "ValidationException",
            ),
            (
                "rate_limit_error",
                StatusCode::TOO_MANY_REQUESTS,
                "ThrottlingException",
            ),
            (
                "permission_error",
                StatusCode::FORBIDDEN,
                "AccessDeniedException",
            ),
            (
                "insufficient_quota",
                StatusCode::PAYMENT_REQUIRED,
                "ServiceQuotaExceededException",
            ),
        ] {
            let resp = ingress_error("bedrock", status, kind, "m");
            let hdr = resp
                .headers()
                .get("x-amzn-errortype")
                .and_then(|h| h.to_str().ok())
                .unwrap_or("");
            assert_eq!(hdr, expected, "x-amzn-errortype for kind {kind}");
            assert_eq!(
                crate::proto::error_kind_to_bedrock_type(kind),
                expected,
                "header mapping for {kind}"
            );
        }
        // An OpenAI-ingress error must not carry the Bedrock-only headers.
        let openai = ingress_error("openai", StatusCode::NOT_FOUND, "not_found_error", "m");
        assert!(
            openai.headers().get("x-amzn-requestid").is_none(),
            "non-bedrock protocol does not emit x-amzn-RequestId"
        );
        assert!(
            openai.headers().get("x-amzn-errortype").is_none(),
            "non-bedrock protocol does not emit x-amzn-errortype"
        );
    }

    // ---- MEDIUM/test-coverage: 400 native error envelopes on the new ingress routes ----

    /// Bad JSON on a Cohere `/v2/chat` request ⇒ 400 with the Cohere-native error envelope
    /// (`{"message": ...}`), served as application/json — not a plain-text 400 or a foreign shape.
    #[tokio::test]
    async fn test_cohere_bad_json_is_400_native_envelope() {
        crate::metrics::init();
        let app = TestApp::new().build();
        let (addr, handle) = serve(app).await;
        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/v2/chat"))
            .bearer_auth("t")
            .body("not json{".to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 400, "cohere bad json ⇒ 400");
        let ct = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .to_string();
        assert!(
            ct.starts_with("application/json"),
            "cohere error is JSON; got {ct}"
        );
        let body: serde_json::Value = resp.json().await.unwrap();
        assert!(
            body.get("message").is_some(),
            "cohere native error envelope has a message field; got {body}"
        );
        handle.abort();
    }

    /// Bad JSON on a Responses `/v1/responses` request ⇒ 400 with the Responses/OpenAI-native
    /// error envelope (`{"error":{"type":...}}`).
    #[tokio::test]
    async fn test_responses_bad_json_is_400_native_envelope() {
        crate::metrics::init();
        let app = TestApp::new().build();
        let (addr, handle) = serve(app).await;
        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/v1/responses"))
            .bearer_auth("t")
            .body("not json{".to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 400, "responses bad json ⇒ 400");
        let body: serde_json::Value = resp.json().await.unwrap();
        assert!(
            body.get("error").and_then(|e| e.get("type")).is_some(),
            "responses native error envelope has error.type; got {body}"
        );
        handle.abort();
    }

    /// An OpenAI `/v1/chat/completions` body that omits `model` ⇒ 400 with the OpenAI-native error
    /// envelope (`{"error":{"type":"invalid_request_error",...}}`).
    #[tokio::test]
    async fn test_openai_missing_model_is_400_native_envelope() {
        crate::metrics::init();
        let app = TestApp::new().build();
        let (addr, handle) = serve(app).await;
        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/v1/chat/completions"))
            .bearer_auth("t")
            .body(json!({"messages": []}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 400, "missing model ⇒ 400");
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(
            body.get("error")
                .and_then(|e| e.get("type"))
                .and_then(|t| t.as_str()),
            Some("invalid_request_error"),
            "missing-model 400 carries the OpenAI invalid_request_error type; got {body}"
        );
        handle.abort();
    }

    /// A top-level JSON ARRAY body to a Gemini ingress path hits the non-object branch in
    /// `ingress_path_model` and must return a Gemini-native 400 (not panic, not 500). Gemini's
    /// envelope is `{"error":{"code":...,"status":...}}`.
    #[tokio::test]
    async fn test_gemini_non_object_body_is_400() {
        crate::metrics::init();
        let app = TestApp::new().build();
        let (addr, handle) = serve(app).await;
        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/v1beta/models/foo:generateContent"))
            .bearer_auth("t")
            .body(json!([1, 2]).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status().as_u16(),
            400,
            "gemini non-object body ⇒ 400 (not panic/500)"
        );
        let ct = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .to_string();
        assert!(
            ct.starts_with("application/json"),
            "gemini error is JSON; got {ct}"
        );
        let body: serde_json::Value = resp.json().await.unwrap();
        assert!(
            body.get("error").and_then(|e| e.get("code")).is_some(),
            "gemini native error envelope has error.code; got {body}"
        );
        handle.abort();
    }

    /// A top-level JSON ARRAY body to a Bedrock ingress path hits the non-object branch and must
    /// return a Bedrock-native 400 (`{"__type":"ValidationException",...}`) plus the x-amzn-*
    /// headers — not a panic or a 500.
    #[tokio::test]
    async fn test_bedrock_non_object_body_is_400() {
        crate::metrics::init();
        let app = TestApp::new().build();
        let (addr, handle) = serve(app).await;
        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/model/foo/converse"))
            .bearer_auth("t")
            .body(json!([1, 2]).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status().as_u16(),
            400,
            "bedrock non-object body ⇒ 400 (not panic/500)"
        );
        assert!(
            resp.headers().get("x-amzn-errortype").is_some(),
            "bedrock 400 still carries x-amzn-errortype"
        );
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(
            body.get("__type").and_then(|t| t.as_str()),
            Some("ValidationException"),
            "bedrock non-object body ⇒ ValidationException; got {body}"
        );
        handle.abort();
    }

    // ---- MEDIUM/test-coverage: unknown-model 404 native envelope per protocol ----

    /// Gemini unknown-model 404 must carry the Gemini-native NOT_FOUND envelope
    /// (`error.status == "NOT_FOUND"`), produced by `forward_resolved`'s resolution-miss path.
    #[tokio::test]
    async fn test_gemini_unknown_model_404_native_shape() {
        crate::metrics::init();
        let app = TestApp::new().build();
        let (addr, handle) = serve(app).await;
        let resp = reqwest::Client::new()
            .post(format!(
                "http://{addr}/v1beta/models/no-such:generateContent"
            ))
            .bearer_auth("t")
            .body(json!({"contents": []}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 404, "gemini unknown model ⇒ 404");
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(
            body.get("error")
                .and_then(|e| e.get("status"))
                .and_then(|s| s.as_str()),
            Some("NOT_FOUND"),
            "gemini 404 carries error.status NOT_FOUND; got {body}"
        );
        handle.abort();
    }

    /// Bedrock unknown-model 404 must carry the Bedrock-native `ResourceNotFoundException` body and
    /// the x-amzn-* headers.
    #[tokio::test]
    async fn test_bedrock_unknown_model_404_native_shape() {
        crate::metrics::init();
        let app = TestApp::new().build();
        let (addr, handle) = serve(app).await;
        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/model/no-such/converse"))
            .bearer_auth("t")
            .body(json!({"messages": []}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 404, "bedrock unknown model ⇒ 404");
        assert_eq!(
            resp.headers()
                .get("x-amzn-errortype")
                .and_then(|h| h.to_str().ok()),
            Some("ResourceNotFoundException"),
            "bedrock 404 x-amzn-errortype is ResourceNotFoundException"
        );
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(
            body.get("__type").and_then(|t| t.as_str()),
            Some("ResourceNotFoundException"),
            "bedrock 404 body __type is ResourceNotFoundException; got {body}"
        );
        handle.abort();
    }

    /// Cohere unknown-model 404 must carry the Cohere-native envelope (`{"message": ...}`).
    #[tokio::test]
    async fn test_cohere_unknown_model_404_native_shape() {
        crate::metrics::init();
        let app = TestApp::new().build();
        let (addr, handle) = serve(app).await;
        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/v2/chat"))
            .bearer_auth("t")
            .body(json!({"model": "no-such-model", "messages": []}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 404, "cohere unknown model ⇒ 404");
        let body: serde_json::Value = resp.json().await.unwrap();
        assert!(
            body.get("message").and_then(|m| m.as_str()).is_some(),
            "cohere 404 carries a native message field; got {body}"
        );
        handle.abort();
    }

    /// Responses unknown-model 404 must carry the OpenAI-identical envelope
    /// (`{"error":{"type":"not_found_error",...}}`).
    #[tokio::test]
    async fn test_responses_unknown_model_404_native_shape() {
        crate::metrics::init();
        let app = TestApp::new().build();
        let (addr, handle) = serve(app).await;
        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/v1/responses"))
            .bearer_auth("t")
            .body(json!({"model": "no-such-model", "input": "hi"}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 404, "responses unknown model ⇒ 404");
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(
            body.get("error")
                .and_then(|e| e.get("type"))
                .and_then(|t| t.as_str()),
            Some("not_found_error"),
            "responses 404 carries not_found_error type; got {body}"
        );
        handle.abort();
    }

    // ---- HIGH/test-coverage: streaming integration for Cohere and Responses ingress ----

    /// Collect the `data:` payloads of an SSE body into a Vec of `(event_name, data_json_text)`,
    /// where `event_name` is the value of the frame's `event:` line (empty string for an
    /// OpenAI/Cohere-style bare-`data:` frame). `[DONE]` sentinels are skipped. Used by the
    /// native-shape stream assertions below so a regression that leaked the OpenAI egress chunks
    /// verbatim (which also begin `data:`) is caught.
    fn sse_frames(body: &str) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for frame in body.split("\n\n") {
            let mut event_name = String::new();
            let mut data: Option<String> = None;
            for line in frame.lines() {
                if let Some(rest) = line.strip_prefix("event:") {
                    event_name = rest.trim().to_string();
                } else if let Some(rest) = line.strip_prefix("data:") {
                    data = Some(rest.trim().to_string());
                }
            }
            if let Some(d) = data {
                if d == "[DONE]" {
                    continue;
                }
                out.push((event_name, d));
            }
        }
        out
    }

    /// A Cohere `/v2/chat` request with `"stream": true` must return `Content-Type:
    /// text/event-stream` AND a body framed as a NATIVE Cohere v2 stream — `data:` frames whose JSON
    /// `type` walks `message-start` → `content-delta` → `message-end` — with NO leaked OpenAI
    /// `chat.completion.chunk` objects. Routes cohere→openai (cross-protocol) so the full
    /// ingress→forward→SSE-output reframe runs; a regression that passed the OpenAI egress chunks
    /// through verbatim would still start `data:` but carries none of the Cohere vocabulary and is
    /// caught here.
    #[tokio::test]
    async fn test_cohere_ingress_stream_emits_native_cohere_frames() {
        crate::metrics::init();
        let state = StdArc::new(MockServerState::new());
        state.push(MockResponse::Sse {
            events: openai_stream_events(),
            abort_at_index: None,
        });
        let server = MockServer::new(state.clone()).await;
        let app = TestApp::new()
            .lane(
                LaneSpec::new("co", crate::proto::Protocol::openai(), &server.base_url())
                    .provider("zai"),
            )
            .pool("co", &[(0, 1)])
            .build();
        let (addr, handle) = serve(app).await;

        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/v2/chat"))
            .bearer_auth("t")
            .body(
                json!({
                    "model": "co",
                    "stream": true,
                    "messages": [{"role": "user", "content": "hello"}]
                })
                .to_string(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200, "cohere stream ⇒ 200");
        let ct = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .to_string();
        assert!(
            ct.starts_with("text/event-stream"),
            "cohere streaming ingress is SSE; got {ct}"
        );
        let text = resp.text().await.unwrap();

        // No OpenAI egress object may leak through to a Cohere SDK.
        assert!(
            !text.contains("chat.completion.chunk"),
            "cohere stream leaked an OpenAI chat.completion.chunk object; got:\n{text}"
        );

        // Collect the JSON `type` discriminants of every data frame, in order.
        let types: Vec<String> = sse_frames(&text)
            .into_iter()
            .filter_map(|(_, d)| serde_json::from_str::<serde_json::Value>(&d).ok())
            .filter_map(|v| {
                v.get("type")
                    .and_then(|t| t.as_str())
                    .map(|s| s.to_string())
            })
            .collect();
        assert!(
            types.iter().any(|t| t == "message-start"),
            "cohere stream must open with a message-start frame; got types {types:?}"
        );
        assert!(
            types.iter().any(|t| t == "content-delta"),
            "cohere stream must carry a content-delta frame; got types {types:?}"
        );
        assert!(
            types.iter().any(|t| t == "message-end"),
            "cohere stream must close with a message-end frame; got types {types:?}"
        );
        // Ordering: message-start strictly precedes message-end (native Cohere framing).
        let start_at = types.iter().position(|t| t == "message-start");
        let end_at = types.iter().rposition(|t| t == "message-end");
        assert!(
            matches!((start_at, end_at), (Some(s), Some(e)) if s < e),
            "cohere message-start must precede message-end; got types {types:?}"
        );
        handle.abort();
        server.shutdown().await;
    }

    /// A Responses `/v1/responses` request with `"stream": true` must return SSE framing whose typed
    /// `event:` names are the NATIVE Responses vocabulary — a `response.created` opener, a
    /// `response.output_text.delta`, and a `response.completed` terminator — with NO leaked OpenAI
    /// `chat.completion.chunk` objects. Routes responses→openai (cross-protocol).
    #[tokio::test]
    async fn test_responses_ingress_stream_emits_native_responses_events() {
        crate::metrics::init();
        let state = StdArc::new(MockServerState::new());
        state.push(MockResponse::Sse {
            events: openai_stream_events(),
            abort_at_index: None,
        });
        let server = MockServer::new(state.clone()).await;
        let app = TestApp::new()
            .lane(
                LaneSpec::new("re", crate::proto::Protocol::openai(), &server.base_url())
                    .provider("zai"),
            )
            .pool("re", &[(0, 1)])
            .build();
        let (addr, handle) = serve(app).await;

        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/v1/responses"))
            .bearer_auth("t")
            .body(
                json!({
                    "model": "re",
                    "stream": true,
                    "input": "hello"
                })
                .to_string(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200, "responses stream ⇒ 200");
        let ct = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .to_string();
        assert!(
            ct.starts_with("text/event-stream"),
            "responses streaming ingress is SSE; got {ct}"
        );
        let text = resp.text().await.unwrap();

        // No OpenAI egress object may leak through to a Responses SDK.
        assert!(
            !text.contains("chat.completion.chunk"),
            "responses stream leaked an OpenAI chat.completion.chunk object; got:\n{text}"
        );

        let events: Vec<String> = sse_frames(&text).into_iter().map(|(e, _)| e).collect();
        assert!(
            events.iter().any(|e| e == "response.created"),
            "responses stream must open with response.created; got events {events:?}"
        );
        assert!(
            events.iter().any(|e| e == "response.output_text.delta"),
            "responses stream must carry response.output_text.delta; got events {events:?}"
        );
        assert!(
            events.iter().any(|e| e == "response.completed"),
            "responses stream must terminate with response.completed; got events {events:?}"
        );
        // The completed terminator must be the LAST typed event (native Responses ordering).
        let created_at = events.iter().position(|e| e == "response.created");
        let completed_at = events.iter().rposition(|e| e == "response.completed");
        assert!(
            matches!((created_at, completed_at), (Some(c), Some(d)) if c < d),
            "responses response.created must precede response.completed; got events {events:?}"
        );
        handle.abort();
        server.shutdown().await;
    }

    // ---- MEDIUM/test-coverage: percent-encoded Bedrock model id end-to-end ----

    /// A percent-encoded Bedrock model id (`anthropic.claude-3%3Ahaiku` → `anthropic.claude-3:haiku`)
    /// must be decoded by axum, resolved, and the converse-stream response re-encoded as a binary
    /// AWS eventstream. This exercises the real HTTP decode + routing + binary re-encode end-to-end
    /// (the unit `percent_decode` tests bypass axum's own first decode).
    #[tokio::test]
    async fn test_bedrock_percent_encoded_model_id_converse_stream() {
        crate::metrics::init();
        let state = StdArc::new(MockServerState::new());
        state.push(MockResponse::Sse {
            events: openai_stream_events(),
            abort_at_index: None,
        });
        let server = MockServer::new(state.clone()).await;
        // The lane is named with the DECODED colon-bearing id so a correct end-to-end decode is the
        // only way it resolves.
        let app = TestApp::new()
            .lane(
                LaneSpec::new(
                    "anthropic.claude-3:haiku",
                    crate::proto::Protocol::openai(),
                    &server.base_url(),
                )
                .provider("zai"),
            )
            .pool("anthropic.claude-3:haiku", &[(0, 1)])
            .build();
        let (addr, handle) = serve(app).await;

        let resp = reqwest::Client::new()
            .post(format!(
                "http://{addr}/model/anthropic.claude-3%3Ahaiku/converse-stream"
            ))
            .bearer_auth("t")
            .body(json!({"messages": [{"role": "user", "content": [{"text": "hi"}]}]}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status().as_u16(),
            200,
            "percent-encoded model id decodes, resolves, and 2xx round-trips"
        );
        let ct = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .to_string();
        assert!(
            ct.starts_with("application/vnd.amazon.eventstream"),
            "decoded model resolves to a binary eventstream; got {ct}"
        );
        let body = resp.bytes().await.unwrap();
        let mut buf = body.to_vec();
        let frames = crate::eventstream::drain_frames(&mut buf);
        assert!(
            !frames.is_empty(),
            "at least one binary eventstream frame decodes for the percent-encoded model"
        );
        handle.abort();
        server.shutdown().await;
    }

    // ---- HIGH/test-coverage: mid-stream transport-error E2E for Cohere and Responses ingress ----
    //
    // `test_sse_ingress_mid_stream_error_uses_native_framing` (forward.rs) tests the byte shape of
    // `mid_stream_error_bytes` in isolation; these two drive a TRUE `SseTransportError` through the
    // REAL router on the two ingress routes that previously lacked an E2E mid-stream error test
    // (bedrock/openai/gemini-json-array already have theirs above). Each routes cross-protocol to an
    // OpenAI backend that drops the connection after the first frame.

    /// Cohere `/v2/chat` (stream:true) mid-stream transport failure: the body must terminate with a
    /// NATIVE Cohere SSE error frame — a BARE `data:` frame (Cohere's native stream never emits an
    /// `event:` line mid-stream) whose JSON carries the Cohere-native flat shape (a `message`, or a
    /// `type`+`message`) — and must NOT regress to an OpenAI `{"error":{...}}` envelope NESTED under
    /// `error` only (the leak the finding guards against would be an `event:` line or a foreign shape).
    #[tokio::test]
    async fn test_cohere_ingress_mid_stream_transport_error_appends_native_sse() {
        crate::metrics::init();
        let state = StdArc::new(MockServerState::new());
        state.push(MockResponse::SseTransportError {
            ok_events: vec![r#"{"choices":[{"delta":{"content":"hi"}}]}"#.to_string()],
        });
        let server = MockServer::new(state.clone()).await;
        let app = TestApp::new()
            .lane(
                LaneSpec::new("co", crate::proto::Protocol::openai(), &server.base_url())
                    .provider("zai"),
            )
            .pool("co", &[(0, 1)])
            .build();
        let (addr, handle) = serve(app).await;

        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/v2/chat"))
            .bearer_auth("t")
            .body(
                json!({ "model": "co", "stream": true, "messages": [{"role": "user", "content": "hi"}] })
                    .to_string(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200, "cohere stream starts 2xx");
        let body = resp.bytes().await.unwrap();
        let text = String::from_utf8_lossy(&body);
        // No `event:` line anywhere — a native Cohere stream never emits one mid-stream.
        assert!(
            !text.contains("event:"),
            "cohere mid-stream error must be a bare data: frame (no event: line); got:\n{text}"
        );
        // No OpenAI egress object may leak through verbatim.
        assert!(
            !text.contains("chat.completion.chunk"),
            "cohere mid-stream error leaked an OpenAI chunk object; got:\n{text}"
        );
        // The LAST `data:` frame is the native Cohere error envelope (a flat `message`, possibly with
        // a `type`), NOT a top-level OpenAI `{"error":{...}}`-only shape.
        let last_data = sse_frames(&text)
            .into_iter()
            .next_back()
            .map(|(_, d)| d)
            .expect("a trailing data: error frame");
        let v: Value = serde_json::from_str(&last_data).expect("native Cohere JSON envelope");
        assert!(
            v.get("message").is_some(),
            "cohere mid-stream error carries a native flat `message`; got {v}"
        );
        handle.abort();
        server.shutdown().await;
    }

    /// Responses `/v1/responses` (stream:true) mid-stream transport failure: the body must terminate
    /// with `event: response.failed` whose `data:` payload is the SDK-required STREAM shape
    /// `{"response":{"status":"failed","error":{...}}}` — and must NOT regress to a top-level
    /// `{"error":{...}}` HTTP envelope (which the official Responses stream decoder cannot locate via
    /// `event.response`).
    #[tokio::test]
    async fn test_responses_ingress_mid_stream_transport_error_appends_response_failed() {
        crate::metrics::init();
        let state = StdArc::new(MockServerState::new());
        state.push(MockResponse::SseTransportError {
            ok_events: vec![r#"{"choices":[{"delta":{"content":"hi"}}]}"#.to_string()],
        });
        let server = MockServer::new(state.clone()).await;
        let app = TestApp::new()
            .lane(
                LaneSpec::new("re", crate::proto::Protocol::openai(), &server.base_url())
                    .provider("zai"),
            )
            .pool("re", &[(0, 1)])
            .build();
        let (addr, handle) = serve(app).await;

        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/v1/responses"))
            .bearer_auth("t")
            .body(json!({ "model": "re", "stream": true, "input": "hi" }).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200, "responses stream starts 2xx");
        let body = resp.bytes().await.unwrap();
        let text = String::from_utf8_lossy(&body);
        // The terminal frame is the named `response.failed` event.
        assert!(
            text.contains("event: response.failed"),
            "responses mid-stream error must terminate with event: response.failed; got:\n{text}"
        );
        // Locate the `response.failed` frame and assert its payload is the STREAM shape.
        let failed_data = sse_frames(&text)
            .into_iter()
            .find(|(ev, _)| ev == "response.failed")
            .map(|(_, d)| d)
            .expect("a response.failed data: frame");
        let v: Value = serde_json::from_str(&failed_data).expect("native Responses JSON envelope");
        assert!(
            v.get("response").is_some(),
            "responses stream error MUST wrap in a `response` object (SDK reads event.response); got {v}"
        );
        assert_eq!(
            v["response"]["status"], "failed",
            "response.status is `failed`; got {v}"
        );
        assert!(
            v["response"]["error"]["message"].is_string(),
            "the error lives inside response.error; got {v}"
        );
        assert!(
            v.get("error").is_none(),
            "responses stream error must NOT carry a top-level `error` (the HTTP envelope the stream \
             decoder cannot locate); got {v}"
        );
        handle.abort();
        server.shutdown().await;
    }

    // ---- HIGH/conformance: no client-facing error message carries the wire-visible `router:` tell --

    /// CLASS regression for the `router:` prefix leak. Drives the REAL router on EVERY ingress
    /// protocol and asserts that NONE of the synthesized client-facing error bodies (bad JSON,
    /// missing/unknown model, malformed gemini path, unsupported gemini action, non-object body,
    /// provider mismatch) contains the substring `router:` anywhere — including inside the
    /// per-protocol native envelope's `message`/`error.message`/`__type` fields. A native vendor
    /// endpoint never returns an error whose copy begins `router:`, so its presence is a
    /// deterministic proxy tell on any of the six surfaces.
    #[tokio::test]
    async fn test_no_client_error_message_carries_router_prefix() {
        crate::metrics::init();
        let app = TestApp::new().build();
        let (addr, handle) = serve(app).await;
        let client = reqwest::Client::new();

        // (path, body) pairs that each hit a distinct synthesized-error site across all protocols.
        let cases: Vec<(String, String)> = vec![
            // openai: bad json + missing model + unknown model.
            (
                format!("http://{addr}/v1/chat/completions"),
                "not json{".to_string(),
            ),
            (
                format!("http://{addr}/v1/chat/completions"),
                json!({"messages": []}).to_string(),
            ),
            (
                format!("http://{addr}/v1/chat/completions"),
                json!({"model": "no-such", "messages": []}).to_string(),
            ),
            // cohere unknown model.
            (
                format!("http://{addr}/v2/chat"),
                json!({"model": "no-such", "messages": []}).to_string(),
            ),
            // responses unknown model.
            (
                format!("http://{addr}/v1/responses"),
                json!({"model": "no-such", "input": "hi"}).to_string(),
            ),
            // gemini: malformed path (no colon), unsupported action, non-object body, unknown model.
            (
                format!("http://{addr}/v1beta/models/gemini-flash"),
                json!({}).to_string(),
            ),
            (
                format!("http://{addr}/v1beta/models/foo:countTokens"),
                json!({"contents": []}).to_string(),
            ),
            (
                format!("http://{addr}/v1beta/models/foo:generateContent"),
                json!([1, 2]).to_string(),
            ),
            (
                format!("http://{addr}/v1beta/models/no-such:generateContent"),
                json!({"contents": []}).to_string(),
            ),
            // bedrock: non-object body + unknown model.
            (
                format!("http://{addr}/model/foo/converse"),
                json!([1, 2]).to_string(),
            ),
            (
                format!("http://{addr}/model/no-such/converse"),
                json!({"messages": []}).to_string(),
            ),
            // anthropic named: unknown model/pool.
            (
                format!("http://{addr}/no-such/v1/messages"),
                json!({"model": "no-such", "messages": [], "max_tokens": 16}).to_string(),
            ),
        ];

        for (url, payload) in cases {
            let resp = client
                .post(&url)
                .bearer_auth("t")
                .body(payload.clone())
                .send()
                .await
                .unwrap();
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap();
            assert!(
                !body.contains("router:"),
                "client-facing error body for {url} (payload {payload}) leaked the `router:` tell \
                 (status {status}); got: {body}"
            );
        }
        handle.abort();
    }
}
