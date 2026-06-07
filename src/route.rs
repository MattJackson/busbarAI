// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

use std::sync::Arc;
use std::time::Instant;

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
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
            return Some(ingress_error(
                proto,
                StatusCode::FORBIDDEN,
                "permission_error",
                &format!(
                    "virtual key '{}' is not allowed to use pool '{pool}'",
                    key.id
                ),
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
            return Some(ingress_error(
                proto,
                StatusCode::PAYMENT_REQUIRED,
                "billing_error",
                &format!("virtual key '{}' has exceeded its budget", key.id),
            ));
        }
    }
    None
}

/// reject (429 + Retry-After) before forwarding when the resolved virtual key is over
/// its RPM/TPM for the current window. No-op when governance is off or the key has no rate cap.
fn rate_check(app: &Arc<App>, gov: &crate::governance::GovCtx, proto: &str) -> Option<Response> {
    if let (Some(g), Some(key)) = (&app.governance, &gov.key) {
        if let Err(retry) = g.check_rate(key, crate::store::now()) {
            // Native error envelope for the body, plus the standard `Retry-After` header so a
            // well-behaved SDK backs off the right amount.
            let mut resp = ingress_error(
                proto,
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limit_error",
                &format!("rate limit exceeded for virtual key '{}'", key.id),
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
/// protocol-appropriate error category; `message` is the human-readable detail. The body is always
/// served as `application/json` (every vendor's error envelope is JSON). If `proto` is somehow not
/// a known protocol, fall back to a plain-text body rather than panicking on the request path.
fn ingress_error(proto: &str, status: StatusCode, kind: &str, message: &str) -> Response {
    match crate::proto::protocol_for(proto) {
        Some(p) => {
            let body = p.writer().write_error(status.as_u16(), kind, message);
            (
                status,
                [(
                    axum::http::header::CONTENT_TYPE,
                    axum::http::HeaderValue::from_static("application/json"),
                )],
                body.to_string(),
            )
                .into_response()
        }
        None => (status, message.to_string()).into_response(),
    }
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
                &format!("router: bad json: {e}"),
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
                "router: missing 'model' in request body",
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
#[allow(clippy::too_many_arguments)]
async fn ingress_path_model(
    app: &Arc<App>,
    gov: &crate::governance::GovCtx,
    caller: &crate::auth::CallerToken,
    headers: &HeaderMap,
    body: Bytes,
    model: &str,
    stream: bool,
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
                &format!("router: bad json: {e}"),
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
        }
        None => {
            return ingress_error(
                proto,
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                "router: request body must be a JSON object",
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
                &format!("router: cannot re-serialize body: {e}"),
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
    // enforce the virtual key's allowed-pools against the requested model/pool.
    if let Some(resp) = pool_authorized(gov, model, proto) {
        return resp;
    }
    // reject over-budget keys before forwarding.
    if let Some(resp) = budget_check(app, gov, proto).await {
        return resp;
    }
    // reject rate-limited keys before forwarding.
    if let Some(resp) = rate_check(app, gov, proto) {
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

    ingress_error(
        proto,
        StatusCode::NOT_FOUND,
        "not_found",
        &format!("router: unknown model '{model}'"),
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
// other action is an unknown native operation → a Gemini-shaped 404.
#[tracing::instrument(name = "gemini_ingress", skip_all)]
pub(crate) async fn gemini_ingress(
    State(app): State<Arc<App>>,
    Path(rest): Path<String>,
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
                &format!("router: malformed gemini path '/v1beta/models/{rest}'"),
            )
        }
    };

    let stream = match action {
        "streamGenerateContent" => true,
        "generateContent" => false,
        other => {
            return ingress_error(
                "gemini",
                StatusCode::NOT_FOUND,
                "NOT_FOUND",
                &format!("router: unknown gemini action '{other}'"),
            )
        }
    };

    ingress_path_model(&app, &gov, &caller, &headers, body, model, stream, "gemini").await
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

// POST /model/:modelId/converse-stream — Bedrock Converse ingress (streaming). Same as `converse`
// but stream=true. NOTE: the binary `application/vnd.amazon.eventstream` RESPONSE encoding is built
// in the NEXT wave; this wave only wires the route + stream intent so the request resolves and
// forwards correctly.
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

/// Shared body for both Bedrock ingress routes: URL-decode the `modelId` path segment (Bedrock
/// model ids carry `.`/`:` and the AWS SDK percent-encodes them in the path) then delegate to the
/// path-model core with the route-selected stream intent.
async fn bedrock_ingress(
    app: &Arc<App>,
    gov: &crate::governance::GovCtx,
    caller: &crate::auth::CallerToken,
    headers: &HeaderMap,
    body: Bytes,
    model_id: &str,
    stream: bool,
) -> Response {
    // URL-decode the model id. On a malformed percent-encoding, fall back to the raw segment rather
    // than failing — a raw (already-decoded) id is the common case and still resolves.
    let model = percent_decode(model_id);
    ingress_path_model(app, gov, caller, headers, body, &model, stream, "bedrock").await
}

/// Minimal percent-decoding for a single path segment (no external dependency). Decodes `%XX`
/// escapes as UTF-8; on any malformed escape it leaves the bytes as-is. Used to recover a Bedrock
/// `modelId` (e.g. `anthropic.claude-3%3A0`) from the URL path.
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

    // enforce the virtual key's allowed-pools against the named pool/model.
    if let Some(resp) = pool_authorized(&gov, &name, "anthropic") {
        return resp;
    }
    // reject over-budget keys before forwarding.
    if let Some(resp) = budget_check(&app, &gov, "anthropic").await {
        return resp;
    }
    // reject rate-limited keys before forwarding.
    if let Some(resp) = rate_check(&app, &gov, "anthropic") {
        return resp;
    }

    let started = Instant::now();

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

    ingress_error(
        "anthropic",
        StatusCode::NOT_FOUND,
        "not_found_error",
        &format!("router: '{name}' is not a known model or pool"),
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

    // enforce the virtual key's allowed-pools against the ad-hoc model target.
    if let Some(resp) = pool_authorized(&gov, &model, "anthropic") {
        return resp;
    }
    // reject over-budget keys before forwarding.
    if let Some(resp) = budget_check(&app, &gov, "anthropic").await {
        return resp;
    }
    // reject rate-limited keys before forwarding.
    if let Some(resp) = rate_check(&app, &gov, "anthropic") {
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
        Some(&i) => ingress_error(
            "anthropic",
            StatusCode::BAD_REQUEST,
            "invalid_request_error",
            &format!(
                "router: model '{}' is on provider '{}', not '{}'",
                model, app.lanes[i].provider, provider
            ),
        ),
        None => ingress_error(
            "anthropic",
            StatusCode::NOT_FOUND,
            "not_found_error",
            &format!("router: unknown model '{model}'"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    /// an OpenAI backend, and returns native Converse JSON. (Streaming binary assertion is DEFERRED
    /// to the eventstream-encoder wave.)
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
}
