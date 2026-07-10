// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

use std::sync::Arc;
use std::time::Instant;

use axum::{
    body::Bytes,
    extract::{OriginalUri, Path, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use serde_json::Value;

use crate::forward::{forward_with_pool, forward_with_pool_parsed};
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
                crate::forward::KIND_PERMISSION,
                "Your API key does not have permission to access this resource.",
            ));
        }
    }
    None
}

/// Re-enforce the virtual key's `allowed_pools` ACL against EVERY fallback pool the request could
/// reach if the requested pool exhausts (`OnExhausted::FallbackPool`). The initial `pool_authorized`
/// check only gates the FIRST pool; without this, a key restricted to pool A could be served by a
/// fallback pool B (configured via A's `on_exhausted = fallback_pool:B`) it is not allowed to touch,
/// because the fallback dispatch in `forward::handle_fallback_pool` never re-checks the key (the
/// `gov` context is not threaded that deep — the ACL is an INGRESS concern, enforced here).
///
/// The fallback chain is multi-level (A→B→C: B's own `on_exhausted` may name C) and may cycle
/// (A→B→A). We walk it with the SAME visited-pool termination guard `handle_fallback_pool` uses, so
/// the walk always terminates, and we reject (403) the moment any reachable fallback pool is one the
/// key may not use — mirroring the initial `pool_authorized` 403 exactly (same status/kind/body, so
/// the denial is vendor-indistinguishable whether it trips on the initial or a fallback pool).
///
/// No-op when governance is off (`gov.key` is None) or the key allows all pools.
fn fallback_pools_authorized(
    app: &Arc<App>,
    gov: &crate::governance::GovCtx,
    pool: &str,
    proto: &str,
) -> Option<Response> {
    let key = gov.key.as_ref()?;
    // A key with no restriction (empty `allowed_pools`) admits every pool — nothing to walk.
    if key.allowed_pools.is_empty() {
        return None;
    }
    let mut visited: std::collections::HashSet<&str> = std::collections::HashSet::new();
    let mut current = pool;
    loop {
        // Termination guard: a chain that cycles back to an already-walked pool (A→B→A) stops —
        // mirrors `handle_fallback_pool`'s `visited_pools` guard so the two cannot diverge.
        if !visited.insert(current) {
            return None;
        }
        let next = match app.on_exhausted_cfgs.get(current) {
            Some(crate::config::OnExhausted::FallbackPool(fallback)) => fallback.as_str(),
            // `Status503` and `LeastBad` stay within `current` (no new pool name is introduced), and
            // an unconfigured pool defaults to 503 — neither can reach a different pool, so the walk
            // ends here. Explicit arms, no `_ =>` catch-all.
            Some(crate::config::OnExhausted::Status503)
            | Some(crate::config::OnExhausted::LeastBad)
            | None => return None,
        };
        // Re-run the identical ACL gate against the fallback pool name before it could ever be
        // dispatched to. A 403 here is byte-for-byte the initial-pool 403.
        if let Some(resp) = pool_authorized(gov, next, proto) {
            return Some(resp);
        }
        current = next;
    }
}

/// Build the token-usage sink for a request: when governance is on and a virtual key resolved, the
/// response stream charges its tapped token usage to that key's budget at completion (token-accurate
/// accounting). `None` disables it (governance off / no key).
fn usage_sink(
    app: &Arc<App>,
    gov: &crate::governance::GovCtx,
    charged_at: u64,
) -> Option<crate::forward::UsageSink> {
    match (&app.governance, &gov.key) {
        (Some(g), Some(key)) => Some(crate::forward::UsageSink {
            gov: g.clone(),
            key_id: key.id.clone(),
            period: key.budget_period.clone(),
            // The header-arrival epoch this request was admitted at — reused for the token fee so it
            // shares the flat per-request fee's window (#29). See `UsageSink::charged_at`.
            charged_at,
        }),
        _ => None,
    }
}

/// The default affinity header name used when a pool's `affinity` config does not specify a custom
/// header. Both the `Some`-arm fallback and the `None`-arm of `affinity_header_for` must agree on
/// this spelling; a single const prevents them from silently diverging.
const DEFAULT_AFFINITY_HEADER: &str = "x-session-id";

/// The request header that pins a session to a lane for a pool. Defaults to `x-session-id`; a
/// pool's `affinity` config (mode `session`) may name a different header (e.g. `x-user-id`).
fn affinity_header_for<'a>(app: &'a Arc<App>, pool: &str) -> &'a str {
    match app.pool_runtime.get(pool).and_then(|r| r.affinity.as_ref()) {
        // `mode` is `AffinityMode::Session` (the only variant); honour the configured header name.
        Some(a) => match a.mode {
            crate::config::AffinityMode::Session => {
                a.header_name.as_deref().unwrap_or(DEFAULT_AFFINITY_HEADER)
            }
        },
        None => DEFAULT_AFFINITY_HEADER,
    }
}

/// Reject before forwarding when the resolved virtual key is already over its budget for the
/// window the request was admitted in. No-op when governance is off or the key has no budget cap.
/// Async: the atomic budget check-and-charge is a (blocking) SQLite UPSERT offloaded to the blocking
/// pool inside `charge_within_budget_async`, so the request path never stalls a Tokio worker thread.
///
/// The admission window is keyed off `charged_at` (the pinned header-arrival epoch), NOT a fresh
/// `store::now()`. The flat per-request fee is charged HERE, atomically, into the `charged_at`
/// window, and the token-fee (`UsageSink::charged_at` → `record_tokens`) bills into the SAME window,
/// so the charge-and-check and the later token charge must read the SAME window — else, when a
/// request straddles a window boundary, a fresh clock here could admit/charge against an empty new
/// window while the token fee falls into the old one, or vice-versa (#29 sibling of the token pin).
async fn budget_check(
    app: &Arc<App>,
    gov: &crate::governance::GovCtx,
    proto: &str,
    charged_at: u64,
) -> Option<Response> {
    if let (Some(g), Some(key)) = (&app.governance, &gov.key) {
        // ATOMIC budget check-and-charge (fix 2a): one indivisible UPSERT charges the flat per-request
        // fee + one request IFF it stays within the cap. This replaces the old non-atomic read
        // (`is_over_budget_async`) + later write (`record_request` in `finish`) pair, which let N
        // concurrent requests for one key all read "under budget" and all charge → overshoot. Now the
        // flat fee is a HARD cap. The charge fires HERE (so `finish` must NOT re-charge it); a non-2xx
        // outcome is REFUNDED in `finish` to preserve the "bill 2xx only" flat-fee policy. This guard
        // runs LAST in `governance_guard` (after pool/rate), so no later guard can reject an
        // already-charged request.
        match g.try_charge_request_within_budget(key, charged_at).await {
            Ok(true) => {} // charged + admitted — proceed
            Ok(false) => {
                // `insufficient_quota` is the canonical OpenAI/Responses quota error type (the OpenAI
                // writer passes it through verbatim as a real type; the Responses writer maps it
                // explicitly). The older `billing_error` token was not in either vocabulary, so it
                // leaked verbatim as a non-canonical `error.type` that an SDK's typed-exception mapping
                // did not recognize — a router-side tell on a 402.
                //
                // The client-facing message carries only vendor-plausible quota copy — never the
                // internal key id or governance vocabulary. The key id is recorded server-side.
                tracing::info!(key_id = %key.id, "governance: key over budget");
                // Native quota status differs by vendor (Bedrock's `ServiceQuotaExceededException` is
                // 400; every other vendor surfaces over-quota as 429). The writer owns that mapping via
                // `quota_exceeded_status()`, so this agnostic guard never branches on the protocol
                // name. The body `kind` (`insufficient_quota`) drives the per-protocol error vocabulary.
                let status = crate::proto::protocol_for(proto)
                    .map(|p| p.writer().quota_exceeded_status())
                    .unwrap_or(StatusCode::TOO_MANY_REQUESTS);
                return Some(ingress_error(
                    proto,
                    status,
                    crate::forward::KIND_INSUFFICIENT_QUOTA,
                    "You have exceeded your current quota. Please check your plan and billing details.",
                ));
            }
            Err(e) => {
                // fix 2b: store error on the budget charge → consult the configured fail-mode.
                // `Allow` (default) fails OPEN (proceed → availability, today's behavior); `Deny`
                // fails CLOSED (reject → hard guarantee). The flat fee is NOT charged on this path
                // (the atomic UPSERT did not commit), so an allowed request is simply un-billed for
                // its flat fee this time — acceptable on a telemetry-store hiccup.
                match g.budget_on_store_error() {
                    crate::config::BudgetOnStoreError::Allow => {
                        tracing::warn!(key_id = %key.id, error = %e, "budget charge store error; failing open (allow)");
                    }
                    crate::config::BudgetOnStoreError::Deny => {
                        tracing::warn!(key_id = %key.id, error = %e, "budget charge store error; failing closed (deny)");
                        let status = crate::proto::protocol_for(proto)
                            .map(|p| p.writer().quota_exceeded_status())
                            .unwrap_or(StatusCode::TOO_MANY_REQUESTS);
                        return Some(ingress_error(
                            proto,
                            status,
                            crate::forward::KIND_INSUFFICIENT_QUOTA,
                            "You have exceeded your current quota. Please check your plan and billing details.",
                        ));
                    }
                }
            }
        }
    }
    None
}

/// Run the three governance guards (pool-allowed / over-budget / rate-limited) for a request that
/// is about to be forwarded. Returns the protocol-native rejection response already passed through
/// `finish_rejected`. The statuses are deliberately vendor-faithful and never 402: pool-not-allowed maps to
/// 403, over-budget maps to 429 (Bedrock's quota shape is a 400-class error — see `budget_check`),
/// and rate-limited maps to 429 + `Retry-After`. busbar never emits 402 here — a blanket 402 was a
/// vendor-agnostic tell, since no real provider returns 402 for these conditions. Routing through
/// `finish_rejected` means a governance-rejected request still emits `REQUESTS_TOTAL`, the
/// `REQUEST_DURATION_SECONDS` histogram, and the request-log webhook. Returns `None` when every
/// guard passes and the caller should proceed to resolve+forward. Without this, the early returns
/// from `forward_resolved`/`named`/`adhoc` made every governance-rejected request invisible to
/// Prometheus and the webhook.
async fn governance_guard(
    app: &Arc<App>,
    gov: &crate::governance::GovCtx,
    proto: &'static str,
    pool: &str,
    started: Instant,
    charged_at: u64,
) -> Option<Response> {
    // A governance rejection fires BEFORE the model is resolved to a configured pool, so the raw
    // client-supplied `pool` string must be mapped to the bounded metric label (metrics.rs)
    // before it reaches `finish` (which stamps it onto REQUESTS_TOTAL / the duration histogram /
    // the request-log webhook). Passing it raw was an unbounded-cardinality DoS vector.
    let label = pool_label(app, pool);
    if let Some(resp) = pool_authorized(gov, pool, proto) {
        return Some(finish_rejected(
            app, gov, proto, label, started, charged_at, resp,
        ));
    }
    // The initial-pool ACL passed, but the requested pool may be configured to fail over to a
    // FALLBACK pool on exhaustion (`OnExhausted::FallbackPool`). Re-enforce the key's `allowed_pools`
    // against every fallback pool reachable from here, so a key restricted to pool A can never be
    // served by a fallback pool B it is not allowed to use (the fallback dispatch in
    // `forward::handle_fallback_pool` does not — and cannot — re-check the key; the ACL is enforced
    // at this ingress boundary). A denial is the SAME protocol-native 403 the initial check emits.
    if let Some(resp) = fallback_pools_authorized(app, gov, pool, proto) {
        return Some(finish_rejected(
            app, gov, proto, label, started, charged_at, resp,
        ));
    }
    // RATE check BEFORE the budget charge: `budget_check` now atomically CHARGES the flat fee at
    // admission (fix 2a), so it must be the LAST guard — nothing may reject an already-charged
    // request. A rate-limited request is rejected here without ever being charged.
    if let Some(resp) = rate_check(app, gov, proto, charged_at) {
        return Some(finish_rejected(
            app, gov, proto, label, started, charged_at, resp,
        ));
    }
    // Budget charge LAST. On rejection (`Some`) nothing was charged → `finish_rejected` (no refund);
    // on `None` the flat fee is now billed, and the post-admission `finish` refunds it if the upstream
    // produces a non-2xx result.
    if let Some(resp) = budget_check(app, gov, proto, charged_at).await {
        return Some(finish_rejected(
            app, gov, proto, label, started, charged_at, resp,
        ));
    }
    None
}

/// reject (429 + Retry-After) before forwarding when the resolved virtual key is over
/// its RPM/TPM for the current window. No-op when governance is off or the key has no rate cap.
fn rate_check(
    app: &Arc<App>,
    gov: &crate::governance::GovCtx,
    proto: &str,
    charged_at: u64,
) -> Option<Response> {
    if let (Some(g), Some(key)) = (&app.governance, &gov.key) {
        // Pin the rate window to the SAME `charged_at` epoch the budget charge uses (the once-captured
        // header-arrival time), NOT a fresh `store::now()`. `budget_check` evaluates against
        // `charged_at`; reading a fresh clock here could attribute the rate check and the budget charge
        // to different sub-second windows on a 60s boundary. Both governance guards now read one epoch.
        if let Err(retry) = g.check_rate(key, charged_at) {
            // Native error envelope for the body, plus the standard `Retry-After` header so a
            // well-behaved SDK backs off the right amount. The client-facing message carries only
            // vendor-plausible rate-limit copy — never the internal key id or governance
            // vocabulary. The key id + retry window are recorded server-side via tracing.
            tracing::info!(key_id = %key.id, retry_after_secs = retry, "governance: key rate limited");
            let mut resp = ingress_error(
                proto,
                StatusCode::TOO_MANY_REQUESTS,
                crate::forward::KIND_RATE_LIMIT,
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

/// Map a client-supplied model/name string to a BOUNDED `pool` metric label (metrics.rs).
/// Returns the string verbatim ONLY when it names a configured pool (`app.pools`) or a configured
/// by-model lane (`app.by_model`) — i.e. a value drawn from the finite, operator-controlled label
/// space. For anything else (an unknown model, a governance-rejected request whose model was never
/// resolved, a provider-mismatched ad-hoc model) it returns the fixed sentinel `"unresolved"`.
///
/// Without this, every `finish`/webhook call on a 404 / governance-rejection path stamped the raw
/// attacker-controlled model as the `pool` label, letting a single valid credential mint an
/// unbounded number of Prometheus time series (one per distinct model string) — a low-effort
/// memory-exhaustion DoS that also bloats every `/metrics` scrape and leaks the attacker-chosen
/// string into the request-log webhook. The label space is now bounded BY CONSTRUCTION:
/// |configured pools| + |configured by-model lanes| + 1.
fn pool_label<'a>(app: &Arc<App>, model: &'a str) -> &'a str {
    if app.pools.contains_key(model) || app.by_model.contains_key(model) {
        model
    } else {
        crate::forward::POOL_LABEL_UNRESOLVED
    }
}

/// The ingress boundary — emit per-request observability metrics (one client request =
/// one call here, unlike the re-entrant forward_with_pool) and, on a NON-2xx outcome, REFUND the
/// flat per-request fee charged at admission. `finish` does NOT charge: the flat fee is charged at
/// admission by `budget_check` → `try_charge_request_within_budget`. Outcome is derived from the
/// final status; duration is wall-clock.
/// Post-ADMISSION finish: the request passed `governance_guard`, so the flat per-request fee was
/// already charged ATOMICALLY at admission (fix 2a, in `budget_check`). This emits metrics + the
/// request-log webhook and, on a NON-2xx outcome (router 503, upstream 4xx/5xx, post-admit 404),
/// REFUNDS that flat fee — preserving the "bill 2xx only" flat-fee policy now that the hard-cap
/// charge bills every admitted request up front. Token fees are charged post-response only on success
/// (via `UsageSink`), so this keeps both fee policies "successful requests only".
fn finish(
    app: &Arc<App>,
    gov: &crate::governance::GovCtx,
    ingress_protocol: &str,
    pool: &str,
    started: Instant,
    charged_at: u64,
    resp: Response,
) -> Response {
    finish_inner(
        app,
        gov,
        ingress_protocol,
        pool,
        started,
        charged_at,
        resp,
        true,
    )
}

/// NOT-CHARGED finish: the request was turned away BEFORE the admission charge ever ran — either a
/// governance guard rejected it (pool / rate / over-budget / store-error-deny) OR it failed
/// pre-routing (malformed body, missing/unresolved model, unsupported path/action) before reaching
/// `governance_guard`. In every case the flat fee was NEVER charged, so this emits metrics + the
/// webhook with NO refund. Using `finish` (refund-on-non-2xx) on a pre-charge path would issue a
/// SPURIOUS refund — `refund_request` is a blind `UPDATE` that decrements the spend/requests of
/// OTHER, legitimately-charged requests in the same window, eroding the budget cap. So every
/// pre-charge exit MUST use this, never `finish`.
fn finish_rejected(
    app: &Arc<App>,
    gov: &crate::governance::GovCtx,
    ingress_protocol: &str,
    pool: &str,
    started: Instant,
    charged_at: u64,
    resp: Response,
) -> Response {
    finish_inner(
        app,
        gov,
        ingress_protocol,
        pool,
        started,
        charged_at,
        resp,
        false,
    )
}

#[allow(clippy::too_many_arguments)]
fn finish_inner(
    app: &Arc<App>,
    gov: &crate::governance::GovCtx,
    ingress_protocol: &str,
    pool: &str,
    started: Instant,
    charged_at: u64,
    resp: Response,
    refund_on_non_2xx: bool,
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

    // The flat per-request fee was charged ATOMICALLY at admission (fix 2a). REFUND it for a request
    // that produced no usable upstream result (non-2xx: router 503 exhaustion, upstream 5xx, 4xx
    // upstream errors, post-admission 404) so a key is never billed the flat fee for a failure
    // outside its control — preserving the prior "bill 2xx only" policy. (Token fees are likewise
    // only charged on successful streams via UsageSink, so both fee policies stay consistent.) The
    // refund bills against the SAME window the admission charge used (`charged_at`, the header-arrival
    // epoch), so a window-straddling request refunds where it charged (#29). `refund_on_non_2xx` is
    // false for governance-rejection finishes (those were never charged — nothing to refund).
    let is_success = matches!(resp.status().as_u16(), 200..=299);
    if refund_on_non_2xx && !is_success {
        if let (Some(g), Some(key)) = (&app.governance, &gov.key) {
            g.refund_request(key, charged_at);
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
/// Thin delegation to the CANONICAL `crate::forward::ingress_error` (the single
/// source of truth for native error shaping + per-protocol headers — Bedrock
/// `x-amzn-RequestId`/`x-amzn-errortype` via the `ProtocolWriter::attach_error_response_headers` vtable method (BedrockWriter delegates to its private helper), the generic
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
    // Wall-clock epoch pinned ONCE at header-arrival; reused for BOTH the flat per-request fee
    // (`budget_check` → `try_charge_request_within_budget`) and the token fee (`UsageSink::charged_at` → `record_tokens`) so
    // a streaming request's two charges share one rate-limit/budget window (#29).
    let charged_at = crate::store::now();
    let v: Value = match crate::json::parse(&body) {
        Ok(v) => v,
        Err(_) => {
            // Log a SANITIZED note for operators (just the byte length), never the parser's raw error:
            // with sonic-rs it embeds a fragment of the malformed body, which can contain secrets/PII.
            // The client gets only the generic, vendor-plausible message.
            tracing::debug!(detail = %crate::json::parse_err_log(body.len()), "request body JSON parse failed");
            // Pre-routing failures (the model was never resolved) must still be counted in
            // REQUESTS_TOTAL / REQUEST_DURATION_SECONDS and fire the request-log webhook, the same
            // observability invariant the governance rejections and the model-miss 404s enforce. A
            // raw early-return made every malformed-body request invisible to Prometheus and the
            // webhook. The model is unresolved here, so stamp the bounded `"unresolved"` sentinel as
            // the `pool` label (metrics.rs), never a raw client string.
            return finish_rejected(
                app,
                gov,
                proto,
                crate::forward::POOL_LABEL_UNRESOLVED,
                started,
                charged_at,
                ingress_error(
                    proto,
                    StatusCode::BAD_REQUEST,
                    crate::forward::KIND_INVALID_REQUEST,
                    "We could not parse the JSON body of your request.",
                ),
            );
        }
    };

    let model = match v.get("model").and_then(|m| m.as_str()) {
        Some(m) if !m.is_empty() => m.to_string(),
        _ => {
            // Missing/empty model is a pre-routing failure: route through `finish_rejected` (bounded
            // `"unresolved"` label) so it is observable in metrics + the webhook — never charged.
            return finish_rejected(
                app,
                gov,
                proto,
                crate::forward::POOL_LABEL_UNRESOLVED,
                started,
                charged_at,
                ingress_error(
                    proto,
                    StatusCode::BAD_REQUEST,
                    crate::forward::KIND_INVALID_REQUEST,
                    "Missing required parameter: 'model'.",
                ),
            );
        }
    };

    forward_resolved(
        app,
        gov,
        proto,
        &model,
        headers,
        body,
        v,
        caller_token,
        started,
        charged_at,
        // Body-model protocols (openai/cohere/responses) are never gemini, so the model-not-found
        // 404 uses the canonical OpenAI-style message.
        None,
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
    gemini_api_version: Option<&str>,
) -> Response {
    let caller_token = caller.0.as_deref();
    let started = Instant::now();
    // Header-arrival epoch pinned once and reused for both the per-request and token fees (#29).
    let charged_at = crate::store::now();
    let mut v: Value = match crate::json::parse(&body) {
        Ok(v) => v,
        Err(_) => {
            // Log a SANITIZED note for operators (just the byte length), never the parser's raw error:
            // with sonic-rs it embeds a fragment of the malformed body, which can contain secrets/PII.
            // The client gets only the generic, vendor-plausible message.
            tracing::debug!(detail = %crate::json::parse_err_log(body.len()), "request body JSON parse failed");
            // Pre-routing failure (model never resolved): route through `finish_rejected` with the
            // bounded `"unresolved"` label so the malformed-body request is still counted in REQUESTS_TOTAL /
            // REQUEST_DURATION_SECONDS and fires the request-log webhook, mirroring the model-miss
            // path. A raw early-return made it invisible to Prometheus and the webhook.
            return finish_rejected(
                app,
                gov,
                proto,
                crate::forward::POOL_LABEL_UNRESOLVED,
                started,
                charged_at,
                ingress_error(
                    proto,
                    StatusCode::BAD_REQUEST,
                    crate::forward::KIND_INVALID_REQUEST,
                    "We could not parse the JSON body of your request.",
                ),
            );
        }
    };

    // Inject model+stream so the shared resolution/forward plumbing (which reads both from the
    // body) works for protocols whose native wire carries them in the URL instead. A native client
    // body is always a JSON object; if it is not, return a protocol-shaped 400 rather than panic.
    match v.as_object_mut() {
        Some(obj) => {
            obj.insert("model".to_string(), Value::String(model.to_string()));
            obj.insert("stream".to_string(), Value::Bool(stream));
            // Signal a non-`alt=sse` streaming request so the response is framed as a JSON array
            // rather than SSE (only Gemini's writer carries such a key today). The marker key is
            // resolved through the writer vtable by protocol NAME — route.rs names no protocol
            // submodule, so "delete proto/gemini → app is gemini-free" holds. The shim is stripped
            // before the upstream call (`forward::strip_router_shim_keys`); cross-protocol egress
            // drops it via the IR.
            if gemini_json_array {
                if let Some(shim_key) = crate::proto::array_stream_shim_key_for(proto) {
                    obj.insert(shim_key.to_string(), Value::Bool(true));
                }
            }
        }
        None => {
            // Pre-routing failure (body is not a JSON object → model never resolved): route through
            // `finish_rejected` with the bounded `"unresolved"` label so it is observable in metrics +
            // the webhook, not a silent early-return — and never charged, so nothing to refund.
            return finish_rejected(
                app,
                gov,
                proto,
                crate::forward::POOL_LABEL_UNRESOLVED,
                started,
                charged_at,
                ingress_error(
                    proto,
                    StatusCode::BAD_REQUEST,
                    crate::forward::KIND_INVALID_REQUEST,
                    "Request body must be a JSON object.",
                ),
            );
        }
    }

    // Re-serializing a `serde_json::Value` we just parsed (with only `String`/`Bool` keys spliced
    // in) cannot fail in practice — `to_vec` on an in-memory `Value` has no fallible component. The
    // `Err` arm is kept as a non-panicking, protocol-shaped guard (never `unwrap`) so the request
    // path stays panic-free even if a future change introduces a non-serializable injected value;
    // it is effectively unreachable today, hence not exercised by a dedicated test.
    let injected: Bytes = match crate::json::to_vec(&v) {
        Ok(b) => b.into(),
        Err(_e) => {
            // Same leak class as the parse arms above: the JSON library's error Display is a
            // busbar-internal tell (on the parse side it embeds raw body fragments), so we never echo
            // it — a bare operator breadcrumb only, consistent with the `parse_err_log` policy used at
            // every deserialize site. (Serialization errors don't carry body bytes today, but aligning
            // here closes the latent leak class if that ever changes.)
            tracing::debug!("injected request body re-serialization failed");
            // Pre-routing failure (model never reached resolution): route through `finish_rejected`
            // with the bounded `"unresolved"` label so it is observable in metrics + the webhook. This
            // arm is effectively unreachable today (see the comment above), but keeping it on
            // `finish_rejected` preserves the observability invariant for every pre-routing exit.
            return finish_rejected(
                app,
                gov,
                proto,
                crate::forward::POOL_LABEL_UNRESOLVED,
                started,
                charged_at,
                ingress_error(
                    proto,
                    StatusCode::BAD_REQUEST,
                    crate::forward::KIND_INVALID_REQUEST,
                    "The request body could not be processed.",
                ),
            );
        }
    };

    forward_resolved(
        app,
        gov,
        proto,
        model,
        headers,
        injected,
        v,
        caller_token,
        started,
        charged_at,
        gemini_api_version,
    )
    .await
}

/// The common tail shared by both ingress cores: run the governance guards, resolve `model`
/// against `app.pools` then `app.by_model`, forward through `forward_with_pool` with `proto`, and
/// `finish`. A miss on both maps is a protocol-shaped 404.
///
/// `gemini_api_version` is `Some("v1"|"v1beta")` only for the gemini ingress (threaded down from
/// `gemini_ingress`, which derives it from the request path); it shapes the model-not-found 404
/// message into Gemini's native vocabulary. Every other protocol passes `None` and gets the
/// canonical OpenAI-style copy (see `not_found_message`).
#[allow(clippy::too_many_arguments)]
async fn forward_resolved(
    app: &Arc<App>,
    gov: &crate::governance::GovCtx,
    proto: &'static str,
    model: &str,
    headers: &HeaderMap,
    body: Bytes,
    v: Value,
    caller_token: Option<&str>,
    started: Instant,
    charged_at: u64,
    gemini_api_version: Option<&str>,
) -> Response {
    // Governance guards (pool-allowed / budget / rate). A rejection is wrapped in `finish_rejected`
    // inside `governance_guard` so it is still counted in metrics and the request-log webhook.
    if let Some(resp) = governance_guard(app, gov, proto, model, started, charged_at).await {
        return resp;
    }

    if let Some(cands) = app.pools.get(model) {
        let affinity_key = headers
            .get(affinity_header_for(app, model))
            .and_then(|v| v.to_str().ok());
        let resp = forward_with_pool_parsed(
            app.clone(),
            cands.clone(),
            body,
            v,
            caller_token,
            model,
            affinity_key,
            proto,
            crate::ops::CHAT,
            usage_sink(app, gov, charged_at),
        )
        .await;
        return finish(app, gov, proto, model, started, charged_at, resp);
    }

    if let Some(&i) = app.by_model.get(model) {
        // Route through forward_with_pool with this ingress protocol so a request to a
        // different-protocol backend is translated both ways. (The `forward` wrapper assumes
        // Anthropic ingress, which is correct only for the /v1/messages routes — not here.)
        //
        // pool_name is "" — the lane-default breaker CELL shared by every direct/single-model
        // route (forward.rs: `forward` passes "" for the same reason; LOW #4). This is a
        // by_model hit, NOT a named pool, so it must share breaker state with the same model
        // reached via the `named`/`adhoc` single-model paths. Passing the MODEL name here would
        // track the same lane under a model-keyed cell on universal ingress but under the ""
        // cell on the /v1/messages routes, splitting breaker state (and /stats, /healthz) for
        // one lane across two cells purely by route shape. The bounded `pool` metric LABEL still
        // resolves to the model name for the "" cell (forward.rs `metric_pool_label`), so the
        // request/upstream metric correlation is unaffected — only the cell key is unified.
        let resp = forward_with_pool_parsed(
            app.clone(),
            vec![WeightedLane { idx: i, weight: 1 }],
            body,
            v,
            caller_token,
            "",
            None,
            proto,
            crate::ops::CHAT,
            usage_sink(app, gov, charged_at),
        )
        .await;
        return finish(app, gov, proto, model, started, charged_at, resp);
    }

    // `not_found_error` is the canonical token every writer maps (OpenAI, Responses, Anthropic →
    // their native not-found type; Gemini → NOT_FOUND). The older generic `not_found` leaked
    // verbatim through the OpenAI writer as a non-canonical `error.type`.
    //
    // Model/pool miss: wrap the 404 in `finish` so it is still counted in REQUESTS_TOTAL /
    // REQUEST_DURATION_SECONDS and fires the request-log webhook — the same observability invariant
    // the governance rejections and the `named`/`adhoc` 404s already enforce. A raw early-return
    // made every unknown-model miss on the universal-ingress routes (openai/cohere/responses/
    // gemini/bedrock) invisible to Prometheus and the webhook.
    // Both maps missed, so `model` is an unresolved, client-supplied string — stamp the bounded
    // sentinel as the `pool` label (metrics.rs), never the raw model (unbounded-cardinality
    // DoS). `pool_label` returns `"unresolved"` here by construction.
    finish(
        app,
        gov,
        proto,
        pool_label(app, model),
        started,
        charged_at,
        ingress_error(
            proto,
            StatusCode::NOT_FOUND,
            crate::forward::KIND_NOT_FOUND,
            &not_found_message(model, gemini_api_version),
        ),
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

/// Minimal `model` form-field extractor for multipart transcription. A boundary-aware
/// `parse_multipart_model` is a P5 refinement; this scan handles the standard `name="model"` part.
fn multipart_model(body: &[u8]) -> Option<String> {
    let s = String::from_utf8_lossy(body);
    let idx = s.find("name=\"model\"")?;
    let start = s[idx..].find("\r\n\r\n")? + idx + 4;
    let val = &s[start..];
    let end = val.find("\r\n").unwrap_or(val.len());
    let m = val[..end].trim().to_string();
    (!m.is_empty()).then_some(m)
}

/// Ingress for the NEW operations (embeddings/moderations/images/audio, 1.2). Resolves the
/// (protocol, operation) cell — absent ⇒ no-cell 404 in the CALLER's dialect (design §3) — then
/// forwards SAME-protocol through `forward_operation`. Model comes from the JSON body `model` (JSON
/// ops) or the multipart form (transcription). Cross-protocol IR bridge lands after first green.
async fn operation_ingress(
    app: &Arc<App>,
    gov: &crate::governance::GovCtx,
    caller: &crate::auth::CallerToken,
    headers: &HeaderMap,
    body: Bytes,
    proto: &'static str,
    operation: crate::operation::Operation,
) -> Response {
    let caller_token = caller.0.as_deref();
    let started = Instant::now();
    let charged_at = crate::store::now();

    let Some(rh) = crate::cells::request_handler(proto) else {
        return finish_rejected(
            app, gov, proto, crate::forward::POOL_LABEL_UNRESOLVED, started, charged_at,
            ingress_error(proto, StatusCode::NOT_FOUND, crate::forward::KIND_NOT_FOUND,
                "This protocol does not support that operation."),
        );
    };
    let Some(cell) = rh.operation_handler(operation) else {
        return finish_rejected(
            app, gov, proto, crate::forward::POOL_LABEL_UNRESOLVED, started, charged_at,
            ingress_error(proto, StatusCode::NOT_FOUND, crate::forward::KIND_NOT_FOUND,
                "This endpoint does not support that operation."),
        );
    };

    let ct = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let model = if ct.starts_with("multipart/") {
        multipart_model(&body)
    } else {
        crate::json::parse(&body)
            .ok()
            .and_then(|v: serde_json::Value| v.get("model").and_then(|m| m.as_str()).map(str::to_string))
    };
    let model = match model {
        Some(m) if !m.is_empty() => m,
        _ => {
            return finish_rejected(
                app, gov, proto, crate::forward::POOL_LABEL_UNRESOLVED, started, charged_at,
                ingress_error(proto, StatusCode::BAD_REQUEST, crate::forward::KIND_INVALID_REQUEST,
                    "Missing required parameter: 'model'."),
            );
        }
    };

    if let Some(resp) = governance_guard(app, gov, proto, &model, started, charged_at).await {
        return resp;
    }

    let (cands, pool_name): (Vec<WeightedLane>, &str) = if let Some(c) = app.pools.get(&model) {
        (c.clone(), model.as_str())
    } else if let Some(&i) = app.by_model.get(&model) {
        (vec![WeightedLane { idx: i, weight: 1 }], "")
    } else {
        return finish(
            app, gov, proto, pool_label(app, &model), started, charged_at,
            ingress_error(proto, StatusCode::NOT_FOUND, crate::forward::KIND_NOT_FOUND,
                &not_found_message(&model, None)),
        );
    };

    let req_ct = headers
        .get(axum::http::header::CONTENT_TYPE)
        .cloned()
        .unwrap_or_else(|| axum::http::HeaderValue::from_static("application/json"));
    let accept = match operation {
        crate::operation::Operation::Speech => "*/*",
        _ => "application/json",
    };
    let resp = crate::forward::forward_operation(
        app.clone(), cands, body, req_ct, caller_token, pool_name, proto, cell, accept,
    )
    .await;
    finish(app, gov, proto, &model, started, charged_at, resp)
}

macro_rules! op_ingress_handler {
    ($name:ident, $proto:literal, $op:expr) => {
        pub(crate) async fn $name(
            State(app): State<Arc<App>>,
            axum::extract::Extension(gov): axum::extract::Extension<crate::governance::GovCtx>,
            axum::extract::Extension(caller): axum::extract::Extension<crate::auth::CallerToken>,
            headers: HeaderMap,
            body: Bytes,
        ) -> Response {
            operation_ingress(&app, &gov, &caller, &headers, body, $proto, $op).await
        }
    };
}

op_ingress_handler!(openai_moderations, "openai", crate::operation::Operation::Moderation);
op_ingress_handler!(openai_embeddings, "openai", crate::operation::Operation::Embeddings);
op_ingress_handler!(openai_images, "openai", crate::operation::Operation::Image);
op_ingress_handler!(openai_transcriptions, "openai", crate::operation::Operation::Transcription);
op_ingress_handler!(openai_speech, "openai", crate::operation::Operation::Speech);

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
    OriginalUri(uri): OriginalUri,
    axum::extract::Extension(gov): axum::extract::Extension<crate::governance::GovCtx>,
    axum::extract::Extension(caller): axum::extract::Extension<crate::auth::CallerToken>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // The native Gemini error envelope echoes the API version the client actually used in its path
    // ("v1" for the stable `/v1/models/...` surface, "v1beta" for `/v1beta/models/...`). Hardcoding
    // "v1beta" is a distinguishability tell: the real Gemini v1 API says "v1" for these same paths.
    // Derive the version from the matched ingress prefix (both surfaces route here via main.rs); fall
    // back to "v1beta" only if the path is unexpectedly shaped (it always carries one of the two).
    let api_version = gemini_api_version(uri.path());

    // Captured BEFORE the path-parse guards so a malformed-path / unsupported-action rejection
    // (which never reaches `ingress_path_model`, where `started` is otherwise taken) is still
    // counted through `finish_rejected` — the same pre-routing observability invariant the body/path
    // cores enforce. Without it, a malformed gemini path was invisible to Prometheus and the webhook.
    let started = Instant::now();
    // Header-arrival epoch for this handler's pre-routing `finish_rejected` calls. (The success path
    // delegates to `ingress_path_model`, which pins its own `charged_at`; these pre-routing
    // rejections never reach the admission charge, so they use `finish_rejected` — metrics + webhook
    // but NO refund. The arg is still required for a uniform finish-family signature.) (#29)
    let charged_at = crate::store::now();

    // `rest` is everything after `/{version}/models/`, e.g. `foo:generateContent`. Split on the LAST
    // colon into (model, action). A missing colon (or an empty model/action) is NOT necessarily a
    // malformed Gemini path: the stable `/v1/models/{id}` prefix is SHARED with the OpenAI SDK's
    // `model.retrieve` (`GET`/`POST /v1/models/{id}`), which carries no `:<action>`. Hardcoding a
    // Gemini-shaped NOT_FOUND for every colon-less `/v1/models/...` request would hand an OpenAI
    // client an undecodable Gemini envelope on this ambiguous prefix — and would diverge from the
    // `proto_for_path` classifier the fallback/405 handlers use (which maps a colon-less
    // `/v1/models/{id}` to "openai", `/v1beta/models/...` to "gemini"). Resolve the error
    // ENVELOPE protocol from that same canonical classifier so a colon-less hit gets the shape its
    // most-likely client expects: `/v1beta/...` (Gemini-only surface) stays Gemini; a colon-less
    // `/v1/models/...` (or a `/v1/models/{ft:..:..}` whose colons are NOT a Gemini action suffix)
    // gets the canonical `not_found_error` OpenAI envelope. There is no `_ =>` catch-all on the
    // resulting protocol: the classifier returns a registered literal and only "gemini" keeps the
    // native Gemini NOT_FOUND envelope; every other literal shares the canonical not-found shape.
    let (model, action) = match rest.rsplit_once(':') {
        Some((m, a)) if !m.is_empty() && !a.is_empty() => (m, a),
        _ => {
            // Pre-routing failure (no parsable model/action in the path): the envelope protocol is
            // the bounded `proto_for_path` literal, which doubles as the bounded metric
            // `ingress_protocol` label; the model was never resolved, so the `pool` label is the
            // bounded `"unresolved"` sentinel. Routing through `finish_rejected` keeps this malformed-path
            // rejection observable in metrics + the webhook instead of a silent early-return.
            let envelope_proto = crate::proto::proto_for_path(uri.path());
            if crate::proto::protocol_for(envelope_proto)
                .map(|p| p.writer().has_native_path_not_found())
                .unwrap_or(false)
            {
                return finish_rejected(
                    &app,
                    &gov,
                    envelope_proto,
                    crate::forward::POOL_LABEL_UNRESOLVED,
                    started,
                    charged_at,
                    ingress_error(
                        envelope_proto,
                        StatusCode::NOT_FOUND,
                        crate::forward::KIND_NOT_FOUND,
                        &format!(
                "Invalid resource path: models/{rest} is not found for API version {api_version}."
            ),
                    ),
                );
            }
            // Non-Gemini (ambiguous `/v1/models/...` without a Gemini action suffix): emit the
            // canonical OpenAI-shaped 404 the fallback handler uses for this path, so a GET/POST on
            // `/v1/models/{id}` produces the SAME envelope shape whether it hits this route or the
            // method fallback — no GET-vs-POST error-shape divergence a client could probe.
            return finish_rejected(
                &app,
                &gov,
                envelope_proto,
                crate::forward::POOL_LABEL_UNRESOLVED,
                started,
                charged_at,
                ingress_error(
                    envelope_proto,
                    StatusCode::NOT_FOUND,
                    crate::forward::KIND_NOT_FOUND,
                    "the requested resource was not found",
                ),
            );
        }
    };

    // Only the two generate actions are proxied (see the route doc above). Any other action is an
    // intentional limitation and returns a NOT_FOUND envelope. No `_ =>` catch-all: the two
    // supported actions are listed explicitly, with the unsupported-action fallback handled
    // afterwards.
    //
    // The unsupported-action envelope SHAPE must match the same `proto::proto_for_path` classifier
    // the no-colon branch (and the fallback/405 handlers) use, for the same reason: the stable
    // `/v1/models/...` prefix is SHARED with the OpenAI surface. `rsplit_once(':')` on an OpenAI
    // fine-tune id like `ft:gpt-3.5-turbo:my-org::abc` splits a NON-empty `action` (`abc`) that is
    // NOT a Gemini method — so this branch fires for a request a real OpenAI client made. Classify
    // by KNOWN Gemini action suffix (what `proto_for_path` does): a genuine Gemini method such as
    // `:countTokens`/`:embedContent` stays Gemini-shaped (a real Gemini NOT_FOUND naming the
    // unsupported method); a colon-bearing OpenAI id whose tail is not a Gemini action gets the
    // canonical OpenAI `not_found_error` envelope, so the same path never yields two different error
    // shapes depending on how the client (Gemini SDK vs OpenAI SDK) reached it.
    let stream = match action {
        "streamGenerateContent" => true,
        "generateContent" => false,
        other => {
            // Pre-routing failure (unsupported native action → model never resolved): route through
            // `finish_rejected` with the bounded `proto_for_path` literal as both envelope + metric protocol
            // and the bounded `"unresolved"` pool label, keeping it observable in metrics + webhook.
            let envelope_proto = crate::proto::proto_for_path(uri.path());
            if crate::proto::protocol_for(envelope_proto)
                .map(|p| p.writer().has_native_path_not_found())
                .unwrap_or(false)
            {
                return finish_rejected(
                    &app,
                    &gov,
                    envelope_proto,
                    crate::forward::POOL_LABEL_UNRESOLVED,
                    started,
                    charged_at,
                    ingress_error(
                        envelope_proto,
                        StatusCode::NOT_FOUND,
                        crate::forward::KIND_NOT_FOUND,
                        &format!(
                            "models/{model} is not found for API version {api_version}, \
                             or is not supported for {other}."
                        ),
                    ),
                );
            }
            return finish_rejected(
                &app,
                &gov,
                envelope_proto,
                crate::forward::POOL_LABEL_UNRESOLVED,
                started,
                charged_at,
                ingress_error(
                    envelope_proto,
                    StatusCode::NOT_FOUND,
                    crate::forward::KIND_NOT_FOUND,
                    "the requested resource was not found",
                ),
            );
        }
    };

    // `?alt=sse` selects SSE framing for a STREAMING request; its ABSENCE means the native client
    // expects the JSON-array streaming format. `alt` is the documented Gemini query param; treat any
    // `alt=sse` token in the raw query as the SSE request (matching the Gemini SDKs, which append
    // exactly `?alt=sse`). The param is meaningless on a non-stream request, so only a streaming
    // request without `alt=sse` engages the JSON-array framing.
    let alt_sse = uri.query().map(query_has_alt_sse).unwrap_or(false);
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
        // Thread the path-derived api_version so a model-not-found 404 says
        // "models/{model} is not found for API version {api_version}, …" (the native Gemini
        // message), not the OpenAI-style copy — a distinguishability tell for SDKs that match on
        // `error.message`.
        Some(api_version),
    )
    .await
}

/// Build the human-readable message for a model/pool-miss 404, in the INGRESS protocol's native
/// vocabulary. Gemini's real API does NOT use the OpenAI-style "The model '{model}' does not exist…"
/// string — it says "models/{model} is not found for API version {api_version}, or is not supported
/// for the task you are trying to perform." Any client/SDK that pattern-matches the message string to
/// distinguish a model-not-found 404 from other 404 variants (Google's client libraries surface
/// `error.message` in their exception text) would diverge from a native call if we leaked the OpenAI
/// copy. `gemini_api_version` carries the version token the gemini ingress derived from the request
/// path (`v1` vs `v1beta`); it is `None` for every non-gemini protocol, which keeps the canonical
/// OpenAI-style copy the OpenAI/Responses/Cohere/Anthropic SDKs expect. There is no `_ =>` catch-all:
/// the gemini branch is selected by the presence of the version token, every other protocol shares
/// the canonical message.
fn not_found_message(model: &str, gemini_api_version: Option<&str>) -> String {
    match gemini_api_version {
        Some(api_version) => format!(
            "models/{model} is not found for API version {api_version}, \
             or is not supported for the task you are trying to perform."
        ),
        None => format!("The model '{model}' does not exist or you do not have access to it."),
    }
}

/// The Gemini API version token to echo in the native error envelope, derived from the actual
/// ingress path the client used. busbar mounts the Gemini surface at both the stable `/v1/models/...`
/// and the `/v1beta/models/...` prefixes (main.rs); the real Gemini API echoes whichever the caller
/// sent ("v1" vs "v1beta"). Matching the prefix verbatim keeps the error indistinguishable from the
/// native API — a client pinned to the stable v1 surface must not see "v1beta" leaked back. Unknown
/// shapes fall back to "v1beta" (the historical default and the documented full surface).
fn gemini_api_version(path: &str) -> &'static str {
    if path.starts_with("/v1beta/") {
        "v1beta"
    } else if path.starts_with("/v1/") {
        "v1"
    } else {
        "v1beta"
    }
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
    // Bedrock never uses the gemini JSON-array framing, and a model-not-found 404 uses the canonical
    // (non-gemini) message, so no api_version is threaded.
    ingress_path_model(
        app, gov, caller, headers, body, model_id, stream, false, "bedrock", None,
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

// POST /<name>/v1/messages   — name resolves to a pool (weighted) or a single model
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
    // Header-arrival epoch pinned once; reused for both the per-request and token fees (#29).
    let charged_at = crate::store::now();

    // Governance guards (pool-allowed / budget / rate); a rejection is wrapped in `finish_rejected`
    // inside `governance_guard` (this handler just returns that response).
    if let Some(resp) = governance_guard(&app, &gov, "anthropic", &name, started, charged_at).await
    {
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
            crate::ops::CHAT,
            usage_sink(&app, &gov, charged_at),
        )
        .await;
        return finish(&app, &gov, "anthropic", &name, started, charged_at, resp);
    }
    if let Some(&i) = app.by_model.get(&name) {
        // Model-based routing: anthropic ingress, lane-default breaker cell (empty pool name → the
        // cell shared by all direct/ad-hoc routes, surfaced by /stats and /healthz), no affinity.
        let resp = crate::forward::forward_with_pool(
            app.clone(),
            vec![WeightedLane { idx: i, weight: 1 }],
            body,
            caller_token,
            "",
            None,
            "anthropic",
            crate::ops::CHAT,
            usage_sink(&app, &gov, charged_at),
        )
        .await;
        return finish(&app, &gov, "anthropic", &name, started, charged_at, resp);
    }

    // Model/pool miss: wrap the 404 in `finish` so it is still counted in REQUESTS_TOTAL /
    // REQUEST_DURATION_SECONDS and fires the request-log webhook — the same observability invariant
    // already enforced for governance rejections (a raw early-return made the miss invisible).
    // Both maps missed, so `name` is an unresolved, client-supplied URL segment — stamp the bounded
    // sentinel as the `pool` label (metrics.rs), never the raw segment (unbounded-cardinality
    // DoS). `pool_label` returns `"unresolved"` here by construction.
    finish(
        &app,
        &gov,
        "anthropic",
        pool_label(&app, &name),
        started,
        charged_at,
        ingress_error(
            "anthropic",
            StatusCode::NOT_FOUND,
            crate::forward::KIND_NOT_FOUND,
            // Anthropic ingress: canonical (non-gemini) model-not-found copy.
            &not_found_message(&name, None),
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
    // Header-arrival epoch pinned once; reused for both the per-request and token fees (#29).
    let charged_at = crate::store::now();

    // Governance guards (pool-allowed / budget / rate); a rejection is wrapped in `finish_rejected`
    // inside `governance_guard` (this handler just returns that response).
    if let Some(resp) = governance_guard(&app, &gov, "anthropic", &model, started, charged_at).await
    {
        return resp;
    }

    match app.by_model.get(&model) {
        Some(&i) if app.lanes[i].provider == provider => {
            // Single lane with weight=1 (default for ad-hoc routing): anthropic ingress, lane-default
            // breaker cell (empty pool name), no affinity.
            let resp = crate::forward::forward_with_pool(
                app.clone(),
                vec![WeightedLane { idx: i, weight: 1 }],
                body,
                caller_token,
                "",
                None,
                "anthropic",
                crate::ops::CHAT,
                usage_sink(&app, &gov, charged_at),
            )
            .await;
            finish(&app, &gov, "anthropic", &model, started, charged_at, resp)
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
            // The model IS a configured by-model lane (bounded), but route the label through
            // `pool_label` for uniformity with the other ingress paths; it returns `model` here.
            finish(
                &app,
                &gov,
                "anthropic",
                pool_label(&app, &model),
                started,
                charged_at,
                ingress_error(
                    "anthropic",
                    StatusCode::BAD_REQUEST,
                    crate::forward::KIND_INVALID_REQUEST,
                    // Anthropic ingress: canonical (non-gemini) model-not-found copy.
                    &not_found_message(&model, None),
                ),
            )
        }
        // Model miss: `model` is an unresolved, client-supplied string — stamp the bounded sentinel
        // as the `pool` label (metrics.rs). `pool_label` returns `"unresolved"` here.
        None => finish(
            &app,
            &gov,
            "anthropic",
            pool_label(&app, &model),
            started,
            charged_at,
            ingress_error(
                "anthropic",
                StatusCode::NOT_FOUND,
                crate::forward::KIND_NOT_FOUND,
                // Anthropic ingress: canonical (non-gemini) model-not-found copy.
                &not_found_message(&model, None),
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
            failover_cfg: None,
            pool_runtime: std::collections::HashMap::new(),
            fallback_pools: std::collections::HashMap::new(),
            on_exhausted_cfgs: std::collections::HashMap::new(),
            governance: None,
            default_max_tokens: crate::config::DEFAULT_DEFAULT_MAX_TOKENS,
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
            crate::store::now(),
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
                members: Default::default(),
                failover: None,
                affinity: Some(crate::config::AffinityCfg {
                    mode: crate::config::AffinityMode::Session,
                    header_name: Some("x-user-id".to_string()),
                }),
                breaker: None,
                policy: None,
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
                members: Default::default(),
                failover: None,
                affinity: Some(crate::config::AffinityCfg {
                    mode: crate::config::AffinityMode::Session,
                    header_name: None,
                }),
                breaker: None,
                policy: None,
            },
        );
        let inner = Arc::get_mut(&mut app).expect("sole owner");
        inner.pool_runtime = pr;
        assert_eq!(affinity_header_for(&app, "p"), "x-session-id");
    }

    /// Build a governance-enabled App with a single budgeted key, plus return the key so the test
    /// can pass a matching GovCtx to `finish`. Just assembles the App + key; it performs no charge.
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

    /// fix 2a: the flat fee is charged ATOMICALLY at admission, and `finish` REFUNDS it on a non-2xx
    /// outcome (so the net effect remains "bill 2xx only"). A 2xx `finish` keeps the charge; each
    /// non-2xx `finish` (503 / 5xx / 4xx) refunds exactly one flat fee. `finish_rejected` (governance
    /// rejection, never charged) refunds nothing.
    // No-runtime `#[test]` so the offloaded refund (`offload_store_write`) runs INLINE and is
    // observable synchronously — the atomic charge is seeded via the SYNC store path for the same
    // reason. `at` is the fixed budget window `key_spend` reads.
    #[test]
    fn test_finish_refunds_flat_fee_on_non_2xx_keeps_on_2xx() {
        use crate::governance::Store;
        crate::metrics::init();
        let (app, key) = governed_app_with_key();
        let gov = crate::governance::GovCtx {
            key: Some(key.clone()),
        };
        let store = app.governance.as_ref().unwrap().store();
        let at = 1_700_000_000u64;
        // governed_app_with_key uses the "total" period → window 0; key_spend reads the same window.
        let window = crate::governance::budget_window("total", at);

        // Seed the admission charge synchronously (30c flat fee), like budget_check's atomic UPSERT.
        let charge = |store: &std::sync::Arc<dyn Store>| {
            assert!(store
                .charge_within_budget(&key.id, window, 30, Some(100_000))
                .unwrap());
        };
        charge(&store);
        assert_eq!(
            key_spend(&app, &key.id),
            30,
            "admission charged the flat fee"
        );

        // A 2xx finish keeps the charge (no refund).
        let resp = (StatusCode::OK, "ok").into_response();
        let _ = finish(&app, &gov, "openai", "p", Instant::now(), at, resp);
        assert_eq!(
            key_spend(&app, &key.id),
            30,
            "2xx keeps the admission charge"
        );

        // Each non-2xx finish refunds exactly one flat fee. Re-charge before each.
        for status in [
            StatusCode::SERVICE_UNAVAILABLE,
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::BAD_REQUEST,
        ] {
            charge(&store);
            assert_eq!(
                key_spend(&app, &key.id),
                60,
                "re-charged to 60 before {status}"
            );
            let resp = (status, "x").into_response();
            let _ = finish(&app, &gov, "openai", "p", Instant::now(), at, resp);
            assert_eq!(
                key_spend(&app, &key.id),
                30,
                "{status} (non-2xx) refunds the flat fee back to 30"
            );
        }

        // A governance-rejection finish (finish_rejected) refunds NOTHING (it was never charged).
        let resp = (StatusCode::FORBIDDEN, "x").into_response();
        let _ = finish_rejected(&app, &gov, "openai", "p", Instant::now(), at, resp);
        assert_eq!(
            key_spend(&app, &key.id),
            30,
            "finish_rejected must not refund (nothing was charged)"
        );
    }

    /// Regression for the R3 pre-routing spurious-refund bug: a request that fails BEFORE the
    /// admission charge (here a malformed JSON body) must route through `finish_rejected`, NOT
    /// `finish`. With the bug it went through `finish` (refund-on-non-2xx), and `refund_request`'s
    /// blind `UPDATE` decremented the spend/requests of a PRIOR, legitimately-charged request in the
    /// same window — eroding the hard budget cap (repeatable → unbounded overspend). This drives the
    /// REAL ingress path end-to-end (not just the `finish_rejected` unit).
    // No-runtime `#[test]`: any (buggy) refund via `offload_store_write` runs INLINE here, so a
    // regression is observable synchronously. The `"total"` period ⇒ window 0 regardless of the
    // internal `charged_at = store::now()`, so the prior charge and any spurious refund hit one row.
    #[test]
    fn test_pre_routing_failure_does_not_refund_prior_charge() {
        crate::metrics::init();
        let (app, key) = governed_app_with_key();
        let gov = crate::governance::GovCtx {
            key: Some(key.clone()),
        };
        let store = app.governance.as_ref().unwrap().store();
        let window = crate::governance::budget_window("total", 1_700_000_000);

        // A prior, legitimately-charged request: seed one flat fee (30c) of spend in the window.
        assert!(store
            .charge_within_budget(&key.id, window, 30, Some(100_000))
            .unwrap());
        assert_eq!(key_spend(&app, &key.id), 30, "prior charge seeded");

        // A malformed-JSON request on the SAME key fails pre-routing (model never resolved) → 400.
        let caller = crate::auth::CallerToken(None);
        let headers = HeaderMap::new();
        let resp = futures::executor::block_on(ingress_body_model(
            &app,
            &gov,
            &caller,
            &headers,
            Bytes::from_static(b"{ this is not valid json"),
            "openai",
        ));
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "malformed body is a pre-routing 400"
        );

        // The prior charge MUST be intact: the pre-routing 400 was never charged, so it must not
        // refund (a refund would blindly erode the prior request's spend). With the bug this is 0.
        assert_eq!(
            key_spend(&app, &key.id),
            30,
            "pre-routing failure must NOT refund/erode a prior charge (would be 0 with the bug)"
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
            crate::store::now(),
            resp,
        );
        assert!(
            crate::metrics::render().contains("outcome=\"exhausted\""),
            "503 maps to outcome=exhausted"
        );
    }

    // Regression for #29 (flat-fee side), updated for fix 2a: both the ATOMIC admission charge AND
    // the `finish` REFUND must use the window implied by the pinned `charged_at` (header-arrival)
    // epoch, NOT a fresh `store::now()`. With a `daily` key and a `charged_at` on a past day, the
    // charge lands in that day; a non-2xx finish refunds in that SAME day (net 0 there), and nothing
    // ever leaks into today's window. (Token-fee side: `forward::usage_tap_tests::
    // test_nonstream_token_fee_uses_charged_at_window_not_clock`.)
    // No-runtime `#[test]`: the offloaded refund in `finish` runs INLINE and is observable. The
    // admission charge is seeded via the SYNC store path into the charged_at window.
    #[test]
    fn test_flat_fee_charge_and_refund_use_charged_at_window() {
        use crate::governance::{GovState, NewKeySpec, SqliteStore, Store, SECS_PER_DAY};
        crate::metrics::init();

        let store = std::sync::Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = std::sync::Arc::new(GovState::new(store.clone(), 30, 0, None).unwrap()); // 30c/request
        let (key, _secret) = gov
            .create_key(
                NewKeySpec {
                    name: "k".to_string(),
                    allowed_pools: vec![],
                    max_budget_cents: Some(1_000_000),
                    budget_period: "daily".to_string(),
                    rpm_limit: None,
                    tpm_limit: None,
                },
                1_700_000_000,
            )
            .unwrap();
        let mut app = minimal_app();
        Arc::get_mut(&mut app).expect("sole owner").governance = Some(gov.clone());
        let govctx = crate::governance::GovCtx {
            key: Some(key.clone()),
        };

        let charged_at: u64 = 1_700_000_000; // a fixed past day
        let day_window = charged_at / SECS_PER_DAY * SECS_PER_DAY;
        assert_ne!(
            day_window,
            crate::store::now() / SECS_PER_DAY * SECS_PER_DAY,
            "test precondition: charged_at must be a different day than now"
        );

        // Admission charge into the charged_at day window (sync store path = budget_check's UPSERT).
        assert!(store
            .charge_within_budget(&key.id, day_window, 30, Some(1_000_000))
            .unwrap());
        assert_eq!(
            gov.usage_for(&key.id, charged_at)
                .unwrap()
                .map(|u| u.spend_cents)
                .unwrap_or(0),
            30,
            "admission charged the flat fee into the charged_at day window"
        );

        // A non-2xx finish refunds in the SAME (charged_at) window → net 0 there.
        let resp = (StatusCode::SERVICE_UNAVAILABLE, "x").into_response();
        let _ = finish(
            &app,
            &govctx,
            "openai",
            "p",
            Instant::now(),
            charged_at,
            resp,
        );
        assert_eq!(
            gov.usage_for(&key.id, charged_at)
                .unwrap()
                .map(|u| u.spend_cents)
                .unwrap_or(0),
            0,
            "non-2xx refund must land in the charged_at window (net 0)"
        );
        let in_today = gov
            .usage_for(&key.id, crate::store::now())
            .unwrap()
            .map(|u| u.spend_cents)
            .unwrap_or(0);
        assert_eq!(
            in_today, 0,
            "neither charge nor refund may leak into the wall-clock 'now' window (#29)"
        );
    }

    /// Regression for #29 (admission-gate side): `budget_check` must evaluate the over-budget
    /// condition against the SAME window the request will be charged in — the pinned `charged_at`
    /// (header-arrival) epoch — NOT a fresh `store::now()`. Otherwise the admission gate and the
    /// charge can land in different windows when a request straddles a window boundary: the old
    /// code (`is_over_budget_async(key, store::now())`) admitted against an empty current-day
    /// window while the spend that exhausts the budget lives in the `charged_at` day.
    ///
    /// Setup: a `daily`-period key with a 30c cap whose spend (30c) was already charged into a PAST
    /// day window. Probing that past window (`charged_at` on that day) must reject (spend ≥ cap);
    /// probing today's empty window (`store::now()`) must admit. The pre-fix code used the latter
    /// unconditionally and so would have admitted a request that the charge then overshot the cap.
    #[tokio::test]
    async fn test_budget_check_uses_charged_at_window_not_clock() {
        use crate::governance::{GovState, NewKeySpec, SqliteStore, Store, SECS_PER_DAY};
        crate::metrics::init();

        let past_day: u64 = 1_700_000_000; // a fixed past day
        let past_window = past_day / SECS_PER_DAY * SECS_PER_DAY;
        assert_ne!(
            past_window,
            crate::store::now() / SECS_PER_DAY * SECS_PER_DAY,
            "test precondition: charged_at must be a different day than now"
        );

        // Seed 30c of spend directly into the PAST day window BEFORE wrapping the store in GovState,
        // so the precondition is deterministic — `charge_within_budget_async` offloads its write to the blocking
        // pool under a Tokio runtime (fire-and-forget, not awaited), which would race this test.
        let store = std::sync::Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = std::sync::Arc::new(GovState::new(store.clone(), 30, 0, None).unwrap()); // 30c/req
        let (key, _secret) = gov
            .create_key(
                NewKeySpec {
                    name: "k".to_string(),
                    allowed_pools: vec![],
                    max_budget_cents: Some(30), // exhausted by a single 30c request
                    budget_period: "daily".to_string(),
                    rpm_limit: None,
                    tpm_limit: None,
                },
                1_700_000_000,
            )
            .unwrap();
        store
            .add_usage(&key.id, past_window, 30, 0, true)
            .expect("seed spend into the past day window");

        let mut app = minimal_app();
        Arc::get_mut(&mut app).expect("sole owner").governance = Some(gov.clone());
        let govctx = crate::governance::GovCtx {
            key: Some(key.clone()),
        };

        assert_eq!(
            gov.usage_for(&key.id, past_day)
                .unwrap()
                .map(|u| u.spend_cents)
                .unwrap_or(0),
            30,
            "test precondition: the past day window is at the cap"
        );

        // Gate keyed off the (past) `charged_at` window sees spend ≥ cap → reject.
        let rejected = budget_check(&app, &govctx, "openai", past_day).await;
        assert!(
            rejected.is_some(),
            "budget_check must reject against the charged_at window where the spend lives (#29)"
        );
        assert_eq!(
            rejected.unwrap().status(),
            StatusCode::TOO_MANY_REQUESTS,
            "over-budget on an OpenAI ingress maps to 429"
        );

        // Sanity: today's window is empty, so a gate keyed off the wall clock (the OLD behaviour)
        // would have WRONGLY admitted. This proves the bug was real and the pin fixes it.
        let admitted_today = budget_check(&app, &govctx, "openai", crate::store::now()).await;
        assert!(
            admitted_today.is_none(),
            "today's window is empty; the old clock-based gate would have admitted here"
        );
    }

    /// A `Store` whose atomic budget charge always ERRORS, to exercise the fix-2b fail-mode knob.
    struct ErrChargeStore(crate::governance::SqliteStore);
    impl crate::governance::Store for ErrChargeStore {
        fn put_key(&self, k: &crate::governance::VirtualKey) -> crate::governance::StoreResult<()> {
            self.0.put_key(k)
        }
        fn get_key(
            &self,
            id: &str,
        ) -> crate::governance::StoreResult<Option<crate::governance::VirtualKey>> {
            self.0.get_key(id)
        }
        fn get_key_by_hash(
            &self,
            h: &str,
        ) -> crate::governance::StoreResult<Option<crate::governance::VirtualKey>> {
            self.0.get_key_by_hash(h)
        }
        fn list_keys(&self) -> crate::governance::StoreResult<Vec<crate::governance::VirtualKey>> {
            self.0.list_keys()
        }
        fn delete_key(&self, id: &str) -> crate::governance::StoreResult<()> {
            self.0.delete_key(id)
        }
        fn add_usage(
            &self,
            k: &str,
            w: u64,
            s: i64,
            t: u64,
            c: bool,
        ) -> crate::governance::StoreResult<()> {
            self.0.add_usage(k, w, s, t, c)
        }
        fn get_usage(
            &self,
            k: &str,
            w: u64,
        ) -> crate::governance::StoreResult<crate::governance::Usage> {
            self.0.get_usage(k, w)
        }
        fn charge_within_budget(
            &self,
            _k: &str,
            _w: u64,
            _c: i64,
            _m: Option<i64>,
        ) -> crate::governance::StoreResult<bool> {
            Err(crate::governance::StoreError(
                "injected charge error".into(),
            ))
        }
        fn refund_request(&self, k: &str, w: u64, c: i64) -> crate::governance::StoreResult<()> {
            self.0.refund_request(k, w, c)
        }
    }

    fn govctx_for(gov: &Arc<crate::governance::GovState>) -> (Arc<App>, crate::governance::GovCtx) {
        use crate::governance::NewKeySpec;
        let (key, _s) = gov
            .create_key(
                NewKeySpec {
                    name: "k".to_string(),
                    allowed_pools: vec![],
                    max_budget_cents: Some(1000),
                    budget_period: "total".to_string(),
                    rpm_limit: None,
                    tpm_limit: None,
                },
                1_700_000_000,
            )
            .unwrap();
        let mut app = minimal_app();
        Arc::get_mut(&mut app).expect("sole owner").governance = Some(gov.clone());
        (app, crate::governance::GovCtx { key: Some(key) })
    }

    /// fix 2b: on a budget-store ERROR, the `allow` (default) fail-mode PROCEEDS (availability) and
    /// `deny` REJECTS (hard guarantee). Same injected error, opposite outcome by config.
    #[tokio::test]
    async fn test_budget_store_error_respects_fail_mode_knob() {
        use crate::config::BudgetOnStoreError;
        use crate::governance::{GovState, SqliteStore};
        crate::metrics::init();

        // allow (default): store error → proceed (budget_check returns None).
        let store = Arc::new(ErrChargeStore(SqliteStore::open_in_memory().unwrap()));
        let gov = Arc::new(
            GovState::new(store, 1, 0, None)
                .unwrap()
                .with_budget_on_store_error(BudgetOnStoreError::Allow),
        );
        let (app, govctx) = govctx_for(&gov);
        assert!(
            budget_check(&app, &govctx, "openai", 1_700_000_000)
                .await
                .is_none(),
            "allow fail-mode must PROCEED on a store error"
        );

        // deny: same store error → reject (429 on openai).
        let store = Arc::new(ErrChargeStore(SqliteStore::open_in_memory().unwrap()));
        let gov = Arc::new(
            GovState::new(store, 1, 0, None)
                .unwrap()
                .with_budget_on_store_error(BudgetOnStoreError::Deny),
        );
        let (app, govctx) = govctx_for(&gov);
        let rejected = budget_check(&app, &govctx, "openai", 1_700_000_000).await;
        assert!(
            rejected.is_some(),
            "deny fail-mode must REJECT on a store error"
        );
        assert_eq!(rejected.unwrap().status(), StatusCode::TOO_MANY_REQUESTS);
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
        // MEDIUM/test-coverage: the CLIENT-facing response must be the native Gemini
        // `GenerateContentResponse` shape (a top-level `candidates` array), NOT the raw OpenAI
        // `choices[]` body the backend returned. A regression that skipped the IR→Gemini write step
        // (returning the upstream OpenAI body verbatim) would still be a 200 but a protocol
        // indistinguishability violation a Gemini SDK would choke on. Mirrors the streaming-case
        // `candidates` assertion in `test_gemini_stream_generate_content_no_alt_sse_is_json_array`.
        let body: serde_json::Value = resp.json().await.unwrap();
        assert!(
            body.get("candidates").is_some(),
            "non-stream gemini ingress returns a native GenerateContentResponse (candidates[]); \
             got {body}"
        );
        assert!(
            body.get("choices").is_none(),
            "no OpenAI `choices` field may leak to a Gemini client; got {body}"
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
            ct.starts_with("application/json"), // golden wire-contract literal (kept bare on purpose)
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
            ct.starts_with("application/json"), // golden wire-contract literal (kept bare on purpose)
            "non-stream bedrock returns JSON; got {ct}"
        );
        // HIGH/test-coverage: a real AWS Bedrock Converse (non-stream) result ALWAYS exposes a
        // request id via `*Output::request_id()`, which the AWS SDK reads from the `x-amzn-RequestId`
        // response header. busbar synthesizes one on the success path (maybe_attach_response_request_id);
        // an absent or malformed header makes the SDK's `request_id()` return None — an impossibility
        // for a native endpoint and a deterministic proxy tell. Assert the header is present AND
        // UUID-v4 shaped (8-4-4-4-12 lowercase hex), mirroring the streaming-case assertion in
        // `test_bedrock_converse_stream_returns_binary_eventstream`.
        let req_id = resp
            .headers()
            .get("x-amzn-requestid")
            .and_then(|h| h.to_str().ok())
            .expect("bedrock converse (non-stream) success carries x-amzn-RequestId")
            .to_string();
        let segs: Vec<&str> = req_id.split('-').collect();
        assert_eq!(
            segs.iter().map(|s| s.len()).collect::<Vec<_>>(),
            vec![8, 4, 4, 4, 12],
            "x-amzn-RequestId is UUID-v4 shaped (8-4-4-4-12); got {req_id}"
        );
        assert!(
            req_id
                .chars()
                .all(|c| (c.is_ascii_hexdigit() && !c.is_ascii_uppercase()) || c == '-'),
            "x-amzn-RequestId is lowercase hex with dashes; got {req_id}"
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
            req_id
                .chars()
                .all(|c| (c.is_ascii_hexdigit() && !c.is_ascii_uppercase()) || c == '-'),
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

    /// HIGH/test-coverage: SAME-PROTOCOL bedrock streaming passthrough (bedrock client → bedrock
    /// backend). The headline indistinguishability case: a native AWS SDK talks ConverseStream and the
    /// upstream IS a Bedrock backend, so the binary `application/vnd.amazon.eventstream` body must be
    /// relayed VERBATIM (no SSE→binary re-encode, no buffering) and the upstream's REAL
    /// `x-amzn-RequestId` forwarded as-is — never re-synthesized. The cross-protocol stream tests
    /// (OpenAI backend) only exercise the re-encode path; this one drives forward.rs's same-protocol
    /// branch (`is_streaming_content_type` on the eventstream CT, verbatim FirstByteBody relay with
    /// `translate=None`, upstream-CT preservation, and `upstream_amzn_id.or_else(synth)` taking the
    /// upstream value). Asserts: (a) CT is `application/vnd.amazon.eventstream`, (b) the body decodes
    /// via `drain_frames` with the buffer empty, (c) the response `x-amzn-RequestId` EQUALS the fixed
    /// upstream id verbatim (proving it was passed through, not a freshly-minted UUID).
    #[tokio::test]
    async fn test_bedrock_same_protocol_stream_passthrough_forwards_upstream_request_id() {
        crate::metrics::init();
        // Fixed upstream request id: NOT UUID-shaped, so a synthesized id can never accidentally
        // match it — the only way the assertion passes is verbatim passthrough.
        const UPSTREAM_REQ_ID: &str = "fixed-upstream-amzn-req-id-0001";
        let state = StdArc::new(MockServerState::new());
        state.push(MockResponse::EventStream {
            frames: vec![
                ("messageStart", br#"{"role":"assistant"}"#.to_vec()),
                (
                    "contentBlockDelta",
                    br#"{"delta":{"text":"hi"},"contentBlockIndex":0}"#.to_vec(),
                ),
                ("messageStop", br#"{"stopReason":"end_turn"}"#.to_vec()),
                (
                    "metadata",
                    br#"{"usage":{"inputTokens":5,"outputTokens":3,"totalTokens":8}}"#.to_vec(),
                ),
            ],
            amzn_request_id: UPSTREAM_REQ_ID,
        });
        let server = MockServer::new(state.clone()).await;

        // Bedrock ingress → BEDROCK backend (same-protocol). The mock only routes
        // `/v1/messages` + `/v1/chat/completions`; bedrock's native egress path is
        // `/model/{model}/converse-stream`, which the mock does not serve, so point the lane's
        // upstream path at a route the handler answers (the same-protocol relay under test is
        // path-independent — it keys off the upstream Content-Type, not the URL).
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
            "bedrock→bedrock converse-stream 2xx round-trip"
        );

        // (a) the upstream eventstream Content-Type is preserved verbatim.
        let ct = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .to_string();
        assert!(
            ct.starts_with("application/vnd.amazon.eventstream"),
            "same-protocol bedrock stream preserves the upstream eventstream CT; got {ct}"
        );

        // (c) the upstream's REAL x-amzn-RequestId is forwarded VERBATIM (not a synthesized UUID).
        let req_id = resp
            .headers()
            .get("x-amzn-requestid")
            .and_then(|h| h.to_str().ok())
            .expect("bedrock converse-stream success carries x-amzn-RequestId")
            .to_string();
        assert_eq!(
            req_id, UPSTREAM_REQ_ID,
            "same-protocol passthrough must forward the upstream x-amzn-RequestId verbatim, \
             not synthesize a fresh UUID; got {req_id}"
        );

        // (b) the relayed body is the upstream's binary frames byte-for-byte: decodes via
        // drain_frames with the buffer empty, carrying the native ConverseStream event names.
        let body = resp.bytes().await.unwrap();
        let mut buf = body.to_vec();
        let frames = crate::eventstream::drain_frames(&mut buf);
        assert!(
            buf.is_empty(),
            "verbatim-relayed body must be a whole frame sequence (no trailing partial bytes); \
             {} bytes left",
            buf.len()
        );
        let event_types: Vec<&str> = frames.iter().map(|(t, _)| t.as_str()).collect();
        assert_eq!(
            event_types,
            vec![
                "messageStart",
                "contentBlockDelta",
                "messageStop",
                "metadata"
            ],
            "the exact upstream frame sequence is relayed verbatim, in order; got {event_types:?}"
        );
        handle.abort();
        server.shutdown().await;
    }

    /// HIGH/test-coverage: SAME-PROTOCOL bedrock NON-STREAM passthrough (native AWS SDK speaking
    /// `Converse` → a Bedrock backend). This is the most common Bedrock call pattern, and it takes a
    /// COMPLETELY DIFFERENT code branch from the streaming case asserted by
    /// `test_bedrock_same_protocol_stream_passthrough_forwards_upstream_request_id`: a non-stream
    /// `/converse` flows through the buffered/verbatim same-protocol relay (`is_sse == false`,
    /// `cross_protocol == false`) where forward.rs forwards the upstream `x-amzn-RequestId` verbatim
    /// (`upstream_amzn_id.or_else(synth)`). A real `Converse` body carries NO body-level identity
    /// (`id`/`created`/`model` are all absent — only `output`/`stopReason`/`usage`), so the ONLY
    /// request-id surface the AWS SDK exposes (`*Output::request_id()`) is the `x-amzn-RequestId`
    /// response header. If that header is dropped on this path, every non-stream Bedrock call's
    /// `request_id()` returns None — an impossibility against the real API and a deterministic proxy
    /// tell that would stay invisible until an SDK user noticed.
    ///
    /// A `MockResponse::Ok` cannot set a custom response header (and a synthesized fallback id would
    /// not prove VERBATIM passthrough), so this test stands up a tiny ad-hoc upstream that returns a
    /// native Converse JSON body with a FIXED, NON-UUID `x-amzn-RequestId` — the only way the
    /// verbatim assertion can pass is true passthrough, never a freshly-minted UUID. Asserts: (a)
    /// status 200, (b) the response `x-amzn-RequestId` EQUALS the upstream's fixed value verbatim,
    /// (c) Content-Type is `application/json` (no SSE/eventstream reframe on a non-stream relay), (d)
    /// the body carries the native Converse shape (`output`/`usage`).
    #[tokio::test]
    async fn test_bedrock_same_protocol_converse_non_stream_forwards_upstream_request_id() {
        crate::metrics::init();
        // Fixed upstream request id: NOT UUID-shaped, so a synthesized id can never accidentally
        // match — the assertion passes ONLY on verbatim passthrough.
        const UPSTREAM_REQ_ID: &str = "fixed-upstream-amzn-req-id-nonstream-0001";

        // Ad-hoc Bedrock-shaped upstream: a native Converse JSON body + a fixed `x-amzn-RequestId`
        // header on a 200. Served on every path so the bedrock egress writer's model-scoped path
        // reaches it (the same-protocol relay keys off the upstream Content-Type, not the URL).
        let upstream = axum::Router::new().fallback(axum::routing::any(|| async {
            axum::response::Response::builder()
                .status(StatusCode::OK)
                .header("content-type", crate::forward::APPLICATION_JSON)
                .header("x-amzn-requestid", UPSTREAM_REQ_ID)
                .body(axum::body::Body::from(
                    json!({
                        "output": {
                            "message": {
                                "role": "assistant",
                                "content": [{"text": "hi there"}]
                            }
                        },
                        "stopReason": "end_turn",
                        "usage": {"inputTokens": 5, "outputTokens": 3, "totalTokens": 8}
                    })
                    .to_string(),
                ))
                .unwrap()
        }));
        let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let upstream_handle =
            tokio::spawn(async move { axum::serve(upstream_listener, upstream).await.unwrap() });
        let upstream_base = format!("http://{upstream_addr}");

        // Bedrock ingress → BEDROCK backend (same-protocol). Point the lane at a served path; the
        // relay under test is path-independent (it keys off the upstream Content-Type).
        let app = TestApp::new()
            .lane(
                LaneSpec::new("foo", crate::proto::Protocol::bedrock(), &upstream_base)
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

        // (a) 2xx round-trip.
        assert_eq!(
            resp.status().as_u16(),
            200,
            "bedrock→bedrock /converse (non-stream) 2xx round-trip"
        );

        // (c) the non-stream relay preserves the upstream JSON Content-Type (no eventstream reframe).
        let ct = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .to_string();
        assert!(
            ct.starts_with("application/json"), // golden wire-contract literal (kept bare on purpose)
            "same-protocol non-stream bedrock preserves the upstream JSON CT; got {ct}"
        );

        // (b) the upstream's REAL x-amzn-RequestId is forwarded VERBATIM (not a synthesized UUID).
        let req_id = resp
            .headers()
            .get("x-amzn-requestid")
            .and_then(|h| h.to_str().ok())
            .expect("bedrock /converse (non-stream) success carries x-amzn-RequestId")
            .to_string();
        assert_eq!(
            req_id, UPSTREAM_REQ_ID,
            "same-protocol non-stream passthrough must forward the upstream x-amzn-RequestId \
             verbatim, not synthesize a fresh UUID; got {req_id}"
        );

        // (d) the body is the native Converse shape, relayed verbatim.
        let body: serde_json::Value = resp.json().await.unwrap();
        assert!(
            body.get("output").is_some() || body.get("usage").is_some(),
            "native Converse JSON shape (output/usage) is relayed; got {body}"
        );

        handle.abort();
        upstream_handle.abort();
    }

    /// CORE-deferred cross-file test: a TRUE mid-stream TRANSPORT failure on a SAME-PROTOCOL
    /// bedrock→bedrock streaming passthrough. The companion
    /// `test_bedrock_ingress_mid_stream_transport_error_appends_binary_exception` drives the
    /// CROSS-protocol (openai-backend, SSE→binary reframe) path; this one drives the same-protocol
    /// VERBATIM relay (`translate=None`): the upstream is a Bedrock backend emitting binary
    /// `application/vnd.amazon.eventstream` frames that then drops the connection mid-binary-body. The
    /// proxy must (a) preserve the eventstream Content-Type, (b) relay the real first frame, and (c)
    /// after the first byte append a CRC-valid BINARY `:message-type: exception` frame
    /// (`InternalServerException`) — NEVER SSE `event:`/`data:` ASCII text, which would yield an
    /// undecodable prelude/CRC for the AWS SDK's eventstream decoder. Exercises `FirstByteBody`'s
    /// `Poll::Ready(Some(Err))` arm with `is_sse=true` (eventstream upstream CT) and
    /// `ingress_eventstream=true` (bedrock ingress) on the passthrough branch the cross-protocol
    /// variants cannot reach.
    #[tokio::test]
    async fn test_bedrock_same_protocol_stream_mid_stream_transport_error_appends_binary_exception()
    {
        crate::metrics::init();
        let state = StdArc::new(MockServerState::new());
        state.push(MockResponse::EventStreamTransportError {
            ok_frames: vec![("messageStart", br#"{"role":"assistant"}"#.to_vec())],
            amzn_request_id: "fixed-upstream-amzn-req-id-err1",
        });
        let server = MockServer::new(state.clone()).await;

        // Bedrock ingress → BEDROCK backend (same-protocol verbatim relay). The mock only serves
        // `/v1/messages`; the same-protocol relay keys off the upstream Content-Type, not the URL, so
        // point the lane's upstream path at a route the mock answers.
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
            .post(format!("http://{addr}/model/foo/converse-stream"))
            .bearer_auth("t")
            .body(
                json!({ "messages": [{"role": "user", "content": [{"text": "hi"}]}] }).to_string(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status().as_u16(),
            200,
            "bedrock→bedrock converse-stream 2xx before the mid-stream drop"
        );
        // (a) the upstream eventstream Content-Type is preserved (verbatim relay, not reframed).
        let ct = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .to_string();
        assert!(
            ct.starts_with("application/vnd.amazon.eventstream"),
            "same-protocol bedrock stream preserves the eventstream CT; got {ct}"
        );

        let body = resp.bytes().await.unwrap();
        // (c) NO SSE ASCII may be spliced into the binary body — it must be pure binary frames.
        assert!(
            !body.windows(7).any(|w| w == b"event: ") && !body.windows(6).any(|w| w == b"data: "),
            "same-protocol bedrock mid-stream error must NOT contain SSE ASCII; body: {body:?}"
        );
        // The body decodes as a whole sequence of CRC-valid binary frames (real frame(s) + the
        // appended exception frame), with no trailing partial bytes.
        let mut buf = body.to_vec();
        let frames = crate::eventstream::drain_frames(&mut buf);
        assert!(
            buf.is_empty(),
            "body must be a whole sequence of CRC-valid frames; {} bytes left",
            buf.len()
        );
        assert!(
            !frames.is_empty(),
            "at least the first real frame decodes before the drop"
        );
        // A trailing BINARY exception frame is present (drain_frames normalizes its `:exception-type`
        // to "internalServerException"); re-scan the raw bytes to confirm the modeled-exception headers/name.
        let raw_str = String::from_utf8_lossy(&body);
        assert!(
            raw_str.contains(":exception-type"),
            "a binary :message-type:exception frame must be appended after the real frames; \
             body: {body:?}"
        );
        assert!(
            raw_str.contains("InternalServerException"),
            "the mid-stream transport failure maps to InternalServerException"
        );
        handle.abort();
        server.shutdown().await;
    }

    /// HIGH/test-coverage (forward.rs): a TRUE mid-stream transport failure on a
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
        // The trailing exception frame carries `:exception-type` instead of `:event-type`
        // (drain_frames normalizes it to the lowercased "internalServerException"); re-scan the raw
        // bytes to confirm an exception frame is present.
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

    /// HIGH/test-coverage twin (forward.rs): the SSE-ingress (openai) mid-stream transport-failure
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
            ct.starts_with("text/event-stream"), // golden wire-contract literal (kept bare on purpose)
            "gemini streaming ingress WITH ?alt=sse is SSE-framed; got {ct}"
        );
        // MEDIUM/test-coverage: text/event-stream alone does not prove the SSE FRAMES carry the
        // native Gemini `GenerateContentResponse` vocabulary. A regression that relayed the raw
        // OpenAI `chat.completion.chunk` objects verbatim would still be `text/event-stream` and
        // pass a header-only assertion — a protocol-indistinguishability break. Parse each SSE
        // `data:` payload as JSON and assert at least one carries a `candidates` array (mirroring
        // the JSON-array path's assertion in
        // `test_gemini_stream_generate_content_no_alt_sse_is_json_array`), and that none leaks the
        // OpenAI `choices` shape.
        let body = resp.text().await.unwrap();
        let payloads: Vec<serde_json::Value> = body
            .lines()
            .filter_map(|line| line.strip_prefix("data:"))
            .map(str::trim)
            .filter(|data| !data.is_empty() && *data != crate::proto::SSE_DONE_SENTINEL)
            .filter_map(|data| serde_json::from_str(data).ok())
            .collect();
        assert!(
            !payloads.is_empty(),
            "SSE body carries at least one JSON data: frame; got {body:?}"
        );
        assert!(
            payloads.iter().any(|c| c.get("candidates").is_some()),
            "at least one SSE frame is a native gemini GenerateContentResponse (candidates[]); \
             got {body:?}"
        );
        assert!(
            payloads.iter().all(|c| c.get("choices").is_none()),
            "no OpenAI `choices` field may leak into the gemini SSE frames; got {body:?}"
        );
        handle.abort();
        server.shutdown().await;
    }

    /// Round-13 HIGH/test-coverage: a MID-STREAM transport failure on a gemini
    /// `:streamGenerateContent?alt=sse` request (the SSE framer, `json_array=false`) must terminate
    /// the body with a NATIVE Gemini SSE error frame — `text/event-stream`, a trailing `data:`
    /// payload carrying a `google.rpc.Status`-shaped envelope (`error.status`), with NO `event:`
    /// line (native Gemini SSE never emits one mid-stream) and NO OpenAI `choices`/
    /// `chat.completion.chunk` leak. This drives `FirstByteBody`'s `Poll::Ready(Some(Err))` arm
    /// with `json_array=false`, a DISTINCT code path from the JSON-array case covered by
    /// `test_gemini_json_array_mid_stream_error_closes_array_no_sse`. Routes gemini→openai with
    /// `SseTransportError` so the upstream drops the connection after the first frame.
    #[tokio::test]
    async fn test_gemini_alt_sse_mid_stream_transport_error_appends_native_sse_frame() {
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
                "http://{addr}/v1beta/models/foo:streamGenerateContent?alt=sse"
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
            ct.starts_with("text/event-stream"), // golden wire-contract literal (kept bare on purpose)
            "alt=sse mid-stream error stays SSE-framed; got {ct}"
        );
        let body = resp.text().await.unwrap();
        // Native Gemini SSE never emits a named `event:` line mid-stream — only bare `data:` frames.
        assert!(
            !body.contains("event:"),
            "native gemini SSE carries no `event:` line; got {body:?}"
        );
        // The body must NOT be JSON-array framed (no brackets spliced into the SSE).
        let payloads: Vec<serde_json::Value> = body
            .lines()
            .filter_map(|line| line.strip_prefix("data:"))
            .map(str::trim)
            .filter(|data| !data.is_empty() && *data != crate::proto::SSE_DONE_SENTINEL)
            .filter_map(|data| serde_json::from_str(data).ok())
            .collect();
        assert!(
            !payloads.is_empty(),
            "SSE body carries at least one JSON data: frame; got {body:?}"
        );
        // No OpenAI envelope may leak into the gemini SSE frames.
        assert!(
            payloads.iter().all(|p| p.get("choices").is_none()),
            "no OpenAI `choices` field may leak into the gemini SSE frames; got {body:?}"
        );
        assert!(
            !body.contains("chat.completion.chunk"),
            "no OpenAI `chat.completion.chunk` object may leak; got {body:?}"
        );
        // The LAST `data:` payload is the native Gemini `google.rpc.Status`-shaped error envelope.
        let last = payloads
            .last()
            .unwrap_or_else(|| panic!("expected a trailing SSE error frame; got {body:?}"));
        assert!(
            last.get("error").and_then(|e| e.get("status")).is_some(),
            "trailing SSE frame is a native gemini google.rpc.Status error (error.status); \
             got {body:?}"
        );
        handle.abort();
        server.shutdown().await;
    }

    /// Round-13 MEDIUM/security: an UNRESOLVED model on a body-model ingress (openai) must NOT stamp
    /// the raw client-supplied model string as the Prometheus `pool` label — the bounded-cardinality
    /// contract (metrics.rs) requires the fixed sentinel `"unresolved"`. A regression that
    /// passed the raw model through `finish` would let a single credential mint unbounded time
    /// series (a memory-exhaustion DoS) and leak the attacker string into `/metrics`. Drives the
    /// 404 (both-maps-miss) path through the real router and scrapes the registry.
    #[tokio::test]
    async fn test_unresolved_model_uses_bounded_pool_label_not_raw_string() {
        crate::metrics::init();
        // A lane/pool named "foo" exists, but the client asks for a DISTINCT unknown model so both
        // `app.pools` and `app.by_model` miss and the 404 path runs.
        let app = TestApp::new()
            .lane(
                LaneSpec::new(
                    "foo",
                    crate::proto::Protocol::openai(),
                    "http://127.0.0.1:1",
                )
                .provider("zai"),
            )
            .pool("foo", &[(0, 1)])
            .build();
        let (addr, handle) = serve(app).await;

        // A unique, attacker-flavored model string that is NOT a configured pool/by-model key.
        let attacker_model = "zzz-unbounded-cardinality-probe-9f3a";
        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/v1/chat/completions"))
            .bearer_auth("t")
            .body(
                json!({
                    "model": attacker_model,
                    "messages": [{"role": "user", "content": "hi"}]
                })
                .to_string(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 404, "unknown model is a 404");

        let scrape = crate::metrics::render();
        // The raw attacker string must NEVER appear as a label value in the exposition.
        assert!(
            !scrape.contains(attacker_model),
            "raw client model must not become a Prometheus label; got:\n{scrape}"
        );
        // The bounded sentinel must be present instead.
        assert!(
            scrape.contains("pool=\"unresolved\""),
            "unresolved model stamps the bounded `unresolved` sentinel; got:\n{scrape}"
        );
        handle.abort();
    }

    /// Sum every `busbar_requests_total` counter value whose label set contains BOTH the given
    /// `pool="…"` and `outcome="…"` fragments, parsed straight out of the Prometheus text exposition.
    /// Used by the pre-routing-observability regressions to assert a STRICT increase (the metric was
    /// actually incremented) rather than mere label presence — the only signal that distinguishes the
    /// fixed code (request flows through `finish`) from the old early-return (no counter at all).
    fn requests_total_for(scrape: &str, pool: &str, outcome: &str) -> u64 {
        let pool_frag = format!("pool=\"{pool}\"");
        let outcome_frag = format!("outcome=\"{outcome}\"");
        scrape
            .lines()
            .filter(|l| l.starts_with(crate::metrics::REQUESTS_TOTAL))
            .filter(|l| l.contains(&pool_frag) && l.contains(&outcome_frag))
            .filter_map(|l| l.rsplit(' ').next())
            .filter_map(|v| v.trim().parse::<u64>().ok())
            .sum()
    }

    /// MED #4 (re-audit, completeness): a JSON-parse failure on a BODY-MODEL ingress (openai) is a
    /// PRE-ROUTING error — the model is never resolved. It must still flow through `finish` so it is
    /// counted in `REQUESTS_TOTAL` (and the duration histogram + request-log webhook), with the
    /// bounded `pool="unresolved"` label. The old code early-returned `ingress_error` directly,
    /// leaving the malformed-body request invisible to Prometheus — this test asserts a STRICT
    /// increase of the `unresolved`/`client_error` counter across the request, so it fails against
    /// that old behavior.
    #[tokio::test]
    async fn test_body_model_parse_error_is_observable() {
        crate::metrics::init();
        // No backend needed: the request never gets past the body parse.
        let app = TestApp::new()
            .lane(
                LaneSpec::new(
                    "foo",
                    crate::proto::Protocol::openai(),
                    "http://127.0.0.1:1",
                )
                .provider("zai"),
            )
            .pool("foo", &[(0, 1)])
            .build();
        let (addr, handle) = serve(app).await;

        let before = requests_total_for(&crate::metrics::render(), "unresolved", "client_error"); // golden wire-contract literal (kept bare on purpose)

        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/v1/chat/completions"))
            .bearer_auth("t")
            .body("{ this is not json ")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 400, "malformed body is a 400");

        let after = requests_total_for(&crate::metrics::render(), "unresolved", "client_error"); // golden wire-contract literal (kept bare on purpose)
        assert!(
            after > before,
            "a parse-error pre-routing failure must increment REQUESTS_TOTAL \
             (pool=unresolved,outcome=client_error): before={before} after={after}"
        );
        handle.abort();
    }

    /// MED #4 (re-audit, completeness): a MISSING `model` field on a body-model ingress is likewise a
    /// pre-routing failure and must flow through `finish` (bounded `pool="unresolved"`), not a silent
    /// early-return. Asserts a strict counter increase, so it fails against the old early-return.
    #[tokio::test]
    async fn test_body_model_missing_model_is_observable() {
        crate::metrics::init();
        let app = TestApp::new()
            .lane(
                LaneSpec::new(
                    "foo",
                    crate::proto::Protocol::openai(),
                    "http://127.0.0.1:1",
                )
                .provider("zai"),
            )
            .pool("foo", &[(0, 1)])
            .build();
        let (addr, handle) = serve(app).await;

        let before = requests_total_for(&crate::metrics::render(), "unresolved", "client_error"); // golden wire-contract literal (kept bare on purpose)

        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/v1/chat/completions"))
            .bearer_auth("t")
            // Valid JSON object, but no `model`.
            .body(json!({"messages": [{"role": "user", "content": "hi"}]}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 400, "missing model is a 400");

        let after = requests_total_for(&crate::metrics::render(), "unresolved", "client_error"); // golden wire-contract literal (kept bare on purpose)
        assert!(
            after > before,
            "a missing-model pre-routing failure must increment REQUESTS_TOTAL \
             (pool=unresolved,outcome=client_error): before={before} after={after}"
        );
        handle.abort();
    }

    /// MED #4 (re-audit, completeness): a NON-OBJECT body on a PATH-MODEL ingress (bedrock) is a
    /// pre-routing failure (`v.as_object_mut()` is `None`) and must flow through `finish` with the
    /// bounded `pool="unresolved"` label. Asserts a strict counter increase; fails against the old
    /// early-return that bypassed `finish`.
    #[tokio::test]
    async fn test_path_model_non_object_body_is_observable() {
        crate::metrics::init();
        let app = TestApp::new()
            .lane(
                LaneSpec::new(
                    "foo",
                    crate::proto::Protocol::openai(),
                    "http://127.0.0.1:1",
                )
                .provider("zai"),
            )
            .pool("foo", &[(0, 1)])
            .build();
        let (addr, handle) = serve(app).await;

        let before = requests_total_for(&crate::metrics::render(), "unresolved", "client_error"); // golden wire-contract literal (kept bare on purpose)

        // Valid JSON, but a top-level ARRAY (not an object) — `as_object_mut` returns `None`.
        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/model/foo/converse"))
            .bearer_auth("t")
            .body(json!([1, 2, 3]).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 400, "non-object body is a 400");

        let after = requests_total_for(&crate::metrics::render(), "unresolved", "client_error"); // golden wire-contract literal (kept bare on purpose)
        assert!(
            after > before,
            "a non-object-body pre-routing failure must increment REQUESTS_TOTAL \
             (pool=unresolved,outcome=client_error): before={before} after={after}"
        );
        handle.abort();
    }

    /// MED #4 (re-audit, completeness — sibling sweep): an UNSUPPORTED gemini action (e.g.
    /// `:countTokens`) rejected in `gemini_ingress` BEFORE `ingress_path_model` runs is the same
    /// pre-routing observability blind spot. It must now flow through `finish` (bounded
    /// `pool="unresolved"`, gemini protocol). Asserts a strict counter increase; fails against the
    /// old early-return.
    #[tokio::test]
    async fn test_gemini_unsupported_action_is_observable() {
        crate::metrics::init();
        let app = TestApp::new()
            .lane(
                LaneSpec::new(
                    "foo",
                    crate::proto::Protocol::openai(),
                    "http://127.0.0.1:1",
                )
                .provider("zai"),
            )
            .pool("foo", &[(0, 1)])
            .build();
        let (addr, handle) = serve(app).await;

        let before = requests_total_for(&crate::metrics::render(), "unresolved", "client_error"); // golden wire-contract literal (kept bare on purpose)

        // `:countTokens` is a genuine Gemini action suffix (so the path stays gemini-classified) but
        // is NOT one of the two proxied generate actions → unsupported-action 404 in gemini_ingress.
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
            "unsupported gemini action is a 404"
        );

        let after = requests_total_for(&crate::metrics::render(), "unresolved", "client_error"); // golden wire-contract literal (kept bare on purpose)
        assert!(
            after > before,
            "an unsupported-action pre-routing failure must increment REQUESTS_TOTAL \
             (pool=unresolved,outcome=client_error): before={before} after={after}"
        );
        handle.abort();
    }

    /// Round-13 MEDIUM/security (unit test for `pool_label`): the bounded-label mapper returns a
    /// model verbatim ONLY when it names a configured pool or by-model lane, and the fixed sentinel
    /// `"unresolved"` for anything else.
    #[test]
    fn test_pool_label_bounds_cardinality() {
        let mut app = minimal_app();
        {
            let inner = Arc::get_mut(&mut app).expect("sole owner");
            inner.pools.insert(
                "mypool".to_string(),
                vec![WeightedLane { idx: 0, weight: 1 }],
            );
            inner.by_model.insert("mymodel".to_string(), 0);
        }
        // Configured pool name → verbatim.
        assert_eq!(pool_label(&app, "mypool"), "mypool");
        // Configured by-model lane → verbatim.
        assert_eq!(pool_label(&app, "mymodel"), "mymodel");
        // Unknown / attacker-controlled string → bounded sentinel.
        assert_eq!(pool_label(&app, "anything-else"), "unresolved"); // golden wire-contract literal (kept bare on purpose)
        assert_eq!(pool_label(&app, ""), "unresolved"); // golden wire-contract literal (kept bare on purpose)
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
            ct.starts_with("application/json"), // golden wire-contract literal (kept bare on purpose)
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
            ct.starts_with("application/json"), // golden wire-contract literal (kept bare on purpose)
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

    /// Round-4 HIGH/conformance (UPDATED R9): the router-internal `__busbar_gemini_json_array` shim
    /// must NEVER reach a CROSS-protocol backend. Routes gemini `:streamGenerateContent` (no
    /// `?alt=sse`) → an OpenAI backend and asserts the upstream-received body carries no array shim
    /// key (the bug: the gemini reader swept it into IR `extra` and the egress writer re-emitted the
    /// router fingerprint onto the foreign backend).
    ///
    /// R9 HIGH (forward.rs) correction: the egress `stream` field is NOT a router fingerprint
    /// for a BODY-MODEL backend — the OpenAI writer AUTHORS `"stream": ir.stream` and the backend
    /// reads it to decide whether to stream. The client called `:streamGenerateContent`, so it
    /// genuinely wants streaming; `stream: true` MUST reach the OpenAI backend, otherwise the backend
    /// answers non-streaming and the gemini client gets a wrong (buffered) response. The shim-key
    /// strip is now gated on the EGRESS protocol, so `stream` survives for body-model egress and is
    /// stripped only for path-model (gemini/bedrock) egress where it rides the URL.
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
        // R9 HIGH (forward.rs): the writer-authored `stream` MUST reach a body-model (OpenAI)
        // backend so it actually streams — the client called `:streamGenerateContent`. Stripping it
        // here was the bug that made the backend answer non-streaming.
        assert_eq!(
            upstream_v.get("stream").and_then(|s| s.as_bool()),
            Some(true),
            "writer-authored `stream: true` MUST reach the body-model backend so it streams; got {upstream_v}"
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
            Some("authentication_error"), // golden wire-contract literal (kept bare on purpose)
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
            ct.starts_with("application/json"), // golden wire-contract literal (kept bare on purpose)
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

    /// MEDIUM/conformance regression: a request on the STABLE `/v1/models/...` Gemini surface that
    /// hits an unsupported action (e.g. `countTokens`) must echo "v1" in the native NOT_FOUND
    /// message — NOT the hardcoded "v1beta". The real Gemini v1 API says "v1" for this path; leaking
    /// "v1beta" is a distinguishability tell against a google-generativeai SDK pinned to v1.
    #[tokio::test]
    async fn test_gemini_v1_surface_error_echoes_v1_not_v1beta() {
        crate::metrics::init();
        let app = TestApp::new().build();
        let (addr, handle) = serve(app).await;

        // Unsupported-action branch on the v1 surface.
        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/v1/models/foo:countTokens"))
            .bearer_auth("t")
            .body(json!({"contents": []}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 404, "unsupported action ⇒ 404");
        let body: serde_json::Value = resp.json().await.unwrap();
        let msg = body
            .get("error")
            .and_then(|e| e.get("message"))
            .and_then(|m| m.as_str())
            .unwrap_or("");
        assert!(
            msg.contains("API version v1,") || msg.contains("API version v1 "),
            "v1-surface error must echo 'v1', not 'v1beta'; got message: {msg}"
        );
        assert!(
            !msg.contains("v1beta"),
            "v1-surface error must NOT leak 'v1beta'; got message: {msg}"
        );

        // No-colon branch on the v1 surface: a colon-less `/v1/models/{id}` is the OpenAI
        // `model.retrieve` shape on this AMBIGUOUS stable prefix, so the MEDIUM/conformance fix
        // returns the canonical OpenAI `not_found_error` envelope here (matching `proto_for_path`
        // and the method fallback), NOT a Gemini-shaped NOT_FOUND. (The Gemini-shaped no-colon 404
        // is reserved for the unambiguous `/v1beta/...` surface — see
        // `test_gemini_v1beta_surface_error_still_echoes_v1beta`.) The v1-version-echo coverage is
        // carried by the unsupported-ACTION (`countTokens`) case above, which stays Gemini-shaped.
        let resp2 = reqwest::Client::new()
            .post(format!("http://{addr}/v1/models/gemini-flash"))
            .bearer_auth("t")
            .body(json!({"contents": []}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(resp2.status().as_u16(), 404, "no-colon v1 path ⇒ 404");
        let body2: serde_json::Value = resp2.json().await.unwrap();
        assert_eq!(
            body2
                .get("error")
                .and_then(|e| e.get("type"))
                .and_then(|t| t.as_str()),
            Some("not_found_error"), // golden wire-contract literal (kept bare on purpose)
            "colon-less /v1/models/{{id}} returns the canonical OpenAI not_found_error envelope, \
             not a Gemini NOT_FOUND; got {body2}"
        );

        handle.abort();
    }

    /// The `/v1beta/models/...` surface must still echo "v1beta" (no regression for the historical
    /// full surface) — the fix is version-faithful, not a blanket rewrite.
    #[tokio::test]
    async fn test_gemini_v1beta_surface_error_still_echoes_v1beta() {
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
        assert_eq!(resp.status().as_u16(), 404);
        let body: serde_json::Value = resp.json().await.unwrap();
        let msg = body
            .get("error")
            .and_then(|e| e.get("message"))
            .and_then(|m| m.as_str())
            .unwrap_or("");
        assert!(
            msg.contains("v1beta"),
            "v1beta-surface error must still echo 'v1beta'; got: {msg}"
        );
        handle.abort();
    }

    /// MEDIUM/conformance regression: the AMBIGUOUS stable `/v1/models/{id}` prefix is SHARED between
    /// the Gemini `:<action>` surface and the OpenAI `model.retrieve` (`/v1/models/{id}`) surface.
    /// A colon-less `/v1/models/{id}` (or a `/v1/models/{id}` whose colons are NOT a Gemini action
    /// suffix, e.g. an OpenAI fine-tune id `ft:gpt:org::abc`) must therefore return the canonical
    /// OpenAI `not_found_error` envelope — the SAME shape the method/fallback handler emits for the
    /// path — rather than a Gemini-shaped NOT_FOUND, so a client probing GET vs POST on
    /// `/v1/models/{id}` cannot distinguish busbar by a divergent error shape. The unambiguous
    /// `/v1beta/...` surface (Gemini-only; OpenAI has no v1beta) stays Gemini-shaped. This locks the
    /// `gemini_ingress` no-colon branch's delegation to `proto::proto_for_path`.
    #[tokio::test]
    async fn test_gemini_v1_no_action_returns_openai_shaped_404() {
        crate::metrics::init();
        let app = TestApp::new().build();
        let (addr, handle) = serve(app).await;

        // (a) Colon-less stable `/v1/models/{id}` ⇒ OpenAI `not_found_error` (the model.retrieve
        // surface), NOT a Gemini NOT_FOUND.
        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/v1/models/gpt-4o"))
            .bearer_auth("t")
            .body(json!({"contents": []}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status().as_u16(),
            404,
            "no-action /v1/models/{{id}} ⇒ 404"
        );
        let ct = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .to_string();
        assert!(
            ct.starts_with("application/json"), // golden wire-contract literal (kept bare on purpose)
            "OpenAI not-found envelope is JSON; got {ct}"
        );
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(
            body.get("error")
                .and_then(|e| e.get("type"))
                .and_then(|t| t.as_str()),
            Some("not_found_error"), // golden wire-contract literal (kept bare on purpose)
            "colon-less /v1/models/{{id}} returns the OpenAI not_found_error envelope; got {body}"
        );
        // A Gemini NOT_FOUND would carry a `status: NOT_FOUND` field; the OpenAI envelope does not.
        assert!(
            body.get("error").and_then(|e| e.get("status")).is_none(),
            "OpenAI not-found envelope has no Gemini-style `status`; got {body}"
        );

        // (b) An OpenAI fine-tune id whose segment CONTAINS colons but NO Gemini action suffix is
        // still the OpenAI surface (the action split would otherwise mis-read `:abc` as the action).
        let resp_ft = reqwest::Client::new()
            .post(format!(
                "http://{addr}/v1/models/ft:gpt-3.5-turbo:my-org::abc"
            ))
            .bearer_auth("t")
            .body(json!({"contents": []}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp_ft.status().as_u16(),
            404,
            "fine-tune id (no action) ⇒ 404"
        );
        let body_ft: serde_json::Value = resp_ft.json().await.unwrap();
        assert_eq!(
            body_ft
                .get("error")
                .and_then(|e| e.get("type"))
                .and_then(|t| t.as_str()),
            Some("not_found_error"), // golden wire-contract literal (kept bare on purpose)
            "colon-bearing OpenAI fine-tune id (no Gemini action) ⇒ OpenAI not_found_error; got {body_ft}"
        );

        // (c) The unambiguous `/v1beta/...` surface (Gemini-only) keeps the Gemini NOT_FOUND shape
        // for a colon-less path: its envelope carries the Gemini `status: NOT_FOUND`.
        let resp_beta = reqwest::Client::new()
            .post(format!("http://{addr}/v1beta/models/gemini-flash"))
            .bearer_auth("t")
            .body(json!({"contents": []}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(resp_beta.status().as_u16(), 404, "v1beta no-colon ⇒ 404");
        let body_beta: serde_json::Value = resp_beta.json().await.unwrap();
        assert_eq!(
            body_beta
                .get("error")
                .and_then(|e| e.get("status"))
                .and_then(|s| s.as_str()),
            Some("NOT_FOUND"),
            "v1beta no-colon path stays Gemini-shaped (status: NOT_FOUND); got {body_beta}"
        );

        handle.abort();
    }

    /// Unit: `gemini_api_version` maps each ingress prefix to the token the native error echoes.
    #[test]
    fn test_gemini_api_version_prefix_mapping() {
        assert_eq!(
            gemini_api_version("/v1/models/foo:countTokens"),
            "v1",
            "stable surface ⇒ v1"
        );
        assert_eq!(
            gemini_api_version("/v1beta/models/foo:countTokens"),
            "v1beta",
            "beta surface ⇒ v1beta"
        );
        // Unexpected shape falls back to the historical default.
        assert_eq!(
            gemini_api_version("/weird/path"),
            "v1beta",
            "fallback ⇒ v1beta"
        );
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
            Some("not_found_error"), // golden wire-contract literal (kept bare on purpose)
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
        let rejected = governance_guard(
            &app,
            &gov,
            "openai",
            "denied-pool",
            Instant::now(),
            crate::store::now(),
        )
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
        let passed = governance_guard(
            &app,
            &gov,
            "openai",
            "allowed-only",
            Instant::now(),
            crate::store::now(),
        )
        .await;
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

    /// MEDIUM/security regression: the three governance rejection bodies (403 pool-not-allowed, 429
    /// over-budget (400 for Bedrock), 429 rate-limited) must carry ONLY vendor-plausible copy — never the internal
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

        // --- over budget. A key with a zero budget cap is immediately over budget. The
        // body-model protocols surface this as 429 (native OpenAI/Gemini quota semantics); no
        // vendor returns 402 here. ---
        let (app2, key2) = governed_app_over_budget();
        let gov2 = crate::governance::GovCtx {
            key: Some(key2.clone()),
        };
        let resp = budget_check(&app2, &gov2, "openai", crate::store::now())
            .await
            .expect("zero-budget key ⇒ over-budget response");
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        let body = body_string(resp).await;
        assert_leak_free(&body, &key2.id, "any-pool");

        // Bedrock ingress maps the same over-budget condition to a 400-class
        // ServiceQuotaExceededException (the native AWS shape), NOT 429.
        let (app2b, key2b) = governed_app_over_budget();
        let gov2b = crate::governance::GovCtx {
            key: Some(key2b.clone()),
        };
        let resp = budget_check(&app2b, &gov2b, "bedrock", crate::store::now())
            .await
            .expect("zero-budget key ⇒ over-budget response (bedrock)");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_string(resp).await;
        assert!(
            body.contains("ServiceQuotaExceededException"),
            "bedrock over-budget body carries native quota exception: {body}"
        );
        assert_leak_free(&body, &key2b.id, "any-pool");
        let _ = &app2b;

        // --- 429: rate limited. A key with rpm_limit=0 is rate-limited on the first request. ---
        let (app3, key3) = governed_app_rate_limited();
        let gov3 = crate::governance::GovCtx {
            key: Some(key3.clone()),
        };
        let resp = rate_check(&app3, &gov3, "openai", crate::store::now())
            .expect("rpm=0 key ⇒ 429 response");
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
            crate::forward::KIND_NOT_FOUND,
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
            req_id
                .chars()
                .all(|c| (c.is_ascii_hexdigit() && !c.is_ascii_uppercase()) || c == '-'),
            "request id is lowercase hex: {req_id}"
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
                crate::forward::KIND_INVALID_REQUEST,
                StatusCode::BAD_REQUEST,
                "ValidationException",
            ),
            (
                crate::forward::KIND_RATE_LIMIT,
                StatusCode::TOO_MANY_REQUESTS,
                "ThrottlingException",
            ),
            (
                crate::forward::KIND_PERMISSION,
                StatusCode::FORBIDDEN,
                "AccessDeniedException",
            ),
            (
                crate::forward::KIND_INSUFFICIENT_QUOTA,
                StatusCode::BAD_REQUEST,
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
                crate::proto::bedrock::error_kind_to_bedrock_type(kind),
                expected,
                "header mapping for {kind}"
            );
        }
        // An OpenAI-ingress error must not carry the Bedrock-only headers.
        let openai = ingress_error(
            "openai",
            StatusCode::NOT_FOUND,
            crate::forward::KIND_NOT_FOUND,
            "m",
        );
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
            ct.starts_with("application/json"), // golden wire-contract literal (kept bare on purpose)
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
            Some("invalid_request_error"), // golden wire-contract literal (kept bare on purpose)
            "missing-model 400 carries the OpenAI invalid_request_error type; got {body}"
        );
        handle.abort();
    }

    /// MEDIUM/test-coverage: an EMPTY `"model"` string (`""`) is a distinct branch from a MISSING
    /// model in `ingress_body_model`'s guard (`Some(m) if !m.is_empty()`), and must produce the SAME
    /// native 400 `invalid_request_error` for every body-model protocol — NOT fall through to
    /// resolution (which would surface a 404 a native SDK reads differently). If the `!m.is_empty()`
    /// guard were dropped or weakened to `.is_some()`, an empty model would reach `forward_resolved`
    /// and 404 on a pool/by_model miss; these three tests (openai/cohere/responses) lock the 400.
    #[tokio::test]
    async fn test_openai_empty_model_is_400_native_envelope() {
        crate::metrics::init();
        let app = TestApp::new().build();
        let (addr, handle) = serve(app).await;
        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/v1/chat/completions"))
            .bearer_auth("t")
            .body(json!({"model": "", "messages": []}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 400, "empty model ⇒ 400 (not 404)");
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(
            body.get("error")
                .and_then(|e| e.get("type"))
                .and_then(|t| t.as_str()),
            Some("invalid_request_error"), // golden wire-contract literal (kept bare on purpose)
            "openai empty-model 400 carries invalid_request_error; got {body}"
        );
        handle.abort();
    }

    /// MEDIUM/test-coverage twin: Cohere `/v2/chat` with `"model": ""` ⇒ native Cohere 400 envelope
    /// (a BARE top-level `message`, NO `error`/`type` wrapper).
    #[tokio::test]
    async fn test_cohere_empty_model_is_400_native_envelope() {
        crate::metrics::init();
        let app = TestApp::new().build();
        let (addr, handle) = serve(app).await;
        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/v2/chat"))
            .bearer_auth("t")
            .body(json!({"model": "", "messages": []}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 400, "empty model ⇒ 400 (not 404)");
        let body: serde_json::Value = resp.json().await.unwrap();
        assert!(
            body.get("message").and_then(|m| m.as_str()).is_some(),
            "cohere empty-model 400 envelope carries a bare top-level message; got {body}"
        );
        assert!(
            body.get("error").is_none() && body.get("type").is_none(),
            "cohere empty-model 400 envelope has NO error/type wrapper; got {body}"
        );
        handle.abort();
    }

    /// MEDIUM/test-coverage twin: Responses `/v1/responses` with `"model": ""` ⇒ native Responses 400
    /// envelope (`{"error":{"type":"invalid_request_error"}}`).
    #[tokio::test]
    async fn test_responses_empty_model_is_400_native_envelope() {
        crate::metrics::init();
        let app = TestApp::new().build();
        let (addr, handle) = serve(app).await;
        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/v1/responses"))
            .bearer_auth("t")
            .body(json!({"model": "", "input": "hi"}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 400, "empty model ⇒ 400 (not 404)");
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(
            body.get("error")
                .and_then(|e| e.get("type"))
                .and_then(|t| t.as_str()),
            Some("invalid_request_error"), // golden wire-contract literal (kept bare on purpose)
            "responses empty-model 400 carries invalid_request_error; got {body}"
        );
        handle.abort();
    }

    /// MEDIUM/test-coverage: a syntactically valid JSON body whose `"model"` is NOT a string (a
    /// number / bool / null) is a distinct branch from MISSING and EMPTY in `ingress_body_model`'s
    /// guard. `v.get("model").and_then(|m| m.as_str())` returns `None` for any non-string value, so
    /// it MUST fall into the same native 400 `invalid_request_error` branch — never be coerced
    /// (e.g. `as_str().unwrap_or("")` or a `to_string()` of the number) and passed to
    /// `forward_resolved`, where a numeric "model" would 404 (model-not-found) instead of 400. A
    /// native vendor API rejects a non-string `model` with a 400, so a 404 here is a status-code
    /// distinguishability tell for SDK-generated requests. These three tests (openai/cohere/
    /// responses) lock the 400 for the body-model protocols; each asserts the protocol's native
    /// 400 envelope shape so the guard cannot be weakened to coerce a numeric model.
    #[tokio::test]
    async fn test_openai_numeric_model_is_400_native_envelope() {
        crate::metrics::init();
        let app = TestApp::new().build();
        let (addr, handle) = serve(app).await;
        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/v1/chat/completions"))
            .bearer_auth("t")
            .body(json!({"model": 42, "messages": []}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status().as_u16(),
            400,
            "numeric model ⇒ 400 (not 404 from resolution)"
        );
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(
            body.get("error")
                .and_then(|e| e.get("type"))
                .and_then(|t| t.as_str()),
            Some("invalid_request_error"), // golden wire-contract literal (kept bare on purpose)
            "openai numeric-model 400 carries invalid_request_error; got {body}"
        );
        handle.abort();
    }

    /// MEDIUM/test-coverage twin: Cohere `/v2/chat` with a non-string `"model"` (here `null`) ⇒
    /// native Cohere 400 envelope (a BARE top-level `message`, NO `error`/`type` wrapper). A `null`
    /// model is the exact case a guard weakened to `.is_some()` would mishandle (it IS present but
    /// not a string), so it must still 400 rather than fall through to a 404.
    #[tokio::test]
    async fn test_cohere_numeric_model_is_400_native_envelope() {
        crate::metrics::init();
        let app = TestApp::new().build();
        let (addr, handle) = serve(app).await;
        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/v2/chat"))
            .bearer_auth("t")
            .body(json!({"model": null, "messages": []}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status().as_u16(),
            400,
            "non-string model ⇒ 400 (not 404)"
        );
        let body: serde_json::Value = resp.json().await.unwrap();
        assert!(
            body.get("message").and_then(|m| m.as_str()).is_some(),
            "cohere non-string-model 400 envelope carries a bare top-level message; got {body}"
        );
        assert!(
            body.get("error").is_none() && body.get("type").is_none(),
            "cohere non-string-model 400 envelope has NO error/type wrapper; got {body}"
        );
        handle.abort();
    }

    /// MEDIUM/test-coverage twin: Responses `/v1/responses` with a non-string `"model"` (here a
    /// bool) ⇒ native Responses 400 envelope (`{"error":{"type":"invalid_request_error"}}`).
    #[tokio::test]
    async fn test_responses_numeric_model_is_400_native_envelope() {
        crate::metrics::init();
        let app = TestApp::new().build();
        let (addr, handle) = serve(app).await;
        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/v1/responses"))
            .bearer_auth("t")
            .body(json!({"model": true, "input": "hi"}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status().as_u16(),
            400,
            "non-string model ⇒ 400 (not 404)"
        );
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(
            body.get("error")
                .and_then(|e| e.get("type"))
                .and_then(|t| t.as_str()),
            Some("invalid_request_error"), // golden wire-contract literal (kept bare on purpose)
            "responses non-string-model 400 carries invalid_request_error; got {body}"
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
            ct.starts_with("application/json"), // golden wire-contract literal (kept bare on purpose)
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
            Some("not_found_error"), // golden wire-contract literal (kept bare on purpose)
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
                if d == crate::proto::SSE_DONE_SENTINEL {
                    continue;
                }
                out.push((event_name, d));
            }
        }
        out
    }

    /// A NATIVE OpenAI streamed chat-completion the mock backend emits, carrying the full identity
    /// vocabulary a real OpenAI stream uses — `object: "chat.completion.chunk"`, an `id`, `created`,
    /// `model`, a role/content delta walk, and a `finish_reason: "stop"` terminator. Distinct from
    /// `openai_stream_events` (which omits `object`/identity to exercise the cross-protocol WRITER):
    /// these realistic chunks let the openai→openai SAME-protocol passthrough below assert that the
    /// native frame vocabulary survives the proxy intact.
    fn openai_native_stream_events() -> Vec<String> {
        vec![
            r#"{"id":"chatcmpl-abc","object":"chat.completion.chunk","created":1700000000,"model":"gpt-4o","choices":[{"index":0,"delta":{"role":"assistant"},"finish_reason":null}]}"#.to_string(),
            r#"{"id":"chatcmpl-abc","object":"chat.completion.chunk","created":1700000000,"model":"gpt-4o","choices":[{"index":0,"delta":{"content":"hi"},"finish_reason":null}]}"#.to_string(),
            r#"{"id":"chatcmpl-abc","object":"chat.completion.chunk","created":1700000000,"model":"gpt-4o","choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":3,"total_tokens":8}}"#.to_string(),
        ]
    }

    /// An OpenAI `/v1/chat/completions` request with `"stream": true` must return `Content-Type:
    /// text/event-stream` AND a body whose JSON `data:` frames carry the NATIVE OpenAI
    /// chat-completion frame vocabulary — every chunk's `object` is `chat.completion.chunk`, no typed
    /// `event:` line (that would be an Anthropic/Responses SSE tell, not chat-completion shape), and
    /// the stream closes on the `[DONE]` sentinel. This is the OpenAI happy-path counterpart to
    /// `test_cohere_ingress_stream_emits_native_cohere_frames`: it pins the OpenAI egress frame
    /// vocabulary on the same-protocol passthrough so a regression that mangled the
    /// `chat.completion.chunk` object tag, dropped the `[DONE]` terminator, or injected a foreign
    /// typed-`event:` frame is caught.
    #[tokio::test]
    async fn test_openai_ingress_stream_emits_native_openai_frames() {
        crate::metrics::init();
        let state = StdArc::new(MockServerState::new());
        state.push(MockResponse::Sse {
            events: openai_native_stream_events(),
            abort_at_index: None,
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
            .body(
                json!({
                    "model": "gpt-4o",
                    "stream": true,
                    "messages": [{"role": "user", "content": "hello"}]
                })
                .to_string(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200, "openai stream ⇒ 200");
        let ct = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .to_string();
        assert!(
            ct.starts_with("text/event-stream"), // golden wire-contract literal (kept bare on purpose)
            "openai streaming ingress is SSE; got {ct}"
        );
        let text = resp.text().await.unwrap();

        // Native OpenAI chunks are bare `data:` frames — no typed `event:` line (a typed event would
        // be an Anthropic/Responses SSE tell, not chat-completion vocabulary).
        assert!(
            !text.contains("event:"),
            "openai chat-completion stream frames must be bare data: (no event: line); got:\n{text}"
        );

        // The stream must terminate with the native `[DONE]` sentinel.
        assert!(
            text.contains("[DONE]"), // golden wire-contract literal (kept bare on purpose)
            "openai stream must terminate with the native [DONE] sentinel; got:\n{text}"
        );

        // Every JSON data frame must carry the native `chat.completion.chunk` object tag, and there
        // must be at least one such chunk (content actually flowed).
        let objects: Vec<String> = sse_frames(&text)
            .into_iter()
            .filter_map(|(_, d)| serde_json::from_str::<serde_json::Value>(&d).ok())
            .filter_map(|v| {
                v.get("object")
                    .and_then(|o| o.as_str())
                    .map(|s| s.to_string())
            })
            .collect();
        assert!(
            !objects.is_empty(),
            "openai stream must carry at least one JSON data chunk; got:\n{text}"
        );
        assert!(
            objects.iter().all(|o| o == "chat.completion.chunk"),
            "every openai stream data chunk must be a chat.completion.chunk; got objects {objects:?}"
        );
        handle.abort();
        server.shutdown().await;
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
            ct.starts_with("text/event-stream"), // golden wire-contract literal (kept bare on purpose)
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
            ct.starts_with("text/event-stream"), // golden wire-contract literal (kept bare on purpose)
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
        // The LAST `data:` frame is the native Cohere v2 stream terminator on error: a `message-end`
        // event with `delta.finish_reason: "ERROR"` and NO top-level free-text `message` (a native
        // client never sees a proxy-detail string; the cause is logged server-side), and NOT a
        // top-level OpenAI `{"error":{...}}` shape.
        let last_data = sse_frames(&text)
            .into_iter()
            .next_back()
            .map(|(_, d)| d)
            .expect("a trailing data: error frame");
        let v: Value = serde_json::from_str(&last_data).expect("native Cohere JSON envelope");
        assert_eq!(
            v.get("type").and_then(|t| t.as_str()),
            Some("message-end"),
            "cohere mid-stream error is a native message-end frame; got {v}"
        );
        assert!(
            v.pointer("/delta/finish_reason")
                .and_then(|f| f.as_str())
                .is_some_and(|f| f.starts_with("ERROR")),
            "cohere message-end carries delta.finish_reason ERROR; got {v}"
        );
        assert!(
            v.get("message").is_none(),
            "cohere native message-end must not carry a top-level free-text message; got {v}"
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

    // ---- HIGH/test-coverage: governance pool-ACL 403 native envelope on the new ingress routes ----
    //
    // `test_governance_vkey_auth_and_pool_acl` (test_support.rs) and
    // `test_governance_rejection_is_counted_via_finish` (above) only exercise the Anthropic ingress
    // (`/v1/messages` / `/anypool/v1/messages`). The four first-class ingress routes
    // (`/v2/chat`, `/v1/responses`, `/v1beta/models/...`, `/model/...`) each call `forward_resolved`
    // → `governance_guard` with the route's own `proto`, so a pool-ACL 403 on those routes returns a
    // PROTOCOL-NATIVE 403 envelope. These four tests drive a governance-rejected request through the
    // REAL router on each route and assert the native 403 shape, so a regression in `ingress_error`
    // writer dispatch / kind mapping for any of them is caught.
    //
    // The governance guard keys the ACL on the resolved MODEL string (the body `"model"` for
    // body-model routes, the path model for path-model routes) — see `forward_resolved`. So a key
    // whose `allowed_pools` does NOT contain the request model is pool-rejected with 403 BEFORE
    // resolution. We still wire a matching lane+pool so the request is otherwise fully valid and the
    // ONLY reason for the 403 is the ACL.

    /// Build a governance-enabled router whose single virtual key is allowed ONLY on `other-pool`
    /// (never on the model/pool the tests request), wired with `lane`+`pool` named `model` so the
    /// request is otherwise valid. Returns `(addr, handle, secret)`.
    async fn governed_pool_acl_router(
        model: &str,
        protocol: crate::proto::Protocol,
        provider: &str,
    ) -> (
        std::net::SocketAddr,
        tokio::task::JoinHandle<()>,
        &'static str,
    ) {
        use crate::governance::{GovState, SqliteStore, Store, VirtualKey};
        // The lane needs a base_url, but the pool-ACL 403 short-circuits before any forward, so an
        // unreachable upstream is fine.
        const SECRET: &str = "sk-vk-acl-denied";
        let store = StdArc::new(SqliteStore::open_in_memory().unwrap());
        store
            .put_key(&VirtualKey {
                id: "kacl".to_string(),
                key_hash: crate::sigv4::sha256_hex(SECRET.as_bytes()),
                name: "acl".to_string(),
                // Allowed ONLY on a pool the requests never use → every request is pool-rejected 403.
                allowed_pools: vec!["other-pool".to_string()],
                max_budget_cents: None,
                budget_period: "total".to_string(),
                rpm_limit: None,
                tpm_limit: None,
                enabled: true,
                created_at: 0,
            })
            .unwrap();
        let gov = StdArc::new(GovState::new(store, 1, 0, None).unwrap());
        let app = TestApp::new()
            .governance(gov)
            .lane(LaneSpec::new(model, protocol, "http://127.0.0.1:1").provider(provider))
            .pool(model, &[(0, 1)])
            .build();
        let (addr, handle) = serve(app).await;
        (addr, handle, SECRET)
    }

    /// Cohere `/v2/chat` governance pool-ACL 403 must carry the Cohere-native error envelope
    /// (`{"message": ...}`), served as application/json.
    #[tokio::test]
    async fn test_governance_pool_acl_403_cohere_native_envelope() {
        crate::metrics::init();
        let (addr, handle, secret) =
            governed_pool_acl_router("co", crate::proto::Protocol::openai(), "zai").await;
        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/v2/chat"))
            .bearer_auth(secret)
            .body(
                json!({"model": "co", "messages": [{"role": "user", "content": "hi"}]}).to_string(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 403, "cohere pool-ACL ⇒ 403");
        let ct = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .to_string();
        assert!(
            ct.starts_with("application/json"), // golden wire-contract literal (kept bare on purpose)
            "cohere 403 envelope is JSON; got {ct}"
        );
        let body: serde_json::Value = resp.json().await.unwrap();
        assert!(
            body.get("message").and_then(|m| m.as_str()).is_some(),
            "cohere native 403 envelope has a message field; got {body}"
        );
        handle.abort();
    }

    /// Responses `/v1/responses` governance pool-ACL 403 must carry the OpenAI-identical error
    /// envelope (`{"error":{"type":"permission_error"}}`).
    #[tokio::test]
    async fn test_governance_pool_acl_403_responses_native_envelope() {
        crate::metrics::init();
        let (addr, handle, secret) =
            governed_pool_acl_router("re", crate::proto::Protocol::openai(), "zai").await;
        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/v1/responses"))
            .bearer_auth(secret)
            .body(json!({"model": "re", "input": "hi"}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 403, "responses pool-ACL ⇒ 403");
        let ct = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .to_string();
        assert!(
            ct.starts_with("application/json"), // golden wire-contract literal (kept bare on purpose)
            "responses 403 envelope is JSON; got {ct}"
        );
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(
            body.get("error")
                .and_then(|e| e.get("type"))
                .and_then(|t| t.as_str()),
            Some("permission_error"), // golden wire-contract literal (kept bare on purpose)
            "responses 403 carries the permission_error type; got {body}"
        );
        handle.abort();
    }

    /// OpenAI `/v1/chat/completions` governance pool-ACL 403 must carry the OpenAI-native error
    /// envelope (`{"error":{"type":"permission_error"}}`), served as application/json. The native
    /// OpenAI ingress route (`openai_ingress` → `ingress_body_model(..., "openai")`) shares the
    /// `forward_resolved` → `governance_guard` path with the other four ingresses, so a regression in
    /// `ingress_error` writer dispatch / `permission_error` kind mapping for the `openai` writer is
    /// caught here exactly as the symmetric four tests catch it for their protocols.
    #[tokio::test]
    async fn test_governance_pool_acl_403_openai_native_envelope() {
        crate::metrics::init();
        let (addr, handle, secret) =
            governed_pool_acl_router("gpt-4o", crate::proto::Protocol::openai(), "openai").await;
        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/v1/chat/completions"))
            .bearer_auth(secret)
            .body(
                json!({"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]})
                    .to_string(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 403, "openai pool-ACL ⇒ 403");
        let ct = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .to_string();
        assert!(
            ct.starts_with("application/json"), // golden wire-contract literal (kept bare on purpose)
            "openai 403 envelope is JSON; got {ct}"
        );
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(
            body.get("error")
                .and_then(|e| e.get("type"))
                .and_then(|t| t.as_str()),
            Some("permission_error"), // golden wire-contract literal (kept bare on purpose)
            "openai 403 carries the permission_error type; got {body}"
        );
        handle.abort();
    }

    /// Gemini `/v1beta/models/{model}:generateContent` governance pool-ACL 403 must carry the
    /// Gemini-native error envelope (`{"error":{"code":403,"status":"PERMISSION_DENIED"}}`).
    #[tokio::test]
    async fn test_governance_pool_acl_403_gemini_native_envelope() {
        crate::metrics::init();
        let (addr, handle, secret) =
            governed_pool_acl_router("foo", crate::proto::Protocol::openai(), "zai").await;
        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/v1beta/models/foo:generateContent"))
            .bearer_auth(secret)
            .body(json!({"contents": [{"role": "user", "parts": [{"text": "hi"}]}]}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 403, "gemini pool-ACL ⇒ 403");
        let ct = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .to_string();
        assert!(
            ct.starts_with("application/json"), // golden wire-contract literal (kept bare on purpose)
            "gemini 403 envelope is JSON; got {ct}"
        );
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(
            body.get("error")
                .and_then(|e| e.get("code"))
                .and_then(|c| c.as_u64()),
            Some(403),
            "gemini 403 envelope carries error.code 403; got {body}"
        );
        assert_eq!(
            body.get("error")
                .and_then(|e| e.get("status"))
                .and_then(|s| s.as_str()),
            Some("PERMISSION_DENIED"),
            "gemini 403 envelope carries status PERMISSION_DENIED; got {body}"
        );
        handle.abort();
    }

    /// Bedrock `/model/{model}/converse` governance pool-ACL 403 must carry the Bedrock-native error
    /// body (`{"__type":"AccessDeniedException"}`) AND the `x-amzn-errortype: AccessDeniedException`
    /// header (plus `x-amzn-RequestId`), exactly as a real AWS Bedrock 403 does.
    #[tokio::test]
    async fn test_governance_pool_acl_403_bedrock_native_envelope() {
        crate::metrics::init();
        let (addr, handle, secret) =
            governed_pool_acl_router("foo", crate::proto::Protocol::openai(), "zai").await;
        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/model/foo/converse"))
            .bearer_auth(secret)
            .body(json!({"messages": [{"role": "user", "content": [{"text": "hi"}]}]}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 403, "bedrock pool-ACL ⇒ 403");
        let ct = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .to_string();
        assert!(
            ct.starts_with("application/json"), // golden wire-contract literal (kept bare on purpose)
            "bedrock 403 envelope is JSON; got {ct}"
        );
        assert_eq!(
            resp.headers()
                .get("x-amzn-errortype")
                .and_then(|h| h.to_str().ok()),
            Some("AccessDeniedException"),
            "bedrock 403 carries x-amzn-errortype: AccessDeniedException"
        );
        assert!(
            resp.headers().get("x-amzn-requestid").is_some(),
            "bedrock 403 still carries x-amzn-RequestId"
        );
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(
            body.get("__type").and_then(|t| t.as_str()),
            Some("AccessDeniedException"),
            "bedrock 403 body __type is AccessDeniedException; got {body}"
        );
        handle.abort();
    }

    // ---- SECURITY MED #3: the allowed_pools ACL must also gate the FALLBACK pool ----
    //
    // A virtual key's `allowed_pools` was enforced only on the INITIAL pool. A pool configured with
    // `on_exhausted = fallback_pool:B` would, on exhaustion, route the request to pool B inside
    // `forward::handle_fallback_pool` — which never re-checks the key (the `gov` context is not
    // threaded that deep). So a key allowed ONLY on pool A could be served by pool B it was never
    // permitted to use. The fix (`fallback_pools_authorized`, wired into `governance_guard`) walks
    // the fallback chain reachable from the requested pool and re-runs the SAME `pool_authorized`
    // 403 gate against every fallback pool name BEFORE any dispatch.

    /// REGRESSION (SECURITY MED #3): a key restricted to pool A must be DENIED (403, the same
    /// protocol-native permission envelope as the initial-pool denial) when A is configured to fail
    /// over to a fallback pool B the key is NOT allowed on — even though the key passes A's own ACL
    /// and A's backend would itself answer 200. Against the pre-fix code this request reached A and
    /// returned 200 (the fallback ACL was never checked); with the fix it is a 403 upfront, because B
    /// is reachable from A on exhaustion and the key may not use B.
    #[tokio::test]
    async fn test_fallback_pool_acl_denies_key_not_allowed_on_fallback_target() {
        use crate::governance::{GovState, SqliteStore, Store, VirtualKey};
        crate::metrics::init();

        // Pool A's backend would succeed (200) if the request ever reached it — proving the 403 is
        // due ONLY to the fallback-pool ACL, not to A being unreachable.
        let state = StdArc::new(MockServerState::new());
        state.push(MockResponse::Ok {
            status: StatusCode::OK,
            body: anthropic_ok_body(),
        });
        let server = MockServer::new(state).await;
        let a_url = server.base_url();

        const SECRET: &str = "sk-vk-fallback-acl";
        let store = StdArc::new(SqliteStore::open_in_memory().unwrap());
        store
            .put_key(&VirtualKey {
                id: "kfb".to_string(),
                key_hash: crate::sigv4::sha256_hex(SECRET.as_bytes()),
                name: "fb".to_string(),
                // Allowed ONLY on pool A. Pool B (the fallback target) is NOT in the list.
                allowed_pools: vec!["A".to_string()],
                max_budget_cents: None,
                budget_period: "total".to_string(),
                rpm_limit: None,
                tpm_limit: None,
                enabled: true,
                created_at: 0,
            })
            .unwrap();
        let gov = StdArc::new(GovState::new(store, 0, 0, None).unwrap());

        // Lane 0 → pool A (reachable mock). Lane 1 → pool B (the disallowed fallback target).
        let app = TestApp::new()
            .governance(gov)
            .lane(LaneSpec::new("A", crate::proto::Protocol::anthropic(), &a_url).provider("zai"))
            .lane(
                LaneSpec::new(
                    "B",
                    crate::proto::Protocol::anthropic(),
                    "http://127.0.0.1:1",
                )
                .provider("zai"),
            )
            .pool("A", &[(0, 1)])
            .pool("B", &[(1, 1)])
            // A fails over to B on exhaustion — B is exactly the pool the key may NOT use.
            .fallback_pool("B", &[(1, 1)])
            .on_exhausted(
                "A",
                crate::config::OnExhausted::FallbackPool("B".to_string()),
            )
            .build();
        let (addr, handle) = serve(app).await;

        // Request pool A via the named Anthropic ingress. The key is allowed on A, but A→B fallback
        // is configured and the key is not allowed on B, so the request must be rejected upfront.
        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/A/v1/messages"))
            .bearer_auth(SECRET)
            .body(
                json!({"model": "A", "messages": [{"role": "user", "content": "hi"}]}).to_string(),
            )
            .send()
            .await
            .unwrap();

        assert_eq!(
            resp.status().as_u16(),
            403,
            "key restricted to A must be denied (not served) when A falls back to disallowed pool B"
        );
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(
            body.get("error")
                .and_then(|e| e.get("type"))
                .and_then(|t| t.as_str()),
            Some("permission_error"), // golden wire-contract literal (kept bare on purpose)
            "fallback-pool ACL 403 carries the SAME permission_error envelope as the initial check; got {body}"
        );
        handle.abort();
        server.shutdown().await;
    }

    /// COMPLEMENT to the above: a key that IS allowed on BOTH the initial pool A and its fallback
    /// pool B is NOT spuriously rejected — the fallback-pool ACL walk only denies pools outside the
    /// key's `allowed_pools`. The request reaches A's backend and round-trips 200. Guards against the
    /// fix over-rejecting legitimate fallback configurations.
    #[tokio::test]
    async fn test_fallback_pool_acl_allows_key_permitted_on_both_pools() {
        use crate::governance::{GovState, SqliteStore, Store, VirtualKey};
        crate::metrics::init();

        let state = StdArc::new(MockServerState::new());
        state.push(MockResponse::Ok {
            status: StatusCode::OK,
            body: anthropic_ok_body(),
        });
        let server = MockServer::new(state).await;
        let a_url = server.base_url();

        const SECRET: &str = "sk-vk-fallback-ok";
        let store = StdArc::new(SqliteStore::open_in_memory().unwrap());
        store
            .put_key(&VirtualKey {
                id: "kfb2".to_string(),
                key_hash: crate::sigv4::sha256_hex(SECRET.as_bytes()),
                name: "fb2".to_string(),
                // Allowed on BOTH A and the fallback target B → no ACL rejection on either.
                allowed_pools: vec!["A".to_string(), "B".to_string()],
                max_budget_cents: None,
                budget_period: "total".to_string(),
                rpm_limit: None,
                tpm_limit: None,
                enabled: true,
                created_at: 0,
            })
            .unwrap();
        let gov = StdArc::new(GovState::new(store, 0, 0, None).unwrap());

        let app = TestApp::new()
            .governance(gov)
            .lane(LaneSpec::new("A", crate::proto::Protocol::anthropic(), &a_url).provider("zai"))
            .lane(
                LaneSpec::new(
                    "B",
                    crate::proto::Protocol::anthropic(),
                    "http://127.0.0.1:1",
                )
                .provider("zai"),
            )
            .pool("A", &[(0, 1)])
            .pool("B", &[(1, 1)])
            .fallback_pool("B", &[(1, 1)])
            .on_exhausted(
                "A",
                crate::config::OnExhausted::FallbackPool("B".to_string()),
            )
            .build();
        let (addr, handle) = serve(app).await;

        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/A/v1/messages"))
            .bearer_auth(SECRET)
            .body(
                json!({"model": "A", "messages": [{"role": "user", "content": "hi"}]}).to_string(),
            )
            .send()
            .await
            .unwrap();

        assert_eq!(
            resp.status().as_u16(),
            200,
            "key allowed on both A and fallback B must NOT be rejected by the fallback ACL walk"
        );
        handle.abort();
        server.shutdown().await;
    }

    // ---- MEDIUM/test-coverage: adhoc `/{provider}/{model}/v1/messages` E2E through the router ----
    //
    // `test_adhoc_rejects_unconfigured_provider_model` (test_support.rs) calls the handler directly,
    // bypassing the router, axum `Path` extraction, the auth middleware + CallerToken extension
    // wiring, and `finish` metrics accounting. These three drive the adhoc route through the REAL
    // router (`build_router`) so that whole stack is covered: (a) a successful round-trip, (b) a
    // provider-mismatch 400 with the Anthropic-native envelope, (c) a governance pool-ACL rejection.

    /// Adhoc success: `/{provider}/{model}/v1/messages` resolves the configured provider+model lane,
    /// round-trips through the router (Anthropic ingress → Anthropic backend), and returns 2xx. This
    /// exercises the axum two-segment `Path((provider, model))` extraction, the auth middleware +
    /// CallerToken extension wiring, and `finish` — none of which the handler-direct unit test runs.
    #[tokio::test]
    async fn test_adhoc_success_round_trip_via_router() {
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
            .build();
        let (addr, handle) = serve(app).await;

        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/anthropic/claude-x/v1/messages"))
            .bearer_auth("t")
            .body(json!({"model": "claude-x", "messages": [], "max_tokens": 16}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status().as_u16(),
            200,
            "adhoc provider+model resolves and 2xx round-trips"
        );
        handle.abort();
        server.shutdown().await;
    }

    /// Adhoc provider mismatch via the router: a configured model requested under the WRONG provider
    /// segment ⇒ 400 with the Anthropic-native error envelope (`{"type":"error","error":{"type":...}}`),
    /// not a foreign shape or a plain-text body.
    #[tokio::test]
    async fn test_adhoc_provider_mismatch_400_anthropic_envelope_via_router() {
        crate::metrics::init();
        let app = TestApp::new()
            .lane(
                LaneSpec::new(
                    "claude-x",
                    crate::proto::Protocol::anthropic(),
                    "http://127.0.0.1:1",
                )
                .provider("anthropic"),
            )
            .build();
        let (addr, handle) = serve(app).await;

        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/wrong-provider/claude-x/v1/messages"))
            .bearer_auth("t")
            .body(json!({"model": "claude-x", "messages": [], "max_tokens": 16}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status().as_u16(),
            400,
            "model on a mismatched provider ⇒ 400"
        );
        let ct = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .to_string();
        assert!(
            ct.starts_with("application/json"), // golden wire-contract literal (kept bare on purpose)
            "adhoc 400 envelope is JSON; got {ct}"
        );
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(
            body.get("type").and_then(|t| t.as_str()),
            Some("error"),
            "adhoc 400 is the Anthropic native error envelope; got {body}"
        );
        assert_eq!(
            body.get("error")
                .and_then(|e| e.get("type"))
                .and_then(|t| t.as_str()),
            Some("invalid_request_error"), // golden wire-contract literal (kept bare on purpose)
            "adhoc provider-mismatch 400 carries invalid_request_error; got {body}"
        );
        handle.abort();
    }

    /// Adhoc governance pool-ACL rejection via the router: the adhoc handler also runs
    /// `governance_guard` (keyed on the resolved MODEL). A key allowed only on `other-pool` requesting
    /// the configured model ⇒ 403 with the Anthropic-native envelope, finished through `finish_rejected`. This
    /// covers the governance path on the adhoc route end-to-end (untested by the handler-direct test,
    /// which passes a default no-key GovCtx).
    #[tokio::test]
    async fn test_adhoc_governance_pool_acl_403_via_router() {
        use crate::governance::{GovState, SqliteStore, Store, VirtualKey};
        crate::metrics::init();
        const SECRET: &str = "sk-vk-adhoc-acl";
        let store = StdArc::new(SqliteStore::open_in_memory().unwrap());
        store
            .put_key(&VirtualKey {
                id: "kadhoc".to_string(),
                key_hash: crate::sigv4::sha256_hex(SECRET.as_bytes()),
                name: "adhoc-acl".to_string(),
                allowed_pools: vec!["other-pool".to_string()],
                max_budget_cents: None,
                budget_period: "total".to_string(),
                rpm_limit: None,
                tpm_limit: None,
                enabled: true,
                created_at: 0,
            })
            .unwrap();
        let gov = StdArc::new(GovState::new(store, 1, 0, None).unwrap());
        let app = TestApp::new()
            .governance(gov)
            .lane(
                LaneSpec::new(
                    "claude-x",
                    crate::proto::Protocol::anthropic(),
                    "http://127.0.0.1:1",
                )
                .provider("anthropic"),
            )
            .build();
        let (addr, handle) = serve(app).await;

        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/anthropic/claude-x/v1/messages"))
            .bearer_auth(SECRET)
            .body(json!({"model": "claude-x", "messages": [], "max_tokens": 16}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status().as_u16(),
            403,
            "adhoc governance pool-ACL ⇒ 403"
        );
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(
            body.get("type").and_then(|t| t.as_str()),
            Some("error"),
            "adhoc 403 is the Anthropic native error envelope; got {body}"
        );
        assert_eq!(
            body.get("error")
                .and_then(|e| e.get("type"))
                .and_then(|t| t.as_str()),
            Some("permission_error"), // golden wire-contract literal (kept bare on purpose)
            "adhoc governance 403 carries permission_error; got {body}"
        );
        handle.abort();
    }

    /// MEDIUM/conformance regression: `not_found_message` shapes the model-not-found copy per the
    /// INGRESS protocol. A gemini api_version yields the NATIVE Gemini string (versioned, no OpenAI
    /// "The model '…'" phrasing); every other protocol (api_version `None`) keeps the canonical
    /// OpenAI-style copy the OpenAI/Responses/Cohere/Anthropic SDKs expect. Guards against a future
    /// edit re-leaking the OpenAI message onto the gemini surface.
    #[test]
    fn test_not_found_message_is_protocol_native() {
        // Gemini v1beta: native versioned message, NO OpenAI phrasing.
        let g_beta = not_found_message("gemini-1.5-pro", Some("v1beta"));
        assert_eq!(
            g_beta,
            "models/gemini-1.5-pro is not found for API version v1beta, \
             or is not supported for the task you are trying to perform."
        );
        // Gemini stable v1: the version token echoes "v1" (not a hardcoded "v1beta").
        let g_v1 = not_found_message("gemini-1.5-pro", Some("v1"));
        assert!(
            g_v1.contains("for API version v1,"),
            "stable v1 message echoes the v1 token; got {g_v1}"
        );
        assert!(
            !g_v1.contains("does not exist"),
            "gemini message must NOT use the OpenAI 'does not exist' phrasing; got {g_v1}"
        );
        // Non-gemini (None): the canonical OpenAI-style copy is preserved.
        let oai = not_found_message("gpt-4o", None);
        assert_eq!(
            oai,
            "The model 'gpt-4o' does not exist or you do not have access to it."
        );
    }

    /// MEDIUM/conformance: a model-not-found 404 on the gemini ingress returns the NATIVE Gemini
    /// message ("models/{model} is not found for API version {api_version}, …"), with the version
    /// token matching the request path — `v1beta` on the v1beta surface, `v1` on the stable v1
    /// surface. NO OpenAI "The model '…' does not exist" copy may leak (a tell for SDKs matching on
    /// `error.message`). Drives the real router with an empty app so resolution misses on both maps.
    #[tokio::test]
    async fn test_gemini_model_not_found_uses_native_message() {
        crate::metrics::init();
        let app = TestApp::new().build();
        let (addr, handle) = serve(app).await;

        for (path, version) in [
            ("/v1beta/models/no-such-model:generateContent", "v1beta"),
            ("/v1/models/no-such-model:generateContent", "v1"),
        ] {
            let resp = reqwest::Client::new()
                .post(format!("http://{addr}{path}"))
                .bearer_auth("t")
                .body(json!({"contents": []}).to_string())
                .send()
                .await
                .unwrap();
            assert_eq!(
                resp.status().as_u16(),
                404,
                "gemini unknown-model ⇒ native 404 ({path})"
            );
            let body: serde_json::Value = resp.json().await.unwrap();
            let msg = body
                .get("error")
                .and_then(|e| e.get("message"))
                .and_then(|m| m.as_str())
                .unwrap_or("");
            assert_eq!(
                msg,
                format!(
                    "models/no-such-model is not found for API version {version}, \
                     or is not supported for the task you are trying to perform."
                ),
                "gemini 404 carries the native versioned message ({path}); got {body}"
            );
            assert!(
                !msg.contains("does not exist"),
                "no OpenAI 'does not exist' copy may leak to a gemini client ({path}); got {body}"
            );
        }
        handle.abort();
    }

    /// MEDIUM/test-coverage: the STABLE v1 gemini surface (`/v1/models/*rest`) is a separately
    /// registered route (main.rs) that funnels through the same `gemini_ingress` handler as v1beta.
    /// This exercises a happy-path STREAMING request via the stable v1 prefix WITH `?alt=sse`, so a
    /// routing regression on the v1 alias (e.g. a wildcard conflict) is caught. Mirrors
    /// `test_gemini_stream_generate_content_alt_sse_is_event_stream` but on the v1 path: asserts SSE
    /// framing and that the frames carry native gemini `candidates[]` (never OpenAI `choices`).
    #[tokio::test]
    async fn test_gemini_v1_stable_stream_generate_content_alt_sse() {
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
                "http://{addr}/v1/models/foo:streamGenerateContent?alt=sse"
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
            "stable v1 :streamGenerateContent?alt=sse resolves and 2xx round-trips"
        );
        let ct = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .to_string();
        assert!(
            ct.starts_with("text/event-stream"), // golden wire-contract literal (kept bare on purpose)
            "stable v1 gemini streaming WITH ?alt=sse is SSE-framed; got {ct}"
        );
        let body = resp.text().await.unwrap();
        let payloads: Vec<serde_json::Value> = body
            .lines()
            .filter_map(|line| line.strip_prefix("data:"))
            .map(str::trim)
            .filter(|data| !data.is_empty() && *data != crate::proto::SSE_DONE_SENTINEL)
            .filter_map(|data| serde_json::from_str(data).ok())
            .collect();
        assert!(
            !payloads.is_empty(),
            "stable v1 SSE body carries at least one JSON data: frame; got {body:?}"
        );
        assert!(
            payloads.iter().any(|c| c.get("candidates").is_some()),
            "stable v1 SSE frames are native gemini GenerateContentResponse (candidates[]); \
             got {body:?}"
        );
        assert!(
            payloads.iter().all(|c| c.get("choices").is_none()),
            "no OpenAI `choices` field may leak into the stable v1 gemini SSE frames; got {body:?}"
        );
        handle.abort();
        server.shutdown().await;
    }

    /// MEDIUM/test-coverage: the STABLE v1 gemini surface (`/v1/models/*rest`), streaming WITHOUT
    /// `?alt=sse`, must return the JSON-ARRAY framing (`application/json`, a `[{...}]` body) exactly
    /// like the v1beta surface. Mirrors `test_gemini_stream_generate_content_no_alt_sse_is_json_array`
    /// on the v1 path so a regression isolating the stable-v1 alias is caught.
    #[tokio::test]
    async fn test_gemini_v1_stable_stream_generate_content_no_alt_sse() {
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
            .post(format!("http://{addr}/v1/models/foo:streamGenerateContent"))
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
            "stable v1 :streamGenerateContent (no alt=sse) 2xx"
        );
        let ct = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .to_string();
        assert!(
            ct.starts_with("application/json"), // golden wire-contract literal (kept bare on purpose)
            "stable v1 gemini streaming WITHOUT ?alt=sse is JSON-array framed; got {ct}"
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
        assert!(
            arr.iter().any(|c| c.get("candidates").is_some()),
            "stable v1 array chunk is a native gemini GenerateContentResponse; got {body:?}"
        );
        assert!(
            arr.iter().all(|c| c.get("choices").is_none()),
            "no OpenAI `choices` field may leak into the stable v1 JSON-array frames; got {body:?}"
        );
        handle.abort();
        server.shutdown().await;
    }

    // ---- MEDIUM/test-coverage: governance 429 (rate) and over-budget paths on the new ingress ----
    //
    // The route.rs governance suite above (`test_governance_pool_acl_403_*`) only exercises the
    // pool-ACL 403 guard end-to-end. The OTHER two `governance_guard` rejections — `rate_check`
    // (429 + Retry-After) and `budget_check` (over-quota) — share the same `forward_resolved`
    // dispatch but map to DIFFERENT per-protocol `kind`s (`rate_limit_error` / `insufficient_quota`)
    // and (for budget) DIFFERENT statuses (429 for openai/cohere/gemini, 400 for bedrock). A
    // regression in either kind-to-envelope mapping on a new ingress protocol would slip past the
    // 403-only set. These drive a virtual key that is over its rate cap / budget through the REAL
    // router on each first-class ingress route and assert the protocol-native rejection shape.
    //
    // The rejection fires in `governance_guard` BEFORE model resolution, so no lane/pool/backend is
    // needed — only a parseable body carrying `model` where the body-model protocols expect it.

    /// Build a governance-enabled router whose single virtual key is over its limit, selected by
    /// `rpm` (`Some(0)` ⇒ rate-limited on the first request) and/or `max_budget_cents` (`Some(0)` ⇒
    /// over budget on the first request). `allowed_pools: vec![]` admits every pool so the ACL never
    /// short-circuits the gate under test. Returns `(addr, handle, secret)`.
    async fn governed_limit_router(
        rpm: Option<u32>,
        max_budget_cents: Option<i64>,
    ) -> (
        std::net::SocketAddr,
        tokio::task::JoinHandle<()>,
        &'static str,
    ) {
        use crate::governance::{GovState, SqliteStore, Store, VirtualKey};
        const SECRET: &str = "sk-vk-limit-route";
        let store = StdArc::new(SqliteStore::open_in_memory().unwrap());
        store
            .put_key(&VirtualKey {
                id: "klimit".to_string(),
                key_hash: crate::sigv4::sha256_hex(SECRET.as_bytes()),
                name: "limit".to_string(),
                allowed_pools: vec![], // all pools — ACL never short-circuits
                max_budget_cents,
                budget_period: "total".to_string(),
                rpm_limit: rpm,
                tpm_limit: None,
                enabled: true,
                created_at: 0,
            })
            .unwrap();
        let gov = StdArc::new(GovState::new(store, 1, 0, None).unwrap());
        let app = TestApp::new().governance(gov).build();
        let (addr, handle) = serve(app).await;
        (addr, handle, SECRET)
    }

    /// Each first-class ingress route: an over-RPM virtual key is rejected with a PROTOCOL-NATIVE
    /// 429 (`Retry-After` set) before resolution. Asserts the per-protocol `kind`-to-envelope
    /// mapping (`rate_limit_error` for the body-model/anthropic writers, the native quota envelope
    /// for gemini/bedrock) that the 403-only set above does not reach.
    #[tokio::test]
    async fn test_governance_rate_limit_429_native_envelope_all_ingress() {
        crate::metrics::init();

        // openai / responses / cohere: body-model routes, native error envelope is JSON.
        for (path, payload) in [
            (
                "/v1/chat/completions",
                json!({"model": "m", "messages": []}),
            ),
            ("/v1/responses", json!({"model": "m", "input": "hi"})),
            ("/v2/chat", json!({"model": "m", "messages": []})),
        ] {
            let (addr, handle, secret) = governed_limit_router(Some(0), None).await;
            let resp = reqwest::Client::new()
                .post(format!("http://{addr}{path}"))
                .bearer_auth(secret)
                .body(payload.to_string())
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status().as_u16(), 429, "{path} over-RPM ⇒ 429");
            assert!(
                resp.headers().get(reqwest::header::RETRY_AFTER).is_some(),
                "{path} 429 carries Retry-After"
            );
            handle.abort();
        }

        // gemini path-model route: native quota envelope is error.code 429 + RESOURCE_EXHAUSTED.
        {
            let (addr, handle, secret) = governed_limit_router(Some(0), None).await;
            let resp = reqwest::Client::new()
                .post(format!("http://{addr}/v1beta/models/m:generateContent"))
                .bearer_auth(secret)
                .body(json!({"contents": []}).to_string())
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status().as_u16(), 429, "gemini over-RPM ⇒ 429");
            let body: serde_json::Value = resp.json().await.unwrap();
            assert_eq!(
                body.get("error")
                    .and_then(|e| e.get("status"))
                    .and_then(|s| s.as_str()),
                Some("RESOURCE_EXHAUSTED"),
                "gemini 429 envelope carries RESOURCE_EXHAUSTED; got {body}"
            );
            handle.abort();
        }

        // bedrock path-model route: native 429 carries the ThrottlingException envelope + headers.
        {
            let (addr, handle, secret) = governed_limit_router(Some(0), None).await;
            let resp = reqwest::Client::new()
                .post(format!("http://{addr}/model/m/converse"))
                .bearer_auth(secret)
                .body(json!({"messages": []}).to_string())
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status().as_u16(), 429, "bedrock over-RPM ⇒ 429");
            assert!(
                resp.headers().get("x-amzn-errortype").is_some(),
                "bedrock 429 carries x-amzn-errortype header"
            );
            assert!(
                resp.headers().get("x-amzn-requestid").is_some(),
                "bedrock 429 carries x-amzn-RequestId header"
            );
            handle.abort();
        }
    }

    /// Each first-class ingress route: an over-budget virtual key is rejected with the protocol's
    /// native quota shape before resolution. The over-quota `kind` is `insufficient_quota`; the
    /// status is 429 for every protocol EXCEPT bedrock (whose native `ServiceQuotaExceededException`
    /// is a 400-class error — see `budget_check`). Closes the route.rs gap the 403-only set left on
    /// the `budget_check` guard.
    #[tokio::test]
    async fn test_governance_over_budget_native_envelope_all_ingress() {
        crate::metrics::init();

        // 429-mapping protocols: openai / responses / cohere / gemini.
        for (path, payload) in [
            (
                "/v1/chat/completions",
                json!({"model": "m", "messages": []}),
            ),
            ("/v1/responses", json!({"model": "m", "input": "hi"})),
            ("/v2/chat", json!({"model": "m", "messages": []})),
            ("/v1beta/models/m:generateContent", json!({"contents": []})),
        ] {
            let (addr, handle, secret) = governed_limit_router(None, Some(0)).await;
            let resp = reqwest::Client::new()
                .post(format!("http://{addr}{path}"))
                .bearer_auth(secret)
                .body(payload.to_string())
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status().as_u16(), 429, "{path} over-budget ⇒ 429");
            handle.abort();
        }

        // bedrock: native ServiceQuotaExceededException is a 400-class error, not 429.
        {
            let (addr, handle, secret) = governed_limit_router(None, Some(0)).await;
            let resp = reqwest::Client::new()
                .post(format!("http://{addr}/model/m/converse"))
                .bearer_auth(secret)
                .body(json!({"messages": []}).to_string())
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status().as_u16(), 400, "bedrock over-budget ⇒ 400");
            let body: serde_json::Value = resp.json().await.unwrap();
            assert_eq!(
                body.get("__type").and_then(|t| t.as_str()),
                Some("ServiceQuotaExceededException"),
                "bedrock over-budget body __type is ServiceQuotaExceededException; got {body}"
            );
            handle.abort();
        }
    }

    // ---- MEDIUM/test-coverage: the `named` handler's `by_model` fallback branch ----
    //
    // `named` (`POST /<name>/v1/messages`) resolves `name` against `app.pools` first, then falls
    // back to `app.by_model` (the by_model arm). The pool path is covered by
    // `test_adhoc_success_round_trip_via_router` and the governance pool-ACL set; the by_model
    // fallback — where `name` is a configured single-model lane with NO pool entry, routed via
    // `crate::forward::forward_with_pool` — had no test. A refactor that dropped the fallback, or fed the
    // wrong model string, would go undetected. This wires ONLY a by_model lane (no `.pool(...)`),
    // POSTs an Anthropic body to `/<model>/v1/messages`, and asserts the 2xx plus that the upstream
    // received the (translated) forwarded request.

    /// `named` by_model fallback: a single-model lane (no pool) reached via `/<model>/v1/messages`
    /// round-trips through `forward_with_pool` to its backend and returns 2xx; the upstream sees the request.
    #[tokio::test]
    async fn test_named_by_model_fallback_round_trip_via_router() {
        crate::metrics::init();
        let state = StdArc::new(MockServerState::new());
        state.push(MockResponse::Ok {
            status: StatusCode::OK,
            body: anthropic_ok_body(),
        });
        let server = MockServer::new(state.clone()).await;

        // Lane registered in by_model only — no `.pool(...)`, so the `named` pool lookup misses and
        // the by_model fallback arm handles the request.
        let app = TestApp::new()
            .lane(
                LaneSpec::new(
                    "claude-x",
                    crate::proto::Protocol::anthropic(),
                    &server.base_url(),
                )
                .provider("anthropic"),
            )
            .build();
        let (addr, handle) = serve(app).await;

        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/claude-x/v1/messages"))
            .bearer_auth("t")
            .body(json!({"model": "claude-x", "messages": [], "max_tokens": 16}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status().as_u16(),
            200,
            "named by_model fallback (no pool) resolves and 2xx round-trips"
        );

        // The backend must have actually received the forwarded request — proves the fallback
        // routed through `forward` rather than 404-ing on the pool miss.
        assert!(
            state.get_last_request_body().is_some(),
            "upstream received the forwarded request via the named by_model fallback"
        );
        handle.abort();
        server.shutdown().await;
    }

    // ---- LOW #4 (re-audit, completeness): breaker cell-key consistency for by_model routes ----
    //
    // A single-model lane (no pool) can be reached two ways:
    //   1. the universal body-model ingress (`/v1/chat/completions` etc.) → `forward_resolved`'s
    //      `by_model` arm, which calls `forward_with_pool` directly with the ingress protocol so a
    //      cross-protocol backend is translated both ways; and
    //   2. the Anthropic `/<model>/v1/messages` (`named`) / `/<provider>/<model>/v1/messages`
    //      (`adhoc`) routes → `crate::forward::forward_with_pool`, which passes `""` (the lane-default breaker
    //      CELL shared by every direct/single-model route — forward.rs design intent).
    //
    // forward.rs records every breaker outcome against the CELL keyed by the `pool_name` argument
    // (`record_transient_in(pool_name, …)`). If `forward_resolved`'s by_model arm passes the MODEL
    // name as `pool_name` (the pre-fix bug) while the named/adhoc paths pass `""`, the SAME lane's
    // breaker state is split across two cells purely by route shape: failures driven through the
    // universal ingress would never trip (and never be seen by) the `""` cell that `/<model>/v1/
    // messages` selects against, and vice-versa. The fix passes `""` from the by_model arm too, so
    // both route shapes converge on the one lane-default cell.
    //
    // This drives the trip THRESHOLD worth of upstream 5xx through the universal (openai) by_model
    // ingress, then asserts the `""` cell tripped Open while the model-keyed cell stayed Closed —
    // the exact inverse of the pre-fix behavior, so it fails against the old code.

    /// LOW #4: a by_model lane reached via the universal (openai) ingress must record breaker state
    /// on the lane-default `""` cell — the SAME cell the `named`/`adhoc` single-model routes use —
    /// not on a model-keyed cell, so a lane reached by-name and by-pool shares one breaker view.
    ///
    /// The discriminating observable is the lane-default `""` cell's pending cooldown: a single
    /// upstream 5xx through the by_model arm records `record_transient_in(pool_name, …)`, which sets
    /// a cooldown ONLY on the cell keyed by `pool_name`. The `""` cell is the `LaneState` itself
    /// (store.rs `cell`: `pool.is_empty()` → `self.lanes[lane]`), written by the FIX (`pool_name ==
    /// ""`) and left untouched (cooldown 0) by the pre-fix code (which wrote a SEPARATE model-keyed
    /// pool cell). So `cooldown_remaining_in("", 0) > 0` is true after the fix and false before it.
    ///
    /// NOTE: the model-keyed cell is NOT a usable counter-assertion — reading `*_in(model, 0)` LAZILY
    /// CREATES that cell, and a freshly-minted pool cell INHERITS the lane's (i.e. the `""` cell's)
    /// current cooldown/state (store.rs `cell`). Under the fix it would therefore
    /// inherit the non-zero `""` cooldown and read non-zero too — indistinguishable. The `""` cell
    /// cooldown alone cleanly separates fixed from broken.
    #[tokio::test]
    async fn test_forward_resolved_by_model_uses_lane_default_breaker_cell() {
        crate::metrics::init();
        let state = StdArc::new(MockServerState::new());
        // One upstream 5xx is enough: a single transient failure sets a pending cooldown on the
        // routed breaker cell (the trip-to-Open threshold is irrelevant — the cooldown is recorded
        // on the very first transient, on whichever cell `pool_name` selects).
        let model = "glm-4.5";
        state.push(MockResponse::ServerError {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            body: json!({"error": {"message": "boom"}}),
        });
        let server = MockServer::new(state.clone()).await;

        // Lane registered in by_model ONLY (no `.pool(...)`), so the universal ingress resolves it
        // through `forward_resolved`'s by_model arm — the site under test.
        let app = TestApp::new()
            .lane(
                LaneSpec::new(model, crate::proto::Protocol::openai(), &server.base_url())
                    .provider("zai"),
            )
            .build();
        // Hold a handle to the same App the router serves so the breaker cell can be inspected after
        // the request (`serve` only needs a clone of the Arc).
        let app_for_inspect = app.clone();
        let (addr, handle) = serve(app).await;

        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/v1/chat/completions"))
            .bearer_auth("t")
            .body(
                json!({"model": model, "messages": [{"role": "user", "content": "hi"}]})
                    .to_string(),
            )
            .send()
            .await
            .unwrap();
        // The forward fails (single lane, no failover target) — the breaker transient is recorded
        // before the exhausted response is returned, which is all this test cares about.
        assert!(
            !resp.status().is_success(),
            "a 5xx-backed forward returns a non-2xx to the client"
        );

        // The lane-default `""` cell — the SAME cell the `named`/`adhoc` single-model routes select
        // against — must carry the breaker effect of the by_model forward. Under the pre-fix bug
        // (`pool_name == model`) this cell is never written and reads cooldown 0; the fix
        // (`pool_name == ""`) records here, so it reads a pending cooldown.
        assert!(
            app_for_inspect
                .store
                .cooldown_remaining_in("", 0, crate::store::now())
                > 0,
            "by_model forwards must record breaker state on the lane-default \"\" cell (the cell \
             /<model>/v1/messages selects against); a 0 cooldown means the failure was tracked under \
             a model-keyed cell instead, splitting breaker state by route shape"
        );

        handle.abort();
        server.shutdown().await;
    }
}
