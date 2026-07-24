// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;
use std::time::Instant;

use axum::{
    body::Bytes,
    extract::{OriginalUri, Path},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use serde_json::Value;

use crate::proto::{PROTO_ANTHROPIC, PROTO_BEDROCK, PROTO_GEMINI};
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
                crate::proxy::KIND_PERMISSION,
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
/// because the fallback dispatch in `proxy::handle_fallback_pool` never re-checks the key (the
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
    // A key with no restriction (`allowed_pools` omitted at mint = None) admits every pool,
    // nothing to walk. (An explicit empty list is the EMPTY set and walks like any list: every
    // pool denies.)
    key.allowed_pools.as_ref()?;
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
    pool: &str,
    charged_at: u64,
    admit: Option<crate::governance::AdmitGrant>,
) -> Option<crate::proxy::UsageSink> {
    match (&app.governance, &gov.key) {
        (Some(g), Some(key)) => Some(crate::proxy::UsageSink {
            gov: g.clone(),
            // The resolved cost model rides along (an Arc bump) so the stream-end accrual can walk
            // the key's budget-group chain without reaching back into the App snapshot.
            cost: app.cost.clone(),
            // Share the resolved key by `Arc`: no per-request `id` String clone; it is read
            // through `sink.key` at charge time.
            key: key.clone(),
            // The admitted pool: the accounting scope for pool-qualified limits (accrual mirrors
            // the admission charge).
            pool: std::sync::Arc::from(pool),
            // The header-arrival epoch this request was admitted at — reused for the token fee so it
            // shares the flat per-request fee's window (#29). See `UsageSink::charged_at`.
            charged_at,
            // The admission's in-flight HOLDS (the `concurrent` limit gauges) ride the sink so
            // they release when the response stream completes / the request context unwinds - the
            // sink is the one per-request object that provably lives to stream end. Arc'd because
            // the sink clones per failover attempt; the LAST clone dropping releases the gauges.
            admit: admit.map(std::sync::Arc::new),
        }),
        // No governance/key = nothing was admitted through the limit engine; a grant cannot exist.
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

/// Render the pool scope of a blocking limit for the client-facing rejection: a pool-qualified
/// limit caps only that pool's traffic, and saying so tells the caller the actionable part -
/// other pools may still serve them.
fn pool_scope_suffix(pool: &Option<String>) -> String {
    match pool {
        Some(p) => format!(", pool '{p}'"),
        None => String::new(),
    }
}

/// Run the atomic group-limit ADMISSION for a request that is about to be forwarded (the P4
/// generic limit engine). `Ok(Some(grant))` = admitted AND charged (the flat per-request fee + one
/// request landed on every chain bucket; a non-2xx must refund, and the grant holds the
/// `concurrent` in-flight gauges until the response completes). `Ok(None)` = admitted WITHOUT a
/// charge (governance off / no key) - a non-2xx must NOT refund, because `refund_request` is a
/// blind decrement that would erode ANOTHER request's spend/count in the same window (see
/// `finish_rejected`). `Err(resp)` = rejected with the protocol-native error NAMING the exact
/// blocking bucket (group + metric + window).
///
/// The admission window is keyed off `charged_at` (the pinned header-arrival epoch), NOT a fresh
/// `store::now()`: the token fee (`UsageSink::charged_at` -> `record_usage`) bills into the SAME
/// window, so a request straddling a window boundary can never split its charges (#29).
fn admit_check(
    app: &Arc<App>,
    gov: &crate::governance::GovCtx,
    proto: &str,
    pool: &str,
    charged_at: u64,
) -> Result<(Option<crate::governance::AdmitGrant>, Option<String>), Box<Response>> {
    let (Some(g), Some(key)) = (&app.governance, &gov.key) else {
        // Governance off or no resolved key → no charge landed; nothing to refund on a non-2xx.
        return Ok((None, None));
    };
    // ONE indivisible check-and-charge over the whole chain: every group's every limit must admit
    // (AND / most-restrictive) and every bucket is charged in the same critical section - N
    // concurrent requests can never each read "under the cap" and all charge. Infallible
    // in-memory (write-behind store): admission never blocks on or fails from the durable store.
    //
    // BUDGET DOWNGRADE (§6c "budgets that teach"): a budget block whose limit declared
    // `on_exhaust: downgrade` re-admits through `downgrade_to` instead of refusing - the caller's
    // expensive traffic gets CHEAPER, not blocked. The chain may cascade (value's own budget may
    // downgrade further); a visited set bounds it, and every hop re-runs the key's pool ACL (a
    // downgrade must never route a key into a pool it may not use). The charge lands on the
    // EFFECTIVE pool's buckets, and the caller dispatches there - accounting follows the traffic.
    let mut effective: Option<String> = None;
    let mut visited: Vec<String> = Vec::new();
    let blocked = loop {
        let attempt_pool = effective.as_deref().unwrap_or(pool);
        match g.try_admit(&app.cost, key, attempt_pool, charged_at) {
            Ok(grant) => return Ok((Some(grant), effective)),
            Err(crate::governance::LimitBlocked::Limit {
                downgrade_to: Some(to),
                group,
                ..
            }) if !visited.iter().any(|v| v == &to)
                && visited.len() < app.pools.len()
                && app.pools.contains_key(&to)
                && pool_authorized(gov, &to, proto).is_none()
                && fallback_pools_authorized(app, gov, &to, proto).is_none() =>
            {
                tracing::info!(key_id = %key.id, from = attempt_pool, to = %to, group = %group,
                    "governance: budget exhausted; downgrading pool (on_exhaust: downgrade)");
                visited.push(to.clone());
                effective = Some(to);
            }
            Err(blocked) => break blocked,
        }
    };
    {
        // The rejection NAMES WHICH BUCKET blocked (group + metric + window). The key ID
        // itself is never echoed; a group name is an operator-chosen, caller-meaningful
        // bucket label, not an internal credential handle. Server-side tracing records the
        // full detail either way.
        tracing::info!(key_id = %key.id, blocked = ?blocked, "governance: limit bucket blocked admission");
        use crate::governance::LimitBlocked;
        let (status, kind, message, retry_after) = match &blocked {
            LimitBlocked::Limit {
                group,
                metric: metric @ ("requests" | "tokens"),
                window,
                pool: limit_pool,
                retry_after,
                ..
            } => (
                StatusCode::TOO_MANY_REQUESTS,
                crate::proxy::KIND_RATE_LIMIT,
                format!(
                    "Rate limit exceeded (group '{group}': {metric} per {}{}). Please retry \
                         after the indicated time.",
                    window.unwrap_or("total"),
                    pool_scope_suffix(limit_pool),
                ),
                *retry_after,
            ),
            LimitBlocked::Limit {
                group,
                metric: "concurrent",
                ..
            } => (
                StatusCode::TOO_MANY_REQUESTS,
                crate::proxy::KIND_RATE_LIMIT,
                format!(
                    "Too many concurrent requests (group '{group}' is at its in-flight \
                         limit). Please retry shortly."
                ),
                None,
            ),
            LimitBlocked::Limit {
                group,
                window,
                pool: limit_pool,
                retry_after,
                ..
            } => (
                // Native quota status differs by vendor (Bedrock's
                // ServiceQuotaExceededException is 400; every other vendor surfaces
                // over-quota as 429). The writer owns that mapping.
                crate::proto::protocol_for(proto)
                    .map(|p| p.writer().quota_exceeded_status())
                    .unwrap_or(StatusCode::TOO_MANY_REQUESTS),
                crate::proxy::KIND_INSUFFICIENT_QUOTA,
                format!(
                    "You have exceeded your current quota (group '{group}' budget per {}{} \
                         exhausted). Please check your plan and billing details.",
                    window.unwrap_or("total"),
                    pool_scope_suffix(limit_pool),
                ),
                *retry_after,
            ),
            // A FROZEN group (`enabled: false`) is an administrative freeze, not a quota: the
            // vendor-plausible shape is a permission denial.
            LimitBlocked::Disabled(group) => (
                StatusCode::FORBIDDEN,
                crate::proxy::KIND_PERMISSION,
                format!(
                    "Your API key does not currently have access to this resource (group \
                         '{group}' is disabled)."
                ),
                None,
            ),
            // FAIL-CLOSED: a key bound to a group this node's config does not know is not
            // admitted; the message names the missing bucket so the operator can fix it.
            LimitBlocked::MissingGroup(group) => (
                crate::proto::protocol_for(proto)
                    .map(|p| p.writer().quota_exceeded_status())
                    .unwrap_or(StatusCode::TOO_MANY_REQUESTS),
                crate::proxy::KIND_INSUFFICIENT_QUOTA,
                format!(
                    "Your quota configuration is incomplete (group '{group}' is not \
                         configured). Please contact your administrator."
                ),
                None,
            ),
        };
        let mut resp = ingress_error(proto, status, kind, &message);
        // Standard `Retry-After` for a rolling window so a well-behaved SDK backs off the
        // right amount ('total' never rolls: no header).
        if let Some(retry) = retry_after {
            if let Ok(hv) = axum::http::HeaderValue::from_str(&retry.to_string()) {
                resp.headers_mut()
                    .insert(axum::http::header::RETRY_AFTER, hv);
            }
        }
        Err(Box::new(resp))
    }
}

/// Run the governance guards (pool ACL / unpriced-model / the atomic group-limit admission) for a
/// request that is about to be forwarded. Returns the protocol-native rejection response already
/// passed through `finish_rejected`. The statuses are deliberately vendor-faithful and never 402:
/// pool-not-allowed and a frozen group map to 403, an exhausted budget maps to the vendor's quota
/// status (Bedrock's quota shape is a 400-class error, see `admit_check`), and requests / tokens /
/// concurrent limits map to 429 (+ `Retry-After` for rolling windows). busbar never emits 402 here
/// a blanket 402 was a vendor-agnostic tell, since no real provider returns 402 for these
/// conditions. Routing through `finish_rejected` means a governance-rejected request still emits
/// `REQUESTS_TOTAL`, the `REQUEST_DURATION_SECONDS` histogram, and the request-log webhook.
/// `Ok((Some(grant), effective_pool))` = admitted + charged (see `admit_check`); the caller
/// threads the grant into the request's `UsageSink` so the in-flight holds release at stream end,
/// and — when `effective_pool` is `Some` — DISPATCHES through that pool instead of the requested
/// one (a budget `on_exhaust: downgrade` fired; the charge already landed on the effective pool's
/// buckets, so routing must follow the accounting).
fn governance_guard(
    app: &Arc<App>,
    gov: &crate::governance::GovCtx,
    proto: &'static str,
    pool: &str,
    started: Instant,
    charged_at: u64,
) -> Result<(Option<crate::governance::AdmitGrant>, Option<String>), Box<Response>> {
    // A governance rejection fires BEFORE the model is resolved to a configured pool, so the raw
    // client-supplied `pool` string must be mapped to the bounded metric label (metrics.rs)
    // before it reaches `finish` (which stamps it onto REQUESTS_TOTAL / the duration histogram /
    // the request-log webhook). Passing it raw was an unbounded-cardinality DoS vector.
    let label = pool_label(app, pool);
    if let Some(resp) = pool_authorized(gov, pool, proto) {
        return Err(Box::new(finish_rejected(
            app, gov, proto, label, started, charged_at, resp,
        )));
    }
    // The initial-pool ACL passed, but the requested pool may be configured to fail over to a
    // FALLBACK pool on exhaustion (`OnExhausted::FallbackPool`). Re-enforce the key's `allowed_pools`
    // against every fallback pool reachable from here, so a key restricted to pool A can never be
    // served by a fallback pool B it is not allowed to use (the fallback dispatch in
    // `proxy::handle_fallback_pool` does not — and cannot — re-check the key; the ACL is enforced
    // at this ingress boundary). A denial is the SAME protocol-native 403 the initial check emits.
    if let Some(resp) = fallback_pools_authorized(app, gov, pool, proto) {
        return Err(Box::new(finish_rejected(
            app, gov, proto, label, started, charged_at, resp,
        )));
    }
    // ALL-OR-NOTHING pricing, fail-closed arm: when a rate card is PRESENT, every governed request
    // must resolve to a priced model. A configured pool / by-model lane is priced by construction
    // (`--validate`/boot enforce rate-card completeness over config.models), so only an ARBITRARY
    // passthrough model string can be unpriced - reject it with a clear error rather than serve
    // tokens that cannot be billed. Zero-cost when no rate card is configured (one bool), and a
    // single borrowed map probe otherwise.
    if gov.key.is_some()
        && app.cost.pricing_enabled()
        && !app.pools.contains_key(pool)
        && !app.by_model.contains_key(pool)
        && app.cost.model_unpriced(pool)
    {
        tracing::info!(model = %pool, "governance: no configured rate for model; rejecting (rate_card is authoritative and complete)");
        let resp = ingress_error(
            proto,
            StatusCode::BAD_REQUEST,
            crate::proxy::KIND_INVALID_REQUEST,
            &format!("no configured rate for model '{pool}'"),
        );
        return Err(Box::new(finish_rejected(
            app, gov, proto, label, started, charged_at, resp,
        )));
    }
    // The atomic group-limit ADMISSION runs LAST: it CHARGES every chain bucket on admit, so
    // nothing may reject an already-charged request after it. On rejection nothing was charged →
    // `finish_rejected` (no refund). On admission the returned grant reports whether the charge
    // LANDED (`Some` = refund on non-2xx) and holds the `concurrent` in-flight gauges.
    match admit_check(app, gov, proto, pool, charged_at) {
        Err(resp) => Err(Box::new(finish_rejected(
            app, gov, proto, label, started, charged_at, *resp,
        ))),
        Ok(admitted) => Ok(admitted),
    }
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
        crate::proxy::POOL_LABEL_UNRESOLVED
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
///
/// Test-only now: every production admission threads the `charged` flag through
/// [`finish_admitted`] (a store-error fail-open admit must not refund); this unconditional-refund
/// form survives only for the in-module tests that always charge.
#[cfg(test)]
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

/// Post-admission finish whose non-2xx refund is CONDITIONAL on whether the flat fee actually landed
/// at admission (`charged`, from `governance_guard`). Admitting a request WITHOUT charging (store-
/// error fail-open, or governance off) and then refunding on a non-2xx would blind-decrement OTHER
/// requests' spend/count in the same window — so those requests must finish with `charged = false`.
/// (found: audit c2r1.)
#[allow(clippy::too_many_arguments)]
fn finish_admitted(
    app: &Arc<App>,
    gov: &crate::governance::GovCtx,
    ingress_protocol: &str,
    pool: &str,
    started: Instant,
    charged_at: u64,
    resp: Response,
    charged: bool,
) -> Response {
    finish_inner(
        app,
        gov,
        ingress_protocol,
        pool,
        started,
        charged_at,
        resp,
        charged,
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
    // FINISH stage: metrics record + request-log gate + non-2xx refund check (zero cost unprofiled).
    let _fin = crate::profile::start(crate::profile::Stage::Finish);
    let outcome = match resp.status().as_u16() {
        200..=299 => "ok",
        503 => "exhausted",
        400..=499 => "client_error",
        _ => "error",
    };
    // Per-request emits via the TELEMETRY BANK (telemetry.rs): a plain add into THIS thread's
    // pre-registered cells — no shared-atomic contention, no per-request `Label`/`Key` allocation,
    // no registry probe. The scrape-time aggregator folds the cells into the recorder, so the
    // rendered series/values are identical to the macro emission. Unregistered label values (e.g.
    // a bare test `App`) fall back to the cached-handle helpers in `metrics.rs` inside the helper.
    let elapsed = started.elapsed();
    crate::telemetry::request_finished(app, ingress_protocol, pool, outcome, elapsed.as_secs_f64());

    // best-effort request-log webhook (no-op unless configured). Gated on the configured check so an
    // unconfigured webhook (the default) skips even BUILDING the JSON payload — `fire_request_log`
    // would only drop it; when configured, the payload/delivery are unchanged.
    if crate::observability::request_log_configured() {
        crate::observability::fire_request_log(crate::observability::build_request_log(
            crate::store::now(),
            ingress_protocol,
            pool,
            outcome,
            elapsed.as_millis() as u64,
        ));
    }

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
            g.refund_request(&app.cost, key, pool, charged_at);
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
/// Thin delegation to the CANONICAL `crate::proxy::ingress_error` (the single
/// source of truth for native error shaping + per-protocol headers — Bedrock
/// `x-amzn-RequestId`/`x-amzn-errortype` via the `ProtocolWriter::attach_error_response_headers` vtable method (BedrockWriter delegates to its private helper), the generic
/// fallback envelope, etc.). Keeping ingress on this one function rather than a private copy means
/// route/forward error shaping cannot drift. The route call sites (and the in-module tests) keep
/// the short `proto`/`message` parameter names; the canonical fn names them `ingress`/`msg`.
fn ingress_error(proto: &str, status: StatusCode, kind: &str, message: &str) -> Response {
    crate::proxy::ingress_error(proto, status, kind, message)
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
    operation: crate::operation::Operation,
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
                crate::proxy::POOL_LABEL_UNRESOLVED,
                started,
                charged_at,
                ingress_error(
                    proto,
                    StatusCode::BAD_REQUEST,
                    crate::proxy::KIND_INVALID_REQUEST,
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
            // resolved through the writer vtable by protocol NAME — ingress names no protocol
            // submodule, so "delete proto/gemini → app is gemini-free" holds. The shim is stripped
            // before the upstream call (`proxy::strip_router_shim_keys`); cross-protocol egress
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
                crate::proxy::POOL_LABEL_UNRESOLVED,
                started,
                charged_at,
                ingress_error(
                    proto,
                    StatusCode::BAD_REQUEST,
                    crate::proxy::KIND_INVALID_REQUEST,
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
                crate::proxy::POOL_LABEL_UNRESOLVED,
                started,
                charged_at,
                ingress_error(
                    proto,
                    StatusCode::BAD_REQUEST,
                    crate::proxy::KIND_INVALID_REQUEST,
                    "The request body could not be processed.",
                ),
            );
        }
    };

    // UNIVERSAL: the caller (that protocol's routing arm) already resolved WHICH operation this is
    // (`RequestHandler::resolve_operation`); look its handler up through the registry — identical
    // for every protocol and operation. This arm's only per-protocol work was the URL parsing above.
    let Some(op_handler) =
        crate::handlers::request_handler(proto).and_then(|rh| rh.operation_handler(operation))
    else {
        return finish_rejected(
            app,
            gov,
            proto,
            crate::proxy::POOL_LABEL_UNRESOLVED,
            started,
            charged_at,
            ingress_error(
                proto,
                StatusCode::NOT_FOUND,
                crate::proxy::KIND_NOT_FOUND,
                "This endpoint does not support that operation.",
            ),
        );
    };
    operation_resolved(
        app,
        gov,
        proto,
        operation,
        op_handler,
        model,
        headers,
        injected,
        // Path-model ingress already parsed (and shim-injected into) the body — carry the DOM
        // eagerly; the engine's pristine head check reads it directly and behaves as before.
        Some(crate::proxy::LazyBody::from_value(v)),
        caller_token,
        started,
        charged_at,
        gemini_api_version,
    )
    .await
}

mod dispatch;
pub(crate) use dispatch::{operation_resolved, protocol_dispatch};
// The universal ingress entry — live callers sit inside `dispatch` itself; tests drive it directly.
#[cfg(test)]
pub(crate) use dispatch::operation_ingress;

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
#[tracing::instrument(level = "debug", name = "gemini_ingress", skip_all)]
pub(crate) async fn gemini_ingress(
    crate::state::CurrentApp(app): crate::state::CurrentApp,
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
                    crate::proxy::POOL_LABEL_UNRESOLVED,
                    started,
                    charged_at,
                    ingress_error(
                        envelope_proto,
                        StatusCode::NOT_FOUND,
                        crate::proxy::KIND_NOT_FOUND,
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
                crate::proxy::POOL_LABEL_UNRESOLVED,
                started,
                charged_at,
                ingress_error(
                    envelope_proto,
                    StatusCode::NOT_FOUND,
                    crate::proxy::KIND_NOT_FOUND,
                    "the requested resource was not found",
                ),
            );
        }
    };

    // The gemini RequestHandler resolves WHICH operation this request is (path action + body for the
    // generateContent multiplex) — ONE resolution, and every operation takes the SAME flow below.
    let operation = crate::handlers::request_handler(PROTO_GEMINI)
        .and_then(|rh| rh.resolve_operation(uri.path(), &body));

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
    let stream = match (operation.is_some(), action) {
        (true, "streamGenerateContent") => true,
        (true, _) => false, // generateContent / embedContent / predict — non-stream in 1.2
        (false, other) => {
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
                    crate::proxy::POOL_LABEL_UNRESOLVED,
                    started,
                    charged_at,
                    ingress_error(
                        envelope_proto,
                        StatusCode::NOT_FOUND,
                        crate::proxy::KIND_NOT_FOUND,
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
                crate::proxy::POOL_LABEL_UNRESOLVED,
                started,
                charged_at,
                ingress_error(
                    envelope_proto,
                    StatusCode::NOT_FOUND,
                    crate::proxy::KIND_NOT_FOUND,
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

    // `operation` is Some here (a None already returned the unsupported-action envelope above);
    // bail with the standard no-handler 404 rather than assume any operation.
    let Some(operation) = operation else {
        return finish_rejected(
            &app,
            &gov,
            PROTO_GEMINI,
            crate::proxy::POOL_LABEL_UNRESOLVED,
            started,
            charged_at,
            ingress_error(
                PROTO_GEMINI,
                StatusCode::NOT_FOUND,
                crate::proxy::KIND_NOT_FOUND,
                "This endpoint does not support that operation.",
            ),
        );
    };
    ingress_path_model(
        &app,
        &gov,
        &caller,
        &headers,
        body,
        model,
        operation,
        stream,
        gemini_json_array,
        PROTO_GEMINI,
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
#[tracing::instrument(level = "debug", name = "bedrock_converse", skip_all)]
pub(crate) async fn bedrock_converse(
    crate::state::CurrentApp(app): crate::state::CurrentApp,
    Path(model_id): Path<String>,
    axum::extract::Extension(gov): axum::extract::Extension<crate::governance::GovCtx>,
    axum::extract::Extension(caller): axum::extract::Extension<crate::auth::CallerToken>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(op) = crate::handlers::request_handler(PROTO_BEDROCK)
        .and_then(|rh| rh.resolve_operation(&format!("/model/{model_id}/converse"), &body))
    else {
        return ingress_error(
            PROTO_BEDROCK,
            StatusCode::NOT_FOUND,
            crate::proxy::KIND_NOT_FOUND,
            "This endpoint does not support that operation.",
        );
    };
    bedrock_ingress(&app, &gov, &caller, &headers, body, &model_id, op, false).await
}

// POST /model/:modelId/converse-stream — Bedrock Converse ingress (streaming, stream=true). The
// upstream stream is re-encoded into binary `application/vnd.amazon.eventstream` frames (one
// CRC32-valid frame per event via `eventstream::encode_frame`, wired through
// `StreamTranslate::ingress_eventstream`) so a native AWS SDK Bedrock client decodes the response as
// ConverseStream.
#[tracing::instrument(level = "debug", name = "bedrock_converse_stream", skip_all)]
pub(crate) async fn bedrock_converse_stream(
    crate::state::CurrentApp(app): crate::state::CurrentApp,
    Path(model_id): Path<String>,
    axum::extract::Extension(gov): axum::extract::Extension<crate::governance::GovCtx>,
    axum::extract::Extension(caller): axum::extract::Extension<crate::auth::CallerToken>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(op) = crate::handlers::request_handler(PROTO_BEDROCK)
        .and_then(|rh| rh.resolve_operation(&format!("/model/{model_id}/converse-stream"), &body))
    else {
        return ingress_error(
            PROTO_BEDROCK,
            StatusCode::NOT_FOUND,
            crate::proxy::KIND_NOT_FOUND,
            "This endpoint does not support that operation.",
        );
    };
    bedrock_ingress(&app, &gov, &caller, &headers, body, &model_id, op, true).await
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
#[allow(clippy::too_many_arguments)]
async fn bedrock_ingress(
    app: &Arc<App>,
    gov: &crate::governance::GovCtx,
    caller: &crate::auth::CallerToken,
    headers: &HeaderMap,
    body: Bytes,
    model_id: &str,
    operation: crate::operation::Operation,
    stream: bool,
) -> Response {
    // Bedrock never uses the gemini JSON-array framing, and a model-not-found 404 uses the canonical
    // (non-gemini) message, so no api_version is threaded.
    ingress_path_model(
        app,
        gov,
        caller,
        headers,
        body,
        model_id,
        operation,
        stream,
        false,
        PROTO_BEDROCK,
        None,
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
#[tracing::instrument(level = "debug", name = "named", skip_all, fields(pool = %name))]
pub(crate) async fn named(
    crate::state::CurrentApp(app): crate::state::CurrentApp,
    Path(name): Path<String>,
    axum::extract::Extension(gov): axum::extract::Extension<crate::governance::GovCtx>,
    axum::extract::Extension(caller): axum::extract::Extension<crate::auth::CallerToken>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // Deletion switch (chat is a standard operation): the named/adhoc conveniences are the
    // anthropic-dialect chat surface, so they consult the anthropic chat OperationHandler exactly
    // like the catch-all does. Absent handler → the standard no-handler 404 in the caller's dialect.
    if crate::handlers::request_handler(PROTO_ANTHROPIC)
        .and_then(|rh| rh.operation_handler(crate::operation::Operation::Chat))
        .is_none()
    {
        return crate::proxy::ingress_error(
            PROTO_ANTHROPIC,
            StatusCode::NOT_FOUND,
            crate::proxy::KIND_NOT_FOUND,
            "This endpoint does not support that operation.",
        );
    }
    // Caller's bearer token (for passthrough-mode forwarding); None falls back to the lane's key.
    let caller_token = caller.0.as_deref();
    // `started` is taken BEFORE the governance guards so a governance-rejected request still
    // records a (small) wall-clock duration and is counted via `finish`.
    let started = Instant::now();
    // Header-arrival epoch pinned once; reused for both the per-request and token fees (#29).
    let charged_at = crate::store::now();

    // Governance guards (pool ACL / group limits); a rejection is wrapped in `finish_rejected`
    // inside `governance_guard` (this handler just returns that response). On admission the grant
    // reports whether the fee was CHARGED (refund gate) and holds the in-flight gauges.
    let (admit, downgraded) =
        match governance_guard(&app, &gov, PROTO_ANTHROPIC, &name, started, charged_at) {
            Err(resp) => return *resp,
            Ok(admitted) => admitted,
        };
    let charged = admit.is_some();
    // A budget downgrade (§6c) re-pooled the admission: dispatch where the charge landed.
    let name = downgraded.unwrap_or(name);

    if let Some(cands) = app.pools.get(&name) {
        let affinity_key = headers
            .get(affinity_header_for(&app, &name))
            .and_then(|v| v.to_str().ok());
        let resp = crate::proxy::forward_with_pool_keyed(
            app.clone(),
            cands.clone(),
            body,
            caller_token,
            // Thread the resolved/synthesized key so a group/SSO principal's usage/send_user pool
            // policy sees rate_headroom/identity here too (not just the universal dispatch path).
            gov.key.as_ref(),
            &name,
            affinity_key,
            PROTO_ANTHROPIC,
            crate::handlers::chat(PROTO_ANTHROPIC),
            usage_sink(&app, &gov, &name, charged_at, admit),
        )
        .await;
        return finish_admitted(
            &app,
            &gov,
            PROTO_ANTHROPIC,
            &name,
            started,
            charged_at,
            resp,
            charged,
        );
    }
    if let Some(&i) = app.by_model.get(&name) {
        // Model-based routing: anthropic ingress, lane-default breaker OperationHandler (empty pool name → the
        // op_handler shared by all direct/ad-hoc routes, surfaced by /stats and /healthz), no affinity.
        let resp = crate::proxy::forward_with_pool_keyed(
            app.clone(),
            vec![WeightedLane {
                reasoning: None,
                idx: i,
                weight: 1,
                attempt_timeout_ms: None,
            }],
            body,
            caller_token,
            gov.key.as_ref(),
            "",
            None,
            PROTO_ANTHROPIC,
            crate::handlers::chat(PROTO_ANTHROPIC),
            usage_sink(&app, &gov, "", charged_at, admit),
        )
        .await;
        return finish_admitted(
            &app,
            &gov,
            PROTO_ANTHROPIC,
            &name,
            started,
            charged_at,
            resp,
            charged,
        );
    }

    // Model/pool miss: wrap the 404 in `finish` so it is still counted in REQUESTS_TOTAL /
    // REQUEST_DURATION_SECONDS and fires the request-log webhook — the same observability invariant
    // already enforced for governance rejections (a raw early-return made the miss invisible).
    // Both maps missed, so `name` is an unresolved, client-supplied URL segment — stamp the bounded
    // sentinel as the `pool` label (metrics.rs), never the raw segment (unbounded-cardinality
    // DoS). `pool_label` returns `"unresolved"` here by construction.
    finish_admitted(
        &app,
        &gov,
        PROTO_ANTHROPIC,
        pool_label(&app, &name),
        started,
        charged_at,
        ingress_error(
            PROTO_ANTHROPIC,
            StatusCode::NOT_FOUND,
            crate::proxy::KIND_NOT_FOUND,
            // Anthropic ingress: canonical (non-gemini) model-not-found copy.
            &not_found_message(&name, None),
        ),
        charged,
    )
}

// POST /<provider>/<model>/v1/messages — ad-hoc direct
#[tracing::instrument(level = "debug", name = "adhoc", skip_all, fields(provider = %provider, model = %model))]
pub(crate) async fn adhoc(
    crate::state::CurrentApp(app): crate::state::CurrentApp,
    Path((provider, model)): Path<(String, String)>,
    axum::extract::Extension(gov): axum::extract::Extension<crate::governance::GovCtx>,
    axum::extract::Extension(caller): axum::extract::Extension<crate::auth::CallerToken>,
    body: Bytes,
) -> Response {
    // Deletion switch — same consult as `named` (this is the other anthropic-dialect chat surface).
    if crate::handlers::request_handler(PROTO_ANTHROPIC)
        .and_then(|rh| rh.operation_handler(crate::operation::Operation::Chat))
        .is_none()
    {
        return crate::proxy::ingress_error(
            PROTO_ANTHROPIC,
            StatusCode::NOT_FOUND,
            crate::proxy::KIND_NOT_FOUND,
            "This endpoint does not support that operation.",
        );
    }
    let caller_token = caller.0.as_deref();
    let started = Instant::now();
    // Header-arrival epoch pinned once; reused for both the per-request and token fees (#29).
    let charged_at = crate::store::now();

    // Governance guards (pool ACL / group limits); a rejection is wrapped in `finish_rejected`
    // inside `governance_guard` (this handler just returns that response). `charged` gates the
    // post-admission refund so an un-charged (governance-off) admit never blind-refunds.
    // Ad-hoc by-model dispatch: the admission "pool" is the model name, which is not a
    // configured pool, so pool-scoped buckets (and their downgrades) do not participate;
    // the effective pool is always the requested one.
    let (admit, _downgraded) =
        match governance_guard(&app, &gov, PROTO_ANTHROPIC, &model, started, charged_at) {
            Err(resp) => return *resp,
            Ok(admitted) => admitted,
        };
    let charged = admit.is_some();

    match app.by_model.get(&model) {
        Some(&i) if app.lanes[i].provider == provider => {
            // Single lane with weight=1 (default for ad-hoc routing): anthropic ingress, lane-default
            // breaker OperationHandler (empty pool name), no affinity.
            let resp = crate::proxy::forward_with_pool_keyed(
                app.clone(),
                vec![WeightedLane {
                    reasoning: None,
                    idx: i,
                    weight: 1,
                    attempt_timeout_ms: None,
                }],
                body,
                caller_token,
                gov.key.as_ref(),
                "",
                None,
                PROTO_ANTHROPIC,
                crate::handlers::chat(PROTO_ANTHROPIC),
                usage_sink(&app, &gov, "", charged_at, admit),
            )
            .await;
            finish_admitted(
                &app,
                &gov,
                PROTO_ANTHROPIC,
                &model,
                started,
                charged_at,
                resp,
                charged,
            )
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
            finish_admitted(
                &app,
                &gov,
                PROTO_ANTHROPIC,
                pool_label(&app, &model),
                started,
                charged_at,
                ingress_error(
                    PROTO_ANTHROPIC,
                    StatusCode::BAD_REQUEST,
                    crate::proxy::KIND_INVALID_REQUEST,
                    // Anthropic ingress: canonical (non-gemini) model-not-found copy.
                    &not_found_message(&model, None),
                ),
                charged,
            )
        }
        // Model miss: `model` is an unresolved, client-supplied string — stamp the bounded sentinel
        // as the `pool` label (metrics.rs). `pool_label` returns `"unresolved"` here.
        None => finish_admitted(
            &app,
            &gov,
            PROTO_ANTHROPIC,
            pool_label(&app, &model),
            started,
            charged_at,
            ingress_error(
                PROTO_ANTHROPIC,
                StatusCode::NOT_FOUND,
                crate::proxy::KIND_NOT_FOUND,
                // Anthropic ingress: canonical (non-gemini) model-not-found copy.
                &not_found_message(&model, None),
            ),
            charged,
        ),
    }
}

#[cfg(test)]
#[path = "tests/tests.rs"]
mod tests;
