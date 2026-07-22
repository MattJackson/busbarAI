use super::*;

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
    resolved_gov_key: Option<&std::sync::Arc<crate::governance::VirtualKey>>,
    pool_name: &str,
    affinity_key: Option<&str>,
    ingress_protocol: &str,
    op: crate::handlers::Op,
    usage_sink: Option<UsageSink>,
) -> Response {
    // Validate + head-project WITHOUT building a DOM (same malformed-body 400 contract as the old
    // eager parse — `LazyBody::parse` goes through the identical `crate::json` guard + parser).
    let v: LazyBody = match LazyBody::parse(&body) {
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
// `level = "debug"`: at the default info filter this span is DISABLED at the callsite (one relaxed
// atomic check) instead of allocating a span + formatting three fields on every request. The
// info-level events on the rejection paths carry their own pool/policy fields, so no info-level
// log line loses context; run with RUST_LOG=busbar=debug to get the span back.
#[tracing::instrument(
    level = "debug",
    name = "forward",
    skip_all,
    fields(pool = %pool_name, ingress = %ingress_protocol, op = op.name())
)]
pub(crate) async fn forward_with_pool_parsed(
    app: Arc<App>,
    cands: Vec<WeightedLane>,
    body: Bytes,
    mut v: Option<LazyBody>,
    req_content_type: &str,
    caller_token: Option<&str>,
    resolved_gov_key: Option<&std::sync::Arc<crate::governance::VirtualKey>>,
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
        // `stream` is a captured head key — read it via `probe` (no DOM needed); the SHAPE capture
        // reads arbitrary body fields, so materialize the DOM (taps are configured — the DOM was
        // going to be built for the request stages anyway).
        let stream = v
            .as_ref()
            .and_then(|b| b.probe().get("stream"))
            .and_then(|s| s.as_bool())
            .unwrap_or(false);
        let dom: Option<&Value> = match v.as_mut() {
            Some(l) => l.ensure_dom().ok().map(|m| &*m),
            None => None,
        };
        Some(capture_stage_shape(
            dom,
            pool_name,
            ingress_protocol,
            stream,
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
pub(crate) async fn forward_with_pool_parsed_inner(
    app: Arc<App>,
    cands: Vec<WeightedLane>,
    mut body: Bytes,
    // The request body VALIDATED once by the caller for JSON-body operations, carried as a
    // `LazyBody` (head projection + on-demand DOM); `None` for an OPAQUE ingress body (multipart
    // transcription, binary) — those relay/translate at the BYTE level via the operation codecs and
    // skip every JSON-only read below. The top-level point reads below (`stream`, affinity `system`,
    // shim keys) go through the head `probe`; the full DOM is materialized ONLY when a consumer
    // needs the tree (rewrite hooks, taps, gates/policies, cross-protocol translation, failover).
    // `mut` so the global rewrite pass can materialize + mutate it before dispatch.
    mut v: Option<LazyBody>,
    // The ingress request Content-Type — the byte-level codec's parse hint (multipart boundary).
    req_content_type: &str,
    caller_token: Option<&str>,
    // The key the auth layer already resolved/synthesized for this caller (`GovCtx.key`) — used as
    // the routing-signal source when the token is not a virtual-key secret (group/SSO principals).
    resolved_gov_key: Option<&std::sync::Arc<crate::governance::VirtualKey>>,
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
    // Stage profiler: PREPARE spans all pre-dispatch bookkeeping (op-support filter, wants_stream +
    // affinity derivation, failover/breaker config) up to the failover loop. Zero cost when
    // `BUSBAR_PROFILE` is unset — `start` returns `None` and takes no `Instant`.
    let _prep = crate::profile::start(crate::profile::Stage::Prepare);
    // EGRESS deletion switch (design §3, same contract as `forward_operation`): every candidate
    // lane's protocol must HOLD this operation's handler. A protocol whose handler was deleted is
    // not a valid egress for the operation — a clean no-handler 404 in the CALLER's dialect, never a
    // silent dispatch. Dormant while all six protocols serve chat; load-bearing the moment one is
    // removed (the deletion test).
    let mut cands: Vec<WeightedLane> = {
        let supports = |wl: &WeightedLane| {
            crate::handlers::request_handler(app.lanes[wl.idx].protocol.name())
                .and_then(|rh| rh.operation_handler(op.operation))
                .is_some()
        };
        // Fast path (the norm: every registered protocol serves every 1.x operation): all candidates
        // support the operation, so keep the caller's Vec as-is — no partition, no re-allocation.
        // Only when at least one lane lacks the handler do we pay the filter; semantics identical to
        // the previous `partition` (an all-dropped non-empty set is the same no-handler 404, and an
        // initially-empty set passes through to the pool-empty 503 below either way).
        if cands.iter().all(supports) {
            cands
        } else {
            let kept: Vec<WeightedLane> = cands.into_iter().filter(|wl| supports(wl)).collect();
            if kept.is_empty() {
                return ingress_error(
                    ingress_protocol,
                    StatusCode::NOT_FOUND,
                    KIND_NOT_FOUND,
                    DETAIL_MODEL_UNSUPPORTED_OPERATION,
                );
            }
            kept
        }
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
    // `probe()` answers this from the head projection (chat reads only the top-level `stream`
    // boolean — a captured head key) without materializing the DOM; once a DOM exists, `probe()` IS
    // the DOM, so the read is byte-identical either way.
    let wants_stream = v
        .as_ref()
        .map(|l| op.wants_stream(l.probe()))
        .unwrap_or(false);

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
        if let Some(lazy) = v.as_mut() {
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
            // Rewrite hooks mutate the tree — materialize the DOM (rewrite paths always paid this
            // parse). The unreachable-in-practice parse failure (these bytes already validated)
            // fails CLOSED, matching the rewrite guarantee's serialize guard below.
            let Ok(parsed) = lazy.ensure_dom() else {
                tracing::error!(
                    "materializing the validated request body for the rewrite pass failed; \
                     rejecting rather than forwarding un-rewritten"
                );
                return reject(500, "request rewrite could not be applied".to_string());
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
                    // A `prompt: rw` rewrite is a TRUSTED, possibly security-critical transform. If it
                    // cannot be serialized into the retained bytes, the first hop carries it but every
                    // FAILOVER hop (which re-parses `body`) would forward the ORIGINAL un-rewritten
                    // request — fail-OPEN on the rewrite guarantee. Fail CLOSED: reject rather than
                    // leak the un-rewritten body to a fallback lane. (Not realistically reachable;
                    // defense-in-depth for the rewrite invariant.)
                    Err(e) => {
                        tracing::error!(error = %e, "re-serializing a committed rewrite failed; rejecting to avoid forwarding the un-rewritten request on failover");
                        return reject(500, "request rewrite could not be applied".to_string());
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
    // Hoisted empty check (mirrors `fire_global_taps`'s own first-line early return) so the DOM is
    // only materialized when a tap is actually configured — ZERO COST stays zero-parse.
    if !app.tap_hooks.is_empty() {
        if let Some(Ok(body)) = v.as_mut().map(|l| l.ensure_dom()) {
            fire_global_taps(&app, body, pool_name, ingress_protocol, wants_stream);
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
                        // The shim key is a captured head key — `probe()` answers without a DOM.
                        .map(|l| p.writer().wants_array_stream(l.probe()))
                        .unwrap_or(false)
            })
            .unwrap_or(false);

    // Derive the affinity HASH early (before any mutations to v), from BORROWED bytes — the sticky
    // preference needs only `stable_hash(key)`, never the owned string, so hashing here avoids a
    // per-request `String` allocation. Prefer the supplied header key; else fall back to the
    // operation's body-derived key (chat: the top-level `system` string — byte-identical selection to
    // the previous owned-String read; other ops: no body affinity). `None` = no sticky preference.
    let affinity_key_hash: Option<u64> =
        affinity_key.map(crate::proxy::stable_hash).or_else(|| {
            v.as_ref()
                // Chat's body affinity key is the top-level `system` string — a captured head key,
                // so `probe()` answers without materializing the DOM.
                .and_then(|l| op.body_affinity_key(l.probe()))
                .map(crate::proxy::stable_hash)
        });

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
    // thresholds the synchronous path used. The default (no per-pool breaker — the common case) is
    // a process-wide cached Arc, so the hot path pays no per-request allocation for it.
    let breaker_cfg: std::sync::Arc<crate::store::BreakerCfg> =
        resolve_breaker_cfg(&app, pool_name);

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
        // for a non-JSON body (the same projection the sequential path used). Gates project
        // arbitrary body fields, so a configured gate materializes the DOM (as it always did).
        static NULL_BODY: Value = Value::Null;
        let gate_body: &Value = match v.as_mut() {
            Some(l) => match l.ensure_dom() {
                Ok(m) => &*m,
                Err(()) => &NULL_BODY,
            },
            None => &NULL_BODY,
        };
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
                // A configured routing policy projects the body — materialize the DOM (this pool
                // always paid the parse). `NULL_BODY_POLICY` stands in for non-JSON, as before.
                static NULL_BODY_POLICY: Value = Value::Null;
                let policy_body: &Value = match v.as_mut() {
                    Some(l) => match l.ensure_dom() {
                        Ok(m) => &*m,
                        Err(()) => &NULL_BODY_POLICY,
                    },
                    None => &NULL_BODY_POLICY,
                };
                let outcome = decide_policy_order(
                    &app,
                    resolved,
                    &cands,
                    &request_ctx,
                    policy_body,
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
        // Stage taps read arbitrary body fields for the shape — materialize the DOM (taps are
        // configured, so this request always paid the parse).
        let dom: Option<&Value> = match v.as_mut() {
            Some(l) => l.ensure_dom().ok().map(|m| &*m),
            None => None,
        };
        Some(capture_stage_shape(
            dom,
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

    // PREPARE ends here (dispatch loop begins).
    drop(_prep);
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

        let _pick = crate::profile::start(crate::profile::Stage::LanePick);
        let (i, permit) = match pick_among(
            &app,
            &cands,
            &mut request_ctx,
            affinity_key_hash,
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
                // Box::pin: the exhaustion future (~2.1 KB) is COLD (no usable lane), but awaited
                // inline it alone sets this fn's coroutine union max — boxing it shrinks the
                // per-request future every happy-path request carries; the alloc only happens on
                // the already-degraded path. (Same pattern as walk.rs's recursive box.)
                return Box::pin(handle_exhaustion_for_pool(
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
                ))
                .await;
            }
        };
        // LANE_PICK ends here (a lane + permit are in hand).
        drop(_pick);

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
        let _xlate = crate::profile::start(crate::profile::Stage::TranslateReq);
        // REQUEST SHORT-CIRCUIT WITHOUT A DOM (perf/throughput-1.5.0): hop 1 of a SAME-protocol
        // JSON dispatch whose head projection PROVES no same-proto invalidator (#1-#4, Vertex)
        // fires re-emits the retained bytes verbatim — the exact bytes the translate seam's own
        // pristine short-circuit would emit — without ever materializing the `Value` tree.
        // `head_provably_pristine` is one-sided (see its docs + parity test): any doubt falls
        // through to the unchanged materialize-and-translate path below, so the wire bytes are
        // byte-identical on every branch. When the DOM was already materialized (hooks/taps/gates/
        // path-model ingress), `probe()` IS the (possibly hook-rewritten) DOM and `body` was
        // re-serialized in lockstep by the rewrite pass — the check stays sound.
        let head_pristine = ingress_protocol == egress_name
            && first_hop_v
                .as_ref()
                .is_some_and(|l| head_provably_pristine(&app, i, l.probe()));
        let payload = if head_pristine {
            // Consume the hop-1 body exactly as the translate path does; failover hops 2+ re-parse
            // from the retained pristine bytes, unchanged. `Bytes::clone` = refcount bump.
            first_hop_v = None;
            body.clone()
        } else {
            let hop_v: Option<Value> = if !body_is_json {
                None // opaque ingress body: byte-level relay/translate; nothing to re-parse.
            } else {
                let parsed = match first_hop_v.take() {
                    // First hop: consume the carried body — the memoized DOM when one was
                    // materialized (hooks/taps/gates/path-model), else ONE parse of the validated
                    // bytes (the parse the old eager path performed at ingress).
                    Some(l) => l.into_value(),
                    // Failover hops: re-parse from the retained pristine bytes (sonic-rs: SIMD parse).
                    None => crate::json::parse(&body).map_err(|_| ()),
                };
                match parsed {
                    Ok(v) => Some(v),
                    // `body` already validated/parsed once successfully above; this is infallible.
                    Err(()) => {
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
                }
            };
            // SINGLE shared cross-protocol request-shaping seam (shared verbatim with `forward_once`'s
            // degraded path): read→clear-extra→write, shim-key strip, model rewrite, serialize. Both
            // paths route through `translate_request_cross_protocol` so neither can carry a translation
            // step the other lacks (the recurring drift class this round's unification ends).
            match translate_request_cross_protocol(
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
            }
        };
        // TRANSLATE_REQ ends here (egress payload bytes in hand). CLIENT_BUILD spans the egress auth
        // + URL/path build + reqwest RequestBuilder construction that follows.
        drop(_xlate);
        let _cbuild = crate::profile::start(crate::profile::Stage::ClientBuild);
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
        let _cb_auth = crate::profile::start(crate::profile::Stage::CbAuth);
        let (wire_path, canonical_uri) = sign_and_wire_path_parts(&url_path);
        let signing_ctx = crate::proto::SigningContext {
            host: &app.lanes[i].signing_host,
            canonical_uri,
            body: &payload,
            timestamp_epoch: now(),
            upstream_creds: app.upstream_creds(),
        };
        let auth = lane_auth_headers(&app.lanes[i], key, &signing_ctx);
        drop(_cb_auth);

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
        let _cb_reqwest = crate::profile::start(crate::profile::Stage::CbReqwest);
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
        drop(_cb_reqwest);
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
        // CLIENT_BUILD ends here (the RequestBuilder is fully assembled). UPSTREAM_SEND spans the
        // `req.send().await` round-trip to response headers.
        drop(_cbuild);
        let _send = crate::profile::start(crate::profile::Stage::UpstreamSend);
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
        // UPSTREAM_SEND ends here (response headers received or transport error).
        drop(_send);
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

                // RECORD_SUCCESS: the post-2xx breaker/latency/budget bookkeeping (store lock ops).
                let _rec = crate::profile::start(crate::profile::Stage::RecordSuccess);
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
                // RECORD_SUCCESS ends; RESP_BUILD spans everything from here to the returned Response
                // (usage/CT capture, SSE-vs-buffered branch, FirstByteBody wiring, response builder).
                drop(_rec);
                let _resp = crate::profile::start(crate::profile::Stage::RespBuild);
                // RB_PRE sub-stage: header/CT/relay-id capture + SSE detection + translate resolution,
                // up to `FirstByteBody::new`. (The cross-protocol buffered branch returns before the
                // streaming builder, so on that path RB_PRE covers the pre-buffer work only.)
                let _rb_pre = crate::profile::start(crate::profile::Stage::RbPre);

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
                // RB_PRE ends; RB_BODY spans the FirstByteBody wiring + response builder + return.
                drop(_rb_pre);
                let _rb_body = crate::profile::start(crate::profile::Stage::RbBody);
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

    // Box::pin: cold path (candidates exhausted), boxed for the same coroutine-size reason as the
    // in-loop exhaustion return above — the happy path never allocates here.
    Box::pin(handle_exhaustion_for_pool(
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
    ))
    .await
}

/// GLOBAL TAP (observe) stage of the forward pipeline — extracted from `forward_with_pool_parsed_inner`
/// so it is independently readable and testable. Fires the global request-stage `kind: tap` hooks
/// FIRE-AND-FORGET: serialize the projection(s) once, then spawn one detached task per tap. A tap gets
/// a write-only send with its own deadline; its reply is ignored, its errors swallowed — a tap can
/// NEVER delay, reorder, or fail the request. Each tap receives the projection its GRANT allows: a
/// `prompt: ro` tap gets the prompt-content projection, a `prompt: no` (default) tap gets shape-only.
/// At most TWO projections are built (shape-only + with-prompt) regardless of tap count. ZERO COST
/// when no tap is configured (the empty-list early return).
fn fire_global_taps(
    app: &Arc<App>,
    body: &Value,
    pool_name: &str,
    ingress_protocol: &str,
    wants_stream: bool,
) {
    if app.tap_hooks.is_empty() {
        return;
    }
    let ctx = crate::hooks::RoutingContext {
        pool: pool_name,
        budget_remaining: None,
    };
    let build_proj = |with_prompt: bool| {
        let req =
            build_rewrite_request(body, pool_name, ingress_protocol, wants_stream, with_prompt);
        crate::json::to_vec(&crate::hooks::wire::build(
            crate::hooks::wire::OP_NOTIFY,
            &req,
            &[],
            &ctx,
        ))
        .ok()
        .map(std::sync::Arc::new)
    };
    // Shape-only is needed whenever any tap lacks the prompt grant; the prompt projection only when at
    // least one tap holds `prompt: ro`. Build each at most once.
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
            crate::proxy::hooks::spawn_bounded_tap(
                async move { policy.notify(&proj, budget).await },
            );
        }
    }
}

/// Resolve the effective `BreakerCfg` Arc for a pool: the pool's own settings when configured, else
/// a PROCESS-WIDE cached default Arc. The default is by far the common case, and the previous
/// per-request `Arc::new(clone().unwrap_or_default())` paid a heap allocation + struct clone on
/// EVERY forwarded request for a value that never changes; the cached Arc reduces that to a refcount
/// bump. Behavior is identical — the resolved thresholds are byte-for-byte the same.
pub(crate) fn resolve_breaker_cfg(
    app: &Arc<App>,
    pool_name: &str,
) -> std::sync::Arc<crate::store::BreakerCfg> {
    match app
        .pool_runtime
        .get(pool_name)
        .and_then(|r| r.breaker.as_ref())
    {
        Some(cfg) => std::sync::Arc::new(cfg.clone()),
        None => {
            static DEFAULT: std::sync::OnceLock<std::sync::Arc<crate::store::BreakerCfg>> =
                std::sync::OnceLock::new();
            DEFAULT
                .get_or_init(|| std::sync::Arc::new(crate::store::BreakerCfg::default()))
                .clone()
        }
    }
}

mod walk;
pub(crate) use walk::*;
