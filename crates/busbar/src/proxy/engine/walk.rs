use super::*;

/// Find the lane index with the soonest cooldown expiry among candidates.
pub(crate) fn find_soonest_cooldown(
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
pub(crate) async fn handle_exhaustion_for_pool(
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
pub(crate) fn handle_status_503(
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
pub(crate) async fn forward_once(
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
pub(crate) async fn handle_fallback_pool(
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
pub(crate) async fn handle_least_bad(
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
