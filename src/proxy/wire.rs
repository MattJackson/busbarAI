use super::*;

/// Record the upstream round-trip (to response headers) for the current request so the
/// `server_timing` middleware can subtract it from the total and report Busbar's own added latency.
/// On failover the LAST attempt's value wins (recorded after every `send`, before success/error
/// classification) — so a success overwrites a prior failed hop; on an all-hops-fail exhaustion the
/// last failed hop's (typically short) RTT is what remains, which can mildly inflate the reported
/// `busbar;dur` on that error response. Telemetry only; never affects translation. No-op outside the
/// unit tests and the admin/health routes that never dispatch upstream simply don't record one.
pub(crate) fn record_upstream_rtt(rtt: std::time::Duration) {
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
pub(crate) fn maybe_attach_response_request_id(
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
pub(crate) fn ingress_relays_amzn_headers(ingress_protocol: &str) -> bool {
    crate::proto::protocol_for(ingress_protocol)
        .map(|p| p.writer().ingress_relays_amzn_headers())
        .unwrap_or(false)
}

/// The UPSTREAM response header NAMES this ingress protocol forwards VERBATIM on a same-protocol
/// passthrough — read from the upstream response and re-emitted on the client response (Bedrock's
/// `x-amzn-requestid` + `x-amzn-errortype`; Anthropic's `request-id`). Dispatched through the
/// `ProtocolWriter::ingress_relayed_response_header_names()` vtable so the agnostic forward path reads
/// and forwards these by NAME without naming any protocol module. Unknown protocols: `&[]`.
pub(crate) fn ingress_relayed_response_header_names(
    ingress_protocol: &str,
) -> &'static [&'static str] {
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
pub(crate) fn maybe_attach_route_policy(
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
pub(crate) fn cross_protocol_error_kind(status: StatusCode) -> &'static str {
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
pub(crate) fn shape_cross_protocol_error(
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
pub(crate) fn strip_router_shim_keys(v: &mut Value, egress_protocol: &str) -> bool {
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
pub(crate) fn strip_same_protocol_model_shim(v: &mut Value, ingress_protocol: &str) -> bool {
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
pub(crate) fn translate_request_cross_protocol(
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
pub(crate) fn max_upstream_buffered_bytes() -> usize {
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
pub(crate) fn max_translated_body_bytes() -> usize {
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
pub(crate) enum ReadEnd {
    /// The upstream signalled end-of-body (`Ok(None)`): the buffer holds the complete response.
    Complete,
    /// The body overran `cap` before EOF: the buffer holds a prefix, more bytes existed.
    Truncated,
    /// The transport failed mid-body (`Err(_)` from `chunk()`): the buffer holds an incomplete,
    /// possibly-corrupt fragment of a transfer that never finished. NOT a clean completion.
    TransportError,
}

pub(crate) async fn read_capped(r: reqwest::Response, cap: usize) -> (Bytes, ReadEnd) {
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
pub(crate) async fn read_capped_body(r: reqwest::Response) -> Bytes {
    read_capped(r, max_upstream_buffered_bytes()).await.0
}

/// Map the classified `StatusClass` of a CLIENT-fault upstream 4xx to a protocol-agnostic error
/// `kind` for `ingress_error` (the per-protocol writer maps it to its native error type/category).
/// Exhaustive over `StatusClass` — no `_` wildcard (the no-catch-all rule for disposition matches).
pub(crate) fn client_fault_kind(class: StatusClass) -> &'static str {
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
pub(crate) fn extract_error_message(bytes: &[u8]) -> Option<String> {
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
pub(crate) const MID_STREAM_GENERIC_DETAIL: &str = crate::proto::STREAM_ABORT_DETAIL;

/// Vendor-neutral fallback `error.message` for a NON-2xx response whose body carried no extractable
/// human message. Rendered into the CLIENT's native error envelope via `ingress_error`, so it must
/// read like copy a real single-vendor API would emit — NOT reverse-proxy vocabulary like "upstream".
/// The real status/cause is logged server-side; only this generic string reaches the client.
pub(crate) const GENERIC_REJECTED_DETAIL: &str = "The request could not be processed.";

/// Client-visible fallback `detail` strings each repeated across several ingress-error sites —
/// hoisted so the copy cannot drift between them. Same vendor-neutral rules as
/// `GENERIC_REJECTED_DETAIL`: generic service phrasing, no proxy/translation vocabulary.
pub(crate) const DETAIL_INTERNAL_ERROR: &str =
    "We received an unexpected internal error. Please try again.";
pub(crate) const DETAIL_MODEL_UNSUPPORTED_OPERATION: &str =
    "This model does not support that operation.";
pub(crate) const DETAIL_ENDPOINT_UNSUPPORTED_OPERATION: &str =
    "This endpoint does not support that operation.";
pub(crate) const DETAIL_REQUEST_TIMEOUT: &str = "The request timed out. Please retry shortly.";

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
pub(crate) fn mid_stream_error_bytes(
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
pub(crate) fn stable_hash(s: &str) -> u64 {
    crate::store::fnv1a_u64(s)
}
