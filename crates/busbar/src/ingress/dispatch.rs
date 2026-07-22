// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The protocol catch-all dispatch (design: web server listens for anything → Router IDs the
//! protocol → that protocol's `RequestHandler` decides the operation → its OperationHandler). Holds
//! `protocol_dispatch` (the axum fallback), the generic `operation_ingress` for the 1.2 operations,
//! and the bedrock InvokeModel arm. A child of `route` so it shares the ingress core's private
//! helpers (`finish*`, `governance_guard`) without widening their visibility.

use super::*;

/// Minimal `model` form-field extractor for multipart transcription. Scans only the HEAD of the
/// body (byte-level, no allocation) rather than lossy-converting the ENTIRE body: the `model` text
/// part sits before the (potentially multi-MiB binary) audio part in a well-formed request, so a
/// bounded head window finds it without allocating a full-body String per transcription. If it is
/// not in the head (a pathologically-ordered body), it resolves to `None` → a clean routing 404,
/// same as a genuinely-absent model.
fn multipart_model(body: &[u8]) -> Option<String> {
    // 64 KiB is far larger than any plausible run of text form fields preceding the audio blob.
    const HEAD: usize = 64 * 1024;
    let head = &body[..body.len().min(HEAD)];
    let find = |hay: &[u8], needle: &[u8]| hay.windows(needle.len()).position(|w| w == needle);
    let idx = find(head, b"name=\"model\"")?;
    let sep = find(&head[idx..], b"\r\n\r\n")? + idx + 4;
    let val = &head[sep..];
    let end = find(val, b"\r\n").unwrap_or(val.len());
    let m = String::from_utf8_lossy(&val[..end]).trim().to_string();
    (!m.is_empty()).then_some(m)
}

/// Ingress for the NEW operations (embeddings/moderations/images/audio, 1.2), for EVERY dialect that
/// speaks the op. Resolves the (protocol, operation) OperationHandler — absent ⇒ no-handler 404 in the CALLER's
/// dialect (design §3) — then forwards through `proxy::forward_with_pool_parsed` (same-proto
/// passthrough or the cross-protocol IR bridge). Model resolution: `model_hint` for path-model dialects (gemini/bedrock —
/// their route handler parsed it from the URL), else the JSON body `model` (openai/cohere) or the
/// multipart form (openai transcription).
// 8 args: the (proto, operation, model_hint) triple collapses into the unified catch-all dispatch
// (Router → RequestHandler decides operation+model) in the step-2 refactor; grouping them into a
// one-shot struct now would be churn the collapse immediately deletes.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn operation_ingress(
    app: &Arc<App>,
    gov: &crate::governance::GovCtx,
    caller: &crate::auth::CallerToken,
    headers: &HeaderMap,
    body: Bytes,
    proto: &'static str,
    operation: crate::operation::Operation,
    model_hint: Option<String>,
) -> Response {
    let caller_token = caller.0.as_deref();
    let started = Instant::now();
    let charged_at = crate::store::now();

    let Some(rh) = crate::handlers::request_handler(proto) else {
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
                "This protocol does not support that operation.",
            ),
        );
    };
    let Some(op_handler) = rh.operation_handler(operation) else {
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

    let ct = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    // VALIDATE ONCE, before model extraction, so a malformed JSON body gets the parse 400 (below),
    // never a misleading missing-model 400. `LazyBody::parse` preserves the exact malformed-body
    // reject set of the old eager `parse::<Value>` (same depth guard, same parser, full-body scan)
    // but builds NO DOM — only the top-level head projection the passthrough path reads. The full
    // `Value` tree is materialized downstream ONLY on the paths that need it (cross-protocol
    // translation, hooks, taps, gates, failover hops 2+).
    let parsed_v: Option<crate::proxy::LazyBody> = if ct.starts_with("application/json")
        || ct.is_empty()
    {
        match crate::proxy::LazyBody::parse(&body) {
            Ok(v) => Some(v),
            Err(_) => {
                tracing::debug!(detail = %crate::json::parse_err_log(body.len()), "request body JSON parse failed");
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
        }
    } else {
        None
    };
    let model = if let Some(m) = model_hint {
        Some(m)
    } else if ct.starts_with("multipart/") {
        multipart_model(&body)
    } else {
        // `model` is a captured head key: this point read never materializes the DOM and returns
        // exactly what the full `Value` returned (missing / non-string / non-object body -> None).
        parsed_v.as_ref().and_then(|v| {
            v.probe()
                .get("model")
                .and_then(|m| m.as_str())
                .map(str::to_string)
        })
    };
    let model = match model {
        Some(m) if !m.is_empty() => m,
        _ => {
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
                    "Missing required parameter: 'model'.",
                ),
            );
        }
    };

    operation_resolved(
        app,
        gov,
        proto,
        operation,
        op_handler,
        &model,
        headers,
        body,
        parsed_v,
        caller_token,
        started,
        charged_at,
        None,
    )
    .await
}

/// THE UNIVERSAL RESOLVED CORE — every operation, chat included, from the moment the model is known:
/// governance → candidates → affinity → the one engine. `gemini_api_version` shapes the gemini
/// dialect's model-not-found echo; everything else is operation- and protocol-blind.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn operation_resolved(
    app: &Arc<App>,
    gov: &crate::governance::GovCtx,
    proto: &'static str,
    operation: crate::operation::Operation,
    op_handler: &'static dyn crate::handlers::OperationHandler,
    model: &str,
    headers: &HeaderMap,
    body: Bytes,
    parsed_v: Option<crate::proxy::LazyBody>,
    caller_token: Option<&str>,
    started: Instant,
    charged_at: u64,
    gemini_api_version: Option<&str>,
) -> Response {
    let ct = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let charged = match governance_guard(app, gov, proto, model, started, charged_at) {
        Err(resp) => return *resp,
        Ok(charged) => charged,
    };

    let (cands, pool_name): (Vec<WeightedLane>, &str) = if let Some(c) = app.pools.get(model) {
        (c.clone(), model)
    } else if let Some(&i) = app.by_model.get(model) {
        (
            vec![WeightedLane {
                reasoning: None,
                idx: i,
                weight: 1,
                attempt_timeout_ms: None,
            }],
            "",
        )
    } else {
        return finish_admitted(
            app,
            gov,
            proto,
            pool_label(app, model),
            started,
            charged_at,
            ingress_error(
                proto,
                StatusCode::NOT_FOUND,
                crate::proxy::KIND_NOT_FOUND,
                &not_found_message(model, gemini_api_version),
            ),
            charged,
        );
    };

    // THE ONE ENGINE: every operation — chat included — forwards through the same failover/breaker/
    // policy pipeline. JSON bodies ride parsed (`Some(v)`, parsed once by the caller); opaque bodies
    // (multipart/binary) ride `None` and relay/translate at the byte level via the operation codecs.
    let v = parsed_v;
    // Session affinity: the pool's configured affinity header, read generically for EVERY operation
    // (sticky routing is an engine capability, not a chat feature).
    let affinity_key: Option<String> = headers
        .get(affinity_header_for(app, model))
        .and_then(|h| h.to_str().ok())
        .map(str::to_string);
    let resp = crate::proxy::forward_with_pool_parsed(
        app.clone(),
        cands,
        body,
        v,
        // `ct` borrows `headers` (a caller-held reference that outlives this call) — no per-request
        // `to_string` copy is needed to thread the Content-Type through.
        if ct.is_empty() {
            crate::proxy::APPLICATION_JSON
        } else {
            ct
        },
        caller_token,
        // The key the auth layer resolved/synthesized for this caller — lets the routing-signal
        // path project rate_headroom/identity for group/SSO principals whose token is not a
        // virtual-key secret (so a token `lookup` would miss).
        gov.key.as_ref(),
        pool_name,
        affinity_key.as_deref(),
        proto,
        crate::handlers::OpDispatch {
            operation,
            op_handler,
        },
        usage_sink(app, gov, charged_at),
    )
    .await;
    finish_admitted(app, gov, proto, model, started, charged_at, resp, charged)
}

// (The per-operation axum wrappers are gone: the protocol catch-all `protocol_dispatch` resolves the
// operation via the RequestHandler and calls `operation_ingress` directly.)

/// THE PROTOCOL CATCH-ALL (design: web server listens for anything). One axum fallback replaces the
/// per-path protocol routes: the Router does DUMB protocol identification from (path, headers); the
/// identified protocol's RequestHandler reads path+body and decides the operation; the operation's
/// OperationHandler does the rest. `main.rs` keeps explicit routes ONLY for busbar's own API (health/metrics/
/// admin/discovery + the named/adhoc conveniences) — a new protocol touches the Router ID ladder, a
/// RequestHandler, and its OperationHandlers, never this dispatch and never `main.rs`.
///
/// Gemini and Bedrock delegate to their protocol arms wholesale (path-model parsing, streaming
/// variants, native unsupported-action envelopes live there); the body-model protocols split here:
/// every operation → `operation_ingress` (the universal core). Unknown paths/methods keep the
/// pre-collapse fallback shaping (native 404/405 envelopes, no proxy tells).
pub(crate) async fn protocol_dispatch(
    crate::state::CurrentApp(app): crate::state::CurrentApp,
    OriginalUri(uri): OriginalUri,
    method: axum::http::Method,
    axum::extract::Extension(gov): axum::extract::Extension<crate::governance::GovCtx>,
    axum::extract::Extension(caller): axum::extract::Extension<crate::auth::CallerToken>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let path = uri.path().to_string();
    let Some(proto) = crate::proto::detect::protocol_id(&path, &headers) else {
        // Not a protocol endpoint: the pre-collapse 404 fallback shape (native envelope by path).
        return crate::fallback_error_response(
            &path,
            StatusCode::NOT_FOUND,
            crate::admin::ERR_TYPE_NOT_FOUND,
            "the requested resource was not found",
        );
    };
    if method != axum::http::Method::POST {
        // A protocol endpoint hit with the wrong method: the pre-collapse 405 shape.
        return crate::fallback_error_response(
            &path,
            StatusCode::METHOD_NOT_ALLOWED,
            crate::admin::ERR_TYPE_INVALID_REQUEST,
            "method not allowed for this resource",
        );
    }
    // THE UNIVERSAL RULE — we only process operations for which the protocol HOLDS an
    // OperationHandler; otherwise 404 in the caller's dialect. No operation is special: chat,
    // embeddings, audio — same consult, same terminal. Delete any protocol's handler for any
    // operation (its registry arm) and that operation dies HERE while everything else keeps working.
    // (`resolve_operation` = the RequestHandler naming the operation; `None` falls through to the
    // protocol arms, which own their native unknown-action envelopes.)
    if let Some(rh) = crate::handlers::request_handler(proto) {
        if let Some(op) = rh.resolve_operation(&path, &body) {
            if rh.operation_handler(op).is_none() {
                return crate::proxy::ingress_error(
                    proto,
                    StatusCode::NOT_FOUND,
                    crate::proxy::KIND_NOT_FOUND,
                    "This endpoint does not support that operation.",
                );
            }
        }
    }
    match proto {
        // Path-model protocols keep their full arms (streaming variants, native action errors).
        // Their ingress futures are Box::pin'd: in a match every arm's future is inlined into the
        // dispatch coroutine's union, so the gemini/bedrock arms (~5.7 KB each) inflate the future
        // EVERY request carries even when the traffic is another dialect. Boxing moves that weight
        // behind one allocation paid only by requests that actually take the arm.
        PROTO_GEMINI => {
            // axum's {*rest} wildcard percent-decoded the tail before the collapse; match it.
            let rest =
                crate::observability::percent_decode(path.split("/models/").nth(1).unwrap_or(""));
            Box::pin(gemini_ingress(
                crate::state::CurrentApp(app),
                Path(rest),
                OriginalUri(uri),
                axum::extract::Extension(gov),
                axum::extract::Extension(caller),
                headers,
                body,
            ))
            .await
        }
        PROTO_BEDROCK => {
            // axum's Path extractor percent-decoded {model_id} before the collapse; match it.
            let model = crate::handlers::request_handler(PROTO_BEDROCK)
                .and_then(|rh| rh.path_model(&path))
                .map(|m| crate::observability::percent_decode(&m))
                .unwrap_or_default();
            if path.ends_with("/converse") {
                Box::pin(bedrock_converse(
                    crate::state::CurrentApp(app),
                    Path(model),
                    axum::extract::Extension(gov),
                    axum::extract::Extension(caller),
                    headers,
                    body,
                ))
                .await
            } else if path.ends_with("/converse-stream") {
                Box::pin(bedrock_converse_stream(
                    crate::state::CurrentApp(app),
                    Path(model),
                    axum::extract::Extension(gov),
                    axum::extract::Extension(caller),
                    headers,
                    body,
                ))
                .await
            } else if path.ends_with("/invoke") {
                Box::pin(bedrock_invoke(
                    crate::state::CurrentApp(app),
                    Path(model),
                    OriginalUri(uri),
                    axum::extract::Extension(gov),
                    axum::extract::Extension(caller),
                    headers,
                    body,
                ))
                .await
            } else {
                crate::fallback_error_response(
                    &path,
                    StatusCode::NOT_FOUND,
                    crate::admin::ERR_TYPE_NOT_FOUND,
                    "the requested resource was not found",
                )
            }
        }
        // Body-model protocols: the RequestHandler names the operation; every operation →
        // the generic operation ingress. (`anthropic` bare `/v1/messages` is served here — an
        // Anthropic SDK pointed at busbar root works like every other dialect; the named/adhoc
        // prefix routes remain for URL-pinned model selection.)
        _ => {
            let op = crate::handlers::request_handler(proto)
                .and_then(|rh| rh.resolve_operation(&path, &body));
            match op {
                // EVERY operation — chat included — takes the same universal ingress. No chat
                // match, no chat cores: body-model dialects resolve the model from the body inside
                // `operation_ingress`, exactly like embeddings or speech.
                Some(op) => {
                    operation_ingress(&app, &gov, &caller, &headers, body, proto, op, None).await
                }
                None => crate::fallback_error_response(
                    &path,
                    StatusCode::NOT_FOUND,
                    crate::admin::ERR_TYPE_NOT_FOUND,
                    "the requested resource was not found",
                ),
            }
        }
    }
}

/// POST /model/{model_id}/invoke — Bedrock `InvokeModel` ingress. The path names the model; the
/// bedrock RequestHandler reads the BODY and decides the operation (`textToImageParams` ⇒ image,
/// `inputText` ⇒ embeddings). An unrecognized body is a clean 400 in the Bedrock dialect.
pub(crate) async fn bedrock_invoke(
    crate::state::CurrentApp(app): crate::state::CurrentApp,
    Path(model_id): Path<String>,
    OriginalUri(uri): OriginalUri,
    axum::extract::Extension(gov): axum::extract::Extension<crate::governance::GovCtx>,
    axum::extract::Extension(caller): axum::extract::Extension<crate::auth::CallerToken>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(operation) = crate::handlers::request_handler(PROTO_BEDROCK)
        .and_then(|rh| rh.resolve_operation(uri.path(), &body))
    else {
        return ingress_error(
            PROTO_BEDROCK,
            StatusCode::BAD_REQUEST,
            crate::proxy::KIND_INVALID_REQUEST,
            "InvokeModel body is not a supported operation (expected inputText or textToImageParams).",
        );
    };
    operation_ingress(
        &app,
        &gov,
        &caller,
        &headers,
        body,
        PROTO_BEDROCK,
        operation,
        Some(model_id),
    )
    .await
}

#[cfg(test)]
mod multipart_model_tests {
    use super::multipart_model;

    #[test]
    fn extracts_model_from_head_ignoring_large_binary_tail() {
        // A well-formed transcription: the `model` text part precedes a large binary audio part.
        // multipart_model must find the model in the head without touching the (here 1 MiB) tail.
        let mut body = Vec::new();
        body.extend_from_slice(
            b"--BOUNDARY\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\nwhisper-1\r\n",
        );
        body.extend_from_slice(
            b"--BOUNDARY\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a\"\r\n\r\n",
        );
        body.extend(std::iter::repeat_n(0u8, 1 << 20)); // 1 MiB of binary, not valid UTF-8
        body.extend_from_slice(b"\r\n--BOUNDARY--\r\n");
        assert_eq!(multipart_model(&body).as_deref(), Some("whisper-1"));
    }

    #[test]
    fn absent_model_is_none() {
        let body = b"--B\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\nx\r\n--B--\r\n";
        assert_eq!(multipart_model(body), None);
    }
}
