// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! The protocol catch-all dispatch (design: web server listens for anything → Router IDs the
//! protocol → that protocol's `RequestHandler` decides the operation → its OperationHandler). Holds
//! `protocol_dispatch` (the axum fallback), the generic `operation_ingress` for the 1.2 operations,
//! and the bedrock InvokeModel arm. A child of `route` so it shares the ingress core's private
//! helpers (`finish*`, `governance_guard`, chat cores) without widening their visibility.

use super::*;

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

/// Ingress for the NEW operations (embeddings/moderations/images/audio, 1.2), for EVERY dialect that
/// speaks the op. Resolves the (protocol, operation) OperationHandler — absent ⇒ no-handler 404 in the CALLER's
/// dialect (design §3) — then forwards through `forward_operation` (same-proto passthrough or the
/// cross-protocol IR bridge). Model resolution: `model_hint` for path-model dialects (gemini/bedrock —
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
            crate::forward::POOL_LABEL_UNRESOLVED,
            started,
            charged_at,
            ingress_error(
                proto,
                StatusCode::NOT_FOUND,
                crate::forward::KIND_NOT_FOUND,
                "This protocol does not support that operation.",
            ),
        );
    };
    let Some(op_handler) = rh.operation_handler(operation) else {
        return finish_rejected(
            app,
            gov,
            proto,
            crate::forward::POOL_LABEL_UNRESOLVED,
            started,
            charged_at,
            ingress_error(
                proto,
                StatusCode::NOT_FOUND,
                crate::forward::KIND_NOT_FOUND,
                "This endpoint does not support that operation.",
            ),
        );
    };

    let ct = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let model = if let Some(m) = model_hint {
        Some(m)
    } else if ct.starts_with("multipart/") {
        multipart_model(&body)
    } else {
        crate::json::parse(&body)
            .ok()
            .and_then(|v: serde_json::Value| {
                v.get("model").and_then(|m| m.as_str()).map(str::to_string)
            })
    };
    let model = match model {
        Some(m) if !m.is_empty() => m,
        _ => {
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

    if let Some(resp) = governance_guard(app, gov, proto, &model, started, charged_at).await {
        return resp;
    }

    let (cands, pool_name): (Vec<WeightedLane>, &str) = if let Some(c) = app.pools.get(&model) {
        (c.clone(), model.as_str())
    } else if let Some(&i) = app.by_model.get(&model) {
        (vec![WeightedLane { idx: i, weight: 1 }], "")
    } else {
        return finish(
            app,
            gov,
            proto,
            pool_label(app, &model),
            started,
            charged_at,
            ingress_error(
                proto,
                StatusCode::NOT_FOUND,
                crate::forward::KIND_NOT_FOUND,
                &not_found_message(&model, None),
            ),
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
        app.clone(),
        cands,
        body,
        req_ct,
        caller_token,
        pool_name,
        proto,
        operation,
        op_handler,
        accept,
    )
    .await;
    finish(app, gov, proto, &model, started, charged_at, resp)
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
/// chat → the chat ingress core, 1.2 operations → `operation_ingress`. Unknown paths/methods keep the
/// pre-collapse fallback shaping (native 404/405 envelopes, no proxy tells).
pub(crate) async fn protocol_dispatch(
    State(app): State<Arc<App>>,
    OriginalUri(uri): OriginalUri,
    method: axum::http::Method,
    axum::extract::Extension(gov): axum::extract::Extension<crate::governance::GovCtx>,
    axum::extract::Extension(caller): axum::extract::Extension<crate::auth::CallerToken>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let path = uri.path().to_string();
    let Some(proto) = crate::router::protocol_id(&path, &headers) else {
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
    // THE DELETION SWITCH — chat is a standard operation. Before any chat arm runs, the protocol's
    // RequestHandler must actually HOLD a chat OperationHandler; an absent handler is the same
    // no-handler 404 (in the caller's dialect) every other operation gets. Delete a protocol's
    // `static CHAT` + registry arm and its chat dies here while everything else keeps working.
    if let Some(rh) = crate::handlers::request_handler(proto) {
        if rh.resolve_operation(&path, &body) == Some(crate::operation::Operation::Chat)
            && rh
                .operation_handler(crate::operation::Operation::Chat)
                .is_none()
        {
            return crate::forward::ingress_error(
                proto,
                StatusCode::NOT_FOUND,
                crate::forward::KIND_NOT_FOUND,
                "This endpoint does not support that operation.",
            );
        }
    }
    match proto {
        // Path-model protocols keep their full arms (streaming variants, native action errors).
        "gemini" => {
            // axum's {*rest} wildcard percent-decoded the tail before the collapse; match it.
            let rest =
                crate::observability::percent_decode(path.split("/models/").nth(1).unwrap_or(""));
            gemini_ingress(
                State(app),
                Path(rest),
                OriginalUri(uri),
                axum::extract::Extension(gov),
                axum::extract::Extension(caller),
                headers,
                body,
            )
            .await
        }
        "bedrock" => {
            // axum's Path extractor percent-decoded {model_id} before the collapse; match it.
            let model = crate::handlers::request_handler("bedrock")
                .and_then(|rh| rh.path_model(&path))
                .map(|m| crate::observability::percent_decode(&m))
                .unwrap_or_default();
            if path.ends_with("/converse") {
                bedrock_converse(
                    State(app),
                    Path(model),
                    axum::extract::Extension(gov),
                    axum::extract::Extension(caller),
                    headers,
                    body,
                )
                .await
            } else if path.ends_with("/converse-stream") {
                bedrock_converse_stream(
                    State(app),
                    Path(model),
                    axum::extract::Extension(gov),
                    axum::extract::Extension(caller),
                    headers,
                    body,
                )
                .await
            } else if path.ends_with("/invoke") {
                bedrock_invoke(
                    State(app),
                    Path(model),
                    OriginalUri(uri),
                    axum::extract::Extension(gov),
                    axum::extract::Extension(caller),
                    headers,
                    body,
                )
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
        // Body-model protocols: the RequestHandler names the operation; chat → chat core, 1.2 ops →
        // the generic operation ingress. (`anthropic` bare `/v1/messages` is served here — an
        // Anthropic SDK pointed at busbar root works like every other dialect; the named/adhoc
        // prefix routes remain for URL-pinned model selection.)
        _ => {
            let op = crate::handlers::request_handler(proto)
                .and_then(|rh| rh.resolve_operation(&path, &body));
            match op {
                Some(crate::operation::Operation::Chat) => match proto {
                    "openai" => {
                        openai_ingress(
                            State(app),
                            axum::extract::Extension(gov),
                            axum::extract::Extension(caller),
                            headers,
                            body,
                        )
                        .await
                    }
                    "cohere" => {
                        cohere_ingress(
                            State(app),
                            axum::extract::Extension(gov),
                            axum::extract::Extension(caller),
                            headers,
                            body,
                        )
                        .await
                    }
                    "responses" => {
                        responses_ingress(
                            State(app),
                            axum::extract::Extension(gov),
                            axum::extract::Extension(caller),
                            headers,
                            body,
                        )
                        .await
                    }
                    _ => ingress_body_model(&app, &gov, &caller, &headers, body, proto).await,
                },
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
    State(app): State<Arc<App>>,
    Path(model_id): Path<String>,
    OriginalUri(uri): OriginalUri,
    axum::extract::Extension(gov): axum::extract::Extension<crate::governance::GovCtx>,
    axum::extract::Extension(caller): axum::extract::Extension<crate::auth::CallerToken>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(operation) = crate::handlers::request_handler("bedrock")
        .and_then(|rh| rh.resolve_operation(uri.path(), &body))
    else {
        return ingress_error(
            "bedrock",
            StatusCode::BAD_REQUEST,
            crate::forward::KIND_INVALID_REQUEST,
            "InvokeModel body is not a supported operation (expected inputText or textToImageParams).",
        );
    };
    operation_ingress(
        &app,
        &gov,
        &caller,
        &headers,
        body,
        "bedrock",
        operation,
        Some(model_id),
    )
    .await
}
