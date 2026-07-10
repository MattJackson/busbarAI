// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! The OPERATIONS forward path (design §6): `forward_operation` — same-protocol passthrough or the
//! cross-protocol IR bridge, per candidate lane, with failover. A child of `forward` so it shares the
//! engine's private send/auth/permit primitives without widening their visibility.

use super::*;

#[cfg(test)]
mod sigv4_path_tests {
    use super::sign_and_wire_path_parts;

    /// Bedrock model ids contain `:` (e.g. `amazon.titan-embed-text-v2:0`). AWS double-URI-encodes
    /// the canonical path for non-S3 services, so the SIGNED canonical must be double-encoded
    /// (`%253A`) while the wire path is single-encoded (`%3A`). Using the single-encoded path for
    /// BOTH (the historical bug) yields SignatureDoesNotMatch → 403 against real AWS on EVERY Bedrock
    /// request — invisible to the signature-blind mock, confirmed only by a real InvokeModel/Converse
    /// call. Pin both encodings so this cannot silently regress.
    #[test]
    fn sigv4_canonical_double_encodes_bedrock_colon_path() {
        let (wire, canonical) =
            sign_and_wire_path_parts("/model/amazon.titan-embed-text-v2:0/invoke");
        assert_eq!(
            wire, "/model/amazon.titan-embed-text-v2%3A0/invoke",
            "wire = single-encoded"
        );
        assert_eq!(
            canonical, "/model/amazon.titan-embed-text-v2%253A0/invoke",
            "SigV4 canonical = double-encoded (non-S3 rule)"
        );
    }

    /// Colon-free paths (openai/anthropic `/v1/...`) are unaffected: `uri_encode_path` is a no-op, so
    /// canonical == wire and nothing changed for the bearer-auth protocols.
    #[test]
    fn sigv4_plain_path_canonical_equals_wire() {
        let (wire, canonical) = sign_and_wire_path_parts("/v1/chat/completions");
        assert_eq!(wire, "/v1/chat/completions");
        assert_eq!(canonical, wire);
    }
}

#[cfg(test)]
mod coerce_on_error_tests {
    use super::{coerce_on_error, PolicyOutcome};
    use crate::config::PolicyOnError;

    /// Each `on_error` disposition maps to its own distinct `PolicyOutcome` — this is the sole path
    /// that turns a policy error/timeout into the caller's fallback. `Reject` (→ 503-to-client) and
    /// `First` (→ deterministic config-order dispatch) each carry real availability behavior a
    /// regression could silently flip, so pin all three arms. An empty candidate slice suffices:
    /// `Weighted`/`Reject` ignore the candidates and `First` simply maps each `.idx`.
    #[test]
    fn coerce_on_error_maps_each_disposition() {
        let cands: &[crate::routing::Candidate] = &[];
        assert!(matches!(
            coerce_on_error(&PolicyOnError::Weighted, cands, "p"),
            PolicyOutcome::Weighted
        ));
        assert!(matches!(
            coerce_on_error(&PolicyOnError::Reject, cands, "p"),
            PolicyOutcome::Reject
        ));
        match coerce_on_error(&PolicyOnError::First, cands, "testpolicy") {
            PolicyOutcome::Order { order, name } => {
                assert!(
                    order.is_empty(),
                    "empty candidate set yields an empty order"
                );
                assert_eq!(
                    name, "testpolicy",
                    "First preserves the policy name verbatim"
                );
            }
            _ => panic!("First must produce a config-order Order outcome"),
        }
    }
}

/// Forward a NEW operation (embeddings/moderations/images/audio) through a candidate pool — v1
/// SAME-PROTOCOL passthrough: the ingress body is relayed to the egress lane UNCHANGED (ingress dialect
/// == egress dialect, so no translation), reusing the send/auth/permit primitives. Deliberately simpler
/// than [`forward_with_pool`]: no streaming, no cross-protocol IR bridge yet, and v1 records a breaker
/// SUCCESS on 2xx but does not yet classify upstream errors into the breaker (enriched in a follow-up).
/// The cross-protocol IR bridge (ingress OperationHandler `read_request`→IrReq→egress OperationHandler `write_request`; response
/// reverse) is layered on after first green. Multipart/binary bodies pass through verbatim same-proto.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn forward_operation(
    app: Arc<App>,
    cands: Vec<WeightedLane>,
    body: Bytes,
    req_content_type: axum::http::HeaderValue,
    caller_token: Option<&str>,
    pool_name: &str,
    ingress_protocol: &str,
    operation: crate::operation::Operation,
    op_handler: &dyn crate::handlers::OperationHandler,
    accept: &'static str,
) -> Response {
    for wl in &cands {
        let i = wl.idx;
        // Egress dimension (design §3): if the egress lane speaks a DIFFERENT protocol, it must have a
        // OperationHandler for this operation. No op_handler → no-handler 404 in the CALLER's dialect (e.g. images→anthropic).
        // An OperationHandler present but no cross-protocol IR bridge yet → fail LOUD (501), never a silent
        // mistranslation. Same-protocol (egress == ingress) skips straight to verbatim passthrough below.
        let egress_proto = app.lanes[i].protocol.name();
        if egress_proto != ingress_protocol {
            let egress_rh = crate::handlers::request_handler(egress_proto);
            match egress_rh.and_then(|h| h.operation_handler(operation)) {
                None => {
                    return ingress_error(
                        ingress_protocol,
                        StatusCode::NOT_FOUND,
                        KIND_NOT_FOUND,
                        "This model does not support that operation.",
                    );
                }
                Some(egress_op_handler) => {
                    // Safe: the same registry lookup that yielded `egress_op_handler` yielded this handler.
                    let egress_rh = egress_rh.expect("egress request_handler present");
                    // CROSS-PROTOCOL IR BRIDGE (the core value): ingress wire → IR → egress wire; on
                    // the way back, egress wire → IR → caller-dialect wire.
                    let Some(_permit) = app.store.try_acquire(i) else {
                        continue;
                    };
                    // The OperationHandler owns the wire format: hand it raw bytes + the request content-type and let
                    // it parse (JSON, multipart, …). The engine never inspects the body.
                    let mut ir_req = match op_handler
                        .read_request(body.as_ref(), req_content_type.to_str().unwrap_or(""))
                    {
                        Ok(ir) => ir,
                        Err(_) => {
                            return ingress_error(
                                ingress_protocol,
                                StatusCode::BAD_REQUEST,
                                KIND_INVALID_REQUEST,
                                "We could not process the content of your request.",
                            )
                        }
                    };
                    // The egress wire must carry the LANE's wire model, never the caller's busbar
                    // model name (routing owns model resolution; the codec stays blind to lanes).
                    ir_req.set_model(app.lanes[i].wire_model());
                    let egress_bytes = egress_op_handler.write_request(&ir_req);
                    let base = &app.lanes[i].base_url;
                    // Routing owns the path: apply the lane override, else ask the EGRESS protocol's
                    // RequestHandler to render it from resolved primitives (never the Lane).
                    let e_path = app.lanes[i].path.clone().unwrap_or_else(|| {
                        egress_rh.upstream_path(&crate::handlers::EgressCtx {
                            operation,
                            model: app.lanes[i].wire_model(),
                            stream: false,
                        })
                    });
                    let (wire_path, canonical_uri) = sign_and_wire_path_parts(&e_path);
                    let key = match app.auth_mode() {
                        crate::auth::AuthMode::Passthrough => caller_token.unwrap_or(""),
                        crate::auth::AuthMode::Token | crate::auth::AuthMode::None => {
                            app.lanes[i].api_key.as_str()
                        }
                    };
                    let signing_ctx = crate::proto::SigningContext {
                        host: host_from_base(base),
                        canonical_uri,
                        body: egress_bytes.as_ref(),
                        timestamp_epoch: now(),
                        auth_mode: app.auth_mode(),
                    };
                    let auth = lane_auth_headers(&app.lanes[i], key, &signing_ctx);
                    let writer = app.lanes[i].protocol.writer();
                    let req = app
                        .client
                        .post(format!("{base}{wire_path}"))
                        .headers(convert_headers(auth))
                        .header(CONTENT_TYPE, APPLICATION_JSON)
                        .header(USER_AGENT, writer.egress_user_agent())
                        .header(ACCEPT, accept)
                        .body(egress_bytes.clone())
                        .timeout(std::time::Duration::from_secs(30));
                    match req.send().await {
                        Ok(resp) => {
                            let status = StatusCode::from_u16(resp.status().as_u16())
                                .unwrap_or(StatusCode::BAD_GATEWAY);
                            match resp.bytes().await {
                                Ok(bytes) => {
                                    if !status.is_success() {
                                        // Never translate an error body; surface an ingress-native error.
                                        return ingress_error(
                                            ingress_protocol,
                                            status,
                                            KIND_API_ERROR,
                                            "The upstream provider returned an error.",
                                        );
                                    }
                                    app.store.record_success_in(pool_name, i);
                                    let ir_resp = match egress_op_handler.read_response(&bytes) {
                                        Ok(ir) => ir,
                                        Err(_) => {
                                            return ingress_error(
                                                ingress_protocol,
                                                StatusCode::BAD_GATEWAY,
                                                KIND_API_ERROR,
                                                "We could not read the upstream response.",
                                            )
                                        }
                                    };
                                    // The OperationHandler chose the caller-dialect wire AND its content-type
                                    // (JSON, or audio/* for speech); relay both verbatim.
                                    let wire = op_handler.write_response(&ir_resp);
                                    return Response::builder()
                                        .status(StatusCode::OK)
                                        .header(CONTENT_TYPE, wire.content_type)
                                        .body(Body::from(wire.bytes))
                                        .unwrap_or_else(|_| StatusCode::OK.into_response());
                                }
                                Err(_) => continue, // body read failed → failover
                            }
                        }
                        Err(_) => continue, // transport error → failover
                    }
                }
            }
        }
        // SAME-protocol passthrough. Concurrency permit; busy/cooling lane → next candidate.
        let Some(_permit) = app.store.try_acquire(i) else {
            continue;
        };
        let base = &app.lanes[i].base_url;
        // Same-protocol passthrough: lane override, else this protocol's RequestHandler renders the path.
        let url_path = app.lanes[i].path.clone().unwrap_or_else(|| {
            crate::handlers::request_handler(ingress_protocol)
                .map(|rh| {
                    rh.upstream_path(&crate::handlers::EgressCtx {
                        operation,
                        model: app.lanes[i].wire_model(),
                        stream: false,
                    })
                })
                .unwrap_or_default()
        });
        let (wire_path, canonical_uri) = sign_and_wire_path_parts(&url_path);
        let key = match app.auth_mode() {
            crate::auth::AuthMode::Passthrough => caller_token.unwrap_or(""),
            crate::auth::AuthMode::Token | crate::auth::AuthMode::None => {
                app.lanes[i].api_key.as_str()
            }
        };
        let signing_ctx = crate::proto::SigningContext {
            host: host_from_base(base),
            canonical_uri,
            body: body.as_ref(),
            timestamp_epoch: now(),
            auth_mode: app.auth_mode(),
        };
        let auth = lane_auth_headers(&app.lanes[i], key, &signing_ctx);
        let writer = app.lanes[i].protocol.writer();
        let req = app
            .client
            .post(format!("{base}{wire_path}"))
            .headers(convert_headers(auth))
            .header(CONTENT_TYPE, req_content_type.clone())
            .header(USER_AGENT, writer.egress_user_agent())
            .header(ACCEPT, accept)
            .body(body.clone())
            .timeout(std::time::Duration::from_secs(30));
        match req.send().await {
            Ok(resp) => {
                let status =
                    StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
                let up_ctype = resp
                    .headers()
                    .get(CONTENT_TYPE)
                    .cloned()
                    .unwrap_or_else(|| axum::http::HeaderValue::from_static(APPLICATION_JSON));
                match resp.bytes().await {
                    Ok(bytes) => {
                        if status.is_success() {
                            app.store.record_success_in(pool_name, i);
                        }
                        return Response::builder()
                            .status(status)
                            .header(CONTENT_TYPE, up_ctype)
                            .body(Body::from(bytes))
                            .unwrap_or_else(|_| status.into_response());
                    }
                    Err(_) => continue, // body read failed → failover
                }
            }
            Err(_) => continue, // transport error → failover
        }
    }
    ingress_error(
        ingress_protocol,
        StatusCode::SERVICE_UNAVAILABLE,
        KIND_API_ERROR,
        "All upstreams for this operation are unavailable.",
    )
}
