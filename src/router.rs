// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! The ingress Router (design-operations-oop.md §6, the 1.2 lynchpin): DUMB protocol identification.
//! `(path, headers)` → which protocol dialect the client is speaking — that is the Router's ENTIRE
//! job. Which OPERATION the request asks for is the chosen `RequestHandler`'s decision
//! (`resolve_operation(path, body)` — it may need the body; the Router never sees one). Returns
//! `None` for non-protocol paths (health, admin, unknown) — those keep their explicit routes.
//!
//! Adding a protocol touches exactly three places: an ID line here, a `RequestHandler`, and its
//! `OperationHandler` cells. Nothing else.
//!
//! NB: this is `router` (protocol identification), distinct from `routing` (load-balancing policy).
#![allow(dead_code)]

use axum::http::HeaderMap;

/// The ingress protocol. Ladder (order load-bearing, M2): mandatory-unique auth header → Gemini path
/// verb → path discriminator. A `(path, header)` pattern claimed by two protocols must be a registry
/// error at load time (enforced elsewhere), never a silent first-match.
pub(crate) fn protocol_id(path: &str, h: &HeaderMap) -> Option<&'static str> {
    // 1. mandatory-unique auth headers (unambiguous regardless of path)
    if h.get("authorization")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|a| a.starts_with("AWS4-HMAC-SHA256"))
    {
        return Some("bedrock");
    }
    if h.contains_key("anthropic-version") || h.contains_key("anthropic-beta") {
        return Some("anthropic");
    }
    if h.contains_key("x-goog-api-key") {
        return Some("gemini");
    }
    // `x-api-key` is Anthropic's credential header and, among the six registered protocols, unique to
    // it (Gemini uses x-goog-api-key; Azure-style is `api-key`). Catches curl users who omit the
    // anthropic-version header.
    if h.contains_key("x-api-key") {
        return Some("anthropic");
    }
    // 2. Gemini path verb (key in ?key=, no header)
    if path.contains(":generateContent")
        || path.contains(":streamGenerateContent")
        || path.contains(":embedContent")
        || path.contains(":batchEmbedContents")
        || path.contains(":predict")
    {
        return Some("gemini");
    }
    // 2b. The Gemini models wildcard surface: everything under `/v1{,beta}/models/{rest}` goes to the
    // gemini ARM even when the action is unknown or absent — that arm owns the ambiguity envelopes
    // (a colon-less `/v1/models/{id}` is an OpenAI `model.retrieve`; an unknown `:action` gets the
    // native Gemini unsupported-action error). Mirrors the pre-collapse wildcard routes exactly.
    if path.starts_with("/v1/models/") || path.starts_with("/v1beta/models/") {
        return Some("gemini");
    }
    // 3. path discriminator (bearer trio + everyone else)
    if path.ends_with("/v1/chat/completions") {
        return Some("openai");
    }
    if path.ends_with("/v2/chat") || path.ends_with("/v1/chat") {
        return Some("cohere");
    }
    if path.ends_with("/v2/embed") || path.ends_with("/v2/rerank") {
        return Some("cohere");
    }
    if path.ends_with("/v1/responses") {
        return Some("responses");
    }
    if path.contains("/v1/messages") {
        return Some("anthropic");
    }
    if path.contains("/converse") {
        return Some("bedrock");
    }
    if path.starts_with("/model/") && path.ends_with("/invoke") {
        return Some("bedrock");
    }
    // OpenAI-family JSON/audio/image ops
    if path.ends_with("/v1/embeddings")
        || path.ends_with("/v1/moderations")
        || path.contains("/v1/images/")
        || path.contains("/v1/audio/")
    {
        return Some("openai");
    }
    None
}

// NOTE: operation resolution deliberately does NOT live here. The Router identifies the protocol;
// the chosen `RequestHandler::resolve_operation(path, body)` decides the operation (it may need the
// body — Gemini's generateContent and Bedrock's InvokeModel are body-disambiguated).

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};

    fn hm(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(*k, HeaderValue::from_static(v));
        }
        h
    }

    /// The resolver table (design §6 test obligation), exercised through the REAL two-step pipeline:
    /// Router IDs the protocol, then that protocol's `RequestHandler::resolve_operation` decides the
    /// operation. Includes collision defaults and the ordering (an Anthropic request to a shared path
    /// must not fall through to OpenAI).
    #[test]
    fn resolver_table() {
        use crate::operation::Operation;
        // (path, headers, expected (protocol, operation)) — aliased to keep the type readable.
        type ResolverCase = (
            &'static str,
            &'static [(&'static str, &'static str)],
            Option<(&'static str, Operation)>,
        );
        let cases: &[ResolverCase] = &[
            (
                "/v1/chat/completions",
                &[],
                Some(("openai", Operation::Chat)),
            ),
            (
                "/v1/embeddings",
                &[],
                Some(("openai", Operation::Embeddings)),
            ),
            (
                "/v1/moderations",
                &[],
                Some(("openai", Operation::Moderation)),
            ),
            (
                "/v1/images/generations",
                &[],
                Some(("openai", Operation::Image)),
            ),
            (
                "/v1/audio/transcriptions",
                &[],
                Some(("openai", Operation::Transcription)),
            ),
            (
                "/v1/audio/translations",
                &[],
                Some(("openai", Operation::Transcription)),
            ),
            ("/v1/audio/speech", &[], Some(("openai", Operation::Speech))),
            ("/v2/chat", &[], Some(("cohere", Operation::Chat))),
            ("/v2/embed", &[], Some(("cohere", Operation::Embeddings))),
            ("/v2/rerank", &[], Some(("cohere", Operation::Rerank))),
            ("/v1/responses", &[], Some(("responses", Operation::Chat))),
            // anthropic ingress: mandatory header wins even though path is model-prefixed
            (
                "/claude-3/v1/messages",
                &[("anthropic-version", "2023-06-01")],
                Some(("anthropic", Operation::Chat)),
            ),
            // anthropic via x-api-key alone (curl user, no version header)
            (
                "/v1/messages",
                &[("x-api-key", "sk-ant-xxx")],
                Some(("anthropic", Operation::Chat)),
            ),
            // anthropic via anthropic-beta alone
            (
                "/v1/messages",
                &[("anthropic-beta", "prompt-caching-2024-07-31")],
                Some(("anthropic", Operation::Chat)),
            ),
            // gemini via header
            (
                "/v1beta/models/x:generateContent",
                &[("x-goog-api-key", "k")],
                Some(("gemini", Operation::Chat)),
            ),
            // gemini via path verb (no header)
            (
                "/v1beta/models/x:embedContent",
                &[],
                Some(("gemini", Operation::Embeddings)),
            ),
            (
                "/v1beta/models/x:predict",
                &[],
                Some(("gemini", Operation::Image)),
            ),
            // bedrock via SigV4 auth; InvokeModel op comes from the BODY (see body cases below)
            (
                "/model/m/converse",
                &[("authorization", "AWS4-HMAC-SHA256 Credential=x")],
                Some(("bedrock", Operation::Chat)),
            ),
            // non-operation paths → None
            ("/v1/models", &[], None),
            ("/healthz", &[], None),
        ];
        for (path, headers, expect) in cases {
            let got = protocol_id(path, &hm(headers)).and_then(|proto| {
                crate::handlers::request_handler(proto)
                    .and_then(|rh| rh.resolve_operation(path, b""))
                    .map(|op| (proto, op))
            });
            assert_eq!(got, *expect, "path {path:?} headers {headers:?}");
        }

        // BODY-disambiguated cases (the RequestHandler needs more than the path):
        let body_cases: &[(&str, &[u8], (&str, Operation))] = &[
            ("/model/m/invoke", br#"{"inputText":"hi"}"#, ("bedrock", Operation::Embeddings)),
            ("/model/m/invoke", br#"{"taskType":"TEXT_IMAGE","textToImageParams":{"text":"x"}}"#,
             ("bedrock", Operation::Image)),
            ("/v1beta/models/x:generateContent",
             br#"{"contents":[{"parts":[{"inline_data":{"mime_type":"audio/wav","data":"AA=="}}]}]}"#,
             ("gemini", Operation::Transcription)),
            ("/v1beta/models/x:generateContent",
             br#"{"contents":[{"parts":[{"text":"hi"}]}],"generationConfig":{"responseModalities":["AUDIO"]}}"#,
             ("gemini", Operation::Speech)),
            // an inline IMAGE part is multimodal CHAT, not audio
            ("/v1beta/models/x:generateContent",
             br#"{"contents":[{"parts":[{"inline_data":{"mime_type":"image/png","data":"AA=="}}]}]}"#,
             ("gemini", Operation::Chat)),
        ];
        for (path, body, (want_proto, want_op)) in body_cases {
            let proto = protocol_id(path, &hm(&[])).expect(path);
            assert_eq!(proto, *want_proto, "protocol for {path:?}");
            let op = crate::handlers::request_handler(proto)
                .and_then(|rh| rh.resolve_operation(path, body))
                .expect(path);
            assert_eq!(op, *want_op, "operation for {path:?} with body");
        }
    }

    #[test]
    fn mandatory_header_beats_path_ordering() {
        // an Anthropic request to a path that also looks bearer-ish must resolve Anthropic, not fall through.
        let p = protocol_id("/v1/messages", &hm(&[("anthropic-version", "2023-06-01")])).unwrap();
        assert_eq!(p, "anthropic");
    }
}
