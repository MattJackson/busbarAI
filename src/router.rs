// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! The ingress Router (design-operations-oop.md §6, the 1.2 lynchpin): resolve `(path, headers)` to
//! the ingress `(protocol, operation)` the client is speaking. Ordered ladder — order is load-bearing
//! (M2). Signature is `(path, headers)` only; any body-level disambiguation is the chosen
//! RequestHandler's job. Returns `None` for non-operation paths (health, `/v1/models`, unknown) —
//! those keep their existing routes.
//!
//! NB: this is `router` (protocol/operation resolution), distinct from `routing` (load-balancing
//! policy). Keep the names apart.
//!
//! Foundation; `dead_code` allowed until the seam consumes it (P4).
#![allow(dead_code)]

use crate::operation::Operation;
use axum::http::HeaderMap;

/// The resolved ingress identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Route {
    pub(crate) protocol: &'static str,
    pub(crate) operation: Operation,
}

/// `(path, headers)` → `(protocol, operation)`, or `None` if the path is not one of the six operations.
pub(crate) fn resolve(path: &str, headers: &HeaderMap) -> Option<Route> {
    let operation = resolve_operation(path)?;
    let protocol = resolve_protocol(path, headers)?;
    Some(Route { protocol, operation })
}

/// The ingress protocol. Ladder (order load-bearing, M2): mandatory-unique auth header → Gemini path
/// verb → path discriminator. A `(path, header)` pattern claimed by two protocols must be a registry
/// error at load time (enforced elsewhere), never a silent first-match.
fn resolve_protocol(path: &str, h: &HeaderMap) -> Option<&'static str> {
    // 1. mandatory-unique auth headers (unambiguous regardless of path)
    if h.get("authorization")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|a| a.starts_with("AWS4-HMAC-SHA256"))
    {
        return Some("bedrock");
    }
    if h.contains_key("anthropic-version") {
        return Some("anthropic");
    }
    if h.contains_key("x-goog-api-key") {
        return Some("gemini");
    }
    // 2. Gemini path verb (key in ?key=, no header)
    if path.contains(":generateContent")
        || path.contains(":streamGenerateContent")
        || path.contains(":embedContent")
        || path.contains(":batchEmbedContents")
    {
        return Some("gemini");
    }
    // 3. path discriminator (bearer trio + everyone else)
    if path.ends_with("/v1/chat/completions") {
        return Some("openai");
    }
    if path.ends_with("/v2/chat") || path.ends_with("/v1/chat") {
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

/// The operation, by path suffix (semantic, endpoint-count-agnostic §1b). Translation folds into
/// transcription; image edit/variation fold into Image (the `op` discriminant is read from the body
/// by the cell, not here).
fn resolve_operation(path: &str) -> Option<Operation> {
    if path.contains("/embeddings") || path.contains(":embedContent") || path.contains(":batchEmbedContents") {
        return Some(Operation::Embeddings);
    }
    if path.contains("/moderations") {
        return Some(Operation::Moderation);
    }
    if path.contains("/images/") {
        return Some(Operation::Image);
    }
    if path.contains("/audio/transcriptions") || path.contains("/audio/translations") {
        return Some(Operation::Transcription);
    }
    if path.contains("/audio/speech") {
        return Some(Operation::Speech);
    }
    if path.contains("/chat/completions")
        || path.contains("/v1/messages")
        || path.contains("/v2/chat")
        || path.ends_with("/v1/chat")
        || path.contains("/v1/responses")
        || path.contains(":generateContent")
        || path.contains(":streamGenerateContent")
        || path.contains("/converse")
    {
        return Some(Operation::Chat);
    }
    None
}

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

    /// The resolver table (design §6 test obligation): (path, headers) → (protocol, operation),
    /// including collision defaults and the ordering (an Anthropic request to a shared path must not
    /// fall through to OpenAI).
    #[test]
    fn resolver_table() {
        // (path, headers, expected (protocol, operation)) — aliased to keep the type readable.
        type ResolverCase =
            (&'static str, &'static [(&'static str, &'static str)], Option<(&'static str, Operation)>);
        let cases: &[ResolverCase] = &[
            ("/v1/chat/completions", &[], Some(("openai", Operation::Chat))),
            ("/v1/embeddings", &[], Some(("openai", Operation::Embeddings))),
            ("/v1/moderations", &[], Some(("openai", Operation::Moderation))),
            ("/v1/images/generations", &[], Some(("openai", Operation::Image))),
            ("/v1/audio/transcriptions", &[], Some(("openai", Operation::Transcription))),
            ("/v1/audio/translations", &[], Some(("openai", Operation::Transcription))),
            ("/v1/audio/speech", &[], Some(("openai", Operation::Speech))),
            ("/v2/chat", &[], Some(("cohere", Operation::Chat))),
            ("/v1/responses", &[], Some(("responses", Operation::Chat))),
            // anthropic ingress: mandatory header wins even though path is model-prefixed
            ("/claude-3/v1/messages", &[("anthropic-version", "2023-06-01")], Some(("anthropic", Operation::Chat))),
            // gemini via header
            ("/v1beta/models/x:generateContent", &[("x-goog-api-key", "k")], Some(("gemini", Operation::Chat))),
            // gemini via path verb (no header)
            ("/v1beta/models/x:embedContent", &[], Some(("gemini", Operation::Embeddings))),
            // bedrock via SigV4 auth
            ("/model/m/converse", &[("authorization", "AWS4-HMAC-SHA256 Credential=x")], Some(("bedrock", Operation::Chat))),
            // non-operation paths → None
            ("/v1/models", &[], None),
            ("/healthz", &[], None),
        ];
        for (path, headers, expect) in cases {
            let got = resolve(path, &hm(headers)).map(|r| (r.protocol, r.operation));
            assert_eq!(got, *expect, "path {path:?} headers {headers:?}");
        }
    }

    #[test]
    fn mandatory_header_beats_path_ordering() {
        // an Anthropic request to a path that also looks bearer-ish must resolve Anthropic, not fall through.
        let r = resolve("/v1/messages", &hm(&[("anthropic-version", "2023-06-01")])).unwrap();
        assert_eq!(r.protocol, "anthropic");
    }
}
