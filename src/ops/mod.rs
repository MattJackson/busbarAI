// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! Operations — the second first-class axis of busbar, peer to protocols.
//!
//! A **protocol** is a wire *language* (openai, anthropic, gemini, bedrock, cohere, responses),
//! implemented once behind the [`crate::proto::ProtocolReader`]/[`ProtocolWriter`] vtables. An
//! **operation** is a *kind of work* a request asks for — chat completion, embeddings, moderation,
//! image generation, audio — orthogonal to which language carries it.
//!
//! Historically "chat" was implicit throughout the forward engine: the upstream path, the stream
//! intent, the usage-extraction shape, and the affinity key were all hardcoded to chat's world.
//! `OpSpec` lifts those assumptions out of the engine and behind a spec, so the engine
//! (`forward.rs`) is written ONCE against the spec and every operation — including ones a provider
//! ships next year — is a new spec plus a route registration, never an engine edit.
//!
//! ## The seam discipline
//!
//! Every default method on [`OpSpec`] encodes the MOST RESTRICTIVE behavior (no streaming,
//! same-protocol-only, no usage). Chat is the spec that *overrides* nearly everything; its
//! overrides are the code that used to live in the engine, relocated verbatim. The engine branches
//! on the *capabilities a spec declares*, never on an op's identity — there is no
//! `if op.name() == "chat"` anywhere in `forward.rs`. That invariant is what makes chat removable
//! and audio addable without touching the engine, and it is enforced by a source-scanning test.
//!
//! Representation: `Op = &'static dyn OpSpec`. Specs are zero-state unit structs in `static`s, so
//! threading one through the engine is a pointer copy and a call through it is the same cost class
//! as the `Box<dyn ProtocolWriter>` calls already on those lines — negligible against busbar's
//! ~40 µs overhead, and monomorphizing a 9k-line engine per-op would cost far more than it saves.

use serde_json::Value;

use crate::ir::IrUsage;
use crate::proto::ProtocolWriter;
use crate::state::Lane;

pub(crate) mod chat;

/// A `&'static` handle to an operation spec, threaded through the forward engine.
pub(crate) type Op = &'static dyn OpSpec;

/// A first-class operation. The forward engine consumes only this trait and never names an
/// operation; each concrete op lives in its own file under `src/ops/`.
///
/// The trait surface is exactly what the engine wires today (chat-only). The additional axes an
/// operation needs to be non-chat — cross-protocol translation capability, the `(protocol × op)`
/// support matrix and candidate-lane filtering, opaque (non-JSON) request/response bodies — land
/// alongside the operations that first exercise them, so the engine never carries a capability no
/// registered operation uses.
pub(crate) trait OpSpec: Send + Sync {
    /// Stable identifier — a bounded metric label, the `paths:` config key, and the docs name.
    /// e.g. `"chat"`, `"embeddings"`.
    fn name(&self) -> &'static str;

    /// Can this operation produce a client-facing incremental stream? Gates the ingress `stream`
    /// read, the JSON-array shim probe, SSE detection, and every `StreamTranslate` path. A
    /// non-streaming op's request body is still forwarded byte-verbatim; only response streaming
    /// is disabled. Default: `false`.
    fn streaming(&self) -> bool {
        false
    }

    /// The caller's stream intent, read from the parsed ingress body. Default: `false` — a
    /// non-streaming op never asks the upstream to stream regardless of body contents. Chat
    /// overrides with the OpenAI-family `"stream"` boolean read.
    fn wants_stream(&self, _body: &Value) -> bool {
        false
    }

    /// A session-affinity key derived from the request body when no affinity header is present.
    /// Default: `None`. Chat overrides with the top-level `system` string (Anthropic-shaped).
    fn body_affinity_key<'a>(&self, _body: &'a Value) -> Option<&'a str> {
        None
    }

    /// THE (protocol × operation) SUPPORT-MATRIX CELL, fused with path resolution: the upstream
    /// path this `lane`'s protocol serves this operation on, or `None` if the protocol does not
    /// speak this operation (which drives candidate-lane filtering in the router). The `lane`
    /// carries its own per-operation path override, so provider-specific overrides stay
    /// spec-contained. `None` for chat is impossible — every protocol speaks chat.
    fn upstream_path(&self, lane: &Lane, wants_stream: bool) -> Option<String>;

    /// Should the non-stream response body be buffered so [`OpSpec::extract_usage`] can read it?
    /// Default: `false` — an op that never bills tokens (moderations) and an op whose response is
    /// large binary (audio speech) skip the reassembly buffer entirely. Chat and the token-billed
    /// ops override to `true`.
    fn taps_nonstream_usage(&self) -> bool {
        false
    }

    /// Extract billable usage from a complete same-protocol non-stream 2xx body, called once at
    /// stream end. Default: `None` — flat-fee-only billing (the per-request fee is charged at
    /// admission regardless; token billing only fires when this returns `Some`). Chat runs the
    /// egress protocol's reader over the body and reports its IR usage.
    fn extract_usage(&self, _ingress_protocol: &str, _body: &[u8]) -> Option<IrUsage> {
        None
    }

    /// The egress `Accept` header for the upstream request. Default: the protocol writer's own
    /// stream-aware choice (JSON / SSE / eventstream) — correct for chat and every JSON-response
    /// op. An op whose response is binary (audio speech) overrides this to `*/*`.
    fn egress_accept(&self, writer: &dyn ProtocolWriter, wants_stream: bool) -> &'static str {
        writer.egress_accept(wants_stream)
    }
}

/// The chat operation — spec #1, and the only operation the engine registers today. Threaded
/// through the forward path as the concrete [`Op`]. Embeddings/moderations/images/audio join as
/// their own spec files, and a registry over them lands with the router that enumerates ops.
pub(crate) static CHAT: Op = &chat::ChatOp;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chat_declares_its_capabilities() {
        let chat = CHAT;
        assert_eq!(chat.name(), "chat");
        assert!(chat.streaming(), "chat streams");
        assert!(
            chat.taps_nonstream_usage(),
            "chat bills tokens from the body"
        );
        assert!(
            chat.wants_stream(&serde_json::json!({"stream": true})),
            "chat reads the stream boolean"
        );
        assert!(!chat.wants_stream(&serde_json::json!({})));
        assert_eq!(
            chat.body_affinity_key(&serde_json::json!({"system": "you are helpful"})),
            Some("you are helpful")
        );
        assert_eq!(
            chat.body_affinity_key(&serde_json::json!({"system": ""})),
            None
        );
    }
}
