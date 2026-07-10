// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! The forward engine's operation-dispatch handle.
//!
//! There is ONE operation mechanism in busbar: `Router → RequestHandler → OperationHandler → IR`
//! (see [`crate::handler`]). The streaming forward engine (`forward.rs`) needs a small value it can
//! carry through failover/streaming and query for operation behavior; [`OpDispatch`] is that value —
//! a `(operation, cell)` pair. It holds NO behavior of its own: every method delegates to the
//! [`OperationHandler`] cell (capabilities) or to the [`crate::handler::RequestHandler`] (path). The
//! obsolete `OpSpec` trait and `ChatOp` are gone; chat is operation #1, reached through the same
//! registry as every other operation via [`crate::cells::request_handler`].
//!
//! The engine still branches on the *capabilities a cell declares*, never on an operation's
//! *identity* — there is no `if op.name() == "chat"` anywhere in `forward.rs` (enforced by the
//! source-scanning test below). That invariant is what keeps chat removable and audio addable
//! without touching the engine.

use serde_json::Value;

use crate::handler::{EgressCtx, OperationHandler};
use crate::ir::IrUsage;
use crate::operation::Operation;
use crate::proto::ProtocolWriter;
use crate::state::Lane;

/// A `(operation, cell)` dispatch handle, threaded through the forward engine by value (`Copy`). The
/// engine reads operation behavior off it without ever naming an operation.
#[derive(Clone, Copy)]
pub(crate) struct OpDispatch {
    pub(crate) operation: Operation,
    pub(crate) cell: &'static dyn OperationHandler,
}

/// The engine's operation handle. (Kept as `Op` so the engine's signatures read unchanged.)
pub(crate) type Op = OpDispatch;

impl OpDispatch {
    /// Stable identifier — a bounded metric label / tracing span field. VALUE use only; the engine
    /// must never compare or `match` on it (that would be an operation-identity branch).
    pub(crate) fn name(&self) -> &'static str {
        self.operation.name()
    }
    pub(crate) fn streaming(&self) -> bool {
        self.cell.streaming()
    }
    pub(crate) fn wants_stream(&self, body: &Value) -> bool {
        self.cell.wants_stream(body)
    }
    pub(crate) fn body_affinity_key<'a>(&self, body: &'a Value) -> Option<&'a str> {
        self.cell.body_affinity_key(body)
    }
    pub(crate) fn taps_nonstream_usage(&self) -> bool {
        self.cell.taps_usage()
    }
    pub(crate) fn extract_usage(&self, ingress_protocol: &str, body: &[u8]) -> Option<IrUsage> {
        self.cell.extract_usage(ingress_protocol, body)
    }
    pub(crate) fn egress_accept(&self, writer: &dyn ProtocolWriter, wants_stream: bool) -> &'static str {
        self.cell.egress_accept(writer, wants_stream)
    }
    /// The (protocol × operation) upstream path: lane override, else the lane's protocol
    /// `RequestHandler` renders it from resolved primitives (never the `Lane`). `None` only if the
    /// protocol has no registered handler — impossible for chat (all six are registered).
    pub(crate) fn upstream_path(&self, lane: &Lane, wants_stream: bool) -> Option<String> {
        if let Some(p) = &lane.path {
            return Some(p.clone());
        }
        crate::cells::request_handler(lane.protocol.name()).map(|rh| {
            rh.upstream_path(&EgressCtx {
                operation: self.operation,
                model: lane.wire_model(),
                stream: wants_stream,
            })
        })
    }
}

/// Chat — operation #1. A const handle to the shared chat cell, for tests and as the resolver's
/// fallback. Prefer [`chat`] on the request path so the RequestHandler actually decides the cell.
pub(crate) const CHAT: Op = OpDispatch {
    operation: Operation::Chat,
    cell: &crate::cells::chat::CHAT_HANDLER,
};

/// Resolve the chat dispatch THROUGH the registry — the same path every other operation takes:
/// `request_handler(protocol).operation_handler(Chat)`. This is how "the RequestHandler decides which
/// OperationHandler handles the request" is honored for chat too, not just the JSON ops. Every protocol
/// is registered and serves chat, so the fallback is unreachable (kept for total-safety, not behavior).
pub(crate) fn chat(protocol: &str) -> Op {
    crate::cells::request_handler(protocol)
        .and_then(|rh| rh.operation_handler(Operation::Chat))
        .map(|cell| OpDispatch { operation: Operation::Chat, cell })
        .unwrap_or(CHAT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chat_declares_its_capabilities() {
        let chat = CHAT;
        assert_eq!(chat.name(), "chat");
        assert!(chat.streaming(), "chat streams");
        assert!(chat.taps_nonstream_usage(), "chat bills tokens from the body");
        assert!(
            chat.wants_stream(&serde_json::json!({"stream": true})),
            "chat reads the stream boolean"
        );
        assert!(!chat.wants_stream(&serde_json::json!({})));
        assert_eq!(
            chat.body_affinity_key(&serde_json::json!({"system": "you are helpful"})),
            Some("you are helpful")
        );
        assert_eq!(chat.body_affinity_key(&serde_json::json!({"system": ""})), None);
    }

    /// The load-bearing invariant of the operations axis: the forward engine branches on the
    /// *capabilities* a cell declares, never on an operation's *identity*. If someone adds
    /// `if op.name() == "embeddings"` or `match op.name() { ... }` to the engine, chat stops being
    /// just operation #1 and the "add an operation without touching the engine" property is lost.
    /// (`op.name()` used as a value — a tracing span field — is fine; only comparisons/matches are
    /// forbidden.)
    #[test]
    fn engine_never_branches_on_operation_identity() {
        let engine = include_str!("../forward.rs");
        let forbidden = [
            "op.name() ==",
            "op.name()==",
            "== op.name()",
            "==op.name()",
            "match op.name()",
        ];
        for pat in forbidden {
            assert!(
                !engine.contains(pat),
                "src/forward.rs contains a forbidden operation-identity branch (`{pat}`). The \
                 engine must read capabilities off the cell, never branch on op.name()."
            );
        }
    }
}
