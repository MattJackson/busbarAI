// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! The `RequestHandler` and `OperationHandler` trait contracts (design-operations-oop.md §6).
//!
//! NOT to be confused with `handlers.rs` (the axum route functions). Per the design these live under
//! `handlers/request/`; consolidating the physical layout is deferred (a minor, cosmetic move) — the
//! contracts and their behavior are what matter for correctness.
//!
//! - [`OperationHandler`] — ONE per (protocol × operation) cell. A pure codec: wire ↔ IR, both
//!   directions. It never routes, fails over, checks auth, bills, or knows another protocol exists.
//!   Stateless and unit-testable in isolation. The cell exists iff its protocol serves its operation
//!   (§3): an absent cell IS the no-cell 404.
//! - [`RequestHandler`] — ONE per protocol. Owns the dialect and holds its operation cells (its row of
//!   the support matrix). `operation_handler(op) == None` is the no-cell 404 site.
//!
//! Foundation contracts; `dead_code` allowed until the Router/seam wiring consumes them (P3/P4).
#![allow(dead_code)]

use crate::ir::variant::{IrReq, IrResp};
use crate::operation::Operation;
use crate::state::Lane;
use bytes::Bytes;
use serde_json::Value;

/// A request that could not be parsed into this operation's IR — rendered as a caller-dialect 4xx
/// (via the existing `forward::ingress_error`). `UnsupportedSubOp` is the m3 second 404 site
/// (`ImageIr.op` unsupported for the model) — distinct from cell-absence (§3), same terminal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum IngressReject {
    BadRequest(String),
    UnsupportedSubOp { op: Operation, model: String },
}

/// An upstream response body this cell could not decode into its operation's IR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CodecError {
    Malformed(String),
}

/// A pure per-(protocol × operation) codec. Feed it wire, assert the IR; feed it IR, assert the wire.
/// That is the entire contract — the load-bearing discipline that makes the matrix scale.
pub(crate) trait OperationHandler: Send + Sync {
    /// The egress path this cell's protocol serves this operation on, for `lane`.
    fn upstream_path(&self, lane: &Lane, wants_stream: bool) -> String;

    /// CELL capabilities (M1): whether THIS (protocol, operation) cell can stream a response, and
    /// whether its non-stream response must be buffered for usage. Defaults: no.
    fn streaming(&self) -> bool {
        false
    }
    fn taps_usage(&self) -> bool {
        false
    }

    /// Ingress wire → IR (request). Returns this cell's `IrReq` variant.
    fn read_request(&self, wire: &Value) -> Result<IrReq, IngressReject>;
    /// IR → egress wire (request bytes sent upstream).
    fn write_request(&self, ir: &IrReq) -> Bytes;
    /// Egress wire → IR (response) — called only when `taps_usage()` or a cross-protocol translation
    /// requires the neutral form.
    fn read_response(&self, wire: &[u8]) -> Result<IrResp, CodecError>;
    /// IR → caller-dialect wire (response bytes returned to the client).
    fn write_response(&self, ir: &IrResp) -> Bytes;
}

/// A protocol's dialect + its operation cells (one impl per protocol).
pub(crate) trait RequestHandler: Send + Sync {
    /// Stable protocol identity (matches `proto::Protocol::name()`).
    fn protocol_name(&self) -> &'static str;

    /// This protocol's row of the support matrix. `None` ⇒ the protocol does not serve the operation
    /// ⇒ the no-cell 404 (§3). The cell, when present, is a pure codec.
    fn operation_handler(&self, op: Operation) -> Option<&dyn OperationHandler>;
}

#[cfg(test)]
mod tests {
    use super::*;

    // A trivial cell + handler prove the trait objects are object-safe and the no-cell lookup works.
    struct NoopModeration;
    impl OperationHandler for NoopModeration {
        fn upstream_path(&self, _lane: &Lane, _s: bool) -> String {
            "/v1/moderations".into()
        }
        fn read_request(&self, _w: &Value) -> Result<IrReq, IngressReject> {
            Err(IngressReject::BadRequest("noop".into()))
        }
        fn write_request(&self, _ir: &IrReq) -> Bytes {
            Bytes::new()
        }
        fn read_response(&self, _w: &[u8]) -> Result<IrResp, CodecError> {
            Err(CodecError::Malformed("noop".into()))
        }
        fn write_response(&self, _ir: &IrResp) -> Bytes {
            Bytes::new()
        }
    }

    struct OpenAiLike;
    impl RequestHandler for OpenAiLike {
        fn protocol_name(&self) -> &'static str {
            "openai"
        }
        fn operation_handler(&self, op: Operation) -> Option<&dyn OperationHandler> {
            // openai serves moderation; not, say, chat-on-a-moderation-only stub → None = no-cell 404.
            match op {
                Operation::Moderation => Some(&NoopModeration),
                _ => None,
            }
        }
    }

    #[test]
    fn no_cell_lookup_returns_none_for_unsupported_op() {
        let h = OpenAiLike;
        assert!(h.operation_handler(Operation::Moderation).is_some());
        assert!(
            h.operation_handler(Operation::Chat).is_none(),
            "an absent cell IS the no-cell 404"
        );
        assert_eq!(h.protocol_name(), "openai");
    }

    #[test]
    fn sub_op_reject_carries_op_and_model() {
        let r = IngressReject::UnsupportedSubOp { op: Operation::Image, model: "gpt-image-1".into() };
        assert!(matches!(r, IngressReject::UnsupportedSubOp { op: Operation::Image, .. }));
    }
}
