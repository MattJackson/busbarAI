// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! The chat-completion operation — spec #1.
//!
//! Every override below is code that used to live inline in `forward.rs`, relocated verbatim. When
//! the seam refactor lands, each engine site that today hardcodes a chat assumption instead calls
//! the corresponding method here, and for `op = CHAT` the behavior is byte-identical to today.
//! That equivalence is the whole proof obligation of the refactor: chat is not the engine's
//! foundation, it is spec #1, and these methods are exactly what makes it so.

use serde_json::Value;

use super::OpSpec;
use crate::proto::ProtocolWriter;
use crate::state::Lane;

pub(crate) struct ChatOp;

impl OpSpec for ChatOp {
    fn name(&self) -> &'static str {
        "chat"
    }

    fn streaming(&self) -> bool {
        true
    }

    fn wants_stream(&self, body: &Value) -> bool {
        // Relocated from forward.rs: the caller's stream intent from the OpenAI-family body.
        body.get("stream")
            .and_then(|s| s.as_bool())
            .unwrap_or(false)
    }

    fn body_affinity_key<'a>(&self, body: &'a Value) -> Option<&'a str> {
        // Relocated from forward.rs: the top-level `system` string as the body-derived affinity key
        // (used only when no affinity header is present). Empty strings do not pin affinity.
        body.get("system")
            .and_then(|s| s.as_str())
            .filter(|s| !s.is_empty())
    }

    fn upstream_path(&self, lane: &Lane, wants_stream: bool) -> Option<String> {
        // Relocated from forward.rs verbatim: a provider-configured `path` override wins; otherwise
        // the protocol writer's stream-aware default path. Every protocol speaks chat, so this is
        // never `None`.
        Some(match &lane.path {
            Some(p) => p.clone(),
            None => lane
                .protocol
                .writer()
                .upstream_path_for_stream(lane.wire_model(), wants_stream),
        })
    }

    fn taps_nonstream_usage(&self) -> bool {
        true
    }

    fn extract_usage(&self, ingress_protocol: &str, body: &[u8]) -> Option<crate::ir::IrUsage> {
        // Relocated from the forward.rs same-protocol non-stream usage tap: run the egress reader
        // (== ingress on this path) over the reassembled body and report its IR usage. An unknown
        // protocol has no reader and yields `None`, exactly as before.
        crate::proto::protocol_for(ingress_protocol)
            .zip(crate::json::parse::<Value>(body).ok())
            .and_then(|(p, v)| p.reader().read_response(&v).ok())
            .map(|ir| ir.usage)
    }

    fn egress_accept(&self, writer: &dyn ProtocolWriter, wants_stream: bool) -> &'static str {
        // Chat keeps the writer's own stream-aware Accept — byte-identical to today's engine site.
        writer.egress_accept(wants_stream)
    }
}
