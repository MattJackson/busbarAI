// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! Anthropic `RequestHandler`. Chat-only today (Anthropic ships no embeddings/images/audio API here);
//! its non-chat operations stay `None` = no-handler 404. Chat dispatches through the same registry as
//! every other operation.
#![allow(dead_code)]

use crate::handlers::{EgressCtx, OperationHandler, RequestHandler};
use crate::operation::Operation;

pub(crate) struct AnthropicRequestHandler;
/// This protocol's OWN chat instance — delete this line (and the registry arm) and this
/// protocol's chat 404s via the standard no-handler path; everything else keeps working.
static CHAT: crate::handlers::chat::ChatOperation =
    crate::handlers::chat::ChatOperation("anthropic");

impl RequestHandler for AnthropicRequestHandler {
    fn protocol_name(&self) -> &'static str {
        "anthropic"
    }
    fn operation_handler(&self, op: Operation) -> Option<&dyn OperationHandler> {
        match op {
            Operation::Chat => Some(&CHAT),
            _ => None, // no embeddings/images/audio → no-handler 404 in the caller's dialect
        }
    }
    fn upstream_path(&self, _ctx: &EgressCtx) -> String {
        // The Messages API (chat only); streaming is negotiated via the `stream` flag + SSE Accept.
        "/v1/messages".into()
    }
    fn resolve_operation(&self, path: &str, _body: &[u8]) -> Option<Operation> {
        path.ends_with("/v1/messages").then_some(Operation::Chat)
    }
}
