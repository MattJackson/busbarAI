// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! OpenAI Responses `RequestHandler`. Chat-only (the `/v1/responses` conversational API); non-chat
//! operations stay `None` = no-handler 404. Chat dispatches through the same registry as every op.
#![allow(dead_code)]

use crate::handlers::{EgressCtx, OperationHandler, RequestHandler};
use crate::operation::Operation;

pub(crate) struct ResponsesRequestHandler;
/// This protocol's OWN chat instance — delete this line (and the registry arm) and this
/// protocol's chat 404s via the standard no-handler path; everything else keeps working.
static CHAT: crate::handlers::chat::ChatOperation =
    crate::handlers::chat::ChatOperation("responses");

impl RequestHandler for ResponsesRequestHandler {
    fn protocol_name(&self) -> &'static str {
        "responses"
    }
    fn operation_handler(&self, op: Operation) -> Option<&dyn OperationHandler> {
        match op {
            Operation::Chat => Some(&CHAT),
            // Enumerated (not `_`) so adding an operation is a compile error here — the documented
            // removability/symmetry gate. The Responses API serves only chat here.
            Operation::Embeddings
            | Operation::Moderation
            | Operation::Image
            | Operation::Transcription
            | Operation::Speech
            | Operation::Rerank => None,
        }
    }
    fn upstream_path(&self, _ctx: &EgressCtx) -> String {
        "/v1/responses".into()
    }
    fn resolve_operation(&self, path: &str, _body: &[u8]) -> Option<Operation> {
        path.ends_with("/v1/responses").then_some(Operation::Chat)
    }
}
