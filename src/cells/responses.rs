// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! OpenAI Responses `RequestHandler`. Chat-only (the `/v1/responses` conversational API); non-chat
//! operations stay `None` = no-cell 404. Chat dispatches through the same registry as every op.
#![allow(dead_code)]

use crate::handler::{EgressCtx, OperationHandler, RequestHandler};
use crate::operation::Operation;

pub(crate) struct ResponsesRequestHandler;

impl RequestHandler for ResponsesRequestHandler {
    fn protocol_name(&self) -> &'static str {
        "responses"
    }
    fn operation_handler(&self, op: Operation) -> Option<&dyn OperationHandler> {
        match op {
            Operation::Chat => Some(&crate::cells::chat::CHAT_HANDLER),
            _ => None,
        }
    }
    fn upstream_path(&self, _ctx: &EgressCtx) -> String {
        "/v1/responses".into()
    }
}
