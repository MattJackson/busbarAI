// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! The `RequestHandler` registry + operation cells (design §6/§7), one submodule per protocol. The
//! dispatch (route.rs) looks a protocol's handler up by name; the handler's `operation_handler(op)`
//! returns the cell (or `None` = no-cell 404). Per the design these live under `handlers/request/`;
//! the flat `cells/` layout is a deferred cosmetic move.
//!
//! Foundation; `dead_code` allowed until the seam dispatch consumes the registry (P4).
#![allow(dead_code)]

pub(crate) mod anthropic;
pub(crate) mod bedrock;
pub(crate) mod chat;
pub(crate) mod cohere;
pub(crate) mod gemini;
pub(crate) mod openai;
pub(crate) mod responses;

use crate::handler::RequestHandler;

static OPENAI: openai::OpenAiRequestHandler = openai::OpenAiRequestHandler;
static BEDROCK: bedrock::BedrockRequestHandler = bedrock::BedrockRequestHandler;
static COHERE: cohere::CohereRequestHandler = cohere::CohereRequestHandler;
static GEMINI: gemini::GeminiRequestHandler = gemini::GeminiRequestHandler;
static ANTHROPIC: anthropic::AnthropicRequestHandler = anthropic::AnthropicRequestHandler;
static RESPONSES: responses::ResponsesRequestHandler = responses::ResponsesRequestHandler;

/// The protocol's `RequestHandler`, by name (matches `router` / `proto::Protocol::name()`). All six
/// protocols are registered (every one speaks chat); a registered handler may still return `None`
/// from `operation_handler` for an op it lacks — that IS the no-cell 404.
pub(crate) fn request_handler(protocol: &str) -> Option<&'static dyn RequestHandler> {
    match protocol {
        "openai" => Some(&OPENAI),
        "bedrock" => Some(&BEDROCK),
        "cohere" => Some(&COHERE),
        "gemini" => Some(&GEMINI),
        "anthropic" => Some(&ANTHROPIC),
        "responses" => Some(&RESPONSES),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operation::Operation;

    #[test]
    fn registry_resolves_openai_and_its_moderation_cell() {
        let h = request_handler("openai").expect("openai handler registered");
        assert_eq!(h.protocol_name(), "openai");
        assert!(h.operation_handler(Operation::Moderation).is_some());
        assert!(request_handler("zzz-unknown").is_none(), "unknown protocol → None");
    }

    #[test]
    fn every_protocol_serves_chat_via_its_request_handler() {
        // Chat is operation #1, reached through the SAME registry as every other op. All six
        // protocols resolve a handler and a chat cell — the unified dispatch, no special path.
        for proto in ["openai", "anthropic", "gemini", "bedrock", "cohere", "responses"] {
            let h = request_handler(proto).expect("protocol registered");
            assert!(
                h.operation_handler(Operation::Chat).is_some(),
                "{proto} must serve chat via operation_handler(Chat)"
            );
        }
    }
}
