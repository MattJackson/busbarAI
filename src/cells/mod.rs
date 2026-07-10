// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! The `RequestHandler` registry + operation cells (design §6/§7), one submodule per protocol. The
//! dispatch (route.rs) looks a protocol's handler up by name; the handler's `operation_handler(op)`
//! returns the cell (or `None` = no-cell 404). Per the design these live under `handlers/request/`;
//! the flat `cells/` layout is a deferred cosmetic move.
//!
//! Foundation; `dead_code` allowed until the seam dispatch consumes the registry (P4).
#![allow(dead_code)]

pub(crate) mod openai;

use crate::handler::RequestHandler;

static OPENAI: openai::OpenAiRequestHandler = openai::OpenAiRequestHandler;

/// The ingress protocol's `RequestHandler`, by name (matches `router` / `proto::Protocol::name()`).
/// `None` for a protocol with no operation cells yet (its ops 404 until built).
pub(crate) fn request_handler(protocol: &str) -> Option<&'static dyn RequestHandler> {
    match protocol {
        "openai" => Some(&OPENAI),
        // anthropic/gemini/bedrock/cohere/responses handlers registered as their cells are built.
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
        assert!(request_handler("anthropic").is_none(), "unbuilt protocol → None");
    }
}
