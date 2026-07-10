//! B1 cross-protocol drop contract primitives (design-operations-oop.md §1/§5b, risk 6).
//!
//! "Lossless, no compromise" is trivial SAME-protocol (the same cell re-emits everything). The hard,
//! core-value case is CROSS-protocol: a source-only knob with no analog on the egress protocol. These
//! primitives make such a drop EXPLICIT — logged and counted via `Ir::unmappable_for(egress)` — so a
//! populated field can never *silently* vanish (which is a harness-failing bug).
//!
//! Protocols are identified by name (the codebase uses a string-keyed protocol registry).
//!
//! Foundation types; `dead_code` allowed until the IR/codec wiring consumes them.
#![allow(dead_code)]

use serde_json::{Map, Value};
use std::collections::BTreeMap;

/// Request/response extras NAMESPACED BY SOURCE PROTOCOL. Outer key = source protocol name (e.g.
/// `"openai"`), inner map = that protocol's unmodeled fields. An egress cell may CHOOSE to honor a
/// foreign knob it recognizes; anything it does not consume is surfaced by `unmappable_for` and
/// warn-and-dropped — never silently lost. Same-protocol round-trips re-emit the whole map verbatim.
pub(crate) type SourceScopedExtra = BTreeMap<String, Map<String, Value>>;

/// Why a field could not survive to the egress protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DropReason {
    /// A first-class IR field with no analog on the egress protocol (e.g. OpenAI `logprobs` → Anthropic).
    NoTargetAnalog,
    /// A source-protocol-only `extra` knob the egress cell did not recognize.
    SourceOnlyExtra,
}

/// One field that could not be expressed on the egress protocol — surfaced (logged + counted), NEVER
/// silently dropped. The engine emits these from `write_request`/`write_response`; a KAT row asserts
/// no populated field vanishes without a corresponding `DroppedField`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DroppedField {
    /// Source-scoped key or dotted path of the dropped field, e.g. `"openai.logprobs"`.
    pub(crate) field: String,
    /// The egress protocol name that cannot express it.
    pub(crate) egress: String,
    pub(crate) reason: DropReason,
}

impl DroppedField {
    pub(crate) fn no_analog(field: impl Into<String>, egress: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            egress: egress.into(),
            reason: DropReason::NoTargetAnalog,
        }
    }
    pub(crate) fn source_only(field: impl Into<String>, egress: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            egress: egress.into(),
            reason: DropReason::SourceOnlyExtra,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_scoped_extra_namespaces_by_protocol() {
        let mut e: SourceScopedExtra = BTreeMap::new();
        e.entry("openai".into())
            .or_default()
            .insert("logprobs".into(), Value::Bool(true));
        assert!(e["openai"].contains_key("logprobs"));
        assert!(
            !e.contains_key("anthropic"),
            "a foreign protocol's namespace is absent, not merged"
        );
    }

    #[test]
    fn dropped_field_records_field_egress_and_reason() {
        let d = DroppedField::no_analog("openai.logprobs", "anthropic");
        assert_eq!(d.field, "openai.logprobs");
        assert_eq!(d.egress, "anthropic");
        assert_eq!(d.reason, DropReason::NoTargetAnalog);
        assert_eq!(
            DroppedField::source_only("cohere.priority", "openai").reason,
            DropReason::SourceOnlyExtra
        );
    }
}
