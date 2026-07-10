//! The `Operation` axis — busbar's semantic operation vocabulary (design-operations-oop.md §1b/§6).
//!
//! A coarse TAG only: a metrics label and the `paths:` config key. It carries NO capability booleans
//! — whether a given (protocol, operation, model) streams or reports usage is an OperationHandler fact and lives on
//! the `OperationHandler`, not here (design §6, M1). Variant names are 1:1 with the forthcoming
//! `enum Ir` (design C2), so the egress-`write` dispatch is a trivial same-name match.
//!
//! Semantic, endpoint-count-agnostic (§1b): `translation` is `Transcription` with a `target_language`;
//! image edit/variation are `Image` with an `op` discriminant — NOT separate operations.
//!
//! Foundation type; `dead_code` allowed until the Router/IR wiring lands.
#![allow(dead_code)]

/// The seven semantic operations busbar 1.2 speaks. Closed set — adding one is a compile error at
/// every exhaustive match (the removability/symmetry gate, §9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Operation {
    Chat,
    Embeddings,
    Moderation,
    Image,
    Transcription,
    Speech,
    Rerank,
}

impl Operation {
    /// Stable identifier — the metrics label and the `paths:` config key.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Operation::Chat => "chat",
            Operation::Embeddings => "embeddings",
            Operation::Moderation => "moderation",
            Operation::Image => "image",
            Operation::Transcription => "transcription",
            Operation::Speech => "speech",
            Operation::Rerank => "rerank",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_stable_and_distinct() {
        let all = [
            Operation::Chat,
            Operation::Embeddings,
            Operation::Moderation,
            Operation::Image,
            Operation::Transcription,
            Operation::Speech,
            Operation::Rerank,
        ];
        let names: Vec<_> = all.iter().map(|o| o.name()).collect();
        // all distinct
        let mut sorted = names.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), names.len(), "operation names must be unique");
        assert_eq!(Operation::Chat.name(), "chat");
    }
}
