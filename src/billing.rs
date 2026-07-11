//! Polymorphic billable-item data model (design-operations-oop.md §0b/§5b).
//!
//! The billable UNIT is (operation, model)-dependent: chat/embeddings bill tokens, `whisper-1` bills
//! audio DURATION, `tts-1` bills CHARACTERS, dall-e bills per IMAGE. A single fixed struct cannot
//! represent that, so [`Billing`] is a closed enum every `OperationHandler` emits from a response (or
//! computes from request params when the provider returns no usage object). The 1.2 middle RECORDS
//! every variant (observability from day one) and PRICES [`Billing::Tokens`] exactly as today; the
//! 1.3 governance overhaul prices the remaining units. Closed enum → pricing is an exhaustive match,
//! so adding a unit is a compile error at every price site.
//!
//! Foundation types for the 1.2 operations rebuild; wired into the IR as
//! `IrResp::usage() -> Option<Billing>` (see `ir/variant.rs`). `dead_code` is allowed for units the
//! 1.3 pricing engine has not yet wired.
#![allow(dead_code)]

/// Token usage — the SUPERSET of chat's cache-aware accounting AND the new ops' modality breakdown.
///
/// Subsumes the former `ir::IrUsage`: `input` is UNCACHED input (readers normalize to this), the
/// cache fields stay ADDITIVE across protocols, and the optional per-modality fields carry
/// `gpt-4o-transcribe`-style audio/text/image detail — without losing the chat cache convention. So
/// one `Tokens` variant is lossless for chat (cache) and audio/image (modality) alike.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct TokenUsage {
    /// Uncached input tokens (normalized; providers whose wire total includes the cache subtract it).
    pub(crate) input: u64,
    pub(crate) output: u64,
    /// Additive cache accounting (Anthropic/Bedrock native; OpenAI-family normalized to additive).
    pub(crate) cache_read: Option<u64>,
    pub(crate) cache_creation: Option<u64>,
    /// Per-modality input breakdown (gpt-4o-transcribe etc). When present, these partition `input`.
    pub(crate) input_text: Option<u64>,
    pub(crate) input_audio: Option<u64>,
    pub(crate) input_image: Option<u64>,
}

impl TokenUsage {
    /// Total billable tokens under the normalized additive-cache convention (was
    /// `IrUsage::billable_tokens`): uncached `input` + cache reads + cache creation + `output`. All
    /// adds saturate — operands are UPSTREAM-controlled, so an unchecked `+` could wrap in release.
    pub(crate) fn billable_tokens(&self) -> u64 {
        self.input
            .saturating_add(self.cache_read.unwrap_or(0))
            .saturating_add(self.cache_creation.unwrap_or(0))
            .saturating_add(self.output)
    }

    /// True when the per-modality breakdown is internally consistent with `input` (Billing invariant
    /// m2). A provider that reports only a subset leaves the rest `None`; this checks only the fully
    /// specified case, so a partial report is accepted (not silently trusted as a total).
    pub(crate) fn modality_consistent(&self) -> bool {
        match (self.input_text, self.input_audio, self.input_image) {
            (Some(t), Some(a), Some(i)) => t.saturating_add(a).saturating_add(i) == self.input,
            _ => true,
        }
    }
}

/// The billable item produced for one response. Priced by the 1.3 engine via an exhaustive match.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Billing {
    /// Token-metered (chat, embeddings, `gpt-image-1`, `gpt-4o-transcribe`/`-tts`, Gemini).
    Tokens(TokenUsage),
    /// Audio duration in seconds (`whisper-1` transcription: `usage.type == "duration"`).
    Duration { seconds: f64 },
    /// Character count (`tts-1`/`-hd` speech — no usage in the binary body; counted from `input`).
    Characters { count: u64 },
    /// Per-image, tiered by size/quality (dall-e, Imagen, Titan, SDXL — no usage object in the body).
    Images {
        count: u32,
        size: Option<String>,
        quality: Option<String>,
    },
    /// Flat / no meter (moderations).
    Flat,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn billable_tokens_sums_uncached_input_cache_and_output() {
        let u = TokenUsage {
            input: 10,
            output: 5,
            cache_read: Some(3),
            cache_creation: Some(2),
            ..Default::default()
        };
        assert_eq!(u.billable_tokens(), 20);
    }

    #[test]
    fn billable_tokens_saturates_on_upstream_overflow() {
        let u = TokenUsage {
            input: u64::MAX,
            output: 1,
            ..Default::default()
        };
        assert_eq!(u.billable_tokens(), u64::MAX);
    }

    #[test]
    fn modality_breakdown_partitions_input_when_fully_specified() {
        let ok = TokenUsage {
            input: 12,
            input_text: Some(4),
            input_audio: Some(8),
            input_image: Some(0),
            ..Default::default()
        };
        assert!(ok.modality_consistent());
        let bad = TokenUsage {
            input: 12,
            input_text: Some(4),
            input_audio: Some(4),
            input_image: Some(0),
            ..Default::default()
        };
        assert!(!bad.modality_consistent());
    }

    #[test]
    fn partial_modality_report_is_accepted() {
        // whisper-family reports no modality split — must not be treated as inconsistent.
        let u = TokenUsage {
            input: 100,
            input_audio: Some(100),
            ..Default::default()
        };
        assert!(u.modality_consistent());
    }

    #[test]
    fn billing_variants_are_distinct() {
        assert_ne!(Billing::Flat, Billing::Characters { count: 0 });
        assert_ne!(
            Billing::Duration { seconds: 1.0 },
            Billing::Duration { seconds: 2.0 }
        );
    }
}
