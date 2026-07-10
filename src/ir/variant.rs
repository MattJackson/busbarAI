// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! The per-operation IR enums (design §12.4): `IrReq` / `IrResp`, one variant per operation. The
//! design's single `enum Ir` reconciles to TWO enums because the engine already splits request from
//! response (`IrRequest`/`IrResponse`). The inherent methods here ARE the surface the operation-blind
//! middle sees; each exhaustive `match` is the removability / symmetry gate (§9) — adding operation #7
//! is a compile error at every one.
//!
//! `affinity_key` and `unmappable_for` (B1) land with the seam wiring (P4/P5), where they can be
//! verified against the harness for chat-byte-identical behavior; they are intentionally not stubbed
//! with guessed behavior here.
#![allow(dead_code)]

use super::audio::{SpeechReq, SpeechResp, TranscriptionReq, TranscriptionResp};
use super::embeddings::{EmbeddingsReq, EmbeddingsResp};
use super::image::{ImageReq, ImageResp};
use super::moderation::{ModerationReq, ModerationResp};
use super::{IrRequest, IrResponse};
use crate::billing::{Billing, TokenUsage};
use crate::operation::Operation;

/// Request-side IR — one variant per operation. `Chat` reuses the existing `IrRequest` verbatim.
#[derive(Debug, Clone)]
pub(crate) enum IrReq {
    Chat(IrRequest),
    Embeddings(EmbeddingsReq),
    Moderation(ModerationReq),
    Image(ImageReq),
    Transcription(TranscriptionReq),
    Speech(SpeechReq),
}

impl IrReq {
    /// Which operation this is (the coarse tag the middle carries).
    pub(crate) fn operation(&self) -> Operation {
        match self {
            IrReq::Chat(_) => Operation::Chat,
            IrReq::Embeddings(_) => Operation::Embeddings,
            IrReq::Moderation(_) => Operation::Moderation,
            IrReq::Image(_) => Operation::Image,
            IrReq::Transcription(_) => Operation::Transcription,
            IrReq::Speech(_) => Operation::Speech,
        }
    }

    /// Did the caller ask to stream? Only chat and audio can (1.2); the JSON ops never stream.
    pub(crate) fn wants_stream(&self) -> bool {
        match self {
            IrReq::Chat(r) => r.stream,
            IrReq::Transcription(r) => r.stream,
            IrReq::Speech(r) => r.stream,
            IrReq::Embeddings(_) | IrReq::Moderation(_) | IrReq::Image(_) => false,
        }
    }
}

/// Response-side IR — one variant per operation. `Chat` reuses the existing `IrResponse` verbatim.
#[derive(Debug, Clone)]
pub(crate) enum IrResp {
    Chat(IrResponse),
    Embeddings(EmbeddingsResp),
    Moderation(ModerationResp),
    Image(ImageResp),
    Transcription(TranscriptionResp),
    Speech(SpeechResp),
}

impl IrResp {
    pub(crate) fn operation(&self) -> Operation {
        match self {
            IrResp::Chat(_) => Operation::Chat,
            IrResp::Embeddings(_) => Operation::Embeddings,
            IrResp::Moderation(_) => Operation::Moderation,
            IrResp::Image(_) => Operation::Image,
            IrResp::Transcription(_) => Operation::Transcription,
            IrResp::Speech(_) => Operation::Speech,
        }
    }

    /// The billable item for this response (§0b/§5b). Chat maps the existing `IrUsage` into
    /// `Billing::Tokens` (preserving the uncached-input + additive-cache convention); moderation is
    /// flat; the rest project their own usage. Exhaustive match = the symmetry gate.
    pub(crate) fn usage(&self) -> Option<Billing> {
        match self {
            IrResp::Chat(r) => Some(Billing::Tokens(TokenUsage {
                input: r.usage.input_tokens,
                output: r.usage.output_tokens,
                cache_read: r.usage.cache_read_input_tokens,
                cache_creation: r.usage.cache_creation_input_tokens,
                ..Default::default()
            })),
            IrResp::Embeddings(r) => r.billing(),
            IrResp::Moderation(_) => Some(Billing::Flat),
            IrResp::Image(r) => r.billing(),
            IrResp::Transcription(r) => r.billing(),
            IrResp::Speech(r) => r.billing(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wants_stream_true_only_for_chat_and_audio() {
        assert!(!IrReq::Embeddings(Default::default()).wants_stream());
        assert!(!IrReq::Moderation(Default::default()).wants_stream());
        assert!(!IrReq::Image(Default::default()).wants_stream());
        let s = SpeechReq { stream: true, ..Default::default() };
        assert!(IrReq::Speech(s).wants_stream());
        assert!(!IrReq::Speech(SpeechReq::default()).wants_stream());
    }

    #[test]
    fn usage_projects_per_operation() {
        // moderation → flat
        assert!(matches!(
            IrResp::Moderation(Default::default()).usage(),
            Some(Billing::Flat)
        ));
        // embeddings → tokens
        let e = EmbeddingsResp {
            usage: Some(TokenUsage { input: 5, ..Default::default() }),
            ..Default::default()
        };
        assert!(matches!(IrResp::Embeddings(e).usage(), Some(Billing::Tokens(_))));
        // image with no usage/cost_basis → None
        assert!(IrResp::Image(Default::default()).usage().is_none());
    }

    #[test]
    fn operation_tag_matches_variant_both_directions() {
        assert_eq!(IrReq::Image(Default::default()).operation(), Operation::Image);
        assert_eq!(
            IrResp::Transcription(Default::default()).operation(),
            Operation::Transcription
        );
    }
}
