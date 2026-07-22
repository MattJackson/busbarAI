// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The per-operation IR enums (design §12.4): `IrReq` / `IrResp`, one variant per operation. The
//! design's single `enum Ir` reconciles to TWO enums because the engine already splits request from
//! response (`IrRequest`/`IrResponse`). The inherent methods here ARE the surface the operation-blind
//! middle sees; each exhaustive `match` is the removability / symmetry gate (§9) — adding the next
//! operation (an 8th, past the current seven Chat..Rerank) is a compile error at every one.
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
    Rerank(crate::ir::rerank::RerankReq),
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
            IrReq::Rerank(_) => Operation::Rerank,
        }
    }

    /// Did the caller ask to stream? Only chat and audio can (1.2); the JSON ops never stream.
    pub(crate) fn wants_stream(&self) -> bool {
        match self {
            IrReq::Chat(r) => r.stream,
            IrReq::Transcription(r) => r.stream,
            IrReq::Speech(r) => r.stream,
            IrReq::Rerank(_) => false,
            IrReq::Embeddings(_) | IrReq::Moderation(_) | IrReq::Image(_) => false,
        }
    }

    /// Neutral CROSS-PROTOCOL egress preparation — each operation applies ITS OWN semantics before
    /// its IR is written into a foreign egress dialect; the engine calls this without knowing which
    /// operation it holds. Chat: default `max_tokens` when the egress requires one, decode the
    /// client-echoed tool ids back to the backend's originals, and clear source-only `extra` keys
    /// (the §8.2 foreign-format leak guard). The other operations' extras are source-scoped by
    /// construction, so they need no clearing.
    pub(crate) fn prepare_for_egress(&mut self, prep: &EgressPrep) {
        match self {
            IrReq::Chat(ir) => {
                if ir.max_tokens.is_none() && prep.egress_requires_max_tokens {
                    ir.max_tokens = Some(
                        prep.lane_default_max_tokens
                            .unwrap_or(prep.global_default_max_tokens),
                    );
                }
                crate::proto::decode_request_tool_ids(prep.ingress_protocol, &mut ir.messages);
                // n>1 clamp on the cross-protocol seam. `n` asks the backend for N candidate
                // completions, but the neutral `IrResponse` models exactly ONE candidate (`role` +
                // one `content` vec) — there is no place to carry choices 1..N. Forwarding `n>1` to a
                // cross-protocol backend made it generate (and BILL for) N candidates while the
                // translation kept only choice 0 and silently discarded the rest: wasted spend plus a
                // response that does not match the request. IR cannot round-trip multiple choices, so
                // the honest behavior is to clamp `n` to 1 before the egress writer emits it, so the
                // backend generates exactly the one candidate the translated response can carry. A
                // SAME-protocol passthrough never reaches here (the body is forwarded verbatim), so
                // `n>1` still works end-to-end where the response is not funneled through the IR.
                if ir.n.is_some_and(|n| n > 1) {
                    tracing::warn!(
                        ingress = %prep.ingress_protocol,
                        "clamping n>1 to 1 on the cross-protocol seam: the neutral response IR carries \
                         a single candidate, so extra choices would be generated, billed, and then \
                         dropped; the backend is asked for exactly one candidate"
                    );
                    ir.n = Some(1);
                }
                // The reasoning gate. A lane that did not claim the capability never receives a
                // thinking param (a non-reasoning model would 400 on it); the request still
                // proceeds, thinking at the backend's default level.
                if ir.reasoning.is_some() {
                    if prep.reasoning_allowed {
                        ir.reasoning_budgets = Some(prep.reasoning_budgets);
                    } else {
                        tracing::warn!(
                            ingress = %prep.ingress_protocol,
                            "dropping cross-protocol reasoning/thinking ask: the target lane does \
                             not declare the capability; set `reasoning: true` on the model (or \
                             pool member) if this backend accepts thinking params"
                        );
                        ir.reasoning = None;
                    }
                }
                // The prompt-cache gate — the cache twin of the reasoning gate above. Fires only
                // when the EGRESS writer's cache marker is model-gated (Bedrock `cachePoint`) and
                // the lane did not assert `prompt_caching`: the breakpoints are cleared so the
                // writer emits no marker a model like Amazon Nova would 400 on. The request still
                // proceeds, uncached — fail-safe over fail-hard.
                if !prep.prompt_caching_allowed {
                    let mut cleared = false;
                    let mut clear_blocks = |blocks: &mut [crate::ir::IrBlock]| {
                        for b in blocks {
                            let cc = match b {
                                crate::ir::IrBlock::Text { cache_control, .. }
                                | crate::ir::IrBlock::Thinking { cache_control, .. }
                                | crate::ir::IrBlock::ToolUse { cache_control, .. }
                                | crate::ir::IrBlock::ToolResult { cache_control, .. }
                                | crate::ir::IrBlock::Image { cache_control, .. } => cache_control,
                                // A raw JSON tool-result block carries no cache breakpoint.
                                crate::ir::IrBlock::Json(_) => continue,
                            };
                            cleared |= cc.take().is_some();
                        }
                    };
                    clear_blocks(&mut ir.system);
                    for m in &mut ir.messages {
                        clear_blocks(&mut m.content);
                    }
                    for t in &mut ir.tools {
                        cleared |= t.cache_control.take().is_some();
                    }
                    if cleared {
                        tracing::warn!(
                            ingress = %prep.ingress_protocol,
                            "dropping cross-protocol prompt-cache breakpoints: the target lane's \
                             dialect gates its cache marker per model and the lane does not \
                             declare the capability; set `prompt_caching: true` on the model if \
                             this backend accepts cache markers (e.g. Claude on Bedrock)"
                        );
                    }
                }
                ir.extra.clear();
            }
            IrReq::Embeddings(_)
            | IrReq::Moderation(_)
            | IrReq::Image(_)
            | IrReq::Transcription(_)
            | IrReq::Speech(_)
            | IrReq::Rerank(_) => {}
        }
    }

    /// Set the model — the ROUTING layer's injection point, operation-blind. Two callers:
    /// path-model ingress dialects (gemini/bedrock carry the model in the URL, so the OperationHandler parses an
    /// empty body model and routing fills it), and the cross-protocol egress hop (the egress wire must
    /// carry the LANE's wire model, not the caller's busbar model name). Chat is a no-op: `IrRequest`
    /// carries no model field (chat's model lives at the routing/rewrite layer, as today).
    pub(crate) fn set_model(&mut self, model: &str) {
        match self {
            IrReq::Chat(_) => {}
            IrReq::Embeddings(r) => r.model = model.to_string(),
            IrReq::Moderation(r) => r.model = model.to_string(),
            IrReq::Image(r) => r.model = model.to_string(),
            IrReq::Transcription(r) => r.model = model.to_string(),
            IrReq::Speech(r) => r.model = model.to_string(),
            IrReq::Rerank(r) => r.model = model.to_string(),
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
    Rerank(crate::ir::rerank::RerankResp),
}

/// Resolved primitives for [`IrReq::prepare_for_egress`] — never a `Lane` or config handle.
pub(crate) struct EgressPrep<'a> {
    pub(crate) ingress_protocol: &'a str,
    pub(crate) egress_requires_max_tokens: bool,
    pub(crate) lane_default_max_tokens: Option<u32>,
    pub(crate) global_default_max_tokens: u32,
    /// The per-lane reasoning capability gate: the effective `reasoning` flag for THIS attempt's
    /// lane (pool-member override wins over the model-level flag). When false and the request
    /// carries a reasoning ask, the ask is CLEARED here with a warn — the one place the gate
    /// lives, so no writer can ever send a thinking param to a lane that did not claim it.
    pub(crate) reasoning_allowed: bool,
    /// The resolved effort-word → budget table (limits.reasoning_effort_budgets), stamped onto the
    /// IR for writers to project words ↔ numbers with the operator's numbers.
    pub(crate) reasoning_budgets: [u32; 4],
    /// The prompt-cache gate: `lane.prompt_caching || !writer.cache_markers_model_gated()`,
    /// resolved by the caller. When false and the request carries `cache_control` breakpoints,
    /// they are CLEARED here with a warn — the one place the gate lives, so no writer can emit a
    /// model-gated cache marker (Bedrock `cachePoint`) to a lane that did not claim it.
    pub(crate) prompt_caching_allowed: bool,
}

impl IrResp {
    /// Neutral CROSS-PROTOCOL ingress preparation — each operation reshapes ITS OWN response IR for
    /// delivery in the caller's dialect; the engine calls this blind. Chat: strip the backend's
    /// native-format identity (`id`/`system_fingerprint`/`stop_sequence`) so the ingress writer
    /// mints CLIENT-format values, stamp a synthesized `created` when the egress reader left it
    /// empty (the protocol-agnostic boundary signal identity-gating writers key on), and remap tool
    /// ids to the caller's native shape. The other operations' responses carry no cross-protocol
    /// identity to reshape.
    pub(crate) fn prepare_for_ingress(&mut self, ingress_protocol: &str, now_epoch: u64) {
        match self {
            IrResp::Chat(ir) => {
                ir.id = None;
                ir.system_fingerprint = None;
                ir.stop_sequence = None;
                if ir.created.is_none() {
                    ir.created = Some(now_epoch);
                }
                crate::proto::ToolIdRemap::default().remap_response(ingress_protocol, ir);
            }
            IrResp::Embeddings(_)
            | IrResp::Moderation(_)
            | IrResp::Image(_)
            | IrResp::Transcription(_)
            | IrResp::Speech(_)
            | IrResp::Rerank(_) => {}
        }
    }

    /// Buffered-2xx-to-native-stream synthesis (bedrock ConverseStream answered by a non-SSE
    /// upstream): operations that can stream delegate to the ingress writer's frame synthesizer;
    /// the rest have no stream wire. Engine stays operation-blind.
    pub(crate) fn wrap_buffered_as_stream(
        &self,
        writer: &dyn crate::proto::ProtocolWriter,
        elapsed_ms: Option<u64>,
    ) -> Option<Vec<u8>> {
        match self {
            IrResp::Chat(ir) => writer.wrap_buffered_as_stream(ir, elapsed_ms),
            IrResp::Embeddings(_)
            | IrResp::Moderation(_)
            | IrResp::Image(_)
            | IrResp::Transcription(_)
            | IrResp::Speech(_)
            | IrResp::Rerank(_) => None,
        }
    }

    pub(crate) fn operation(&self) -> Operation {
        match self {
            IrResp::Chat(_) => Operation::Chat,
            IrResp::Embeddings(_) => Operation::Embeddings,
            IrResp::Moderation(_) => Operation::Moderation,
            IrResp::Image(_) => Operation::Image,
            IrResp::Transcription(_) => Operation::Transcription,
            IrResp::Speech(_) => Operation::Speech,
            IrResp::Rerank(_) => Operation::Rerank,
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
            IrResp::Rerank(r) => r.billing(),
        }
    }

    /// The token usage for this response as an [`IrUsage`], if it is token-metered. Used by the
    /// same-protocol non-stream usage tap (`OperationHandler::extract_usage`) so a token-metered
    /// non-chat op (embeddings) bills its virtual key's TPM/spend the same way chat does — and the
    /// same way the cross-protocol path already bills. Flat/duration/character meters return `None`.
    pub(crate) fn token_usage(&self) -> Option<crate::ir::IrUsage> {
        match self.usage() {
            Some(Billing::Tokens(t)) => Some(crate::ir::IrUsage {
                input_tokens: t.input,
                output_tokens: t.output,
                cache_read_input_tokens: t.cache_read,
                cache_creation_input_tokens: t.cache_creation,
            }),
            _ => None,
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
        let s = SpeechReq {
            stream: true,
            ..Default::default()
        };
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
            usage: Some(TokenUsage {
                input: 5,
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(matches!(
            IrResp::Embeddings(e).usage(),
            Some(Billing::Tokens(_))
        ));
        // image with no usage/cost_basis → None
        assert!(IrResp::Image(Default::default()).usage().is_none());
    }

    #[test]
    fn token_usage_maps_token_meter_and_none_for_flat() {
        // A token-metered embeddings response projects its input tokens into an IrUsage.
        let e = EmbeddingsResp {
            usage: Some(TokenUsage {
                input: 12,
                output: 0,
                ..Default::default()
            }),
            ..Default::default()
        };
        let tu = IrResp::Embeddings(e)
            .token_usage()
            .expect("token-metered op yields Some");
        assert_eq!(tu.input_tokens, 12);
        // A flat-metered moderation response has no token usage.
        assert!(IrResp::Moderation(Default::default())
            .token_usage()
            .is_none());
    }

    #[test]
    fn operation_tag_matches_variant_both_directions() {
        assert_eq!(
            IrReq::Image(Default::default()).operation(),
            Operation::Image
        );
        assert_eq!(
            IrResp::Transcription(Default::default()).operation(),
            Operation::Transcription
        );
    }
}
