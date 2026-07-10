// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! Image-generation IR (design-operations-oop.md §5b). Cross-protocol across OpenAI, Gemini, Bedrock.
//! ONE operation with an `op` discriminant (Generate/Edit/Variation) — edit/variation are not separate
//! ops; an unsupported `(op, model)` pair is a sub-op 404 (§3/m3). Split request/response per §12.4.
//!
//! Losslessness: the three provider geometry conventions (explicit W×H, `aspect_ratio` string, size
//! `tier`) are PARALLEL optionals — never collapsed. Response images are additive [`ImageOutput`]
//! (b64 AND url may coexist). Common cross-provider fields are typed; provider-unique knobs (Titan
//! `controlMode`, SDXL `sampler`/`clip_guidance_preset`, per-prompt weights…) ride source-scoped
//! `extra`. Billing: `Tokens` for gpt-image-1/Gemini, else `Billing::Images` (per-image, no usage body).
#![allow(dead_code)]

use crate::billing::{Billing, TokenUsage};
use crate::lossless::SourceScopedExtra;
use crate::media::ImageOutput;

/// Which image operation. Support is non-uniform per model → unsupported `(op, model)` = 404 (m3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum ImageOp {
    #[default]
    Generate,
    Edit,
    Variation,
}

/// Explicit pixel geometry (OpenAI string `"1024x1024"`/`"auto"`, Titan/SDXL width/height ints).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ImageSize {
    Wh { width: u32, height: u32 },
    Auto,
}

/// Image request IR — superset of common cross-provider fields; exotic knobs ride `extra`.
#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) struct ImageReq {
    pub(crate) op: ImageOp,
    pub(crate) model: String,
    pub(crate) prompt: Option<String>, // Option: dall-e-2 variations carry no prompt
    pub(crate) negative_prompt: Option<String>,
    pub(crate) n: Option<u32>,
    // --- geometry: three mutually-exclusive provider conventions, kept parallel (lossless) ---
    pub(crate) size: Option<ImageSize>,      // OpenAI/Titan/SDXL
    pub(crate) aspect_ratio: Option<String>, // Google, Stable Image ("16:9")
    pub(crate) image_size_tier: Option<String>, // Imagen ("1K"/"2K")
    // --- quality / style / output ---
    pub(crate) quality: Option<String>, // standard|hd|low|medium|high|premium|auto
    pub(crate) style: Option<String>,   // dall-e-3 vivid/natural; SDXL style_preset
    pub(crate) response_format: Option<String>, // url|b64_json (only dall-e honors; else b64)
    pub(crate) output_format: Option<String>, // png|jpeg|webp
    pub(crate) output_compression: Option<u8>,
    // --- sampling / determinism ---
    pub(crate) seed: Option<u64>,
    pub(crate) guidance_scale: Option<f32>, // guidanceScale / cfg_scale / cfgScale
    pub(crate) steps: Option<u32>,          // SDXL
    pub(crate) background: Option<String>,  // transparent|opaque|auto (gpt-image-1)
    // --- edit / img2img inputs ---
    pub(crate) input_images: Vec<String>, // b64 / data-URI (edits up to 16; variation 1)
    pub(crate) mask: Option<String>,      // b64 mask (dall-e-2 edits; Titan)
    pub(crate) mask_prompt: Option<String>, // Titan text mask
    pub(crate) strength: Option<f32>,     // img2img / similarityStrength
    // --- safety / provenance / misc ---
    pub(crate) person_generation: Option<String>,
    pub(crate) moderation: Option<String>,
    pub(crate) add_watermark: Option<bool>,
    pub(crate) output_uri: Option<String>, // Google storageUri (gs://)
    pub(crate) user: Option<String>,
    /// SDXL weighted prompts; if non-empty, overrides `prompt`.
    pub(crate) weighted_prompts: Vec<(String, f32)>,
    pub(crate) extra: SourceScopedExtra,
}

/// For per-image providers that return no usage object — the gateway records what it billed from
/// request params (priced by 1.3). Complements `usage` (token-metered models).
#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) struct CostBasis {
    pub(crate) count: u32,
    pub(crate) size: Option<String>,
    pub(crate) quality: Option<String>,
}

/// Image response IR.
#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) struct ImageResp {
    pub(crate) created: Option<u64>,
    pub(crate) images: Vec<ImageOutput>, // additive per image (b64 AND url may coexist)
    pub(crate) usage: Option<TokenUsage>, // gpt-image-1, Gemini (token-metered)
    pub(crate) cost_basis: Option<CostBasis>, // per-image providers (dall-e/Imagen/Titan/SDXL)
    pub(crate) warnings: Vec<String>,    // raiFilteredReason, finish_reasons, moderation notes
    pub(crate) extra: SourceScopedExtra,
}

impl ImageResp {
    /// Billing projection: token usage when present (gpt-image-1/Gemini); else per-image `Images`.
    pub(crate) fn billing(&self) -> Option<Billing> {
        if let Some(u) = &self.usage {
            Some(Billing::Tokens(u.clone()))
        } else {
            self.cost_basis.as_ref().map(|cb| Billing::Images {
                count: cb.count,
                size: cb.size.clone(),
                quality: cb.quality.clone(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn geometry_conventions_are_parallel_not_collapsed() {
        let req = ImageReq {
            model: "imagen-3".into(),
            aspect_ratio: Some("16:9".into()),
            image_size_tier: Some("2K".into()),
            size: Some(ImageSize::Wh {
                width: 1024,
                height: 1024,
            }),
            ..Default::default()
        };
        // all three can be set — a codec picks its provider's convention without losing the others.
        assert!(req.aspect_ratio.is_some() && req.image_size_tier.is_some() && req.size.is_some());
    }

    #[test]
    fn billing_prefers_tokens_else_per_image() {
        let tokenized = ImageResp {
            usage: Some(TokenUsage {
                input: 5,
                output: 272,
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(matches!(tokenized.billing(), Some(Billing::Tokens(_))));

        let per_image = ImageResp {
            cost_basis: Some(CostBasis {
                count: 2,
                size: Some("1024x1024".into()),
                quality: Some("hd".into()),
            }),
            ..Default::default()
        };
        assert!(matches!(
            per_image.billing(),
            Some(Billing::Images { count: 2, .. })
        ));

        assert!(ImageResp::default().billing().is_none());
    }

    #[test]
    fn variation_op_needs_no_prompt() {
        let req = ImageReq {
            op: ImageOp::Variation,
            input_images: vec!["b64data".into()],
            ..Default::default()
        };
        assert_eq!(req.op, ImageOp::Variation);
        assert!(req.prompt.is_none());
    }
}
