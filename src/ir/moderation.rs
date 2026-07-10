// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! Moderation IR (design-operations-oop.md §5b). The degenerate operation: OpenAI-only (K=1), no
//! cross-provider superset needed — no other provider ships a moderations endpoint — so this models
//! OpenAI's shape exactly. Split request/response per §12.4. Flat-fee: no `Billing` on the response
//! (`IrResp::usage()` returns `Billing::Flat` for moderation).
#![allow(dead_code)]

use crate::lossless::SourceScopedExtra;
use std::collections::BTreeMap;

/// A moderation input item — text or an image reference (omni-moderation accepts both).
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum ModerationInput {
    Text(String),
    ImageUrl(String),
}

/// Moderation request IR.
#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) struct ModerationReq {
    pub(crate) model: String,
    pub(crate) input: Vec<ModerationInput>,
    /// Source-protocol-namespaced extras (B1). Empty for OpenAI (the only provider), but present for
    /// uniformity so the codec pattern is identical across ops.
    pub(crate) extra: SourceScopedExtra,
}

/// One per-input moderation verdict. Positional: `results[i]` corresponds to `input[i]`.
#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) struct ModerationResult {
    pub(crate) flagged: bool,
    pub(crate) categories: BTreeMap<String, bool>,
    pub(crate) category_scores: BTreeMap<String, f64>,
    /// Per-category, which input modalities triggered it (omni-moderation: `["text"]` / `["image"]`).
    pub(crate) applied_input_types: BTreeMap<String, Vec<String>>,
}

/// Moderation response IR.
#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) struct ModerationResp {
    pub(crate) id: Option<String>,
    pub(crate) model: Option<String>,
    pub(crate) results: Vec<ModerationResult>,
    pub(crate) extra: SourceScopedExtra,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn results_are_positional_and_carry_flags_and_scores() {
        let mut r = ModerationResult::default();
        r.flagged = true;
        r.categories.insert("violence".into(), true);
        r.category_scores.insert("violence".into(), 0.97);
        r.applied_input_types.insert("violence".into(), vec!["text".into()]);
        let resp = ModerationResp { results: vec![r], ..Default::default() };
        assert!(resp.results[0].flagged);
        assert_eq!(resp.results[0].category_scores["violence"], 0.97);
        assert_eq!(resp.results[0].applied_input_types["violence"], vec!["text".to_string()]);
    }

    #[test]
    fn request_holds_mixed_text_and_image_inputs() {
        let req = ModerationReq {
            model: "omni-moderation-latest".into(),
            input: vec![
                ModerationInput::Text("hi".into()),
                ModerationInput::ImageUrl("https://example/i.png".into()),
            ],
            ..Default::default()
        };
        assert_eq!(req.input.len(), 2);
    }
}
