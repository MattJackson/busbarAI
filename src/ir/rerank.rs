// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Rerank IR (the seventh operation). Cross-protocol across Cohere (`/v2/rerank`) and Bedrock
//! (rerank models via `InvokeModel`) — the two protocols that ship a rerank surface. The wire
//! shapes are near-identical (query + documents in, index + relevance_score out), so the IR is a
//! thin normalization; OpenAI/Anthropic/Gemini/Responses have no surface and 404 via the standard
//! no-handler rule. Search-unit metered → `Billing::Flat` (Cohere bills per search unit, carried
//! for the response echo; the pricing engine lands in 1.3).
#![allow(dead_code)]

use crate::billing::Billing;
use crate::lossless::SourceScopedExtra;

/// Rerank request IR — the superset over both providers.
#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) struct RerankReq {
    pub(crate) model: String,
    pub(crate) query: String,
    pub(crate) documents: Vec<String>,
    pub(crate) top_n: Option<u32>,
    pub(crate) max_tokens_per_doc: Option<u32>, // Cohere
    pub(crate) extra: SourceScopedExtra,
}

/// One ranked hit: the index into the REQUEST's `documents` and its relevance.
#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) struct RerankResult {
    pub(crate) index: usize,
    pub(crate) relevance_score: f64,
}

/// Rerank response IR.
#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) struct RerankResp {
    pub(crate) id: Option<String>,
    pub(crate) results: Vec<RerankResult>,
    pub(crate) search_units: Option<u64>, // Cohere meta.billed_units.search_units
    pub(crate) extra: SourceScopedExtra,
}

impl RerankResp {
    /// Billing projection: no token meter on either wire; flat until the 1.3 pricing engine
    /// prices search units.
    pub(crate) fn billing(&self) -> Option<Billing> {
        Some(Billing::Flat)
    }
}
