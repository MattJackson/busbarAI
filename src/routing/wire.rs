// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! The ONE hook wire contract — shared by every out-of-process routing transport (HTTP webhook,
//! Unix-socket binary). A policy hook receives this exact JSON projection and returns this exact
//! reply shape, whatever the transport, so a hook graduates between transports (webhook prototype →
//! socket binary) without changing its logic. Versioned by shape, not a field, in v1: the schema is
//! append-only.

use super::{Candidate, RoutingContext, RoutingDecision, RoutingRequest};
use serde::{Deserialize, Serialize};

/// The stable request schema sent to a hook: the request projection, every candidate, and context.
#[derive(Debug, Serialize)]
pub(crate) struct HookRequest<'a> {
    pub(crate) request: HookReqProjection<'a>,
    pub(crate) candidates: Vec<HookCandidate<'a>>,
    pub(crate) context: HookContext<'a>,
}

/// The request projection (a cheap, read-only slice of the ingress request). Shape signals only —
/// no prompt text or message content ever rides this projection.
#[derive(Debug, Serialize)]
pub(crate) struct HookReqProjection<'a> {
    pub(crate) pool: &'a str,
    pub(crate) ingress_protocol: &'a str,
    pub(crate) message_count: usize,
    pub(crate) has_tools: bool,
    pub(crate) total_chars: usize,
    pub(crate) max_tokens: Option<u32>,
    pub(crate) stream: bool,
}

/// One candidate as seen by the hook. `idx` is the stable handle the hook echoes back in `order`;
/// the rest are the live signals + operator metadata a policy ranks on.
#[derive(Debug, Serialize)]
pub(crate) struct HookCandidate<'a> {
    pub(crate) idx: usize,
    pub(crate) model: &'a str,
    pub(crate) tier: Option<&'a str>,
    pub(crate) cost_per_mtok: Option<f64>,
    pub(crate) latency_ms: Option<f64>,
    pub(crate) available_concurrency: usize,
    pub(crate) budget_remaining: Option<i64>,
    pub(crate) rate_headroom: Option<f64>,
}

/// The routing context projection.
#[derive(Debug, Serialize)]
pub(crate) struct HookContext<'a> {
    pub(crate) pool: &'a str,
    pub(crate) budget_remaining: Option<i64>,
}

/// The hook's reply. `order` is the ranked preference (candidate `idx` values, most-preferred
/// first); an explicit `abstain: true` (or an absent/empty `order`) means "no opinion". Both fields
/// are optional so an empty `{}` deserializes to Abstain. Unknown JSON fields are ignored, so a hook
/// may attach extra diagnostics without breaking the contract.
#[derive(Debug, Deserialize, Default)]
pub(crate) struct HookResponse {
    #[serde(default)]
    pub(crate) order: Option<Vec<usize>>,
    #[serde(default)]
    pub(crate) abstain: bool,
}

/// Build the wire projection from the live request/candidates/context. Borrows everywhere — the
/// projection is serialized immediately by the transport, never stored.
pub(crate) fn build<'a>(
    req: &'a RoutingRequest<'_>,
    candidates: &'a [Candidate<'_>],
    ctx: &'a RoutingContext<'_>,
) -> HookRequest<'a> {
    HookRequest {
        request: HookReqProjection {
            pool: req.pool,
            ingress_protocol: req.ingress_protocol,
            message_count: req.message_count,
            has_tools: req.has_tools,
            total_chars: req.total_chars,
            max_tokens: req.max_tokens,
            stream: req.stream,
        },
        candidates: candidates
            .iter()
            .map(|c| HookCandidate {
                idx: c.idx,
                model: c.model,
                tier: c.tier,
                cost_per_mtok: c.cost_per_mtok,
                latency_ms: c.latency_ms,
                available_concurrency: c.available_concurrency,
                budget_remaining: c.budget_remaining,
                rate_headroom: c.rate_headroom,
            })
            .collect(),
        context: HookContext {
            pool: ctx.pool,
            budget_remaining: ctx.budget_remaining,
        },
    }
}

/// Normalize a parsed hook reply into a decision: explicit abstain / absent order → `Abstain`;
/// otherwise the shared liberal normalizer (drop unknown idxs, dedup, empty → Abstain). One
/// normalization for every transport.
pub(crate) fn normalize(parsed: HookResponse, candidates: &[Candidate<'_>]) -> RoutingDecision {
    if parsed.abstain {
        return RoutingDecision::Abstain;
    }
    let Some(order) = parsed.order else {
        return RoutingDecision::Abstain;
    };
    let valid: std::collections::HashSet<usize> = candidates.iter().map(|c| c.idx).collect();
    RoutingDecision::from_ranked(order, &valid)
}
