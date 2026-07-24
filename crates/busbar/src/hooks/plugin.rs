// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The engine-side glue that binds a `kind: hook` dlopen plugin to the routing seam: the
//! [`HookProjectors`] the loader's [`busbar_plugin_loader::DlopenPolicy`] calls to (a) build the wire
//! `payload` for each op from the borrowed projection and (b) parse the reply back through the
//! engine's OWN fail-closed `hooks::wire` normalizers.
//!
//! This is what keeps the retired socket/webhook seam and the dlopen seam provably identical: the
//! projection built here is byte-for-byte [`wire::build`]'s output, and the reply is parsed by the
//! same [`wire::normalize`] / [`wire::transform_outcome`] / [`wire::parse_status_metrics`] the old
//! transports used. The loader crate never depends on `hooks::wire` — it only calls these closures.

use super::wire;
use busbar_plugin_loader::hook::HookProjectors;
use std::sync::Arc;

/// Build the shared [`HookProjectors`] the engine installs on every [`DlopenPolicy`]. Constructed
/// once at config load and cloned (behind the `Arc`) into each hook's `open_hook`. Stateless — every
/// closure is a pure projection/parse over the request or the reply.
///
/// [`DlopenPolicy`]: busbar_plugin_loader::DlopenPolicy
pub(crate) fn projectors() -> Arc<HookProjectors> {
    Arc::new(HookProjectors {
        // decide: the full request projection (candidates + context). Byte-identical to what the
        // socket/webhook transports sent — `wire::build` serialized to an owned Value.
        decide: Box::new(|req, cands, ctx| {
            serde_json::to_value(wire::build(wire::OP_DECIDE, req, cands, ctx)).unwrap_or_default()
        }),
        // transform: the request projection with no candidates (a rewrite gate reads the prompt, not
        // the candidate set), exactly as the socket transport's `transform` built it.
        transform: Box::new(|req| {
            let empty: [super::Candidate<'_>; 0] = [];
            let ctx = super::RoutingContext {
                pool: req.pool,
                budget_remaining: None,
                budget: &[],
            };
            serde_json::to_value(wire::build(wire::OP_TRANSFORM, req, &empty, &ctx))
                .unwrap_or_default()
        }),
        // normalize: parse the reply Value into the shared fail-closed `HookResponse` and run the
        // engine's `wire::normalize` (reject > restrict > abstain > order; unknown idxs dropped). A
        // malformed reply is FAIL-CLOSED to Abstain (never a silent route) — the loader coerces the
        // decide-path `Err` to on_error, and an un-parseable OK reply is treated as "no opinion".
        normalize: Box::new(
            |v, cands| match serde_json::from_value::<wire::HookResponse>(v) {
                Ok(parsed) => wire::normalize(parsed, cands),
                Err(_) => super::RoutingDecision::Abstain,
            },
        ),
        // transform_outcome: parse the reply and run the shared reject > rewrite > abstain
        // normalizer. A malformed reply → Abstain (proceed with the ORIGINAL body).
        transform_outcome: Box::new(|v| match serde_json::from_value::<wire::HookResponse>(v) {
            Ok(parsed) => wire::transform_outcome(parsed),
            Err(_) => busbar_api::TransformOutcome::Abstain,
        }),
        // status: parse the `{"status": {...}}` envelope into the shared `HookStatus`. `{}` / no
        // `status` key = the hook doesn't speak status (fail-open None). Metrics are validated +
        // bounded downstream by `parse_status_metrics` (the scrape's job), exactly as before.
        status: Box::new(|v| {
            let env: wire::StatusEnvelope = serde_json::from_value(v).ok()?;
            env.status.map(Into::into)
        }),
        // describe_schema: extract the `schema` member of the self-description envelope (the
        // endpoint adds its own {name, schema} wrapper, so extracting here prevents a double nest).
        describe_schema: Box::new(|v| {
            serde_json::from_value::<wire::DescribeReply>(v)
                .ok()?
                .schema
        }),
    })
}
