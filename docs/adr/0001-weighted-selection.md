# ADR-0001 — Smooth weighted round-robin (SWRR) member selection

> Status: accepted (reconstructed from code). The number `ADR-0001` is referenced
> in `src/store/mod.rs`; the prose below is reconstructed from the implementation, not
> from an original ADR document.

## Context

A pool fans one ingress request out across several member lanes. We want
distribution proportional to per-member `weight` (so an 8:2 pool sends ~80% of
traffic to the first member), but plain weighted random produces bursty,
clumped output, and naive "repeat each member N times in a list" round-robin
produces long runs of the same member. We also need selection to operate only
over the *currently healthy* subset (a tripped or budget-exhausted member must
be skipped), and the algorithm must be cheap and lock-light because it runs on
the hot request path.

## Decision

Use Nginx-style **smooth weighted round-robin**. Each candidate cell carries a
signed `current_weight` (an `AtomicI64` on `BreakerCell` / `LaneState`). On each
selection over the healthy candidate subset (implementation:
`InMemoryStore::select_weighted_for` in `src/store/mod.rs`):

1. Filter candidates to the usable subset (not dead, budget remaining, breaker
   cell admits — see [ADR-0002](0002-circuit-breaker.md)).
2. For every healthy candidate, `current_weight += effective_weight`.
3. Pick the candidate with the largest `current_weight`.
4. `current_weight -= total_weight` (sum of the healthy subset's weights) for the
   winner.

This yields a smooth, deterministic interleaving (for weights 5/1/1 the order is
`a a b a c a a …`) while staying exactly proportional over a full cycle. Because
`current_weight` lives **per (pool, lane) cell**, two pools sharing a lane keep
independent rotation state.

Direct/ad-hoc routes are the degenerate case: a single-member candidate set of
weight 1 (selection over the lane-default cell).

## Consequences

- Distribution is proportional *and* smooth — no thundering one member then
  another.
- Selection naturally adapts when members drop out: an unhealthy member is
  filtered before the weight math, so the remaining members absorb its share for
  that selection.
- `current_weight` is `Relaxed`-ordered atomics; under concurrency the smoothness
  is approximate (two selections can race), but the long-run proportionality and
  the correctness of *which members are eligible* are unaffected.
- Per-pool `current_weight` means a lane in two pools does not share rotation
  position; combined with per-pool breaker cells this keeps pools isolated.

## See also

- [docs/internals.md](../internals.md) — the selection math worked through.
- [docs/architecture.md](../architecture.md) — where selection sits in the
  request lifecycle.
- [docs/configuration.md](../configuration.md) — pool / member `weight` config.
