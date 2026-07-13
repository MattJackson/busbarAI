# ADR-0005 — Superset IR & translation fidelity

> Status: accepted (reconstructed from code). `ADR-0005` is referenced in
> `src/ir/mod.rs` (including the explicit f64-not-f32 note). The prose is
> reconstructed from the implementation.

## Context

Busbar's thesis is *protocols, not providers*: a client speaking one wire
protocol can reach a backend speaking another. That requires an intermediate
representation (IR) every protocol can read into and write out of. The IR's whole
reason to exist is **fidelity** — if translating a request silently mutates the
caller's intent, the gateway has failed at its one job. Two specific hazards:

1. **Numeric drift.** JSON numbers are IEEE-754 doubles. If `temperature` were
   held as `f32`, a caller's `0.7` round-trips to `0.699999988…` — a silent
   mutation of exactly the kind busbar exists to prevent.
2. **Dropped semantics.** Anthropic-style `cache_control`, extended-thinking
   blocks (with their `signature`), and citations carry real billing/behavioral
   weight. The IR must model them, not flatten them to plain text.

## Decision

Define a **superset IR** (`src/ir/mod.rs`) that is the union of what the six
protocols can represent, not the intersection:

- `IrRequest` holds `system`, `messages`, `tools`, `max_tokens`,
  `temperature: Option<f64>` (explicitly f64 — see the in-code comment), a
  `stream` flag, and an `extra: Map` passthrough for modeled-subset-adjacent
  fields (e.g. `top_p`).
- `IrBlock` models `Text { cache_control, citations }`,
  `Thinking { signature }`, `ToolUse`, `ToolResult`, and `Image` — so
  cache-control, thinking signatures, and citations survive a hop.
- `IrResponse` carries `model` (the upstream-reported serving model) so a pooled
  cross-protocol response still names the member that served it, matching a direct
  route.
- Same-protocol requests are never cross-protocol-translated: the IR read→write
  translation only runs when `ingress_protocol != egress_name`. A same-protocol hop
  that triggers no body mutation re-emits its original bytes verbatim (byte-for-byte),
  so passthrough stays lossless.

Translation rides the `ProtocolReader` / `ProtocolWriter` seam (referenced as
ADR-0006 in `src/proto/mod.rs`; that seam is the *mechanism*, while this ADR is
about *what the IR preserves*).

## Consequences

- A caller's `temperature` is bit-exact across translation. Same for any modeled
  field.
- Fields outside the modeled subset survive a *same-protocol* route losslessly
  (passthrough) and survive a *cross-protocol* route only insofar as they are
  modeled or carried in `extra`. Anything neither modeled nor in `extra` is
  **lossy by necessity** on a cross-protocol hop — this is documented as expected
  behavior in [operations.md](../operations.md) troubleshooting.
- The IR is a superset, so adding a protocol that introduces a genuinely new
  content kind may require extending the IR enums (and every writer's handling of
  the new variant) — a deliberate, compiler-enforced cost.

## See also

- [docs/internals.md](../internals.md) — the fidelity contract and what is lossy.
- [docs/architecture.md](../architecture.md) — the IR seam in the request
  lifecycle.
- [docs/development.md](../development.md) — adding a protocol against the IR
  contract.
