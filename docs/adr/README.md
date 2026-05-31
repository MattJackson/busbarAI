# Architecture Decision Records

These ADRs are **reconstructed from the code** — the source references ADR
numbers (e.g. `ADR-0001`, `ADR-0002`, `ADR-0005`) but the original decision
documents are not in this repository. Each record below is rebuilt from the
observed implementation; sections marked as reconstructed or inferred should be
treated as such until reconciled with any canonical ADR source.

| ADR | Title | Primary code |
|---|---|---|
| [0001](0001-weighted-selection.md) | Smooth weighted round-robin (SWRR) selection | `src/store.rs` |
| [0002](0002-circuit-breaker.md) | Circuit breaker: disposition taxonomy & recovery | `src/breaker.rs`, `src/store.rs`, `src/forward.rs` |
| [0005](0005-ir-fidelity.md) | Superset IR & translation fidelity | `src/ir.rs`, `src/proto/` |

Other ADR numbers referenced in code but not written up here (the references are
in comments only):

- `ADR-0006` — the `ProtocolReader` / `ProtocolWriter` seam (`src/proto/mod.rs`).
- `ADR-0007` — `IrError` kept compatible with `CanonicalSignal` (`src/proto/mod.rs`).
- `ADR-0008` — the string-keyed `ProtocolRegistry` (`src/proto/mod.rs`, `src/config.rs`).
- `ADR-0009` — the durable governance `Store` seam / SqliteStore (`src/governance.rs`, `src/config.rs`).

See [docs/internals.md](../internals.md) for the design deep-dive these ADRs
underpin, and [docs/architecture.md](../architecture.md) for the public
request-lifecycle overview.
