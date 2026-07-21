# Architecture Decision Records

These ADRs are **reconstructed from the code**: the source references ADR
numbers (e.g. `ADR-0001`, `ADR-0002`, `ADR-0005`) but the original decision
documents are not in this repository. Each record below is rebuilt from the
observed implementation; sections marked as reconstructed or inferred should be
treated as such until reconciled with any canonical ADR source.

| ADR | Title | Primary code |
|---|---|---|
| [0001](0001-weighted-selection.md) | Smooth weighted round-robin (SWRR) selection | `crates/busbar/src/store/mod.rs` |
| [0002](0002-circuit-breaker.md) | Circuit breaker: disposition taxonomy & recovery | `crates/busbar/src/breaker.rs`, `crates/busbar/src/store/mod.rs`, `crates/busbar/src/proxy/engine/mod.rs` |
| [0005](0005-ir-fidelity.md) | Superset IR & translation fidelity | `crates/busbar/src/ir/mod.rs`, `crates/busbar/src/proto/` |

Other ADR numbers referenced in code but not written up here (the references are
in comments only):

- `ADR-0006`: the `ProtocolReader` / `ProtocolWriter` seam (`crates/busbar/src/proto/mod.rs`).
- `ADR-0007`: `IrError` kept compatible with `CanonicalSignal` (`crates/busbar/src/proto/mod.rs`).
- `ADR-0008`: the string-keyed `ProtocolRegistry` (`crates/busbar/src/proto/mod.rs`, `crates/busbar/src/config/mod.rs`).
- `ADR-0009`: the durable governance `Store` seam / SqliteStore (`crates/busbar/src/governance/mod.rs`, `crates/busbar/src/config/mod.rs`).

See [docs/internals.md](../internals.md) for the design deep-dive these ADRs
underpin, and [docs/architecture.md](../architecture.md) for the public
request-lifecycle overview.
