# ADR-0002 — Circuit breaker: disposition taxonomy & recovery

> Status: accepted (reconstructed from code). `ADR-0002` is referenced throughout
> `src/breaker.rs`, `src/store.rs`, `src/forward.rs`, and `src/config.rs`. The
> prose is reconstructed from the implementation.

## Context

Busbar fronts upstreams of varying reliability. A naive breaker that trips a lane
on *any* non-2xx is wrong in two directions:

- It would **eject a healthy backend** when a caller sends a malformed/oversized
  request (the fault is the caller's, not the upstream's).
- It would treat a recoverable blip (one 503) the same as a definitive failure
  (a bad API key), so it either flaps healthy lanes or never re-tries truly-down
  ones.

The core correctness property we need: **who is at fault determines what
happens.** A client fault must never penalize lane health; an upstream fault
must; and "definitive" upstream faults (auth/billing) deserve different handling
from "transient" ones (5xx/overload/rate-limit/network/timeout).

## Decision

A **two-stage disposition pipeline** classifies every non-2xx outcome, then an
exhaustive `Disposition` match drives the lane state machine.

**Stage 1a** (`ProtocolReader::extract_error`, per protocol) — pull a
`RawUpstreamError { http_status, provider_code, … }` out of the wire body.

**Stage 1b** (`breaker::normalize_raw_error` + the provider's `error_map`) — map
that raw error to a `CanonicalSignal` carrying a typed `StatusClass`. The
provider's `error_map` (data, not code) takes precedence over the HTTP-status
default, so a vendor's idiosyncratic in-body code (e.g. a "1113 = billing"
signal on an HTTP 200/4xx) is canonicalized correctly. `context_length_exceeded`
is recognized as a built-in canonical code.

**Stage 2** (`breaker::classify`) — an **exhaustive** `match` (no `_ =>`) from
`StatusClass` to `Disposition`:

| StatusClass | Disposition |
|---|---|
| `RateLimit`, `Overloaded`, `ServerError`, `Timeout`, `Network` | `TransientUpstream` |
| `Auth`, `Billing` | `HardDown` |
| `ClientError` | `ClientFault` |
| `ContextLength` | `ContextLength` |

Outcome rules (applied in `src/forward.rs`, written via `StateStore`):

- **`ClientFault`** — relay the upstream error verbatim to the caller; record
  *nothing* against the breaker (a separate `client_fault` counter tracks it for
  observability). The lane is never penalized.
- **`TransientUpstream`** — drive trip evaluation (`error_rate` or `consecutive`
  per the pool's `breaker.trip`) and re-arm an exponential cooldown; **fail over**
  to the next candidate. Rate-limit honors the server `Retry-After` as a cooldown
  floor.
- **`HardDown`** — open the breaker immediately with a long *sticky* cooldown
  (`HARD_DOWN_COOLDOWN_SECS` = 1800s / 30 min) rather than waiting for a trip
  threshold. It does **not** set a permanent `dead` flag, so it remains
  recoverable via the half-open probe (or active health probe). Auth → relay the
  error to the caller (the key is wrong; failover to a sibling with the same bad
  config is pointless if config-shared, and in passthrough mode it is the
  caller's key). Billing → fail over (a sibling may have funds).
- **`ContextLength`** — the lane is healthy; record nothing. Exclude this request's
  candidates whose `context_max` is <= the failed lane's, then fail over to a
  larger-context member.

Recovery is a **single-flight half-open probe**: when an Open cell's cooldown
expires, the next selection transitions it to HalfOpen and admits exactly one
request via a CAS on `probe_in_flight`. A 2xx completes recovery to Closed
(streak/err/window cleared); a failure reopens with an escalated cooldown.

## Consequences

- A healthy backend is never benched because a caller sent garbage — the headline
  correctness property, enforced by the exhaustive match (a new `StatusClass`
  won't compile until its disposition is decided).
- Hard-down lanes self-heal once the human fixes the key / funds the account,
  without a restart, because hard-down is a sticky cooldown rather than a kill.
- Breaker state is **per (pool, lane)** (see
  [docs/internals.md](../internals.md)): one pool tripping a lane does not bench
  it in other pools. Concurrency and lifetime budget remain lane-global.
- The exhaustive-match invariant is a documented contribution rule
  ([CONTRIBUTING.md](../../CONTRIBUTING.md)).

## See also

- [docs/internals.md](../internals.md) — the FSM, cells, and `_in` method split.
- [docs/operations.md](../operations.md) — states, trip modes, cooldown backoff.
- [docs/testing.md](../testing.md) — the disposition-matrix tests.
