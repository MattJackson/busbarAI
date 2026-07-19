# Internals, design deep-dive

Developer-facing companion to the public [architecture.md](architecture.md). That
document traces a request end-to-end; this one digs into the *why* behind the
three load-bearing seams: the superset IR, the per-(pool, lane) breaker store, and
the two-stage disposition pipeline, plus the governance internals. Read the
public doc first; this assumes it.

Cross-references: [ADRs](adr/) · [development.md](development.md) ·
[testing.md](testing.md) · [operations.md](operations.md).

---

## 1. The IR fidelity contract (ADR-0005)

The IR (`crates/busbar/src/ir/mod.rs`) is a **superset** of what the six protocols can represent,
not an intersection. Its job is to make a cross-protocol hop lossless for
everything it models, and to make a same-protocol hop lossless for *everything*.

- **`temperature: Option<f64>`, deliberately not f32.** JSON numbers are f64; an
  f32 round-trip turns a caller's `0.7` into `0.699999988…`. The `f64` choice (and
  the comment explaining it) is in `IrRequest`. This is the canonical example of
  the fidelity contract.
- **What survives a cross-protocol hop:** `system`, `messages`, `tools`
  (name + description + JSON `input_schema`), `max_tokens`, `temperature`, the
  `stream` flag, and the block kinds in `IrBlock`:
  - `Text { cache_control, citations }`: Anthropic `cache_control: ephemeral`
    and citation arrays.
  - `Thinking { signature }`, extended-thinking text and its signature.
  - `ToolUse { id, name, input }`, `ToolResult { tool_use_id, content, is_error }`,
    `Image { media_type, data }`.
  - `IrResponse.model`, the upstream-reported serving model, so a pooled
    cross-protocol response still names the member that served it.
- **The `extra` map.** `IrRequest.extra` is a passthrough `Map` for fields adjacent
  to the modeled subset (e.g. `top_p`). A reader can stash unmodeled request
  fields here; whether a given writer re-emits them depends on that writer.
- **Lossy by necessity.** Anything neither modeled in the IR enums nor carried in
  `extra` does not survive a *cross-protocol* hop. **Same-protocol routes use the IR
  path but remain byte-exact.** `StreamTranslate::new_same_proto` re-emits the
  original frame bytes verbatim instead of re-serializing from IR, so a
  same-protocol request/response stays fully lossless while sharing the unified
  translate path.

Streaming uses a parallel set of IR types: `IrStreamEvent`
(MessageStart/BlockStart/BlockDelta/BlockStop/MessageDelta/MessageStop/Error),
`IrDelta`, and `StreamDecodeState`. The decode state exists because flat streams
(OpenAI) must synthesize the IR's block boundaries: one OpenAI chunk fans out to
`0..n` IR events via `read_response_events(.., &mut state)`, whereas Anthropic's
events are 1:1 and ignore the state. See `StreamTranslate` in `crates/busbar/src/proto/mod.rs`
for the live wiring (frame reassembly, Bedrock binary `eventstream` decode
(egress) and re-encode (ingress), and the per-ingress terminator: OpenAI emits
`data: [DONE]`, Anthropic's `message_stop` carries its own).

---

## 2. The StateStore seam & per-(pool, lane) breaker cells

### Why a seam

`StateStore` (`crates/busbar/src/store/mod.rs`) is a trait of **operations, not fields**: `usable`,
`record_transient`, `record_hard_down`, `recover_lane`, `select_weighted`,
`try_acquire`, `spend_budget`, `snapshot`, etc. The production impl is
`InMemoryStore`. The seam keeps the hot lane-health path swappable and, crucially,
lets the breaker FSM be unit-tested by driving operations directly (with injected
time) rather than spinning up HTTP.

### What is lane-global vs per-pool

A lane (one model on one provider) can be a member of several pools. Two concerns
are split:

- **Lane-global** (shared across every pool fronting the lane), kept on
  `LaneState`: the concurrency semaphore (`max_concurrent`), the lifetime
  `max_requests` budget, the permanent `dead` flag, and the `ok`/`err`/
  `client_fault` counters. These cap or describe the **shared upstream**, so they
  must not be per-pool: a concurrency cap that didn't aggregate across pools
  wouldn't cap anything.
- **Per (pool, lane)**: the **breaker FSM**: `breaker_state` (Closed/Open/
  HalfOpen), `streak`, `cooldown_until`, `probe_in_flight`, `err`, the
  `OutcomeWindow`, and SWRR `current_weight`. These live in a `BreakerCell`. The
  rationale: one pool's traffic tripping a lane should not bench that lane for
  other pools (a pool sending pathological requests shouldn't degrade a sibling
  pool's view of the same backend).

### The `BreakerCell` / `BreakerCellAccess` design

The FSM logic is written **once** against `&dyn BreakerCellAccess`, a trait
exposing the breaker atomics (`breaker_state()`, `streak()`, `cooldown_until()`,
`probe_in_flight()`, `err()`, `outcome_window()`, `current_weight()`). Both
`BreakerCell` (per-pool) and `LaneState` (the lane-default cell) implement it.
That is why `should_trip`, `cell_open`, `cell_closed`, `cell_usable_breaker`,
`cell_record_failure`, and `cell_record_success` are generic over the cell and run
identically on either.

### The lazy cell map and the `_in` vs default split

```
InMemoryStore {
    lanes:      Vec<Arc<LaneState>>,                       // lane-global, one per model
    pool_cells: Mutex<HashMap<(Box<str>, usize), Arc<BreakerCell>>>,  // per (pool, lane), lazy
}
```

- `cell(pool, lane)` resolves the breaker cell. An **empty pool name** selects the
  lane-default cell (`LaneState` itself): used by direct/ad-hoc routes and
  `/stats`. A **named pool** lazily creates a dedicated `BreakerCell` on first
  access, inheriting the lane's current known health (breaker state + pending
  cooldown + streak) so a pool whose first request arrives mid-cooldown respects
  it.
- The `StateStore` methods come in two flavors: the bare `lane` methods operate on
  the default cell; the `_in(pool, …)` variants operate on the per-pool cell.
  Release routing always goes through `_in`; the bare variants exist for
  direct/ad-hoc routes, `/stats`, and as a tested handle for unit tests (hence the
  `#[cfg_attr(not(test), allow(dead_code))]` on several of them). The lane-global
  checks (`dead`, budget) are identical in both; only the breaker FSM differs.
- **`recover_lane(lane)`** (a successful health probe) and
  **`lane_tripped_anywhere(lane)`** intentionally cross every cell: a probe tests
  the *shared upstream*, so a recovery clears the default cell **and** every
  per-pool cell for that lane, and "should we probe?" is "tripped in any cell."

### The FSM, precisely (`crates/busbar/src/store/mod.rs`)

- **`cell_usable_breaker(now)`**: Closed → usable iff `now >= cooldown_until`
  (a sub-trip failure can still arm a short cooldown that briefly skips the lane).
  Open → if `now >= cooldown_until`, flip to HalfOpen and admit exactly one probe
  via `compare_exchange` on `probe_in_flight` (single-flight). HalfOpen → not
  usable to anyone else.
- **`cell_record_failure`**: push the timestamp into the `OutcomeWindow`, bump
  `err` and `streak`; if Closed and `should_trip` → `cell_open`, else arm a
  cooldown without changing state; if HalfOpen (the probe failed) → `cell_open`
  with an escalated cooldown.
- **`cell_record_success`**: reset `streak`, push the outcome; if the cell was
  HalfOpen, complete recovery to Closed (`cell_closed` clears streak/err/window/
  cooldown and releases the probe flag). The lane-global `ok` counter is bumped
  by the caller because it is shared.
- **`should_trip`**: `ErrorRate` mode trips when the windowed failure fraction
  `>= threshold` but only once `min_requests` outcomes have accrued in `window_secs`
  (the `err` count is capped at the windowed outcome count so a stale cumulative
  error can't dominate). `Consecutive` mode trips when `streak >= consecutive_n`.
- **`compute_cooldown_with_retry_after`**: exponential backoff doubling from
  `base_cooldown_secs` to `max_cooldown_secs`, indexed by `streak`, with ±10%
  jitter once `streak > 0`. A server `Retry-After` is honored as a **floor**,
  `duration.max(retry_after)`: even beyond `max_cooldown_secs`.
- **Hard-down** (`record_hard_down_for`) bypasses trip evaluation: it sets the
  cell to Open with a fixed sticky cooldown (`HARD_DOWN_COOLDOWN_SECS` = 1800s)
  and records a `dead_reason`, but deliberately does **not** set the lane-global
  `dead` flag, so the half-open probe (or an active probe) can still recover it.

> `OutcomeWindow` is a bounded ring of timestamps (capacity 1024); `count_in_window`
> filters to entries within `now - window_s`. Memory is bounded regardless of
> traffic.

---

## 3. The two-stage disposition pipeline (ADR-0002)

The classification chain (see [breaker.rs](../src/breaker.rs) and the disposition
`match` in `proxy/engine/mod.rs`):

```
Stage 1a  proto.reader().extract_error(status, body) -> RawUpstreamError
Stage 1b  normalize_raw_error(raw, provider.error_map) -> CanonicalSignal { StatusClass }
Stage 2   classify(signal) -> Disposition          (exhaustive, no `_ =>`)
```

**Stage 1b precedence** (in `normalize_raw_error`): a provider's `error_map` entry
for the in-body `provider_code` wins first; then the built-in
`context_length_exceeded` code; otherwise fall through to a universal HTTP-status
classification (401/403→Auth, 429→RateLimit, 408→Timeout, 529→Overloaded,
5xx→ServerError, other 4xx→ClientError). This is why a provider that signals
billing/quota with an idiosyncratic code can be canonicalized purely with YAML
(`error_map`), no code.

**Stage 2 outcome rules** (applied in the `proxy/engine/mod.rs` disposition match: each arm
exhaustively re-matches `StatusClass`, using `unreachable!()` for classes that
cannot reach that arm, so the compiler keeps the taxonomy honest):

- `ClientFault` → `record_client_fault` (a separate counter; **no** err/streak/
  cooldown) and relay the upstream body verbatim. **The healthy backend is never
  penalized for a caller's bad request.**
- `TransientUpstream` → `record_rate_limit_in` (rate-limit, with `Retry-After`) or
  `record_transient_in` (5xx/timeout/network/overloaded); emit failure + failover
  metrics; `continue` to the next candidate.
- `HardDown` → `record_hard_down_in` (sticky cooldown, breaker trip metric); for
  `Auth`, relay the error to the caller; for `Billing`, fail over.
- `ContextLength` → no breaker write; exclude this request's candidates whose
  `context_max <= the failed lane's, then fail over (to a larger-context member).

Passthrough auth nuance: a `401/403` in `passthrough` mode is the *caller's* key
failing, so `forward_with_pool` relays it without touching lane health (the
`is_passthrough_40x` short-circuit before the pipeline).

Failover is allowed **only before the first upstream byte reaches the client**.
After that, `FirstByteBody` (the streaming body wrapper) records the breaker fault
and emits an SSE `error` event instead of retrying: the client already holds a
partial response.

---

## 4. SWRR selection math (ADR-0001)

`select_weighted_for(pool, candidates, weights, now)`:

1. Filter to the **usable** subset (`usable_for`: not dead, budget remaining,
   `cell_usable_breaker` admits).
2. For each healthy candidate: `current_weight += weight`.
3. Winner = max `current_weight`.
4. Winner: `current_weight -= total_weight` (sum over the healthy subset).

For weights 5/1/1 the per-cycle order is `a a b a c a a`: proportional and
smooth. `current_weight` is a per-cell `AtomicI64`, so each pool keeps its own
rotation. Atomics are `Relaxed`; under heavy concurrency the smoothness is
approximate, but eligibility filtering and long-run proportionality hold. See
[ADR-0001](adr/0001-weighted-selection.md).

---

## 5. Governance internals (ADR-0009)

`crates/busbar/src/governance/mod.rs` is a **separate** durable store from the hot in-memory
`StateStore`; it holds only bounded enforcement state.

- **Key storage / hashing.** A virtual key's secret is generated from 16 bytes of
  the OS CSPRNG (`getrandom`), formatted `sk-bb-<hex>`. Only its **SHA-256 hex** is
  stored (`key_hash`); the plaintext is returned **once** at creation and never
  persisted. The key id is `vk_<first 16 hex of the hash>`. Lookup on the hot path
  hashes the presented secret and hits an in-memory `by_hash` cache (a `RwLock`
  map), not the DB; the cache is refreshed after any management-API mutation.
- **Budget windows.** `budget_window(period, now)` maps to an epoch window start:
  `total` → `0` (one all-time window), `daily` → UTC midnight, `monthly` → UTC
  first-of-month (computed with Howard Hinnant's civil-date algorithms, no date
  crate). Spend = flat `price_per_request_cents` (charged at request completion) +
  `tokens/1000 * price_per_1k_tokens_cents` (charged at stream end from the usage
  tap). `is_over_budget` compares accumulated `spend_cents` to `max_budget_cents`.
- **Rate windows.** RPM/TPM are **in-memory, fixed 60s** windows per key
  (`RateState`), not persisted, single-node only. `check_rate` returns
  `Err(retry_after_secs)` (→ 429) when over RPM or TPM. TPM is enforced against
  tokens accrued *so far* in the window; since tokens are fed post-response from
  the usage tap, TPM reflects the prior responses' tokens.
- **SqliteStore.** The ADR-0009 default impl behind the `Store` trait: a single
  mutex-guarded `rusqlite::Connection`, two tables (`virtual_keys`,
  `usage_counters`), `INSERT … ON CONFLICT … DO UPDATE` upserts for both key CRUD
  and usage accumulation. It is embedded + statically linked, preserving the
  single-binary story; the `Store` trait leaves room for a `PostgresStore` for
  multi-node later.
- **Enforcement order** (in `crates/busbar/src/ingress/mod.rs`, before forwarding): allowed-pools
  (`pool_allowed` → 403) → budget (`is_over_budget` → 429, or 400 for Bedrock
  ingress) → rate (`check_rate` → 429 + `Retry-After`). Over-budget never returns
  402 (no vendor does); the body `error.type` is `insufficient_quota`. The auth
  middleware resolves the virtual
  key first (`crates/busbar/src/auth/mod.rs`); `/admin/*` is guarded by the separate admin token,
  not a virtual key.

See [operations.md](operations.md) for the operator-facing governance/admin view.
