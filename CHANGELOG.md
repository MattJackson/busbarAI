# Changelog

All notable changes to Busbar are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.17.0] — 2026-05-31

Release candidate for final testing ahead of 1.0. Outcome of a three-model code audit
(Opus, Sonnet, qwen3.5) of the full source.

### Fixed (correctness / security)
- **Panics removed on hostile input:** a malformed `Authorization` header could panic on a
  UTF-8 boundary; a closing brace before an opening one in an upstream body could underflow
  the JSON brace scanner; an API key with a control character could panic the worker. All now
  fail cleanly.
- **Circuit-breaker error-rate trip** now uses windowed errors vs windowed total (both from the
  sliding window) — a long-running lane no longer spuriously trips on clean recent traffic once
  old errors age out.
- **SWRR weight updates are serialized** — concurrent selections could corrupt the algorithm's
  invariant and bias distribution.
- **Cooldown jitter** applies its sign (±) instead of only ever lengthening cooldowns.
- **Session affinity** uses a stable hash, so sticky routing survives a restart (was a randomly
  seeded hasher).
- **Passthrough auth** now forwards the caller's bearer token (handlers previously dropped it,
  silently falling back to the lane's static key).
- **Degraded routing** (least-bad / fallback-pool) now applies cross-protocol translation, so it
  is correct when the chosen lane speaks a different protocol.
- Anthropic `tool` role messages map to the `user` role (no nonexistent `tool_use` role → 422);
  bedrock parse-error signal typo (`ir-parse` → `ir_parse`); token-count i64 saturation.

### Fixed (robustness / accounting)
- Per-key rate-limit map evicts stale windows (was an unbounded per-key memory leak).
- `/admin` usage `requests` no longer double-counts non-streaming cross-protocol responses.
- `/stats` `inflight` is derived from the semaphore (was always 0).

### Changed
- **Logging:** a stderr `tracing` subscriber is always installed (level from `RUST_LOG`); OTLP
  export composes on top when configured. Previously all spans/warnings were dropped unless OTLP
  was set. Operational warnings moved from `eprintln!` to structured `tracing`.
- **Quality:** named the magic numbers/strings (auth modes, breaker states, failover/timeout/
  probe/rate-window/price/window-capacity defaults, Anthropic API version); the outcome window is
  a `VecDeque` (O(1) eviction); scrubbed internal references from comments; `Cargo.toml` reports
  the real version. One unconditional dead-code allow remains (a RAII guard).

## [0.16.2] — 2026-05-31

### Security
- **Admin-token comparison is now constant-time.** The `/admin` management API
  compared the configured admin token with `==`, a timing side channel that could
  let an attacker recover the token byte-by-byte. It now uses the same
  constant-time comparison as client tokens.
- **Virtual-key generation fails closed.** If the OS CSPRNG (`getrandom`) is
  unavailable, busbar now refuses to mint a key instead of falling back to a
  predictable, time-derived secret. (CSPRNG failure is near-impossible on supported
  platforms; the failure aborts only the key-mint request.)

### Notes
- Security review found no other issues: virtual keys are SHA-256 hashed and never
  stored/compared raw; the admin API is token-gated and disabled when no admin token
  is set; key listings never expose hashes; no secrets are logged; cross-protocol JSON
  parsing has no caller-triggered panics; ad-hoc routes only reach configured
  (provider, model) pairs (no SSRF). `/healthz` and `/metrics` are intentionally open
  (protect `/metrics` at the network layer).

## [0.16.1] — 2026-05-31

### Added
- **`error_map` can now match a provider's structured error *type***, not just its
  numeric code. Stage 1b checks `raw.structured_type` against `error_map` as a second
  data-driven signal (the explicit code still wins) — useful for providers that
  surface a typed `error.type` but no code. (Previously `structured_type` was
  extracted by every protocol but never consulted.)
- `/stats` now reports each lane's `client_fault` counter alongside `ok`/`err`.

### Changed
- Dead-code cleanup: removed vestigial scaffolding (`SseCarryBuffer` and its test,
  `COOLDOWN_BASE_SECS`, an unused `FirstByteBody::usage` and `GovState::store`
  accessor) and resolved nearly every `#[allow(dead_code)]` — the remaining
  suppressions are one RAII permit guard plus test-only API gated behind
  `cfg(test)` / `cfg_attr(not(test))`. No behavior change from this part.

## [0.16.0] — 2026-05-31

### Added
- **Per-(pool, lane) circuit-breaker isolation.** A lane shared by multiple pools now carries
  independent breaker state (Open/Closed/HalfOpen, streak, cooldown, error window, SWRR weight)
  per pool, so one pool's traffic tripping a lane no longer benches it for every other pool.
  Direct/ad-hoc routes and `/stats` use a lane-default cell; named pools each get their own,
  created lazily and inheriting the lane's current known health on first use. The breaker FSM
  is now written once over a `BreakerCellAccess` seam and run against either cell — no logic
  duplication. Lane-global concerns (the concurrency semaphore and the `max_requests` lifetime
  budget) remain shared across pools, since they cap the one upstream.
- Active health probing now recovers a lane across **every** cell (all pools + default) on a
  successful probe, and gates `dead`-mode probing on "tripped in any cell" — a probe tests the
  shared upstream, so its result is lane-global.

### Notes
- This supersedes the 0.15.0 note that deferred per-(pool, lane) state.

## [0.15.0] — 2026-05-31

### Fixed
- **Breaker recovery was broken — a tripped lane never came back.** On cooldown
  expiry the lane went HalfOpen and admitted a single probe; the probe's success
  reset the streak but never transitioned the breaker out of HalfOpen
  (`closed_state` was only ever called from tests), so `probe_in_flight` stayed set
  and every later `usable()` returned false. Any lane that ever tripped became
  permanently dead after one request. `record_success` now completes the recovery
  (→ Closed, cooldown cleared, probe released) when it sees a HalfOpen lane.

### Added
- **Active health checks are now live.** A provider's `health:` block has a `mode`:
  `none` (default — passive health only), `dead` (periodically re-probe only tripped
  lanes so a recovered upstream is picked back up promptly), or `active` (probe every
  lane so a silently-dead upstream trips before real traffic hits it). Probes are a
  one-token request built by the lane's protocol writer (`probe_body`), so all six
  protocols work with no per-protocol code; `interval_secs`/`timeout_secs` are honored.
  One background task per probing lane; lanes with no key are skipped.
- **Per-pool circuit-breaker config is now live.** A pool's `breaker:` block
  (`trip.mode` error_rate|consecutive, `trip.window_s`/`threshold`/`min_requests`/`n`,
  `base_cooldown_secs`/`max_cooldown_secs`) is resolved at startup and drives the
  trip decision via `should_trip` — previously the block was parsed but ignored and
  the breaker used a hardcoded `err >= 5` rule. Streak ownership moved to the record
  path (incremented once per failure, reset on success) so consecutive-mode trips and
  cooldown escalation are coherent. Example added to `config.yaml` (pool `sensitive`).
- **`failover.exclusions`** are enforced — members named there are removed from a
  pool's candidate set (never selected, primary or failover).
- **Pool `affinity.header_name`** is honored — the session-pinning header is now
  configurable per pool (defaults to `x-session-id`).

### Notes
- Breaker state remains **per-lane** (not per-(pool,lane)). This is correct for the
  common case and for upstream-driven signals (a 401/429 is a property of the
  upstream, shared across pools). Full per-(pool,lane) state isolation — where one
  shared lane carries independent Open/Closed status per pool — was deferred: it
  would require threading a pool key through the `StateStore` trait and its 77
  constructor sites, and only differs when one lane is shared by multiple pools with
  *different* breaker configs.

## [0.14.0]

### Added
- **Cohere v2 protocol** (`/v2/chat`) — the 6th wire protocol (Reader + Writer,
  request/response/streaming, bearer auth). System prompts are canonicalized into
  the IR so they survive cross-protocol translation.
- **Azure OpenAI auth adapter** — a per-provider `auth: api-key` style that sends
  the `api-key` header instead of bearer (deployment + `?api-version=` ride the
  existing `path` override). No new dependency; same `sign_request` seam as Bedrock
  SigV4. Template shipped in `providers.yaml`.
- `docs/roadmap.md` — the protocols-not-providers thesis and auth-adapter design.

### Fixed
- Cross-protocol pool responses now preserve the upstream `model` field (added to
  the IR), matching direct routes — a pool landing on a cross-protocol member no
  longer returns a model-less body.
- Token accounting on the buffered cross-protocol (non-streaming) path: usage is
  now tapped and charged to the virtual key, so TPM limits enforce (previously
  per-key tokens stayed 0).
- `max_requests` lifetime cap is now enforced — the success path records the lane
  success and decrements the budget (`spend_budget` previously never decremented),
  and the per-lane `ok` counter increments on success (was always 0; also fixed a
  latent double-count in `record_success`).

### Notes
- This changelog was previously stale; entries before 0.14.0 are not yet
  backfilled (tracked for the 1.0 documentation pass).

## [Unreleased]

### Added
- Project scaffolding for open-source release: `README`, `CONTRIBUTING`,
  `SECURITY`, issue/PR templates, and CI workflow.

### Changed
- Licensed the project under **AGPL-3.0-or-later** (previously MIT) — the AGPL's
  network-use clause is the appropriate copyleft for a gateway run as a service.

### Notes
- Pre-1.0: the current binary is an Anthropic-format gateway with named/ad-hoc
  routing, round-robin pools, and a circuit breaker. See the roadmap for the path
  to native multi-protocol support, weighted distribution, and cross-protocol
  failover.

[Unreleased]: https://github.com/MattJackson/busbarAI/commits/main
