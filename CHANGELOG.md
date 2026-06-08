# Changelog

All notable changes to Busbar are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Universal ingress — all six protocols are now first-class ingress.** Previously
  clients could only speak Anthropic (`/<...>/v1/messages`) or OpenAI
  (`/v1/chat/completions`); now native Responses (`/v1/responses`), Cohere
  (`/v2/chat`), Gemini (`/v1beta/models/{model}:generateContent` /
  `:streamGenerateContent`), and Bedrock (`/model/{modelId}/converse` /
  `/converse-stream`) clients can point their SDK's base URL at busbar unmodified.
  Each protocol has one ingress route; body-model protocols (`openai`, `responses`,
  `cohere`) take the model/pool from the request body, path-model protocols
  (`anthropic`, `gemini`, `bedrock`) from the URL. Errors are emitted in the
  caller's native protocol shape, with multi-scheme auth and content-type/identity
  handling per protocol.

### Security
- **`/metrics` is no longer unconditionally open.** It now goes through the same
  auth check as `/stats` (requires a valid client token in `token` mode, or a
  virtual key under governance) because the Prometheus exposition — lane/pool
  topology, per-protocol counters, error rates — is an information-disclosure
  surface. Only `/healthz` remains unconditionally open. In `none`/`passthrough`
  mode `/metrics` is still admitted unconditionally. This supersedes the 0.16.2
  security-review note that described `/metrics` as intentionally open.

## [1.0.0-rc.2] — 2026-06-04

### Changed
- **~30× faster cold start (≈206 ms → ≈6 ms).** The Prometheus recorder is now installed on a
  background thread, so its one-time clock calibration (quanta's TSC calibration, ~200 ms) no longer
  blocks the listener — busbar binds and serves (including `/healthz`) in single-digit milliseconds,
  the right behavior for a daemon/k8s readiness path. Trade-off: `/metrics` renders empty until the
  recorder finishes calibrating shortly after start, and the few requests in that window are not
  counted.

## [1.0.0-rc.1] — 2026-06-03

First release candidate for 1.0. Busbar is feature-complete and API-stable: six wire protocols
with lossless cross-protocol translation, weighted SWRR pools with per-(pool,lane) circuit breaking
and in-flight failover, governance (virtual keys / budgets / rate limits), and a security-hardened
request path — all in one static binary. The remaining work before 1.0.0 is operational validation
(extended soak/leak testing and a performance/SLO baseline), not features.

### Changed
- **Release profile optimized for distribution.** opt-level 3 + fat LTO + `codegen-units = 1` +
  symbol stripping cut the release binary from ~12 MB to **7.4 MB** with a faster hot path. `panic`
  stays `unwind` so a panic in one request task can't abort the whole gateway.
- **README rewritten** around the value proposition (SDK-swap hook, competitor comparison, Security
  and cross-protocol-translation sections, badges).

## [0.17.4] — 2026-06-03

### Fixed
- **OpenAI→Anthropic translation no longer drops `max_tokens`.** An OpenAI-format request that omits
  `max_tokens` (legal — the OpenAI server applies a default) was translated to the Anthropic
  Messages API without one, which hard-rejects it (`400 max_tokens: Field required`). So any
  OpenAI-compatible client relying on the server default 400'd on every call once pointed at an
  Anthropic-backed lane. busbar now injects a `max_tokens` at the cross-protocol translation
  boundary when the egress protocol requires it (Anthropic) and the source omitted it. A
  caller-supplied value is always preserved, and same-protocol passthrough is unaffected. Bedrock
  Converse defaults `maxTokens` server-side, so it is intentionally excluded (injecting would
  silently cap output).

### Added
- **`default_max_tokens` per-model config (optional).** Sets the value injected for the case above;
  unset falls back to a conservative `4096`. Validated `> 0` at startup. Documented in `config.yaml`.

## [0.17.3] — 2026-05-31

Security hardening. The following vectors were reviewed and confirmed clean — SSRF on the routing
paths (provider/model validated against config; upstream URL never caller-derived), token-compare
timing (constant-time for client and admin tokens; virtual keys via SHA-256 + map), `/metrics` label
cardinality (unknown models are rejected before any metric, so labels stay config-bounded),
secret-in-logs (no keys/tokens/bodies logged), SQL injection (fully parameterized), and auth-bypass.
Fixes below close the few hardening gaps that review surfaced.

### Security
- **Request body size limit.** The HTTP router now caps request bodies at 32 MiB
  (`DefaultBodyLimit`) — previously unbounded beyond axum's 2 MiB default toggling, so a
  multi-gigabyte body could be buffered and exhaust memory (notably under `auth.mode=none`).
- **Constant-time token compare hardened.** `constant_time_eq` is now `#[inline(never)]` and runs
  its result through `std::hint::black_box`, so the optimizer can't fold the accumulation loop into
  an early-exit branch and reintroduce a timing signal (no new dependency).
- Documented the two `to_vec` re-serialization sites as the invariants they are (built from
  already-valid JSON), and corrected a stale `UsageTap` doc comment that referenced a nonexistent
  carry buffer.

### Tests
- Added an ad-hoc-route SSRF regression test (unknown provider/model → 404, mismatched provider →
  400, both before any upstream call). 262 tests total.

## [0.17.2] — 2026-05-31

### Fixed
- **Provider `health:` in `config.yaml` now takes effect.** The deployment-side `ProviderDeploy`
  had no `health` field, so a `health:` block under a provider in `config.yaml` (exactly as the
  shipped example documents it) was silently dropped at parse time and `resolve()` only used the
  catalog's `providers.yaml` health — meaning active/dead health probing never spawned for
  config-defined health. `ProviderDeploy` now carries `health`, and `resolve()` merges it
  deployment-wins-over-catalog (mirroring `path`/`auth`). + regression test.

## [0.17.1] — 2026-05-31

Second RC for final testing — fixes from the first 0.17.0 testing pass.

### Fixed
- **Dead-mode health probing now recovers soft-cooldown lanes.** A sub-threshold transient leaves
  the breaker Closed but arms a cooldown; the prober gate only fired for fully-tripped (Open) cells,
  so a single 5xx benched a single-member route for the full ~30s cooldown with no active recovery.
  The gate is now "breaker-suppressed in any cell" (Open/HalfOpen **or** a pending cooldown), and a
  successful probe clears the soft cooldown too.
- **Cross-protocol reasoning is preserved (OpenAI → Anthropic).** A model's `reasoning_content`
  (chain-of-thought) now maps to a `thinking` block instead of being dropped — both non-streaming
  (a leading thinking block) and streaming (a thinking block at index 0, with text/tools shifted
  after it). Non-reasoning responses are unchanged.
- **`--help` / `--version` and startup errors** no longer panic before argument handling: those
  flags print and exit without touching the filesystem, an unknown flag is a clean usage error, and
  every misconfiguration (missing/invalid providers.yaml or config.yaml, bad env interpolation,
  unknown provider/protocol, pool→unknown-model, invalid on_exhausted, bind failure) prints a clean
  `[error] …` instead of a backtrace.

### Notes
- +7 unit tests (now 261): soft-cooldown recovery, reasoning translation (stream + non-stream),
  malformed-Authorization safety, config parsing, JSON-scanner underflow safety, stable affinity hash.

## [0.17.0] — 2026-05-31

Release candidate for final testing ahead of 1.0. Outcome of a systematic review of the full
source for correctness, robustness, and security.

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

[Unreleased]: https://github.com/MattJackson/busbarAI/commits/main
