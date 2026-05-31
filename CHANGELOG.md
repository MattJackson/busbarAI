# Changelog

All notable changes to Busbar are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
