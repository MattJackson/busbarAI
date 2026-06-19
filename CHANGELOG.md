# Changelog

All notable changes to Busbar are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0-rc.6] — 2026-06-19

Performance and observability. Busbar now reports its own added latency in-band, and the hot
translate path is ~2× faster on large payloads via SIMD JSON. The request path, wire protocols,
breaker FSM, governance contract, and lossless translation semantics are unchanged.

### Added

- **`Server-Timing: busbar;dur=<ms>` response header.** Busbar reports its own internal processing
  time — total request time minus the upstream round-trip — on every response. A W3C-standard,
  per-request measurement of exactly the latency Busbar adds (not the network, not the model), readable
  in browser DevTools or any APM tool, on your own production traffic.

### Changed

- **SIMD JSON (sonic-rs) on the hot translate path.** Request/response body parse and serialize now go
  through a single `crate::json` seam backed by sonic-rs (NEON on arm64, AVX2/SSE on x86); `serde_json`
  is retained for cold/config/error paths and as the in-memory `Value` type. ~5× faster serialize on
  the large, string-heavy bodies LLM traffic carries.
- **Single-parse ingest.** The request body is parsed once across the routing and forwarding layers —
  the ingress layer hands its already-parsed `Value` to the forwarder — instead of being parsed twice.
- Net effect (measured on a pinned AWS `c7g.2xlarge`, Server-Timing): cross-protocol translation of a
  ~32 KB payload roughly halved (≈186µs → ≈84µs); small requests are unchanged at the per-request
  framework floor (~33µs). Full reproducible methodology and numbers are published at
  [getbusbar.com/benchmark](https://getbusbar.com/benchmark).

### Notes

- The sonic-rs serializer formats some floats differently from serde_json (e.g. `1e26` vs `1e+26`,
  `-0.0` rendered as `0.0`) — numerically lossless and valid JSON. Only an exact-string comparison on an
  exotic numeric passthrough field would observe a different byte sequence; the IR round-trip and all
  translation behavior are unchanged.

## [1.0.0-rc.5] — 2026-06-17

Three independent features land together: pluggable routing policies, deeper Prometheus
observability, and native inbound TLS/mTLS. The request path, wire protocols, breaker FSM,
and governance contract are unchanged. This release also folds in a multi-round security
and correctness audit and an internal provider-containment refactor.

### Added

- **Pluggable routing policies (`route:` per pool).** A pool can declare a `route:` key
  that produces an ordered preference over its members. The ranked list feeds the existing
  failover loop — if the policy's first choice is tripped or at capacity, Busbar walks to
  the next; a policy can never strand a request.

  Five built-in native policies, selected with `route: <name>`:

  - `weighted` — default smooth weighted round-robin (SWRR); no behavioral change from rc.4.
  - `cheapest` — prefer the member with the lowest operator-declared `cost_per_mtok`.
  - `fastest` — prefer the member with the lowest rolling-EWMA latency.
  - `least_busy` — prefer the member with the most available concurrency permits.
  - `usage` — prefer the member with the most rate-limit headroom (fraction of the
    caller key's RPM/TPM budget still available this window), steering traffic away from
    candidates approaching a provider 429.

  Members missing a signal are demoted to the back of the preference list but never
  dropped, so incomplete signal data cannot strand a lane.

  Two additional transports for operator-defined logic:

  - `webhook` — POSTs a stable JSON projection of the request and candidates to an
    operator-run HTTP sidecar (any language, any runtime); the sidecar returns a ranked
    `{ "order": [...] }`.
  - `script` — evaluates an operator-supplied [Rhai](https://rhai.rs/) script compiled
    once at config load. Gated behind the `script-policy` Cargo feature (off by default),
    keeping the default binary free of the Rhai dependency.

  Both transports honor a per-pool `timeout_ms`; a timeout or transport error falls back
  to the pool's `on_error` setting (`abstain | weighted | reject | first`) and never
  blocks or fails the client request.

  **Zero-cost default path.** A pool with `route: weighted` — including any pool that
  omits the `route:` key entirely — resolves to no policy object at config load. The hot
  path is a single branch that is never entered for default pools: no allocation, no signal
  projection, no I/O, identical throughput to rc.4.

- **Four new Prometheus gauges (scrape-time).** Refreshed on each `/metrics` scrape from
  in-process reads, not on the request hot path. All label values are drawn from
  operator-controlled configuration; no client-supplied input appears as a label:

  - `busbar_key_spend_cents` — per-virtual-key accumulated spend in cents for the current
    budget window (label: `key` = virtual-key id). Only emitted when governance is enabled.
  - `busbar_key_budget_remaining_cents` — `max_budget_cents` minus current spend for keys
    that carry a budget cap. Suitable for Prometheus burn-rate alerting. Only emitted for
    capped keys.
  - `busbar_key_tokens_total` — accumulated tokens consumed by each virtual key in the
    current budget window (label: `key`).
  - `busbar_lane_state` — per-(pool, lane-index) circuit-breaker health: `0` = healthy
    (Closed), `1` = half-open (cooling, probe admitted), `2` = tripped (Open or
    hard-down). Labels: `pool` and `lane` (numeric index). Read-only; does not trigger
    FSM transitions.

- **Native inbound TLS and optional mutual TLS.** Busbar now terminates TLS on the
  client-to-Busbar hop natively, without a reverse proxy. Add a `tls:` block to
  `config.yaml`:

  ```yaml
  tls:
    cert_file: /etc/busbar/tls/fullchain.pem
    key_file:  /etc/busbar/tls/privkey.pem
    client_ca_file: /etc/busbar/tls/ca.pem   # optional — enables mTLS
  ```

  When `client_ca_file` is present, Busbar requires a client certificate signed by that CA;
  connections without a valid cert are rejected at the TLS handshake, before any HTTP or
  bearer-token processing. Omitting `tls:` entirely leaves the plain-HTTP path unchanged.

### Security

- **mTLS client-cert enforcement.** With `client_ca_file` set, unauthenticated connections
  are rejected at the TLS layer — before HTTP routing or governance checks — providing
  zero-trust transport without a service mesh.
- **TLS handshake timeout.** A 10-second wall-clock cap on each incoming TLS handshake
  prevents a client from parking a file descriptor and task indefinitely before
  authentication (slowloris / handshake-flood mitigation). A timed-out or failed handshake
  drops only that connection; the server continues serving other clients.
- **Webhook response size cap.** The `webhook` routing transport reads sidecar responses
  under a 64 KiB cap. A slow or hostile sidecar cannot drive unbounded memory allocation;
  an oversized response is an error and falls back to `on_error`.
- **Rhai script operation budget.** The `script` transport evaluates operator scripts under
  a per-invocation Rhai operation count limit and a hard wall-clock deadline (run on the
  blocking pool so a runaway script cannot pin an async worker). No module resolver, no file
  or network host functions are registered in the sandboxed engine.
- **Startup fail-fast for TLS config errors.** PEM cert, key, or CA load/parse failures
  abort startup with a message naming the offending file; key material is never logged. A
  single-connection handshake failure is logged at debug level only.

### Fixed

- **Weight-zero drain bypass on the session-affinity path.** A pool member set to
  `weight: 0` (an operator draining a lane) could still receive requests that carried an
  existing session-affinity stickiness, sidestepping the drain. Affinity resolution now
  applies the same weight-zero exclusion as fresh routing; regression test added.
- **Anthropic outbound `User-Agent`.** Corrected the User-Agent header shape emitted on the
  Anthropic upstream hop.
- **SSRF guard covers the Oracle Cloud metadata address.** The trusted-upstream net guard
  now blocks `192.0.0.192` alongside the other link-local / cloud-metadata ranges.
- Additional cross-cutting correctness fixes from a deep audit pass (streaming-translation
  vtable flag propagation, request-id header constant) and the multi-round security and
  correctness review (rounds R3–R12).

### Changed

- **Provider containment (internal).** All provider-name branches were removed from the
  protocol-agnostic core and relocated behind the `ProtocolReader`/`ProtocolWriter` vtable,
  so provider-specific behavior lives entirely in `src/proto/*` (safe defaults plus
  per-provider overrides). No user-visible behavior change — architecture only.

## [1.0.0-rc.4] — 2026-06-16

A continuation of the rc.3 hardening campaign: nine further rounds (R19→R27) of
multi-round, dual-model (Sonnet + Opus) security/correctness auditing over the
rc.3 tree, with adversarial triage and class-level fixes. No API changes vs rc.3.

The severity gate — **0 critical / 0 high / 0 medium-security / 0 medium-correctness**
— is met and has held flat for the final four rounds; remaining findings are
documented low/medium-completeness items at the asymptote of the audit loop. The
test suite grew from 267 (rc.2) to **1334** passing; `fmt`, `build`, `clippy
-D warnings`, and `test` all green.

### Fixed
- **Circuit-breaker / streaming / FSM cluster** — clean SSE stream-end no longer
  records a spurious breaker failure; breaker success is recorded synchronously
  before streaming; mid-stream error paths no longer double-record. Readiness
  checks (`cell_ready_breaker`/`is_ready`) are split from the probe-acquiring
  transition (`cell_acquire_breaker`) so candidate enumeration no longer steals
  probes or transitions lanes; a failed half-open probe releases its permit
  instead of benching a lane permanently.
- **Upstream `Retry-After`** is extracted on the forward path and propagated
  through error normalization so the breaker cooldown floor is honored.
- **SSRF hardening** — backslash-bypass and OTLP-redirect vectors closed; the
  OTLP exporter uses a no-redirect client. Removed a duplicate `reqwest` major
  as a side effect.
- **Same-protocol non-stream large-body token undercount** — `FirstByteBody`
  now buffers and feeds the whole body once, so usage is no longer dropped past
  the per-chunk scan cap.
- A long tail of medium/low conformance, governance, admin-validation, and
  protocol-translation findings across all six wire protocols (see the private
  audit residuals for the per-finding ledger).

## [1.0.0-rc.3] — 2026-06-10

This is a hardening release: a multi-round security/correctness audit campaign over the rc.2 code,
plus the universal-ingress feature. No API changes vs rc.2 beyond the new ingress routes.

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
- **SSRF guard hardened against trailing-dot hosts.** The webhook and OTLP endpoint
  validators stripped a trailing FQDN-root dot only inside one branch, so
  `127.0.0.1.` / `metadata.google.internal.` slipped past the IP-literal and
  cloud-metadata checks and resolved to internal targets. The dot is now stripped
  before every check, matching the upstream-config SSRF guard.
- **Admin reserved-name collision now rejected for models too.** A model named
  `admin` was reachable at `/admin/v1/messages` (the operator admin surface),
  making it unreachable to clients and bypassing per-model governance. Config
  validation now rejects it, symmetric with the pool/provider checks.
- **Anthropic egress no longer emits a dual-credential header.** An ambiguous
  credential previously sent both `x-api-key` and `authorization: Bearer` — a
  request shape no native client produces. The wire path now resolves it to the
  single native header the auth mode implies.

### Fixed
- **Cohere streaming text no longer dropped.** The content-delta reader could not
  decode the native object shape (`delta.message.content = {type,text}`) the writer
  emits, silently dropping streamed assistant text on the Cohere read/proxy path.
- **OpenAI `include_usage` streams.** A `usage: null` non-final chunk no longer
  synthesizes a spurious mid-stream `message_delta`; and a trailing usage-only chunk
  no longer produces a `message_delta` after `message_stop` on non-Bedrock ingress.
- **Gemini safety-filtered responses.** A `finishReason: SAFETY` candidate with no
  `content` field (a legitimate Gemini shape) is decoded normally instead of
  returning a spurious 500.
- **Bedrock conformance:** cross-protocol degraded error relays now forward
  `x-amzn-requestid` / `x-amzn-errortype`; tool-call ids are remapped to the client's
  native shape on the degraded path; prompt-cache token fields round-trip.
- **Responses non-streaming output items** now carry the native `id` / `status` /
  `annotations` the streaming path emits.
- Numerous lower-severity correctness/conformance fixes across the breaker cooldown
  jitter, SigV4 header canonicalization, health-probe Retry-After handling, and id
  synthesis (unbiased base62). Active health probes now send the same `User-Agent` /
  `Accept` as organic traffic. Admin key creation rejects negative budgets.

### Changed
- **MSRV is now Rust 1.87** (declared via `rust-version`), reflecting use of
  `u32::is_multiple_of`.
- Internal: the auth mode is now a single source of truth on the auth middleware
  (removed a denormalized copy on the app state).

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
request path — all in one native binary. The remaining work before 1.0.0 is operational validation
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
  - **Correction (superseded):** the claim that `/metrics` is intentionally open no
    longer holds. `/metrics` now goes through the same auth check as any other route
    — only `/healthz` stays unauthenticated for liveness probes — though under
    `none`/`passthrough` mode the check still admits unconditionally. See the
    Unreleased *Security* entry above and `src/auth.rs` (`auth_middleware`). The
    original line is kept as-written to preserve the historical record.

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
