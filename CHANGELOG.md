# Changelog

All notable changes to Busbar are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Every release uses the same section headings, in this order: **Added**, **Changed**, **Deprecated**,
**Removed**, **Fixed**, **Security**. Migration steps for a breaking change appear as a bold **Migration**
item under **Changed**.

## [Unreleased]

## [1.4.1], 2026-07-20

### Added

- **Published OpenAPI schema per release** — every tagged release now attaches the admin API's OpenAPI 3.1
  document as a release asset (`busbar-openapi-<tag>.json`), emitted in CI from the same `openapi_doc()` that
  serves `GET /api/v1/admin/openapi.json` and stamped with the release version. Downstream tooling can
  generate a client or diff the API surface across releases without running the gateway.

### Changed

- **Repository now at [`github.com/GetBusbar/busbar`](https://github.com/GetBusbar/busbar)** (older links
  redirect). Release binaries, the GHCR image (`ghcr.io/getbusbar/busbar`), and build-provenance attestation
  are published under this repository — verify this release's artifacts with `--repo GetBusbar/busbar`.
  Docker Hub (`getbusbar/busbar`) is unchanged.

## [1.4.0], 2026-07-19

### Added

- **`jwt-bearer` egress auth (OAuth 2.0 JWT-bearer grant, RFC 7523)** — the 5th auth mechanism. A provider
  with `auth: jwt-bearer` self-mints a short-lived bearer by signing a JWT assertion (RS256) and posting it
  to the token endpoint, then refreshes in the background ahead of expiry. A Google service-account JSON is a
  recognized credential container (`client_email`→iss, `private_key`→signing key, `token_uri`→aud); `scope`
  defaults to `cloud-platform` and is overridable. Any RFC 7523 provider works via config, no new code.
- **`oauth-client-credentials` egress auth (OAuth 2.0 client-credentials grant, RFC 6749 §4.4)** — the 6th
  auth mechanism. `auth: oauth-client-credentials` with `token_url` + `scope` exchanges a
  `client_id:client_secret` for a bearer and refreshes it. This is what authenticates Azure OpenAI via Entra
  ID (AAD). It shares the self-minting bearer-refresh machinery with `jwt-bearer` — the two differ only in the
  mint call.
- **`path_base` provider knob** — overrides a URL-model protocol's hardcoded base segment while keeping the
  `/{model}:verb` suffix, so one config line can reach a non-standard base path (e.g. Vertex's
  `/v1/projects/{project}/locations/{location}/publishers/{publisher}/models`).
- **Google Vertex AI, delivered as configuration** — Gemini on Vertex (`protocol: gemini` + `path_base` +
  `auth: jwt-bearer`) and Claude on Vertex (`protocol: anthropic` + `path_base` + `auth: jwt-bearer`; the
  model moves into the `:rawPredict`/`:streamRawPredict` URL and the body carries `anthropic_version` in
  place of `model`). No new protocol — Vertex speaks Gemini and Anthropic on the wire, so it is a config
  entry, not code. Azure OpenAI via Entra ID lands the same way (`protocol: openai` +
  `auth: oauth-client-credentials`).
- **`token_url` and `scope` provider fields**, consumed by the OAuth auth mechanisms above.
- **Oracle OCI Generative AI, delivered as configuration** — the `oci-genai` catalog entry targets OCI's
  OpenAI-compatible surface (`/openai/v1/chat/completions`, serving OCI's hosted OpenAI/Llama/xAI/Google/
  Cohere models). Since Jan 2026 OCI issues plain API keys (`Bearer`), so no OCI request-signing is needed —
  `protocol: openai` + `auth: bearer` with the OCI regional `base_url`. No new protocol or code; its
  `TooManyRequests`/`QuotaExceeded`/`LimitExceeded`-in-a-400 quirk is handled by the catalog `error_map`.

  The support surface is now **6 protocols × 6 auth mechanisms**. To be clear on direction: these are
  **egress** auth mechanisms — how Busbar authenticates OUTWARD to each upstream AI provider (Busbar →
  provider), configured per provider in `providers.yaml`. They are unrelated to how clients authenticate
  INWARD to Busbar (client → Busbar), which is the separate `auth:` client-token / virtual-key layer. Any
  upstream speaking one of the six wire protocols and one of the six egress auth styles is a config entry,
  no code change.

### Changed

- **Default worker-thread count now scales to the box.** The async worker pool defaulted to `min(cores, 4)`
  in 1.3.1–1.3.3 (1.3.0 used Tokio's all-cores default), which pinned the CPU-bound request path (parse,
  translate, serialize) to ~4 cores no matter how large the machine — throughput plateaued regardless of
  core count. The default is now one
  worker per available core (`available_parallelism`, which respects CPU affinity and the cgroup **cpuset**
  — but **not** the CFS `cpu.max` bandwidth quota, which it cannot see), so **throughput scales linearly
  with cores out of the box** — ~9,750 req/s per core, ~156k req/s on 16 cores at 100% success in the
  [published benchmark](https://getbusbar.com/performance), with added latency flat at ~33 µs. On a
  quota-limited orchestrator (e.g. a k8s pod with a CPU limit on a many-core node) this defaults to the
  node's core count and oversubscribes the quota — **pin `BUSBAR_WORKER_THREADS` to your CPU limit there.**
  Each worker carries a thread stack and its own allocator arena, so idle memory grows slowly with the
  count; footprint-sensitive sidecars should set `BUSBAR_WORKER_THREADS=1` (or `2`). No config or API
  change. For back-compat, an operator who pinned the standard `TOKIO_WORKER_THREADS` on 1.3.0 (honored
  by 1.3.0's `#[tokio::main]` runtime) still gets that pool size — it is read as a fallback when
  `BUSBAR_WORKER_THREADS` is unset; an explicitly-set-but-invalid value warns instead of being silently
  ignored. The reproducible throughput/scaling harness and raw per-core data are checked in under
  `bench/scaling/`.
- **Allocator: jemalloc with a background purge thread.** The request hot path holds a few copies of each
  request body while it is parsed and forwarded, so peak RSS tracks `peak concurrency × payload size`. The
  system allocator (glibc) almost never returns freed pages to the OS, so after a big-payload burst RSS
  stayed pinned at the peak indefinitely — memory read as a one-way ratchet even though the live set had
  collapsed. Busbar now uses jemalloc with `background_thread` enabled: freed pages return to the OS after a
  short decay, so memory **plateaus** under sustained load and **falls back toward idle** when the load
  subsides (measured: a ~1.2 GB plateau under a 5-minute 150 KB-payload soak drops to ~250 MB within ~30 s of
  the load stopping). It remains bounded — a function of in-flight work, never unbounded growth. Cost: ~450 KB
  of binary and four new dependency crates (`tikv-jemallocator` / `tikv-jemalloc-ctl` / `tikv-jemalloc-sys`
  plus the `paste` build-macro dep), all vendored under the Apache-2.0/MIT compatible set. Reproduction harness in `bench/memory/`. **Windows (`msvc` target) keeps the system allocator:**
  jemalloc's C build is incompatible with the MSVC toolchain, so it is compiled in only for non-msvc targets
  (Linux/macOS, incl. the published container and static musl builds) — Windows binaries build and run
  unchanged on the system allocator and do not get the plateau/fall-back-to-idle behavior.
- `ring` and `base64` are now direct dependencies (both were already in the lockfile via rustls) — used for
  the RS256 JWT signature and the PKCS#8/base64url handling in `jwt-bearer`. No new crates enter the tree.
- Streaming: for a cross-protocol stream whose backend reports token usage in a SEPARATE trailing chunk
  (the OpenAI `include_usage` convention), the terminal usage frame is now DEFERRED and the trailing usage
  folded into it, so a non-OpenAI client (Anthropic/Gemini/Cohere/Responses) receives the real prompt/
  completion counts on its terminal frame instead of zeros. Delivery is uniform across the SSE and
  gemini-json-array paths (the response body now streams `finish()`'s content through the json-array framer,
  which previously discarded it). Behavior-preserving for OpenAI ingress (which still receives the separate
  usage chunk) and Bedrock ingress (which carries usage in its `metadata` frame). **Wire-shape note:** a
  Gemini JSON-array (non-SSE) client on a cross-protocol stream now receives one ADDITIONAL trailing array
  element carrying the terminal `usageMetadata` that 1.3.0 silently dropped — spec-correct for native Gemini
  streaming, but a client that counted or hashed raw array elements will see N+1 elements.
- **Upgrade hint for the removed `auth.mode:` key.** A config that still carries the pre-`auth.chain`
  `auth.mode:` key now fails to boot with a targeted migration hint (`mode: none` → an empty/omitted
  `chain:`; `mode: token`/`apikey` → `chain: [tokens]`; `mode: passthrough` →
  `auth.upstream_credentials: passthrough`) instead of a bare serde "unknown field" error. Still fail-closed.

### Fixed

- **Security — OAuth egress SSRF hardening (config-time AND runtime):** the `token_url` a
  `oauth-client-credentials` provider POSTs the client secret to now runs through the SAME SSRF/cloud-metadata
  denylist and case-insensitive https requirement as `base_url` (previously only a case-sensitive `http://`
  check with NO metadata guard, so a typo'd/templated `token_url` pointing at IMDS or
  `metadata.google.internal` could leak the secret). Additionally: (a) both self-minting OAuth clients
  (`jwt-bearer`, `oauth-client-credentials`) now **refuse HTTP redirects and carry connect/overall timeouts**
  — the credential rides in the POST body, so a 307/308 from a compromised token endpoint would otherwise
  re-POST the plaintext `client_secret` / signed assertion to a redirect target the boot-time URL check never
  saw; (b) the `jwt-bearer` service-account `token_uri` now gets the same https + metadata denylist vetting as
  `token_url`; and (c) `busbar --validate` now dry-run-validates a `jwt-bearer` credential's SA JSON + PKCS#8
  key (when the env var is set), instead of surfacing malformed key material only at boot/apply.
- An aborted cross-protocol **gemini JSON-array** stream now emits exactly ONE trailing error element (a
  mid-cycle change had it wrap the native error frame AND append a second one). `busbar --validate` no longer
  reports false errors on a config that env-templates its `base_url` / `token_url` (`${VAR}`) when the variable
  is unset (a Lenient-mode placeholder was failing the URL/https checks it will pass at boot). Streaming
  Cohere→X hops now preserve `message.tool_plan` (the pre-tool-call reasoning), matching the non-stream path.
- `jwt-bearer` now honors a configured `scope:` (it was dropped, so the default `cloud-platform` scope always
  won). JWT claims are built with a JSON serializer instead of string interpolation (a `"`/`\` in
  `client_email`/`scope` can no longer malform or inject into the claim set).
- Health probers are re-spawned on config reload/apply and hold a `Weak<App>`: reloaded lanes are now probed,
  and the previous generation exits instead of leaking one task-set per reload (which also pinned the orphaned
  snapshot and wrote breaker outcomes into a store no longer serving traffic).
- A mid-stream upstream **transport** error no longer token-bills the partial usage accumulated before the cut
  — symmetric with the terminal-error / translate-abort no-bill gates.
- Translation fidelity: the Cohere reader surfaces `message.tool_plan` (the assistant's pre-tool reasoning was
  silently dropped on any Cohere→X hop); the Cohere and Responses writers emit a raw-string tool argument
  verbatim instead of JSON-encoding it a second time; a prompt-level Gemini `RECITATION` block maps to `safety`
  (consistent with the candidate-level mapping).
- `busbar --validate` now catches a model whose `context_max` conflicts across pools (previously rejected only
  at real boot, so a clean `--validate` could still `die` on start).
- The shared upstream HTTP client sets a `connect_timeout` and TCP keepalive; the virtual-key secret is widened
  to 256 bits; the self-minting bearer credential recovers from a poisoned lock on the request hot path rather
  than panicking.
- License hygiene: the three OAuth source files that were mislabeled `AGPL-3.0-or-later` are corrected to
  `Apache-2.0` (the project license); a test now fails on any non-Apache SPDX header in first-party source.

## [1.3.3], 2026-07-16

### Added

- `busbar --validate` — validate a config file without booting or binding a socket (the `nginx -t`
  workflow). Reports structural/reference errors and, in lenient env mode, records unset `${VARS}` as
  placeholders (structure, not secrets) so a config can be checked in CI without the runtime environment.

### Changed

- Egress auth is now fully separated from the protocol writers: a `CredentialProvider` owned by the lane
  (resolved once at boot from protocol + auth style) produces each request's outbound auth headers via
  `lane.credential.headers_for(...)`, replacing per-writer `auth_headers`/`sign_request`. Behavior-preserving
  — every protocol emits byte-identical auth — and it sets up a self-minting (OAuth/Vertex) credential later.
- Release profile is `opt-level = 3` (was `s`). New `BUSBAR_WORKER_THREADS` env knob hard-caps the Tokio
  worker pool (default `min(cores, 4)`, ~5% lower RSS on many-core hosts). Deduped busbar's own
  `getrandom` usage onto 0.3 (dropped the 0.4 copy); `ring` still vendors its own 0.2 line, so two
  `getrandom` majors remain in the tree.
- All workspace crates are now versioned in lockstep at `1.3.3`. The internal `publish = false` support
  crates (`busbar-api`, `busbar-auth-tokens`, `busbar-auth-admin-tokens`, `busbar-hooks-ranking`) had
  lagged at 1.3.0 across the last few releases; they now track the binary's version.

### Fixed

- Tap (fire-and-forget hook) spawns are now bounded by a semaphore (cap 1024) so a slow hook can't grow
  unbounded in-flight tasks; over-cap taps are dropped and counted (`tap_notifications_dropped_total`).
- Config overlay no longer risks tombstone-loss: an unreadable overlay file is refused rather than
  overwritten (which previously could silently drop persisted admin state).
- Request rewrite-on-failover now fails **closed** — if a queued rewrite can't be re-applied to the retried
  upstream, the request is rejected (500) instead of silently forwarding the un-rewritten body.

### Security

- SSRF egress guard extended to block Azure WireServer (`168.63.129.16`) and Oracle Cloud IMDS
  (`192.0.0.192`) alongside the existing cloud metadata ranges. `host_from_base` strips userinfo,
  folds backslashes, and drops any path before deriving the SigV4-signed host, so the signed host can
  never desync from the host actually dialed.

## [1.3.2], 2026-07-14

### Fixed

- Finished greening the CI matrix 1.3.1 began; three still-red checks are now clean with no binary change.
  **fmt** — committed the rustfmt reformatting of `render_histogram` that had been applied locally but never
  committed. **Windows** — `PolicyOnError` (used only by the unix-only socket-gate tests) is now imported
  under `#[cfg(unix)]`. **cargo-deny** — workspace member crates are versionless path deps; marking them
  `publish = false` (they never go to crates.io) lets `allow-wildcard-paths` apply, so `bans` passes while
  external wildcards stay denied.

### Changed

- `scripts/preflight.sh` now fails on an **uncommitted working tree** (CI tests the committed state — an
  uncommitted `cargo fmt` is how the fmt red slipped past 1.3.1) and runs **cargo-deny** (the Security job)
  when installed.
- Dependency bumps (Dependabot): `bytes` 1.12.0 → 1.12.1; CI/release actions `docker/build-push@7`,
  `docker/setup-buildx@4`, `docker/metadata@6`, `docker/login@4`, `actions/upload-artifact@7`,
  `actions/download-artifact@8`.

## [1.3.1], 2026-07-14

A maintenance release: no binary behavior change, a clean CI matrix, and a pre-release gate so the
config-specific breakage caught here can't recur.

### Fixed

- Restored a clean CI matrix: config-specific dead code that only `-D warnings` rejects under
  `--no-default-features` or on Windows now compiles cleanly. `PROBE_TIMEOUT` moved inside its `#[cfg(unix)]`
  scope; the `admin_token_hash` getter and a `WarnCapture` test helper are gated to the features that use
  them; the admin-listener split test is gated to `auth-admin-tokens`.

### Added

- `scripts/preflight.sh` — a pre-release gate mirroring the full CI matrix locally (fmt, structure-lint,
  clippy + build + test on both the default and `--no-default-features` feature sets, and a best-effort
  Windows type-check). Run it before tagging so a release can't ship red CI.

## [1.3.0], 2026-07-13

The API release: everything you could only do by editing YAML and restarting, you can now do over an
authenticated, audited API. The routing hook grew into a hook system — gates and taps on every request.

This release reshapes how hooks and policies are configured. Hooks are now defined once by name and referenced
everywhere; the old inline `policy:` block and transport-named `route:` values are replaced. **Existing
configs need a one-time update** (see the 1.2.x → 1.3 migration guide, `docs/migration-1.3.md`). It is a clean
cut with no silent fallbacks: an old-form key reports a clear startup error telling you exactly what to write
instead.

### Added

- **FinOps metering, built for third parties.** `GET /api/v1/admin/usage` reports per-model and per-key
  consumption as the RAW token split (input / output / cache-read / cache-creation — each prices differently)
  in fixed UTC-day buckets, with `spend_micros` (micro-USD, integer math) derived at read time from your
  configured prices. Busbar exposes the inputs of cost, not just its own number, so a consumer with negotiated
  per-model pricing reconstructs cost exactly from the split. `?window=` selects past buckets; over-cap key
  lists carry an `others` remainder so every unit stays attributable; `window`/`as_of`/`currency` label the
  numbers.
- **Hooks are control-plane citizens.** A hook self-reports its OBSERVED settings and its own operational
  metrics over the new `status` wire message, and `GET /api/v1/admin/hooks/{name}/status` surfaces it with a
  desired-vs-reported drift verdict — so a dashboard built on Busbar sees what every plug is doing without
  each hook needing its own dashboard.
- **One professional wire contract, audited to zero.** Three independent contract-audit rounds on the Admin
  API and two on the hook wire, all findings fixed pre-freeze: one error envelope everywhere with a frozen
  code taxonomy (including `unauthorized`, `method_not_allowed`, and retryable `version_conflict` split from
  terminal `conflict`), one `{items, next_cursor}` list envelope with opaque cursors, one
  optimistic-concurrency mechanism (RFC-7232 `If-Match`/ETag on every mutable resource), `Idempotency-Key` on
  both secret-minting POSTs, `Retry-After` on 429s, machine-readable query params + scope annotations in
  `openapi.json`, and explicit per-request `op` discrimination + append-only evolvability rules on the hook
  wire.
- **The Admin API is a full config plane.** Anything the config file can express, the API can do: read the
  running config, apply a validated change atomically, roll back to any previous version, register hooks,
  adjust pools, budgets, and rate limits. Drive Busbar from Terraform, Ansible, or CI — no SSH, no file edits,
  no restarts.
- **Config overlay.** API-applied changes persist to a Busbar-owned overlay file; your hand-written
  `config.yaml` is never touched. The effective config is base plus overlay, both human-readable, so "who set
  this" is always answerable.
- **Admin audit log.** Every admin mutation records who changed what, when. Scoped admin tokens let you mint
  credentials that can, for example, only register hooks or only read.
- **Named hooks.** Define a hook once under `hooks:`, reference it anywhere: in a pool's `hooks: [...]` list
  or via `global_hooks:` to run on every request. One list carries both jobs — a pool names its ranking
  strategy (weighted, cheapest, fastest, least_busy, usage) and any gates together, e.g. `hooks: [cheapest,
  pii-guard]`. The old `route:` values and inline `policy:` block are removed; an old-form key is a clear
  startup error naming its replacement (a clean cut, no silent fallback). See the 1.2.x → 1.3 migration guide.
- **Gates and taps.** A `gate` is a blocking hook that can reject a request or restrict which pool members may
  serve it; a `tap` is fire-and-forget observation (request, route, per-attempt, and completion stages) that
  can never delay or fail a request. Routes rank, gates decide, taps watch.
- **The restrict verb.** A gate can reply "only members carrying these tags may serve this":
  compliance-constrained routing (data residency, BAA-only lanes) without teaching your router about
  compliance. Restrictions hold across failover.
- **Concurrent hooks.** All of a request's hooks fire at once, so added latency is the slowest hook, not the
  sum. Any reject wins; restrictions intersect; the route ranks what survives.
- **Pluggable auth.** Authentication is now an ordered chain of modules: each identifies the caller, rejects,
  or passes to the next. Token auth is the first module and the default, and it is removable — list only your
  own module and tokens are gone. External modules speak the same hook transports; validated identities are
  cached (with instant admin flush), and auth always fails closed. Budgets, rate limits, pool access, and
  audit all follow the authenticated principal, whoever issued it.
- **Admin API lockdown.** The admin API authenticates through its own pluggable chain, with scoped principals
  (read-only, hooks-register, full) replacing the single shared admin token, and every mutation in the audit
  log attributed to the person who made it. The chain itself is live-mutable (`PUT /api/v1/admin/admin-auth`)
  and guarded so a change that would lock the caller out is refused instead of applied.
- **The rewrite verb.** A trusted gate (`prompt: rw`) can replace the request body before dispatch — context
  compression and redaction, across all six protocols at once, because it fires on the normalized form.
  Rewrites persist across failover, token accounting uses the rewritten body (the savings are real and
  measured), and a malformed or slow rewrite proceeds with the original body untouched; a broken compressor
  can never corrupt a request.
- **Live hook settings.** Push a settings map to a running hook over the admin API; the change commits only
  when the hook acknowledges it, and a restarted hook always receives its current settings before any traffic.
  Hooks can also describe their own settings schema, served verbatim by the API.
- **Config reload, and health that survives everything.** `POST /api/v1/admin/config/reload` re-reads your
  config files and applies them atomically, and lane health (circuit breakers, cooldowns, learned latency) is
  carried across by model identity, not list position, so a reorder or added model never resets what Busbar
  has learned. That health state now persists across restarts too — kill Busbar, fix the config, start again,
  and sub-second it comes back remembering which lanes were misbehaving. `--safe-mode` boots from your base
  config alone when an API-applied overlay is the problem.
- **Group-based governance.** `group_map:` maps identity-provider groups to authority in one place: admin
  scopes and data-plane access (allowed pools, rate limits, budgets), governed by exactly the machinery a
  virtual key uses. Per-module caps bound what any auth module can assert: an allowlist of groups it may claim
  and a ceiling on the admin scope obtainable through it.
- **The admin API runs on its own listener, always.** The management surface (`/api/v1/admin/…`) is served on
  a dedicated `admin_listen` and is never mounted on the data `listen` — the public bind cannot serve
  `/api/v1/admin/*` at all. It carries its own `admin_tls:` (cert + optional `client_ca_file` for
  client-certificate mTLS), so the control plane can require client certs, bind, and firewall independently of
  public LLM traffic. `admin_listen` defaults to loopback (`127.0.0.1:8081`), so a zero-config deployment
  boots with admin reachable only on-host; point it at an exposed address (with mTLS) to manage Busbar
  remotely.

### Changed

- **The management API lives under one root: `/api/v1/admin/…`.** Every Busbar-native API mounts under
  `/api/<version>/<area>/`, cleanly separated from data-plane protocol paths (dictated by the vendor SDKs,
  which don't move). The key-management endpoints previously at `/admin/keys*` are now `/api/v1/admin/keys*`;
  scripts calling the old paths need a one-line URL update. Future surfaces (and a future `v2`) slot in under
  the same root without new top-level paths.
- Completion telemetry now carries usage for every operation type (chat tokens, embeddings, images, audio,
  rerank) plus a request id that correlates a request across hook stages.

### Removed

- **The inline `policy:` block and transport-named `route:` values.** A pool's `route:` now takes a hook name
  (defined once under `hooks:`) or a native policy name
  (`weighted`/`cheapest`/`fastest`/`least_busy`/`usage`); the old `route: socket` / `route: webhook` +
  `policy:` form is replaced. Each removed key reports a startup error with the exact replacement. See the
  migration guide.
- **The embedded Rhai script routing policy (`route: script`).** Available only behind an opt-in build flag
  and deprecated in 1.2.1, it is gone. A compiled hook over a socket or an HTTP webhook does the same job with
  real process isolation; if you want scripting, run a hook that embeds it.

### Security

- **Exposed admin plane requires mTLS — fail closed.** A network-exposed `admin_listen` (any non-loopback
  bind) refuses to boot unless protected by client-certificate mTLS (`admin_tls.client_ca_file`). A loopback
  admin bind is exempt (unreachable off-host), and an operator fronting admin with a mesh that terminates mTLS
  can waive the guard explicitly with `admin_insecure: true`. The management plane is never silently published
  behind a bearer token alone.

## [1.2.1], 2026-07-11

A hardening release, plus the routing hook layer growing up: a faster transport and the payload and verbs that
make screening hooks possible.

### Added

- **The socket routing hook (`route: socket`).** Your routing policy as a compiled binary on a local Unix
  domain socket. Same wire contract as the HTTP webhook (a hook moves between the two without changing its
  logic), same hard deadline and `on_error` fail-safe, no HTTP stack in between: measured end to end against a
  real external Rust hook, a decision costs about **8 microseconds** median. Busbar never spawns or supervises
  the hook binary; you (or your init system) run it, Busbar connects lazily, keeps the connection alive, and
  reconnects transparently across hook restarts. Kill the hook mid-traffic and requests keep flowing on the
  pool's fallback. Unix-only; on other platforms use `route: webhook`.
- **Hook payload opt-ins: `policy.send_prompt` and `policy.send_user`.** The hook payload stays shape-only by
  default; two per-pool booleans (both default `false`) extend it. `send_prompt` adds the flattened prompt
  content (`request.system` + `request.messages` as `{role, text}`) so a trusted hook can screen content —
  PII, guardrails, audit. `send_user` adds caller identity (`request.user`: the governance virtual-key
  `id`/`name` plus the body's end-user field) so a hook can route by who is asking. The caller's secret/token
  is never in the payload, under any configuration. Both transports carry the same fields; a pool that sets
  neither flag sends the exact pre-1.2.1 payload.
- **Member `tags` in the hook payload.** Each candidate now carries its operator-declared free-form `tags`
  (team names, regions, compliance labels), omitted when the member declares none.
- **The hook `reject` verb.** A hook may reply `{"reject": {"status": 451, "message": "..."}}` instead of an
  order: no upstream is dispatched and the caller receives a dialect-native error. Fail-closed and bounded:
  the status is clamped to 400–499 (default 403) and picks the typed error class the SDK sees, the message is
  sanitized, and a malformed reject still rejects — never silently routes. Counted in the new
  `busbar_route_policy_rejections_total` metric. Combined with `send_prompt`, this is the PII-screen
  primitive: a hook that sees content can stop a request before it leaves your network.

### Changed

- **Default hook deadline is now 1 ms** (`policy.timeout_ms`, was 150). The default says hooks are fast — a
  co-located socket hook decides in ~8 µs and a co-located webhook in ~34 µs. Raise it when your hook
  legitimately does I/O or crosses the network; on timeout the decision falls back per `on_error` and the
  request proceeds regardless.

### Deprecated

- **`route: script` (Rhai).** The embedded interpreter costs ~100x more per decision than a compiled socket
  hook for the same logic, and its sandbox is a weaker isolation story than a separate process. It still works
  behind the `script-policy` feature but warns at startup; migrate to `route: socket` (compiled hook) or
  `route: webhook` (any language).

### Fixed

- **Hardened throughout.** Multiple rounds of extensive adversarial testing and code review over the full
  1.2.0 change set and the new hook layer surfaced and fixed a broad batch of defects — protocol-translation
  edge cases, input validation and sanitization, error handling, and observability gaps. Every fix shipped
  with the regression test that catches it; the suite grew by several hundred tests this release.

## [1.2.0], 2026-07-10

Busbar now speaks more than chat. Five new operations land on top of chat: **Embeddings**, **Moderations**,
**Image generation**, **Audio** (transcription and speech), and **Rerank**. Every one is **cross-protocol**,
carried by the same lossless translation that already carried chat — a Gemini client can call embeddings on an
Amazon Bedrock backend, an OpenAI client can route images and audio to Google Gemini, and every answer comes
back in the caller's own dialect, lossless in both directions, errors included. Chat itself is byte-for-byte
unchanged: it is simply the first operation now, not a special case.

### Added

- **Embeddings (`/v1/embeddings` and each protocol's native surface), cross-protocol.** An OpenAI-dialect
  embeddings request routes to **OpenAI**, **Amazon Bedrock** (Titan), **Cohere** (v2 `/embed`), or **Google
  Gemini** (`embedContent`) and returns in the caller's own dialect. Vectors, token/usage accounting, and
  errors all survive the hop.
- **Per-attempt hang detection (`attempt_timeout_ms`).** Some providers fail by hanging: the connection opens
  and response headers never come back, silently eating the whole failover budget on one member.
  `attempt_timeout_ms` caps a single attempt's time to response headers; on expiry the attempt is recorded as
  a transient breaker failure and the request fails over to the next pool member within the same request. Set
  it on a model as that model's default and override per pool member, so the same model can carry a 10s cap in
  a batch pool and a 50ms cap in a latency-critical one. The cap covers connect and headers only (a stream
  that has started answering is never cut off) and is always floored by the request's remaining
  `failover.timeout_secs`. `0` is a startup error. Observable as `disposition="attempt_timeout"` on
  `busbar_upstream_failures_total` and `reason="attempt_timeout"` on `busbar_failovers_total`.
- **Cross-protocol logprobs (OpenAI ↔ Gemini), buffered and streaming.** Per-token log probabilities are now a
  first-class IR concept. The ask crosses the seam either direction (OpenAI `logprobs`/`top_logprobs` ↔ Gemini
  `generationConfig.responseLogprobs`/`logprobs`) and the response comes back in the caller's own shape
  (`choices[].logprobs.content[]` ↔ `candidates[].logprobsResult`, including chosen tokens, top alternatives,
  and synthesized UTF-8 `bytes` where OpenAI's shape requires them), buffered and per-chunk in streams.
  Backends with no logprobs concept (Anthropic, Bedrock) never receive the ask; Cohere logprobs stay
  same-protocol-only (its wire shape carries bare token IDs under its own tokenizer). Live-validated against
  real OpenAI from a Gemini-dialect client, buffered and streaming.
- **Two new cross-protocol carries: `user` and `parallel_tool_calls`.** OpenAI's `user` and Anthropic's
  `metadata.user_id` are the same end-user identifier; OpenAI's `parallel_tool_calls` and Anthropic's
  `tool_choice.disable_parallel_tool_use` are the same switch, inverted. Both are now first-class in the IR
  and translate between the two protocols in both directions instead of being dropped at the seam. The
  documented field-survival table (docs/protocols.md) is now measured against real egress capture, not
  asserted.
- **Moderations (`/v1/moderations`), cross-protocol.** Content-classification requests translate through the
  IR and return in the caller's dialect, so a moderation call is not pinned to one vendor's endpoint.
- **Image generation, cross-protocol.** An OpenAI-dialect image request routes to **OpenAI**, **Google
  Gemini** (Imagen), or **Amazon Bedrock** (Titan) and comes back in the caller's dialect.
- **Rerank (`/v2/rerank` and Bedrock rerank models), cross-protocol.** The sixth operation: **Cohere** v2
  rerank and **Amazon Bedrock** rerank models (via `InvokeModel`, detected by the `query` + `documents` body)
  translate exactly in both directions — the two wires share the same result shape (`index` +
  `relevance_score`), so a Cohere-dialect client can rerank on a Bedrock backend and vice versa, with pools,
  failover, and breakers like every other operation. The other four protocols ship no rerank surface and
  answer with the standard dialect-native 404.
- **Audio, cross-protocol.** **Transcription** (speech-to-text, including speech-to-English translation) and
  **Speech** (text-to-speech) against **OpenAI** and **Google Gemini** backends, translated to and from the
  caller's dialect like every other operation.
- **Clean, dialect-native 404 for an operation a backend lacks.** Calling an operation a backend does not
  implement (e.g. image generation on an Anthropic backend) returns a well-formed 404 **in the caller's own
  protocol dialect**: never a crash, never a malformed body, and never taking the lane down for other traffic.
- **Cross-protocol reasoning/thinking carry (opt-in per lane).** The reasoning ask now translates between the
  three protocols that model it: OpenAI `reasoning_effort` / Responses `reasoning.effort` (words), Anthropic
  `thinking.budget_tokens` and Gemini `thinkingConfig.thinkingBudget` (token budgets). Number to number is a
  straight copy (a Claude/Gemini thinking pool loses nothing); words and numbers convert through a
  configurable effort table (`limits.reasoning_effort_budgets`, defaults 1024/4096/8192/16384). Because
  thinking support is per-MODEL, not per-protocol, the carry is **gated by an operator flag**: `reasoning:
  true` on a model (overridable per pool member) declares "this backend accepts thinking params". Without the
  flag the ask is dropped at the seam with a warn and the request proceeds normally, so a non-reasoning model
  can never 400 from translation. Budgets are clamped to fit `max_tokens` (Anthropic requires it), and
  Anthropic-incompatible sampling knobs (temperature, top_k) are omitted with a warn when thinking is emitted.
  The response-side thinking CONTENT was already lossless and is unaffected. Gemini's dynamic `-1` round-trips
  to Gemini and projects elsewhere as `medium`.

### Changed

- **License: Apache 2.0.** Busbar 1.2.0 and onward is licensed under the **Apache License, Version 2.0**:
  permissive, commercial-friendly, with an explicit patent grant, no copyleft obligations — use, modify, and
  redistribute privately or commercially.
- **Every operation is lossless across protocols, errors included.** Responses *and* error envelopes always
  come back in the caller's own protocol dialect, and token/usage accounting survives the cross-protocol round
  trip on every operation, not just chat.
- **Four-layer operation architecture (internal).** The request path is now Router → RequestHandler →
  OperationHandler → IR, where each operation is a small codec over the shared reliability engine and chat is
  operation #1 rather than a special case. Adding an operation is a codec, not a change to routing, failover,
  or the breaker. No user-visible behavior change to chat.
- **Billing is now a polymorphic data model (internal).** Usage is metered as tokens, duration, characters,
  images, or a flat unit depending on the operation, so non-chat operations meter on their natural axis. A
  pricing engine that turns these units into cost is planned for 1.3.

### Fixed

- **Gemini streamed thinking no longer leaks into answer text on cross-protocol streams.** The Gemini stream
  reader routed `thought: true` parts into the answer text, so a Gemini backend's streamed reasoning was
  concatenated into the visible reply for every cross-protocol client (the buffered path was already correct).
  Thought parts now stream as proper thinking blocks (signature included) with balanced block framing on every
  terminal path. Caught by the new offline streaming-reasoning harness rows.

## [1.1.1], 2026-07-09

### Added

- **`GET /v1/models` and `GET /v1beta/models`**: the list-models surface. Returns every routable name —
  configured pools first, then model entries, each sorted. This is the first call `client.models.list()` and
  self-hosted UIs (Open WebUI, LibreChat) make to build a model picker; it previously returned 404. Three
  protocols put list-models on the same noun, so Busbar answers in the **caller's dialect** by protocol
  fingerprint: an `anthropic-version` header gets the Anthropic envelope, `x-goog-api-key` or the `/v1beta`
  path gets Gemini's, otherwise OpenAI's. Governance-scoped like `/stats`: a virtual key restricted by
  `allowed_pools` sees only the pools it may target and the models reachable through them.

### Changed

- **Operations are now a first-class axis of the forward engine (internal).** The request path is generic over
  an operation spec (`OpSpec`) rather than hardcoding chat's assumptions (stream intent, upstream path, usage
  extraction, affinity, egress `Accept`). Chat is spec #1 and its behavior is byte-for-byte unchanged — the
  full test suite passes unmodified. Groundwork that lets a future release add non-chat operations
  (embeddings, moderations, images, audio) as small spec files with no change to the reliability engine. No
  user-visible behavior change.

### Fixed

- **`/metrics` is no longer empty before the first request.** The unlabeled counter family is pre-registered
  at startup and per-lane `busbar_lane_state` gauges are now also emitted for direct-model (pool-less) lanes —
  labeled with the model name as `pool`, matching the counter convention — so a freshly booted gateway exposes
  a live exposition to Prometheus immediately. Both issues were found by the user-emulated acceptance harness
  on its first run.
- **`/stats` output is now deterministic across restarts.** Lanes are built sorted by model name (previously
  in `HashMap` iteration order, randomized per process), and `/stats` serializes pools in sorted key order.
  The lane/pool ordering — and therefore metric lane-series identity — is now stable boot to boot, so scrapes,
  dashboards, and tests are reproducible.

## [1.1.0], 2026-06-30

### Added

- **`upstream_model` config field**: decouples a model's config key (operator alias) from the model id sent to
  the provider on the wire. Lets the **same model run behind two providers** in one failover pool (e.g. Claude
  3.5 Sonnet via Anthropic *and* Bedrock), where the keys must differ but each provider needs its own model
  string. Threaded through body rewriting, URL generation, and health probes (probes hit the same wire id as
  real traffic). Metrics, breaker cells, and logs continue to key off the config key. Feature contributed by
  [@lguzzon](https://github.com/lguzzon) (adopted as `upstream_model`; the resolver is `Lane::wire_model()`).

### Fixed

- Documentation drift surfaced by [@lguzzon](https://github.com/lguzzon) and a deep doc-vs-code audit: removed
  dead `UsageTap` references, corrected same-protocol passthrough to the IR-unified model, fixed the
  `billing_truncated` metric and budget-atomicity descriptions, updated all route notation to axum 0.8
  `{param}`/`{*rest}` syntax, and `window_s` → `window_secs`.

## [1.0.1], 2026-06-30

First hardened maintenance release. No request-path behavior change; the binary is functionally identical to
1.0.0, and the API, config schema, and six wire-protocol contracts are unchanged.

### Changed

- **Dependency upgrades.** **axum 0.7 → 0.8**: route path-param syntax migrated (`:id` → `{id}`, `*rest` →
  `{*rest}`), no behavior change. **getrandom 0.2 → 0.3** (`getrandom()` → `fill()`, same OS-CSPRNG). **rcgen
  0.13 → 0.14** (test-only). All build-verified: 1,667 tests pass, clippy `-D warnings` clean. A new
  credential-generator contract test pins the bearer / AWS-AKID / AWS-secret wire shapes so a future
  dependency change that alters them fails loudly.

### Security

- **Dependency scanning gate.** A `cargo-deny` CI workflow checks every dependency against the RustSec
  advisory DB and enforces a license allow-list, crates.io-only sources, and a duplicate-version ban: on
  dependency changes and on a weekly schedule (an advisory can be filed after a dep is merged).
- **Signed, inventoried releases.** Each release now ships a CycloneDX SBOM and a keyless (Sigstore/OIDC)
  build-provenance attestation, so a downloaded artifact can be verified with `gh attestation verify <file>
  --repo GetBusbar/busbar`.

## [1.0.0], 2026-06-21

First stable release. 1.0.0 keeps the `1.0.0-rc.7` architecture (all traffic through the superset IR with a
verbatim serialize short-circuit, IR-metered billing) and ships an extensive hardening pass on top of it. The
HTTP API, configuration schema, and the six wire-protocol contracts are stable under Semantic Versioning: no
breaking change without a major-version bump. See the rc entries below for the full pre-1.0 history.

### Changed

- **Typed-IR completeness.** `response_format`, `stop_reason`, image source, and redacted-reasoning are
  first-class IR fields rather than passthrough blobs, so each survives a cross-protocol hop losslessly and no
  off-spec value reaches a wire.
- **Containment refactor.** Per-protocol logic moved fully behind the reader/writer vtable so the agnostic
  core names no protocol module; load-bearing literals named as consts; in-module-only items privatized.
- **OpenAI-family module split.** `proto/openai.rs` → `openai_chat.rs`, `proto/responses.rs` →
  `openai_responses.rs`, with shared error/auth/id helpers in `openai_family.rs`. The protocol names
  (`openai`, `responses`) are unchanged: internal layout only.
- **Reproducible builds.** CI and release builds run with `--locked`.
- **Migration (rc.7 → 1.0.0):** `governance.rate_sweep_interval` must now be `>= 1`; `0` is rejected at boot
  (rc.7 silently disabled the rate-map idle-entry sweep on `0`). No other config change for a default
  deployment.

### Fixed

- **Cross-protocol fidelity.** Two Bedrock egress shapes that returned 400 on a valid request; consecutive
  same-role turn coalescing on Bedrock; Anthropic `cache_control` carried through on thinking/image blocks;
  unknown `stop_reason` normalized on egress; a streaming-Responses refusal data-loss.
- **Billing precision.** Sub-cent carry attribution, billing of cancelled mid-stream requests, and no
  token-billing of a translate-aborted stream.

### Security

- A slow-loris header-read bound on both the TLS and plain-HTTP listeners; the SigV4 inbound body buffer
  capped independently of the body-limit layer; circuit-breaker probe-leak / streak-inflation / jitter
  hardening.

## [1.0.0-rc.7], 2026-06-20

The 1.0 candidate. Two themes: an architectural unification so every request takes one code path (wire → IR →
wire) with billing metered from that IR, and the config/surface cleanup that freezes a clean 1.0 contract.
Same-protocol traffic stays byte-exact and just as fast via a verbatim serialize short-circuit, five of six
protocols now forward same-protocol requests byte-exact (the prior path always re-serialized), and a provider
cache-token billing gap is closed. Audited for security and correctness with zero HIGH/CRITICAL findings. The
request path, wire protocols, and breaker FSM are unchanged.

### Added

- **All operational limits are now operator config (no hardcoded caps).** A new `limits:` block surfaces the
  eight previously-hardcoded limits: upstream request timeout, request body max, idle connections per host,
  hard-down cooldown, upstream error-body cap, TLS handshake timeout, honored `Retry-After` ceiling, default
  max_tokens, plus a new `max_inbound_concurrent` (0 = unlimited; >0 installs an outermost concurrency-limit
  layer). Extended `observability`, `metrics`, `governance`, `health`, and `routing` blocks expose their own
  tunables. Every limit defaults to its current value, so behavior is unchanged unless set.
- **Cross-protocol grounding/web-search citations (streaming and non-stream).** A neutral `IrCitation` (with a
  `raw` escape hatch for byte-exact Anthropic re-emit) carries Anthropic and Gemini citations through the IR,
  including a streamed `citations_delta`, so citations survive a cross-protocol hop instead of being silently
  dropped. Anthropic same-protocol output is unchanged (raw verbatim).
- **`observability.emit_server_timing`** (default `false`): set `true` to emit the `Server-Timing: busbar`
  response header.

### Changed

- **Same-protocol traffic now flows through the IR path, like cross-protocol: one code path.** A serialize
  short-circuit keeps it byte-exact and just as cheap: when the egress protocol equals the ingress protocol
  and the value was not mutated, the original bytes are re-emitted verbatim instead of re-serializing the IR.
  Net effect is a *fidelity improvement*: five of six protocols now forward same-protocol requests
  byte-for-byte (the prior path always re-serialized, which reorders JSON keys).
- **Billing is metered from the IR's usage on every path** (streaming and non-stream, same- and
  cross-protocol), replacing a second usage parser that byte-scanned the response. Same numbers for the
  supported cases, with the fixes below.
- **Config keys renamed** for consistency (old names still accepted via alias; prefer the new ones):
  `window_s`→`window_secs`, breaker `trip.n`→`consecutive_n`, `failover.cap`→`max_hops`,
  `failover.deadline_secs`→`timeout_secs`.
- **Closed-set config fields are now enums** (`auth.mode`, `affinity.mode`, per-provider `auth`): invalid
  values are rejected at parse with a clear error. Every value accepted by rc.6 still parses.
- **Admin API error responses** now use the same `{"error":{"message","type"}}` envelope as the proxy
  endpoints (was `{"error":"<string>"}`). **Breaking for scripts parsing the old admin error shape.**
- **Migration (rc.6 → rc.7):**
  - If `auth.token:` was your only credential, move its value into `auth.client_tokens: [...]`, or the gateway
    refuses to boot (`unknown field 'token'`).
  - Fix any typo'd/stale key under `auth:`, `governance:`, or `security:` (now a hard boot error).
  - Prefer the renamed breaker/failover keys; the old names still work but don't set both spellings.
  - Update any script that parses the admin API error shape to `{"error":{"message","type"}}`.
  - Cache-hit requests on Anthropic/Bedrock backends will accrue more token spend (now counted).
  - No change for a default config: enum/casing acceptance and `default_max_tokens` precedence are unchanged.
    The `Server-Timing` response header is opt-in via `observability.emit_server_timing` (default off).

### Removed

- **`auth.token`** (the deprecated single-token field) is removed. `auth:`, `governance:`, and `security:` now
  reject unknown keys, so a stale `token:` or a typo'd security key is a loud startup error instead of a
  silent default. (See the migration notes above.)
- Internal: the duplicate usage byte-scanner, and the last `#[deprecated]` / dead-code shims: the 1.0 tree
  carries none.

### Fixed

- **Provider cache tokens are now billed.** Cache-heavy Anthropic and Bedrock requests previously under-billed
  because their additive `cache_read`/`cache_creation` tokens were not counted. IrUsage is normalized
  (uncached input + additive cache) so billing counts all consumed tokens once, with no double-count for
  OpenAI/Gemini/Responses (whose wire already folds cache into the input total). **Operator note: cache-hit
  requests on Anthropic/Bedrock now bill more than in rc.6.**
- **Responses streaming usage is now metered.** Streamed Responses requests reported zero tokens (the old
  scanner read a top-level `usage`; Responses nests it under `response.usage`).
- **`image_s3` leak (HIGH):** a Bedrock S3-source image translated to any other protocol leaked the
  `s3Location` as a corrupt base64/`inlineData` payload; foreign writers now drop+warn before emit.
- **Redacted-reasoning sentinel leak (HIGH):** the internal `__busbar_*` redacted-reasoning signature no
  longer leaks onto Anthropic/Gemini/Responses wires, and a client can no longer inject it.
- **Multi-citation streaming SSE framing (HIGH):** a Gemini chunk batching N citation sources is now fanned
  out into N single-object Anthropic `citations_delta` events instead of one JSON-array event that crashes
  native Anthropic SDKs.
- **Same-protocol Bedrock malformed-prelude:** a corrupt eventstream prelude no longer splices raw bytes into
  the client stream ahead of the native exception frame.
- **Admin key endpoints** no longer surface a request-body fragment (which carries the key secret) in a parse
  error, and the budget-period 400 no longer echoes the caller's value.
- **Webhook delivery:** `observability.max_inflight_webhook_deliveries` is floored at 1 (a 0-permit semaphore
  silently dropped every delivery).

### Security

- `#[serde(deny_unknown_fields)]` on `AuthCfg`, `GovernanceCfg`, `SecurityCfg`: a typo in a security-relevant
  key (an auth token, the admin token, the SSRF override) can no longer be silently ignored. The legacy-token
  removal fails closed (refuse to boot), never to an open relay.
- Routing-policy webhook response bodies parse through the depth-guarded JSON path.

## [1.0.0-rc.6], 2026-06-19

Performance, observability, a security fix, and cross-protocol losslessness completeness. Busbar now reports
its own added latency in-band, the hot translate path is ~2× faster on large payloads via SIMD JSON, a
remotely-triggerable parser DoS is closed, and a fidelity audit closed a class of cross-protocol silent-loss
gaps so native provider features survive translation. The request path, wire protocols, breaker FSM, and
governance contract are unchanged.

### Added

- **`Server-Timing: busbar;dur=<ms>` response header.** Busbar reports its own internal processing time (total
  request time minus the upstream round-trip) on every response — a W3C-standard, per-request measurement of
  exactly the latency Busbar adds (not the network, not the model), readable in browser DevTools or any APM
  tool, on your own production traffic.
- **Cross-protocol losslessness completeness.** Provider-native request/response features now survive
  cross-protocol translation instead of being silently dropped: sampling controls
  (`frequency_penalty`/`presence_penalty`/`seed`/`n`), structured output (`response_format` mapped to each
  protocol's analog), reasoning/thinking blocks both ways (Gemini `thought` parts and Responses reasoning
  items, with signatures, non-stream and streaming), Anthropic `cache_control` ↔ Bedrock `cachePoint`,
  Gemini/Responses cache-read token accounting, and Cohere v2 image input. Where a target genuinely lacks an
  analog (e.g. structured output on Anthropic/Bedrock, or a Responses `file_id` image on another vendor), the
  parameter is dropped with a `warn!` rather than silently.

### Changed

- **SIMD JSON (sonic-rs) on the hot translate path.** Request/response body parse and serialize now go through
  a single `crate::json` seam backed by sonic-rs (NEON on arm64, AVX2/SSE on x86); `serde_json` is retained
  for cold/config/error paths and as the in-memory `Value` type. ~5× faster serialize on the large,
  string-heavy bodies LLM traffic carries.
- **Single-parse ingest.** The request body is parsed once across the routing and forwarding layers: the
  ingress layer hands its already-parsed `Value` to the forwarder instead of being parsed twice.
- Net effect (measured on a pinned AWS `c7g.2xlarge`, Server-Timing): cross-protocol translation of a ~32 KB
  payload roughly halved (≈186µs → ≈84µs); small requests are unchanged at the per-request framework floor
  (~33µs). Full reproducible methodology and numbers are published at
  [getbusbar.com/benchmark](https://getbusbar.com/benchmark).
- The sonic-rs serializer formats some floats differently from serde_json (e.g. `1e26` vs `1e+26`, `-0.0`
  rendered as `0.0`): numerically lossless and valid JSON. Only an exact-string comparison on an exotic
  numeric passthrough field would observe a different byte sequence; the IR round-trip and all translation
  behavior are unchanged.

### Fixed

- **Translation-fidelity siblings.** `top_k` camelCase/snake-case spelling is preserved to Bedrock;
  temperature clamps to a provider's native range are now non-silent (a `warn!`) on Anthropic, Bedrock, and
  Cohere; `max_completion_tokens` is preserved for OpenAI reasoning models (o1/o3); `max_tokens: 0` is
  filtered uniformly across all six protocol readers.
- **Breaker-trip telemetry.** `busbar_breaker_trips_total` now counts exactly one logical Closed→Open trip on
  the degraded routing paths (previously under- or over-counted on some arms).
- **Parse-error log hygiene.** A JSON (de)serialization error is logged as a sanitized byte-count breadcrumb,
  never the raw library `Display` (which can embed body fragments).

### Security

- **Nested-JSON stack-overflow DoS closed.** A small (~20 KB) deeply-nested request body could overflow the
  worker stack and abort the whole process: an uncatchable crash that killed every in-flight request for all
  tenants. The JSON seam now rejects bodies past a 128-level nesting depth before any value is constructed.
  (Introduced by this release's SIMD-JSON parser, which, unlike `serde_json`, does not bound recursion depth;
  found and fixed pre-release by a security audit.)

## [1.0.0-rc.5], 2026-06-17

Three independent features land together: pluggable routing policies, deeper Prometheus observability, and
native inbound TLS/mTLS. The request path, wire protocols, breaker FSM, and governance contract are unchanged.
This release also folds in a security and correctness hardening pass and an internal provider-containment
refactor.

### Added

- **Pluggable routing policies (`route:` per pool).** A pool can declare a `route:` key that produces an
  ordered preference over its members. The ranked list feeds the existing failover loop: if the policy's first
  choice is tripped or at capacity, Busbar walks to the next; a policy can never strand a request.

  Five built-in native policies, selected with `route: <name>`:

  - `weighted`, default smooth weighted round-robin (SWRR); no behavioral change from rc.4.
  - `cheapest`, prefer the member with the lowest operator-declared `cost_per_mtok`.
  - `fastest`, prefer the member with the lowest rolling-EWMA latency.
  - `least_busy`, prefer the member with the most available concurrency permits.
  - `usage`, prefer the member with the most rate-limit headroom (fraction of the caller key's RPM/TPM budget
    still available this window), steering traffic away from candidates approaching a provider 429.

  Members missing a signal are demoted to the back of the preference list but never dropped, so incomplete
  signal data cannot strand a lane.

  Two additional transports for operator-defined logic:

  - `webhook`, POSTs a stable JSON projection of the request and candidates to an operator-run HTTP sidecar
    (any language, any runtime); the sidecar returns a ranked `{ "order": [...] }`.
  - `script`, evaluates an operator-supplied [Rhai](https://rhai.rs/) script compiled once at config load.
    Gated behind the `script-policy` Cargo feature (off by default), keeping the default binary free of the
    Rhai dependency.

  Both transports honor a per-pool `timeout_ms`; a timeout or transport error falls back to the pool's
  `on_error` setting (`weighted | reject | first`) and never blocks or fails the client request.

  **Zero-cost default path.** A pool with `route: weighted` (including any pool that omits `route:` entirely)
  resolves to no policy object at config load. The hot path is a single branch never entered for default
  pools: no allocation, no signal projection, no I/O, identical throughput to rc.4.

- **Four new Prometheus gauges (scrape-time).** Refreshed on each `/metrics` scrape from in-process reads, not
  on the request hot path. All label values are drawn from operator-controlled configuration; no
  client-supplied input appears as a label:

  - `busbar_key_spend_cents`: per-virtual-key accumulated spend in cents for the current budget window (label:
    `key` = virtual-key id). Only emitted when governance is enabled.
  - `busbar_key_budget_remaining_cents`: `max_budget_cents` minus current spend for keys that carry a budget
    cap. Suitable for Prometheus burn-rate alerting. Only emitted for capped keys.
  - `busbar_key_tokens_total`: accumulated tokens consumed by each virtual key in the current budget window
    (label: `key`).
  - `busbar_lane_state`: per-(pool, lane-index) circuit-breaker health: `0` = healthy (Closed), `1` =
    half-open (cooling, probe admitted), `2` = tripped (Open or hard-down). Labels: `pool` and `lane` (numeric
    index). Read-only; does not trigger FSM transitions.

- **Native inbound TLS and optional mutual TLS.** Busbar now terminates TLS on the client-to-Busbar hop
  natively, without a reverse proxy. Add a `tls:` block to `config.yaml`:

  ```yaml
  tls:
    cert_file: /etc/busbar/tls/fullchain.pem
    key_file:  /etc/busbar/tls/privkey.pem
    client_ca_file: /etc/busbar/tls/ca.pem   # optional: enables mTLS
  ```

  When `client_ca_file` is present, Busbar requires a client certificate signed by that CA; connections
  without a valid cert are rejected at the TLS handshake, before any HTTP or bearer-token processing. Omitting
  `tls:` entirely leaves the plain-HTTP path unchanged.

### Changed

- **Provider containment (internal).** All provider-name branches were removed from the protocol-agnostic core
  and relocated behind the `ProtocolReader`/`ProtocolWriter` vtable, so provider-specific behavior lives
  entirely in `src/proto/*` (safe defaults plus per-provider overrides). No user-visible behavior change,
  architecture only.

### Fixed

- **Weight-zero drain bypass on the session-affinity path.** A pool member set to `weight: 0` (an operator
  draining a lane) could still receive requests that carried an existing session-affinity stickiness,
  sidestepping the drain. Affinity resolution now applies the same weight-zero exclusion as fresh routing;
  regression test added.
- **Anthropic outbound `User-Agent`.** Corrected the User-Agent header shape emitted on the Anthropic upstream
  hop.
- **SSRF guard covers the Oracle Cloud metadata address.** The trusted-upstream net guard now blocks
  `192.0.0.192` alongside the other link-local / cloud-metadata ranges.
- Additional cross-cutting correctness fixes (streaming-translation vtable flag propagation, request-id header
  constant) from the security and correctness review.

### Security

- **mTLS client-cert enforcement.** With `client_ca_file` set, unauthenticated connections are rejected at the
  TLS layer, before HTTP routing or governance checks — zero-trust transport without a service mesh.
- **TLS handshake timeout.** A 10-second wall-clock cap on each incoming TLS handshake prevents a client from
  parking a file descriptor and task indefinitely before authentication (slowloris / handshake-flood
  mitigation). A timed-out or failed handshake drops only that connection; the server continues serving other
  clients.
- **Webhook response size cap.** The `webhook` routing transport reads sidecar responses under a 64 KiB cap. A
  slow or hostile sidecar cannot drive unbounded memory allocation; an oversized response is an error and
  falls back to `on_error`.
- **Rhai script operation budget.** The `script` transport evaluates operator scripts under a per-invocation
  Rhai operation count limit and a hard wall-clock deadline (run on the blocking pool so a runaway script
  cannot pin an async worker). No module resolver, no file or network host functions are registered in the
  sandboxed engine.
- **Startup fail-fast for TLS config errors.** PEM cert, key, or CA load/parse failures abort startup with a
  message naming the offending file; key material is never logged. A single-connection handshake failure is
  logged at debug level only.

## [1.0.0-rc.4], 2026-06-16

A continued security and correctness hardening pass over the rc.3 tree, with class-level fixes. No API changes
vs rc.3. The test suite grew from 267 (rc.2) to **1334** passing; `fmt`, `build`, `clippy -D warnings`, and
`test` all green.

### Fixed

- **Circuit-breaker / streaming / FSM cluster**: clean SSE stream-end no longer records a spurious breaker
  failure; breaker success is recorded synchronously before streaming; mid-stream error paths no longer
  double-record. Readiness checks (`cell_ready_breaker`/`is_ready`) are split from the probe-acquiring
  transition (`cell_acquire_breaker`) so candidate enumeration no longer steals probes or transitions lanes; a
  failed half-open probe releases its permit instead of benching a lane permanently.
- **Upstream `Retry-After`** is extracted on the forward path and propagated through error normalization so
  the breaker cooldown floor is honored.
- **SSRF hardening**: backslash-bypass and OTLP-redirect vectors closed; the OTLP exporter uses a no-redirect
  client. Removed a duplicate `reqwest` major as a side effect.
- **Same-protocol non-stream large-body token undercount**: `FirstByteBody` now buffers and feeds the whole
  body once, so usage is no longer dropped past the per-chunk scan cap.
- A long tail of conformance, governance, admin-validation, and protocol-translation fixes across all six wire
  protocols.

## [1.0.0-rc.3], 2026-06-10

A security and correctness hardening release, plus the universal-ingress feature. No API changes vs rc.2
beyond the new ingress routes.

### Added

- **Universal ingress, all six protocols are now first-class ingress.** Previously clients could only speak
  Anthropic (`/<...>/v1/messages`) or OpenAI (`/v1/chat/completions`); now native Responses (`/v1/responses`),
  Cohere (`/v2/chat`), Gemini (`/v1beta/models/{model}:generateContent` / `:streamGenerateContent`), and
  Bedrock (`/model/{modelId}/converse` / `/converse-stream`) clients can point their SDK's base URL at Busbar
  unmodified. Each protocol has one ingress route; body-model protocols (`openai`, `responses`, `cohere`) take
  the model/pool from the request body, path-model protocols (`anthropic`, `gemini`, `bedrock`) from the URL.
  Errors are emitted in the caller's native protocol shape, with multi-scheme auth and content-type/identity
  handling per protocol.

### Changed

- **MSRV is now Rust 1.87** (declared via `rust-version`), reflecting use of `u32::is_multiple_of`.
- Internal: the auth mode is now a single source of truth on the auth middleware (removed a denormalized copy
  on the app state).

### Fixed

- **Cohere streaming text no longer dropped.** The content-delta reader could not decode the native object
  shape (`delta.message.content = {type,text}`) the writer emits, silently dropping streamed assistant text on
  the Cohere read/proxy path.
- **OpenAI `include_usage` streams.** A `usage: null` non-final chunk no longer synthesizes a spurious
  mid-stream `message_delta`; and a trailing usage-only chunk no longer produces a `message_delta` after
  `message_stop` on non-Bedrock ingress.
- **Gemini safety-filtered responses.** A `finishReason: SAFETY` candidate with no `content` field (a
  legitimate Gemini shape) is decoded normally instead of returning a spurious 500.
- **Bedrock conformance:** cross-protocol degraded error relays now forward `x-amzn-requestid` /
  `x-amzn-errortype`; tool-call ids are remapped to the client's native shape on the degraded path;
  prompt-cache token fields round-trip.
- **Responses non-streaming output items** now carry the native `id` / `status` / `annotations` the streaming
  path emits.
- Numerous lower-severity correctness/conformance fixes across the breaker cooldown jitter, SigV4 header
  canonicalization, health-probe Retry-After handling, and id synthesis (unbiased base62). Active health
  probes now send the same `User-Agent` / `Accept` as organic traffic. Admin key creation rejects negative
  budgets.

### Security

- **`/metrics` is no longer unconditionally open.** It now goes through the same auth check as `/stats`
  (requires a valid client token in `token` mode, or a virtual key under governance) because the Prometheus
  exposition — lane/pool topology, per-protocol counters, error rates — is an information-disclosure surface.
  Only `/healthz` remains unconditionally open. In `none`/`passthrough` mode `/metrics` is still admitted
  unconditionally. This supersedes the 0.16.2 security-review note that described `/metrics` as intentionally
  open.
- **SSRF guard hardened against trailing-dot hosts.** The webhook and OTLP endpoint validators stripped a
  trailing FQDN-root dot only inside one branch, so `127.0.0.1.` / `metadata.google.internal.` slipped past
  the IP-literal and cloud-metadata checks and resolved to internal targets. The dot is now stripped before
  every check, matching the upstream-config SSRF guard.
- **Admin reserved-name collision now rejected for models too.** A model named `admin` was reachable at
  `/admin/v1/messages` (the operator admin surface), making it unreachable to clients and bypassing per-model
  governance. Config validation now rejects it, symmetric with the pool/provider checks.
- **Anthropic egress no longer emits a dual-credential header.** An ambiguous credential previously sent both
  `x-api-key` and `authorization: Bearer`, a request shape no native client produces. The wire path now
  resolves it to the single native header the auth mode implies.

## [1.0.0-rc.2], 2026-06-04

### Changed

- **~30× faster cold start (≈206 ms → ≈6 ms).** The Prometheus recorder is now installed on a background
  thread, so its one-time clock calibration (quanta's TSC calibration, ~200 ms) no longer blocks the listener:
  Busbar binds and serves (including `/healthz`) in single-digit milliseconds, the right behavior for a
  daemon/k8s readiness path. Trade-off: `/metrics` renders empty until the recorder finishes calibrating
  shortly after start, and the few requests in that window are not counted.

## [1.0.0-rc.1], 2026-06-03

First release candidate for 1.0. Busbar is feature-complete and API-stable: six wire protocols with lossless
cross-protocol translation, weighted SWRR pools with per-(pool,lane) circuit breaking and in-flight failover,
governance (virtual keys / budgets / rate limits), and a security-hardened request path, all in one native
binary. The remaining work before 1.0.0 is operational validation (extended soak/leak testing and a
performance/SLO baseline), not features.

### Changed

- **Release profile optimized for distribution.** opt-level 3 + fat LTO + `codegen-units = 1` + symbol
  stripping cut the release binary from ~12 MB to **7.4 MB** with a faster hot path. `panic` stays `unwind` so
  a panic in one request task can't abort the whole gateway.
- **README rewritten** around the value proposition (SDK-swap hook, competitor comparison, Security and
  cross-protocol-translation sections, badges).

## [0.17.4], 2026-06-03

### Added

- **`default_max_tokens` per-model config (optional).** Sets the value injected for the case below; unset
  falls back to a conservative `4096`. Validated `> 0` at startup. Documented in `config.yaml`.

### Fixed

- **OpenAI→Anthropic translation no longer drops `max_tokens`.** An OpenAI-format request that omits
  `max_tokens` (legal: the OpenAI server applies a default) was translated to the Anthropic Messages API
  without one, which hard-rejects it (`400 max_tokens: Field required`), so any OpenAI-compatible client
  relying on the server default 400'd on every call once pointed at an Anthropic-backed lane. Busbar now
  injects a `max_tokens` at the cross-protocol translation boundary when the egress protocol requires it
  (Anthropic) and the source omitted it. A caller-supplied value is always preserved, and same-protocol
  passthrough is unaffected. Bedrock Converse defaults `maxTokens` server-side, so it is intentionally
  excluded (injecting would silently cap output).

## [0.17.3], 2026-05-31

Security hardening. The following vectors were reviewed and confirmed clean: SSRF on the routing paths
(provider/model validated against config; upstream URL never caller-derived), token-compare timing
(constant-time for client and admin tokens; virtual keys via SHA-256 + map), `/metrics` label cardinality
(unknown models are rejected before any metric, so labels stay config-bounded), secret-in-logs (no
keys/tokens/bodies logged), SQL injection (fully parameterized), and auth-bypass. Fixes below close the few
hardening gaps review surfaced.

### Changed

- Documented the two `to_vec` re-serialization sites as the invariants they are (built from already-valid
  JSON), and corrected a stale `UsageTap` doc comment that referenced a nonexistent carry buffer.
- Added an ad-hoc-route SSRF regression test (unknown provider/model → 404, mismatched provider → 400, both
  before any upstream call). 262 tests total.

### Security

- **Request body size limit.** The HTTP router now caps request bodies at 32 MiB (`DefaultBodyLimit`):
  previously unbounded beyond axum's 2 MiB default toggling, so a multi-gigabyte body could be buffered and
  exhaust memory (notably under `auth.mode=none`).
- **Constant-time token compare hardened.** `constant_time_eq` is now `#[inline(never)]` and runs its result
  through `std::hint::black_box`, so the optimizer can't fold the accumulation loop into an early-exit branch
  and reintroduce a timing signal (no new dependency).

## [0.17.2], 2026-05-31

### Fixed

- **Provider `health:` in `config.yaml` now takes effect.** The deployment-side `ProviderDeploy` had no
  `health` field, so a `health:` block under a provider in `config.yaml` (exactly as the shipped example
  documents) was silently dropped at parse time and `resolve()` only used the catalog's `providers.yaml`
  health — meaning active/dead health probing never spawned for config-defined health. `ProviderDeploy` now
  carries `health`, and `resolve()` merges it deployment-wins-over-catalog (mirroring `path`/`auth`). +
  regression test.

## [0.17.1], 2026-05-31

Second RC for final testing, fixes from the first 0.17.0 testing pass.

### Changed

- +7 unit tests (now 261): soft-cooldown recovery, reasoning translation (stream + non-stream),
  malformed-Authorization safety, config parsing, JSON-scanner underflow safety, stable affinity hash.

### Fixed

- **Dead-mode health probing now recovers soft-cooldown lanes.** A sub-threshold transient leaves the breaker
  Closed but arms a cooldown; the prober gate only fired for fully-tripped (Open) cells, so a single 5xx
  benched a single-member route for the full ~30s cooldown with no active recovery. The gate is now
  "breaker-suppressed in any cell" (Open/HalfOpen **or** a pending cooldown), and a successful probe clears
  the soft cooldown too.
- **Cross-protocol reasoning is preserved (OpenAI → Anthropic).** A model's `reasoning_content`
  (chain-of-thought) now maps to a `thinking` block instead of being dropped: both non-streaming (a leading
  thinking block) and streaming (a thinking block at index 0, with text/tools shifted after it). Non-reasoning
  responses are unchanged.
- **`--help` / `--version` and startup errors** no longer panic before argument handling: those flags print
  and exit without touching the filesystem, an unknown flag is a clean usage error, and every misconfiguration
  (missing/invalid providers.yaml or config.yaml, bad env interpolation, unknown provider/protocol,
  pool→unknown-model, invalid on_exhausted, bind failure) prints a clean `[error] …` instead of a backtrace.

## [0.17.0], 2026-05-31

Release candidate for final testing ahead of 1.0. Outcome of a systematic review of the full source for
correctness, robustness, and security.

### Changed

- **Logging:** a stderr `tracing` subscriber is always installed (level from `RUST_LOG`); OTLP export composes
  on top when configured. Previously all spans/warnings were dropped unless OTLP was set. Operational warnings
  moved from `eprintln!` to structured `tracing`.
- **Quality:** named the magic numbers/strings (auth modes, breaker states, failover/timeout/probe/
  rate-window/price/window-capacity defaults, Anthropic API version); the outcome window is a `VecDeque` (O(1)
  eviction); scrubbed internal references from comments; `Cargo.toml` reports the real version. One
  unconditional dead-code allow remains (a RAII guard).

### Fixed

- **Panics removed on hostile input:** a malformed `Authorization` header could panic on a UTF-8 boundary; a
  closing brace before an opening one in an upstream body could underflow the JSON brace scanner; an API key
  with a control character could panic the worker. All now fail cleanly.
- **Circuit-breaker error-rate trip** now uses windowed errors vs windowed total (both from the sliding
  window): a long-running lane no longer spuriously trips on clean recent traffic once old errors age out.
- **SWRR weight updates are serialized**: concurrent selections could corrupt the algorithm's invariant and
  bias distribution.
- **Cooldown jitter** applies its sign (±) instead of only ever lengthening cooldowns.
- **Session affinity** uses a stable hash, so sticky routing survives a restart (was a randomly seeded
  hasher).
- **Passthrough auth** now forwards the caller's bearer token (handlers previously dropped it, silently
  falling back to the lane's static key).
- **Degraded routing** (least-bad / fallback-pool) now applies cross-protocol translation, so it is correct
  when the chosen lane speaks a different protocol.
- Anthropic `tool` role messages map to the `user` role (no nonexistent `tool_use` role → 422); bedrock
  parse-error signal typo (`ir-parse` → `ir_parse`); token-count i64 saturation.
- Per-key rate-limit map evicts stale windows (was an unbounded per-key memory leak).
- `/admin` usage `requests` no longer double-counts non-streaming cross-protocol responses.
- `/stats` `inflight` is derived from the semaphore (was always 0).

## [0.16.2], 2026-05-31

### Security

- **Admin-token comparison is now constant-time.** The `/admin` management API compared the configured admin
  token with `==`, a timing side channel that could let an attacker recover the token byte-by-byte. It now
  uses the same constant-time comparison as client tokens.
- **Virtual-key generation fails closed.** If the OS CSPRNG (`getrandom`) is unavailable, Busbar now refuses
  to mint a key instead of falling back to a predictable, time-derived secret. (CSPRNG failure is
  near-impossible on supported platforms; the failure aborts only the key-mint request.)
- Security review found no other issues: virtual keys are SHA-256 hashed and never stored/compared raw; the
  admin API is token-gated and disabled when no admin token is set; key listings never expose hashes; no
  secrets are logged; cross-protocol JSON parsing has no caller-triggered panics; ad-hoc routes only reach
  configured (provider, model) pairs (no SSRF). At the time, `/healthz` and `/metrics` were intentionally open
  (protect `/metrics` at the network layer).
  - **Correction (superseded):** the claim that `/metrics` is intentionally open no longer holds. `/metrics`
    now goes through the same auth check as any other route: only `/healthz` stays unauthenticated for
    liveness probes, though under `none`/`passthrough` mode the check still admits unconditionally. See the
    **Security** notes in the 1.0.0-rc releases above and `src/auth.rs` (`auth_middleware`) for current
    behavior. The original line is kept as-written to preserve the historical record.

## [0.16.1], 2026-05-31

### Added

- **`error_map` can now match a provider's structured error *type***, not just its numeric code. Stage 1b
  checks `raw.structured_type` against `error_map` as a second data-driven signal (the explicit code still
  wins): useful for providers that surface a typed `error.type` but no code. (Previously `structured_type` was
  extracted by every protocol but never consulted.)
- `/stats` now reports each lane's `client_fault` counter alongside `ok`/`err`.

### Changed

- Dead-code cleanup: removed vestigial scaffolding (`SseCarryBuffer` and its test, `COOLDOWN_BASE_SECS`, an
  unused `FirstByteBody::usage` and `GovState::store` accessor) and resolved nearly every
  `#[allow(dead_code)]`; the remaining suppressions are one RAII permit guard plus test-only API gated behind
  `cfg(test)` / `cfg_attr(not(test))`. No behavior change from this part.

## [0.16.0], 2026-05-31

### Added

- **Per-(pool, lane) circuit-breaker isolation.** A lane shared by multiple pools now carries independent
  breaker state (Open/Closed/HalfOpen, streak, cooldown, error window, SWRR weight) per pool, so one pool's
  traffic tripping a lane no longer benches it for every other pool. Direct/ad-hoc routes and `/stats` use a
  lane-default cell; named pools each get their own, created lazily and inheriting the lane's current known
  health on first use. The breaker FSM is now written once over a `BreakerCellAccess` seam and run against
  either cell: no logic duplication. Lane-global concerns (the concurrency semaphore and the `max_requests`
  lifetime budget) remain shared across pools, since they cap the one upstream.
- Active health probing now recovers a lane across **every** cell (all pools + default) on a successful probe,
  and gates `dead`-mode probing on "tripped in any cell": a probe tests the shared upstream, so its result is
  lane-global.

### Changed

- This supersedes the 0.15.0 note that deferred per-(pool, lane) state.

## [0.15.0], 2026-05-31

### Added

- **Active health checks are now live.** A provider's `health:` block has a `mode`: `none` (default: passive
  health only), `dead` (periodically re-probe only tripped lanes so a recovered upstream is picked back up
  promptly), or `active` (probe every lane so a silently-dead upstream trips before real traffic hits it).
  Probes are a one-token request built by the lane's protocol writer (`probe_body`), so all six protocols work
  with no per-protocol code; `interval_secs`/`timeout_secs` are honored. One background task per probing lane;
  lanes with no key are skipped.
- **Per-pool circuit-breaker config is now live.** A pool's `breaker:` block (`trip.mode`
  error_rate|consecutive, `trip.window_s`/`threshold`/`min_requests`/`n`,
  `base_cooldown_secs`/`max_cooldown_secs`) is resolved at startup and drives the trip decision via
  `should_trip`: previously the block was parsed but ignored and the breaker used a hardcoded `err >= 5` rule.
  Streak ownership moved to the record path (incremented once per failure, reset on success) so
  consecutive-mode trips and cooldown escalation are coherent. Example added to `config.yaml` (pool
  `sensitive`).
- **`failover.exclusions`** are enforced: members named there are removed from a pool's candidate set (never
  selected, primary or failover).
- **Pool `affinity.header_name`** is honored: the session-pinning header is now configurable per pool
  (defaults to `x-session-id`).

### Changed

- Breaker state remains **per-lane** (not per-(pool,lane)). This is correct for the common case and for
  upstream-driven signals (a 401/429 is a property of the upstream, shared across pools). Full per-(pool,lane)
  state isolation, where one shared lane carries independent Open/Closed status per pool, was deferred: it
  would require threading a pool key through the `StateStore` trait and its 77 constructor sites, and only
  differs when one lane is shared by multiple pools with *different* breaker configs. (Landed in 0.16.0.)

### Fixed

- **Breaker recovery was broken, a tripped lane never came back.** On cooldown expiry the lane went HalfOpen
  and admitted a single probe; the probe's success reset the streak but never transitioned the breaker out of
  HalfOpen (`closed_state` was only ever called from tests), so `probe_in_flight` stayed set and every later
  `usable()` returned false. Any lane that ever tripped became permanently dead after one request.
  `record_success` now completes the recovery (→ Closed, cooldown cleared, probe released) when it sees a
  HalfOpen lane.

## [0.14.0], 2026-05-31

This changelog begins at 0.14.0; earlier history is not recorded here.

### Added

- **Cohere v2 protocol** (`/v2/chat`): the 6th wire protocol (Reader + Writer, request/response/streaming,
  bearer auth). System prompts are canonicalized into the IR so they survive cross-protocol translation.
- **Azure OpenAI auth adapter**: a per-provider `auth: api-key` style that sends the `api-key` header instead
  of bearer (deployment + `?api-version=` ride the existing `path` override). No new dependency; same
  `sign_request` seam as Bedrock SigV4. Template shipped in `providers.yaml`.
- `docs/roadmap.md`: the protocols-not-providers thesis and auth-adapter design.

### Fixed

- Cross-protocol pool responses now preserve the upstream `model` field (added to the IR), matching direct
  routes; a pool landing on a cross-protocol member no longer returns a model-less body.
- Token accounting on the buffered cross-protocol (non-streaming) path: usage is now tapped and charged to the
  virtual key, so TPM limits enforce (previously per-key tokens stayed 0).
- `max_requests` lifetime cap is now enforced: the success path records the lane success and decrements the
  budget (`spend_budget` previously never decremented), and the per-lane `ok` counter increments on success
  (was always 0; also fixed a latent double-count in `record_success`).

## [Early development]

### Added

- Project scaffolding for open-source release: `README`, `CONTRIBUTING`, `SECURITY`, issue/PR templates, and
  CI workflow.

### Changed

- Relicensed the project from MIT to a copyleft license. (Superseded: as of 1.2.0 the project is licensed
  under the **Apache License 2.0**.)
