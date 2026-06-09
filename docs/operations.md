# Operations

Running busbar in production: process configuration, health/readiness, the metrics
to watch, circuit-breaker and health-probe behavior, failover/exhaustion outcomes,
governance/admin usage, and troubleshooting.

## Process configuration

Busbar is a single native binary configured by two YAML files and environment
variables.

| Env var | Default | Purpose |
|---|---|---|
| `BUSBAR_PROVIDERS` | `/etc/busbar/providers.yaml` | Path to the provider catalog. |
| `BUSBAR_CONFIG` | `/etc/busbar/config.yaml` | Path to the deployment config. |
| Provider key vars | — | Named by each provider's `api_key_env` (e.g. `ANTHROPIC_KEY`). |
| Token/secret vars | — | Anything referenced via `${VAR}` in either file (client tokens, admin token, …). |

Startup is fail-loud: an unset `${VAR}`, an unknown provider reference, an unknown
protocol or auth mode, or an invalid `on_exhausted` action stops the process with a
diagnostic. A provider whose key env var is empty logs a warning and runs (its lane
will fail auth on first use). `auth.mode: none` prints a loud open-relay warning.

The HTTP client uses a 300s request timeout and pools up to 64 idle keep-alive connections per upstream host.

## Health & readiness

| Endpoint | Auth | Meaning |
|---|---|---|
| `GET /healthz` | open | `200 ok` if **any** lane is usable; `503` otherwise. Use for liveness/readiness probes. |
| `GET /metrics` | client token (or virtual key) | Prometheus exposition; requires auth in `token`/governance mode, always open in `none`/`passthrough` mode. Restrict at the network layer if unauthenticated scraping is needed. |
| `GET /stats` | client token (or virtual key) | Per-lane health snapshot + pool membership, JSON. |

`/stats` returns, per lane: `model`, `provider`, `max_concurrent`, `inflight`,
`free_slots`, `ok`, `err`, `usable`, `dead`, `dead_reason`, `cooldown_remaining_s`,
`streak`, and `budget`. It is the first place to look when a pool is degraded.

## Metrics to watch

All metrics are Prometheus counters/histograms exposed at `/metrics`.

| Metric | Type | Labels | Watch for |
|---|---|---|---|
| `busbar_requests_total` | counter | `ingress_protocol`, `pool`, `outcome` | `outcome` is `ok` / `client_error` / `exhausted` (503) / `error`. A rising `exhausted` means pools are running out of healthy members. |
| `busbar_upstream_attempts_total` | counter | `pool`, `lane` | Real upstream calls (re-counted per failover hop). |
| `busbar_upstream_failures_total` | counter | `pool`, `lane`, `disposition` | `disposition` is `transient_upstream` / `hard_down` / `context_length`. Concentration on one lane points at a sick backend. |
| `busbar_breaker_trips_total` | counter | `pool`, `lane` | Each hard-down/trip. Spikes = a backend going down. |
| `busbar_failovers_total` | counter | `pool`, `reason` | `reason` is `timeout` / `connect` / `transient_upstream` / `hard_down`. |
| `busbar_translations_total` | counter | `from`, `to` | Cross-protocol translation hops. |
| `busbar_request_duration_seconds` | histogram | `ingress_protocol`, `pool` | End-to-end latency. |

`/metrics` requires a valid client token in `token` mode (or a virtual key under
governance) — it is treated as an information-disclosure surface and goes through
the same auth check as other routes. Only `none`/`passthrough` mode admits scrapes
unconditionally. Restrict it at the network layer (firewall, reverse proxy) if you
need unauthenticated scraping under your threat model.

## Circuit breaker

The breaker decides health from real request outcomes (passive), with optional
active probing layered on top. The disposition pipeline (see
[architecture.md](architecture.md)) decides *whether* an outcome counts as an
upstream fault; this section covers *what happens to the lane* once it does.

Breaker state is **per-(pool, lane)**: a lane that is a member of more than one pool
carries independent Open/Closed/HalfOpen state, streak, cooldown, and error window in
each pool, so one pool's traffic tripping a lane does not bench it for the others.
Direct/ad-hoc routes (`POST /:provider/:model`, `POST /:model`) and `/stats` share a
single lane-default cell. The concurrency limit and the `max_requests` lifetime budget
are **not** per-pool — they cap the shared upstream, so they apply across every pool.
A successful active health probe (it tests the shared upstream) clears the breaker in
*every* cell for the lane.

### States

```
        success (probe)
   ┌──────────────────────────────┐
   │                              │
   ▼                              │
 Closed ──trip condition──▶ Open ──cooldown expires──▶ HalfOpen
   ▲                                                      │
   │                              ┌──── probe fails ──────┘ (→ Open, longer cooldown)
   └──────────────────────────────┘
              probe succeeds
```

- **Closed** — the lane serves traffic. A single upstream failure that does **not**
  meet the trip condition still arms a short cooldown (the lane is briefly skipped),
  but the breaker stays Closed.
- **Open** — the lane is tripped and skipped during selection until its cooldown
  expires.
- **HalfOpen** — on cooldown expiry, the next selection attempt transitions the lane
  to HalfOpen and admits **exactly one** probe request (single-flight via CAS). A
  successful probe completes recovery to Closed (streak/error window cleared); a
  failed probe reopens the lane with an escalated cooldown.

### Trip conditions

Configured per pool via `breaker.trip` (see
[configuration.md](configuration.md#breaker)):

- **`error_rate`** (default) — trips when the failure fraction over `window_s`
  reaches `threshold` (default 0.5), but never before `min_requests` (default 5)
  outcomes have accrued in the window.
- **`consecutive`** — trips on `n` consecutive failures (default 3).

### Cooldown & backoff

Cooldown grows exponentially with the consecutive failure streak, doubling from
`base_cooldown_secs` up to `max_cooldown_secs`, with ±10% jitter once the streak is
nonzero. A server `Retry-After` header is always honored as a **floor** — even if it
exceeds `max_cooldown_secs`. Defaults (no `breaker:` block): base 15s, max 120s.

### Hard-down vs transient

- A **transient** fault (5xx/timeout/network/overload/rate-limit) drives the trip
  evaluation and, on trip, opens the breaker — recoverable via the half-open probe.
- A **hard-down** fault (billing/quota or auth) opens the breaker immediately with a
  long *sticky* cooldown (30 min) rather than waiting for a trip threshold — it does
  **not** set a permanent `dead` flag, so it is still recoverable: a successful active
  probe (or organic half-open probe) brings it back. An **auth** hard-down also relays the
  error to the caller; a **billing** hard-down fails the request over to another
  member.

## Active health probing

Passive health alone only learns a lane is sick when real traffic hits it, and only
recovers it on the next organic request. Active probing (per-provider `health:`
config) adds a background prober:

| `mode` | Behavior |
|---|---|
| `none` (default) | No probing; pure passive health. |
| `dead` | Periodically re-probe **only tripped** lanes, so a recovered upstream is picked back up promptly. |
| `active` | Periodically probe **every** lane, so a silently-dead upstream trips out before real traffic hits it. Sends a tiny billable one-token request per interval. |

Each probing lane gets one background task. `interval_secs` (default 30) and
`timeout_secs` (default 5) are honored (floored at 1s). The first tick is skipped so
busbar doesn't probe before any traffic establishes health. A lane with no key is
skipped (a guaranteed 401 would only thrash the breaker). A 2xx probe recovers a
tripped lane to Closed without polluting the `ok` stats; a failed probe records a
transient (which, on a Closed lane in `active` mode, can trip it out).

## Failover & exhaustion

For a single request, busbar will retry across pool members up to the failover
`cap` (default 3) and within the `deadline_secs` budget (default 120). Failover is
allowed **only before the first upstream byte reaches the client** — once streaming
has started, a failure cannot fail over (the client holds a partial response); the
lane records the breaker fault and the stream terminates with an SSE `error` event,
and the client must retry.

When all members are unusable, the pool's `on_exhausted` action decides:

- `reject` / `status_503` (default) — `503` with `Retry-After` = soonest member's
  cooldown expiry.
- `least_bad` — serve the member whose cooldown expires soonest (degraded, logged
  loudly).
- `fallback_pool:<name>` — route to another pool (loop-guarded).

If `outcome="exhausted"` (503) is climbing in `busbar_requests_total`, check
`/stats` for dead/tripped lanes and consider a `fallback_pool` or `least_bad` policy
for graceful degradation.

## Governance & the admin API

When `governance.enabled: true`, clients authenticate with **virtual keys** and the
static `auth` tokens no longer apply to proxied requests. Keys are managed over the
admin API, guarded by `governance.admin_token` (sent as `Authorization: Bearer
<admin_token>` or `X-Admin-Token: <admin_token>`). With no admin token configured,
the admin API returns `401`.

| Method · Route | Purpose |
|---|---|
| `POST /admin/keys` | Mint a virtual key. The plaintext secret is returned **once**. |
| `GET /admin/keys` | List key metadata (never secrets/hashes). |
| `GET /admin/keys/:id/usage` | Current-window usage: `spend_cents`, `tokens`, `requests`. |
| `DELETE /admin/keys/:id` | Revoke a key. |

### Creating a key

```bash
curl -s -X POST http://localhost:8080/admin/keys \
  -H "Authorization: Bearer $BUSBAR_ADMIN_TOKEN" \
  -H "content-type: application/json" \
  -d '{
        "name": "team-search",
        "allowed_pools": ["fast", "overflow"],
        "max_budget_cents": 50000,
        "budget_period": "monthly",
        "rpm_limit": 600,
        "tpm_limit": 200000
      }'
```

Create-key fields:

| Field | Type | Default | Notes |
|---|---|---|---|
| `name` | string | — | Required label. |
| `allowed_pools` | list<string> | `[]` | Pools/models this key may target. Empty = all allowed. Violations → `403`. |
| `max_budget_cents` | integer | none | Spend cap for the budget window; exceeded → `429` (or `400` for Bedrock ingress). |
| `budget_period` | string | `total` | `total` (all-time), `daily` (UTC midnight), or `monthly` (UTC first-of-month). |
| `rpm_limit` | integer | none | Requests per 60s window; exceeded → `429` + `Retry-After`. |
| `tpm_limit` | integer | none | Tokens per 60s window; exceeded → `429` + `Retry-After`. |

### Enforcement model

- **Allowed-pools / budget / rate** are checked before forwarding (`403` /
  `429` (or `400` for Bedrock ingress) / `429` respectively). Budget exhaustion is
  not a distinct `402`: it surfaces as the vendor-native quota status with
  `error.type: insufficient_quota` in the body, so it stays indistinguishable from
  a real upstream quota error.
- **Budget** is token-accurate: a flat `price_per_request_cents` is charged at
  request completion, and `price_per_1k_tokens_cents * tokens/1000` is charged when
  the response stream completes, tapped from the upstream's reported usage.
- **Rate windows** are per-key, in-memory, fixed 60s windows (single-node; not yet
  distributed across replicas). RPM is enforced precisely; TPM is enforced against
  tokens accrued in the window from prior responses.
- **Budget windows** persist in SQLite at `governance.db_path`.

> Run a single busbar instance per governance database, or accept that RPM/TPM
> windows are per-process: rate state is in-memory and not shared across replicas.

## Troubleshooting

| Symptom | Where to look |
|---|---|
| `503` on every request | `/stats` — are all lanes `dead` or in cooldown? Check `dead_reason`. |
| A lane stuck `dead` with `billing` reason | Upstream wallet/quota; the lane recovers on a successful probe once funded. Consider `health.mode: dead`. |
| A lane stuck `dead` with `auth` reason | Wrong/expired key in the provider's `api_key_env`. |
| `429` from busbar itself | A virtual key hit a limit. The body's `error.type` distinguishes the cause: `rate_limit_error` = RPM/TPM cap; `insufficient_quota` = over budget for its window (Bedrock ingress signals over-budget as `400` instead). Check `GET /admin/keys/:id/usage`. |
| `403` from busbar | The virtual key's `allowed_pools` doesn't include the target. |
| Startup panic: "unset environment variable" | A `${VAR}` (possibly in a comment) isn't exported. |
| Startup panic: "not found in providers.yaml" | A `config.yaml` provider name isn't in the catalog. |
| Cross-protocol responses missing fields | Expected — only the modeled IR subset survives a cross-protocol hop; same-protocol routes are lossless. |
| High `busbar_failovers_total` for one lane | That backend is flapping; inspect its `busbar_upstream_failures_total` `disposition`. |
