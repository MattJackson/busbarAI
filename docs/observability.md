# Health, metrics, and observability

Busbar exposes its liveness, per-lane topology, and Prometheus metrics on three endpoints. This page documents each, plus the signals worth alerting on.

Cross-references: [Circuit breaker](/docs/circuit-breaker/) · [In-flight failover](/docs/failover/) · [Configuration](/docs/configuration/#observability).

## /healthz

```
GET /healthz
```

No auth required. Returns `200 OK` (body: `ok`) if any lane is usable: meaning at least one lane across all configured pools has a Closed or HalfOpen breaker in any of its cells, and is not permanently dead. Returns `503 Service Unavailable` (body: `no usable lanes`) if every lane is unusable.

Use as a Kubernetes readiness and liveness probe. The check is side-effect-free: it never steals a HalfOpen recovery probe slot.

A `503` from `/healthz` means all lanes are either tripped/cooling, hard-down, budget-exhausted, or permanently dead. Check `/stats` for details.

## /stats

```
GET /stats
Authorization: Bearer <client-token-or-virtual-key>
```

Requires auth (client token or virtual key). Returns a JSON topology snapshot, scoped to the calling key's `allowed_pools`: a key with a non-empty `allowed_pools` list sees only its permitted pools and the lanes reachable through them.

Per-lane fields in the response:

| Field | Meaning |
|---|---|
| `model` | Model name (as declared in `models:`). |
| `provider` | Provider name. |
| `max_concurrent` | Lane's concurrency cap. |
| `inflight` | Currently executing requests. |
| `free_slots` | `max_concurrent - inflight`. |
| `ok` | Lifetime successful upstream responses. |
| `err` | Lifetime recorded upstream failures. |
| `client_fault` | Lifetime 4xx responses attributed to callers (not counted against breaker). |
| `usable` | `true` if the lane is Closed or HalfOpen in any cell. |
| `dead` | `true` if permanently dead (restart to clear). |
| `dead_reason` | `auth`, `billing`, or other hard-down reason. |
| `cooldown_remaining_s` | Worst-case cooldown remaining across all cells (0 if Closed). |
| `streak` | Current consecutive failure streak (worst across cells). |
| `budget` | Remaining `max_requests` lifetime budget (`-1` = unlimited). |

`/stats` is the first tool to reach for when diagnosing a degraded pool. Check `cooldown_remaining_s` (non-zero means a cell is Open and the value shows when it will try to recover), `streak` (growing streak suggests repeated probe failures), and `dead` + `dead_reason` (a hard problem requiring intervention).

## /metrics

```
GET /metrics
Authorization: Bearer <client-token-or-virtual-key>
```

Prometheus text exposition (`text/plain; version=0.0.4`). Goes through the same auth check as other routes, it is treated as an information-disclosure surface (it reveals pool structure, lane names, and failure rates). With no auth chain (`auth.chain: []`), the check admits unconditionally, so `/metrics` is effectively open. Restrict it at the network layer if that matters for your threat model.

Always enabled; no config needed.

## Metrics to watch

| Metric | Type | Labels | What to watch for |
|---|---|---|---|
| `busbar_requests_total` | counter | `ingress_protocol`, `pool`, `outcome` | `outcome=exhausted` rising → pools running out of healthy members. `outcome=error` → 5xx-class problems reaching the client; `outcome=client_error` → 4xx relayed to callers. |
| `busbar_upstream_attempts_total` | counter | `pool`, `lane` | Real upstream calls, re-counted per failover hop. Ratio to `busbar_requests_total` > 1 indicates failovers are happening. |
| `busbar_upstream_failures_total` | counter | `pool`, `lane`, `disposition` | `disposition` is `transient_upstream`, `attempt_timeout`, `hard_down`, or `context_length`. `hard_down` requires intervention (auth/billing problem). |
| `busbar_breaker_trips_total` | counter | `pool`, `lane` | One per Closed→Open trip (reopens don't count). A spike means a backend just went down. |
| `busbar_failovers_total` | counter | `pool`, `reason` | `reason` is `timeout`, `connect`, `transient_upstream`, `attempt_timeout`, `hard_down`, or `context_length`. A high rate on one pool indicates a flapping member. |
| `busbar_translations_total` | counter | `from`, `to` | Cross-protocol translation hops. Useful for auditing unexpected protocol conversion. |
| `busbar_request_duration_seconds` | histogram | `ingress_protocol`, `pool` | End-to-end latency including failover hops. |
| `busbar_key_spend_cents` | gauge | `key` + mint labels | Per-virtual-key DERIVED spend (abstract minor units, all-time attribution bucket), recomputed at scrape time from the token ledger x the current `rate_card` plus the flat fee (reprice-on-read). |
| `busbar_bucket_spend_cents` | gauge | `bucket`, `group`, `window` | Derived spend per (group, window) enforcement bucket (`bucket` = `group:<name>@<window>`). |
| `busbar_bucket_budget_remaining_cents` | gauge | `bucket`, `group`, `window` | Budget cap minus derived spend, only for buckets with a `budget` limit. Use for burn-rate alerting. |
| `busbar_key_budget_remaining_cents` | gauge | `key` + mint labels | Max budget minus current derived spend for keys with a `max_budget_cents` cap. Only emitted for capped keys. Drive Prometheus budget-burn alerts. |
| `busbar_key_tokens_total` | gauge | `key` + mint labels | Accumulated tokens consumed by each virtual key (all-time attribution bucket). |
| `busbar_bucket_tokens` | gauge | `bucket`, `model`, `tier` (+ mint labels on key buckets) | Per-(bucket, model, tier) token counters for the bucket's current budget window, from the token ledger. `bucket` is a virtual-key id or `group:<name>`; `tier` ∈ `input`\|`output`\|`cache_read`\|`cache_write`. The raw material for any external per-model cost dashboard (multiply by your own catalog). |
| `busbar_bucket_spend_cents` | gauge | `bucket` | Derived spend per BUDGET-GROUP bucket (tokens x current rate card; the flat fee counts against key buckets) for its current window. |
| `busbar_bucket_budget_remaining_cents` | gauge | `bucket` | Budget-group cap minus derived spend. The external-alerting hook: point Alertmanager at 80% burn - busbar ships the hard 100% stop only, alerts live outside the core. |
| `busbar_lane_state` | gauge | `pool`, `lane` | Per-(pool, lane-index) circuit-breaker health: `0` = Closed (healthy), `1` = HalfOpen (cooling, probe admitted), `2` = Open (tripped). Side-effect-free at scrape time. |
| `busbar_route_policy_selections_total` | counter | `pool`, `policy` | Requests where a routing policy produced a usable ranked order. Only incremented on a successful `Order` outcome; abstains and on-error fallbacks are not counted. |
| `busbar_route_policy_rejections_total` | counter | `pool`, `policy`, `status` | Requests deliberately rejected by a routing hook's `reject` verb (a 4xx to the caller, no upstream dispatched). A guardrail saying no, not a failure. |
| `busbar_billing_truncated_total` | counter | none | A same-protocol non-stream response whose billing-side buffer hit the translate-body cap before the terminal `usage` block, so tokens could not be parsed and the request billed zero. The client response is unaffected; only the billing side-channel was capped. Alert on a non-zero rate to catch an over-cap billing gap. |
| `busbar_tap_notifications_dropped_total` | counter | none | A fire-and-forget tap notification dropped because the in-flight cap was reached (slow or unreachable tap endpoint). Global backpressure, not per-request. Alert on a non-zero rate. |
| `busbar_webhook_logs_dropped_total` | counter | none | A request-log webhook delivery shed because the bounded delivery pool was saturated (the endpoint is slow or unreachable). Global backpressure. A non-zero rate means logs are being dropped silently. |

**Mint labels.** Key labels attached at mint (`labels: {"team": "growth"}`) are echoed verbatim onto that key's gauge series, so Grafana can `sum by (team)` and Alertmanager can fire per team without busbar knowing what a team is. Label keys are operator-chosen at mint (admin-plane bounded), never request bytes.

**Spend is derived, and the hard cap is per node.** Every spend gauge above is recomputed at scrape time from the token ledger and the current `rate_card`; nothing dollar-shaped is stored, so a rate correction re-prices what you see on the next scrape. When N busbar nodes share a durable store, each node scrapes its own in-memory window counters and enforces the budget hard cap per node (fleet-wide the effective ceiling is up to ~N times a configured cap between flushes; see [operations.md](operations.md)).

The `pool` label is always a configured pool name or the sentinel `unresolved` (for routes that did not resolve to a pool). It is never a raw client-supplied model string, which would create unbounded label cardinality.

An OTLP traces sink (`observability.otlp_url`) and a request-log webhook (`observability.request_log_webhook_url`) are available for deeper observability. Both are validated at startup against SSRF blocklists (no RFC-1918, loopback, or cloud-metadata targets, except OTLP allows plaintext `http://` to loopback for a local collector). See [configuration.md](configuration.md#observability).

---
