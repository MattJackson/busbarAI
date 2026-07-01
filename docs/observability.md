# Health, metrics, and observability

Busbar exposes its liveness, per-lane topology, and Prometheus metrics on three endpoints. This page documents each, plus the signals worth alerting on.

Cross-references: [Circuit breaker](/circuit-breaker/) · [In-flight failover](/failover/) · [Configuration](/configuration/#observability).

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

Prometheus text exposition (`text/plain; version=0.0.4`). Goes through the same auth check as other routes, it is treated as an information-disclosure surface (it reveals pool structure, lane names, and failure rates). In `none`/`passthrough` mode the auth check admits unconditionally, so `/metrics` is effectively open under those modes; restrict it at the network layer if that matters for your threat model.

Always enabled; no config needed.

## Metrics to watch

| Metric | Type | Labels | What to watch for |
|---|---|---|---|
| `busbar_requests_total` | counter | `ingress_protocol`, `pool`, `outcome` | `outcome=exhausted` rising → pools running out of healthy members. `outcome=error` → 5xx-class problems reaching the client; `outcome=client_error` → 4xx relayed to callers. |
| `busbar_upstream_attempts_total` | counter | `pool`, `lane` | Real upstream calls, re-counted per failover hop. Ratio to `busbar_requests_total` > 1 indicates failovers are happening. |
| `busbar_upstream_failures_total` | counter | `pool`, `lane`, `disposition` | `disposition` is `transient_upstream`, `hard_down`, or `context_length`. `hard_down` requires intervention (auth/billing problem). |
| `busbar_breaker_trips_total` | counter | `pool`, `lane` | One per Closed→Open trip (reopens don't count). A spike means a backend just went down. |
| `busbar_failovers_total` | counter | `pool`, `reason` | `reason` is `timeout`, `connect`, `transient_upstream`, `hard_down`, or `context_length`. A high rate on one pool indicates a flapping member. |
| `busbar_translations_total` | counter | `from`, `to` | Cross-protocol translation hops. Useful for auditing unexpected protocol conversion. |
| `busbar_request_duration_seconds` | histogram | `ingress_protocol`, `pool` | End-to-end latency including failover hops. |
| `busbar_key_spend_cents` | gauge | `key` | Per-virtual-key spend in cents for the current budget window (scrape-time). Only emitted when governance is enabled. Use for burn-rate alerting. |
| `busbar_key_budget_remaining_cents` | gauge | `key` | Max budget minus current spend for keys with a `max_budget_cents` cap. Only emitted for capped keys. Drive Prometheus budget-burn alerts. |
| `busbar_key_tokens_total` | gauge | `key` | Accumulated tokens consumed by each virtual key in the current budget window. Only emitted when governance is enabled. |
| `busbar_lane_state` | gauge | `pool`, `lane` | Per-(pool, lane-index) circuit-breaker health: `0` = Closed (healthy), `1` = HalfOpen (cooling, probe admitted), `2` = Open (tripped). Side-effect-free at scrape time. |
| `busbar_route_policy_selections_total` | counter | `pool`, `policy` | Requests where a routing policy produced a usable ranked order. Only incremented on a successful `Order` outcome; abstains and on-error fallbacks are not counted. |

The `pool` label is always a configured pool name or the sentinel `unresolved` (for routes that did not resolve to a pool). It is never a raw client-supplied model string, which would create unbounded label cardinality.

An OTLP traces sink (`observability.otlp_endpoint`) and a request-log webhook (`observability.request_log_webhook_url`) are available for deeper observability. Both are validated at startup against SSRF blocklists (no RFC-1918, loopback, or cloud-metadata targets, except OTLP allows plaintext `http://` to loopback for a local collector). See [configuration.md](configuration.md#observability).

---
