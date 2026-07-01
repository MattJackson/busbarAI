# Pools

A **pool** is a named, weighted group of model lanes that share failover, circuit breaking, and session affinity. Your clients address a pool by name (as the `model` field), and Busbar decides which backend actually serves each request. Pools are how you turn several providers into one reliable endpoint.

Pools are optional: you can route directly to a single model. But the moment you want weighting, failover, cost-aware routing, or overflow, you reach for a pool.

<svg viewBox="0 0 720 300" role="img" aria-label="A client sends a request to a pool; the pool holds three lanes, each a model at a provider with its own breaker cell." style="width:100%;height:auto;max-width:720px;font-family:ui-sans-serif,system-ui,sans-serif;">
  <rect x="0" y="0" width="720" height="300" fill="#ffffff"/>
  <!-- client -->
  <rect x="16" y="120" width="120" height="56" rx="10" fill="#0f172a"/>
  <text x="76" y="153" text-anchor="middle" fill="#ffffff" font-size="15" font-weight="600">Client</text>
  <text x="76" y="196" text-anchor="middle" fill="#64748b" font-size="11">model: "chat"</text>
  <!-- arrow -->
  <line x1="140" y1="148" x2="196" y2="148" stroke="#94a3b8" stroke-width="2"/>
  <polygon points="196,143 208,148 196,153" fill="#94a3b8"/>
  <!-- pool -->
  <rect x="216" y="28" width="488" height="244" rx="16" fill="#f8fafc" stroke="#e2e8f0" stroke-width="1.5"/>
  <text x="240" y="56" fill="#0f172a" font-size="14" font-weight="700">pool: chat</text>
  <text x="680" y="56" text-anchor="end" fill="#64748b" font-size="11">weighted · failover</text>
  <!-- lanes -->
  <g>
    <rect x="240" y="72" width="440" height="52" rx="10" fill="#ffffff" stroke="#e2e8f0"/>
    <circle cx="264" cy="98" r="6" fill="#a3e635"/>
    <text x="284" y="94" fill="#0f172a" font-size="13" font-weight="600">gpt-4o</text>
    <text x="284" y="112" fill="#64748b" font-size="11">via openai</text>
    <text x="656" y="103" text-anchor="end" fill="#334155" font-size="13" font-weight="700">weight 8</text>
  </g>
  <g>
    <rect x="240" y="132" width="440" height="52" rx="10" fill="#ffffff" stroke="#e2e8f0"/>
    <circle cx="264" cy="158" r="6" fill="#a3e635"/>
    <text x="284" y="154" fill="#0f172a" font-size="13" font-weight="600">claude-sonnet</text>
    <text x="284" y="172" fill="#64748b" font-size="11">via anthropic</text>
    <text x="656" y="163" text-anchor="end" fill="#334155" font-size="13" font-weight="700">weight 2</text>
  </g>
  <g>
    <rect x="240" y="192" width="440" height="52" rx="10" fill="#ffffff" stroke="#e2e8f0"/>
    <circle cx="264" cy="218" r="6" fill="#cbd5e1"/>
    <text x="284" y="214" fill="#0f172a" font-size="13" font-weight="600">gemini-pro</text>
    <text x="284" y="232" fill="#64748b" font-size="11">via gemini · tripped, skipped</text>
    <text x="656" y="223" text-anchor="end" fill="#334155" font-size="13" font-weight="700">weight 1</text>
  </g>
</svg>

## The vocabulary

- **Pool** — a named group of lanes (what a client targets). Owns the selection policy, failover, and affinity.
- **Lane** — one model at one provider (a `models:` entry). The unit of concurrency, lifetime budget, and circuit breaking.
- **Cell** — the breaker state for a specific *(pool, lane)* pair. A lane that trips in pool A keeps serving in pool B, because each pool has its own cell. See [Reliability](/reliability/) for the breaker deep-dive.

## How selection works

By default a pool uses **smooth weighted round-robin (SWRR)** over the healthy members: each request goes to the next member by weight, and a tripped, dead, or capacity-exhausted member is skipped with its share redistributed to the rest. If the chosen lane fails before the client has seen a byte, Busbar fails over to the next member, even mid-stream. That is the whole reliability story: weighting for the happy path, automatic failover for the bad one.

Set `route:` to something other than `weighted` and a **routing policy** decides the order instead. The policy runs once per request, before the failover loop:

| `route:` | Picks the member with... |
|---|---|
| `weighted` (default) | the next weighted turn (SWRR). Zero overhead. |
| `cheapest` | the lowest `cost_per_mtok`. |
| `fastest` | the lowest measured latency (rolling EWMA). |
| `least_busy` | the most free concurrency. |
| `usage` | the most rate-limit headroom. |
| `webhook` | the order your HTTP sidecar returns. |
| `script` | the order your Rhai script returns. |

Every policy is documented in full, with worked examples, in the [Routing guide](routing.md). The rest of this page is about pool *structure*: members, weights, failover, and affinity.

## Config reference

**Pool fields**

| Field | Type | Default | Notes |
|---|---|---|---|
| `members` | list | required | The lanes in this pool (see below). |
| `route` | enum | `weighted` | `weighted`, `cheapest`, `fastest`, `least_busy`, `usage`, `webhook`, `script`. |
| `policy` | object | none | Transport config; required for `webhook`/`script`. `url`, `script`/`script_file`, `timeout_ms`, `on_error` (`weighted`/`reject`/`first`). |
| `affinity` | object | none | `mode: session` pins a session to a lane by `header_name` (default `x-session-id`). |

See the [Routing guide](routing.md) for the `route`/`policy` details and every native policy, and [Reliability](/reliability/#circuit-breaker-configuration) for the per-pool `breaker`, `failover`, and `on_exhausted` blocks.

**Member fields**

| Field | Type | Default | Notes |
|---|---|---|---|
| `target` | string | required | A model name (a `models:` entry). |
| `weight` | integer | `1` | Relative SWRR share over healthy members. Must be ≥ 1. |
| `context_max` | integer | none | This lane's context window; requests larger than it fail over to a bigger lane. |
| `tier` | string | none | Routing tier label (e.g. `primary`, `overflow`); read by policies. |
| `cost_per_mtok` | float | none | Cost per million tokens; drives the `cheapest` policy. |
| `tags` | list | `[]` | Free-form labels read by webhook/script policies. |

`tier`, `cost_per_mtok`, and `tags` are consumed by routing policies; see [Routing](routing.md#the-routing-signals) for the full signal set each policy receives.

## Recipes

### Weighted split with automatic failover

```yaml
pools:
  chat:
    members:
      - { target: gpt-4o,        weight: 8 }   # ~80% of traffic
      - { target: claude-sonnet, weight: 2 }   # ~20%
      - { target: gemini-pro,    weight: 1 }   # picks up load when the others trip
```

### Same model, two providers (cross-provider failover)

Run one real model behind two providers. The keys differ; `upstream_model` carries each provider's own model string. See [Configuration](/configuration/#models).

```yaml
models:
  sonnet-anthropic: { provider: anthropic,         max_concurrent: 20, upstream_model: claude-3-5-sonnet-20241022 }
  sonnet-bedrock:   { provider: bedrock-us-east-1, max_concurrent: 10, upstream_model: anthropic.claude-3-5-sonnet-20241022-v2:0 }
pools:
  sonnet:
    members:
      - { target: sonnet-anthropic, weight: 3 }   # primary
      - { target: sonnet-bedrock,   weight: 1 }   # same model, other cloud
```

### Context-length failover

```yaml
pools:
  long-context:
    members:
      - { target: gpt-4o,        context_max: 128000,  weight: 3 }
      - { target: gemini-15-pro, context_max: 2000000, weight: 1 }   # over-128k requests land here
```

### Sticky sessions

```yaml
pools:
  agents:
    affinity:
      mode: session
      header_name: x-session-id      # defaults to x-session-id if omitted
    members:
      - { target: gpt-4o,        weight: 1 }
      - { target: claude-sonnet, weight: 1 }
```

### Cost-, latency-, and custom-based routing

Choosing *which* member serves a request (cheapest, fastest, least busy, or your own webhook/Rhai logic) is a routing-policy concern, not a pool-shape one. Those recipes, with full worked examples, live in the [Routing guide](routing.md#full-examples).

See the [Routing guide](routing.md) for the full policy contract and the signals each policy receives, and [Reliability](/reliability/) for how the breaker and failover behave once a policy has chosen an order.
