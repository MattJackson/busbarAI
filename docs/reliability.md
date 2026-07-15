# Reliability guide

Busbar keeps serving through provider failures. That reliability is not one feature but a stack of them, spread across a few guides. This page is the map, and the worked example at the end shows them working together.

**Structure** — how you describe your backends ([Core concepts](/docs/pools/)):

- **[Pools](/docs/pools/)** - group backends into one named target with weighting and automatic failover.
- **[Routing policies](/docs/routing/)** - choose which member serves each request: cheapest, fastest, least busy, or your own logic.

**Resilience** — what happens when a backend misbehaves (the guides in this section):

- **[Circuit breaker](/docs/circuit-breaker/)** - fault-attributed breaking that classifies each failure and benches only the lane at fault.
- **[In-flight failover](/docs/failover/)** - reroute a failing request before your client sees a byte, even mid-stream, across protocols.
- **[Health and observability](/docs/observability/)** - `/healthz`, `/stats`, `/metrics`, and the signals to watch.

**Control** — who may spend what ([Governance](/docs/guides/governance/)):

- **[Governance and limits](/docs/guides/governance/)** - virtual keys, budgets, rate limits, and pool access control.

The rest of this page ties them together with one production-like configuration.

## End-to-end worked example

The following config creates a production-like setup: a weighted primary pool with fast failover and a cheap overflow, context-length failover between members, session affinity, aggressive tripping with a low streak threshold, and governance-enforced per-team rate limits.

```yaml
listen: "0.0.0.0:8080"

auth:
  chain: [tokens]
  client_tokens:
    - "${BUSBAR_CLIENT_TOKEN}"

providers:
  anthropic:
    api_key_env: ANTHROPIC_KEY
    health:
      mode: dead
      interval_secs: 30
      timeout_secs: 5
  openai:
    api_key_env: OPENAI_KEY
  gemini:
    api_key_env: GEMINI_KEY

models:
  claude-sonnet:
    provider: anthropic
    max_concurrent: 20
    default_max_tokens: 4096

  gpt-4o:
    provider: openai
    max_concurrent: 20

  gemini-flash:
    provider: gemini
    max_concurrent: 30

  claude-haiku:
    provider: anthropic
    max_concurrent: 40

pools:
  primary:
    members:
      - target: claude-sonnet
        weight: 5
        context_max: 200000
      - target: gpt-4o
        weight: 3
      - target: gemini-flash
        weight: 2
        context_max: 1048576
    affinity:
      mode: session
      header_name: x-session-id
    breaker:
      trip:
        mode: consecutive
        consecutive_n: 2       # trip fast, 2 consecutive failures
      base_cooldown_secs: 5
      max_cooldown_secs: 60
    failover:
      timeout_secs: 30
      max_hops: 3
    on_exhausted:
      action: fallback_pool:overflow

  overflow:
    members:
      - target: claude-haiku
        weight: 1
    on_exhausted:
      action: least_bad        # degraded but available; never hard-503

governance:
  enabled: true
  db_path: /var/lib/busbar/governance.db
  admin_token: "${BUSBAR_ADMIN_TOKEN}"
  price_per_request_cents: 0
  price_per_1k_tokens_cents: 10
```

What this achieves:

- **Weighted primary dispatch**: `claude-sonnet` gets 50% of traffic, `gpt-4o` 30%, `gemini-flash` 20%.
- **Fast trip**: two consecutive failures opens a member's breaker in the `primary` pool with a 5-second initial cooldown. Organic traffic triggers failover to the next member within the 30-second deadline.
- **Context-length failover**: if `claude-sonnet` rejects a request as too long (200k context), Busbar excludes `claude-sonnet` and retries to `gemini-flash` (1M context) without penalizing the `claude-sonnet` lane.
- **Session affinity**: callers with `x-session-id` headers stay pinned to the same member while it is healthy.
- **Overflow**: if all primary members are exhausted, traffic spills to `claude-haiku`. If haiku is also exhausted, `least_bad` picks the member with the soonest recovery rather than returning 503.
- **Health probing**: `anthropic` lanes are re-probed on trip (`mode: dead`), so a recovered Anthropic backend is brought back promptly without waiting for organic traffic to probe it.
- **Governance**: each team gets a virtual key with per-pool ACLs and token-based rate limits. Mint keys with `POST /api/v1/admin/keys`.

To mint a key for a team:

```bash
curl -s -X POST http://localhost:8080/api/v1/admin/keys \
  -H "Authorization: Bearer $BUSBAR_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
        "name": "team-search",
        "allowed_pools": ["primary", "overflow"],
        "tpm_limit": 500000,
        "rpm_limit": 300,
        "budget_period": "monthly"
      }'
```

The response's `secret` field (`sk-bb-…`) is what the team uses as their API key pointed at busbar. They set it wherever they previously set their Anthropic/OpenAI key. Busbar handles the rest.
