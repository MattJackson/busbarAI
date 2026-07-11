# Smart router: task-aware model selection with `route: webhook`

A minimal proof of concept for "pick the best model automatically based on the
task, latency, quality, and cost" using busbar's routing-policy hook. No busbar
changes; one Python file, stdlib only.

- `policy_server.py` — the webhook policy sidecar (classify + score + rank).
- `smart_router.rhai` — the same logic as an embedded Rhai script, for binaries
  built with the `script-policy` cargo feature.

## How it works

Before each request's failover loop, busbar POSTs a projection of the request
and the pool's candidates to the sidecar and reads back a ranked preference
list (`{"order": [idx, ...]}`). The exact wire format is documented in the
[routing guide](https://getbusbar.com/docs/routing/) and pinned by
`src/routing/webhook.rs`.

What the sidecar actually receives:

- `request`: `pool`, `ingress_protocol`, `message_count`, `has_tools`,
  `total_chars`, `max_tokens`, `stream`.
- `candidates[]`: `idx`, `model`, `tier`, `cost_per_mtok`, `latency_ms`
  (rolling EWMA, `null` until the lane has served a request),
  `available_concurrency` (free semaphore slots), `budget_remaining`,
  `rate_headroom`.

Note what is NOT in the payload: prompt text and message bodies. Busbar never
sends request content to an external sink, so the classifier works on shape
signals, not keywords or code fences. The `tags` member field is exposed to
the Rhai script environment but not to the webhook payload (tier is available
on both).

### Classification (task buckets)

| Bucket | Trigger (in priority order) | Optimizes for |
|---|---|---|
| `code` | `has_tools: true` (tool/agent traffic) | capable tier |
| `long-form` | `max_tokens >= 4096` or `total_chars > 24000` (~6k tokens at ~4 chars/token) | capable tier, then cost |
| `bulk` | non-streaming and `message_count <= 1` (single-shot batch) | cost |
| `quick-answer` | everything else (interactive chat) | latency |

### Scoring

Each candidate gets a weighted score over normalized signals, all of which
busbar provides live:

```
score = w_cost * (1 - cost/max_cost)
      + w_lat  * (1 - latency/max_latency)
      + w_conc * (concurrency/max_concurrency)
      + 0.5 if tier matches the bucket's preferred tiers
score *= 0.5 + 0.5 * rate_headroom   (when governance provides it)
```

Missing signals (a cold lane with no latency EWMA, a member without
`cost_per_mtok`) score neutral 0.5 so they are neither favored nor stranded.
The full list is returned, most preferred first; omitted or unknown indices
are demoted, never excluded, so the failover loop can still reach every lane.

"Quality" is the operator's judgment encoded as `tier` (and `tags` in the
Rhai variant) on pool members, informed by whatever offline evals you run.
The sidecar reads it; busbar enforces the resulting order.

## Wiring it up

Uses the models already defined in the repo's shipped `config.yaml`. Add this
pool (the `tier`/`cost_per_mtok`/`tags` metadata is what the policy ranks on;
costs below are illustrative — declare your own):

```yaml
pools:
  smart-router:
    route: webhook
    policy:
      url: "http://127.0.0.1:8787/"
      timeout_ms: 150        # default; hard deadline for the sidecar decision
      on_error: weighted     # default; fall back to SWRR on timeout/error/abstain
    members:
      - target: claude-sonnet
        tier: large
        cost_per_mtok: 3.0
        tags: ["code", "general"]
        context_max: 200000
      - target: gpt-4o
        tier: large
        cost_per_mtok: 5.0
        tags: ["code"]
        context_max: 128000
      - target: gemini-1.5-pro
        tier: large
        cost_per_mtok: 2.5
        tags: ["long-context"]
        context_max: 2000000
      - target: claude-haiku
        tier: small
        cost_per_mtok: 0.8
        tags: ["cheap", "fast"]
      - target: gpt-4o-mini
        tier: small
        cost_per_mtok: 0.15
        tags: ["cheap", "fast"]
```

Run it:

```sh
python3 examples/smart-router/policy_server.py       # sidecar on 127.0.0.1:8787
busbar --config config.yaml                          # busbar with the pool above
curl -s http://127.0.0.1:8080/smart-router/v1/messages \
  -H 'content-type: application/json' \
  -d '{"model":"smart-router","max_tokens":100,"messages":[{"role":"user","content":"hi"}]}' -i
```

Every routed response carries `x-busbar-route-policy: webhook` and
`x-busbar-route-target: <model>` so you can see each decision.

Exercise the sidecar directly:

```sh
curl -s http://127.0.0.1:8787/ -d '{
  "request": {"pool":"smart-router","ingress_protocol":"anthropic","message_count":1,
              "has_tools":false,"total_chars":120,"max_tokens":256,"stream":true},
  "candidates": [
    {"idx":0,"model":"claude-sonnet","tier":"large","cost_per_mtok":3.0,
     "latency_ms":320.0,"available_concurrency":18,"budget_remaining":null,"rate_headroom":null},
    {"idx":1,"model":"gpt-4o-mini","tier":"small","cost_per_mtok":0.15,
     "latency_ms":95.0,"available_concurrency":40,"budget_remaining":null,"rate_headroom":null}
  ],
  "context": {"pool":"smart-router","budget_remaining":null}
}'
# → {"order": [1, 0]}   (quick-answer bucket: the fast cheap lane wins)
```

### Rhai variant

If your binary is built with `--features script-policy`:

```yaml
pools:
  smart-router:
    route: script
    policy:
      script_file: examples/smart-router/smart_router.rhai
      on_error: weighted
    members:
      # same members as above
```

## The fail-safe

The hook is advisory, never load-bearing:

- The decision is bounded by `policy.timeout_ms` (default **150 ms**,
  `DEFAULT_POLICY_TIMEOUT_MS` in `src/config.rs`). A slow sidecar is cut off.
- Any timeout, non-2xx, malformed JSON, or oversized response is coerced to
  the pool's `on_error` (default `weighted`, i.e. plain SWRR). The client
  request proceeds either way; a broken sidecar is indistinguishable from no
  policy.
- The ranked order feeds the existing failover loop: if the policy's #1 pick
  is tripped or at capacity, busbar walks to #2 with the normal breaker
  machinery. A wrong ranking degrades gracefully; it cannot strand a request.

Kill the sidecar mid-traffic to see it: requests keep flowing, and
`x-busbar-route-policy` shows the fallback.

## Benchmark

How much latency the hook adds, and how to reproduce it, is in [`bench/`](bench/).
