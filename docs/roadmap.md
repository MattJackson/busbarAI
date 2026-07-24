# Busbar: design notes & roadmap

## Protocols, not providers

Busbar's scope is defined by **wire protocols**, not by a hand-maintained list of
vendor integrations. It implements a small set of protocols losslessly:

| Protocol | Surface | Auth shape |
|---|---|---|
| `anthropic` | `/v1/messages` | `x-api-key` (API key, `sk-ant-api…`) or `Authorization: Bearer` (OAuth, `sk-ant-oat…`); unrecognized credentials get both. See configuration.md. |
| `openai` | `/v1/chat/completions` | bearer |
| `responses` | `/v1/responses` | bearer |
| `gemini` | `:generateContent` / `:streamGenerateContent` | api-key header (`x-goog-api-key`) |
| `bedrock` | Converse / ConverseStream | per-request **AWS SigV4** |
| `cohere` | v2 `/v2/chat` | bearer |

Any provider that speaks one of these is a **catalog entry** in `providers.yaml`
(a name, a `base_url`, an env var for its key, an optional `path` override): no
code. A client speaking any protocol can target any provider; busbar translates
through its superset IR when the two differ.

This is why the number to watch is the **protocol count (6)**, not the provider
count. The shipped catalog is a *curated* convenience set of verified hosted
endpoints, verified, not scraped, because each entry's error-code mappings feed
the breaker's fault attribution. An operator can point busbar at *any*
OpenAI-compatible endpoint, including their own, with three lines of YAML and
no wait for an "integration." We deliberately don't chase a giant provider count;
that's a maintenance treadmill that dilutes the vetting.

## The auth-adapter seam

A provider integration is two things: a **protocol** (request/response shape) and
an **auth method**. Busbar separates them. The `ProtocolWriter` trait exposes two
hooks (`crates/busbar/src/proto/mod.rs`):

- `auth_headers(key)`: static headers (bearer, api-key header, …).
- `sign_request(key, ctx)`, per-request signing, given method/host/path/body/time.

Bedrock overrides `sign_request` to compute SigV4 from `ACCESS_KEY:SECRET[:SESSION]`
with the region parsed from the host. **This already proves the architecture is not
bearer-only**: today there are four distinct auth shapes in production: bearer,
`x-goog-api-key`, SigV4, and a per-provider `auth: api-key` override (Azure OpenAI).
The per-provider `path` override (for version-in-base-url endpoints) is another piece
of the same flexibility.

So "non-standard auth/path" backends are not a categorical exclusion, they are
the next **auth adapters** on a seam that already exists.

## Shipped in 0.14

### Cohere v2 protocol
- **Cohere v2** (`/v2/chat`): the Command family natively, as the 6th protocol
  (request/response/streaming Reader + Writer, bearer auth). System prompts are
  canonicalized into the IR so they survive cross-protocol translation.

## Shipped in 0.15

- **Active health checks**: a per-provider `health:` block (`mode: none|dead|active`,
  `interval_secs`, `timeout_secs`). `dead` re-probes only tripped lanes for prompt
  recovery; `active` probes every lane so a silently-dead upstream trips before real
  traffic hits it. Probes reuse each protocol's `probe_body`, so all six protocols
  work with no per-protocol code.
- **Per-pool circuit-breaker config**: a pool's `breaker:` block (`trip.mode`
  error_rate|consecutive, window/threshold/min_requests/n, base/max cooldown) now
  drives the trip decision instead of a hardcoded rule.
- **`failover.exclusions`**: members named there are removed from a pool's
  candidate set entirely (never primary or failover).
- **Configurable affinity header**: a pool's `affinity.header_name` (default
  `x-session-id`).
- **Breaker recovery fix**: a tripped lane now completes recovery to Closed on a
  successful half-open probe (previously it could become permanently dead).

## Shipped in 0.16

- **Per-(pool, lane) circuit-breaker isolation**: a lane shared across pools now
  carries independent breaker state per pool, so one pool tripping a lane no longer
  benches it for the others. Concurrency and `max_requests` budget stay shared
  (one upstream); a successful health probe recovers the lane in every pool.

## Shipped in 1.5

- **The cost model: tokens are the ledger, dollars are derived.** Enforcement accumulates a
  per-(bucket, window, model, tier) token ledger; every spend figure is computed at read time from
  that ledger and the top-level `rate_card` (per-model, per-tier micro-unit rates in an abstract
  cost unit). Nothing dollar-shaped is stored, so correcting a rate is a config edit and reload,
  not a re-billing. The old flat per-1k-token price is gone; `rate_card` is the only token-pricing
  mechanism, with `per_request_fee` as a separate flat per-call fee.
- **The `groups:` limit tree.** Nestable enforcement buckets — the ONE place limits live (keys are
  pure auth and carry none). A key binds one with the mint field `group`; admission walks the whole
  parent chain (any depth — the arbitrary 8-level ceiling is gone; the cycle check bounds the walk),
  ANDs every limit, and the 429 names the exhausted bucket. Mint-time key `labels` ride onto the
  Prometheus series so external dashboards break spend down by any operator dimension. A group may
  carry a `child_default` limit template: the first auto-provisioned child under a group inherits
  those limits (nearest-ancestor wins), so a org/team/user hierarchy stamps per-user budgets
  automatically.
- **Pool-qualified limits and `on_exhaust: downgrade`.** A windowed limit may carry `pool: <name>`
  to account per `(group, pool)` instead of group-wide: one team's expensive-tier budget is
  independent from their cheap-tier budget. A pool-scoped `budget` limit may also declare
  `on_exhaust: downgrade, downgrade_to: <pool>` — when it runs dry, the request is re-admitted
  through the cheaper pool instead of refused (the caller's expensive calls get cheaper, not
  blocked).
- **Runtime-mutable groups on the Admin API.** `GET/POST/PUT/PATCH/DELETE /api/v1/admin/groups`
  and `GET /groups/{name}/usage` (per-(window, pool) usage vs. caps, repriced at read time) and
  `GET /keys?group=<name>` (the keys bound to a group). A write is validate-at-the-door, then live
  on the next request; the ledger survives the swap. `PATCH` is the ergonomic "raise Alice's
  budget" and "freeze a team" verb.
- **Self-service mint: auto-provision + the `mint` scope.** `POST /keys` accepts an optional
  `parent`: when `group` names a leaf that does not yet exist, it is auto-provisioned under
  `parent` (limits from `child_default`). A new delegated `mint` admin scope — sibling of
  `hooks-register`, NOT a ladder rung above it — lets a self-service portal mint keys without
  god-mode `full`. `limits.max_keys_per_principal` caps keys per group (per-user anti-sprawl).
- **Per-section overlay reset.** `DELETE /api/v1/admin/overlay/{section}` (section `groups` |
  `hooks`) discards all overlay mutations for that section and reverts it to base `config.yaml`
  truth, leaving the other section's runtime mutations untouched.
- **Enforcement is always on.** There is no `governance:` block or enabled switch. Enforcement is
  always present and simply inert until keys are minted, so a default deploy behaves as "off" did
  with the same RAM. Durability is a choice via the top-level `store:` block (`memory` default;
  durable backends load as signed plugins).
- **Dynamic plugins.** Store, auth, and hook backends can load from a signed `.tar.gz` at boot over
  a versioned C ABI, gated by the `plugins.*` block (off by default, ed25519 signature verification
  against the embedded release key, explicit opt-ins for unsigned or third-party). The default
  binary is leaner for it: the SQLite store now ships as a droppable plugin rather than compiled in.

## Post-1.0 roadmap

### Auth adapters for enterprise backends
These reuse existing protocols (no new wire format) gated behind an auth shim: the
same pattern Bedrock established with SigV4 and Azure OpenAI (shipped in 0.14):

- **Google Vertex AI**: **shipped in 1.4**, both **Gemini-on-Vertex** (`gemini`
  protocol) and **Claude-on-Vertex** (`anthropic` protocol), at a project/location-
  scoped URL (`path_base`) authed with the new `auth: jwt-bearer` OAuth adapter (a
  short-lived bearer minted from a service-account key via the RFC 7523 JWT-bearer
  grant, and auto-refreshed). Each is a `providers.yaml` entry, no new protocol.
  Claude-on-Vertex additionally moves the model into the URL (`:rawPredict`) and
  adds the `anthropic_version` body field, both handled automatically.
- **Databricks Foundation Model APIs**: `openai` protocol with bearer auth, but
  the `base_url` is workspace-specific (`https://<workspace>/serving-endpoints`),
  so it is added by the operator as their own host rather than shipped in the
  verified catalog. Supportable today via a config entry + `path` override; will be
  documented as a recipe.

### Pre-release stream buffer

Streaming failover today is bounded by the first byte reaching the client (see
[failover](failover.md)). A configurable pre-release buffer would hold the first
*K* tokens / *T* ms of an upstream stream before releasing any byte, so a provider
that dies inside that window can still be rerouted invisibly. Costs up to *T* ms of
added TTFT, so it will be opt-in per pool and default to off (today's behavior).
Not yet built; no config surface exists for it.

The SemVer-stable contract is the RUNTIME: the data-plane HTTP surface and the six wire protocols do
not break without a major-version bump. The config format is an operator deployment artifact outside
that freeze: it may change between releases, always with a migration path (`busbar --migrate-config`)
and a loud fail-closed boot on an outdated config. The admin API carries its own contract version
(`/api/v1/admin`).
