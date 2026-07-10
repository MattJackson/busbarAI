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
hooks (`src/proto/mod.rs`):

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

## Post-1.0 roadmap

### Auth adapters for enterprise backends
These reuse existing protocols (no new wire format) gated behind an auth shim: the
same pattern Bedrock established with SigV4 and Azure OpenAI (shipped in 0.14):

- **Google Vertex AI**: largely the `gemini` protocol (plus Claude-on-Vertex via
  the `anthropic` protocol) behind **GCP OAuth2**: a short-lived bearer minted from
  a service-account credential and refreshed, against a per-project/region host.
  The wire protocols already exist; the work is the token-mint/refresh adapter.
  This introduces a credential/JWT dependency: an operator-judgment gate before
  it lands.
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

APIs and config are stable at 1.0.0 under Semantic Versioning, no breaking change without a major-version bump.
