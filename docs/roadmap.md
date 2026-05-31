# Busbar — design notes & roadmap

## Protocols, not providers

Busbar's scope is defined by **wire protocols**, not by a hand-maintained list of
vendor integrations. It implements a small set of protocols losslessly:

| Protocol | Surface | Auth shape |
|---|---|---|
| `anthropic` | `/v1/messages` | bearer (`Authorization`) |
| `openai` | `/v1/chat/completions` | bearer |
| `responses` | `/v1/responses` | bearer |
| `gemini` | `:generateContent` / `:streamGenerateContent` | api-key header (`x-goog-api-key`) |
| `bedrock` | Converse / ConverseStream | per-request **AWS SigV4** |
| `cohere` | v2 `/v2/chat` | bearer |

Any provider that speaks one of these is a **catalog entry** in `providers.yaml`
(a name, a `base_url`, an env var for its key, an optional `path` override) — no
code. A client speaking any protocol can target any provider; busbar translates
through its superset IR when the two differ.

This is why the public number to watch is the **protocol count (6)**, not the
provider count. The shipped catalog (currently 42 providers) is a convenience
list of vetted hosted endpoints; an operator can point busbar at *any*
OpenAI-compatible endpoint — including their own — with three lines of YAML and
no wait for an "integration."

## The auth-adapter seam

A provider integration is two things: a **protocol** (request/response shape) and
an **auth method**. Busbar separates them. The `ProtocolWriter` trait exposes two
hooks (`src/proto/mod.rs`):

- `auth_headers(key)` — static headers (bearer, api-key header, …).
- `sign_request(key, ctx)` — per-request signing, given method/host/path/body/time.

Bedrock overrides `sign_request` to compute SigV4 from `ACCESS_KEY:SECRET[:SESSION]`
with the region parsed from the host. **This already proves the architecture is not
bearer-only**: today there are four distinct auth shapes in production — bearer,
`x-goog-api-key`, SigV4, and a per-provider `auth: api-key` override (Azure OpenAI).
The per-provider `path` override (for version-in-base-url endpoints) is another piece
of the same flexibility.

So "non-standard auth/path" backends are not a categorical exclusion — they are
the next **auth adapters** on a seam that already exists.

## Shipped in 0.14

### Cohere v2 protocol
- **Cohere v2** (`/v2/chat`) — the Command family natively, as the 6th protocol
  (request/response/streaming Reader + Writer, bearer auth). System prompts are
  canonicalized into the IR so they survive cross-protocol translation.

## Roadmap (1.0)

### Auth adapters for enterprise backends
These reuse existing protocols (no new wire format) gated behind an auth shim — the
same pattern Bedrock established with SigV4:

- **Azure OpenAI** — **shipped (0.14).** The `openai` protocol with a per-provider
  `auth: api-key` style (sends the `api-key` header instead of bearer); the
  `?api-version=` query parameter and deployment live in the provider's `path`
  override. No new dependency. See the template in `providers.yaml`.
- **Google Vertex AI** — largely the `gemini` protocol (plus Claude-on-Vertex via
  the `anthropic` protocol) behind **GCP OAuth2**: a short-lived bearer minted from
  a service-account credential and refreshed, against a per-project/region host.
  The wire protocols already exist; the work is the token-mint/refresh adapter.
  This introduces a credential/JWT dependency — an operator-judgment gate before
  it lands.
- **Databricks Foundation Model APIs** — `openai` protocol with bearer auth, but
  the `base_url` is workspace-specific (`https://<workspace>/serving-endpoints`),
  so it is added by the operator as their own host rather than shipped in the
  vetted catalog. Supportable today via a config entry + `path` override; will be
  documented as a recipe.

### 1.0 hardening
- Operator documentation (`docs/configuration.md` — every field, routing model,
  governance/observability setup).
- Soak / load testing.
- Security review (virtual-key issuance, budget accounting, Bedrock SigV4).

APIs and config may change before 1.0.
