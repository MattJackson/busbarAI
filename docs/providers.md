# Adding a provider

Busbar's thesis is **protocols, not providers**. It implements six wire protocols losslessly; a *provider* is just a catalog entry that says which protocol it speaks and where it lives. Adding one is a config entry you write yourself; no code changes hands. Any provider that speaks one of the six protocols, `anthropic`, `openai`, `gemini`, `bedrock`, `responses`, `cohere`, is a few lines of YAML. No new code, no pull request to Busbar, no waiting on an "integration."

## What a provider entry is

Providers live in `providers.yaml` as a map of name → definition. The shipped catalog is a verified starting set; you add your own entries exactly the same way (or define one inline in `config.yaml`).

| Field | Required | What it is |
|---|---|---|
| `protocol` | **yes** | The wire protocol the provider speaks: `anthropic`, `openai`, `gemini`, `bedrock`, `responses`, or `cohere`. |
| `base_url` | **yes** | Scheme + host (+ optional path prefix). Must be `https://` for external endpoints. |
| `error_map` | no | Provider-specific **JSON** error codes → a canonical disposition: one of `auth`, `billing`, `rate_limit`, `context_length`, `overloaded`, `server_error`, `timeout`, `network`, or `client_error` (the shipped catalog mostly uses `billing`/`rate_limit`). HTTP-status errors (429/5xx/401/…) are classified automatically without this. |
| `path` | no | Override the upstream request path appended to `base_url`: for providers that embed an API version in `base_url`. Static, ignores the per-request model. |
| `path_base` | no | For URL-model protocols (Gemini): override the hardcoded base segment (`/v1beta/models`) while keeping the per-request `/{model}:verb` suffix, e.g. to reach Google Vertex AI's project/location-scoped layout. |
| `auth` | no | The egress auth mechanism, when a backend doesn't use its protocol's native auth. One of: `bearer` (default) · `api-key` (header style) · `jwt-bearer` (OAuth 2.0 JWT-bearer, RFC 7523, mints + auto-refreshes a token from a service-account key; e.g. Google Vertex AI) · `oauth-client-credentials` (OAuth 2.0 client-credentials, RFC 6749 §4.4, the `api_key` reference resolves to `client_id:client_secret`; e.g. Azure OpenAI via Entra ID). |
| `token_url` | no | OAuth token endpoint for `auth: oauth-client-credentials`. Required for that auth style. |
| `scope` | no | OAuth scope for `auth: oauth-client-credentials`. Required for that auth style. |
| `health` | no | Optional health-probe configuration. |

The API key is **not** in this file. `config.yaml` supplies it as a secret reference (`api_key: { env: VAR }` / `{ file: /path }` / a secret plugin), so secrets never live in config.

## Add one in three steps

**1. Define the provider** in `providers.yaml` (an OpenAI-protocol example):

```yaml
# providers.yaml
my-provider:
  protocol: openai
  base_url: https://api.my-provider.com/v1
  # optional: map provider-specific JSON error codes to a disposition
  error_map:
    insufficient_quota: billing
    rate_limit_exceeded: rate_limit
```

**2. Deploy it** in `config.yaml`: name it, point at the env var holding its key, and give it a model:

```yaml
providers:
  my-provider: { api_key: { env: MY_PROVIDER_KEY } }

models:
  my-model: { provider: my-provider, max_concurrent: 20 }
```

**3. Run it:**

```bash
export MY_PROVIDER_KEY=sk-...
./busbar   # `my-model` is now reachable, and poolable alongside any other provider
```

## Choosing the protocol

The `protocol` is the provider's **native wire format**: what its own SDK speaks. Pick the one that matches:

- **`openai`**: any OpenAI Chat Completions–compatible endpoint (`/v1/chat/completions`). The bulk of the hosted long-tail (Groq, Together, Fireworks, DeepSeek, and most "OpenAI-compatible" APIs) lives here.
- **`anthropic`**: `/v1/messages` (Anthropic and Anthropic-compatible backends).
- **`gemini`**: Google Generative Language (`x-goog-api-key`, `:generateContent`).
- **`bedrock`**: AWS Bedrock Converse (SigV4-signed).
- **`responses`**: OpenAI Responses (`/v1/responses`).
- **`cohere`**: Cohere v2 (`/v2/chat`).

A client speaking *any* of these protocols can target a provider speaking *any other*, Busbar translates between them losslessly. The provider's protocol only says how Busbar talks to it upstream.

## Who speaks what: the model landscape as a lookup

Models are built by model makers; each maker's models are reached over a wire protocol, a *language*, and there are only about six in the world. This table is the lookup for "does Busbar support model X": find who makes it, see what language serves it. We audited the full public catalog of a 400-model aggregator against this table (56 organizations, July 2026): none of them requires a seventh language.

| Who makes the model | Their models are served over | Busbar route |
|---|---|---|
| OpenAI (GPT, o-series) | `openai`, `responses`: they define both | `openai` / `responses` |
| Anthropic (Claude) | `anthropic`: they define it | `anthropic`, or `bedrock` |
| Google (Gemini, Gemma) | `gemini`: they define it | `gemini` |
| Amazon (Nova) + Bedrock-hosted models | `bedrock`: they define it | `bedrock` |
| Cohere (Command) | `cohere`: they define it | `cohere` |
| Alibaba (Qwen), DeepSeek, Z.ai (GLM), Mistral, xAI (Grok), Moonshot (Kimi), MiniMax, NVIDIA (Nemotron), Meta (Llama API), Perplexity (Sonar) | First-party endpoints speaking `openai` | Shipped catalog entries (`dashscope`, `deepseek`, `zai-api`, `mistral`, `xai`, `moonshot`, `minimax`, `nvidia-nim`, `meta-llama`, …) |
| Baidu (ERNIE), ByteDance (Doubao/Seed), Tencent (Hunyuan), StepFun, Upstage (Solar), Reka, AI21 (Jamba), Liquid (LFM), Writer (Palmyra), Inception (Mercury) | First-party endpoints speaking `openai`, per their own docs | A few lines in your `providers.yaml` |
| Open-weights makers: Microsoft (Phi), IBM (Granite), Ai2 (OLMo), NousResearch, Xiaomi (MiMo), Sakana, and the fine-tune community (Sao10K, TheDrummer, Gryphe, …) | No first-party hosted API needed: served by `openai`-speaking hosts | Catalog hosts: `groq`, `together`, `fireworks`, `deepinfra`, `novita`, `featherless`, `cerebras`, `sambanova`, `hyperbolic`, … |
| Aggregator-only or private-deploy makers (Inflection's Pi, poolside) | Their own first-party dialects, but served over `openai` by aggregators | The `openrouter` catalog entry, or the host that serves them |

Two honest notes. First, "supported" here means *reachable in its full native fidelity over one of the six languages*: for open-weights and aggregator-served models, that's the host's endpoint rather than the maker's own. Second, the one first-party endpoint in that audit that speaks its own dialect (Inflection) is still one lane away through an `openai`-speaking host, so the lookup's answer is unchanged; a model would need to be served *exclusively* over a genuinely novel wire format to fall outside it, and we haven't found one.

## `error_map` and the breaker (why we vet)

HTTP-status failures (429, 5xx, 401, …) are classified by the circuit breaker automatically. But some providers signal **billing** or **rate-limit** conditions with their own JSON error codes: sometimes even inside a `200` body. `error_map` translates those codes into a disposition so the breaker reacts correctly: a `billing` failure becomes a sticky 30-minute hard-down, a `rate_limit` becomes a short transient cooldown.

This is exactly why the shipped catalog is **verified, not scraped**: a wrong mapping makes the breaker mis-classify a failure. When you add a provider, check its error documentation and map the billing/rate-limit codes; leave `error_map` empty if it only uses standard HTTP statuses.

## Non-standard endpoints

Some backends don't serve the protocol's default path or native auth:

```yaml
# Version embedded in base_url, endpoint is /chat/completions (no /v1):
zai-api:
  protocol: openai
  base_url: https://api.z.ai/api/paas/v4
  path: /chat/completions

# api-key header instead of bearer (e.g. Azure-style):
my-azure:
  protocol: openai
  base_url: https://my-resource.openai.azure.com/openai/deployments/gpt-4o
  path: /chat/completions?api-version=2024-02-01
  auth: api-key

# Azure OpenAI via Entra ID (AAD): OpenAI protocol, but a bearer minted from an app registration's
# client_id:client_secret at the tenant token endpoint (auto-refreshed) instead of an api-key.
azure-entra:
  protocol: openai
  base_url: https://my-resource.openai.azure.com
  path: /openai/deployments/gpt-4o/chat/completions?api-version=2024-06-01
  auth: oauth-client-credentials
  token_url: https://login.microsoftonline.com/MY-TENANT/oauth2/v2.0/token
  scope: https://cognitiveservices.azure.com/.default
  api_key: { env: AZURE_ENTRA_CREDS }      # value = "client_id:client_secret"

# Google Vertex AI (Gemini): the same gemini protocol at a project/location-scoped URL, authed with a
# self-minting OAuth token instead of an API key. `path_base` reshapes the URL; `auth: jwt-bearer`
# mints + auto-refreshes a bearer from the service-account key the `api_key` reference resolves to (inline JSON or a path).
gemini-vertex:
  protocol: gemini
  base_url: https://us-central1-aiplatform.googleapis.com
  path_base: /v1/projects/YOUR_PROJECT/locations/us-central1/publishers/google/models
  auth: jwt-bearer
  api_key: { env: VERTEX_SA_KEY }
  error_map:
    RESOURCE_EXHAUSTED: rate_limit

# Claude-on-Vertex is the same shape on the anthropic protocol (publishers/anthropic). busbar moves
# the model into the URL (:rawPredict) and adds the required anthropic_version body field for you:
claude-vertex:
  protocol: anthropic
  base_url: https://us-central1-aiplatform.googleapis.com
  path_base: /v1/projects/YOUR_PROJECT/locations/us-central1/publishers/anthropic/models
  auth: jwt-bearer
  api_key: { env: VERTEX_SA_KEY }
  error_map: {}
```

See the [configuration reference](/docs/configuration/) for every field and default.
