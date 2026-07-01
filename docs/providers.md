# Adding a provider

Busbar's thesis is **protocols, not providers**. It implements six wire protocols losslessly; a *provider* is just a catalog entry that says which protocol it speaks and where it lives. Adding one is config, not code, and it's *your* config. Any provider that speaks one of the six protocols, `anthropic`, `openai`, `gemini`, `bedrock`, `responses`, `cohere`, is a few lines of YAML. No new code, no pull request to Busbar, no waiting on an "integration."

## What a provider entry is

Providers live in `providers.yaml` as a map of name → definition. The shipped catalog is a curated, vetted starting set; you add your own entries exactly the same way (or define one inline in `config.yaml`).

| Field | Required | What it is |
|---|---|---|
| `protocol` | **yes** | The wire protocol the provider speaks: `anthropic`, `openai`, `gemini`, `bedrock`, `responses`, or `cohere`. |
| `base_url` | **yes** | Scheme + host (+ optional path prefix). Must be `https://` for external endpoints. |
| `error_map` | no | Provider-specific **JSON** error codes → a disposition (`billing` or `rate_limit`). HTTP-status errors (429/5xx/401/…) are classified automatically without this. |
| `path` | no | Override the upstream request path appended to `base_url`: for providers that embed an API version in `base_url`. |
| `auth` | no | `bearer` (default) or `api-key` (header style), when a backend doesn't use its protocol's native auth. |
| `health` | no | Optional health-probe configuration. |

The API key is **not** in this file. `config.yaml` supplies it by naming the environment variable that holds it (`api_key_env`), so secrets never live in config.

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
  my-provider: { api_key_env: MY_PROVIDER_KEY }

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

## `error_map` and the breaker (why we vet)

HTTP-status failures (429, 5xx, 401, …) are classified by the circuit breaker automatically. But some providers signal **billing** or **rate-limit** conditions with their own JSON error codes: sometimes even inside a `200` body. `error_map` translates those codes into a disposition so the breaker reacts correctly: a `billing` failure becomes a sticky 30-minute hard-down, a `rate_limit` becomes a short transient cooldown.

This is exactly why the shipped catalog is **vetted, not scraped**: a wrong mapping makes the breaker mis-classify a failure. When you add a provider, check its error documentation and map the billing/rate-limit codes; leave `error_map` empty if it only uses standard HTTP statuses.

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
```

See the [configuration reference](/configuration/) for every field and default.
