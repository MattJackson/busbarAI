# Adding a provider

Busbar's thesis is **protocols, not providers**. It implements six wire protocols losslessly; a *provider* is just a catalog entry that says which protocol it speaks and where it lives. Adding one is config, not code, and it's *your* config. Any provider that speaks one of the six protocols, `anthropic`, `openai`, `gemini`, `bedrock`, `responses`, `cohere`, is a few lines of YAML. No new code, no pull request to Busbar, no waiting on an "integration."

## What a provider entry is

Providers live in `providers.yaml` as a map of name → definition. The shipped catalog is a verified starting set; you add your own entries exactly the same way (or define one inline in `config.yaml`).

| Field | Required | What it is |
|---|---|---|
| `protocol` | **yes** | The wire protocol the provider speaks: `anthropic`, `openai`, `gemini`, `bedrock`, `responses`, or `cohere`. |
| `base_url` | **yes** | Scheme + host (+ optional path prefix). Must be `https://` for external endpoints. |
| `error_map` | no | Provider-specific **JSON** error codes → a canonical disposition: one of `auth`, `billing`, `rate_limit`, `context_length`, `overloaded`, `server_error`, `timeout`, `network`, or `client_error` (the shipped catalog mostly uses `billing`/`rate_limit`). HTTP-status errors (429/5xx/401/…) are classified automatically without this. |
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
```

See the [configuration reference](/configuration/) for every field and default.
