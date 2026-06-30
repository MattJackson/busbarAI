# Why Busbar

Busbar is the **reliability layer for your LLM traffic** — the breaker-and-failover control plane that sits between your application and every provider it calls. This page is for the person deciding whether to adopt it: the specific problems it solves, what it *enables* that you would otherwise have to build yourself, and an honest comparison with the tools you are probably weighing it against.

It is the same arena as a multi-provider proxy or a hosted router, but a different class of product. Where those forward requests and list models, Busbar is built reliability-first: it knows *whose fault* a failure is, fails over *inside the request* before your user sees a byte, and translates *losslessly* across six wire protocols — so you never trade away a provider's native features to get portability. You are already paying for every LLM lock-in decision you've made, even if the bill hasn't arrived yet; this is the layer that buys it back.

---

## The problems Busbar solves

### One provider's bad day becomes your outage

If your application calls a single provider directly, any upstream incident — rate limits, degraded capacity, a regional outage — surfaces immediately to your users. The usual fix is defensive `try/except` blocks scattered across the codebase. Those blocks are not failover; they are error handling. They do not retry on a different provider, they do not skip a circuit that is already open, and they do not restore service while the original provider recovers.

Busbar provides genuine in-flight failover. Requests that have not yet received a first byte from the upstream are automatically retried against the next available lane in the pool. A configurable per-request deadline and hop cap (defaults: 120 seconds, 3 hops) bound worst-case latency. The breaker for the failed lane opens independently of every other lane, so a rate-limit storm on one provider does not suppress traffic to healthy ones.

### Vendor lock-in is in the SDK call, not the contract

Every provider ships an SDK that speaks its own wire format. Migrating from Anthropic to OpenAI, or adding a second provider as a fallback, means updating call sites across your codebase. In practice, teams don't do this until they have to, and by then the migration is a project.

Busbar presents a single endpoint to your application. You configure which provider or pool of providers lives behind it. Swapping or adding a provider is a config change, not a code change. Because Busbar translates losslessly between all six supported wire protocols — Anthropic, OpenAI, OpenAI Responses, Gemini, Amazon Bedrock, Cohere — your application does not need to know or care which model answered the request.

### Cost control requires a control plane

Direct API usage gives you a bill at the end of the month. It does not give you per-team or per-application budget caps, rate limits enforced in real time, or auditability of which workload consumed what. Without a control plane, cost control means trusting every developer and every deployment to self-police.

Busbar's governance layer issues virtual keys — scoped bearer tokens with configurable per-request and per-1k-token pricing, daily/monthly/total budget caps, RPM and TPM limits, and pool-level access controls. A virtual key for a staging environment can be capped at a daily budget and restricted to a cheaper model pool. An internal tool can be rate-limited independently of the production path. Usage is tracked per key and queryable via the admin API.

One operational caveat worth stating plainly: RPM limits are enforced precisely (the counter is incremented synchronously on admission), and so are budget caps — the over-budget check and the spend charge are a single atomic SQLite UPSERT (`charge_within_budget`), so concurrent in-flight requests cannot overshoot the cap. TPM limits remain best-effort under concurrency, since token usage is only known after the response. On a governance store error Busbar fails open by default (`budget_on_store_error: allow`) to preserve availability; set `deny` for a hard guarantee that rejects on any store error.

### Your data path is also your security perimeter

When your application calls a provider directly, your traffic and your API keys are visible to any process or infrastructure component in that path. More practically: every provider SDK in your codebase is a secret-handling surface. Rotating a key means finding and updating every deployment that holds it.

Busbar holds provider keys in one place — the process that reads the config file at startup. Your application carries only a Busbar virtual key (or a client token). Rotating an upstream provider key is a Busbar restart, not a deployment sweep. The request path itself is security-hardened: SSRF guards on all configured URLs, constant-time token comparison that closes list-position timing oracles, and native-protocol error envelopes that reveal no Busbar internals to callers.

---

## Honest comparison: Busbar vs LiteLLM vs OpenRouter

These are not the same tool. The right choice depends on what you are actually optimizing for.

### LiteLLM

LiteLLM is a Python library and optional proxy that normalizes many providers to an OpenAI-shaped interface. It is widely used, well-documented, and has a large ecosystem.

**Where LiteLLM fits:** teams that are already Python-native, want a broad provider surface immediately (LiteLLM covers more providers than Busbar's current catalog), and need integration with Python ML tooling.

**Where Busbar pulls ahead:**

- **Native cross-protocol translation, not OpenAI normalization.** LiteLLM maps everything to the OpenAI schema and back. Busbar instead translates through a superset intermediate representation that every protocol reader maps into and every writer maps out of, with deliberate fidelity choices: `temperature` is stored as `f64` (not `f32`) to avoid round-trip precision loss, and source-protocol `extra` fields (such as OpenAI's `logprobs` or `n`) are cleared before forwarding rather than leaked to a foreign backend. You can point a Bedrock SDK at Busbar and have it route to an Anthropic backend, or vice versa, with translation in both directions — including streaming, where Busbar re-frames events into each client's native format (SSE for OpenAI/Anthropic/Gemini/Cohere/Responses, binary `application/vnd.amazon.eventstream` for Bedrock).
- **No Python runtime in your request path.** LiteLLM's proxy is a Python process. It carries the startup time, memory footprint, and GIL constraints of a Python async server. Busbar is a single static Rust binary with no runtime dependencies. You deploy a file.
- **Per-(pool, lane) circuit breakers, not per-request retries.** Busbar's circuit breaker tracks error rate or consecutive failures per lane per pool over a sliding window, trips independently per (pool, lane) combination, enforces exponential backoff with decorrelated jitter, and applies a hard-down disposition for auth/billing failures that persists (30-minute sticky cooldown) until a recovery probe succeeds. A lane that is rate-limiting in pool A can still serve traffic in pool B if it is healthy there. Client (4xx) errors are relayed verbatim and never penalize the lane.
- **Ingress-side protocol flexibility.** Your existing Anthropic SDK, OpenAI SDK, Gemini SDK, Cohere SDK, or Bedrock SDK can point at Busbar with a one-line base URL change. LiteLLM's proxy accepts OpenAI-format requests; other protocol SDKs require adaptation.

**Where LiteLLM still leads:**

- **Out-of-the-box support for a provider on an exotic wire format.** Any provider that speaks one of the six protocols — OpenAI, Anthropic, Gemini, Bedrock, Cohere, Responses — is a few lines of YAML you add yourself ([Adding a provider](/providers/)), and Busbar hand-verifies the ones it ships because their error-code mappings drive the breaker's fault attribution. So "not in the catalog" almost never means "can't use it." The genuine gap is a provider whose wire format is *none* of the six and compatible with none — that needs a new protocol reader.
- **Deep Python ecosystem integration** (LangChain, LlamaIndex, etc.) — though since Busbar speaks those SDKs' native protocols, you reach it through them anyway, just at the HTTP layer rather than as a Python import.
- **A bundled admin dashboard** — LiteLLM ships a hosted UI; Busbar doesn't. Observability instead runs through open standards — Prometheus `/metrics`, OTLP traces, and the admin API — so you point the dashboards you already run (Grafana and the like) at Busbar rather than a proprietary one.

### OpenRouter

OpenRouter is a hosted service. You send requests to `openrouter.ai`; they route to providers and bill you. You do not run anything.

**Where OpenRouter fits:** prototyping, teams with no infrastructure budget, or use cases where third-party data routing is acceptable.

**Where Busbar pulls ahead:**

- **Your data stays in your infrastructure.** Every request through OpenRouter transits OpenRouter's servers. For applications with data residency requirements, PII handling obligations, or internal policies around third-party data access, this is a hard constraint. Busbar runs in your infrastructure. The only external traffic is the upstream provider calls you configure.
- **No per-request markup.** OpenRouter charges a markup above provider list price. Busbar's only cost is the compute to run it; its single-binary footprint is negligible against LLM API costs.
- **Configurable reliability semantics.** OpenRouter's failover behavior is opaque and fixed. Busbar's pool configuration, breaker parameters, failover deadlines, and exhaustion behavior (reject with 503, fall back to another pool, or send to the least-bad lane) are all explicit, observable, and operator-controlled.
- **Virtual key governance.** OpenRouter has no mechanism for issuing scoped sub-keys to internal teams with independent budget caps and rate limits.

**Where OpenRouter still leads:**

- **Zero operational burden** — you send HTTP, they run everything. Real, but the gap is thin: Busbar's "operations" is a single static binary with no runtime, no dependencies, and no database to provision — `./busbar` plus a config file. There's *something* to run; there just isn't much to it.
- **A model marketplace with automatic provider picking** — a hosted catalog to browse and price-compare models, plus routing that chooses a provider for you based on community usage data. With Busbar, you pick the providers and pools yourself, in config.
- **One key for models you'd otherwise need separate accounts for** — OpenRouter aggregates many hosts, so you can reach a niche or open-source model through a single OpenRouter key instead of signing up with each provider. With Busbar you bring your own provider accounts, so you can reach anything those providers offer — but you do need the account or endpoint for each.

---

## The operational story

Busbar ships as a single static binary. Deployment is:

1. Write a `config.yaml` (providers + models, optionally pools and governance).
2. Set the environment variables your config references (one per provider key).
3. Run the binary.

There is no Python environment to manage, no Node runtime, no database to provision (governance uses an embedded SQLite file if you enable it), and no sidecar required. Health, metrics, and management traffic all pass through the same process on the same port.

**Observability is built in.** Prometheus metrics are exposed at `/metrics` with bounded cardinality — metric labels use configured pool names and fixed enumerations, never raw model strings from client requests. OTLP trace export and a request-log webhook are both optional and configurable. The `/healthz` endpoint is side-effect-free (it never steals a recovery probe) and safe for high-frequency load balancer probing. Note that `/metrics` and `/stats` are not auth-exempt — they go through the same auth check as request traffic, since telemetry is itself a fingerprinting surface.

**Security defaults are strict.** Provider `base_url` values are guarded against cloud-metadata/IMDS endpoints (including alternate IP encodings). Loopback, RFC-1918, and CGNAT addresses are permitted for local-model upstreams (e.g. Ollama/vLLM); plain `http://` is only allowed for those private/loopback hosts — public hosts must use `https://`. Observability sink URLs (OTLP endpoint, request-log webhook) apply a stricter guard that additionally blocks loopback, link-local, RFC-1918, and broadcast addresses. Auth failures return native-protocol error envelopes with no Busbar vocabulary — an Anthropic SDK sees an Anthropic 401, an OpenAI SDK sees `invalid_api_key`, a Gemini SDK sees a 400 `INVALID_ARGUMENT`, and a Bedrock SDK sees a 403 `AccessDeniedException`. Admin endpoints are separately guarded by an admin token and disabled entirely if none is configured.

**The request body cap is 32 MiB** (`DefaultBodyLimit`), enforced before handler code runs, with protocol-native 413 responses (not bare text).

One auth note for Bedrock: Busbar signs outbound Bedrock requests with AWS SigV4 AND verifies inbound SigV4 (when governance is enabled). Under governance, a Bedrock-SDK client authenticates with a minted `aws_access_key_id` + `aws_secret_access_key` pair — Busbar verifies the signature and enforces budgets / rate limits exactly like a bearer-token client. Without governance, Bedrock ingress requires `auth.mode: passthrough` (credentials forwarded upstream) or `none`.

---

## Who Busbar is for

**Busbar is a good fit if:**

- You run your own infrastructure and want to own the full request path to LLM providers.
- You use more than one provider and want failover, load distribution, or the ability to swap providers without code changes.
- You need per-team or per-application cost control enforced at the gateway layer.
- Your existing applications use different provider SDKs (OpenAI, Anthropic, Gemini, Bedrock, Cohere) and you want to standardize the routing layer without rewriting call sites.
- You have data residency, compliance, or internal security requirements that exclude third-party traffic routing.

**Busbar is not the right fit if:**

- You need a provider that speaks a wire protocol Busbar doesn't support — one that's neither one of the six protocols nor OpenAI-compatible. That single case needs new translator code (contribute it, or wait for it). Note what this is *not*: adding any **other** provider isn't a code change and doesn't wait on anyone. A provider is just an entry in **your own** `providers.yaml` — its protocol, `base_url`, the env var holding its key, and its error-code mappings. `providers.yaml` is your config file, not something the Busbar project hosts or gatekeeps; the vetted catalog ships as a starting convenience you own and extend, not a list you're limited to.
- You are prototyping and want zero infrastructure overhead — use a hosted service.
- You specifically want an **in-process Python router library** (imported into your code) rather than a network service — that's LiteLLM's design, and the more natural fit. To be clear, "I do ML" is *not* a reason to skip Busbar: LangChain, LlamaIndex, and the rest already work with it today — point their OpenAI/Anthropic client at Busbar's base URL and you keep your whole framework stack, you just get failover and translation underneath it.
- You want a hosted managed service with no operational responsibility.

---

## Current status

Busbar is at **1.0.1**, licensed AGPL-3.0-or-later. The wire protocol translation, circuit breaker model, governance layer, and admin API are stable under Semantic Versioning. The test suite covers over 1,600 test cases across the protocol translators, breaker FSM, auth middleware, governance enforcement, and config validation.

The AGPL license means that if you modify Busbar and run it as a networked service, you must make the modified source available. Read the LICENSE file before deploying in a commercial context.
