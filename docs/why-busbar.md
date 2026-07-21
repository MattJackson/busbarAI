# Why Busbar

Busbar is the **reliability layer for your AI traffic**: the breaker-and-failover control plane that sits between your application and every provider it calls. This page is for the person deciding whether to adopt it: the specific problems it solves, what it *enables* that you would otherwise have to build yourself, and an honest comparison with the tools you are probably weighing it against.

It shares an arena with multi-provider proxies and hosted routers, but the priorities are different. Where those forward requests and list models, Busbar is built reliability-first. It knows whose fault a failure is. It fails over inside the request, before your user sees a byte. And it translates losslessly across six wire protocols, so you never trade away a provider's native features to get portability.

---

## The problems Busbar solves

### One provider's bad day becomes your outage

If your application calls a single provider directly, any upstream incident (rate limits, degraded capacity, a regional outage) surfaces immediately to your users. The usual fix is defensive `try/except` blocks scattered across the codebase. Those blocks are not failover; they are error handling. They do not retry on a different provider, they do not skip a circuit that is already open, and they do not restore service while the original provider recovers.

Busbar provides genuine in-flight failover. Requests that have not yet received a first byte from the upstream are automatically retried against the next available lane in the pool. A configurable per-request deadline and hop cap (defaults: 120 seconds, 3 hops) bound worst-case latency. The breaker for the failed lane opens independently of every other lane, so a rate-limit storm on one provider does not suppress traffic to healthy ones.

### Vendor lock-in is in the SDK call, not the contract

Every provider ships an SDK that speaks its own wire format. Migrating from Anthropic to OpenAI, or adding a second provider as a fallback, means updating call sites across your codebase. In practice, teams don't do this until they have to, and by then the migration is a project.

Busbar presents a single endpoint to your application. You configure which provider or pool of providers lives behind it. Swapping or adding a provider is a config change, not a code change. Because Busbar translates losslessly between all six supported wire protocols (Anthropic, OpenAI, OpenAI Responses, Gemini, Amazon Bedrock, Cohere), your application does not need to know or care which model answered the request.

### Cost control requires a control plane

Direct API usage gives you a bill at the end of the month. It does not give you per-team or per-application budget caps, rate limits enforced in real time, or auditability of which workload consumed what. Without a control plane, cost control means trusting every developer and every deployment to self-police.

Busbar's governance layer issues virtual keys, scoped bearer tokens with configurable per-request and per-1k-token pricing, daily/monthly/total budget caps, RPM and TPM limits, and pool-level access controls. A virtual key for a staging environment can be capped at a daily budget and restricted to a cheaper model pool. An internal tool can be rate-limited independently of the production path. Usage is tracked per key and queryable via the admin API.

One operational caveat worth stating plainly. RPM limits are enforced precisely (the counter is incremented synchronously on admission). Budget caps are too: the over-budget check and the spend charge are a single atomic SQLite UPSERT (`charge_within_budget`), so concurrent in-flight requests cannot overshoot the cap. TPM limits remain best-effort under concurrency, since token usage is only known after the response. On a governance store error Busbar fails open by default (`budget_on_store_error: allow`) to preserve availability; set `deny` for a hard guarantee that rejects on any store error.

### Your data path is also your security perimeter

When your application calls a provider directly, your traffic and your API keys are visible to any process or infrastructure component in that path. More practically: every provider SDK in your codebase is a secret-handling surface. Rotating a key means finding and updating every deployment that holds it.

Busbar holds provider keys in one place: the process that reads the config file at startup. Your application carries only a Busbar virtual key (or a client token). Rotating an upstream provider key is a Busbar restart, not a deployment sweep. The request path itself is security-hardened: SSRF guards on all configured URLs, constant-time token comparison that closes list-position timing oracles, and native-protocol error envelopes that reveal no Busbar internals to callers.

### "We only have one provider" is not a reason to wait

Busbar is valuable before the second provider exists. Run it as a straight same-protocol passthrough in front of your one provider, no features enabled, and your posture improves the same day: the provider key moves out of every app deployment and into one process, so a leaked app credential is no longer a leaked provider account, and rotating the key is a restart, not a deployment sweep. `max_concurrent` caps a runaway loop at your ceiling instead of your bill. Every request becomes visible in `/metrics` and `/stats` where direct SDK calls are invisible. The request path is hardened whether you asked for it or not: SSRF-guarded upstreams, constant-time token checks, body caps, secrets never logged. And the cost of the extra hop is tens of microseconds, measurable per-request on your own traffic via the opt-in `Server-Timing` header.

Then the constraint moves. A team whose compliance posture locks them to one provider today (a BAA that covers AWS Bedrock but not yet Anthropic, say) points their existing SDK at Busbar and changes nothing else. The day the second provider becomes possible (a better price, a better model, a signed BAA, a bad outage), it's a new lane in `config.yaml`. The application code never changes and never learns which backend answered. Without the control plane already in place, that same day starts with rewriting every AI call site you own. The endpoint swap is a one-line change; the option it buys is the point.

---

## How Busbar compares

The detailed comparisons live on their own pages, with every claim about the other tools cited to their own documentation and re-checked against it: **[Busbar vs LiteLLM](https://getbusbar.com/vs/litellm/)** and **[Busbar vs OpenRouter](https://getbusbar.com/vs/openrouter/)**.

The short version. LiteLLM is a Python-native router with a big preconfigured catalog; if you want an in-process Python library, it's the right call. Busbar is a different kind of tool: no privileged protocol (all six first-class, in both directions), a fault-attributed circuit breaker rather than a cooldown timer, and a gateway whose own cost is measured in microseconds and megabytes. OpenRouter is a hosted service, and the deciding question is whether prompts passing through a third party is acceptable for your application: if it is, OpenRouter is excellent; if it isn't, Busbar runs in your infrastructure and nothing enters the data path but the providers you configure.

---

## The operational story

Busbar ships as a single static binary. Deployment is:

1. Write a `config.yaml` (providers + models, optionally pools and governance).
2. Set the environment variables your config references (one per provider key).
3. Run the binary.

There is no Python environment to manage, no Node runtime, no database to provision (governance uses an embedded SQLite file if you enable it), and no sidecar required. Health, metrics, and management traffic all pass through the same process on the same port.

**Observability is built in.** Prometheus metrics are exposed at `/metrics` with bounded cardinality: metric labels use configured pool names and fixed enumerations, never raw model strings from client requests. OTLP trace export and a request-log webhook are both optional and configurable. The `/healthz` endpoint is side-effect-free (it never steals a recovery probe) and safe for high-frequency load balancer probing. Note that `/metrics` and `/stats` are not auth-exempt, they go through the same auth check as request traffic, since telemetry is itself a fingerprinting surface.

**Security defaults are strict.** Provider `base_url` values are guarded against cloud-metadata/IMDS endpoints (including alternate IP encodings). Loopback, RFC-1918, and CGNAT addresses are permitted for local-model upstreams (e.g. Ollama/vLLM); plain `http://` is only allowed for those private/loopback hosts: public hosts must use `https://`. Observability sink URLs (OTLP endpoint, request-log webhook) apply a stricter guard that additionally blocks loopback, link-local, RFC-1918, and broadcast addresses. Auth failures return native-protocol error envelopes with no Busbar vocabulary, an Anthropic SDK sees an Anthropic 401, an OpenAI SDK sees `invalid_api_key`, a Gemini SDK sees a 400 `INVALID_ARGUMENT`, and a Bedrock SDK sees a 403 `AccessDeniedException`. Admin endpoints are separately guarded by an admin token and disabled entirely if none is configured.

**The request body cap is 32 MiB** (`DefaultBodyLimit`), enforced before handler code runs, with protocol-native 413 responses (not bare text).

One auth note for Bedrock: Busbar signs outbound Bedrock requests with AWS SigV4 AND verifies inbound SigV4 (when governance is enabled). Under governance, a Bedrock-SDK client authenticates with a minted `aws_access_key_id` + `aws_secret_access_key` pair: Busbar verifies the signature and enforces budgets / rate limits exactly like a bearer-token client. Without governance, Bedrock ingress requires `auth.chain: []`, with `upstream_credentials: passthrough` to forward the credentials upstream, or plain `chain: []` to ignore them.

---

## Who Busbar is for

**Busbar is a good fit if:**

- You run your own infrastructure and want to own the full request path to AI providers.
- You use more than one provider and want failover, load distribution, or the ability to swap providers without code changes.
- You need per-team or per-application cost control enforced at the control plane, before the request runs.
- Your existing applications use different provider SDKs (OpenAI, Anthropic, Gemini, Bedrock, Cohere) and you want to standardize the routing layer without rewriting call sites.
- You have data residency, compliance, or internal security requirements that exclude third-party traffic routing.

**Busbar is not the right fit if:**

- You need a provider that speaks a wire protocol Busbar doesn't support, one that's neither one of the six protocols nor OpenAI-compatible. That single case needs new translator code (contribute it, or wait for it). Note what this is *not*: adding any **other** provider isn't a code change and doesn't wait on anyone. A provider is just an entry in **your own** `providers.yaml`: its protocol, `base_url`, the env var holding its key, and its error-code mappings. `providers.yaml` is your config file, not something the Busbar project hosts or gatekeeps; the verified catalog ships as a starting convenience you own and extend, not a list you're limited to.
- You are prototyping and want zero infrastructure overhead, use a hosted service.
- You specifically want an **in-process Python router library** (imported into your code) rather than a network service, that's LiteLLM's design, and the more natural fit. To be clear, "I do ML" is *not* a reason to skip Busbar: LangChain, LlamaIndex, and the rest already work with it today, point their OpenAI/Anthropic client at Busbar's base URL and you keep your whole framework stack, you just get failover and translation underneath it.
- You want a hosted managed service with no operational responsibility.

---

## Current status

Busbar is licensed **Apache-2.0**. The wire protocol translation, circuit breaker model, governance layer, and admin API are stable under Semantic Versioning. The test suite covers over 1,600 test cases across the protocol translators, breaker FSM, auth middleware, governance enforcement, and config validation.

Apache-2.0 is permissive: use it commercially, modify it privately, redistribute it, with an explicit patent grant and no copyleft obligations.
