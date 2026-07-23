# Hooks: your logic on the request path

Busbar owns the request path. Hooks are the sanctioned attachment points on it: the places where your own code sees what Busbar sees and steers what Busbar does. Every hook follows one design rule, enforced structurally rather than by convention: **a hook can steer, observe, or rewrite, but a hook can never break the request path.** A slow, crashed, or wrong hook degrades to a safe default; it never blocks, hangs, or fails a request on its own.

A hook is your own code, a compiled binary on a local Unix domain socket (~8µs per call) or an HTTPS sidecar in any language, running on Busbar's **normalized IR**: the canonical request form Busbar produces after losslessly translating whatever dialect the caller spoke. Write a hook once and it runs against all six protocols and every provider, with failover and circuit breaking underneath it, in one hop.

## Two kinds: tap and gate

Every hook is one of two kinds. That is the only structural distinction: the rest is the same contract for both.

| Kind | Mechanic | Reply |
|---|---|---|
| `tap` | fire-and-forget (watch) | none: it observes, it never answers |
| `gate` | fire-and-wait (decide) | one reply arm: nothing / reject / restrict / order / rewrite |

A **tap** watches: logging, audit, metering, shipping records to a SIEM. It can never delay or change a request. A **gate** decides: it can reject the request, restrict which pool members may serve it, re-order the failover walk, or rewrite the request body. The PII guard, the smart router, and the Headroom compressor are all gates: same wire, same timing, same fail-safe, different reply arm.

## Inline instances (no registry)

A hook instance is defined INLINE where it runs: in a pool's `hooks: [...]` list or in the
top-level `global_hooks: [...]` list (there is no separate registry block; a hook is a plugin, and
its instance is a module ref at its point of use):

```yaml
global_hooks:                              # attach to EVERY request, ordered
  - { module: socket, settings: { path: /run/busbar/log.sock }, kind: tap, prompt: ro }
  - { module: socket, settings: { path: /run/busbar/pii.sock },
      kind: gate, prompt: ro, on_error: reject }

pools:
  my-pool:
    hooks:
      - cheapest                           # this pool's base ordering strategy (a bare name)
      - { module: socket, settings: { path: /run/busbar/router.sock } }   # a gate: returns `order`
    members:
      - model: claude-opus
      - model: claude-opus-bedrock
        tags: ["baa"]
```

The `module` names the transport: the built-in `socket` (`settings.path`, an absolute Unix-socket
path; lazy-connect, so the hook may start after Busbar) or `webhook` (`settings.url`, an
`https://` URL, validated at boot against the SSRF blocklist: loopback sidecars allowed,
RFC-1918 / link-local / CGNAT / cloud-metadata rejected), or a loaded `kind: hook` plugin.

**Attach a hook** two ways: an inline ref in a pool's `hooks:` list (fires for that pool) or in
`global_hooks:` (fires on every request). A pool's `hooks:` list carries its ordering strategy
(`weighted`/`cheapest`/`fastest`/`least_busy`/`usage`, a bare name, at most one) and any number of
gates. In a pool list an unmarked ref defaults to `kind: gate`; in `global_hooks` it defaults to
`kind: tap`.

**Gates fire concurrently.** All of a request's decision gates (the pool's own and every global) fire at once against the same candidate set, then reconcile deterministically: any **reject** wins (the lowest-`priority` gate's status/message surfaces), **restrict**s intersect, and with several **order**s the last in the priority chain wins, re-validated against the post-restrict set. Added latency is the slowest gate, not the sum.

**A tap picks its observation stage** with `at:` (default `request`):

| `at:` | Observes | Extra payload |
|---|---|---|
| `request` | the effective (post-rewrite) request | prompt text per the `prompt: ro` grant |
| `route` | the routing decision | surviving candidate count |
| `attempt` | every dispatch attempt | `attempt_number`, `model` (the dispatched member), `remaining_candidates`, `previous_failure` |
| `completion` | the outcome | `outcome` + `status`, including the **synthetic rejected completion**, so an audit tap sees denials, not just served traffic |

Stage payloads ride a top-level `stage` object on the (shape-only) per-request projection, with
only the stage's own fields present:

```jsonc
{"op": "notify", "request": {...}, "candidates": [], "context": {},
 "stage": {"at": "attempt",                 // "route" | "attempt" | "completion"
           "model": "claude-opus",          // the dispatched member (attempt)
           "attempt_number": 2,             // (attempt)
           "remaining_candidates": 3,       // (route, attempt)
           "previous_failure": "...",       // (attempt ≥ 2)
           "outcome": "ok", "status": 200}} // (completion)
```

The completion `outcome` vocabulary is `ok | failed | rejected_by_gate | rejected_by_auth` and is
**append-only**: treat unknown outcomes as "not ok", never crash on one. In 1.3 the `user:` grant
projects identity on **gate decision payloads only**; tap and transform payloads omit identity
(adding it later is an append-only change; key your parser on field presence).

## Access grants: what a hook is trusted to see

By default a hook sees **shapes, not content**: sizes, counts, flags, live lane signals, never prompt text, never caller identity. Two per-hook grants, both default off, opt a trusted hook into more:

| Grant | Levels | Adds |
|---|---|---|
| `prompt:` | `no` (default) · `ro` · `rw` | `ro` sends the flattened system + messages text (for PII screening, guardrails, audit). `rw` additionally lets a **gate** return the `rewrite` arm. |
| `user:` | `no` (default) · `ro` | `ro` sends caller identity: the governance key's `id`/`name` and the body's end-user field. Never the secret/token, under any configuration. |

Grants are a monotonic trust ladder (`no ⊂ ro ⊂ rw`) and are **immutable after registration**: you cannot register a hook with `prompt: no`, wire it in, then quietly raise it to `rw`. `rw` on a `tap` is a boot error (a tap never replies, so it can never rewrite).

### What a gate receives

- **The request projection**: `pool`, `ingress_protocol`, `message_count`, `has_tools`, `total_chars` (a size signal; token counts do not exist pre-dispatch), `max_tokens`, `stream`. With `prompt: ro`/`rw`, also the flattened `system` + `messages` text. With `user: ro`, also caller identity.
- **The candidate projection**: one entry per healthy member: `cost_per_mtok` (derived from the model's `rate_card` entry), `latency_ms` (rolling EWMA), `available_concurrency` (free slots now), `budget_remaining`, `rate_headroom` (fraction: the tightest requests/tokens limit headroom across the key's group chain), and your `tier`/`tags` labels. The full task/latency/cost/quality picture, every signal a built-in strategy ranks on is on the wire, so an external hook can implement any of them identically.
- **The budget-chain state** (when the request carries a virtual key): the whole enforcement chain the request must clear, one entry per bucket from the key's own attribution bucket out through every ancestor group's budget-window buckets (`bucket_id` = `group:<name>@<window>`), each `{bucket_id, budget_group?, spend_micros_at_current_rate, remaining_micros, window_start, budget_period}`. `spend_micros_at_current_rate` is derived at hook-call time from the token ledger times the current top-level `rate_card` (micro-units, 10,000 per cent). This is the read surface for budget-aware routing: a gate can see how close the key or its team is to a cap and downshift to a cheaper `tier`. Busbar exposes the state only; the routing policy lives entirely in your hook.

## The gate reply arms

A gate answers with exactly one of:

- **nothing / abstain**: no opinion; Busbar proceeds as it normally would.
- **reject** (`{"reject": {"status": 451, "message": "..."}}`): no upstream is dispatched; the caller gets a dialect-native error. Status clamped to 400–499 (default 403) so the caller's SDK catches the right typed class (429 → rate-limit, 401 → auth, …); message sanitized. Fail-closed: a malformed reject degrades to the defaults, never to silently routing the request. With `prompt: ro`, this is the PII-screen primitive: see content, say no, before it leaves your network.
- **restrict** (`{"restrict": {"tags_any": ["baa"]}}`): only members carrying one of those `tags` may serve. The restriction **persists across failover** (every hop stays inside the surviving set); an empty intersection follows the gate's `on_empty` (default `reject`, fail-closed).
- **order** (`{"order": [idx, ...]}`): rank the surviving candidates, most-preferred first (omitted members are demoted, not excluded). That order becomes the failover walk: Busbar tries your first choice, and on a pre-first-byte failure walks to your second. You choose the order; the breaker, concurrency caps, and failover budget still apply.
- **rewrite** (`{"rewrite": {"messages": [...], "tools": [...]}}`): replace the request body (compression, redaction). Requires `prompt: rw`. Note the asymmetry: a hook *receives* messages as `{role, text}` (the flattened projection) but *replies* in body form (`{role, content}`); the system prompt is not rewritable; and a socket reply is capped at 64 KiB, which bounds very large rewrites. Body-only: a rewrite never changes routing, the principal, or the target dialect. It fires **before dispatch and before the routing decision**, so both the decision and every upstream see the rewritten body, and it persists across failover. Token accounting (budgets, metrics) is on the provider-reported usage of the rewritten body: the savings are real and measured. A malformed/oversized rewrite follows `on_error` (default: proceed with the body **unmodified**; a broken compressor never corrupts a request).

## Ordering

- **`priority: <n>`** is the one ordering knob: it orders the rewrite transform chain (each rewrite sees the prior's output) and tie-breaks the concurrent decision reconcile: which reject's message surfaces, and which `order` counts as "last". Ties keep globals first, then config order.
- A pool that names no strategy gets the zero-cost inline `weighted` backstop. (The 1.4.x `default: true` registry flag is gone with the registry: name the base strategy per pool.)

## What Busbar guarantees when a hook misbehaves

| Failure | What happens |
|---|---|
| Hook is slow | Cut off at `timeout_ms` (default 1 ms; raise it when your hook hits a DB or the network), decision coerced to `on_error` |
| Hook errors, returns garbage, or is saturated | Same: `on_error` |
| `on_error: nothing` (default) | **Does not participate**: the failing gate drops out of the decision entirely and can never displace another gate's verdict. The right posture for gates whose job is orthogonal to routing (a compressor, a logger-gate): their failure should never reshape traffic. |
| `on_error: weighted` | Falls back to the weighted floor: a broken hook is indistinguishable from no hook. Behaviorally identical to `nothing` (in the concurrent reconcile both mean "didn't participate"); the two names exist so a config reads correctly: `weighted` for ordering gates, `nothing` for everything else. |
| `on_error: first` | Config order, deterministic |
| `on_error: reject` | Fail closed with a 503, for security gates, where an unscreened request is worse than none. Docs mandate this for security gates. |
| `on_error: { hook: <name> }` | **A named fallback** (structured ref): when this gate fails, that hook fires in its place (its decision is honored exactly as a primary's, projected per **its own** grants). Its own `on_error` chains further; Busbar proves at boot that every chain terminates: an unknown name, a tap, or a cycle is a startup error. `weighted`/`reject`/`first` are the reserved chain terminals; a ranking strategy name (`cheapest`, …) is also a valid, infallible fallback. |

A `tap`, being fire-and-forget, has no `on_error` to speak of: its reply is discarded, its errors swallowed, its delivery bounded and dropped-under-pressure. It can never delay, reorder, or fail a request.

## The wire, precisely

One JSON message per line on a socket; one POST body per message on a webhook. The projection is
**byte-identical across both transports**, so a hook graduates webhook → socket without logic
changes. The rules a hook author must know:

- **Message discrimination.** A message with a top-level `configure`, `describe`, or `status` key
  is a **management** message. Everything else is a **per-request** message and its `op` field says
  which kind: `decide` (a gate's blocking decision, answer it), `transform` (a rewrite pass,
  answer it), `notify` (a tap observation, **never answer it**; on a socket, Busbar does not read
  a reply and an answered notify queues bytes forever).
- **Evolvability.** The wire is **append-only**: Busbar may add fields and message kinds at any
  time. A hook MUST ignore unknown fields, MUST treat unknown `op` values and unknown management
  keys as "not for me" (reply `{}` on a socket; `200 {}` on a webhook), and may attach extra fields
  to its own replies (Busbar ignores unknowns symmetrically).
- **Optional fields are absent, not `null`.** Key your parser on field **presence** (e.g.
  `"tier" in candidate`), never on null-ness, and never on key order.
- **Abstain is an explicit reply.** `{}` (or `{"abstain": true}`) is the abstain. An **empty body,
  a non-2xx webhook status, a closed socket, or a missing newline is a transport ERROR**, not an
  abstain. It routes to the gate's `on_error`. Under the default `on_error: nothing` the two look
  identical; under `on_error: reject` an "abstain via 204" fails every request. A webhook's reject
  must ride a **200** response body; a 4xx/5xx status is the hook *erroring*, not rejecting.
- **Transform precedence.** A `transform` reply is read as **reject > rewrite > abstain**: a
  rewrite gate that also screens (a compressor with a PII check) returns `{"reject": ...}` and the
  request stops, exactly as on the decide path. `restrict`/`order` are decide-path verbs and are
  ignored on a transform reply.

## Management messages: `configure`, `describe`, `status`

- **`configure`**: Busbar pushes the hook's opaque `settings` map, stamped with the hook's
  **instance name**, a `settings_version`, and Busbar's version. It is the **first message on every
  socket connection, always**, including a hook with no settings (an empty `settings: {}` is valid
  desired-state), so a (re)started hook always hears its identity, current settings, and Busbar's
  version before any traffic. It is also pushed live by
  `PATCH /api/v1/admin/hooks/{name}/settings`. **One ack rule for both deliveries**: reply
  `{"ack": {"settings_version": <the exact version sent>}}` (5s deadline). On the PATCH, no exact
  ack = nothing commits (the operator gets a 400); on the connection preamble, no exact ack =
  the connection is not used.
- **`describe`** (`{"describe": true}`): reply with your self-description ENVELOPE:
  `{"schema": <settings JSON Schema>, "dashboard"?: {"widgets": [...]}}`. Busbar extracts `schema`
  and serves it at `GET /api/v1/admin/hooks/{name}/schema`; `dashboard` is your DECLARED widget
  layout (`{"metric", "label", "viz", "unit"?, "max"?}` per widget; values come from
  `status.metrics`), so one declaration drives both the config form and the plugin dashboard.
  Both members optional; don't answer (or `{}`) and the API reports `schema: null`.
- **`status`** (`{"status": true}`): the control-plane read: reply your **observed** state,
  `{"status": {"settings_version": N, "settings": {...}, "metrics": [ ... ]}}`, and Busbar surfaces
  it at `GET /api/v1/admin/hooks/{name}/status` with a desired-vs-reported **drift** verdict. The
  `metrics` ARRAY is how your hook feeds its own operational data to the control plane (a Headroom
  compressor reports `chars_saved_total`; a dashboard built on Busbar sees what each plug is doing)
  instead of running its own dashboard. Each entry is Prometheus/OpenMetrics-shaped:
  ```jsonc
  {"name": "chars_saved_total",       // ^[a-z][a-z0-9_]{0,63}$ ; counters SHOULD end _total
   "type": "counter"|"gauge"|"histogram",
   "value": 812000,                   // counter/gauge scalar; a histogram's is its sample count
   "labels":    {"pool": "chat"},     // Prometheus DIMENSIONS: several entries may share a name
   "quantiles": {"0.5": 12, "0.95": 34, "0.99": 51},   // a histogram's distribution (p50/p95/p99)
   "estimated": true, "ci_low": 27.7, "ci_high": 35.7, // mark + bound an ESTIMATE vs a measured fact
   "label": "Characters saved", "unit": "%", "viz": "counter"|"gauge"|"sparkline"|"histogram",
   "max": 100, "help": "..."}
  ```
  Beyond `name`+`type` everything is optional; the simplest hook sends `{name, type, value}`.
  **`labels` is how you break a metric down by dimension** (per-pool, per-model, per-strategy): a
  hook that runs on several pools reports one entry per pool (it receives `request.pool` on every
  message), so `GET /hooks/{name}/status` returns the whole picture and a dashboard drills down by
  label. A hook is ONE process no matter how many pools reference it, so this labeled self-report,
  not a per-pool endpoint, is how per-pool numbers surface. `histogram`+`quantiles` carries a
  latency distribution a mean would hide; `estimated`/`ci_*` marks a value your hook derived from a
  control group. Names/label keys are charset-enforced, every string sanitized + length-bounded,
  every number finite (a `prompt: ro` hook cannot smuggle content into a scrape). Busbar BOUNDS
  everything (64 entries/reply, 8 labels/entry); a malformed entry is dropped whole, a malformed
  optional member individually, never the reply. Time series are the CONSUMER's job in 1.3 (a
  dashboard samples `status` and accumulates); an engine-retained `series` member is the reserved
  additive path. Optional: reply `{}` and Busbar treats status as unsupported.
- **Reserved:** the reply field name **`report`** is reserved on per-request replies for per-request
  hook data (attached to the completion-stage tap payload in a future release); do not use it for
  anything else.

Fail-safety, precisely (don't over-generalize): `describe` and `status` are fully optional: a
hook that ignores them keeps working. **The socket `configure` preamble is NOT optional**: a
socket hook that never acks it has every connection rejected (each delivery then lands on the
gate's `on_error`), because a hook running settings it never acknowledged is running blind. The
exact-echo ack RULE is one; the DEADLINE is the delivery's own budget: the admin PATCH/management
calls allow 5s, but a request-path (re)connect acks within the gate's `timeout_ms` (default 1 ms;
ack `configure` immediately and apply settings asynchronously if application is slow). Webhooks
have no connection preamble (each PATCH push is its own POST). None of the management messages can
delay or fail request traffic: they ride fresh connections, never the request-path connection.

On a connection where you only ever receive `notify` (a tap), **never write anything**. Busbar
does not read tap replies, so even the polite `{}`-for-unknown-ops rule is scoped to
reply-expected connections; Busbar will never send a reply-expected op on a tap connection.

## Managing hooks over the API

Hooks are also lifecycle-managed over the frozen admin API: register, inspect, health-check, and remove at runtime, with a tamper-evident audit trail, and (opt-in) persistence across restart. See the [Admin API guide](./admin-api.md).

---

*Hooks fire on the normalized IR, after the request is understood and before dispatch. That is what makes one hook work across every protocol and provider at once, and what makes Busbar the place your middleware runs.*
