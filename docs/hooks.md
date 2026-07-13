# Hooks: your logic on the request path

Busbar owns the request path. Hooks are the sanctioned attachment points on it: the places where your own code sees what Busbar sees and steers what Busbar does. Every hook follows one design rule, enforced structurally rather than by convention: **a hook can steer, observe, or rewrite, but a hook can never break the request path.** A slow, crashed, or wrong hook degrades to a safe default; it never blocks, hangs, or fails a request on its own.

A hook is your own code — a compiled binary on a local Unix domain socket (~8µs per call) or an HTTPS sidecar in any language — running on Busbar's **normalized IR**: the canonical request form Busbar produces after losslessly translating whatever dialect the caller spoke. Write a hook once and it runs against all six protocols and every provider, with failover and circuit breaking underneath it, in one hop.

## Two kinds: tap and gate

Every hook is one of two kinds. That is the only structural distinction — the rest is the same contract for both.

| Kind | Mechanic | Reply |
|---|---|---|
| `tap` | fire-and-forget (watch) | none — it observes, it never answers |
| `gate` | fire-and-wait (decide) | one reply arm: nothing / reject / restrict / order / rewrite |

A **tap** watches: logging, audit, metering, shipping records to a SIEM. It can never delay or change a request. A **gate** decides: it can reject the request, restrict which pool members may serve it, re-order the failover walk, or rewrite the request body. The PII guard, the smart router, and the Headroom compressor are all gates — same wire, same timing, same fail-safe, different reply arm.

## The registry

Hooks are defined once, by name, in a top-level `hooks:` block, then attached where you want them:

```yaml
hooks:
  request-log:  { kind: tap,  socket: /run/busbar/log.sock, prompt: ro }
  pii-guard:    { kind: gate, socket: /run/busbar/pii.sock, prompt: ro, on_error: reject }
  smart-router: { kind: gate, socket: /run/busbar/router.sock }          # returns `order`
  headroom:     { kind: gate, socket: /run/busbar/headroom.sock, prompt: rw, global: true }

global_hooks: [request-log, pii-guard]     # attach to EVERY request

pools:
  my-pool:
    hooks: [cheapest, smart-router]        # this pool's base ordering + a gate
    members:
      - target: claude-opus
      - target: claude-opus-bedrock
        tags: ["baa"]
```

Each hook declares **exactly one transport** — `socket` (an absolute Unix-socket path; lazy-connect, so the hook may start after Busbar) or `webhook` (an `https://` URL, validated at boot against the SSRF blocklist: loopback sidecars allowed, RFC-1918 / link-local / CGNAT / cloud-metadata rejected).

**Attach a hook** three ways: name it in a pool's `hooks:` list, list it in `global_hooks:`, or set `global: true` on the definition (sugar for "add me to `global_hooks`"). A pool's `hooks:` list carries its ordering strategy (`weighted`/`cheapest`/`fastest`/`least_busy`/`usage`) and any number of gates.

**Gates fire concurrently.** All of a request's decision gates — the pool's own and every global — fire at once against the same candidate set, then reconcile deterministically: any **reject** wins (the lowest-`priority` gate's status/message surfaces), **restrict**s intersect, and with several **order**s the last in the priority chain wins, re-validated against the post-restrict set. Added latency is the slowest gate, not the sum.

**A tap picks its observation stage** with `at:` (default `request`):

| `at:` | Observes | Extra payload |
|---|---|---|
| `request` | the effective (post-rewrite) request | prompt/identity per grants |
| `route` | the routing decision | surviving candidate count |
| `attempt` | every dispatch attempt | `attempt_number`, `target`, `remaining_candidates`, `previous_failure` |
| `completion` | the outcome | `outcome: ok \| failed \| rejected_by_gate` + `status` — the **synthetic rejected completion**, so an audit tap sees denials, not just served traffic |

## Access grants — what a hook is trusted to see

By default a hook sees **shapes, not content**: sizes, counts, flags, live lane signals — never prompt text, never caller identity. Two per-hook grants, both default off, opt a trusted hook into more:

| Grant | Levels | Adds |
|---|---|---|
| `prompt:` | `no` (default) · `ro` · `rw` | `ro` sends the flattened system + messages text (for PII screening, guardrails, audit). `rw` additionally lets a **gate** return the `rewrite` arm. |
| `user:` | `no` (default) · `ro` | `ro` sends caller identity — the governance key's `id`/`name` and the body's end-user field. Never the secret/token, under any configuration. |

Grants are a monotonic trust ladder (`no ⊂ ro ⊂ rw`) and are **immutable after registration** — you cannot register a hook with `prompt: no`, wire it in, then quietly raise it to `rw`. `rw` on a `tap` is a boot error (a tap never replies, so it can never rewrite).

### What a gate receives

- **The request projection** — `pool`, `ingress_protocol`, `message_count`, `has_tools`, `total_chars` (a size signal; token counts do not exist pre-dispatch), `max_tokens`, `stream`. With `prompt: ro`/`rw`, also the flattened `system` + `messages` text. With `user: ro`, also caller identity.
- **The candidate projection** — one entry per healthy member: `cost_per_mtok` (operator-declared), `latency_ms` (rolling EWMA), `available_concurrency` (free slots now), `budget_remaining`, `rate_headroom` (fraction, from governance), and your `tier`/`tags` labels. The full task/latency/cost/quality picture — every signal a built-in strategy ranks on is on the wire, so an external hook can implement any of them identically.

## The gate reply arms

A gate answers with exactly one of:

- **nothing / abstain** — no opinion; Busbar proceeds as it normally would.
- **reject** (`{"reject": {"status": 451, "message": "..."}}`) — no upstream is dispatched; the caller gets a dialect-native error. Status clamped to 400–499 (default 403) so the caller's SDK catches the right typed class (429 → rate-limit, 401 → auth, …); message sanitized. Fail-closed: a malformed reject degrades to the defaults, never to silently routing the request. With `prompt: ro`, this is the PII-screen primitive — see content, say no, before it leaves your network.
- **restrict** (`{"restrict": {"tags_any": ["baa"]}}`) — only members carrying one of those `tags` may serve. The restriction **persists across failover** (every hop stays inside the surviving set); an empty intersection follows the gate's `on_empty` (default `reject`, fail-closed).
- **order** (`{"order": [idx, ...]}`) — rank the surviving candidates, most-preferred first (omitted members are demoted, not excluded). That order becomes the failover walk: Busbar tries your first choice, and on a pre-first-byte failure walks to your second. You choose the order; the breaker, concurrency caps, and failover budget still apply.
- **rewrite** (`{"rewrite": {"messages": [...], "tools": [...]}}`) — replace the request body (compression, redaction). Requires `prompt: rw`. Note the asymmetry: a hook *receives* messages as `{role, text}` (the flattened projection) but *replies* in body form (`{role, content}`); the system prompt is not rewritable; and a socket reply is capped at 64 KiB, which bounds very large rewrites. Body-only: a rewrite never changes routing, the principal, or the target dialect. It fires **before dispatch and before the routing decision**, so both the decision and every upstream see the rewritten body, and it persists across failover. Token accounting (budgets, metrics) is on the provider-reported usage of the rewritten body — the savings are real and measured. A malformed/oversized rewrite follows `on_error` (default: proceed with the body **unmodified** — a broken compressor never corrupts a request).

## Defaults and ordering

- **`default: true`** on an ordering gate makes it the base ordering that any pool which named none inherits — replacing the built-in `weighted` floor (exactly as `auth: [sso]` replaces the built-in `tokens`). At most one hook may be the default (a boot error names both otherwise); a pool that named its own base keeps its choice, and a pool's own gates layer ON TOP of whatever base it has. No default set ⇒ the zero-cost inline `weighted` backstop.
- **`priority: <n>`** is the one ordering knob: it orders the rewrite transform chain (each rewrite sees the prior's output) and tie-breaks the concurrent decision reconcile — which reject's message surfaces, and which `order` counts as "last". Ties keep globals first, then config order.

## What Busbar guarantees when a hook misbehaves

| Failure | What happens |
|---|---|
| Hook is slow | Cut off at `timeout_ms` (default 1 ms — raise it when your hook hits a DB or the network), decision coerced to `on_error` |
| Hook errors, returns garbage, or is saturated | Same: `on_error` |
| `on_error: nothing` (default) | **Does not participate**: the failing gate drops out of the decision entirely and can never displace another gate's verdict. The right posture for gates whose job is orthogonal to routing (a compressor, a logger-gate) — their failure should never reshape traffic. |
| `on_error: weighted` | Falls back to the weighted floor — a broken hook is indistinguishable from no hook. Behaviorally identical to `nothing` (in the concurrent reconcile both mean "didn't participate"); the two names exist so a config reads correctly: `weighted` for ordering gates, `nothing` for everything else. |
| `on_error: first` | Config order, deterministic |
| `on_error: reject` | Fail closed with a 503 — for security gates, where an unscreened request is worse than none. Docs mandate this for security gates. |
| `on_error: <hook-name>` | **A named fallback**: when this gate fails, that hook fires in its place (its decision is honored exactly as a primary's, projected per **its own** grants). Its own `on_error` chains further; Busbar proves at boot that every chain terminates — an unknown name, a tap, or a cycle is a startup error. `weighted`/`reject`/`first` are the reserved chain terminals; a ranking strategy name (`cheapest`, …) is also a valid, infallible fallback. |

A `tap`, being fire-and-forget, has no `on_error` to speak of: its reply is discarded, its errors swallowed, its delivery bounded and dropped-under-pressure — it can never delay, reorder, or fail a request.

## Live settings: `configure` and `describe`

Beyond the decision traffic, the wire carries two management messages, so a hook can be reconfigured without a redeploy:

- **`configure`** — Busbar pushes the hook's opaque `settings` map (from config or the admin API), stamped with a `settings_version` and Busbar's version. It is the **first message on every socket (re)connection** — a hook that crashes and reconnects always hears its current settings before any request traffic — and it is pushed live when an operator calls `PATCH /admin/v1/hooks/{name}/settings`. That PATCH is **commit-on-ack**: the hook must answer with an acknowledgment echoing the pushed `settings_version` (5s deadline) or Busbar commits nothing and the operator gets a 400 — a hook can never end up running settings Busbar doesn't know it accepted.
- **`describe`** — Busbar asks the hook to describe its own settings schema; the reply is served verbatim at `GET /admin/v1/hooks/{name}/schema`. Optional: a hook that doesn't answer simply reports `schema: null`.

Both are as fail-safe as everything else on the wire: a hook that ignores `configure` (never acks) keeps its previous settings; neither message can delay or fail request traffic.

## Managing hooks over the API

Hooks are also lifecycle-managed over the frozen admin API — register, inspect, health-check, and remove at runtime, with a tamper-evident audit trail, and (opt-in) persistence across restart. See the [Admin API guide](./admin-api.md).

---

*Hooks fire on the normalized IR, after the request is understood and before dispatch. That is what makes one hook work across every protocol and provider at once — and what makes Busbar the place your middleware runs.*
