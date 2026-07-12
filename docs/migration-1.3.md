# Migrating from 1.2.x to 1.3

1.3 reshapes how routing and hooks are configured. The change is a **clean cut**: old-form keys are
not silently accepted — Busbar reports a clear startup error naming exactly what to write instead, so
you can migrate with confidence and never run a half-understood config. This guide covers every
config change. Most deployments touch only one or two lines.

The mental model: **the engine runs hooks.** A pool names the hooks it wants — an ordering strategy
and/or gates — in one `hooks: [...]` list. Hooks are defined once under a top-level `hooks:`
registry and referenced by name — on a pool, or globally.

---

## 1. Native routing strategy: `route:` → `hooks: [<strategy>]`

The pool's built-in ranking strategy moved from `route:` into the pool's `hooks:` list. The values
are unchanged (`weighted` — the default — `cheapest`, `fastest`, `least_busy`, `usage`).

```yaml
# 1.2.x
pools:
  my-pool:
    route: cheapest
    members: [...]

# 1.3
pools:
  my-pool:
    hooks: [cheapest]
    members: [...]
```

`route: weighted` (or an absent `route:`) needs no change beyond deleting the key — weighted is
still the zero-cost default when a pool names no strategy. Boot error if you leave `route: cheapest`:
`the `route:` pool key was removed in 1.3; a pool names its ordering strategy in its `hooks:` list —
write `hooks: [<name>]``.

---

## 2. Routing hooks: `route: socket|webhook` + `policy:` block → `hooks:` registry + pool list

A hook (webhook sidecar or Unix-socket binary) is now **defined once** in a top-level `hooks:`
registry and **referenced by name** from a pool's `hooks: [...]` list. The inline `policy:` block is
gone.

```yaml
# 1.2.x — transport named in route:, config inline
pools:
  my-pool:
    route: socket
    policy:
      socket: /run/busbar/router.sock
      timeout_ms: 5
      on_error: weighted
    members: [...]

# 1.3 — define the hook once, name it in the pool's list
hooks:
  my-router:
    kind: gate
    socket: /run/busbar/router.sock
    timeout_ms: 5
    on_error: weighted

pools:
  my-pool:
    hooks: [my-router]
    members: [...]
```

The webhook transport is the same, moved into the registry entry as `webhook: https://…` (exactly one
of `socket` or `webhook` per hook). A name in a pool's `hooks:` list that isn't an ordering strategy
must reference a `kind: gate` registry entry. Boot errors name the fix.

One list carries both jobs, and a pool may name **several gates** — they fire concurrently and
reconcile (any reject wins; restricts intersect; the last order wins):

```yaml
pools:
  my-pool:
    hooks: [cheapest, pii-guard, compliance-gate]   # base ordering + two gates
    members: [...]
```

Note `kind:` — a hook is a `gate` (fire-and-wait: it can rank, reject, restrict, or rewrite) or a
`tap` (fire-and-forget observation). Only a gate may appear in a pool's `hooks:` list.

> **Transitional 1.3 pre-releases** briefly accepted `policy: <strategy>` and `hook: <name>` pool
> keys. Both are retired; each fails at boot with a message naming the `hooks: [...]` fix.

---

## 3. Payload opt-ins: `policy.send_prompt` / `send_user` → hook `prompt:` / `user:` grants

The two payload opt-ins became explicit, monotonic access grants on the hook definition:

```yaml
# 1.2.x
    policy:
      socket: /run/busbar/pii.sock
      send_prompt: true
      send_user: true

# 1.3
hooks:
  pii-guard:
    kind: gate
    socket: /run/busbar/pii.sock
    prompt: ro        # no (default) | ro (read prompt) | rw (read + may rewrite the body)
    user:   ro        # no (default) | ro (read caller identity)
```

`prompt: ro` sends the prompt read-only (screening, guardrails, audit); `prompt: rw` additionally
lets the hook return a `rewrite` (compression/redaction). `prompt: rw` on a `tap` is a config error.
Grants are immutable after registration and enforced both directions — a hook is never sent, and can
never return, a field it wasn't granted.

---

## 4. `route: script` (embedded Rhai) — removed

The embedded Rhai scripting transport, deprecated in 1.2.1, is gone. Scriptable routing is now an
out-of-process socket hook — the same ranked-order wire contract, ~100× faster (a compiled binary vs
an interpreter). Move your logic into a small socket hook binary and register it as in §2. Boot
error: `route: script (the embedded Rhai transport) was removed in 1.3. Define an out-of-process gate
under top-level `hooks:` (kind: gate, socket:) and name it in the pool's `hooks: [...]` list`.

---

## 5. Auth: `auth.mode` → `auth.chain` + `upstream_credentials`

Authentication is now a **chain of modules** (a PAM-style list), not a single `mode`. The old
`mode:` conflated two separate things — *who authenticates the caller* and *whose key hits the
provider* — which are now separate keys.

```yaml
# 1.2.x
auth:
  mode: token            # token | passthrough | none
  client_tokens: [ "${BUSBAR_CLIENT_TOKEN}" ]

# 1.3
auth:
  chain: [tokens]                 # ordered auth modules; [] = open front door (was mode: none)
  upstream_credentials: own       # own (default) | passthrough (was mode: passthrough)
  client_tokens: [ "${BUSBAR_CLIENT_TOKEN}" ]   # the `tokens` module's allowlist
```

Mapping: `mode: token` → `chain: [tokens]`; `mode: none` → `chain: []`; `mode: passthrough` →
`chain: []` + `upstream_credentials: passthrough`. `tokens` is the built-in auth module (removable /
swappable — external SSO/AD/OIDC modules are added at compile time and named in the chain the same
way). A stale `mode:` key is a loud boot error (`unknown field mode`).

## Quick checklist

- [ ] `route: <weighted|cheapest|fastest|least_busy|usage>` → pool `hooks: [<same>]`
- [ ] `route: socket|webhook` + `policy:` block → a `hooks:` registry entry + pool `hooks: [<name>]`
- [ ] `policy.send_prompt: true` → hook `prompt: ro` (or `rw` to allow rewrite)
- [ ] `policy.send_user: true` → hook `user: ro`
- [ ] `route: script` → a socket hook binary + `hooks:` entry
- [ ] `auth.mode: token` → `auth.chain: [tokens]`; `mode: passthrough` → `chain: []` +
      `upstream_credentials: passthrough`; `mode: none` → `chain: []`

If Busbar starts, you're done — there are no silent fallbacks, so a clean boot means a fully migrated
config.
