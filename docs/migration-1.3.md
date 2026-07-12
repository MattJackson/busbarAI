# Migrating from 1.2.x to 1.3

1.3 reshapes how routing and hooks are configured. The change is a **clean cut**: old-form keys are
not silently accepted — Busbar reports a clear startup error naming exactly what to write instead, so
you can migrate with confidence and never run a half-understood config. This guide covers every
config change. Most deployments touch only one or two lines.

The mental model: **the engine runs hooks.** A pool picks a native ranking with `policy:`, and
optionally layers a gate (a hook) with `hook:`. Hooks are defined once under a top-level `hooks:`
registry and referenced by name — on a pool, or globally.

---

## 1. Native routing strategy: `route:` → `policy:`

The pool's built-in ranking strategy moved from `route:` to its own key, `policy:`. The values are
unchanged (`weighted` — the default — `cheapest`, `fastest`, `least_busy`, `usage`).

```yaml
# 1.2.x
pools:
  my-pool:
    route: cheapest
    members: [...]

# 1.3
pools:
  my-pool:
    policy: cheapest
    members: [...]
```

`route: weighted` (or an absent `route:`) needs no change beyond the rename — `policy: weighted` is
still the zero-cost default. Boot error if you leave `route: cheapest`:
`the `route:` pool key was removed in 1.3; the native strategy moved to `policy:` — write `policy: <name>``.

---

## 2. Routing hooks: `route: socket|webhook` + `policy:` block → `hooks:` registry + `hook:`

A hook (webhook sidecar or Unix-socket binary) is now **defined once** in a top-level `hooks:`
registry and **referenced by name** from a pool. The inline `policy:` block is gone.

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

# 1.3 — define the hook once, reference it
hooks:
  my-router:
    kind: gate
    socket: /run/busbar/router.sock
    timeout_ms: 5
    on_error: weighted

pools:
  my-pool:
    hook: my-router
    members: [...]
```

The webhook transport is the same, moved into the registry entry as `webhook: https://…` (exactly one
of `socket` or `webhook` per hook). A pool's `hook:` must name a `kind: gate` entry. Boot errors name
the fix: `the `route: socket|webhook` transport was removed in 1.3; define the hook once under
top-level `hooks:` … and reference it with `hook: my-hook`` and, for the block,
`the `policy:` block was removed in 1.3; `policy:` is now a scalar strategy …`.

Note `kind:` — a hook is a `gate` (fire-and-wait: it can rank, reject, restrict, or rewrite) or a
`tap` (fire-and-forget observation). A pool's `hook:` references a gate.

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
under `hooks:` (kind: gate, socket:) and reference it with `hook:``.

---

## Quick checklist

- [ ] `route: <weighted|cheapest|fastest|least_busy|usage>` → `policy: <same>`
- [ ] `route: socket|webhook` + `policy:` block → a `hooks:` registry entry + pool `hook: <name>`
- [ ] `policy.send_prompt: true` → hook `prompt: ro` (or `rw` to allow rewrite)
- [ ] `policy.send_user: true` → hook `user: ro`
- [ ] `route: script` → a socket hook binary + `hooks:` entry

If Busbar starts, you're done — there are no silent fallbacks, so a clean boot means a fully migrated
config.
