# Code layout conventions

The point of these rules is **predictable location**: given a concept, there is exactly one place
it can live, derivable from its name and role. "I'm looking for X, and I know where it is" should be
true by construction. Size reduction is a side effect of getting that right, not the goal.

Four invariants, all mechanically enforced by `scripts/structure-lint.sh` (run in CI). If they hold,
the tree cannot drift back into giant, inconsistent files.

## 1. A module is a file *or* a folder — never both

`foo.rs` and `foo/` must not coexist. The moment a module needs a second file, the parent `foo.rs`
becomes `foo/mod.rs` and everything moves under `foo/`. (The old `admin.rs` + `admin/` hybrid is the
anti-pattern this kills: the key handlers now live at `admin/keys.rs`, not stranded in a parent
`admin.rs`.)

## 2. Tests live in one predictable place, mirroring the impl

Impl at `foo/X.rs` → its tests at `foo/tests/X.rs`. Always. A hub (`mod.rs`) carries **no inline test
body** — but it *may* carry the one-line `#[path]` **declaration** that keeps the test module a direct
child (so `use super::*` still reaches private items). The body always lives in `tests/`:

```rust
// in foo/mod.rs (or foo/X.rs)
#[cfg(test)]
#[path = "tests/x_behaviour.rs"]
mod x_behaviour;   // file lives in foo/tests/, still a direct child → super::* unchanged
```

A small leaf file (`bar.rs`, under the size cap, no folder) may keep a single inline test module at
the bottom — that's the one allowed exception.

## 3. Objective size trigger, not vibes

A file crosses to a folder-module when it exceeds **~1,500 impl lines** or carries **more than one**
named test module. The lint's hard ceiling on **impl** files is **2,500 lines** — it exists to forbid
genuine monster files (the thing that makes a codebase unnavigable), not to micromanage a cohesive
unit at 1,600. **Test files are exempt** from the size cap: they are located by name
(`foo/tests/<what>.rs`), not read top-to-bottom, so the navigability the cap protects is already
served by the tests/ folder convention and one-module-per-file.

## 4. Files are role-named — the name predicts the content

The filename is a total function of the code's role, so you never hunt:

- `proxy/signing.rs` — request signing / auth headers
- `proxy/select.rs` — lane selection + failover walk
- `proto/gemini/writer.rs` — the Gemini response writer
- `admin/rate.rs` — admin-plane rate limiting

Every protocol dialect has the identical shape — `proto/<name>/{mod,reader,writer}.rs` +
`proto/<name>/tests/` — so learning one lets you find anything in any of the six.

## Naming vocabulary

Module names use the product/API vocabulary (ingress, egress, pool, lane, hook, operation):

| Module | Role |
|---|---|
| `ingress/` | ingress entry handlers (the request comes in here) |
| `proxy/` | proxies the request to the provider: select lane, translate, call, fail over, stream back |
| `hooks/` | the hook system: pool routing resolution + hook transports (socket/webhook/wire) |
| `proto/` | wire dialects; `proto::detect` sniffs which dialect a request speaks |

## Running the lint

```
scripts/structure-lint.sh
```

Non-zero exit on any violation, with the offending path and the fix. It runs in CI (the `check` job),
so a PR that reintroduces a giant file or a hybrid module fails before merge.
