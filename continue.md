# CONTINUE — busbar 1.5.0 plugin release (pickup doc)

**Last updated:** 2026-07-21. **State: 20 local commits ahead of `origin/main`, nothing pushed, tree clean, preflight GREEN.** Everything below is local-only.

---

## TL;DR — what this work is

Turning busbar's durable store (and eventually auth/hooks) into **downloadable dynamic-library plugins** loaded at runtime over a stable C ABI, with **signature verification + a trust posture**, plus an **admin API to install/remove/reload plugins**. This is the **1.5.0 "plugin release."** SQLite is no longer compiled in — it's a droppable plugin, which dropped the release binary **14M → 9.4M**.

## How to resume (read first)

- **Working dir:** `/Users/matthew/Developer/busbarAI/busbarAI` (the Rust workspace). Marketing site: `/Users/matthew/Developer/busbarAI/marketing`. Private design docs: `/Users/matthew/Developer/busbarAI/busbarAI-private/design/plugin-system.md`.
- **Green gate every commit:** `bash scripts/preflight.sh` (fmt, structure-lint, clippy `-D`, build, test, no-default-features, cargo-deny). Windows cross-build can't run locally — verify the CI "windows build" job before tagging. Preflight "fails" only on uncommitted changes → that's just a pre-commit reminder; commit then it's GREEN.
- **Commit locally, DO NOT push.** Use `git -C /Users/matthew/Developer/busbarAI/busbarAI ...`. **Never add a `Co-Authored-By` trailer.**
- **Quality > speed.** Green increment per commit.

## What's DONE (the 20 commits)

1. **1.5.0 cut** — versions bumped 1.4.x→1.5.0 across all crates, CHANGELOG stamped `## [1.5.0], 2026-07-20`.
2. **`busbar-plugin-abi`** — the frozen store **C ABI**: 5 `extern "C"` symbols (`busbar_store_abi_version/open/call/free/close`) carrying **JSON** `StoreRequest`/`StoreResponse` (ptr+len), `ABI_VERSION=1`. NUL-terminated symbol name consts.
3. **`busbar-plugin-sdk`** — `export_store_plugin!(ctor)` macro emits the 5 symbols; unsafe glue (`open/call/free/close_impl`) lives as tested crate fns (panic-caught). Author a store = `impl Store` + macro + build `cdylib`.
4. **`busbar-store-sqlite-plugin`** / **`busbar-store-postgres-plugin`** — cdylib wrappers (droppable artifacts). The `store-sqlite`/`store-postgres` **lib** crates hold the logic (also linkable statically = compile-a-plugin-in escape hatch).
5. **`busbar-store-postgres`** — new `Store` impl over the sync `postgres` crate, mirrors sqlite schema/UPSERTs in PG dialect. Integration test gated on `BUSBAR_TEST_POSTGRES_URL` (skips without).
6. **`busbar-plugin-loader`** — `DynStore` (impl `Store` by JSON-over-C-ABI) + `load_store(path,cfg)` via `libloading` (ABI handshake first). **All FFI unsafe isolated here** so `busbar` keeps `#![forbid(unsafe_code)]`. Also `validate_plugin(path)` (vet without loading a store) + `inventory(dir)` (for the admin list).
7. **Boot integration** — `governance.store: sqlite|postgres` loads the plugin from `governance.plugins_dir` (default `plugins`); `db_path` = the sqlite path or the postgres URL. SQLite dropped from the core binary.
8. **`busbar-plugin-sign`** — signed **`plugin.json` manifest** (name, version, kind, author, homepage, source_url, description, license, publisher, interface_version, sha256, signature). `evaluate(bytes, manifest, policy)` → Trusted / Allowed / Rejected. Posture `OnUntrusted` = halt|alert|log(default)|allow. **Signs the canonical whole-manifest** (BTreeMap sorted JSON, feature-unification-safe). Interim **ed25519**; Sigstore swap is a decoupled follow-up.
9. **`governance.trust` config + boot verification** — `PluginTrustCfg { on_untrusted, publishers:[{name,public_key}] }`; `src/plugin_trust.rs::verify(lib_path, policy)` reads bytes + sidecar `<lib>.manifest.json`, evaluates, logs, `Err` only on halt-rejection. `main.rs::verify_plugin_trust()` gates both store load paths.

## Confirmed design decisions (DO NOT re-litigate)

- **Plugins are in-process dynamic libraries over a C ABI** (`libloading`), NOT out-of-process sockets (multi-OS). Per-OS artifacts (`.so`/`.dll`/`.dylib`), not one universal file.
- **JSON over the C ABI**, not C structs (version-tolerant, language-agnostic; store is off the hot path so cost is irrelevant).
- **Trusted in-process load ≡ compiled-in** (no sandbox). Untrusted third-party code → the opt-in out-of-process sandbox (`hook-install-v2`), never default.
- **Install = upload the library bytes** to `POST /admin/plugins`; busbar **re-verifies** (never trusts the client). A CLI that fetches-from-URL + verifies-locally + uploads is **enterprise**, not OSS.
- **Signed rich manifest**; every displayed field signed so the admin console's "install X by Y from Z?" card can't be spoofed. Manifest pins the library by `sha256`; signature covers the whole manifest → neither can be swapped independently.
- **Signing direction = Sigstore keyless** (matches busbar's existing build-provenance; nothing to leak). Needs a `sigstore-rs` in-engine spike + cosign fixture — **decoupled** (interim ed25519 keeps everything green; only `evaluate`'s verify internals swap).
- **`version` in the manifest** is the plugin's semver → the enterprise dashboard flags "update available."
- **Plugin management CLI/dashboard = enterprise.** OSS ships the admin API endpoints + docs only.
- **Term:** manifest uses `interface_version` (not "ABI") operator-facing; "ABI" stays in the Rust crates.
- **Default posture `log`** (unsigned plugins load with a warning) keeps OSS smooth; `halt` = "only approved plugins."

## What's LEFT (task list)

- **#13 Admin plugin endpoints (NEXT, biggest).** Extend `GET /plugins` to report dynamic plugins (loader:"dynamic-library", version/publisher/interface_version/trust verdict from the sidecar manifest); add `POST` install (upload bytes+manifest → `plugin_trust::verify` reuse → `validate_plugin` → atomic write into `plugins_dir` → audit), `DELETE` remove, `POST reload`. **Frozen Admin v1 integration** — see notes below.
- **#15 Redis store plugin** — `store-redis` lib + cdylib (like postgres). Redis is KV, so model keys as JSON values + index sets; usage/metering as hashes (HSET absolute / HINCRBY). `GovernanceStore::Redis`, url via `db_path`. Gated integration test on a `REDIS_URL` env. Untestable locally without a live Redis.
- **#14 Sigstore verify refactor** — spike `sigstore-rs` (compiles under forbid(unsafe_code)? passes cargo-deny with its TUF/Fulcio/Rekor/OCI tree?), then swap `plugin-sign` verify to cosign-bundle-over-canonical-manifest, trust = allowlisted OIDC identities.
- **#16 Docs (marketing repo)** — installing plugins (drop-in + admin API), manifest schema, trust/security; PLUS the `/download` SDK section (Python/PyPI, TS/npm, Go/pkg.go.dev, Terraform+Pulumi) — **verify each package is actually published before linking.** Marketing site build: `cd marketing/website && npx astro build` (needs a stubbed `src/release.json` `{"version":"1.5.0"}` and the docs sync; the full `npm run build` needs the busbar repo's docs — see marketing/website/sync-docs.mjs).
- **#17 Durable audit log (backlog)** — the audit log (`admin/audit.rs`) is an in-memory hash-chained ring today; decide durable home (through the Store, a 4th "audit sink" plugin category, or a `kind:tap` hook). The `AuditStore` seam is already hinted in that file.

### #13 integration notes (gathered, saves you the study)

- Routes: `crates/busbar/src/admin/v1/json/mod.rs` (`.route(...)` list). Handlers: `.../json/handlers.rs`. Business logic: `.../v1/service.rs` (`AdminService`). Audit: `crates/busbar/src/admin/audit.rs` (hash-chained; `AuditEntry{seq,ts,action,resource,outcome,principal,prev_hash,hash}`).
- **`GET /plugins` already exists** (`list_plugins`, `?type=auth|hooks`) and returns `PluginView{ name, type, loader, active, target }` — **`loader` and `target` were designed for loadable plugins** (`loader:"compiled-in"` today → `"dynamic-library"`). Extend this for `type=store`/`db` from `inventory(plugins_dir)` + the sidecar manifest.
- **Frozen Admin v1 has an OpenAPI drift guard.** Committed schema: `crates/busbar/src/admin/v1/json/openapi.json`; contract: `crates/busbar/src/admin/v1/contract/{mod,schema}.rs`. Mount grammar comment at `json/mod.rs:49` ("no path can drift"). **Adding routes requires updating the OpenAPI contract + the audit taxonomy** (add `plugin.install`/`plugin.remove`/`plugin.reload` outcomes) or the drift-guard test fails. Study `json/mod.rs` + the contract before adding routes.
- Reuse `crate::plugin_trust::verify` (already written) for the server-side re-verify. Use `busbar_plugin_loader::validate_plugin` to vet the uploaded bytes (write to a temp file, validate, then atomic-rename into `plugins_dir`).
- Admin plane is already TLS-capable + admin-token-gated (+ optional mTLS via `admin_tls.client_ca_file`). Store install is boot-time/config-apply, not a hot swap (a store change takes effect on restart/apply; hooks would hot-add on reload later).

## Gotchas / conventions

- **`GovernanceCfg` test literals:** adding a field to `GovernanceCfg` breaks **11 full-struct literals** in `config/tests/tests.rs` (3) + `config_validate/tests/tests.rs` (8). Pattern used: a python one-liner inserting the new field after an existing anchor line (see git history of `plugins_dir` / `trust` commits).
- `busbar` is `#![forbid(unsafe_code)]` — **all FFI unsafe must live in `plugin-loader`** (or another dedicated crate), never in `busbar`.
- Workspace members list: `Cargo.toml` (root). New crates: add there.
- Manifest sidecar path = `<library path> + ".manifest.json"` (`plugin_trust::manifest_path_for`).
- Store plugin lib filename resolution: `busbar_plugin_loader::plugin_library_filename("busbar_store_<name>_plugin")` → per-OS `lib….so/.dylib` / `….dll`.

## Crate map

`crates/`: `api` (contracts incl. `Store` + serde), `plugin-abi` (C ABI), `plugin-sdk` (author macro), `plugin-loader` (libloading, unsafe isolated), `plugin-sign` (manifest + verify + posture), `store-memory` (built-in default), `store-sqlite`(+`-plugin`), `store-postgres`(+`-plugin`), `auth-tokens`, `auth-admin-tokens`, `hooks-ranking`, `busbar` (engine).

## Also parked (non-plugin)

- **Marketing site is LIVE and pushed** (separate from this): `/plugins` Plugin Store with voting (Cloudflare Worker `docker-pulls` serves `/api/votes`+`/api/vote`), Docs links, `/hooks`→`/plugins` 301s. The `/download` SDK section (#16) is the open marketing item.
- Rotate the `cfat_…` Cloudflare token that was pasted this session (hygiene).
