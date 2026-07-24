# Plugins

busbar ships as one small static binary (about 9.4 MB) with nothing compiled in that you did not
ask for: no SQLite, no Postgres, no Redis. The default deploy needs no plugins at all. When you do
need more, a durable store, a secret backend, auth or hook modules, you add
exactly that capability as a signed plugin tarball dropped into a directory. Lightweight by
default, extend when needed.

A plugin is a plugin: store, auth, and hook plugins share ONE artifact format, ONE trust model, ONE
loader, and ONE inventory (`busbar --list-plugins`). The manifest `kind` field is the only
discriminator; it selects which C ABI the cdylib exports and which engine subsystem consumes it.
The engine itself never sees any of this machinery. It receives a `dyn Store` (or, as those seams
open, `dyn Auth` / `dyn Hook`) trait object through the `busbar-api` contract, exactly as if the
backend had been compiled in. The engine cannot tell a dynamic plugin from a built-in, and the
crate boundaries enforce it: all plugin discovery, unpacking, verification, and loading lives in
the `plugin-*` crates, and the engine crate keeps `#![forbid(unsafe_code)]` with every FFI
`unsafe` isolated in `busbar-plugin-loader`.

- [The artifact](#the-artifact)
- [Enabling plugins](#enabling-plugins)
- [Building a plugin](#building-a-plugin)
- [Signing and packaging](#signing-and-packaging)
- [How plugins are secured](#how-plugins-are-secured)
- [Inspecting and validating](#inspecting-and-validating)

## The artifact

One plugin is one `.tar.gz` per (plugin, target) containing exactly two members:

- the cdylib (`.so` / `.dylib` / `.dll`) exporting the C ABI for its `kind`;
- `manifest.json`, the signed manifest.

```json
{
  "name": "busbar-store-redis",
  "alias": "redis",
  "kind": "store",
  "version": "1.5.0",
  "publisher": "busbar",
  "abi_version": 1,
  "sha256": "<64-hex sha256 of the cdylib bytes>",
  "signature": "<128-hex ed25519 signature over the canonical manifest>",
  "description": "busbar redis store plugin",
  "homepage": "",
  "license": "Apache-2.0"
}
```

The signature covers every field except `signature` itself (deterministic sorted-key JSON), and
`sha256` pins the manifest to the exact library bytes, so neither the manifest nor the library can
be altered or swapped independently. Identity comes from the signed manifest, never the filename:
you can name the tarball anything.

`name` is the canonical identity (`[a-z0-9-]+`, e.g. `busbar-store-redis`); `alias` is the short
config name (`redis`). `store.module:` accepts either. `kind` is `store`, `secret`, `auth`, or `hook`.
`version` is strict semver. `abi_version` declares which busbar C ABI generation the cdylib was
built against (currently `1` for every kind).

## Enabling plugins

Plugins are OFF by default. The top-level `plugins:` block is the whole configuration surface:

```yaml
plugins:
  enabled: true          # master switch, default false: off = nothing in the dir ever loads
  dir: plugins           # where the tarballs live
  trust:
    publishers:          # third-party signing keys only; busbar's own key is embedded
      - name: acme
        public_key: "<64-hex ed25519 public key>"
    allow_unsigned: false
    allow_third_party: false
  min_versions:
    acme-store-dynamo: "2.0.0"

store:
  module: redis          # alias or canonical name, resolved against the signed manifests
  settings: { url: "rediss://:password@redis.internal:6380/0" }
```

With `enabled: false` (or the block absent) a tarball in the directory is inert: busbar does not
read it, and referencing a plugin store (`store.module: redis`) fails boot with an error naming
`plugins.enabled`. See [configuration.md](configuration.md#plugins) for the field reference.

## Building a plugin

A store plugin in Rust is small. Implement the `busbar_api::Store` trait (or wrap an existing
implementation), adapt the JSON config busbar passes at open, and let the SDK emit the C glue:

```rust
// Cargo.toml:
//   [lib]
//   crate-type = ["cdylib"]
//   [dependencies]
//   busbar-api = { .. }
//   busbar-plugin-sdk = { .. }
//   serde_json = "1"

use busbar_api::Store;

fn open(cfg: &str) -> Result<Box<dyn Store>, String> {
    // `cfg` is the store's own `settings` map, passed through verbatim as JSON.
    let v: serde_json::Value = serde_json::from_str(cfg).map_err(|e| e.to_string())?;
    let url = v.get("url").and_then(|x| x.as_str()).ok_or("missing url")?;
    Ok(Box::new(MyStore::connect(url)?))
}

busbar_plugin_sdk::export_store_plugin!(open);
```

`export_store_plugin!` emits the five extern-C symbols of the store ABI (`busbar_store_abi_version`,
`open`, `call`, `free`, `close`). Every store operation rides one `call` symbol as a
JSON-serialized `StoreRequest`/`StoreResponse` pair, so the symbol set never grows as the trait
does, and a plugin can equally be written in C, Go, or Zig against the same contract
(`busbar-plugin-abi` is the source of truth). The store sits off the request hot path
(write-behind), so JSON serialization never touches request latency.

Build per target:

```sh
cargo build --release -p my-store-plugin                      # host target
cargo build --release -p my-store-plugin --target aarch64-unknown-linux-gnu
```

## Auth plugins (`kind: auth`)

A `kind: auth` plugin is a first-class **identity provider**: it implements the same
`busbar_api::AuthModule` trait the built-in modules do (`name()` + `authenticate()` returning
`Identify(principal)` / `Reject` / `Pass`), and the engine loads it **in-process** at boot over the
signed hybrid ABI — exactly like a store or secret plugin, same trust posture, same loader. It runs
in the data-plane **`auth.chain`**: name it there and the engine resolves it against the plugins
directory, loads it, and boxes it into the chain.

```rust
// crate-type = ["cdylib"]; deps: busbar-api, busbar-plugin-sdk, serde_json
use busbar_api::{AuthModule, AuthOutcome, Principal};

struct MyIdp { /* … */ }
impl AuthModule for MyIdp {
    fn name(&self) -> &'static str { "myidp" }             // the RUNTIME module identity
    fn authenticate(&self, candidate: Option<&str>) -> AuthOutcome {
        match verify(candidate) {
            Some((id, groups)) => {
                let mut p = Principal::from_id(id);
                p.roles = groups;                            // roles/groups the IdP asserts
                AuthOutcome::Identify(p)
            }
            None => AuthOutcome::Pass,                        // not my credential — defer
        }
    }
    fn cacheable(&self) -> bool { true }                     // per-call I/O ⇒ opt into the cred cache
}

fn open(cfg: &str) -> Result<Box<dyn AuthModule>, String> {
    // `cfg` is the chain entry's own `settings:` map, passed through verbatim as JSON.
    Ok(Box::new(MyIdp::from_config(cfg)?))
}
busbar_plugin_sdk::export_auth_plugin!(open);
```

An auth module returns **identity only** — who the caller is (`id` + `roles`). Policy (which pools,
which group's limits, which admin scope) is resolved by busbar from `auth.role_bindings.<module>`
(nested by module) and capped by `auth.chain.<module>.max_admin_scope`, never asserted by the
module. Crucially, `<module>` is the value the plugin returns from **`name()`** — its runtime
identity — NOT the config alias you write in `auth.chain`. Bind roles under that name.

**Fail-closed, always:** a configured auth plugin that cannot load (missing/untrusted tarball, wrong
kind, or a `dlopen`/ABI failure) is a **hard boot error** — the front door never silently opens
because a module was dropped. `--validate` catches a missing/wrong-kind/untrusted auth plugin
manifest-only, before boot; and referencing an auth plugin while `plugins.enabled: false` is refused,
naming the flag.

The bundled **`oidc`** module (`busbar-auth-oidc-plugin`) is exactly such a plugin — see
[configuration.md](configuration.md#auth-plugins) for the `auth.chain: [oidc]` + `settings:` recipe
(including an Entra ID example).

Hook plugin manifests (`kind: hook`) travel through the same discovery, trust, validation, and
inventory today, but hooks stay **out-of-process** (socket/webhook transports); the in-process
dynamic hook consumer arrives with its ABI generation.

## Signing and packaging

Generate a keypair once (the private half is your signing secret; the public half is what
operators allowlist):

```sh
busbar-plugin-pack keygen
# private (BUSBAR_SIGN_KEY, keep secret): 9f2c...
# public  (publishers allowlist / BUSBAR_RELEASE_PUBKEY): 4ab1...
```

Then sign and package in one step:

```sh
BUSBAR_SIGN_KEY=9f2c... busbar-plugin-pack pack \
    --lib target/release/libmy_store_plugin.so \
    --name acme-store-dynamo --alias dynamo --kind store \
    --version 1.0.0 --publisher acme \
    --license Apache-2.0 \
    --out acme-store-dynamo-1.0.0-x86_64-linux.tar.gz
```

The tool computes the `sha256` binding, signs the canonical manifest, self-checks the result
against the same structural validation busbar runs at load, and writes the tarball. For local
development, `--allow-unsigned` (with no `BUSBAR_SIGN_KEY`) packages an unsigned tarball that
busbar loads only under `plugins.trust.allow_unsigned: true`.

busbar's own store plugins are built, signed (the `BUSBAR_SIGN_KEY` CI secret), and attached to
each GitHub Release per target by the release workflow; release binaries embed the matching public
key, so first-party plugins verify with zero configuration.

## How plugins are secured

Running third-party native code inside a gateway is the sharpest tool in this codebase, so the
design is fail-closed at every layer. The threat model, plainly: an attacker who can write to the
plugins directory, tamper with a tarball in transit, or push an artifact at the admin API must not
get code executed, and a compromised or replayed plugin must not load.

1. **Off by default.** `plugins.enabled` defaults to `false`. Nothing in the directory is read,
   let alone executed. Dropping a file somewhere is never enough.
2. **Signature trust, not location trust.** A plugin loads because its manifest signature verifies,
   not because of where the file sits. busbar's release public key is embedded in the binary, so
   busbar-signed plugins are trusted with zero configuration. Third-party publishers must be
   explicitly allowlisted by key. Unsigned or unknown-publisher plugins are logged and skipped
   unless the operator sets the matching explicit opt-in (`allow_unsigned` / `allow_third_party`),
   and a skipped plugin is never `dlopen`ed: its initialization code never runs, not at boot, not
   from the admin catalog, not from `--list-plugins`.
3. **Anti-downgrade.** A validly-signed but OLD release is still a signed artifact an attacker can
   replay. First-party plugins are automatically floored at the running binary's version;
   `plugins.min_versions` pins floors for third-party plugins by manifest name. A floored plugin
   must prove, with a trusted signature over a version at or above the floor, that it meets it. No
   opt-in flag relaxes a floor.
4. **Structural fail-closed.** Before trust is even consulted, every tarball must unpack cleanly
   (bounded sizes, exactly two members, no path tricks), the manifest must be complete and
   well-formed, `sha256(lib)` must match, and the `abi_version` must be one this binary speaks.
   With plugins enabled, ANY invalid artifact in the directory aborts boot with the file and the
   exact reason named. There is no partial or degraded boot.
5. **Conflicts are hard errors.** No two loadable plugins may share a name or alias, and no alias
   may collide with another plugin's name. You cannot run the first-party `redis` store and a
   third-party plugin that also claims `redis`; boot stops and names both.
6. **Verified bytes are the loaded bytes.** The tarball is unpacked and verified fully in memory;
   the manifest never touches disk. On Linux the verified library bytes go into a `memfd` and are
   loaded from `/proc/self/fd/N`: zero disk files, no path for anyone to race or swap. On macOS
   and Windows the verified bytes are written to a fresh file inside a per-process private `0700`
   staging directory and loaded from there; the file is regenerated from the verified bytes on
   every load, a pre-existing on-disk library is never loaded, clean shutdown unloads the library
   and then removes the file, and a boot-time sweep removes staging left by a crashed prior
   process. There is no time-of-check/time-of-use window between verification and load.
7. **The engine stays memory-safe.** The engine crate compiles under `forbid(unsafe_code)`; all
   FFI lives in `busbar-plugin-loader`. The loader also bounds every plugin response (a buggy or
   hostile plugin cannot force an unbounded allocation).
8. **The pre-flight gate is the boot gate.** `busbar --validate` runs the same
   consistency-policy-scan-resolution pipeline boot runs, so it cannot drift: if `--validate`
   passes, the plugin half of boot succeeds; if it fails, it names exactly what is wrong.

What signing does NOT do: a trusted plugin still runs with busbar's privileges, exactly like a
compiled-in backend would. Signing answers "is this the artifact its publisher shipped, unmodified,
and current"; it does not sandbox the publisher. Allowlist publishers you would be willing to link
into the binary.

## Inspecting and validating

```sh
$ busbar --list-plugins
plugins dir: plugins (plugins.enabled: true)
FILE                               NAME                     ALIAS        KIND   VERSION   SIGNATURE                STATUS
busbar-store-redis-1.5.0.tar.gz    busbar-store-redis       redis        store  1.5.0     first-party              LOADS (store.module: redis)
busbar-store-sqlite-1.5.0.tar.gz   busbar-store-sqlite      sqlite       store  1.5.0     first-party              ready
acme-store-dynamo-1.0.0.tar.gz     acme-store-dynamo        dynamo       store  1.0.0     unknown-publisher        SKIPPED: publisher 'acme' is not in the allowlist; ...
old-redis.tar.gz                   busbar-store-redis       redis        store  1.2.0     trusted (below floor)    REJECTED: ... (anti-downgrade)
broken.tar.gz                      -                        -            -      -         INVALID                  INVALID: manifest.json does not parse: ...
```

`--list-plugins` is manifest-only: it never loads plugin code, so it is safe to run against a
directory full of untrusted artifacts. `busbar --validate` is the gate: it validates
`config.yaml`, `providers.yaml`, and every plugin manifest (structure, signature and trust,
conflicts, ABI, version floors) with zero side effects, exiting 0 only when boot would succeed.

The admin API exposes the same manifest-only catalog (`GET /api/v1/admin/plugins?type=store`) and
can install or remove tarballs remotely through the identical trust gate; see
[admin-api.md](admin-api.md).
