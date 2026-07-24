# ADR-0010: Plugin licensing — plugin self-validates, core resolves & delivers

> Status: accepted (1.5.0). `ADR-0010` is referenced in
> `crates/busbar/src/config/secret.rs` (`resolve_settings`), the three plugin
> open paths (`crates/busbar/src/main.rs`, `crates/busbar/src/auth/mod.rs`,
> `crates/busbar/src/hooks/mod.rs`), and the demo plugin
> `crates/auth-static-plugin/src/lib.rs`.

## Context

Plugins are the extension surface of busbar (`kind: store` / `auth` / `hook` /
`secret`, loaded over the signed hybrid ABI). A plugin author may want to
**license** their plugin — gate it behind a purchased key, an expiry, an
entitlement. The question: *how does busbar license a plugin?*

busbar itself is **Apache-2.0** and does **no phone-home**. Building license
enforcement — key validation, entitlement checks, expiry, a call to a licensing
server — into the gateway would be wrong on three counts:

1. It is not busbar's decision to make. A plugin's licensing terms are the
   **plugin author's** concern, not the gateway's.
2. It would drag a licensing/enforcement mechanism (and likely a network
   dependency) into an Apache-2.0, no-phone-home core.
3. Every plugin's licensing model differs (per-seat, per-node, expiry, feature
   flags). A core mechanism could only ever be wrong for most of them.

At the same time, whatever a plugin needs to validate its license — typically a
**license key** — is a **secret**. It must not sit in plaintext config, and it
must not be logged or persisted.

## Decision

**The plugin validates its own license. The core stays license-agnostic — it
only *delivers* the plugin whatever settings the plugin declares, and *resolves*
any secret-referenced setting first.**

Concretely:

- **No core enforcement.** busbar has no notion of a "license". It never
  validates, checks expiry, counts seats, or calls a licensing server. It hands
  the plugin its `settings:` map (verbatim, opaque JSON — the existing contract)
  and the plugin decides, at `open`, whether it is licensed. An unlicensed
  plugin refuses to load *itself*; that is a plugin decision surfaced as a load
  error, not a gateway policy.

- **`license` / `licenseKey` is a documented, first-class settings convention.**
  These well-known keys (`PLUGIN_LICENSE_KEYS` in `config/secret.rs`) are the
  recommended spelling so operators and plugin authors converge on one name.
  They are *convention only*: the core does not special-case them beyond a
  value-free INFO breadcrumb noting a license credential is being delivered. Any
  plugin is free to read a license from any settings key it documents.

- **The license key may be a `SecretRef`, resolved before the ABI.** Any value
  in a plugin's `settings:` map that is a secret reference
  (`{ env: … }` / `{ file: … }` / `{ module: …, settings: … }`) is resolved
  **core-side, before the settings JSON crosses the ABI at `open`**, and the
  resolved value is substituted in. So an operator writes:

  ```yaml
  auth:
    - my-plugin: { settings: { licenseKey: { env: MY_PLUGIN_LICENSE } } }
  ```

  and the plugin receives the *raw key* — never a reference it cannot
  dereference, and never a plaintext key sitting in config. This reuses the
  existing `SecretRef` + `SecretResolver` machinery (ADR: secret resolution;
  `config/secret.rs`), the same path provider API keys, the admin token, and TLS
  material already resolve through. There is no second secret mechanism.

### Mechanism: `resolve_settings`

`config::secret::resolve_settings(settings, resolver)` walks a plugin's opaque
settings map and, for each value that parses as a full `SecretRef`, substitutes
the resolved UTF-8 secret. A value only resolves if it is a genuine secret
reference; an ordinary settings object (e.g. `{ db_path: … }`) is not a ref (its
keys are not a ref's keys) and passes through **verbatim**.

It runs at all three plugin open paths, so resolution happens on **boot, config
apply/reload, AND hot plugin reload** (the paths all funnel through
`build_app_from_config` / the gate rebuild):

| kind  | open site | resolver source |
|-------|-----------|-----------------|
| store | `build_app_from_config` store open (`main.rs`) | the shared `SecretResolver` |
| auth  | `AuthMiddleware::new` (`auth/mod.rs`) | resolver threaded in |
| hook  | `gate_transport_named` + `push_configure` (`hooks/mod.rs`) | `HookEnv.secret_resolver` |

This is **entirely core-side, before the `open`/`configure` call**. It does not
touch the wire ABI or the manifest signature format — those stay frozen.

## Security properties

- **Fail-closed.** An unresolvable secret setting (unknown module, unset env,
  missing/empty file, secret-plugin error) is a hard error that **fails the
  plugin load/reload**. The plugin is *never* handed a dangling reference or a
  silently-empty value. The store and auth paths abort boot/apply; the runtime
  hook gate degrades to absent with a loud warn (its existing fail-open
  safety-net posture — the plugin pre-flight already gates the reference at
  boot), and `push_configure` refuses to commit an unresolvable settings push.

- **The secret is never persisted.** `SecretRef` derives `Serialize` on the
  *reference* (module + settings), never on the resolved bytes. The overlay and
  the on-disk config therefore keep the `SecretRef`; the resolved value exists
  only transiently, long enough to hand to the plugin. Serializing a settings
  map back out yields the reference, not the key.

- **The secret is never logged.** Resolution errors name the offending settings
  *field*, never echo the value. The license breadcrumb logs the key name and
  whether it arrived via a secret reference — never the value. (`SecretRef`'s
  deserializer likewise refuses a bare inline literal precisely so a pasted key
  never lands in a boot log.)

## Consequences

- A plugin author licenses their plugin however they like (signature, expiry,
  entitlement, offline or online) entirely inside the plugin, with zero gateway
  cooperation beyond receiving its settings.
- Operators keep license keys out of plaintext config using the same secret
  machinery they already use for every other credential.
- The core carries no licensing/enforcement code and no new network dependency;
  it stays Apache-2.0 and phone-home-free.
- The demo plugin `busbar-auth-static-plugin` reads a `licenseKey` setting
  (delivered via a `SecretRef` in the e2e test) and validates it itself,
  proving the whole path end-to-end.

## Docs cross-link

`docs/plugins.md` should carry a one-line pointer to this ADR from its plugin
settings / secrets section (the operator-facing "how do I license a plugin"
answer). That pointer is intentionally *not* added here to avoid a merge
conflict with the parallel `plugins.md` rewrite — wire it at merge time.
