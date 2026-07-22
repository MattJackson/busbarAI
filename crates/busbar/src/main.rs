// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//
// busbar — a native-protocol LLM gateway. It fronts many LLM providers and routes each request to
// a model or to a weighted pool of models, translating losslessly between wire protocols and
// protecting each backend with a circuit breaker. The name is electrical: a busbar takes one feed
// and fans it out across many breakered circuits.
//
// Routing — all SIX ingress protocols are first-class; a native SDK can point its base URL at
// busbar unmodified (clients append the protocol path themselves). Mirrors the `--help` ENDPOINTS
// block and the README routing table:
//   POST /<model>/v1/messages              Anthropic-format ingress (single model)
//   POST /<pool>/v1/messages               a config-defined pool (weighted selection + failover)
//   POST /<provider>/<model>/v1/messages   ad-hoc: a specific configured provider+model
//   POST /v1/chat/completions              OpenAI-format ingress (model from the body)
//   POST /v2/chat                          Cohere-format ingress (model from the body)
//   POST /v1/responses                     OpenAI Responses-API ingress (model from the body)
//   POST /v1/models/<model>:<action>       Gemini-format ingress (stable v1 alias)
//   POST /v1beta/models/<model>:<action>   Gemini-format ingress (v1beta)
//   POST /model/<modelId>/converse[-stream] Bedrock Converse / ConverseStream ingress
//   GET  /v1/models  /v1beta/models        list models (dialect by protocol fingerprint)
//   GET  /stats  /healthz  /metrics
//
// Each model is a "lane" with its own concurrency semaphore, optional lifetime request budget, and
// per-(pool,lane) circuit-breaker health. A pool stacks its members' concurrency into one aggregate
// and distributes via smooth weighted round-robin. Ingress and backend protocols may differ: the
// request and response are translated through a superset intermediate representation (see
// `proto`/`ir`), so e.g. an OpenAI-format client can drive a Gemini or Bedrock backend, or a native
// Responses/Cohere/Gemini/Bedrock client can drive any configured backend.
//
// Failure handling (see `breaker`): transient upstream faults (5xx / overload / rate-limit /
// timeout / network) arm an escalating cooldown; billing and auth faults open the breaker with a
// long sticky cooldown; client-supplied 4xx are relayed verbatim and never penalize the lane; an
// exhausted lifetime budget disables the lane. Tripped lanes recover via a half-open probe.

// busbar contains ZERO `unsafe` code; enforce that as a compile-time guarantee so any future PR that
// introduces an `unsafe` block fails to build rather than slipping in unreviewed.
#![forbid(unsafe_code)]

// Global allocator: jemalloc. The request hot path allocates and frees the request body a few times
// per request (raw bytes → parsed JSON → re-serialized outbound), so RSS under load tracks
// (peak concurrency × payload size). glibc's allocator almost never returns freed pages to the OS,
// so after a big-payload burst the process stays pinned at its peak forever — memory reads as a
// ratchet even though the live set has collapsed. jemalloc plus a background purge thread returns
// dirty/muzzy pages after a short decay, so busbar PLATEAUS under sustained load and falls back to
// idle when the load subsides. `#[global_allocator]` on a static needs no `unsafe`; the background
// purge thread is enabled at startup in `main()` via a safe runtime call (`tikv_jemalloc_ctl::
// background_thread`), so operators get it with zero configuration. NOT on windows-msvc: tikv-jemalloc-sys's
// C build does not compile under native `cl.exe`, so MSVC (a shipped release target + CI gate) falls back
// to the system allocator — the dep is target-gated in Cargo.toml and these two sites match.
#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

mod admin;
mod auth;
mod auth_cache;
mod billing;
mod breaker;
mod config;
mod config_validate;
mod egress_auth;
mod endpoints;
mod eventstream;
mod governance;
mod handlers;
mod health;
mod hooks;
mod ingress;
mod ir;
mod json;
mod limits;
mod lossless;
mod media;
mod metrics;
mod net_guard;
mod observability;
mod operation;
mod plugin_trust;
mod profile;
mod proto;
mod proxy;
mod sigv4;
mod state;
mod state_persist;
mod store;
#[cfg(test)]
mod test_support;
mod tls;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::{routing::get, routing::post, Router};

use auth::AuthMiddleware;

use proto::ProtocolRegistry;
use state::{App, Lane, WeightedLane};
use store::{InMemoryStore, LaneData};

// The upstream-request timeout, pool-idle, and request-body caps that used to live here as `const`s
// are now operator-tunable (`limits.upstream_request_timeout_secs` / `pool_max_idle_per_host` /
// `request_body_max_bytes`), each defaulting to its historical value at the config layer. They are
// threaded from `cfg.limits` into the client builder and router below; the egress translate-body cap
// is COUPLED to `request_body_max_bytes` via `crate::limits::translate_body_max_bytes`.

/// Environment variable name for the providers.yaml path.
const ENV_PROVIDERS: &str = "BUSBAR_PROVIDERS";
/// Environment variable name for the config.yaml path.
const ENV_CONFIG: &str = "BUSBAR_CONFIG";
/// Default path to the providers definition file.
const DEFAULT_PROVIDERS_PATH: &str = "/etc/busbar/providers.yaml";
/// Default path to the deployment config file.
const DEFAULT_CONFIG_PATH: &str = "/etc/busbar/config.yaml";
/// Response header name for the W3C Server-Timing field.
const HEADER_SERVER_TIMING: &str = "server-timing";
/// Sentinel value stored in the `UPSTREAM_RTT_US` task-local when NO upstream hop was dispatched
/// (admin / health / early error). `server_timing_dur_ms` treats this as "report the full request
/// time" rather than subtracting a nonexistent RTT. Only this exact u64::MAX meaning is replaced
/// with the const; overflow/conversion fallbacks that happen to produce u64::MAX are NOT this.
const NO_UPSTREAM_RTT: u64 = u64::MAX;

/// Handle CLI flags before any environment or file access, so they work without a configured
/// deployment. Returns `Some(exit_code)` when the process should exit (after printing), `None` to
/// proceed to normal startup. busbar takes no positional arguments and is configured via
/// environment + YAML; an unrecognized flag is a usage error rather than a silent server start.
fn handle_cli_flags() -> Option<i32> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        None => None, // no args → run the gateway
        Some("--version" | "-V") => {
            println!("busbar {}", env!("CARGO_PKG_VERSION"));
            Some(0)
        }
        Some("--print-metadata-blocklist") => {
            // Print the EFFECTIVE cloud-metadata denylist the running binary enforces: the hardcoded
            // set (single source of truth in config_validate) UNION the operator's
            // `security.blocked_metadata_hosts`. The hardcoded set always prints (no config needed);
            // the operator extension is appended best-effort if BUSBAR_CONFIG is readable + parseable,
            // so the flag is useful even before a deployment is wired up. One entry per line, exit 0.
            let mut entries = config_validate::metadata_denylist_entries();
            let config_path =
                std::env::var(ENV_CONFIG).unwrap_or_else(|_| DEFAULT_CONFIG_PATH.into());
            if let Ok(raw) = std::fs::read_to_string(&config_path) {
                if let Ok(interpolated) = config::interpolate_env(&raw) {
                    match serde_yaml::from_str::<config::DeployCfg>(&interpolated) {
                        Ok(deploy) => {
                            if let Some(sec) = deploy.security {
                                entries.extend(sec.blocked_metadata_hosts);
                            }
                        }
                        Err(_) => {
                            // The config did not parse (e.g. an unknown/typo'd key now rejected by
                            // deny_unknown_fields). Don't silently print an INCOMPLETE denylist that
                            // omits the operator's `security.blocked_metadata_hosts` — warn instead.
                            // (Deliberately NOT echoing the error, which could quote a config value;
                            // the normal boot path surfaces the precise parse error.)
                            eprintln!(
                                "warning: config at {config_path} did not parse; printing the built-in \
                                 metadata denylist only (security.blocked_metadata_hosts skipped). Run \
                                 busbar normally to see the parse error."
                            );
                        }
                    }
                }
            }
            for entry in entries {
                println!("{entry}");
            }
            Some(0)
        }
        Some("--validate") => Some(validate_config_command()),
        Some("--help" | "-h") => {
            println!(
                "busbar {ver} — native-protocol LLM gateway

USAGE:
    busbar              run the gateway (configured entirely via environment + YAML)
    busbar --help       print this help
    busbar --version    print the version
    busbar --validate   parse + validate config.yaml/providers.yaml and exit (0 = valid, 1 = errors);
                        no server, no network, no state — safe in CI and before a reload
    busbar --print-metadata-blocklist
                        print the effective cloud-metadata SSRF denylist and exit

ENVIRONMENT:
    BUSBAR_PROVIDERS    path to providers.yaml  (default: /etc/busbar/providers.yaml)
    BUSBAR_STATE_FILE   state-snapshot path ('' disables; default: busbar-state.json next to config)

Flags:
    --safe-mode         boot on base config.yaml alone (quarantine the persisted overlay)
    BUSBAR_CONFIG       path to config.yaml     (default: /etc/busbar/config.yaml)
    RUST_LOG            log level: error|warn|info|debug|trace  (default: info)

ENDPOINTS (once running, listen address from config.yaml `listen`):
    POST /<model>/v1/messages              Anthropic-format ingress (single model)
    POST /<pool>/v1/messages               route to a configured pool
    POST /<provider>/<model>/v1/messages   ad-hoc direct route
    POST /v1/chat/completions              OpenAI-format ingress
    POST /v2/chat                          Cohere-format ingress
    POST /v1/responses                     Responses-API ingress
    POST /v1/models/<model>:<action>       Gemini-format ingress (stable v1)
    POST /v1beta/models/<model>:<action>   Gemini-format ingress
    POST /model/<modelId>/converse         Bedrock Converse ingress
    POST /model/<modelId>/converse-stream  Bedrock Converse streaming ingress
    GET  /v1/models  /v1beta/models        list models (answers in the caller's dialect)
    GET  /stats  /healthz  /metrics

Docs: https://getbusbar.com   ·   Source: https://github.com/GetBusbar/busbar",
                ver = env!("CARGO_PKG_VERSION")
            );
            Some(0)
        }
        Some(other) => {
            eprintln!("busbar: unrecognized argument '{other}'. Try 'busbar --help'.");
            Some(2)
        }
    }
}

/// `--validate`: parse, resolve, and semantically validate the config WITHOUT booting. Runs the exact
/// same load -> resolve -> validate the gateway runs at boot (so a clean `--validate` means a clean
/// boot), but never binds a listener, writes state, spawns a task, opens TLS, or makes a network call,
/// and does NOT require provider secrets (validation is STRUCTURE, not reachability — the nginx -t rule).
/// Honors BUSBAR_CONFIG/BUSBAR_PROVIDERS/--safe-mode. Prints an OK summary + exits 0 when valid;
/// prints every error (same text boot prints) + exits 1 when not.
fn validate_config_command() -> i32 {
    let providers_path = std::path::PathBuf::from(
        std::env::var(ENV_PROVIDERS).unwrap_or_else(|_| DEFAULT_PROVIDERS_PATH.into()),
    );
    let config_path = std::path::PathBuf::from(
        std::env::var(ENV_CONFIG).unwrap_or_else(|_| DEFAULT_CONFIG_PATH.into()),
    );
    let safe_mode = std::env::args().any(|a| a == "--safe-mode");

    let loaded = match load_config_from_disk(
        &config_path,
        &providers_path,
        safe_mode,
        config::EnvSubst::Lenient,
    ) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[error] {e}");
            return 1;
        }
    };
    let unset_env_vars = loaded.unset_env_vars.clone();
    let cfg = match config::resolve(&loaded.deploy, &loaded.defs) {
        Ok(c) => c,
        Err(errs) => {
            eprintln!("[error] config errors:\n  - {}", errs.join("\n  - "));
            return 1;
        }
    };
    if let Err(errs) = config_validate::validate_with_unset(&cfg, &unset_env_vars) {
        eprintln!(
            "[error] config validation failed:\n  - {}",
            errs.join("\n  - ")
        );
        return 1;
    }
    println!(
        "ok: config valid — {} provider(s), {} model(s), {} pool(s)\n  config:    {}\n  providers: {}",
        cfg.providers.len(),
        cfg.models.len(),
        cfg.pools.len(),
        config_path.display(),
        providers_path.display(),
    );
    if !unset_env_vars.is_empty() {
        println!(
            "  note: {} env var(s) referenced but unset here — required at runtime: {}",
            unset_env_vars.len(),
            unset_env_vars.join(", "),
        );
    }
    0
}

/// Print a clean startup error to stderr and exit non-zero. Used for misconfiguration and other
/// boot-time failures so the operator sees a one-line message instead of a Rust panic backtrace.
fn die(msg: impl std::fmt::Display) -> ! {
    eprintln!("[error] {msg}");
    std::process::exit(1);
}

/// Return the open-relay banner to emit when the auth chain is EMPTY (open front door), or `None`
/// when an auth module is engaged. `chain_empty` = the resolved `auth.chain` is empty. `auth_present`
/// distinguishes an explicit empty chain (operator opted in) from a missing `auth:` block
/// (serde-defaulted to open — the silent foot-gun the banner must call out).
fn open_relay_banner(chain_empty: bool, auth_present: bool) -> Option<&'static str> {
    if !chain_empty {
        return None;
    }
    Some(if auth_present {
        "auth is DISABLED (auth.chain is empty) — busbar is running as an OPEN RELAY; do not run this in production"
    } else {
        "auth is DISABLED: no `auth:` block in config — busbar is running as an OPEN RELAY (anyone can use it). Add `auth:` with `chain: [tokens]` (and `client_tokens`) before exposing it; do not run this in production"
    })
}

/// Return the INERT-KEYS banner to emit when a DURABLE governance store still holds virtual keys
/// from a prior run but NO admin token is configured. In that state the governance engine is inert
/// (the auth middleware gates the vkey-resolution branch on `admin_token_hash().is_some()`), so the
/// persisted keys' per-key controls (budget, RPM/TPM, allowed_pools) are silently NOT enforced —
/// access falls through to the static `auth.chain` instead. A RAM store can never reach this state
/// (keys are only minted through the admin API, which itself requires the admin token), so this is
/// scoped to durable stores. Returns `None` when the state does not apply (RAM store, no keys, or an
/// admin token IS set). `key_count` is the number of keys the store reports at boot.
fn inert_durable_keys_banner(
    store_is_durable: bool,
    key_count: usize,
    admin_token_set: bool,
) -> Option<String> {
    if store_is_durable && key_count > 0 && !admin_token_set {
        Some(format!(
            "durable governance store contains {key_count} key(s) but no admin_token is set — \
             governance is INERT and those keys are NOT enforced (per-key budget / RPM / TPM / \
             allowed_pools are bypassed and access falls through to the static auth.chain). Set \
             governance.admin_token to enforce them."
        ))
    } else {
        None
    }
}

/// Resolve each model's single `context_max` from the pool members that reference it.
///
/// A model is realized as exactly one lane (keyed by model name in `by_model`), so its
/// context window must be single-valued across every pool that lists it. We accept the same
/// `context_max` repeated (including the same `Some(_)` in multiple pools, and a mix of an
/// explicit value with `None` — the explicit value wins, since `None` only means "unspecified
/// here"), but reject two DIFFERENT explicit limits for the same model: that is an operator
/// contradiction that previously resolved nondeterministically to whichever pool iterated last.
fn resolve_model_context_max(
    pools: &HashMap<String, config::PoolCfg>,
) -> Result<HashMap<String, Option<usize>>, String> {
    let mut resolved: HashMap<String, Option<usize>> = HashMap::new();
    for pool in pools.values() {
        for m in &pool.members {
            match resolved.get(&m.target) {
                // First sighting of this model, or this member adds no opinion (None) — keep what
                // we have / record what we got.
                None => {
                    resolved.insert(m.target.clone(), m.context_max);
                }
                Some(None) => {
                    // Previously unspecified; let any value (including another None) refine it.
                    resolved.insert(m.target.clone(), m.context_max);
                }
                Some(Some(existing)) => match m.context_max {
                    // No opinion here, or an identical opinion — both fine, keep the explicit value.
                    None => {}
                    Some(c) if c == *existing => {}
                    Some(c) => {
                        return Err(format!(
                            "model '{}' has conflicting context_max across pools ({} vs {}); a model maps to one lane and must declare a single context_max",
                            m.target, existing, c
                        ));
                    }
                },
            }
        }
    }
    Ok(resolved)
}

fn main() {
    // CLI flags first — BEFORE building any runtime. They must work without a configured deployment,
    // and `--version` / `--validate` should never spin up a thread pool.
    if let Some(code) = handle_cli_flags() {
        std::process::exit(code);
    }
    // Enable jemalloc's background purge thread: freed dirty/muzzy pages are returned to the OS after
    // a short idle decay, so RSS falls back to idle after a big-payload burst instead of ratcheting at
    // the peak (the glibc behavior this replaces). Safe wrapper — no `unsafe`. Skipped on windows-msvc,
    // which uses the system allocator (jemalloc dep is target-gated off msvc; see above).
    //
    // Best-effort and VERIFIED at runtime rather than assumed: some platforms/builds lack background-
    // thread support (macOS keeps only foreground purge; jemalloc also flags it as potentially
    // unavailable on musl — and the SHIPPED release is static musl). Read the flag back after writing and
    // WARN if it did not enable, so the plateau-then-fall-back-to-idle behavior is an observed fact, not a
    // silent assumption. Even when the background thread is absent, jemalloc's FOREGROUND decay purge
    // still bounds RSS under load; only the proactive purge during full idle is lost.
    //
    // This runs in `main()` BEFORE the tracing subscriber is installed (that happens in `run()` after the
    // runtime is built), so the diagnostic goes to STDERR via `eprintln!` — the same channel the other
    // pre-subscriber boot messages use — rather than `tracing`, which would silently drop it. Silent on
    // success; only the problem cases (did-not-enable / error) print.
    #[cfg(not(target_env = "msvc"))]
    {
        use tikv_jemalloc_ctl::background_thread;
        let enabled = match background_thread::write(true).and_then(|()| background_thread::read())
        {
            Ok(true) => true, // enabled — RSS falls back to idle; nothing to report
            Ok(false) => {
                eprintln!(
                    "[warn] jemalloc background purge thread did NOT enable on this target (no \
                     background-thread support); enabling busbar's idle purge fallback so RSS still \
                     returns to idle after a load burst"
                );
                false
            }
            Err(e) => {
                eprintln!(
                    "[warn] could not enable jemalloc background purge thread ({e}); enabling \
                     busbar's idle purge fallback so RSS still returns to idle after a load burst"
                );
                false
            }
        };
        // WITHOUT background threads (static-musl release builds — jemalloc compiles them out under
        // musl — and macOS dev builds), jemalloc's decay purge is FOREGROUND-only: it advances only
        // on allocator activity. A fully idle process therefore never purges, so after a big-payload
        // burst RSS ratchets at (roughly) the burst's dirty-page peak forever — observed as
        // idle 8.7 MiB → burst 322 MiB → "idle" 56 MiB that never comes back down. The fallback
        // below restores the return-to-idle property with ZERO unsafe code and ZERO hot-path cost.
        if !enabled {
            spawn_jemalloc_idle_purge_fallback();
        }
    }
    // BUSBAR_PROFILE set → periodically dump the per-stage breakdown to stderr (every 20 s), so a
    // live benchmark run reports stage timings without the in-process test driver. Measurement-only
    // opt-in, absent from any production deployment; zero cost when the env is unset.
    if crate::profile::enabled() {
        std::thread::spawn(|| loop {
            std::thread::sleep(std::time::Duration::from_secs(20));
            crate::profile::dump();
        });
    }
    // Worker-thread count. `BUSBAR_WORKER_THREADS` is the operator override; the DEFAULT is one worker
    // per available core (`available_parallelism`, which respects CPU affinity and cgroup cpuset — but
    // NOT the CFS bandwidth quota `cpu.max`, which it cannot see). So on a quota-limited pod (e.g. 2 CPUs
    // of quota on a 64-core node) this defaults to the NODE's core count, oversubscribing the quota;
    // such deployments should pin `BUSBAR_WORKER_THREADS` to their CPU limit. Uncapped-by-default is
    // what lets throughput scale with cores: v1.3.1–1.3.3 capped the pool at `min(cores, 4)`, which
    // pinned the data plane to ~4 cores and made throughput plateau no matter how big the box (v1.3.0
    // itself was uncapped via `#[tokio::main]`; 1.4.0 restores that default explicitly). The request
    // path is CPU-bound on JSON translate, so it genuinely uses the cores. Footprint-sensitive sidecars
    // (the ~5 MB-idle case) should set `BUSBAR_WORKER_THREADS=1` (or 2): each worker carries a stack and
    // its own allocator arena, so idle RSS grows with the count. Scale up by default, tune down (or to
    // your CPU quota) deliberately.
    // Resolve the worker-thread override, warning on an EXPLICITLY-SET but invalid value rather than
    // silently ignoring it. v1.3.0 ran under `#[tokio::main]`, which fail-fast panicked on a bad
    // `TOKIO_WORKER_THREADS`; 1.4.0 builds the runtime explicitly and would otherwise fall through to
    // all-cores on a `0`/garbage value — a silent footprint surprise. An UNSET var is not warned (it is
    // the normal default path). `TOKIO_WORKER_THREADS` is read as a back-compat fallback so an operator
    // who pinned it on 1.3.0 keeps the same pool size. (1.4.0 audit.) `eprintln!` because this runs
    // before the tracing subscriber is installed.
    fn worker_threads_from_env(name: &str) -> Option<usize> {
        match std::env::var(name) {
            Ok(v) => match v.trim().parse::<usize>() {
                Ok(n) if n >= 1 => Some(n),
                _ => {
                    eprintln!(
                        "[warn] {name}={v:?} is not a positive integer; ignoring it and using the \
                         default worker-thread count"
                    );
                    None
                }
            },
            Err(_) => None, // unset — normal default path, no warning
        }
    }
    let worker_threads = worker_threads_from_env("BUSBAR_WORKER_THREADS")
        .or_else(|| worker_threads_from_env("TOKIO_WORKER_THREADS"))
        .unwrap_or_else(|| {
            // Fall back to 1 (not 2) when core detection fails, matching v1.3.0's `#[tokio::main]`
            // behavior exactly. Only reachable on an exotic host where `available_parallelism` errors.
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1)
        });
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .enable_all()
        .build()
        .expect("failed to build the tokio runtime")
        .block_on(run());
}

async fn run() {
    // Install the Prometheus recorder on a background thread. Its one-time clock calibration
    // (quanta's TSC calibration, ~200ms) would otherwise block the listener; deferring it lets
    // busbar bind and serve (incl. /healthz) in tens of ms. `/metrics` renders empty until the
    // recorder is live, and the sliver of requests in that startup window go uncounted — an
    // acceptable trade for a daemon/k8s readiness path. Emission macros are no-ops until then.
    std::thread::spawn(metrics::init);

    // Locate the two config files (env-overridable paths) and run the shared disk-load pipeline —
    // the SAME pipeline `POST /api/v1/admin/config/reload` re-runs at runtime.
    let providers_path = std::path::PathBuf::from(
        std::env::var(ENV_PROVIDERS).unwrap_or_else(|_| DEFAULT_PROVIDERS_PATH.into()),
    );
    let config_path = std::path::PathBuf::from(
        std::env::var(ENV_CONFIG).unwrap_or_else(|_| DEFAULT_CONFIG_PATH.into()),
    );
    let safe_mode = std::env::args().any(|a| a == "--safe-mode");
    let loaded = load_config_from_disk(
        &config_path,
        &providers_path,
        safe_mode,
        config::EnvSubst::Strict,
    )
    .unwrap_or_else(|e| die(e));
    let LoadedConfig {
        deploy,
        defs,
        overlay_path,
        base_hook_names,
        unset_env_vars: _,
    } = loaded;

    // Optional observability sinks; grab before `deploy` is borrowed by resolve.
    let observability_cfg = deploy.observability.clone().unwrap_or_default();
    // Governance config; grab before `deploy` is borrowed by resolve.
    let governance_cfg = deploy.governance.clone();

    // Install the tracing subscriber now (stderr fmt always; OTLP export if configured) so all
    // subsequent startup and request-path logging is captured.
    observability::init_logging(observability_cfg.otlp_endpoint.as_deref());

    // First line in the logs: which build is running. Operators need this to confirm a deploy /
    // correlate logs to a release without shelling in to run `--version`.
    tracing::info!(version = env!("CARGO_PKG_VERSION"), "busbar starting");
    // Stamp process start for the `GET /api/v1/admin/info` uptime read.
    admin::mark_start();

    // Resolve deployment + definitions into resolved RootCfg (semantic validation runs inside
    // build_app_from_config — the one construction path).
    let cfg = config::resolve(&deploy, &defs)
        .unwrap_or_else(|errs| die(format!("config errors:\n  - {}", errs.join("\n  - "))));

    // Metadata-SSRF protection status (discoverability). When the nuclear `allow_all_metadata` is set
    // the guard is OFF — that is a security-relevant degradation, so WARN. Otherwise report the count
    // of blocked hosts (hardcoded denylist ∪ security.blocked_metadata_hosts) and point at the CLI
    // flag that dumps the full list.
    if cfg.allow_all_metadata {
        tracing::warn!("metadata protection DISABLED — all cloud-metadata endpoints reachable");
    } else {
        let blocked =
            config_validate::metadata_denylist_entries().len() + cfg.blocked_metadata_hosts.len();
        tracing::info!(
            "metadata protection: {blocked} hosts blocked (--print-metadata-blocklist to view)"
        );
    }

    let listen = cfg.listen.clone();
    let tls_cfg = cfg.tls.clone();
    // The admin plane ALWAYS runs on its own listener (`admin_listen`, default loopback 127.0.0.1:8081)
    // with its own optional TLS/mTLS — never on the data listener. The exposed-admin-requires-mTLS
    // boot-guard has already run in `config::resolve`, so by here `admin_listen` is loopback, mTLS,
    // or an explicit `admin_insecure` waiver.
    let admin_listen = cfg.admin_listen.clone();
    let admin_tls_cfg = cfg.admin_tls.clone();
    let req_body_max = cfg.limits.request_body_max_bytes;
    let max_inbound = cfg.limits.max_inbound_concurrent;
    let app = Arc::new(
        build_app_from_config(
            cfg,
            governance_cfg,
            overlay_path,
            base_hook_names,
            (Some(config_path.clone()), Some(providers_path.clone())),
            None,
        )
        .unwrap_or_else(|e| die(e)),
    );

    // Record the BOOT snapshot as version 0 so the version history always has a rollback floor
    // (the pre-any-mutation state).
    app.versions
        .record(0, "system", "boot", &app.hook_registry, &app.global_hooks);

    // DURABLE AUDIT (#17): when a durable governance store is configured (sqlite/postgres/redis), it
    // is the audit log's durable home. Attach it as the write-through SINK (every future admin
    // mutation persists as it is appended), and RESTORE the ring from it first — the store is the
    // source of truth, so its history (which can exceed the RAM ring bound) survives restart with the
    // hash chain intact. The RAM default (`store: memory`) has no durable audit: the sink no-ops and
    // the restore reads nothing, so the log stays ephemeral exactly as before. A chain-verification
    // failure on restore is logged (a tamper signal) and we fall through to the file snapshot below.
    let mut audit_restored_from_store = false;
    if let Some(gov) = app.governance.as_ref() {
        let store = gov.store();
        crate::admin::audit::AUDIT.set_sink(store.clone());
        match crate::admin::audit::AUDIT.restore_from_store(store.as_ref()) {
            Ok(0) => {} // no durable audit (memory default / empty) — fall through to the snapshot
            Ok(n) => {
                audit_restored_from_store = true;
                tracing::info!(
                    entries = n,
                    "audit log restored from the durable governance store"
                );
            }
            Err(e) => tracing::warn!(
                error = %e,
                "durable audit restore failed (chain verification); falling back to the state snapshot"
            ),
        }
    }

    // D3 RESTORE: bring back the persisted process state (health by lane identity, audit ring,
    // version history) so the restart forgot nothing. Fail-soft in every direction.
    let state_file = state_persist::resolve_path(Some(&config_path));
    if let Some(ref sf) = state_file {
        if let Some(persisted) = state_persist::read(sf, store::now()) {
            let restored = persisted.health.len();
            // Rebuild the store WITH restored health (identity-keyed, so it survives any config
            // edits made while busbar was down). The app was just built and is not yet served, so
            // rebuilding its store here is safe; the swap-in happens before the first request.
            // (Simplest correct wiring: restore INTO the existing store's lanes by identity.)
            app.store.restore_health(&persisted.health);
            // Only seed the audit ring from the FILE snapshot when the durable store did NOT already
            // provide it — otherwise a stale snapshot would clobber the store's authoritative (and
            // more complete) history and rewind the sequence.
            if !audit_restored_from_store {
                crate::admin::audit::AUDIT.load(persisted.audit);
            }
            app.versions.load(persisted.versions);
            // Re-record the boot floor ON TOP of the restored history (a fresh boot version entry).
            app.versions.record(
                app.config_version,
                "system",
                "boot (state restored)",
                &app.hook_registry,
                &app.global_hooks,
            );
            tracing::info!(path = %sf.display(), lanes = restored, "state restored from snapshot");
        }
    } else {
        tracing::info!(
            "state persistence disabled (no config path / BUSBAR_STATE_FILE empty); restarts \
             start with fresh health state"
        );
    }

    // configure the request-log webhook (reusing the pooled client). No-op if unset.
    observability::configure_webhook(
        observability_cfg.request_log_webhook_url.clone(),
        app.client.clone(),
    );

    // Spawn the active health probers (one per lane with a probing mode). No-op when every lane is
    // `mode: none` / has no `health:` block. Re-spawned on every config reload/apply (see the admin
    // swap sites) so reloaded lanes get probed and the old generation exits.
    health::spawn_probers(&app);

    // Build the two routers with the operator-configured ingress body cap + optional inbound-
    // concurrency layer (0 = unlimited / no layer, the default). The admin surface is built onto its
    // OWN router (ABSENT from the data router) and served on `admin_listen` below; the data router
    // serves the protocols. Both share one `app_handle`, so config-apply hot-swaps reach both planes.
    let (data_router, admin_router, app_handle) = build_split_routers_with_limits(
        app,
        req_body_max,
        max_inbound,
        observability_cfg.emit_server_timing,
    );

    // D3 SNAPSHOTTER: persist process state every ~30s (and once more on graceful shutdown below)
    // so a restart — including an upgrade — forgets nothing.
    if let Some(ref sf) = state_file {
        state_persist::spawn_snapshotter(app_handle.clone(), sf.clone());
    }

    // Graceful shutdown: on ctrl_c (SIGINT) or SIGTERM, stop accepting new connections, let
    // in-flight requests drain, then flush the OTLP tracer so the final (most diagnostic) spans are
    // exported rather than dropped when the runtime tears down. The signal future is panic-free —
    // a failed registration logs and parks forever (so a missing signal facility degrades to "no
    // graceful shutdown", never a crash), and `shutdown_tracing()` is a no-op when OTLP is off.
    // ONE signal fans out to BOTH listeners (data + admin) so both planes drain together.
    let (shutdown_tx, _keep_open) = tokio::sync::broadcast::channel::<()>(1);
    {
        let shutdown_tx = shutdown_tx.clone();
        tokio::spawn(async move {
            shutdown_signal().await;
            let _ = shutdown_tx.send(());
        });
    }

    // WRITE-BEHIND BUDGET FLUSHER: the in-memory budget counters are authoritative on the request hot
    // path (no SQLite await on admission); this background task periodically flushes accrued
    // spend/requests to the durable store and runs one FINAL flush when the shutdown signal fires, so
    // a graceful stop loses nothing (an ungraceful crash can lose at most one flush interval). Spawned
    // once here (not on config apply/reload — the reused `Arc<GovState>` keeps its live cells and its
    // already-running flusher). No-op when governance is disabled.
    if let Some(gov) = app_handle.load().governance.clone() {
        crate::governance::spawn_budget_flusher(gov, shutdown_tx.subscribe());
    }

    // Data plane on `listen`, admin plane on its own `admin_listen`, served concurrently — each with
    // its own TLS/mTLS. `tokio::join!` returns only once BOTH have drained.
    let data_listener = bind_listener(&listen).await;
    let admin_listener = bind_listener(&admin_listen).await;
    tokio::join!(
        serve_listener(
            data_listener,
            data_router,
            tls_cfg,
            &listen,
            recv_shutdown(shutdown_tx.subscribe()),
        ),
        serve_listener(
            admin_listener,
            admin_router,
            admin_tls_cfg,
            &admin_listen,
            recv_shutdown(shutdown_tx.subscribe()),
        ),
    );
    // BUDGET WRITE-BEHIND: one FINAL, SYNCHRONOUS flush after the graceful drain, so a graceful stop
    // persists the freshest accrued spend/requests before the process exits. The background flusher's
    // shutdown arm also flushes, but it is a fire-and-forget task that could lose the race with process
    // exit; flushing inline here on the run task guarantees durability (this call blocks briefly under
    // the budget lock, off any request path — the listeners have already drained).
    if let Some(gov) = app_handle.load().governance.clone() {
        let n = gov.flush_budgets();
        tracing::info!(flushed = n, "budget counters flushed on shutdown");
    }
    // D3: one FINAL state snapshot after the graceful drain, so the freshest health picture is
    // what the next boot restores (the periodic 30s tick could be up to 30s stale).
    if let Some(ref sf) = state_file {
        let app = app_handle.load();
        if let Err(e) = state_persist::write(sf, &state_persist::capture(&app)) {
            tracing::warn!(path = %sf.display(), error = %e, "final state snapshot failed");
        } else {
            tracing::info!(path = %sf.display(), "state snapshot written on shutdown");
        }
    }
    observability::shutdown_tracing();
}

/// Bind a TCP listener or `die` with a clear, address-named message. Shared by the data and admin
/// listeners so both fail fast and identically on a bad bind.
async fn bind_listener(addr: &str) -> tokio::net::TcpListener {
    tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| die(format!("cannot bind listen address '{addr}': {e}")))
}

/// One shutdown-broadcast subscription resolved into a plain future. Any receive outcome — a send,
/// or a closed/lagged channel — means "shut down now", so every arm resolves the future.
async fn recv_shutdown(mut rx: tokio::sync::broadcast::Receiver<()>) {
    let _ = rx.recv().await;
}

/// Serve one listener (data OR admin plane) to graceful shutdown. Picks plain-HTTP vs native TLS/mTLS
/// from `tls_cfg` exactly as the single-listener path always has: `None` ⇒ plain HTTP over the shared
/// slow-loris-hardened hyper loop; `Some` ⇒ terminate TLS (mTLS when `client_ca_file` is set), with
/// cert/key/CA loaded and validated up front so a bad path/parse `die`s at startup, not per request.
/// `label` names the plane in log lines and error messages. Any serve error `die`s the process.
async fn serve_listener(
    listener: tokio::net::TcpListener,
    router: Router,
    tls_cfg: Option<crate::config::TlsCfg>,
    label: &str,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) {
    match tls_cfg {
        None => {
            tracing::info!(listen = %label, "busbar listening");
            if let Err(e) = tls::serve_plain(listener, router, shutdown).await {
                die(format!("server error on '{label}': {e}"));
            }
        }
        Some(tls) => {
            tls::install_crypto_provider();
            let server_config = tls::build_server_config(&tls)
                .unwrap_or_else(|e| die(format!("TLS configuration error for '{label}': {e}")));
            let mtls = tls.client_ca_file.is_some();
            tracing::info!(listen = %label, mtls, "busbar listening (TLS)");
            if let Err(e) = tls::serve(listener, router, server_config, shutdown).await {
                die(format!("server error on '{label}': {e}"));
            }
        }
    }
}

/// Resolve when the process receives a shutdown signal (SIGINT/ctrl_c, or SIGTERM on Unix). Used as
/// the `axum::serve(...).with_graceful_shutdown` future. Never panics: a signal-handler
/// registration error is logged and the corresponding branch parks forever, so the other branch
/// still triggers shutdown and a registration failure can never abort a worker.
async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            tracing::warn!(error = %e, "failed to install ctrl_c handler; SIGINT shutdown disabled");
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to install SIGTERM handler; SIGTERM shutdown disabled");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
    tracing::info!("shutdown signal received; draining in-flight requests");
}

/// Infer the INGRESS protocol from a request path so an unmatched/wrong-method request can be
/// answered in the protocol the client was speaking, not a generic shape. The prefixes mirror the
/// route table: OpenAI (`/v1/chat/completions`), Responses (`/v1/responses`), Cohere (`/v2/chat`),
/// Gemini (`/v1/models/...`, `/v1beta/models/...`), Bedrock (`/model/...`), and Anthropic
/// (`.../v1/messages`). When nothing matches we default to `openai` — its envelope is the most
/// widely understood and is what a generic HTTP client probing `/` is most likely to parse. This is
/// inference for ERROR shaping only; it never routes a real request.
fn proto_for_path(path: &str) -> &'static str {
    // Delegate to the CANONICAL classifier in `proto` so the fallback/405 handlers and
    // `auth.rs::unauthorized_response` cannot drift for the same path (the bug this fixes: a
    // non-Converse `/model/foo/bar` path was shaped as bedrock here but openai by auth — contradictory
    // error envelopes for one path, a protocol indistinguishability gap). The canonical version
    // requires the `/converse`/`/converse-stream` suffix before classifying `/model/...` as bedrock.
    proto::proto_for_path(path)
}

/// Render a native ingress-protocol error envelope (`application/json`) for the fallback handlers,
/// attaching the `x-amzn-*` headers when the inferred protocol is Bedrock so the response is
/// indistinguishable from a real vendor 404/405. Shared by [`fallback_handler`] (404, unmatched
/// path) and [`method_not_allowed_handler`] (405, wrong method on a valid path).
pub(crate) fn fallback_error_response(
    path: &str,
    status: axum::http::StatusCode,
    kind: &str,
    message: &str,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    // The NATIVE-API root speaks the frozen admin envelope for EVERY response — including unmatched
    // paths and wrong methods, which previously fell through to the vendor-native shaping below and
    // leaked `{error:{type}}` bodies onto a surface that promises `{error:{code}}` (re-audit HIGH-1).
    // Boundary-safe: exact root or root + '/'.
    {
        use crate::admin::v1::contract::{AdminError, API_ROOT};
        if path == API_ROOT || path.starts_with(&format!("{API_ROOT}/")) {
            let e = if status == axum::http::StatusCode::METHOD_NOT_ALLOWED {
                AdminError::MethodNotAllowed
            } else {
                AdminError::NotFound("resource".into())
            };
            return crate::admin::v1::json::err_json(&e);
        }
    }
    let proto = proto_for_path(path);
    let protocol = proto::protocol_for(proto);
    let body = match &protocol {
        Some(p) => p.writer().write_error(status.as_u16(), kind, message),
        // proto_for_path only ever returns a registered protocol literal, so this is unreachable in
        // practice; shape a generic OpenAI-style envelope rather than panic on the request path.
        None => serde_json::json!({ "error": { "message": message, "type": kind } }),
    };
    let mut resp = (
        status,
        [(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static(crate::proxy::APPLICATION_JSON),
        )],
        body.to_string(),
    )
        .into_response();
    // Provider-specific error RESPONSE HEADERS (Bedrock `x-amzn-RequestId`/`x-amzn-errortype`;
    // Anthropic `request-id` mirrored from the body) — dispatched via the writer vtable so this
    // fallback handler matches the shape produced by `proxy::ingress_error` on the hot path,
    // with no provider name-branch here.
    if let Some(p) = &protocol {
        p.writer()
            .attach_error_response_headers(resp.headers_mut(), kind, &body);
    }
    resp
}

// NOTE: the 404 fallback handler is superseded by `ingress::protocol_dispatch`, which owns the
// catch-all and reproduces the same native-envelope 404 shaping for non-protocol paths.

/// 405 fallback: a valid ingress path hit with the wrong method (e.g. GET on a POST-only ingress).
/// axum's built-in 405 is an `Allow`-header-only empty body; reshape to the protocol-native envelope
/// so an SDK sees a vendor-shaped error instead of a bare proxy tell.
async fn method_not_allowed_handler(uri: axum::http::Uri) -> axum::response::Response {
    fallback_error_response(
        uri.path(),
        axum::http::StatusCode::METHOD_NOT_ALLOWED,
        crate::admin::ERR_TYPE_INVALID_REQUEST,
        "method not allowed for this resource",
    )
}

/// The exact body axum 0.7's `DefaultBodyLimit` emits when a request exceeds the limit: its
/// extractor rejection (`FailedToBufferBody::LengthLimitError`) renders a 413 with this literal
/// `text/plain` body. This is the SENTINEL used to distinguish axum's OWN body-limit 413 from a
/// forward-path-relayed upstream 413: the reshape acts only on a response whose body is
/// exactly this marker, so a relayed upstream 413 (any other body, JSON or not) passes through
/// untouched. (Pinned to axum's wire shape; covered by `test_reshape_oversized_413_passthrough`.)
const AXUM_BODY_LIMIT_413_MARKER: &[u8] = b"length limit exceeded";

/// Reshape an oversized-body rejection into a protocol-native error. axum's `DefaultBodyLimit`
/// rejects a too-large request with HTTP 413 and a bare `text/plain` body (`"length limit
/// exceeded"`) — a router/proxy tell no native vendor API emits. This middleware wraps the
/// body-limit layer: it captures the request path, runs the inner
/// stack, and when the result is axum's OWN body-limit 413 (identified by the
/// [`AXUM_BODY_LIMIT_413_MARKER`] sentinel body — NOT merely any non-JSON 413), it replaces that
/// response with the inferred ingress protocol's native JSON `request_too_large` envelope (Bedrock
/// variants also gain `x-amzn-*` headers, via [`fallback_error_response`]). Any other 413 — a
/// forward-path-relayed UPSTREAM 413 (whatever its content-type), or one a real ingress handler
/// already shaped as JSON — is passed through untouched.
async fn reshape_body_limit_413(
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let path = req.uri().path().to_owned();
    let resp = next.run(req).await;
    reshape_oversized_413(&path, resp).await
}

/// Per-process count of requests that entered the middleware stack — the idleness signal for the
/// jemalloc idle-purge fallback (bumped once per request in `server_timing`, read every sweep tick
/// by the purge thread). Wraps harmlessly (only equality-across-a-window is compared).
static REQUEST_ACTIVITY_TICKS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// How often the idle-purge fallback wakes to check for idleness (and how long a request-free window
/// must be before it purges). 15 s keeps "RSS returns to idle within ~60 s of load stopping" with
/// plenty of margin while never firing under any sustained traffic.
#[cfg(not(target_env = "msvc"))]
const IDLE_PURGE_SWEEP_SECS: u64 = 15;

/// FALLBACK idle purge for targets where jemalloc's background purge threads are unavailable
/// (static-musl release builds compile them out; macOS lacks them). jemalloc's decay purge is
/// otherwise FOREGROUND-only — driven by allocator activity — so a fully idle process never returns
/// its freed dirty pages to the OS and RSS ratchets at the last burst's peak (measured on this
/// machine: an 8-worker burst left 595 MiB of freed-but-unpurged RSS parked indefinitely; one purge
/// pass dropped it to 14.7 MiB). This thread watches the request-activity ticker and, after a full
/// sweep window with ZERO requests, forces a one-shot purge of every INITIALIZED arena's dirty pages
/// by writing `arena.<i>.dirty_decay_ms = 0` (jemalloc's documented "purge all unused dirty pages
/// immediately" setting) and then restoring the configured decay value — all through
/// tikv-jemalloc-ctl's SAFE typed mallctl API (`AsName`/`Access`; no `unsafe` anywhere).
///
/// Per-arena (not the `MALLCTL_ARENAS_ALL` pseudo-index) because the ALL write EFAULTs the moment it
/// hits an UNINITIALIZED arena (jemalloc creates arenas lazily; most of the default 4×ncpu set never
/// initialize), poisoning the whole batch. Individual errors on uninitialized arenas are expected
/// and skipped; `arenas.narenas` is re-read each pass so late-created arenas are covered.
///
/// Request behavior is untouched: the purge only ever fires in a window that served NO requests, the
/// restore returns decay to exactly the configured value, and under load the thread does nothing but
/// one atomic read per 15 s. Repeated purges on a long-idle process are no-ops (no dirty pages
/// remain). Best-effort throughout — mallctl errors are skipped, never panicked on.
#[cfg(not(target_env = "msvc"))]
fn spawn_jemalloc_idle_purge_fallback() {
    use tikv_jemalloc_ctl::{Access, AsName};
    // The configured default decay (what arenas run with; the value restored after each purge).
    const ARENAS_DIRTY_DECAY_DEFAULT: &[u8] = b"opt.dirty_decay_ms\0";
    const ARENAS_NARENAS: &[u8] = b"arenas.narenas\0";
    let spawned = std::thread::Builder::new()
        .name("busbar-idle-purge".into())
        .spawn(move || {
            let restore: isize = match ARENAS_DIRTY_DECAY_DEFAULT.name().read() {
                Ok(v) => v,
                Err(e) => {
                    eprintln!(
                        "[warn] jemalloc idle-purge fallback disabled: could not read \
                         opt.dirty_decay_ms ({e})"
                    );
                    return;
                }
            };
            let mut last = REQUEST_ACTIVITY_TICKS.load(std::sync::atomic::Ordering::Relaxed);
            loop {
                std::thread::sleep(std::time::Duration::from_secs(IDLE_PURGE_SWEEP_SECS));
                let cur = REQUEST_ACTIVITY_TICKS.load(std::sync::atomic::Ordering::Relaxed);
                let idle = cur == last;
                last = cur;
                if !idle {
                    continue;
                }
                // Idle window: force the purge on every initialized arena (decay 0 ⇒ jemalloc purges
                // all unused dirty pages during the set), then restore the configured decay. An
                // uninitialized arena's write errors — expected; skip it.
                let narenas: u32 = ARENAS_NARENAS.name().read().unwrap_or(0);
                for i in 0..narenas {
                    let key = format!("arena.{i}.dirty_decay_ms\0");
                    let name = key.as_bytes().name();
                    let _ = name.write(0isize).and_then(|()| name.write(restore));
                }
            }
        });
    if let Err(e) = spawned {
        eprintln!("[warn] could not spawn the jemalloc idle-purge fallback thread ({e})");
    }
}

/// Compute the `Server-Timing` `dur` value (milliseconds) for a request: Busbar's own processing
/// time = total request wall-clock minus the upstream round-trip. `upstream_us == u64::MAX` means
/// "no upstream hop" (admin/health/early error), so the full time is reported. Saturating, so clock
/// skew (upstream measured slightly larger than total) can never underflow into a huge value.
fn server_timing_dur_ms(total_us: u64, upstream_us: u64) -> f64 {
    let internal_us = if upstream_us == NO_UPSTREAM_RTT {
        total_us
    } else {
        total_us.saturating_sub(upstream_us)
    };
    internal_us as f64 / 1000.0
}

/// Outermost middleware: stamps a standard `Server-Timing: busbar;dur=<ms>` response header
/// reporting the latency Busbar itself added — total request wall-clock MINUS the upstream
/// round-trip — so operators (and browser DevTools / APM tools) can see the gateway's own cost
/// in-band on every response, without scraping `/metrics` or wiring traces. The upstream RTT is
/// recorded by the forward path into the [`proxy::UPSTREAM_RTT_US`] task-local for the duration
/// of this scope; a request that never dispatched upstream (admin / health / early error) reports
/// its full processing time. W3C `Server-Timing` `dur` is milliseconds; emitted at µs precision.
async fn server_timing(
    axum::extract::State(emit): axum::extract::State<bool>,
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use std::sync::atomic::Ordering;
    // Activity tick for the jemalloc idle-purge fallback (see `spawn_jemalloc_idle_purge_fallback`):
    // one relaxed add on the outermost middleware, so the purge thread can tell "no requests this
    // window" apart from "under load" without touching the metrics registry. Negligible cost.
    REQUEST_ACTIVITY_TICKS.fetch_add(1, Ordering::Relaxed);
    let slot = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(NO_UPSTREAM_RTT));
    let start = std::time::Instant::now();
    let mut resp = proxy::UPSTREAM_RTT_US
        .scope(slot.clone(), next.run(req))
        .await;
    // Gated by `observability.emit_server_timing` (default false). When disabled, NO Server-Timing
    // header is emitted at all — the inner stack still runs unchanged, only the header is suppressed
    // (the header is an in-band busbar fingerprint an operator may want to hide). We still scope the
    // RTT task-local so disabling this never changes any other timing behavior.
    if emit {
        let total_us = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
        let dur_ms = server_timing_dur_ms(total_us, slot.load(Ordering::Relaxed));
        if let Ok(v) = axum::http::HeaderValue::from_str(&format!("busbar;dur={dur_ms:.3}")) {
            resp.headers_mut()
                .insert(axum::http::HeaderName::from_static(HEADER_SERVER_TIMING), v);
        }
    }
    resp
}

/// Pure reshaping step of [`reshape_body_limit_413`], split out so it is unit-testable without
/// constructing a `Next`. Returns `resp` unchanged unless it is axum's OWN body-limit 413 —
/// identified by status 413 with a non-JSON content-type AND a body exactly equal to
/// [`AXUM_BODY_LIMIT_413_MARKER`] — in which case it is replaced by the inferred ingress protocol's
/// native JSON `request_too_large` envelope. A 413 a real ingress handler already shaped as
/// `application/json`, or any forward-relayed UPSTREAM 413 (different/non-marker body), is passed
/// through verbatim (the body is buffered to inspect the sentinel, then re-attached unchanged).
async fn reshape_oversized_413(
    path: &str,
    resp: axum::response::Response,
) -> axum::response::Response {
    if resp.status() != axum::http::StatusCode::PAYLOAD_TOO_LARGE {
        return resp;
    }
    // A handler (or upstream relay) that already produced an `application/json` 413 is a native
    // too-large envelope — leave it alone without even buffering the body; re-wrapping would
    // corrupt it, and axum's own body-limit reject is never JSON.
    let is_json = resp
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .is_some_and(|ct| ct.starts_with(crate::proxy::APPLICATION_JSON));
    if is_json {
        return resp;
    }
    // Non-JSON 413: it could be axum's OWN body-limit reject (reshape it) OR a forward-relayed
    // UPSTREAM 413 that happens to be non-JSON (e.g. a `text/plain`/`text/html` upstream error —
    // must pass through untouched). Distinguish by the sentinel body. Buffer the body so
    // we can compare it; if it is not the sentinel, re-attach the buffered bytes verbatim.
    use http_body_util::BodyExt as _;
    let (parts, body) = resp.into_parts();
    let bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        // A 413 body that fails to buffer cannot be confirmed as axum's sentinel; pass the
        // already-consumed parts through with an empty body rather than reshape a non-axum reject.
        Err(_) => return axum::response::Response::from_parts(parts, axum::body::Body::empty()),
    };
    if bytes.as_ref() != AXUM_BODY_LIMIT_413_MARKER {
        // A relayed upstream 413 (or any non-axum 413): pass through untouched, body re-attached.
        return axum::response::Response::from_parts(parts, axum::body::Body::from(bytes));
    }
    fallback_error_response(
        path,
        axum::http::StatusCode::PAYLOAD_TOO_LARGE,
        // CANONICAL kind for an oversized payload across the protocol writers.
        crate::proxy::KIND_REQUEST_TOO_LARGE,
        "request body exceeds the maximum allowed size",
    )
}

/// Everything the DISK half of configuration produces, shared by boot and runtime reload.
pub(crate) struct LoadedConfig {
    pub(crate) deploy: config::DeployCfg,
    pub(crate) defs: HashMap<String, config::ProviderDef>,
    pub(crate) overlay_path: Option<std::path::PathBuf>,
    pub(crate) base_hook_names: std::collections::HashSet<String>,
    /// `${VAR}` refs that were UNSET during interpolation. Empty under Strict (boot/reload); populated
    /// under Lenient (--validate), where it becomes the "set these at runtime" note.
    pub(crate) unset_env_vars: Vec<String>,
}

/// The disk-load pipeline: read providers.yaml + config.yaml, env-interpolate (from the process's
/// boot-time environment — a live reload cannot see edited env files; documented), capture the
/// BASE hook names, then merge the persisted overlay (opt-in, fail-soft). Shared verbatim by boot
/// and `POST /api/v1/admin/config/reload`, so a reload IS a boot-equivalent read of disk truth.
pub(crate) fn load_config_from_disk(
    config_path: &std::path::Path,
    providers_path: &std::path::Path,
    safe_mode: bool,
    env_mode: config::EnvSubst,
) -> Result<LoadedConfig, String> {
    let mut unset_env_vars: Vec<String> = Vec::new();
    let raw_providers = std::fs::read_to_string(providers_path).map_err(|e| {
        format!(
            "cannot read providers file '{}': {e} (set {ENV_PROVIDERS})",
            providers_path.display()
        )
    })?;
    let interpolated_providers =
        config::interpolate_env_with(&raw_providers, env_mode, &mut unset_env_vars)
            .map_err(|e| format!("providers.yaml: {e}"))?;
    let defs: HashMap<String, config::ProviderDef> = serde_yaml::from_str(&interpolated_providers)
        .map_err(|e| format!("providers.yaml: invalid YAML: {e}"))?;

    let raw_config = std::fs::read_to_string(config_path).map_err(|e| {
        format!(
            "cannot read config file '{}': {e} (set {ENV_CONFIG})",
            config_path.display()
        )
    })?;
    let interpolated_config =
        config::interpolate_env_with(&raw_config, env_mode, &mut unset_env_vars)
            .map_err(|e| format!("config.yaml: {e}"))?;
    let mut deploy: config::DeployCfg =
        serde_yaml::from_str(&interpolated_config).map_err(|e| {
            format!(
                "config.yaml: invalid YAML: {}",
                config::augment_config_error(e)
            )
        })?;

    // Config-overlay persistence (opt-in via `BUSBAR_CONFIG_OVERLAY`): capture the BASE hook names
    // BEFORE the overlay merges in API-registered hooks (the admin API refuses to PUT-replace a
    // base hook), then merge. Absent/corrupt overlay is fail-soft.
    let overlay_path = std::env::var("BUSBAR_CONFIG_OVERLAY")
        .ok()
        .filter(|s| !s.is_empty())
        .map(std::path::PathBuf::from);
    let base_hook_names: std::collections::HashSet<String> = deploy.hooks.keys().cloned().collect();
    if safe_mode {
        // `--safe-mode` (D3): boot on the operator-owned base config ALONE — the persisted overlay
        // (API-registered hooks) is quarantined, not deleted. The escape hatch for "an applied
        // hook is harming traffic and re-applies itself every boot".
        tracing::warn!(
            "SAFE MODE: config overlay NOT merged — running on base config.yaml alone (the \
             overlay file is untouched; boot without --safe-mode to re-apply it)"
        );
        return Ok(LoadedConfig {
            deploy,
            defs,
            overlay_path,
            base_hook_names,
            unset_env_vars,
        });
    }
    if let Some(ref p) = overlay_path {
        if let Some(doc) = config::overlay::read(p) {
            tracing::info!(
                path = %p.display(),
                hooks = doc.hooks.len(),
                "merging persisted config overlay onto base config"
            );
            config::overlay::merge_into(&mut deploy, doc);
        }
    }
    Ok(LoadedConfig {
        deploy,
        defs,
        overlay_path,
        base_hook_names,
        unset_env_vars,
    })
}

/// Build a complete `App` from a RESOLVED config — the ONE construction path shared by boot
/// (`prior = None`) and the config plane's apply/reload (`prior = Some(current)`). On apply,
/// process-lifetime state is REUSED from the prior snapshot (HTTP client pool, governance key DB,
/// version history, mutation-rate windows) and the health store is rebuilt with every surviving
/// lane's learned state RESTORED BY STABLE IDENTITY (D1) — so a lane-set change never
/// misattributes or discards breaker/latency knowledge. Errors are returned (never process-exit):
/// boot maps them to `die`, the apply endpoints to `invalid_request` — an invalid apply changes
/// nothing.
///
/// Verify a store plugin's signed manifest against `governance.trust` before it is loaded. Returns
/// `Err` (aborting boot) only when the trust posture is `halt` and the plugin isn't validly signed by
/// an allowlisted publisher; `log`/`alert`/`allow` postures return `Ok` (the load proceeds, and
/// `plugin_trust::verify` has already logged the decision).
fn verify_plugin_trust(
    g: &config::GovernanceCfg,
    lib_path: &std::path::Path,
    store: &str,
) -> Result<(), String> {
    let policy = g
        .trust
        .to_policy()
        .map_err(|e| format!("governance.trust is invalid: {e}"))?;
    plugin_trust::verify(lib_path, &policy).map_err(|reason| {
        format!(
            "governance store '{store}' plugin rejected by the trust policy: {reason}. Sign it with \
             an allowlisted publisher, or relax governance.trust.on_untrusted."
        )
    })?;
    Ok(())
}

pub(crate) fn build_app_from_config(
    cfg: config::RootCfg,
    governance_cfg: Option<config::GovernanceCfg>,
    overlay_path: Option<std::path::PathBuf>,
    base_hook_names: std::collections::HashSet<String>,
    config_paths: (Option<std::path::PathBuf>, Option<std::path::PathBuf>),
    prior: Option<&state::App>,
) -> Result<state::App, String> {
    // Install the resolved operational limits process-wide BEFORE any subsystem reads them —
    // running here (not in main) so a config APPLY/RELOAD refreshes them too. The values threaded
    // explicitly (client/store/router/TLS) read `cfg.limits` directly; the deep call-stack sites
    // (translate-body cap, metrics gauge limit, webhook timeout, governance sqlite/sweep, health
    // probe fallbacks, routing policy timeout) read the installed values.
    limits::install(&cfg.limits);
    // The config version this App will carry — computed ONCE up front because hook-transport
    // resolution stamps it into every socket configure preamble (W-M4: the preamble's
    // settings_version must be the REAL version of the settings it delivers, not a hardcoded 0).
    let app_config_version = prior.map_or(0, |p| p.config_version.wrapping_add(1));
    // Semantic validation — the same gate boot has always had, now on the ONE construction path
    // so an apply/reload validates identically and an invalid config changes nothing.
    if let Err(validation_errors) = config_validate::validate(&cfg) {
        return Err(format!(
            "config validation failed:\n  - {}",
            validation_errors.join("\n  - ")
        ));
    }
    let auth_cfg = cfg
        .auth
        .clone()
        .unwrap_or_else(config::AuthCfg::default_none);
    let mut lanes_data = Vec::new();
    // Validated provider handle for each lane, captured in lockstep with `lanes_data` below. The
    // first loop already resolves `cfg.providers.get(&mc.provider)` (failing loud via `die` on a
    // missing provider), so the lane-build loop reuses that handle instead of re-looking it up —
    // there is no second lookup and no `expect` on the startup path.
    let mut lane_provider_cfgs: Vec<&config::ProviderCfg> = Vec::new();
    let mut by_model = HashMap::new();
    // Per-model configured default_max_tokens (injected at the translation seam for protocols that
    // require max_tokens). Captured here because `cfg.models` is consumed by this loop.
    let mut model_default_max_tokens: std::collections::HashMap<String, Option<u32>> =
        std::collections::HashMap::new();
    // Single source of truth for each provider's resolved API key. The secret-bearing env read
    // happens exactly once per provider here; both the empty-key warning below and the later
    // `Lane.api_key` population reuse this value, so the warning and the captured key can never
    // diverge (and we don't read the same env var twice).
    let mut provider_api_keys: HashMap<String, String> = HashMap::new();
    // Build lanes in a DETERMINISTIC order (sorted by model name) rather than `cfg.models`'
    // HashMap iteration order, which is randomized per process start. Lane index is assigned here
    // (`by_model` → `lanes_data.len()`), so a random iteration order gave each lane a different
    // index every boot — surfacing as non-reproducible `/stats` lane ordering and metric lane-series
    // identity that shifts across restarts (a scrape/dashboard annoyance and a flaky-test source).
    // Sorting makes the whole observable surface stable. (Mirrors the deterministic-resolution fix
    // already applied to `model_context_max` below.)
    let mut sorted_models: Vec<_> = cfg.models.into_iter().collect();
    sorted_models.sort_by(|a, b| a.0.cmp(&b.0));
    for (model, mc) in sorted_models {
        model_default_max_tokens.insert(model.clone(), mc.default_max_tokens);
        let Some(provider_cfg) = cfg.providers.get(&mc.provider) else {
            return Err(format!(
                "model '{model}' references unknown provider '{}'",
                mc.provider
            ));
        };
        let key = provider_api_keys
            .entry(mc.provider.clone())
            .or_insert_with(|| std::env::var(&provider_cfg.api_key_env).unwrap_or_default());
        if key.is_empty() {
            eprintln!(
                "[warn] provider {} key env {} empty",
                mc.provider, provider_cfg.api_key_env
            );
        }
        let limited = mc.max_requests >= 0;
        // `max_concurrent` is an OPT-IN limiter: omitted (None) = UNBOUNDED. Realize "unbounded" as a
        // semaphore seeded with `Semaphore::MAX_PERMITS` (usize::MAX >> 3) — a lane will never reach
        // 2^60 concurrent in-flight requests, so this never throttles, yet it keeps the entire
        // permit-based dispatch path (which every selection route depends on) intact. A literal
        // usize::MAX would PANIC: `Semaphore::new` asserts `permits <= MAX_PERMITS`. `max` records the
        // same count so /stats `inflight = max - available` stays coherent.
        let max_concurrent = mc
            .max_concurrent
            .unwrap_or(tokio::sync::Semaphore::MAX_PERMITS);
        by_model.insert(model.clone(), lanes_data.len());
        lane_provider_cfgs.push(provider_cfg);
        lanes_data.push(LaneData {
            model: model.clone(),
            provider: mc.provider.clone(),
            max: max_concurrent,
            sem: std::sync::Arc::new(tokio::sync::Semaphore::new(max_concurrent)),
            limited,
            budget: if limited { mc.max_requests } else { -1 },
            cooldown_until: 0,
            streak: 0,
            dead: false,
            dead_reason: String::new(),
            ok: 0,
            err: 0,
            client_fault: 0,
            upstream_model: mc.upstream_model.clone(),
            attempt_timeout_ms: mc.attempt_timeout_ms,
            reasoning: mc.reasoning.unwrap_or(false),
            prompt_caching: mc.prompt_caching.unwrap_or(false),
        });

        eprintln!(
            "  model {} via {} ({}) max {}{}",
            model,
            mc.provider,
            provider_cfg.base_url.trim_end_matches('/'),
            // Show the operator-facing form: an omitted cap reads "unbounded", not 2^60.
            match mc.max_concurrent {
                Some(n) => n.to_string(),
                None => "unbounded".to_string(),
            },
            // Surface the alias→wire-id indirection at boot so an operator can see this lane sends a
            // different model string upstream than the config key it's filed under.
            match &mc.upstream_model {
                Some(u) => format!(" → upstream {u}"),
                None => String::new(),
            }
        );
    }

    let registry = ProtocolRegistry::with_builtins();

    // Build a map from model name to context_max. A model is one lane shared across every pool that
    // names it, so its context_max must be single-valued. Previously the last pool to iterate (in
    // nondeterministic HashMap order) silently won, so a model carrying `context_max: Some(128000)`
    // in one pool and `None` (or a different limit) in another could end up with whichever value the
    // iteration happened to land on — defeating the context-length failover exclusion in proxy engine
    // and losing pool-specific limits without a diagnostic. Resolve it deterministically and fail
    // loud on a genuine conflict instead.
    let model_context_max = resolve_model_context_max(&cfg.pools)?;

    let mut lanes = Vec::new();
    for (idx, ld) in lanes_data.iter().enumerate() {
        // Reuse the provider handle resolved (and validated via `die`) in the lanes_data loop above,
        // captured in lockstep into `lane_provider_cfgs`. No redundant re-lookup / `expect` here.
        let provider_cfg = lane_provider_cfgs[idx];
        let Some(protocol) = registry.get(&provider_cfg.protocol) else {
            return Err(format!(
                "provider '{}' uses unknown protocol '{}' (supported: anthropic, openai, gemini, bedrock, responses, cohere)",
                ld.provider, provider_cfg.protocol
            ));
        };
        // Reuse the single env read captured in the lanes_data loop above (same source of truth as
        // the empty-key warning); no second read of the secret-bearing env var.
        let api_key = provider_api_keys
            .get(&ld.provider)
            .cloned()
            .unwrap_or_default();
        // Resolve the outbound credential once. Most auth styles are a simple sync lookup; the OAuth
        // styles parse their credential material here (failing loud on a bad key) and start a
        // background token minter/refresher. `api_key` carries that material.
        //
        // Both OAuth mechanisms vet their token endpoint (oauth `token_url`, jwt-bearer SA `token_uri`)
        // for SSRF against the operator's REAL metadata posture so the boot-time check matches
        // config_validate's validate-time check EXACTLY (validate == apply) and both mechanisms behave
        // identically: the allow-override set is the SAME union config_validate builds (this provider's
        // `allow_metadata_hosts` ∪ the global `security.allow_metadata_hosts`), plus the nuclear
        // `allow_all_metadata` and the operator's extra `blocked_metadata_hosts`. Threading it into
        // jwt-bearer too (1.4.0 audit) means a global `blocked_metadata_hosts` deny is enforced on a jwt
        // `token_uri`, and `allow_all_metadata` uniformly disables the guard for both. (1.4.0 audit.)
        let allow_overrides: Vec<String> = provider_cfg
            .allow_metadata_hosts
            .iter()
            .chain(cfg.allow_metadata_hosts.iter())
            .cloned()
            .collect();
        let ssrf = egress_auth::MetadataSsrfPolicy {
            allow_overrides: &allow_overrides,
            allow_all: cfg.allow_all_metadata,
            blocked_hosts: &cfg.blocked_metadata_hosts,
        };
        let credential = match provider_cfg.auth {
            // `jwt-bearer`: `api_key` is the service-account JSON (inline) or a key-file path. A
            // configured `scope:` overrides the default cloud-platform scope (else `None` → default).
            Some(config::ProviderAuth::JwtBearer) => {
                egress_auth::jwt_bearer::build(&api_key, provider_cfg.scope.as_deref(), &ssrf)
                    .map_err(|e| format!("provider '{}' (jwt-bearer auth): {e}", ld.provider))?
            }
            // `oauth-client-credentials`: `api_key` is `client_id:client_secret`; `token_url`+`scope`
            // come from the provider config (required — the config validator also rejects them absent).
            Some(config::ProviderAuth::OAuthClientCredentials) => {
                let token_url = provider_cfg.token_url.as_deref().ok_or_else(|| {
                    format!(
                        "provider '{}' (oauth-client-credentials auth) requires `token_url`",
                        ld.provider
                    )
                })?;
                let scope = provider_cfg.scope.as_deref().ok_or_else(|| {
                    format!(
                        "provider '{}' (oauth-client-credentials auth) requires `scope`",
                        ld.provider
                    )
                })?;
                egress_auth::oauth_client_credentials::build(&api_key, token_url, scope, &ssrf)
                    .map_err(|e| {
                        format!(
                            "provider '{}' (oauth-client-credentials auth): {e}",
                            ld.provider
                        )
                    })?
            }
            _ => egress_auth::resolve(&provider_cfg.protocol, provider_cfg.auth),
        };
        let base_url = provider_cfg.base_url.trim_end_matches('/').to_string();
        lanes.push(Lane {
            model: ld.model.clone(),
            provider: ld.provider.clone(),
            // Precompute the SigV4 signed-host once at boot (pure function of base_url) so the forward
            // path borrows it into SigningContext instead of re-parsing/allocating it per request.
            signing_host: proxy::host_from_base(&base_url),
            base_url,
            api_key,
            credential,
            protocol,
            max: ld.max,
            error_map: Arc::new(provider_cfg.error_map.clone()),
            context_max: model_context_max.get(&ld.model).copied().flatten(),
            path: provider_cfg.path.clone(),
            path_base: provider_cfg.path_base.clone(),
            health: provider_cfg.health.clone(),
            upstream_model: ld.upstream_model.clone(),
            attempt_timeout_ms: ld.attempt_timeout_ms,
            reasoning: ld.reasoning,
            prompt_caching: ld.prompt_caching,
            default_max_tokens: model_default_max_tokens.get(&ld.model).copied().flatten(),
        });
    }

    let mut pools = HashMap::new();
    for (name, pool) in &cfg.pools {
        // Wire per-member weights from config into the pool structure.
        // Each pool member has a weight; default is 1 if not specified.
        let mut weighted_members: Vec<WeightedLane> = Vec::with_capacity(pool.members.len());
        for m in pool.members.iter() {
            {
                let Some(&lane_idx) = by_model.get(&m.target) else {
                    return Err(format!(
                        "pool '{name}' references unknown model '{}'",
                        m.target
                    ));
                };
                weighted_members.push(WeightedLane {
                    idx: lane_idx,
                    weight: m.weight, // from config PoolMember.weight (default 1)
                    // Per-member attempt cap: one model, different hang budgets per pool/workload.
                    attempt_timeout_ms: m.attempt_timeout_ms,
                    reasoning: m.reasoning,
                });
            }
        }
        pools.insert(name.clone(), weighted_members);
    }

    eprintln!("busbar: {} models, {} pools", lanes.len(), pools.len());
    for (n, wl_vec) in &pools {
        let agg: usize = wl_vec.iter().map(|wl| lanes[wl.idx].max).sum();
        eprintln!(
            "  pool /{} = [{}] aggregate {}",
            n,
            wl_vec
                .iter()
                .map(|wl| lanes[wl.idx].model.clone())
                .collect::<Vec<_>>()
                .join(", "),
            agg
        );
    }

    // Loud warning for an empty `auth.chain` (open relay). Not fatal — busbar still starts (useful for
    // local dev) — but operators must not run this in production. NOTE: an ABSENT `auth:` block
    // serde-defaults to an empty chain too (`AuthCfg::default_none`), so a config that merely omits
    // `auth:` silently becomes an open relay. Surface this at ERROR level (not warn — a warn is
    // suppressed under RUST_LOG=error, the very level an operator most likely runs in production)
    // AND unconditionally on stderr, so the open-relay state cannot be masked by log configuration.
    if let Some(banner) = open_relay_banner(auth_cfg.chain.is_empty(), cfg.auth.is_some()) {
        eprintln!("[error] {banner}");
        tracing::error!("{banner}");
    }

    let auth_mw = Arc::new(AuthMiddleware::new(&auth_cfg));
    // Thread the operator-configured hard-down cooldown + honored-Retry-After ceiling into the store
    // (both default to their historical const at the config layer).
    // D1 carry-over: an APPLY/RELOAD (prior = Some) restores every surviving lane's learned
    // health state BY STABLE IDENTITY from the prior store; boot (None) starts fresh.
    let store: Arc<dyn crate::store::StateStore> = match prior {
        Some(p) => Arc::new(InMemoryStore::new_with_limits_restored(
            lanes_data.clone(),
            cfg.limits.hard_down_cooldown_secs,
            cfg.limits.max_honored_retry_after_secs,
            &p.store.export_health(),
        )),
        None => Arc::new(InMemoryStore::new_with_limits(
            lanes_data.clone(),
            cfg.limits.hard_down_cooldown_secs,
            cfg.limits.max_honored_retry_after_secs,
        )),
    };

    // Global default failover config — the fallback for pools that don't set their own. A fixed
    // default (not "whatever pool HashMap iteration happens to yield first", which was
    // nondeterministic across restarts).
    let failover_cfg = Some(crate::config::FailoverCfg {
        timeout_secs: crate::config::DEFAULT_FAILOVER_DEADLINE_SECS,
        exclusions: None,
        max_hops: crate::config::DEFAULT_FAILOVER_CAP,
    });

    // The fallback-pool routing table: on_exhausted `fallback_pool:<name>` looks a pool up here,
    // so it mirrors the pools map (any pool can be a fallback target).
    let fallback_pools = pools.clone();

    // The shared upstream HTTP client, built ONCE. Constructed before the pool-runtime loop so the
    // webhook routing transport can reuse it (a clone shares the connection pool + the `redirect:none`
    // SSRF posture); the same client is then moved into `App` below.
    let upstream_client = if let Some(p) = prior {
        // REUSED across applies: the pooled connections + their kept-alive upstream sockets.
        p.client.clone()
    } else {
        // Opt-in HTTP/2 PRIOR-KNOWLEDGE for CLEARTEXT upstreams (no TLS/ALPN to negotiate over):
        // `BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE=1` makes the shared client assume h2 without ALPN. This
        // is a PROCESS-WIDE, DEFAULT-OFF switch — production keeps ALPN (safe against h1 upstreams);
        // it exists so a cleartext h2c backend (e.g. the benchmark mock, or an in-mesh h2c service)
        // can exercise multiplexing without TLS. It FORCES h2, so every configured upstream must speak
        // h2c when set — never enable it against a mixed/h1 fleet. Read once at client-build time.
        let h2_prior_knowledge = std::env::var_os("BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE")
            .is_some_and(|v| v != "0" && !v.is_empty());
        // Opt-out ESCAPE HATCH for the ALPN h2 default: `BUSBAR_UPSTREAM_HTTP1_ONLY=1` pins the
        // shared client to HTTP/1.1 (reqwest `.http1_only()`), so ALPN never offers h2 at all. This
        // is a PROCESS-WIDE, DEFAULT-OFF switch — production keeps the ALPN default (h2 where the
        // backend accepts it, h1 otherwise); it exists as an operational rollback lever in case a
        // specific upstream negotiates h2 but misbehaves on it (flow-control stalls, broken
        // keep-alive pings, intermediary bugs) and you need the pre-h2 wire behavior back without a
        // rebuild. Mutually exclusive in spirit with the h2c opt-in above (forcing h1 AND forcing
        // h2 makes no sense); if both are set, http1-only wins because it is applied last. Read
        // once at client-build time.
        let http1_only = std::env::var_os("BUSBAR_UPSTREAM_HTTP1_ONLY")
            .is_some_and(|v| v != "0" && !v.is_empty());
        let mut builder = reqwest::Client::builder().timeout(Duration::from_secs(
            cfg.limits.upstream_request_timeout_secs,
        ));
        builder = builder
            // Bound the TCP connect separately from the coarse overall timeout: a stalled SYN would
            // otherwise hang up to the streaming `.timeout()` (minutes) before failover kicks in.
            .connect_timeout(Duration::from_secs(10))
            // Keep idle upstream sockets alive so a middlebox silently dropping a long-idle
            // keep-alive connection is detected proactively, not discovered as a spurious failure on
            // the next request (added latency + a needless failover hop).
            .tcp_keepalive(Duration::from_secs(60))
            // Disable Nagle's algorithm on the EGRESS sockets. Busbar writes a whole request body in
            // one shot and then immediately awaits the response, so Nagle has nothing to coalesce —
            // but on a small body it interacts with the peer's delayed-ACK to hold the final segment
            // for up to ~40 ms waiting for an ACK that only arrives once the peer's timer fires. That
            // manifests as a bimodal tail-latency spike (a native SDK, which also sets TCP_NODELAY,
            // never sees it) and is pure added latency on the request path. Inbound accepted sockets
            // already set this (tls.rs serve loops); this brings the egress leg to parity. `axum`'s
            // own serve() defaults nodelay on; reqwest does NOT, so it must be set explicitly.
            .tcp_nodelay(true)
            // HTTP/2 to the upstream, NEGOTIATED via ALPN (NOT prior-knowledge): over TLS the client
            // offers `h2,http/1.1` and uses whichever the backend accepts, so an h2-capable provider
            // (Anthropic, OpenAI, Vertex, Bedrock all speak h2) multiplexes many concurrent requests
            // over ONE connection — collapsing the per-request connect+TLS handshake and the socket /
            // epoll pressure that caps proxy RPS on a core-bound box — while an HTTP/1-only backend
            // transparently stays on h1. By DEFAULT we do NOT call `.http2_prior_knowledge()` (that
            // would FORCE h2 and break every h1 upstream and a plaintext h1 mock) — it is applied only
            // when the cleartext-h2c opt-in below is set. H2 keep-alive pings keep a multiplexed
            // connection healthy through idle gaps without the h1 trick of holding N sockets open. No
            // behavior change against an h1-only upstream on the default (ALPN) path.
            .http2_keep_alive_interval(Duration::from_secs(30))
            .http2_keep_alive_timeout(Duration::from_secs(10))
            .http2_adaptive_window(true)
            .pool_max_idle_per_host(cfg.limits.pool_max_idle_per_host)
            // SSRF guard: do NOT follow redirects. The startup SSRF blocklist (config_validate.rs
            // ssrf_blocked_host) only vets the configured base_url; it does not see redirect targets.
            // reqwest's default policy follows up to 10 redirects, so a compromised/malicious upstream
            // could 30x-redirect a vetted base_url to an internal address (169.254.169.254 metadata,
            // localhost, RFC1918) and busbar would follow it — forwarding the signed request
            // (x-api-key / SigV4 Authorization on same-host redirects) to the internal target,
            // defeating the blocklist at runtime. Upstream AI provider APIs do not redirect as part of
            // normal operation, so disabling redirect following entirely closes the vector at no cost.
            .redirect(reqwest::redirect::Policy::none());
        // Cleartext h2c opt-in (bench / in-mesh): FORCE h2 without ALPN. Default-off; when set, every
        // upstream must speak h2c. Applied last so it overrides the ALPN default above.
        if h2_prior_knowledge {
            builder = builder.http2_prior_knowledge();
        }
        // HTTP/1-only escape hatch: pin the client to h1 (no ALPN h2 offer). Applied last so it
        // wins over both the ALPN default and the h2c opt-in above.
        if http1_only {
            builder = builder.http1_only();
        }
        builder.build().expect("build upstream HTTP client")
    };

    // The `default:` hook (if any) — the base ordering that pools which named none inherit, replacing
    // the compiled-in weighted backstop (everything-is-a-hook model). At most one (validated).
    let default_hook = hooks::default_hook_name(&cfg.hooks).map(str::to_string);

    // Per-pool runtime config (failover/exclusions), keyed by pool name.
    let mut pool_runtime = std::collections::HashMap::new();
    for (pool_name, pool_cfg) in &cfg.pools {
        pool_runtime.insert(
            pool_name.clone(),
            state::PoolRuntime {
                failover: pool_cfg.failover.clone(),
                affinity: pool_cfg.affinity.clone(),
                breaker: pool_cfg.breaker.as_ref().map(store::BreakerCfg::from),
                // Operator-declared member metadata (tier/cost/tags) keyed by lane idx, for the
                // routing Candidate projection. Mirrors the WeightedLane construction's target→lane
                // mapping (by_model). Read only inside the policy arm of the seam.
                members: pool_cfg
                    .members
                    .iter()
                    .filter_map(|m| {
                        by_model.get(&m.target).map(|&idx| {
                            (
                                idx,
                                state::MemberMeta {
                                    tier: m.tier.clone(),
                                    cost_per_mtok: m.cost_per_mtok,
                                    tags: m.tags.clone(),
                                },
                            )
                        })
                    })
                    .collect(),
                // Resolve the routing policy ONCE here. `weighted` (default) ⇒ `None` ⇒ the zero-cost
                // inline SWRR path; a `default:` hook replaces that base for pools that named none; the
                // webhook transport reuses the shared upstream client.
                policy: hooks::resolve_pool_ordering(
                    pool_cfg,
                    &cfg.hooks,
                    &upstream_client,
                    default_hook.as_deref(),
                    app_config_version,
                ),
                // This pool's decision gates, resolved once here (priority carried for the phase-2
                // chain merge). NOT re-resolved on config apply yet — same scope caveat as `policy`.
                gates: hooks::resolve_pool_gates(
                    pool_cfg,
                    &cfg.hooks,
                    &upstream_client,
                    app_config_version,
                ),
                rewrite_hooks: hooks::resolve_pool_rewrites(
                    pool_cfg,
                    &cfg.hooks,
                    &upstream_client,
                    app_config_version,
                ),
            },
        );
    }

    // Parse on_exhausted configs per pool
    let mut on_exhausted_cfgs = std::collections::HashMap::new();
    for (pool_name, pool_cfg) in &cfg.pools {
        if let Some(ref on_exc) = pool_cfg.on_exhausted {
            match crate::config::OnExhausted::parse(&on_exc.action) {
                Ok(mode) => {
                    tracing::info!(pool = %pool_name, on_exhausted = ?mode, "pool exhaustion policy");
                    on_exhausted_cfgs.insert(pool_name.clone(), mode);
                }
                Err(e) => {
                    return Err(format!(
                        "pool '{pool_name}' has invalid on_exhausted action '{}': {e}",
                        on_exc.action
                    ))
                }
            }
        } else {
            // Default to Status503 if not specified
            on_exhausted_cfgs.insert(pool_name.clone(), crate::config::OnExhausted::Status503);
        }
    }

    // Capture the plugin-directory + trust posture for the Admin API plugin surface BEFORE
    // `governance_cfg` is consumed by the store-load branch below. These ride on the `App` snapshot so
    // the catalog/install/remove/reload endpoints resolve the SAME directory + posture the boot
    // store-load uses. Absent `governance:` ⇒ the defaults (`plugins`, `on_untrusted: log`).
    let (plugins_dir, plugin_trust) = governance_cfg.as_ref().map_or_else(
        || {
            let d = config::GovernanceCfg::default();
            (
                std::path::PathBuf::from(d.plugins_dir),
                config::PluginTrustCfg::default(),
            )
        },
        |g| {
            (
                std::path::PathBuf::from(g.plugins_dir.clone()),
                g.trust.clone(),
            )
        },
    );

    // open the governance store + load the virtual-key cache when enabled.
    let governance = if let Some(p) = prior {
        // REUSED across applies: the keys + spend/rate state must survive config changes.
        p.governance.clone()
    } else {
        // Governance is ALWAYS available (it is inert until an admin token is set and virtual keys are
        // minted). Only the STORE backend is a choice: ephemeral RAM by default, or a durable store the
        // operator configures. An absent `governance:` section is the RAM default.
        let g = governance_cfg.unwrap_or_default();
        let store: Arc<dyn governance::Store> = match g.store {
            crate::config::GovernanceStore::Sqlite => {
                // The SQLite store is a dynamic-library plugin loaded from the plugins directory (no
                // longer compiled in). Resolve the platform-native library name, pass the store's
                // config as JSON, and load it over the C ABI.
                let libname =
                    busbar_plugin_loader::plugin_library_filename("busbar_store_sqlite_plugin");
                let lib_path = std::path::Path::new(&g.plugins_dir).join(&libname);
                let cfg_json = serde_json::json!({
                    "db_path": g.db_path,
                    "busy_timeout_ms": g.sqlite_busy_timeout_ms,
                })
                .to_string();
                verify_plugin_trust(&g, &lib_path, "sqlite")?;
                match busbar_plugin_loader::load_store(&lib_path, &cfg_json) {
                    Ok(s) => Arc::from(s),
                    Err(e) => {
                        return Err(format!(
                            "governance store 'sqlite' plugin load failed: {e}. Install the SQLite \
                             store plugin ({libname}) into the plugins directory ({}), or set \
                             governance.store: memory.",
                            g.plugins_dir
                        ))
                    }
                }
            }
            crate::config::GovernanceStore::Postgres => {
                // Postgres is the shared, multi-node store — also a plugin. `db_path` carries the
                // libpq connection URL here (see config), passed to the plugin as its `url`.
                let libname =
                    busbar_plugin_loader::plugin_library_filename("busbar_store_postgres_plugin");
                let lib_path = std::path::Path::new(&g.plugins_dir).join(&libname);
                let cfg_json = serde_json::json!({ "url": g.db_path }).to_string();
                verify_plugin_trust(&g, &lib_path, "postgres")?;
                match busbar_plugin_loader::load_store(&lib_path, &cfg_json) {
                    Ok(s) => Arc::from(s),
                    Err(e) => {
                        return Err(format!(
                            "governance store 'postgres' plugin load failed: {e}. Install the \
                             Postgres store plugin ({libname}) into the plugins directory ({}), set \
                             governance.db_path to your postgres:// URL, or set governance.store: \
                             memory.",
                            g.plugins_dir
                        ))
                    }
                }
            }
            crate::config::GovernanceStore::Redis => {
                // Redis is the shared, multi-node KV store — also a plugin. `db_path` carries the
                // redis:// connection URL here (see config), passed to the plugin as its `url`.
                let libname =
                    busbar_plugin_loader::plugin_library_filename("busbar_store_redis_plugin");
                let lib_path = std::path::Path::new(&g.plugins_dir).join(&libname);
                let cfg_json = serde_json::json!({ "url": g.db_path }).to_string();
                verify_plugin_trust(&g, &lib_path, "redis")?;
                match busbar_plugin_loader::load_store(&lib_path, &cfg_json) {
                    Ok(s) => Arc::from(s),
                    Err(e) => {
                        return Err(format!(
                            "governance store 'redis' plugin load failed: {e}. Install the Redis \
                             store plugin ({libname}) into the plugins directory ({}), set \
                             governance.db_path to your redis:// URL, or set governance.store: \
                             memory.",
                            g.plugins_dir
                        ))
                    }
                }
            }
            crate::config::GovernanceStore::Memory => {
                tracing::warn!(
                    "governance store: in-memory (ephemeral) — keys, budgets, and usage reset on \
                     restart; configure a durable store for persistence"
                );
                Arc::new(governance::MemoryStore::new())
            }
        };
        match governance::GovState::new(
            store,
            g.price_per_request_cents,
            g.price_per_1k_tokens_cents,
            g.admin_token.clone(),
        ) {
            Ok(gs) => {
                let gs = Arc::new(gs);
                // BOOT-ONLY crash-recovery: hydrate the in-memory budget cells from the durable store
                // so a restart resumes enforcement from persisted spend. A no-op for the empty RAM store.
                gs.hydrate_budgets(crate::store::now());
                // INERT-KEYS GUARD: a durable store may carry virtual keys minted in a prior run
                // whose admin_token was later REMOVED from config — governance then goes inert and
                // those keys' per-key controls are silently bypassed (access falls to the static
                // auth.chain). Surface it LOUD: ERROR level (survives RUST_LOG=error) AND
                // unconditionally on stderr, mirroring the open-relay banner so log config can't mask
                // it. RAM stores can't reach this state, so `key_count` there is 0 (or the store is
                // non-durable) and the banner is None. `all_keys()` failure is non-fatal — treat as 0
                // keys (the enforcement gate is unaffected; we only lose the advisory).
                let store_is_durable = g.store != crate::config::GovernanceStore::Memory;
                let key_count = gs.all_keys().map(|k| k.len()).unwrap_or(0);
                let admin_token_set = g
                    .admin_token
                    .as_deref()
                    .is_some_and(|t| !t.trim().is_empty());
                if let Some(banner) =
                    inert_durable_keys_banner(store_is_durable, key_count, admin_token_set)
                {
                    eprintln!("[error] {banner}");
                    tracing::error!("{banner}");
                }
                Some(gs)
            }
            Err(e) => return Err(format!("governance init failed: {e}")),
        }
    };

    // Resolve the global rewrite hooks (prompt: rw gates in global_hooks) into priority-ordered
    // transports ONCE. Empty unless the operator configured a rewrite hook — zero cost by default.
    let rewrite_hooks = hooks::resolve_rewrite_hooks(
        &cfg.hooks,
        &cfg.global_hooks,
        &upstream_client,
        app_config_version,
    );
    // Resolve the global request-stage tap hooks the same way. Empty unless configured.
    let tap_hooks = hooks::resolve_tap_hooks(
        &cfg.hooks,
        &cfg.global_hooks,
        &upstream_client,
        app_config_version,
        config::HookStage::Request,
    );
    let tap_hooks_route = hooks::resolve_tap_hooks(
        &cfg.hooks,
        &cfg.global_hooks,
        &upstream_client,
        app_config_version,
        config::HookStage::Route,
    );
    let tap_hooks_attempt = hooks::resolve_tap_hooks(
        &cfg.hooks,
        &cfg.global_hooks,
        &upstream_client,
        app_config_version,
        config::HookStage::Attempt,
    );
    let tap_hooks_completion = hooks::resolve_tap_hooks(
        &cfg.hooks,
        &cfg.global_hooks,
        &upstream_client,
        app_config_version,
        config::HookStage::Completion,
    );
    // Resolve the global DECISION gates (non-rewrite gates in global_hooks) — fired for a verdict on
    // every request. Empty unless configured.
    let global_gates = hooks::resolve_gate_hooks(
        &cfg.hooks,
        &cfg.global_hooks,
        &upstream_client,
        app_config_version,
    );

    Ok(App {
        lanes,
        store,
        by_model,
        pools,
        client: upstream_client.clone(),
        auth: auth_mw.clone(),
        rewrite_hooks,
        tap_hooks,
        tap_hooks_route,
        tap_hooks_attempt,
        tap_hooks_completion,
        global_gates,
        hook_registry: cfg.hooks.clone(),
        global_hooks: cfg.global_hooks.clone(),
        // History + rate windows are Arc-shared across applies (process-lifetime state).
        versions: prior.map_or_else(
            || Arc::new(admin::versions::VersionLog::new()),
            |p| p.versions.clone(),
        ),
        mutation_limiter: prior.map_or_else(
            || Arc::new(admin::rate::MutationLimiter::new()),
            |p| p.mutation_limiter.clone(),
        ),
        idempotency_cache: prior.map_or_else(
            || Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            |p| p.idempotency_cache.clone(),
        ),
        base_hook_names,
        admin_chain: cfg.admin_auth.clone(),
        credential_cache: prior.map_or_else(
            || Arc::new(auth_cache::CredentialCache::new()),
            |p| p.credential_cache.clone(),
        ),
        auth_modules: cfg
            .auth
            .as_ref()
            .map(|a| a.modules.clone())
            .unwrap_or_default(),
        group_map: cfg.group_map.clone(),
        config_path: config_paths.0,
        providers_path: config_paths.1,
        overlay_path,
        config_version: app_config_version,
        failover_cfg,
        pool_runtime,
        fallback_pools,
        on_exhausted_cfgs,
        governance,
        plugins_dir,
        plugin_trust,
        default_max_tokens: cfg.limits.default_max_tokens,
        reasoning_effort_budgets: {
            let b = cfg.limits.reasoning_effort_budgets;
            [b.minimal, b.low, b.medium, b.high]
        },
    })
}

/// Build the busbar HTTP router for a given `App` state with default limits. Factored out so the
/// full route table + auth middleware can be exercised end-to-end in tests; production (`main`) calls
/// `build_router_with_limits` with the operator-configured values, so this convenience wrapper is
/// reached only from the test harness.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn build_router(app: std::sync::Arc<state::App>) -> Router {
    // Convenience builder for tests / callers without an explicit limits handle: the historical 32
    // MiB body cap (via the installed `limits`, falling back to the default when uninstalled) and NO
    // inbound-concurrency layer (`0` = unlimited) — byte-for-byte today's behavior. Production goes
    // through `build_router_with_limits` with the operator-configured values.
    build_router_with_limits(
        app,
        limits::translate_body_max_bytes(),
        crate::config::DEFAULT_MAX_INBOUND_CONCURRENT,
        crate::config::DEFAULT_EMIT_SERVER_TIMING,
    )
    .0
}

/// Router builder with EXPLICIT limits, building the COMBINED router (admin mounted on the data
/// routes). Used only by the test harness (`build_router`) to exercise the full route table + auth
/// middleware end-to-end on one router; production always serves admin on its OWN listener via
/// `build_split_routers_with_limits`, so admin and data never share a listener at runtime.
/// `max_inbound_concurrent == 0` ⇒ NO concurrency layer (a true no-op); `> 0` wraps the whole router
/// in a tower `GlobalConcurrencyLimitLayer` as the OUTERMOST layer.
#[cfg_attr(not(test), allow(dead_code))]
fn build_router_with_limits(
    app: std::sync::Arc<state::App>,
    request_body_max_bytes: usize,
    max_inbound_concurrent: usize,
    emit_server_timing: bool,
) -> (Router, std::sync::Arc<state::AppHandle>) {
    let handle = std::sync::Arc::new(state::AppHandle::new(app));
    // TEST-ONLY combined router: mount the Admin API v1 onto the DATA route table so one router
    // exercises the whole surface. Production never does this — `build_split_routers_with_limits`
    // mounts admin on its OWN router served on a separate listener.
    let router = admin::transport::mount(base_data_router(), &admin::JsonV1);
    let router = apply_common_layers(router, &handle, request_body_max_bytes, emit_server_timing);
    (
        apply_inbound_concurrency_limit(router, max_inbound_concurrent),
        handle,
    )
}

/// The DATA-plane route table — protocols, discovery, and health/metrics/stats — WITHOUT the admin
/// surface. Pre-state (`Router<Arc<AppHandle>>`); the admin API is mounted separately (onto this
/// router in the single-listener case, or onto its own router in the split case) so it can move to
/// a dedicated listener without any of these routes coming with it.
fn base_data_router() -> Router<std::sync::Arc<state::AppHandle>> {
    Router::new()
        .route("/stats", get(endpoints::stats))
        .route("/healthz", get(endpoints::healthz))
        .route("/metrics", get(metrics::handler))
        // The Prometheus scrape of HOOK-reported metrics — a SEPARATE exposition from busbar's own
        // `/metrics` so a hook can never type-conflict or shadow a first-party series. Verbatim hook
        // metric names + an auto `hook="<name>"` label, so an external dashboard built against a hook
        // repoints here and just works. Stale-while-revalidate; never blocks on a hook socket.
        .route("/metrics/hooks", get(crate::hooks::scrape::handler))
        // busbar's OWN API keeps explicit routes (it is not a protocol dialect): discovery,
        // health/metrics/stats above, and the named/adhoc conveniences below.
        // OpenAI list-models: SDKs call `models.list()` first; UIs build pickers from it.
        // Governance-scoped like /stats (restricted keys see only their reachable names).
        .route("/v1/models", get(endpoints::list_models))
        .route("/v1beta/models", get(endpoints::list_models_v1beta))
        .route("/{name}/v1/messages", post(ingress::named))
        .route("/{provider}/{model}/v1/messages", post(ingress::adhoc))
        // EVERY protocol endpoint — chat and the 1.2 operations, all six dialects — flows through the
        // catch-all: Router (dumb protocol ID from path+headers) → that protocol's RequestHandler
        // (reads path+body, decides the operation) → its OperationHandler cell. Adding a protocol or
        // an operation never touches this file. Unknown paths / wrong methods keep the pre-collapse
        // native-envelope 404/405 shaping (no bare-proxy tells).
        .fallback(ingress::protocol_dispatch)
        // Wrong-method hits on a VALID path (axum's built-in 405) get the same native-envelope
        // treatment as the 404 fallback above.
        .method_not_allowed_fallback(method_not_allowed_handler)
}

/// Apply the shared middleware stack — auth chain, request-body cap, 413 reshaping, server-timing —
/// and bind the swappable `AppHandle` state. Identical for the single-listener router and each
/// split-plane router, so both planes get the SAME auth + limit posture and both see config-apply
/// hot-swaps (they share one `handle`).
fn apply_common_layers(
    router: Router<std::sync::Arc<state::AppHandle>>,
    handle: &std::sync::Arc<state::AppHandle>,
    request_body_max_bytes: usize,
    emit_server_timing: bool,
) -> Router {
    let router = router
        // The router's state is a swappable `AppHandle` (the config-apply hot-swap seam). Every
        // handler reads the CURRENT snapshot via the `CurrentApp` extractor; the auth middleware
        // loads it too. Until an admin apply calls `swap()`, this is identical to a fixed `Arc<App>`.
        .layer(axum::middleware::from_fn_with_state(
            handle.clone(),
            auth::auth_middleware,
        ))
        // Cap request body size (buffered before the handler) to bound per-request memory. Driven by
        // `limits.request_body_max_bytes` (default 32 MiB); COUPLED with the egress translate-body cap
        // (`limits::translate_body_max_bytes`) — both read the SAME knob so an accepted request is
        // always buffer-translatable on the cross-protocol path.
        .layer(axum::extract::DefaultBodyLimit::max(request_body_max_bytes))
        // Outermost: reshape the body-limit layer's bare-text 413 into a protocol-native JSON
        // envelope. Must wrap the `DefaultBodyLimit` layer above, so it is applied LAST (the last
        // `.layer()` is the outermost on the response path) and therefore sees that layer's 413.
        .layer(axum::middleware::from_fn(reshape_body_limit_413));
    // Outermost: stamp the `Server-Timing: busbar;dur=<ms>` gateway-overhead header on every
    // response (times the full inner stack). Must be the LAST `.layer()` so it wraps everything.
    // Gated on `observability.emit_server_timing` (default false): when false the header is fully
    // suppressed (see `server_timing`). The `bool` state is independent of the router's `App`
    // state, so it is wired with its own `from_fn_with_state`.
    let router = router.layer(axum::middleware::from_fn_with_state(
        emit_server_timing,
        server_timing,
    ));
    router.with_state(handle.clone())
}

/// Build SEPARATE data-plane and admin-plane routers sharing ONE `AppHandle`, for the split-listener
/// deployment (`admin_listen` set). The admin surface is mounted ONLY on the admin router — it is
/// absent from the data router, so the data listener physically cannot serve `/api/v1/admin/*` (no
/// double-exposure: the whole point of splitting is that admin is not reachable on the public bind).
/// Both planes carry the identical middleware stack; the inbound-concurrency cap applies to the DATA
/// plane only (the low-volume admin plane is uncapped, matching today's default). Returns
/// `(data_router, admin_router, shared_handle)`.
fn build_split_routers_with_limits(
    app: std::sync::Arc<state::App>,
    request_body_max_bytes: usize,
    max_inbound_concurrent: usize,
    emit_server_timing: bool,
) -> (Router, Router, std::sync::Arc<state::AppHandle>) {
    let handle = std::sync::Arc::new(state::AppHandle::new(app));
    // DATA plane: protocols + health/metrics/stats, NO admin mount.
    let data = apply_common_layers(
        base_data_router(),
        &handle,
        request_body_max_bytes,
        emit_server_timing,
    );
    let data = apply_inbound_concurrency_limit(data, max_inbound_concurrent);
    // ADMIN plane: a liveness probe (unauthenticated, like the data plane's) + the admin surface,
    // nothing else. `/healthz` bypasses auth so probes work on the admin port too; every
    // `/api/v1/admin/*` route stays behind the admin auth chain.
    let admin = admin::transport::mount(
        Router::new().route("/healthz", get(endpoints::healthz)),
        &admin::JsonV1,
    );
    let admin = apply_common_layers(admin, &handle, request_body_max_bytes, emit_server_timing);
    (data, admin, handle)
}

/// OUTERMOST inbound-concurrency cap. `max_inbound_concurrent == 0` (the default) returns the router
/// UNCHANGED — NO layer is added, a true no-op so nothing changes unless an operator opts in. When
/// `> 0`, a tower `GlobalConcurrencyLimitLayer` (ONE shared semaphore across ALL requests) wraps the
/// whole router: requests beyond the cap queue for a permit rather than overrunning. Applied as the
/// last `.layer()` so it is outermost (it must admission-control before any inner work, including body
/// buffering). Factored out so the add-only-when-`>0` rule is unit-testable in isolation.
fn apply_inbound_concurrency_limit(router: Router, max_inbound_concurrent: usize) -> Router {
    if max_inbound_concurrent > 0 {
        router.layer(tower::limit::GlobalConcurrencyLimitLayer::new(
            max_inbound_concurrent,
        ))
    } else {
        router
    }
}

#[cfg(test)]
#[path = "tests/tests.rs"]
mod tests;
