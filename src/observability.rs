// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! Observability sinks beyond Prometheus `/metrics`: a best-effort request-log webhook and
//! OTLP trace export. Both are opt-in via the `observability` config section; with no
//! config they are no-ops. State lives in process-wide `OnceLock`s (set once at startup) so the
//! request path can reach it without threading new fields through `App` and its many constructors.

use reqwest::Client;
use serde_json::Value;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::sync::Semaphore;

/// The configured webhook URL, stored as an `Arc<String>` so the per-request fast path in
/// `fire_request_log` clones a reference-count bump (8 bytes) rather than heap-copying the whole URL
/// on every served request. The outer `Option` is gone: an UNSET `OnceLock` (webhook disabled, or a
/// URL that failed validation) is the "not configured" signal, so there is no per-request
/// `Option<String>::clone` allocation on the hot path.
static WEBHOOK_URL: OnceLock<Arc<String>> = OnceLock::new();
static CLIENT: OnceLock<Client> = OnceLock::new();

/// Cap on in-flight request-log deliveries. The webhook is an explicitly best-effort telemetry
/// sink: a slow or unreachable endpoint must NOT let delivery tasks (each holding a connection
/// attempt + the serialized payload) accumulate up to `RPS * timeout` and compete with serving for
/// memory, file descriptors, and connection-pool slots. When the cap is reached we drop the log.
const MAX_INFLIGHT_WEBHOOK_DELIVERIES: usize = 64;
/// Per-delivery timeout for the webhook POST, independent of the (much larger) upstream request
/// timeout the shared client is built with — telemetry must give up quickly.
const WEBHOOK_DELIVERY_TIMEOUT: Duration = Duration::from_secs(2);

static WEBHOOK_INFLIGHT: Semaphore = Semaphore::const_new(MAX_INFLIGHT_WEBHOOK_DELIVERIES);

/// RAII release of one `WEBHOOK_INFLIGHT` slot. We acquire the permit synchronously WITHOUT awaiting
/// (`try_acquire`) and `forget()` it so the slot is held across the spawned delivery without
/// fighting the borrow checker over the `'static` semaphore. Releasing via this guard's `Drop`
/// (rather than a manual `add_permits(1)` at the tail of the task) means the slot is returned even
/// if the delivery task PANICS — a manual release at the end of the closure would be skipped on
/// unwind, permanently leaking the slot and, after `MAX_INFLIGHT_WEBHOOK_DELIVERIES` panics,
/// silently dropping every subsequent log forever.
struct InflightGuard;

impl Drop for InflightGuard {
    fn drop(&mut self) {
        WEBHOOK_INFLIGHT.add_permits(1);
    }
}

/// True when `url`'s scheme equals `scheme` (an all-lowercase ASCII scheme word like `https`),
/// compared CASE-INSENSITIVELY per RFC 3986 §3.1. Matches `<scheme>://...`; the `://` is required so
/// `httpsx://` does not match `https`. Avoids the case-sensitivity bug in a raw
/// `starts_with("https://")`, which rejects the valid uppercase spelling `HTTPS://host/` that
/// reqwest's `Url::parse` would happily lowercase and accept.
fn scheme_is(url: &str, scheme: &str) -> bool {
    url.split_once("://")
        .is_some_and(|(s, _)| s.eq_ignore_ascii_case(scheme))
}

/// Validate the configured webhook URL. Two guarantees, both enforced (not just documented):
///   1. The scheme MUST be `https` (compared case-insensitively, so `HTTPS://` is accepted) — a
///      plaintext `http://` endpoint would expose per-request metadata on the wire.
///   2. The host MUST NOT be an internal target — loopback / link-local / private (RFC1918) / RFC6598
///      CGNAT / unspecified / broadcast, whether written as a canonical IP literal, an IPv4-mapped
///      IPv6 literal, or an alternate IPv4 encoding (decimal/hex/octal/short-dotted) the resolver
///      still expands; nor a loopback (`localhost`) or cloud-metadata (`metadata.google.internal`)
///      DNS name. The URL may not point at `169.254.169.254` cloud-metadata, `127.0.0.1`,
///      `10.x`/`192.168.x`/`172.16.x` internal services, etc.
///
/// This guard is a SIBLING of `config_validate::ssrf_blocked_host`, not an exact mirror of it — the
/// two cover the same threat (operator-supplied URL pointed at an internal target) but DIVERGE in
/// these respects, so do NOT assume bit-for-bit parity:
///   - HOST PARSING: this validator runs the already-`reqwest::Url::parse`d URL and reads
///     `host_str()` (the URL crate has already percent-decoded and normalized the authority);
///     `ssrf_blocked_host` instead parses the raw config string by hand and percent-decodes the host
///     itself (`percent_decode_host`) to neutralize spellings like `169%2E254%2E169%2E254`.
///   - BROADCAST: this guard ALSO blocks `255.255.255.255` (`is_broadcast()`); `ssrf_blocked_host`
///     does not — so this validator is strictly more conservative on that one literal.
///   - LIST SHAPE: here `localhost`/`*.localhost` are handled in the DNS arm of `host_is_internal`
///     and `METADATA_HOSTS` holds only the two metadata names, whereas `ssrf_blocked_host` keeps
///     `localhost`/`localhost.` inside its own `METADATA_HOSTS`. The blocked SET is equivalent for
///     the localhost family; only the code structure differs.
///
/// `None` (webhook disabled) is always valid. Pure, so it is unit-testable without touching the
/// process-wide `OnceLock`s.
fn validate_webhook_url(url: Option<String>) -> Result<Option<String>, String> {
    let Some(u) = url else {
        return Ok(None);
    };
    // Case-INSENSITIVE scheme check: per RFC 3986 the scheme is case-insensitive, and reqwest's
    // `Url::parse` lowercases it — so a valid `HTTPS://host/` (or mixed-case `Https://`) would be
    // wrongly rejected by a literal `starts_with("https://")` on the raw string. Compare the scheme
    // (everything up to and including `://`) without allocating by lowercasing only that prefix.
    if !scheme_is(&u, "https") {
        return Err(format!(
            "observability.request_log_webhook_url must be an https:// URL (got '{u}')"
        ));
    }
    let parsed = reqwest::Url::parse(&u)
        .map_err(|e| format!("observability.request_log_webhook_url is not a valid URL: {e}"))?;
    if host_is_internal(&parsed) {
        return Err(format!(
            "observability.request_log_webhook_url must not target a loopback/link-local/private/\
             CGNAT/cloud-metadata host (SSRF guard); got '{u}'"
        ));
    }
    Ok(Some(u))
}

/// Well-known cloud-metadata / internal DNS names that must be blocked even though they are not IP
/// literals (they resolve, at connect time, to the IMDS family). This holds ONLY the two metadata
/// names; the `localhost` / `*.localhost` family is blocked separately in the `Err(_)` DNS arm of
/// `host_is_internal`. `config_validate::ssrf_blocked_host` folds `localhost`/`localhost.` into its
/// own `METADATA_HOSTS` instead — so this const is a SUBSET of that list, not an exact copy, even
/// though the two guards block the same set of names overall.
const METADATA_HOSTS: &[&str] = &["metadata.google.internal", "metadata.internal"];

/// RFC 6598 Shared Address Space `100.64.0.0/10` (a.k.a. CGNAT). NOT covered by
/// `Ipv4Addr::is_private()`, yet routable inside AWS/GCP VPCs and many Kubernetes clusters where it
/// fronts internal services — an SSRF target the private/link-local checks miss. The /10 is the set
/// of addresses whose first octet is `100` and whose top two bits of the second octet are `01`.
/// Mirrors `config_validate::is_cgnat_shared_v4`.
fn is_cgnat_shared_v4(v4: &std::net::Ipv4Addr) -> bool {
    let o = v4.octets();
    o[0] == 100 && (o[1] & 0xC0) == 64
}

/// True for an IPv4 literal busbar must not POST telemetry to. Shared by the V4 arm and the
/// IPv4-mapped-IPv6 arm so the two stay identical. Covers loopback, link-local (incl. the
/// `169.254.169.254` IMDS endpoint), RFC1918 private, RFC6598 CGNAT, unspecified, and broadcast.
fn is_internal_v4(v4: &std::net::Ipv4Addr) -> bool {
    v4.is_loopback()
        || v4.is_link_local()
        || v4.is_private()
        || is_cgnat_shared_v4(v4)
        || v4.is_unspecified()
        || v4.is_broadcast()
}

/// True when `host` is an alternate (non-dotted-quad) IPv4 encoding that `IpAddr::from_str` rejects
/// but the OS resolver (glibc `getaddrinfo`, used by reqwest's default resolver) still maps to an
/// IPv4 address: a bare decimal integer (`2130706433` = 127.0.0.1), a `0x`/`0X` hex literal
/// (`0x7f000001`), a leading-zero octal literal (`017700000001`), or a dotted form with FEWER than
/// four octets (`127.1`, `10.0.1`). These bypass the canonical IP-literal checks while still
/// resolving to loopback / link-local / private targets at connect time, so they must be treated as
/// blocked. A canonical four-octet dotted-quad is NOT matched here (it is handled by the
/// `parse::<IpAddr>()` path); a normal DNS hostname is not matched either. Mirrors
/// `config_validate::is_alternate_ipv4_encoding`.
fn is_alternate_ipv4_encoding(host: &str) -> bool {
    if host.is_empty() {
        return false;
    }

    // Whole-host `0x...` / `0X...` hex literal (e.g. `0x7f000001`). Only when there is no `.`; a
    // dotted per-octet hex form (`0x7f.0.0.1`) is handled by the dotted branch below.
    if !host.contains('.') {
        if let Some(hex) = host.strip_prefix("0x").or_else(|| host.strip_prefix("0X")) {
            return !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit());
        }
    }

    // Dotted form: split on '.'. A canonical dotted-quad has exactly 4 parts and parses via
    // `IpAddr` — leave it to that path. Fewer than 4 numeric parts (e.g. `127.1`, `10.0.1`) is an
    // alternate short form getaddrinfo expands; flag it. Any part using a `0x` hex or leading-zero
    // octal encoding is also an alternate form.
    if host.contains('.') {
        let parts: Vec<&str> = host.split('.').collect();
        // Every part must be a numeric encoding (decimal, hex, or octal) for this to be an IP-ish
        // host at all; if any part has a non-numeric character it's a DNS name → not our concern.
        let all_numeric = parts.iter().all(|p| {
            if let Some(hex) = p.strip_prefix("0x").or_else(|| p.strip_prefix("0X")) {
                !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit())
            } else {
                !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())
            }
        });
        if !all_numeric {
            return false;
        }
        // Short dotted form (fewer than 4 parts) is an alternate encoding getaddrinfo expands.
        if parts.len() < 4 {
            return true;
        }
        // Four numeric parts: alternate iff any part is hex (`0x`) or leading-zero octal.
        return parts.iter().any(|p| {
            p.starts_with("0x")
                || p.starts_with("0X")
                || (p.len() > 1 && p.starts_with('0') && p.bytes().all(|b| b.is_ascii_digit()))
        });
    }

    // No '.', not `0x`: a bare all-digits host is a decimal integer IP encoding (e.g. `2130706433`).
    host.bytes().all(|b| b.is_ascii_digit())
}

/// True if the URL's host is an address busbar must not POST telemetry to: a literal loopback,
/// link-local (incl. `169.254.169.254` cloud-metadata), private (RFC1918 / unique-local), RFC6598
/// CGNAT, unspecified, or broadcast IP — whether written as a canonical IP literal, an IPv4-mapped
/// IPv6 literal, or one of the alternate IPv4 encodings the OS resolver still expands to an internal
/// address (decimal `2130706433`, hex `0x7f000001`, octal, short-dotted `127.1`). A hostname that
/// does not parse as an IP literal is allowed (operators may name an external collector) EXCEPT the
/// well-known loopback DNS name `localhost` (and its dotted subdomains) and the cloud-metadata DNS
/// names in `METADATA_HOSTS`, which are blocked case-insensitively so an `https://localhost:<port>/`
/// or `https://metadata.google.internal/` URL can't be used to POST request logs to a co-located /
/// metadata process.
///
/// This shares its threat model with `config_validate::ssrf_blocked_host` but is NOT a bit-for-bit
/// mirror — the divergences are (1) host parsing: this guard reads the host from an already
/// `reqwest::Url::parse`d URL, while `ssrf_blocked_host` hand-parses and percent-decodes the raw
/// config string; (2) broadcast: this guard ALSO blocks `255.255.255.255`, which `ssrf_blocked_host`
/// does not; (3) code shape: `localhost`/`*.localhost` are matched in the `Err(_)` DNS arm below
/// rather than via the `METADATA_HOSTS` list. The blocked localhost/metadata/IP SET is equivalent
/// apart from the broadcast literal. Full DNS-rebinding is out of scope for a startup-validated,
/// operator-supplied URL. Returns `true` (reject) when the host is missing entirely.
fn host_is_internal(url: &reqwest::Url) -> bool {
    use std::net::IpAddr;
    match url.host_str() {
        None => true,
        Some(host) => {
            // `Url::host_str` keeps IPv6 literals bracketed; strip for `IpAddr` parsing.
            let host = host.strip_prefix('[').unwrap_or(host);
            let host = host.strip_suffix(']').unwrap_or(host);
            // Strip a single trailing FQDN-root dot BEFORE every check. `Url` preserves it, and
            // getaddrinfo resolves `127.0.0.1.` / `metadata.google.internal.` / `localhost.` to the
            // SAME internal targets as the bare spelling — but without stripping here, the trailing
            // dot makes the IP-literal parse fail (slipping into the DNS arm) and the METADATA_HOSTS
            // exact-compare miss (lengths differ by one), so a trailing-dot host bypassed BOTH the
            // metadata and IP-literal guards. Mirrors `config_validate::ssrf_blocked_host`.
            let host = host.strip_suffix('.').unwrap_or(host);

            // Cloud-metadata DNS names (e.g. `metadata.google.internal`) resolve to internal/IMDS
            // targets but are not IP literals, so check them BEFORE the parse() fallthrough.
            if METADATA_HOSTS.iter().any(|m| host.eq_ignore_ascii_case(m)) {
                return true;
            }

            // Alternate IPv4 encodings that `parse::<IpAddr>()` rejects but the resolver expands to an
            // internal address (decimal/hex/octal/short-dotted). Block BEFORE the parse() fallthrough,
            // which would otherwise treat them as opaque (allowed) DNS names.
            if is_alternate_ipv4_encoding(host) {
                return true;
            }

            match host.parse::<IpAddr>() {
                Ok(IpAddr::V4(v4)) => is_internal_v4(&v4),
                Ok(IpAddr::V6(v6)) => {
                    // Catch `::1` FIRST: under `to_ipv4()` (below) loopback `::1` canonicalizes to
                    // `0.0.0.1`, which is NOT a V4 loopback, so the embedded-V4 arm would miss it —
                    // `is_loopback()` covers it here.
                    if v6.is_loopback() {
                        return true;
                    }
                    // Canonicalize an embedded IPv4 address FIRST and apply the V4 predicates:
                    // otherwise `[::ffff:127.0.0.1]` / `[::169.254.169.254]` parse as V6, match none
                    // of the V6 predicates below, and reach loopback / cloud-metadata — defeating the
                    // guard. Use `to_ipv4()` rather than `to_ipv4_mapped()`: it is a SUPERSET that
                    // ALSO covers the IPv4-COMPATIBLE form (`[::a.b.c.d]`, e.g. `[::127.0.0.1]` /
                    // `[::169.254.169.254]`), where the leading `segments()[0] == 0` makes the
                    // ULA/link-local masks below miss and `to_ipv4_mapped()` returns None — yet a
                    // connecting stack still routes it to the embedded v4 target. This keeps parity
                    // with `config_validate::ssrf_blocked_host`, which deliberately uses `to_ipv4()`.
                    if let Some(v4) = v6.to_ipv4() {
                        return is_internal_v4(&v4);
                    }
                    v6.is_unspecified()
                        // unique-local (fc00::/7) and link-local (fe80::/10): no stable std
                        // predicate on this toolchain, so check the leading bits directly.
                        || (v6.segments()[0] & 0xfe00) == 0xfc00
                        || (v6.segments()[0] & 0xffc0) == 0xfe80
                }
                // Not an IP literal — a DNS name. Block the well-known loopback name `localhost`
                // (and any `*.localhost` subdomain, which RFC 6761 reserves to loopback) so it can't
                // be used as an SSRF target; allow any other external-collector hostname. The
                // trailing FQDN-root dot was already stripped above, so `localhost.` and
                // `sub.localhost.` are caught here too.
                Err(_) => {
                    host.eq_ignore_ascii_case("localhost")
                        || host
                            .rsplit_once('.')
                            .is_some_and(|(_, tld)| tld.eq_ignore_ascii_case("localhost"))
                }
            }
        }
    }
}

/// Configure the request-log webhook once at startup. `url == None` disables it. The shared
/// reqwest `Client` (busbar's pooled client) is reused for delivery. The URL is validated here
/// (startup) so an invalid target is rejected loudly and the webhook left disabled, rather than
/// firing per-request POSTs at an unintended host at runtime (see `validate_webhook_url`).
pub(crate) fn configure_webhook(url: Option<String>, client: Client) {
    let validated = match validate_webhook_url(url) {
        Ok(v) => v,
        Err(msg) => {
            tracing::error!("{msg}; disabling the request-log webhook");
            None
        }
    };
    // Only seed the OnceLock when a URL survived validation. An unset lock IS the "disabled"
    // signal, so `fire_request_log` can `.get().cloned()` (a refcount bump) with no per-request
    // `Option` allocation.
    if let Some(u) = validated {
        let _ = WEBHOOK_URL.set(Arc::new(u));
    }
    let _ = CLIENT.set(client);
}

/// Build the request-log JSON payload. Pure (no I/O) so it is unit-testable.
pub(crate) fn build_request_log(
    ts: u64,
    ingress_protocol: &str,
    pool: &str,
    outcome: &str,
    latency_ms: u64,
) -> Value {
    serde_json::json!({
        "ts": ts,
        "ingress_protocol": ingress_protocol,
        "pool": pool,
        "outcome": outcome,
        "latency_ms": latency_ms,
    })
}

/// Fire-and-forget a request-log POST. No-op when no webhook is configured. Never blocks the
/// request path and never surfaces errors — telemetry must not affect serving.
///
/// Bounded: at most `MAX_INFLIGHT_WEBHOOK_DELIVERIES` deliveries run concurrently (a slow webhook
/// drops logs rather than piling up unbounded tasks), and each POST has its own short timeout
/// independent of the shared client's upstream timeout.
pub(crate) fn fire_request_log(payload: Value) {
    // Refcount bump, NOT a heap copy of the URL: `WEBHOOK_URL` holds an `Arc<String>` and an unset
    // lock means "not configured". `.cloned()` on `Option<&Arc<String>>` is 8 bytes, so the
    // per-request webhook fast-path allocates nothing.
    let Some(url) = WEBHOOK_URL.get().cloned() else {
        return;
    };
    let Some(client) = CLIENT.get().cloned() else {
        return;
    };
    // Acquire a delivery slot WITHOUT awaiting. If the cap is reached the webhook is backed up;
    // drop this log rather than blocking the caller or accumulating an unbounded task backlog.
    let Ok(permit) = WEBHOOK_INFLIGHT.try_acquire() else {
        return;
    };
    // The permit borrows the 'static semaphore; forget it and hand the slot to an `InflightGuard`
    // moved into the task, so the slot is released on the guard's Drop — even if the delivery task
    // panics — rather than via a manual `add_permits` that an unwind would skip (leaking the slot).
    permit.forget();
    let guard = InflightGuard;
    tokio::spawn(async move {
        let _guard = guard;
        // Serialize the payload INSIDE the spawned task, not on the request-serving thread. The
        // full-Value `to_string()` is a heap allocation plus a complete JSON walk; doing it before
        // `tokio::spawn` charged it to the async executor thread on the hot path of every served
        // request — undermining the "allocates nothing" fast-path above and the best-effort,
        // non-blocking contract. `payload` is moved into the closure, so relocating the line costs
        // no lifetime change.
        let body = payload.to_string();
        let _ = client
            .post(url.as_str())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .timeout(WEBHOOK_DELIVERY_TIMEOUT)
            .send()
            .await;
    });
}

/// Retained `SdkTracerProvider` handle so its batched span buffer can be flushed/shut down on
/// process exit (`shutdown_tracing`). Set at most once, only after the subscriber installs
/// successfully — see `init_logging`.
static TRACER_PROVIDER: OnceLock<opentelemetry_sdk::trace::SdkTracerProvider> = OnceLock::new();

/// Install the process-wide `tracing` subscriber once at startup: always a stderr `fmt` layer
/// (level from `RUST_LOG`, default `info`) so spans/warnings are visible out of the box, plus an
/// OpenTelemetry OTLP/HTTP export layer when `observability.otlp_endpoint` is set. Resilient: an
/// OTLP build failure logs and continues with stderr-only logging rather than crashing serving.
///
/// The global OTLP tracer provider is installed only AFTER `try_init()` succeeds: a repeated call
/// (e.g. a re-init path or a second test) must not mutate global tracing state when the new
/// subscriber is not actually installed, which would otherwise leave a new provider behind an old
/// subscriber.
pub(crate) fn init_logging(otlp_endpoint: Option<&str>) {
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::util::SubscriberInitExt as _;

    // Level filter from RUST_LOG (a bare level word, e.g. `debug`); default `info`.
    // NOTE: full `EnvFilter` directive syntax (e.g. `busbar=debug,hyper=warn`) would require
    // enabling the `env-filter` feature on tracing-subscriber in Cargo.toml — see the skipped
    // finding for this unit.
    let level = std::env::var("RUST_LOG")
        .ok()
        .and_then(|v| v.trim().parse::<tracing::Level>().ok())
        .unwrap_or(tracing::Level::INFO);
    let filter = tracing_subscriber::filter::LevelFilter::from_level(level);
    let fmt_layer = tracing_subscriber::fmt::layer().with_target(false);

    // SSRF-validate the OTLP endpoint BEFORE building the exporter, so a config pointing at cloud
    // metadata / an internal service (e.g. `https://169.254.169.254/v1/traces`) is rejected and OTLP
    // left disabled — span data carries key_ids, pool names, and governance decisions, so the export
    // sink must be SSRF-safe (parity with the request-log webhook; loopback collectors are allowed).
    let validated_otlp = match validate_otlp_endpoint(otlp_endpoint) {
        Ok(v) => v,
        Err(msg) => {
            eprintln!("busbar: {msg}; disabling OTLP trace export");
            None
        }
    };
    let otlp_endpoint = validated_otlp.as_deref();

    // Build the OTLP exporter/provider BEFORE installing the subscriber, but defer the global
    // side effect (`set_tracer_provider`) until we know the subscriber actually installed.
    let otel = otlp_endpoint.and_then(build_otlp);
    // Decompose into the layer (used to build the subscriber) and the provider (installed on
    // success). `Option<Layer>` is itself a `Layer`, so it composes cleanly when absent.
    let (otel_layer, otel_provider) = match otel {
        Some((layer, provider)) => (Some(layer), Some(provider)),
        None => (None, None),
    };

    let initialized = tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .with(otel_layer)
        .try_init()
        .is_ok();
    if !initialized {
        eprintln!("busbar: tracing subscriber already initialized");
        // Subscriber not installed — do NOT mutate global tracing state. The provider we built is
        // dropped here, which shuts down its (never-used) exporter cleanly.
        return;
    }
    if let Some(provider) = otel_provider {
        opentelemetry::global::set_tracer_provider(provider.clone());
        // Retain the handle for an explicit shutdown/flush on exit.
        let _ = TRACER_PROVIDER.set(provider);
    }
    if let Some(endpoint) = otlp_endpoint {
        tracing::info!(endpoint, "OTLP tracing enabled");
    }
}

/// Flush and shut down the OTLP tracer provider's batched span buffer. Idempotent and a no-op when
/// OTLP was never configured. Wired into the server's graceful-shutdown path (`main.rs`:
/// `axum::serve(...).with_graceful_shutdown(shutdown_signal())` then `shutdown_tracing()`) so the
/// final spans (often the most diagnostic) are exported rather than dropped when the runtime tears
/// down. Covered by `test_shutdown_tracing_is_noop_when_unconfigured`.
pub(crate) fn shutdown_tracing() {
    if let Some(provider) = TRACER_PROVIDER.get() {
        if let Err(e) = provider.shutdown() {
            eprintln!("busbar: OTLP tracer shutdown failed ({e})");
        }
    }
}

/// Validate an operator-configured OTLP endpoint as an SSRF-safe export target, mirroring the
/// webhook guard (`validate_webhook_url`) so the documented invariant "observability sinks are
/// SSRF-safe" holds for OTLP as well, not just the webhook. Two differences from the webhook guard,
/// both deliberate:
///   1. SCHEME: `http://` is permitted in addition to `https://`, because the standard OTLP
///      collector deployment is a co-located `http://localhost:4318` (or a sidecar) — a plaintext
///      loopback hop carries no exfiltration risk. Any other scheme is rejected.
///   2. LOOPBACK: a loopback / `localhost` target is ALLOWED (it IS the standard collector pattern),
///      whereas the webhook blocks it. Everything else `host_is_internal` blocks is STILL blocked:
///      `169.254.169.254` cloud-metadata, the `METADATA_HOSTS` DNS names, RFC1918 private, RFC6598
///      CGNAT, link-local, and the alternate-IPv4 encodings the resolver expands to those targets.
///      So `http://169.254.169.254/v1/traces` or `https://10.0.0.1/collect` is rejected, but
///      `http://localhost:4318` is accepted.
///
/// `None` (OTLP disabled) is always valid. Pure, so it is unit-testable without process-wide state.
fn validate_otlp_endpoint(endpoint: Option<&str>) -> Result<Option<String>, String> {
    let Some(e) = endpoint else {
        return Ok(None);
    };
    // Case-INSENSITIVE scheme check (see `scheme_is`): `HTTP://localhost:4318` / `HTTPS://...` are
    // valid per RFC 3986 and would be wrongly rejected by a literal lowercase `starts_with`.
    if !(scheme_is(e, "https") || scheme_is(e, "http")) {
        return Err(format!(
            "observability.otlp_endpoint must be an http:// or https:// URL (got '{e}')"
        ));
    }
    let parsed = reqwest::Url::parse(e)
        .map_err(|err| format!("observability.otlp_endpoint is not a valid URL: {err}"))?;
    // Block the internal/metadata set, but carve out loopback (the localhost-collector exception).
    // `otlp_host_is_blocked` is `host_is_internal` minus the loopback/localhost arms.
    if otlp_host_is_blocked(&parsed) {
        return Err(format!(
            "observability.otlp_endpoint must not target a link-local/private/CGNAT/cloud-metadata \
             host (SSRF guard; loopback/localhost collectors are allowed); got '{e}'"
        ));
    }
    Ok(Some(e.to_string()))
}

/// SSRF block predicate for the OTLP endpoint: identical to `host_is_internal` EXCEPT loopback and
/// the `localhost` DNS name are NOT blocked (the standard `http://localhost:4318` collector). Every
/// other internal/metadata target `host_is_internal` rejects is rejected here too — same
/// link-local/IMDS, private, CGNAT, unspecified, alternate-IPv4-encoding, and `METADATA_HOSTS`
/// coverage — so the only relaxation versus the webhook guard is the intentional loopback carve-out.
fn otlp_host_is_blocked(url: &reqwest::Url) -> bool {
    use std::net::IpAddr;
    match url.host_str() {
        // A URL with no host is unusable as an export target; reject it.
        None => true,
        Some(host) => {
            let host = host.strip_prefix('[').unwrap_or(host);
            let host = host.strip_suffix(']').unwrap_or(host);
            // Strip a single trailing FQDN-root dot BEFORE every check — otherwise a trailing-dot
            // metadata name (`metadata.google.internal.`) misses the exact METADATA_HOSTS compare and
            // a trailing-dot internal IP literal (`169.254.169.254.`) fails to parse and falls into
            // the allow-by-default DNS arm, bypassing the block. Mirrors host_is_internal /
            // config_validate::ssrf_blocked_host. (Loopback `127.0.0.1.` still canonicalizes to the
            // allowed collector carve-out below.)
            let host = host.strip_suffix('.').unwrap_or(host);

            if METADATA_HOSTS.iter().any(|m| host.eq_ignore_ascii_case(m)) {
                return true;
            }
            // Alternate IPv4 encodings that resolve to an internal target. A loopback alternate
            // encoding (e.g. `2130706433` == 127.0.0.1) is the localhost-collector exception, so
            // canonicalize and let the loopback carve-out below apply rather than blanket-blocking.
            if is_alternate_ipv4_encoding(host) {
                // Best-effort canonicalization: if it parses to a loopback v4 after the resolver
                // expansion we model here, allow it; otherwise it's an alternate-encoded internal
                // target and must be blocked. We can't run getaddrinfo in a pure validator, so be
                // conservative: block every alternate encoding EXCEPT the canonical decimal/hex/octal
                // spellings of 127.0.0.1, which are unambiguously loopback.
                return !is_alternate_loopback_v4(host);
            }

            match host.parse::<IpAddr>() {
                // Loopback is the allowed collector pattern; every other internal v4 is blocked.
                Ok(IpAddr::V4(v4)) => !v4.is_loopback() && is_internal_v4(&v4),
                Ok(IpAddr::V6(v6)) => {
                    if v6.is_loopback() {
                        return false; // `::1` loopback collector — allowed.
                    }
                    if let Some(v4) = v6.to_ipv4() {
                        return !v4.is_loopback() && is_internal_v4(&v4);
                    }
                    v6.is_unspecified()
                        || (v6.segments()[0] & 0xfe00) == 0xfc00
                        || (v6.segments()[0] & 0xffc0) == 0xfe80
                }
                // DNS name: block the cloud-metadata names (handled above) but ALLOW `localhost`
                // (and `*.localhost`) — the loopback carve-out — and any external collector hostname.
                Err(_) => false,
            }
        }
    }
}

/// True iff `host` is an alternate (non-dotted-quad) IPv4 encoding that unambiguously denotes the
/// loopback address `127.0.0.1`: the decimal integer `2130706433`, the hex `0x7f000001`, the octal
/// `017700000001`, or a short-dotted form like `127.1` / `127.0.1`. Used by `otlp_host_is_blocked`
/// to permit the localhost-collector exception while still blocking every other alternate-encoded
/// internal target. Conservative: anything it can't positively confirm as loopback is treated as
/// non-loopback by the caller (and therefore blocked).
fn is_alternate_loopback_v4(host: &str) -> bool {
    // Decimal integer form: must equal 127.0.0.1 == 2130706433.
    if !host.contains('.') {
        if let Some(hex) = host.strip_prefix("0x").or_else(|| host.strip_prefix("0X")) {
            return u32::from_str_radix(hex, 16).ok() == Some(0x7f00_0001);
        }
        if let Some(oct) = host.strip_prefix('0').filter(|_| host.len() > 1) {
            // Leading-zero octal (e.g. `017700000001`).
            if let Ok(v) = u32::from_str_radix(oct, 8) {
                return v == 0x7f00_0001;
            }
        }
        if let Ok(v) = host.parse::<u32>() {
            return v == 0x7f00_0001;
        }
        return false;
    }
    // Short-dotted form: first octet 127 and every present octet numeric, fewer than 4 parts.
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() >= 4 || parts.is_empty() {
        return false;
    }
    let Some(first) = parts.first().and_then(|p| p.parse::<u32>().ok()) else {
        return false;
    };
    first == 127 && parts.iter().all(|p| p.parse::<u32>().is_ok())
}

/// Build the OpenTelemetry tracing layer + retained provider for OTLP/HTTP export to `endpoint`.
/// Returns `None` (and logs to stderr — the subscriber isn't up yet) if the exporter can't be
/// built. Does NOT install the global provider; the caller does so only after the subscriber is
/// successfully installed.
fn build_otlp<S>(
    endpoint: &str,
) -> Option<(
    impl tracing_subscriber::Layer<S>,
    opentelemetry_sdk::trace::SdkTracerProvider,
)>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    use opentelemetry::trace::TracerProvider as _;
    use opentelemetry_otlp::WithExportConfig as _;

    let exporter = match opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_endpoint(endpoint)
        .build()
    {
        Ok(e) => e,
        Err(e) => {
            eprintln!("busbar: OTLP exporter init failed ({e}); continuing with stderr logging");
            return None;
        }
    };
    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .build();
    let tracer = provider.tracer("busbar");
    let layer = tracing_opentelemetry::layer().with_tracer(tracer);
    Some((layer, provider))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_request_log_shape() {
        let p = build_request_log(1_700_000_000, "anthropic", "prod", "ok", 42);
        assert_eq!(p["ts"], 1_700_000_000_u64);
        assert_eq!(p["ingress_protocol"], "anthropic");
        assert_eq!(p["pool"], "prod");
        assert_eq!(p["outcome"], "ok");
        assert_eq!(p["latency_ms"], 42_u64);
    }

    #[tokio::test]
    async fn test_fire_is_noop_when_unconfigured() {
        // With no webhook URL configured, firing must be a harmless no-op (no panic, no spawn leak).
        fire_request_log(build_request_log(0, "openai", "p", "ok", 1));
    }

    #[test]
    fn test_webhook_url_clone_is_arc_refcount_bump_not_heap_copy() {
        // Regression for the per-request heap allocation: `WEBHOOK_URL` must store an `Arc<String>`
        // so the hot-path clone in `fire_request_log` is a refcount bump that shares the SAME heap
        // buffer, not a fresh `String` allocation. Assert the two clones alias the same allocation
        // (identical data pointer) and that the refcount tracks clones. Uses a local `OnceLock` to
        // avoid mutating the process-wide static (which other tests rely on staying unset).
        let lock: OnceLock<Arc<String>> = OnceLock::new();
        let _ = lock.set(Arc::new("https://hook.example.com/log".to_string()));
        let first = lock.get().cloned().expect("configured");
        assert_eq!(Arc::strong_count(&first), 2, "lock holds one + our clone");
        let second = lock.get().cloned().expect("configured");
        assert_eq!(Arc::strong_count(&first), 3, "second clone bumps the count");
        // Both clones must point at the SAME heap buffer (a refcount bump), not independent copies.
        assert!(
            std::ptr::eq(first.as_str().as_ptr(), second.as_str().as_ptr()),
            "Arc clones must share the underlying String allocation (no per-request heap copy)"
        );
    }

    #[test]
    fn test_validate_webhook_url_accepts_https_and_none() {
        assert_eq!(validate_webhook_url(None), Ok(None));
        assert_eq!(
            validate_webhook_url(Some("https://hook.example.com/log".to_string())),
            Ok(Some("https://hook.example.com/log".to_string()))
        );
    }

    #[test]
    fn test_validate_webhook_url_accepts_uppercase_https_scheme() {
        // Regression: the scheme is case-insensitive per RFC 3986, and reqwest's `Url::parse`
        // lowercases it — so an uppercase/mixed-case `HTTPS://` to a public host is a valid webhook
        // and must NOT be rejected. The old literal `starts_with("https://")` check failed these.
        for ok in [
            "HTTPS://hook.example.com/log",
            "Https://hook.example.com/log",
            "hTTpS://collector.example.org/v1/logs",
        ] {
            assert_eq!(
                validate_webhook_url(Some(ok.to_string())),
                Ok(Some(ok.to_string())),
                "uppercase/mixed-case https scheme '{ok}' must be accepted"
            );
        }
    }

    #[test]
    fn test_validate_webhook_url_uppercase_scheme_still_guards_ssrf() {
        // The case-insensitive scheme acceptance must not bypass the host guard: an uppercase-scheme
        // URL pointed at an internal target is still rejected (by the SSRF host check, not the scheme
        // check). Also confirms `HTTP://` (any case) is still refused as plaintext.
        for bad in [
            "HTTPS://169.254.169.254/latest/meta-data/", // uppercase scheme, internal host
            "HTTPS://127.0.0.1/log",
            "HTTP://hook.example.com/log", // plaintext, uppercase scheme
            "Http://hook.example.com/log", // plaintext, mixed case
        ] {
            assert!(
                validate_webhook_url(Some(bad.to_string())).is_err(),
                "'{bad}' must be rejected (SSRF host guard or plaintext scheme)"
            );
        }
    }

    #[test]
    fn test_scheme_is_case_insensitive() {
        assert!(scheme_is("HTTPS://host/", "https"));
        assert!(scheme_is("https://host/", "https"));
        assert!(scheme_is("HtTp://host/", "http"));
        assert!(!scheme_is("http://host/", "https"));
        assert!(!scheme_is("httpsx://host/", "https")); // require the `://` boundary
        assert!(!scheme_is("not-a-url", "https"));
    }

    #[test]
    fn test_validate_webhook_url_rejects_non_https() {
        for bad in [
            "http://hook.example.com/log",
            "http://169.254.169.254/latest/meta-data/",
            "file:///etc/shadow",
            "ftp://example.com",
            "not-a-url",
            "",
        ] {
            let res = validate_webhook_url(Some(bad.to_string()));
            assert!(
                res.is_err(),
                "non-https webhook URL '{bad}' must be rejected; got {res:?}"
            );
            assert!(
                res.unwrap_err().contains("https://"),
                "rejection message should mention the https requirement for '{bad}'"
            );
        }
    }

    #[test]
    fn test_validate_webhook_url_rejects_https_internal_hosts() {
        // Regression: the scheme check alone let an `https://` SSRF target through. These must all
        // be rejected by the host guard so enforcement matches the documented protection.
        for bad in [
            "https://169.254.169.254/latest/meta-data/", // cloud metadata (link-local)
            "https://127.0.0.1/log",                     // loopback
            "https://10.0.0.5/hook",                     // RFC1918
            "https://192.168.1.10/hook",                 // RFC1918
            "https://172.16.5.4/hook",                   // RFC1918
            "https://0.0.0.0/hook",                      // unspecified
            "https://[::1]/hook",                        // IPv6 loopback
            "https://[fe80::1]/hook",                    // IPv6 link-local
            "https://[fc00::1]/hook",                    // IPv6 unique-local
        ] {
            let res = validate_webhook_url(Some(bad.to_string()));
            assert!(
                res.is_err(),
                "https internal-host webhook URL '{bad}' must be rejected; got {res:?}"
            );
        }
    }

    #[test]
    fn test_validate_webhook_url_rejects_localhost_dns_name() {
        // Regression (SSRF): `localhost` is a DNS name, not an IP literal, but RFC 6761 reserves it
        // (and its subdomains) to loopback. An operator-set `https://localhost:<port>/path` would
        // POST request logs to a co-located process, so it must be blocked case-insensitively.
        for bad in [
            "https://localhost/log",
            "https://LOCALHOST/log",
            "https://localhost:8443/exfil",
            "https://api.localhost/log", // `*.localhost` subdomain -> loopback per RFC 6761
            "https://service.LocalHost/log",
            // Trailing-dot FQDN-root spellings: getaddrinfo resolves `localhost.` to loopback exactly
            // like `localhost`, and `config_validate::ssrf_blocked_host` lists `localhost.` — these
            // previously slipped past `host_is_internal` (the bare-label compare missed the dot and
            // the rsplit TLD was the empty string), enabling `https://localhost./exfil`.
            "https://localhost./log",
            "https://localhost.:443/exfil",
            "https://api.localhost./log", // `*.localhost.` subdomain, trailing dot
        ] {
            let res = validate_webhook_url(Some(bad.to_string()));
            assert!(
                res.is_err(),
                "localhost-family webhook URL '{bad}' must be rejected by the SSRF guard; got {res:?}"
            );
        }
    }

    #[test]
    fn test_validate_webhook_url_rejects_ipv4_mapped_ipv6_internal() {
        // Regression (SSRF): an IPv4-mapped IPv6 literal (`::ffff:a.b.c.d`) parses as IpAddr::V6 and
        // matches none of the plain V6 predicates, so without canonicalization it would reach the
        // same internal targets (loopback / cloud-metadata / RFC1918) the V4 arm rejects.
        for bad in [
            "https://[::ffff:127.0.0.1]/log",        // mapped loopback
            "https://[::ffff:169.254.169.254]/meta", // mapped cloud metadata (link-local)
            "https://[::ffff:10.0.0.5]/hook",        // mapped RFC1918
            "https://[::ffff:192.168.1.10]/hook",    // mapped RFC1918
            "https://[::ffff:0.0.0.0]/hook",         // mapped unspecified
            // IPv4-COMPATIBLE form (`::a.b.c.d`): `to_ipv4_mapped()` returns None for these and the
            // leading `segments()[0] == 0` makes the ULA/link-local masks miss, so under the old
            // `to_ipv4_mapped()` canonicalization they fell through to `false` (allowed) — a real
            // SSRF gap and a broken documented parity with `config_validate::ssrf_blocked_host`.
            "https://[::127.0.0.1]/log",        // compatible loopback
            "https://[::169.254.169.254]/meta", // compatible cloud metadata (link-local IMDS)
            "https://[::10.0.0.5]/hook",        // compatible RFC1918
            "https://[::1]/log",                // bare loopback must still be caught
        ] {
            let res = validate_webhook_url(Some(bad.to_string()));
            assert!(
                res.is_err(),
                "IPv4-mapped-IPv6 internal webhook URL '{bad}' must be rejected; got {res:?}"
            );
        }
    }

    #[test]
    fn test_validate_webhook_url_rejects_cgnat_v4() {
        // Regression (SSRF, parity with config_validate::ssrf_blocked_host): RFC 6598 CGNAT
        // 100.64.0.0/10 is NOT is_private(), yet routable inside cloud VPCs / k8s clusters where it
        // fronts internal services. The V4 arm previously checked only loopback/link-local/private/
        // unspecified/broadcast, so https://100.64.0.5/ slipped through.
        for bad in [
            "https://100.64.0.5/hook",      // bottom of the /10
            "https://100.64.0.0/hook",      // network address
            "https://100.96.0.1/hook",      // mid-range (second octet 0x60, top two bits 01)
            "https://100.127.255.254/hook", // top of the /10
        ] {
            let res = validate_webhook_url(Some(bad.to_string()));
            assert!(
                res.is_err(),
                "CGNAT (RFC6598) webhook URL '{bad}' must be rejected by the SSRF guard; got {res:?}"
            );
        }
    }

    #[test]
    fn test_validate_webhook_url_accepts_non_cgnat_100_block() {
        // 100.0.0.0/8 outside the 100.64.0.0/10 CGNAT slice is ordinary public space and must NOT
        // be over-blocked (top two bits of the second octet are not `01`).
        for ok in [
            "https://100.0.0.1/hook",      // second octet 0
            "https://100.63.255.255/hook", // just below the /10
            "https://100.128.0.1/hook",    // second octet 0x80, top two bits 10
        ] {
            assert!(
                validate_webhook_url(Some(ok.to_string())).is_ok(),
                "public 100.x address '{ok}' must be accepted (no CGNAT over-block)"
            );
        }
    }

    #[test]
    fn test_validate_webhook_url_rejects_alternate_ipv4_encodings() {
        // Regression (SSRF, parity with config_validate): non-canonical IPv4 encodings are rejected
        // by IpAddr::from_str but the OS resolver still maps them to internal addresses. Previously
        // they fell into the Err(_) DNS branch (which only blocked the localhost family) and passed.
        for bad in [
            "https://2130706433/log",   // decimal int = 127.0.0.1
            "https://0x7f000001/log",   // hex = 127.0.0.1
            "https://0X7F000001/log",   // hex, upper-case prefix
            "https://017700000001/log", // octal = 127.0.0.1
            "https://127.1/log",        // short-dotted = 127.0.0.1
            "https://10.0.1/log",       // short-dotted = 10.0.0.1 (RFC1918)
            "https://2852039166/meta",  // decimal = 169.254.169.254 (IMDS)
            "https://0x7f.0.0.1/log",   // per-octet hex in a 4-part form
            "https://0177.0.0.1/log",   // per-octet octal in a 4-part form
        ] {
            let res = validate_webhook_url(Some(bad.to_string()));
            assert!(
                res.is_err(),
                "alternate IPv4 encoding webhook URL '{bad}' must be rejected by the SSRF guard; got {res:?}"
            );
        }
    }

    #[test]
    fn test_validate_webhook_url_rejects_cloud_metadata_dns_names() {
        // Regression (SSRF, parity with config_validate::METADATA_HOSTS): the well-known cloud
        // metadata DNS names resolve to internal/IMDS targets. They are not IP literals, so the
        // Err(_) DNS branch (localhost-only) let them through previously.
        for bad in [
            "https://metadata.google.internal/computeMetadata/v1/",
            "https://METADATA.GOOGLE.INTERNAL/x", // case-insensitive
            "https://metadata.internal/x",
        ] {
            let res = validate_webhook_url(Some(bad.to_string()));
            assert!(
                res.is_err(),
                "cloud-metadata DNS name webhook URL '{bad}' must be rejected by the SSRF guard; got {res:?}"
            );
        }
    }

    #[test]
    fn test_validate_webhook_url_rejects_trailing_dot_internal_hosts() {
        // Regression (HIGH SSRF, final audit): a trailing FQDN-root dot made the IP-literal parse
        // fail (slipping into the allow-by-default DNS arm) and the METADATA_HOSTS exact-compare miss,
        // so a trailing-dot internal target bypassed BOTH guards. getaddrinfo resolves these to the
        // same internal targets as the bare spelling, so they MUST be rejected.
        for bad in [
            "https://127.0.0.1./exfil",
            "https://169.254.169.254./latest/meta-data/",
            "https://metadata.google.internal./computeMetadata/v1/",
            "https://metadata.internal./x",
            "https://localhost./exfil",
        ] {
            let res = validate_webhook_url(Some(bad.to_string()));
            assert!(
                res.is_err(),
                "trailing-dot internal host '{bad}' must be rejected by the SSRF guard; got {res:?}"
            );
        }
        // OTLP twin: link-local/metadata trailing-dot hosts blocked; loopback collector still allowed.
        for bad in [
            "https://169.254.169.254./v1/traces",
            "https://metadata.google.internal./v1/traces",
        ] {
            assert!(
                validate_otlp_endpoint(Some(bad)).is_err(),
                "trailing-dot internal OTLP endpoint '{bad}' must be rejected"
            );
        }
        // The loopback collector carve-out survives the dot strip (allowed for OTLP).
        assert!(
            validate_otlp_endpoint(Some("https://127.0.0.1./v1/traces")).is_ok(),
            "trailing-dot loopback OTLP collector must remain allowed (carve-out)"
        );
    }

    #[test]
    fn test_validate_webhook_url_accepts_metadata_lookalike_dns_names() {
        // A registrable external name that merely contains a metadata label as a subdomain (not the
        // exact reserved name) must NOT be over-blocked.
        for ok in [
            "https://metadata.google.internal.example.com/x", // distinct registrable name
            "https://my-metadata.internal.example.org/x",
        ] {
            assert!(
                validate_webhook_url(Some(ok.to_string())).is_ok(),
                "metadata-lookalike external name '{ok}' must be accepted (no over-block)"
            );
        }
    }

    #[test]
    fn test_validate_webhook_url_accepts_mapped_public_and_localhost_substring() {
        // An IPv4-mapped IPv6 of a PUBLIC address stays allowed (canonicalization must not over-block),
        // and a hostname that merely CONTAINS "localhost" as a substring of a real label (not the
        // `localhost` label itself) is a distinct external name and must not be falsely rejected.
        for ok in [
            "https://[::ffff:93.184.216.34]/log", // mapped public IP literal -> allowed
            "https://mylocalhost.example.com/log", // label is `mylocalhost`, not `localhost`
            "https://localhost.example.com/log", // registrable name under example.com, TLD != localhost
        ] {
            assert!(
                validate_webhook_url(Some(ok.to_string())).is_ok(),
                "external webhook URL '{ok}' must be accepted (no SSRF over-block)"
            );
        }
    }

    #[test]
    fn test_validate_webhook_url_accepts_https_external_host() {
        // An https URL to a public DNS name / public IP literal is allowed.
        for ok in [
            "https://hook.example.com/log",
            "https://collector.internal.example.org/v1/logs", // DNS name -> allowed
            "https://93.184.216.34/log",                      // public IP literal
        ] {
            assert!(
                validate_webhook_url(Some(ok.to_string())).is_ok(),
                "https external webhook URL '{ok}' must be accepted"
            );
        }
    }

    #[test]
    fn test_shutdown_tracing_is_noop_when_unconfigured() {
        // OTLP never configured (TRACER_PROVIDER unset): shutdown must be a harmless, panic-free
        // no-op. Also exercises the function so it is not dead code outside `cfg(test)`.
        shutdown_tracing();
    }

    #[tokio::test]
    async fn test_inflight_guard_releases_slot_on_drop() {
        // The RAII guard returns its semaphore slot on Drop. Mirror the production acquire/forget
        // pattern, then drop the guard and confirm the slot is reusable (no leak).
        let before = WEBHOOK_INFLIGHT.available_permits();
        {
            let permit = WEBHOOK_INFLIGHT
                .try_acquire()
                .expect("a slot should be free");
            permit.forget();
            assert_eq!(WEBHOOK_INFLIGHT.available_permits(), before - 1);
            let _guard = InflightGuard; // drops at end of scope -> add_permits(1)
        }
        assert_eq!(
            WEBHOOK_INFLIGHT.available_permits(),
            before,
            "InflightGuard::drop must return the slot even though the permit was forgotten"
        );
    }

    #[test]
    fn test_validate_otlp_endpoint_accepts_none_and_external() {
        // OTLP disabled is always valid; an external collector over https is accepted verbatim.
        assert_eq!(validate_otlp_endpoint(None), Ok(None));
        assert_eq!(
            validate_otlp_endpoint(Some("https://collector.example.com:4318/v1/traces")),
            Ok(Some(
                "https://collector.example.com:4318/v1/traces".to_string()
            ))
        );
    }

    #[test]
    fn test_validate_otlp_endpoint_allows_loopback_collectors() {
        // The localhost-collector carve-out: the standard OTLP deployment is a co-located plaintext
        // loopback hop. http:// is permitted, and loopback v4/v6/`localhost` must be accepted.
        for ok in [
            "http://localhost:4318/v1/traces",
            "http://LOCALHOST:4318",
            "https://localhost:4318/v1/traces",
            "http://127.0.0.1:4318/v1/traces",
            "http://[::1]:4318/v1/traces",
            "http://api.localhost:4318", // *.localhost -> loopback per RFC 6761
        ] {
            let res = validate_otlp_endpoint(Some(ok));
            assert!(
                res.is_ok(),
                "loopback OTLP collector '{ok}' must be accepted; got {res:?}"
            );
        }
    }

    #[test]
    fn test_validate_otlp_endpoint_rejects_cloud_metadata_and_internal() {
        // Regression (R16 SSRF medium): span data carries key_ids, pool names, and governance
        // decisions, so the OTLP sink must block cloud-metadata / RFC1918 / CGNAT / link-local
        // targets exactly like the webhook guard (only loopback is the intentional exception).
        for bad in [
            "https://169.254.169.254/v1/traces", // IMDS (link-local)
            "http://169.254.169.254/v1/traces",  // IMDS over plaintext too
            "https://10.0.0.1/collect",          // RFC1918
            "http://10.0.0.1/collect",
            "https://192.168.1.10/v1/traces",             // RFC1918
            "https://172.16.5.4/v1/traces",               // RFC1918
            "https://100.64.0.1/v1/traces",               // RFC6598 CGNAT
            "https://0.0.0.0/v1/traces",                  // unspecified
            "https://[fe80::1]/v1/traces",                // IPv6 link-local
            "https://[fc00::1]/v1/traces",                // IPv6 unique-local
            "https://metadata.google.internal/v1/traces", // cloud-metadata DNS name
            "http://2130706433/v1/traces", // 127.0.0.1 alt encoding is loopback -> allowed below
        ] {
            // The last entry is a loopback alternate encoding and is deliberately exercised in the
            // allow-test; here we only assert the genuinely-internal set is rejected.
            if bad.contains("2130706433") {
                continue;
            }
            let res = validate_otlp_endpoint(Some(bad));
            assert!(
                res.is_err(),
                "internal/cloud-metadata OTLP endpoint '{bad}' must be rejected; got {res:?}"
            );
        }
    }

    #[test]
    fn test_validate_otlp_endpoint_rejects_alternate_encoded_internal() {
        // Alternate IPv4 encodings of an INTERNAL target must be blocked (e.g. decimal/hex of an
        // RFC1918 host), while the loopback alternate encodings are the only ones permitted.
        for bad in [
            "http://0xa000001/v1/traces", // 10.0.0.1 in hex
            "http://167772161/v1/traces", // 10.0.0.1 in decimal
            "http://2852039166/collect",  // 169.254.169.254 in decimal
        ] {
            let res = validate_otlp_endpoint(Some(bad));
            assert!(
                res.is_err(),
                "alternate-encoded internal OTLP endpoint '{bad}' must be rejected; got {res:?}"
            );
        }
        // Loopback alternate encodings ARE the localhost-collector exception -> allowed.
        for ok in [
            "http://2130706433/v1/traces", // 127.0.0.1 decimal
            "http://0x7f000001/v1/traces", // 127.0.0.1 hex
        ] {
            let res = validate_otlp_endpoint(Some(ok));
            assert!(
                res.is_ok(),
                "loopback alternate encoding '{ok}' must be accepted (localhost collector); got {res:?}"
            );
        }
    }

    #[test]
    fn test_validate_otlp_endpoint_accepts_uppercase_scheme() {
        // Regression (sibling of the webhook scheme bug): the OTLP scheme check is also
        // case-insensitive, so `HTTP://localhost:4318` / `HTTPS://collector...` are valid and must
        // be accepted. The old literal lowercase `starts_with` rejected them.
        for ok in [
            "HTTP://localhost:4318/v1/traces",
            "HTTPS://collector.example.com:4318/v1/traces",
            "Http://127.0.0.1:4318",
        ] {
            assert!(
                validate_otlp_endpoint(Some(ok)).is_ok(),
                "uppercase/mixed-case scheme OTLP endpoint '{ok}' must be accepted"
            );
        }
        // ...but an uppercase scheme still does not bypass the SSRF host guard.
        assert!(
            validate_otlp_endpoint(Some("HTTPS://169.254.169.254/v1/traces")).is_err(),
            "uppercase scheme must not bypass the OTLP SSRF guard"
        );
    }

    #[test]
    fn test_validate_otlp_endpoint_rejects_bad_scheme() {
        // Only http/https export targets are valid; anything else (or a non-URL) is rejected.
        for bad in [
            "file:///etc/shadow",
            "ftp://collector.example.com",
            "grpc://collector:4317",
            "not-a-url",
            "",
        ] {
            let res = validate_otlp_endpoint(Some(bad));
            assert!(
                res.is_err(),
                "non-http(s) OTLP endpoint '{bad}' must be rejected; got {res:?}"
            );
        }
    }
}
