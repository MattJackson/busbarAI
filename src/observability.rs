// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! Observability sinks beyond Prometheus `/metrics`: a best-effort request-log webhook and
//! OTLP trace export. Both are opt-in via the `observability` config section; with no
//! config they are no-ops. State lives in process-wide `OnceLock`s (set once at startup) so the
//! request path can reach it without threading new fields through `App` and its many constructors.

use reqwest::Client;
use serde_json::Value;
use std::sync::OnceLock;
use std::time::Duration;
use tokio::sync::Semaphore;

static WEBHOOK_URL: OnceLock<Option<String>> = OnceLock::new();
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

/// Validate the configured webhook URL. Two guarantees, both enforced (not just documented):
///   1. The scheme MUST be `https://` — a plaintext `http://` endpoint would expose per-request
///      metadata on the wire.
///   2. The host MUST NOT be an internal target — loopback / link-local / private (RFC1918) / RFC6598
///      CGNAT / unspecified, whether written as a canonical IP literal, an IPv4-mapped IPv6 literal,
///      or an alternate IPv4 encoding (decimal/hex/octal/short-dotted) the resolver still expands;
///      nor a loopback (`localhost`) or cloud-metadata (`metadata.google.internal`) DNS name. The URL
///      may not point at `169.254.169.254` cloud-metadata, `127.0.0.1`, `10.x`/`192.168.x`/`172.16.x`
///      internal services, etc. The earlier scheme-only check did nothing for an `https://` SSRF
///      target (`https://169.254.169.254/...` passed unchanged); this closes that gap so the
///      enforcement matches the documented protection (parity with `config_validate::ssrf_blocked_host`).
///
/// `None` (webhook disabled) is always valid. Pure, so it is unit-testable without touching the
/// process-wide `OnceLock`s.
fn validate_webhook_url(url: Option<String>) -> Result<Option<String>, String> {
    let Some(u) = url else {
        return Ok(None);
    };
    if !u.starts_with("https://") {
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
/// literals (they resolve, at connect time, to the loopback/IMDS family). Kept in lock-step with the
/// `METADATA_HOSTS` list in `config_validate::ssrf_blocked_host` so the parity the doc-comment on
/// `host_is_internal` claims is real, not aspirational.
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
/// CGNAT, or unspecified IP — whether written as a canonical IP literal, an IPv4-mapped IPv6 literal,
/// or one of the alternate IPv4 encodings the OS resolver still expands to an internal address
/// (decimal `2130706433`, hex `0x7f000001`, octal, short-dotted `127.1`). A hostname that does not
/// parse as an IP literal is allowed (operators may name an external collector) EXCEPT the
/// well-known loopback DNS name `localhost` (and its dotted subdomains) and the cloud-metadata DNS
/// names in `METADATA_HOSTS`, which are blocked case-insensitively so an `https://localhost:<port>/`
/// or `https://metadata.google.internal/` URL can't be used to POST request logs to a co-located /
/// metadata process — matching `config_validate::ssrf_blocked_host`. Full DNS-rebinding is out of
/// scope for a startup-validated, operator-supplied URL. Returns `true` (reject) when the host is
/// missing entirely.
fn host_is_internal(url: &reqwest::Url) -> bool {
    use std::net::IpAddr;
    match url.host_str() {
        None => true,
        Some(host) => {
            // `Url::host_str` keeps IPv6 literals bracketed; strip for `IpAddr` parsing.
            let host = host.strip_prefix('[').unwrap_or(host);
            let host = host.strip_suffix(']').unwrap_or(host);

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
                    // Canonicalize an IPv4-mapped address (`::ffff:a.b.c.d`) FIRST and apply the V4
                    // predicates: otherwise `[::ffff:127.0.0.1]` / `[::ffff:169.254.169.254]` parse as
                    // V6, match none of the V6 predicates below, and reach loopback / cloud-metadata —
                    // defeating the guard. `to_ipv4_mapped` only matches true `::ffff:0:0/96` mapped
                    // addresses (NOT `::1`), so the V6 predicates still cover genuine V6 literals.
                    if let Some(v4) = v6.to_ipv4_mapped() {
                        return is_internal_v4(&v4);
                    }
                    v6.is_loopback()
                        || v6.is_unspecified()
                        // unique-local (fc00::/7) and link-local (fe80::/10): no stable std
                        // predicate on this toolchain, so check the leading bits directly.
                        || (v6.segments()[0] & 0xfe00) == 0xfc00
                        || (v6.segments()[0] & 0xffc0) == 0xfe80
                }
                // Not an IP literal — a DNS name. Block the well-known loopback name `localhost`
                // (and any `*.localhost` subdomain, which RFC 6761 reserves to loopback) so it can't
                // be used as an SSRF target; allow any other external-collector hostname.
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
    let _ = WEBHOOK_URL.set(validated);
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
    let Some(url) = WEBHOOK_URL.get().and_then(|o| o.clone()) else {
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
    let body = payload.to_string();
    tokio::spawn(async move {
        let _guard = guard;
        let _ = client
            .post(&url)
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
    fn test_validate_webhook_url_accepts_https_and_none() {
        assert_eq!(validate_webhook_url(None), Ok(None));
        assert_eq!(
            validate_webhook_url(Some("https://hook.example.com/log".to_string())),
            Ok(Some("https://hook.example.com/log".to_string()))
        );
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
}
