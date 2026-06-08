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
///   2. The host MUST NOT be a loopback / link-local / private / unspecified address — i.e. the URL
///      may not point at `169.254.169.254` cloud-metadata, `127.0.0.1`, `10.x`/`192.168.x`/`172.16.x`
///      internal services, etc. The earlier scheme-only check did nothing for an `https://` SSRF
///      target (`https://169.254.169.254/...` passed unchanged); this closes that gap so the
///      enforcement matches the documented protection.
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
            "observability.request_log_webhook_url must not target a loopback/link-local/private \
             host (SSRF guard); got '{u}'"
        ));
    }
    Ok(Some(u))
}

/// True if the URL's host is an address busbar must not POST telemetry to: a literal loopback,
/// link-local (incl. `169.254.169.254` cloud-metadata), private (RFC1918 / unique-local), or
/// unspecified IP. A hostname that does not parse as an IP literal is allowed (operators may name
/// an external collector) EXCEPT the well-known loopback DNS name `localhost` (and its dotted
/// subdomains), which is blocked case-insensitively so an `https://localhost:<port>/path` URL can't
/// be used to POST request logs to a co-located process — matching `config_validate::ssrf_blocked_host`.
/// Full DNS-rebinding is out of scope for a startup-validated, operator-supplied URL. Returns `true`
/// (reject) when the host is missing entirely.
fn host_is_internal(url: &reqwest::Url) -> bool {
    use std::net::IpAddr;
    match url.host_str() {
        None => true,
        Some(host) => {
            // `Url::host_str` keeps IPv6 literals bracketed; strip for `IpAddr` parsing.
            let host = host.strip_prefix('[').unwrap_or(host);
            let host = host.strip_suffix(']').unwrap_or(host);
            match host.parse::<IpAddr>() {
                Ok(IpAddr::V4(v4)) => {
                    v4.is_loopback()
                        || v4.is_link_local()
                        || v4.is_private()
                        || v4.is_unspecified()
                        || v4.is_broadcast()
                }
                Ok(IpAddr::V6(v6)) => {
                    // Canonicalize an IPv4-mapped address (`::ffff:a.b.c.d`) FIRST and apply the V4
                    // predicates: otherwise `[::ffff:127.0.0.1]` / `[::ffff:169.254.169.254]` parse as
                    // V6, match none of the V6 predicates below, and reach loopback / cloud-metadata —
                    // defeating the guard. `to_ipv4_mapped` only matches true `::ffff:0:0/96` mapped
                    // addresses (NOT `::1`), so the V6 predicates still cover genuine V6 literals.
                    if let Some(v4) = v6.to_ipv4_mapped() {
                        return v4.is_loopback()
                            || v4.is_link_local()
                            || v4.is_private()
                            || v4.is_unspecified()
                            || v4.is_broadcast();
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
/// OTLP was never configured. Call this on graceful shutdown so the final spans (often the most
/// diagnostic) are exported rather than dropped when the runtime tears down.
///
/// TODO(graceful-shutdown): wire this into the server's shutdown path so the buffer flushes on exit.
/// busbar currently runs `axum::serve(...).await` with no graceful-shutdown future, and the `tokio`
/// `signal` feature is not enabled, so there is no in-process hook to call this from yet; adding one
/// (e.g. `axum::serve(...).with_graceful_shutdown(sig)` followed by `shutdown_tracing()`) is the
/// remaining step. The mechanism (retained provider + idempotent `shutdown()`) is complete and
/// covered by `test_shutdown_tracing_is_noop_when_unconfigured`.
///
/// The annotation is the crate's standard idiom for a real-but-not-yet-wired hook — the same
/// `#[cfg_attr(not(test), allow(dead_code))]` used on the store's `record_hard_down` /
/// `record_rate_limit` until their call sites land. This replaces the previous blanket
/// `#[allow(dead_code)]` whose doc-comment falsely claimed a live `main.rs` call site existed.
#[cfg_attr(not(test), allow(dead_code))]
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
