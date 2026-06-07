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

/// Validate the configured webhook URL. Only `https://` is accepted: a plaintext `http://`
/// endpoint would expose per-request metadata on the wire, and an arbitrary scheme/host (e.g.
/// `http://169.254.169.254/` cloud-metadata, `file://`, internal services) is an SSRF capability
/// busbar should not silently grant. `None` (webhook disabled) is always valid. Pure, so it is
/// unit-testable without touching the process-wide `OnceLock`s.
fn validate_webhook_url(url: Option<String>) -> Result<Option<String>, String> {
    match url {
        None => Ok(None),
        Some(u) if u.starts_with("https://") => Ok(Some(u)),
        Some(u) => Err(format!(
            "observability.request_log_webhook_url must be an https:// URL (got '{u}')"
        )),
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
    // The permit borrows the 'static semaphore; forget it and release explicitly when the task
    // finishes so the slot is held for the whole delivery without fighting the borrow checker.
    permit.forget();
    let body = payload.to_string();
    tokio::spawn(async move {
        let _ = client
            .post(&url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .timeout(WEBHOOK_DELIVERY_TIMEOUT)
            .send()
            .await;
        WEBHOOK_INFLIGHT.add_permits(1);
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
/// OTLP was never configured. Should be called on graceful shutdown so the final spans (often the
/// most diagnostic) are exported rather than dropped when the runtime tears down.
///
/// NOTE: the call site lives in `main.rs` (a graceful-shutdown hook after `axum::serve` returns),
/// which is outside this unit's owned files — wiring it is tracked as a follow-up. The mechanism
/// (retained provider + explicit `shutdown()`) is provided here so that wiring is a one-liner.
#[allow(dead_code)] // call site is in main.rs (not owned by this fix unit); see doc comment
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
}
