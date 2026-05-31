// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! Observability sinks beyond Prometheus `/metrics`: a best-effort request-log webhook (B-604) and
//! OTLP trace export (B-603). Both are opt-in via the `observability` config section; with no
//! config they are no-ops. State lives in process-wide `OnceLock`s (set once at startup) so the
//! request path can reach it without threading new fields through `App` and its many constructors.

use reqwest::Client;
use serde_json::Value;
use std::sync::OnceLock;

static WEBHOOK_URL: OnceLock<Option<String>> = OnceLock::new();
static CLIENT: OnceLock<Client> = OnceLock::new();

/// Configure the request-log webhook once at startup. `url == None` disables it. The shared
/// reqwest `Client` (busbar's pooled client) is reused for delivery.
pub(crate) fn configure_webhook(url: Option<String>, client: Client) {
    let _ = WEBHOOK_URL.set(url);
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
pub(crate) fn fire_request_log(payload: Value) {
    let Some(url) = WEBHOOK_URL.get().and_then(|o| o.clone()) else {
        return;
    };
    let Some(client) = CLIENT.get().cloned() else {
        return;
    };
    let body = payload.to_string();
    tokio::spawn(async move {
        let _ = client
            .post(&url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await;
    });
}

/// B-603: install an OpenTelemetry tracer that exports OTLP/HTTP spans to `endpoint`, bridged into
/// the `tracing` ecosystem. Called once at startup when `observability.otlp_endpoint` is set.
/// Resilient: a build/exporter failure logs and returns rather than crashing serving.
pub(crate) fn init_otlp(endpoint: &str) {
    use opentelemetry::trace::TracerProvider as _;
    use opentelemetry_otlp::WithExportConfig as _;
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::util::SubscriberInitExt as _;

    let exporter = match opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_endpoint(endpoint)
        .build()
    {
        Ok(e) => e,
        Err(e) => {
            eprintln!("busbar: OTLP exporter init failed ({e}); tracing disabled");
            return;
        }
    };

    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .build();
    let tracer = provider.tracer("busbar");
    opentelemetry::global::set_tracer_provider(provider);

    let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);
    if tracing_subscriber::registry()
        .with(otel_layer)
        .try_init()
        .is_err()
    {
        eprintln!("busbar: tracing subscriber already initialized; OTLP layer not attached");
    } else {
        eprintln!("busbar: OTLP tracing enabled → {endpoint}");
    }
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
}
