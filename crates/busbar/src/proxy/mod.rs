// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::{
    body::Body,
    http::header::{ACCEPT, CONTENT_TYPE, USER_AGENT},
    response::IntoResponse,
    response::Response,
};
use bytes::Bytes;
use futures::Stream;
use reqwest::StatusCode;
use serde_json::Value;

use crate::breaker::{classify as classify_disposition, normalize_raw_error, Disposition};
use crate::config::OnExhausted;
use crate::proto::{
    convert_headers, openai_family, StatusClass, PROTO_BEDROCK, PROTO_GEMINI, PROTO_RESPONSES,
};
use crate::state::{App, WeightedLane};
use crate::store::{now, Permit};

// NOTE: cross-protocol max-tokens defaulting lives in `IrReq::prepare_for_egress` — the IR owns its
// cross-protocol semantics; the engine is operation-blind. Precedence unit tests drive the IR method.

/// The two `x-busbar-*` TRANSPARENCY response headers stamped when a non-default routing policy
/// chose the target lane: the policy name and the chosen lane's model. Hoisted to consts so the
/// emit site and any future readers cannot drift on spelling.
const HDR_ROUTE_POLICY: &str = "x-busbar-route-policy";
const HDR_ROUTE_TARGET: &str = "x-busbar-route-target";

/// The `application/json` media type — the default `Content-Type`/`Accept` for the JSON REST
/// surfaces. Hoisted to one const so the literal isn't repeated across egress/health/observability.
pub(crate) const APPLICATION_JSON: &str = "application/json";

/// Streaming MIME type for SSE (Server-Sent Events) responses — the `Content-Type` value that
/// signals an open event-stream to the client. Placed next to `APPLICATION_JSON` so all
/// protocol-boundary content-types are declared in one spot.
pub(crate) const TEXT_EVENT_STREAM: &str = "text/event-stream";

/// Canonical error-KIND tokens: produced by `cross_protocol_error_kind` / passed to
/// `ingress_error` as the `kind` argument. Each string is the protocol-agnostic discriminant that
/// the per-protocol writer maps to its native error category (e.g. Bedrock `__type`, Gemini
/// `error.status`). Values shared with the OpenAI-family/anthropic/admin vocabularies alias their
/// canonical home in `proto::openai_family`; only the two forward-specific tokens (`overloaded`,
/// `timeout`) are defined here.
pub(crate) const KIND_AUTHENTICATION: &str = openai_family::ERR_TYPE_AUTHENTICATION;
pub(crate) const KIND_PERMISSION: &str = openai_family::ERR_TYPE_PERMISSION;
pub(crate) const KIND_RATE_LIMIT: &str = openai_family::ERR_TYPE_RATE_LIMIT;
pub(crate) const KIND_INVALID_REQUEST: &str = openai_family::ERR_TYPE_INVALID_REQUEST;
pub(crate) const KIND_NOT_FOUND: &str = openai_family::ERR_TYPE_NOT_FOUND;
pub(crate) const KIND_API_ERROR: &str = openai_family::ERR_TYPE_API_ERROR;
/// Bare `overloaded` — DELIBERATELY distinct from `openai_family::ERR_TYPE_OVERLOADED`
/// ("overloaded_error", the Anthropic wire spelling): this is busbar's own agnostic kind for a
/// relayed upstream 503.
pub(crate) const KIND_OVERLOADED: &str = "overloaded";
/// Bare `timeout` — distinct from the Anthropic wire's `timeout_error` spelling.
pub(crate) const KIND_TIMEOUT: &str = "timeout";
pub(crate) const KIND_INSUFFICIENT_QUOTA: &str = openai_family::ERR_TYPE_INSUFFICIENT_QUOTA;
pub(crate) const KIND_SERVER_ERROR: &str = openai_family::ERR_TYPE_SERVER_ERROR;
pub(crate) const KIND_REQUEST_TOO_LARGE: &str = openai_family::ERR_TYPE_REQUEST_TOO_LARGE;

/// Network-transient `err_type` values passed to `record_transient_in`.  These are distinct from
/// the error-KIND tokens above: they label the *category* of network failure recorded in the
/// breaker store, not the protocol-level error kind surfaced to the caller.
const ERR_NET_CONNECT: &str = "connect";
const ERR_NET_TIMEOUT: &str = "timeout";
const ERR_NET_TRANSPORT: &str = "transport";
/// `err_type` recorded when a HalfOpen probe's degraded forward returns a non-2xx (bumps cooldown).
const ERR_DEGRADED_NON2XX: &str = "degraded-non2xx";

/// Metric-label values for the `disposition` dimension on `UPSTREAM_FAILURES_TOTAL` and the
/// `reason` dimension on `FAILOVERS_TOTAL`.
const DISPOSITION_TRANSIENT: &str = "transient_upstream";
/// A single attempt's budget-clamped transport timeout fired (retryable within the request).
const DISPOSITION_ATTEMPT_TIMEOUT: &str = "attempt_timeout";
const DISPOSITION_HARD_DOWN: &str = "hard_down";
const DISPOSITION_CONTEXT_LENGTH: &str = "context_length";

/// Bounded `pool` metric-label sentinel used for every pre-routing failure (malformed body,
/// unresolved model, governance rejection) so the label space stays finite (metrics.rs).
pub(crate) const POOL_LABEL_UNRESOLVED: &str = "unresolved";

/// Provider error-code token emitted when a request exceeds the model's context-window limit.
/// Returned by `client_fault_kind` for `StatusClass::ContextLength` and drives the per-protocol
/// writer to emit the native context-length error category.
pub(crate) const PROVIDER_CODE_CONTEXT_LENGTH: &str = "context_length_exceeded";

tokio::task_local! {
    /// Per-request slot the `server_timing` middleware reads to compute Busbar's INTERNAL
    /// processing time (= total request wall-clock − upstream round-trip), reported as a
    /// `Server-Timing: busbar;dur=<ms>` response header. Set via `.scope()` by the middleware;
    /// written by `record_upstream_rtt` when an upstream call returns. Microseconds; the
    /// `u64::MAX` sentinel means "no upstream hop on this request" (admin/health/early error),
    /// in which case the middleware reports the full request time.
    pub(crate) static UPSTREAM_RTT_US: std::sync::Arc<std::sync::atomic::AtomicU64>;
}

mod egress;
mod engine;
mod hooks;
mod response_body;
mod select;
mod usage;
mod wire;
pub(crate) use egress::*;
pub(crate) use engine::*;
pub(crate) use hooks::*;
pub(crate) use response_body::*;
pub(crate) use select::*;
pub(crate) use usage::*;
pub(crate) use wire::*;

#[cfg(test)]
#[path = "tests/usage_tap_tests.rs"]
mod usage_tap_tests;

// Change A deleted the `UsageTap` byte-scanner and its unit tests (usage extraction across protocols,
// message_start input-token counting, feed_whole past-cap, terminal-error detection, eventstream
// metadata/exception). Their job was to prove the byte-scanner matched the wire usage shapes; billing
// now sources `IrUsage` directly from the per-protocol IR readers, which carry their OWN per-reader
// usage tests, plus the billing-parity tests cover all four {stream,non-stream}×{same,cross} combos.

#[cfg(test)]
#[path = "tests/cross_protocol_extra_tests.rs"]
mod cross_protocol_extra_tests;

#[cfg(test)]
#[path = "tests/bedrock_eventstream_tests.rs"]
mod bedrock_eventstream_tests;

#[cfg(test)]
#[path = "tests/auth_style_tests.rs"]
mod auth_style_tests;

#[cfg(test)]
#[path = "tests/attempt_timeout_precedence_tests.rs"]
mod attempt_timeout_precedence_tests;

#[cfg(test)]
#[path = "tests/max_tokens_precedence_tests.rs"]
mod max_tokens_precedence_tests;

#[cfg(test)]
#[path = "tests/on_exhausted_tests.rs"]
mod on_exhausted_tests;

/// Change B step 1 — REQUEST short-circuit. Proves that a same-protocol passthrough request whose
/// body triggers none of invalidators #1-#4 is re-emitted BYTE-IDENTICAL to the retained original
/// (`hop_bytes`), and that each invalidator individually forces NON-pristine and the correct
/// rewritten bytes. Cross-protocol behaviour is exercised elsewhere; here we pin the same-proto path.
#[cfg(test)]
#[path = "tests/request_short_circuit_tests.rs"]
mod request_short_circuit_tests;

/// Change A — BILLING PARITY GATE. Asserts the IR-derived A-tap usage (`StreamTranslate::usage()`,
/// the value Change A routes billing through) produces EXACTLY the billed (input, output) tokens for
/// every {streaming, non-stream} × {same-proto, cross-proto} path. The numbers asserted here are the
/// SAME numbers the deleted `UsageTap` byte-scanner produced for 5/6 protocols; Responses STREAMING
/// is the one CORRECTED case (the byte-scanner read a top-level `usage` that Responses nests under
/// `response.usage`, so it reported 0 and under-billed — the IR reader reads it correctly, so the
/// asserted number here is the new, higher, CORRECT value). The old shadow-check module that fed both
/// the A-tap and the live byte-scanner and asserted agreement has been retired — its job (prove the
/// A-tap matches the byte-scanner) is done, and the byte-scanner no longer exists.
#[cfg(test)]
#[path = "tests/billing_parity_tests.rs"]
mod billing_parity_tests;

#[cfg(test)]
#[path = "tests/mid_stream_error_tests.rs"]
mod mid_stream_error_tests;

#[cfg(test)]
#[path = "tests/ingress_indistinguishability_tests.rs"]
mod ingress_indistinguishability_tests;

#[cfg(test)]
#[path = "tests/forward_once_pool_cell_tests.rs"]
mod forward_once_pool_cell_tests;

#[cfg(test)]
#[path = "tests/ordered_walk_tests.rs"]
mod ordered_walk_tests;

#[cfg(test)]
#[path = "tests/probe_guard_tests.rs"]
mod probe_guard_tests;

#[cfg(test)]
#[path = "tests/hook_opt_in_projection_tests.rs"]
mod hook_opt_in_projection_tests;

#[cfg(test)]
#[path = "tests/hook_seam_tests.rs"]
mod hook_seam_tests;
