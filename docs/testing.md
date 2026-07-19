# Testing strategy

How busbar is tested, and how to add a test. Companion to
[development.md](development.md) (build/lint commands) and
[internals.md](internals.md) (the systems under test). The disposition taxonomy
is [ADR-0002](adr/0002-circuit-breaker.md).

## Shape of the suite

All tests are **in-crate** and run under `cargo test`. There is no `tests/`
directory of integration binaries. Two patterns:

- **Per-module `#[cfg(test)] mod tests`**: unit tests next to the code they cover
  (`store.rs` breaker FSM, `breaker.rs` classification, `sigv4.rs` against AWS's
  published worked example, `governance.rs` key/budget/rate, `config.rs` parsing,
  `ingress/mod.rs` affinity, `proto/*.rs` translation round-trips, etc.).
- **The `test_support.rs` harness**: a shared `#[cfg(test)] mod test_support`
  with the `MockServer` mock-upstream and the bulk of the end-to-end forwarding
  tests.

## The MockServer harness (`crates/busbar/src/test_support/mod.rs`)

`MockServer` is a real axum server bound to `127.0.0.1:0` (ephemeral port) that
serves every upstream path through one handler: `/v1/messages` and
`/v1/chat/completions` have named routes, and a catch-all `.fallback` routes all
other paths (Bedrock `/model/{model}/converse[-stream]`, Gemini
`/v1beta/models/...`, Cohere `/v2/chat`) through the same handler. You program its
responses ahead of time by pushing onto a shared `MockServerState`:

- **`MockServerState`** holds a `Mutex<Vec<MockResponse>>` (LIFO: `push` then
  `pop` per request), plus the **last seen** auth header and request body for
  assertions (`get_last_auth_header`, `get_last_request_body`).
- **`MockResponse`** variants model upstream behaviors: `Ok { status, body }`,
  `RateLimit { status, provider_signal, retry_after }` (`retry_after:
  Option<u64>` emits a `Retry-After: <n>` header in whole seconds when set),
  `Billing { status, code, message }`, `Auth { status }`,
  `ServerError { status, body }`,
  `Sse { events, abort_at_index }` (the `abort_at_index` simulates a mid-stream
  upstream abort: it sends N events then an SSE `error` frame with no `[DONE]`,
  exercising the after-first-byte path),
  `SseTransportError { ok_events }` (emits the `ok_events` real SSE frames then
  makes the body stream yield an `Err`, a true mid-stream **transport** failure
  that exercises `FirstByteBody`'s `Err` arm rather than a clean SSE `error`
  text frame), and
  `EventStream { frames, amzn_request_id }` (a native AWS binary
  `application/vnd.amazon.eventstream` body as a real Bedrock ConverseStream
  backend emits: `frames` is the ordered `(event_type, json_payload)` sequence
  encoded via `eventstream::encode_frame`, and `amzn_request_id` is served as
  the `x-amzn-RequestId` header for testing same-protocol Bedrock passthrough).

```rust
let state = Arc::new(MockServerState::new());
state.push(MockResponse::ServerError {            // popped first
    status: StatusCode::INTERNAL_SERVER_ERROR,
    body: json!({ "error": "server error" }),
});
let server = MockServer::new(state.clone()).await;
// server.base_url() -> "http://127.0.0.1:<port>"
// ... drive a request ...
server.shutdown().await;                          // aborts the task
```

## Injecting time into the breaker FSM

Breaker/cooldown tests must not depend on wall-clock. The breaker reads time via
`store::now()` (the public crate function at `crates/busbar/src/store/mod.rs:61`), which under
`#[cfg(test)]` is shadowed inside `InMemoryStore` by a private `now_secs()` that
delegates to `now_for_test()`:

- `set_now_for_test(t)` pins the test clock to `t` (epoch seconds).
- `now_for_test()` returns the pinned value (falling back to real `now()` if
  unset).

So a cooldown test sets the clock, records a failure, advances the clock past the
cooldown, and asserts the lane becomes usable again, all deterministically. The
store also exposes `#[cfg(test)]` lane-indexed handles (`open_state`,
`closed_state`, `open_state_with_retry_after`, `try_acquire_probe`, `clear_probe`,
`record_outcome_error_with_time`, `record_outcome_success_with_time`) to seed the
default cell's FSM/window directly without HTTP.

## The disposition matrix

The Stage 1b/Stage 2 pipeline (`breaker.rs`) is covered both as unit tests (raw
error → `StatusClass` → `Disposition`) and end-to-end via the `MockResponse`
variants that map onto each class: `Billing`/`Auth` → `HardDown`,
`RateLimit`/`ServerError` → `TransientUpstream`, an `Ok` with a context-length
provider code → `ContextLength`, and a plain 4xx → `ClientFault`. Because the
disposition `match` is exhaustive (no `_ =>`), adding a `StatusClass` forces a new
test arm to compile. Verify the **lane-effect** in each case: client faults and
context-length must **not** move the breaker (assert `streak`/`err` unchanged via
`/stats`-style `snapshot`), hard-down/transient must.

## Governance tests

`governance.rs` tests use `SqliteStore::open_in_memory()` (no temp files):
key CRUD round-trips, `budget_window` period math (total/daily/monthly),
`is_over_budget` + `record_request` accumulation, `check_rate` RPM windows, and
token-cost accrual via `record_tokens`. These run against the `Store` trait /
`GovState` directly, not through HTTP.

## Writing a new forwarding integration test

Drive `forward_with_pool` (or the thin `forward` wrapper) against a `MockServer`.
The skeleton (adapted from `test_support.rs`'s `test_non_stream_json_relay`):

```rust
#[tokio::test]
async fn my_forwarding_test() {
    crate::metrics::init();                       // so the forward path's counters record

    let state = Arc::new(MockServerState::new());
    state.push(MockResponse::Ok {
        status: StatusCode::OK,
        body: json!({ "content": ["Hello"], "model": "test" }),
    });
    let server = MockServer::new(state.clone()).await;

    // 1. a LaneData (lane-global state) and a Lane (runtime) pointing at the mock
    let lane_data = LaneData { model: "m".into(), provider: "p".into(), max: 10,
        sem: Arc::new(tokio::sync::Semaphore::new(10)), limited: false, budget: -1,
        cooldown_until: 0, streak: 0, dead: false, dead_reason: String::new(),
        ok: 0, err: 0, client_fault: 0 };
    let lane = Lane { model: "m".into(), provider: "p".into(),
        base_url: server.base_url(), api_key: "k".into(),
        protocol: Arc::new(crate::proto::Protocol::anthropic()), max: 10,
        error_map: Arc::new(HashMap::new()), context_max: None,
        path: None, auth: None, health: None, default_max_tokens: None };

    // 2. assemble App (store from the lane_data, governance/observability off)
    let app = Arc::new(App {
        lanes: vec![lane],
        store: Arc::new(InMemoryStore::new(vec![lane_data])),
        by_model: HashMap::from([("m".into(), 0)]),
        pools: HashMap::from([("default".into(), vec![WeightedLane { idx: 0, weight: 1 }])]),
        client: Client::builder().timeout(Duration::from_secs(30)).build().unwrap(),
        auth: Arc::new(AuthMiddleware::new(&AuthCfg::default_none())),
        auth_mode: crate::auth::AuthMode::None,
        failover_cfg: None, pool_runtime: HashMap::new(),
        fallback_pools: HashMap::new(), on_exhausted_cfgs: HashMap::new(),
        governance: None,
    });

    // 3. drive it
    let body = serde_json::to_vec(&json!({
        "model": "m", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100
    })).unwrap();
    let resp = forward_with_pool(
        app.clone(),
        vec![WeightedLane { idx: 0, weight: 1 }],
        body.into(),
        None,            // caller_token (passthrough only)
        "default",       // pool name -> picks the per-pool breaker cell
        None,            // affinity key
        "anthropic",     // ingress protocol
        None,            // usage sink (governance off)
    ).await;

    assert_eq!(resp.status().as_u16(), 200);
    server.shutdown().await;
}
```

Patterns this enables:

- **Failover**: give a pool two members backed by two `MockServer`s; push a
  `ServerError`/`RateLimit` on the first and an `Ok` on the second; assert the
  request still 200s and the first lane's breaker moved.
- **Cross-protocol**: set the lane's `protocol` to OpenAI and call with
  `ingress_protocol = "anthropic"`; assert the upstream `get_last_request_body`
  is OpenAI-shaped and the translated response preserves `model`.
- **Streaming + after-first-byte**: push `MockResponse::Sse { abort_at_index:
  Some(n) }`; assert the client gets the first n events then an SSE `error` frame
  (no failover) and the breaker records the fault.
- **Mid-stream transport error**: push `MockResponse::SseTransportError {
  ok_events }`; the body yields the real frames then an `Err`, exercising the
  after-first-byte mid-stream error path (`FirstByteBody`'s `Err` arm), which
  appends the ingress protocol's native mid-stream error frame after the
  already-sent frames.
- **Bedrock ConverseStream passthrough**: push `MockResponse::EventStream {
  frames, amzn_request_id }` with a Bedrock-protocol lane and a Bedrock ingress;
  assert the same-protocol path relays the binary event-stream verbatim,
  preserves the `application/vnd.amazon.eventstream` content type, and forwards
  the upstream `x-amzn-RequestId` rather than synthesizing a fresh one.
  Note: `MockServer`'s catch-all `.fallback` serves every path, so Bedrock's
  native egress path (`/model/{model}/converse-stream`) reaches the handler with
  no path override needed. Some existing lanes still set `.path("/v1/messages")`;
  that override is now optional (any path resolves to the same handler), since the
  same-protocol relay keys off the upstream Content-Type, not the URL. See
  `test_bedrock_same_protocol_stream_passthrough_forwards_upstream_request_id`
  in `crates/busbar/src/ingress/mod.rs` for the full pattern.
- **on_exhausted**: populate `on_exhausted_cfgs` with `LeastBad` /
  `FallbackPool(..)` and pre-trip all members; assert the configured behavior
  (and loop-guarding for fallback chains).
- **Reading body bytes** in assertions: collect the response body with
  `http_body_util::BodyExt`'s `.collect().await`.

> Reminder: collect response bodies and assert metrics via
> `crate::metrics::render()`; call `crate::metrics::init()` once at the top of any
> test that exercises the forward path or its counters won't be installed.
