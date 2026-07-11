// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! The **Unix-socket** routing hook (`route: socket`) — an operator-run BINARY that ranks pool
//! members over a local Unix domain socket. The fast rung of the hook ladder: same wire contract as
//! the HTTP webhook (`routing::wire`, newline-delimited here instead of HTTP-framed), same hard
//! deadline, same `on_error` fail-safe — but no HTTP stack and no TCP, so a co-located compiled hook
//! answers in single-digit microseconds instead of the webhook's fraction of a millisecond.
//!
//! ## Registration model
//! A hook is a binary that OWNS a socket path; registration is one line of pool config
//! (`policy.socket: /run/busbar/router.sock`). The operator (or their init system) runs the binary —
//! busbar never spawns or supervises it, which is what keeps "a hook can never take busbar down"
//! structurally true. Busbar connects lazily on the first decision, keeps the connection alive, and
//! reconnects transparently when the binary restarts. Binary down → `Err` → the pool's `on_error`.
//!
//! ## Protocol
//! Newline-delimited JSON over the stream: busbar writes ONE line (the `wire::HookRequest`
//! projection — identical JSON to the webhook POST body), the hook replies with ONE line
//! (`{"order":[idx,...]}` / `{"abstain":true}`). The connection is reused for subsequent decisions.
//!
//! ## Security
//! The path is operator config on the local filesystem: no port, no TLS, no SSRF surface — the
//! decision cannot leave the machine. Access control is filesystem permissions on the socket file
//! (the operator's job, e.g. `0600` under a shared service user). Reply reads are capped (64 KiB)
//! and parsed through the depth-guard seam, mirroring the webhook's hostile-peer posture.
//!
//! Unix-only (`tokio::net::UnixStream` is `cfg(unix)`); on other platforms `route: socket` degrades
//! loudly to the default at config load (see `resolve_socket`) — use `route: webhook` there.
#![cfg(unix)]

use super::{Candidate, PolicyResult, RoutingContext, RoutingPolicy, RoutingRequest};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::UnixStream;
use tokio::sync::Mutex;

/// Reply-line cap — a ranking is a short list of indices; a runaway/hostile hook must not drive
/// unbounded allocation (mirrors the webhook's 64 KiB response cap).
const MAX_REPLY_BYTES: u64 = 64 * 1024;

/// One kept-alive connection to the hook binary: buffered read half + write half.
type Conn = (BufReader<OwnedReadHalf>, OwnedWriteHalf);

/// A `SocketPolicy` writes the request projection to the hook binary's Unix socket and reads back
/// the ranked order. Holds ONE kept-alive connection behind an async mutex — a decision is a
/// microseconds-scale round trip, so serializing decisions through one connection is far from being
/// a bottleneck, and one connection is what makes the hook's per-connection state (if any) simple.
pub(crate) struct SocketPolicy {
    /// The operator-configured socket path (validated non-empty at config load; the file itself may
    /// appear after boot — the hook binary can start later, connection is lazy).
    path: String,
    conn: Mutex<Option<Conn>>,
}

impl SocketPolicy {
    pub(crate) fn new(path: String) -> Self {
        Self {
            path,
            conn: Mutex::new(None),
        }
    }

    /// One request/reply round trip on an established connection. Any I/O error bubbles as `Err`;
    /// the caller decides whether to retry on a fresh connection.
    async fn round_trip(conn: &mut Conn, line: &[u8]) -> Result<Vec<u8>, std::io::Error> {
        conn.1.write_all(line).await?;
        conn.1.flush().await?;
        // A ranking reply is a short JSON line ({"order":[...]}); 128 bytes covers realistic pool
        // sizes without intermediate reallocation, while the cap below still bounds a hostile peer.
        let mut reply = Vec::with_capacity(128);
        // Cap the reply read: `take` bounds how many bytes `read_until` may pull. If the cap is hit
        // without a newline, treat it as a protocol error (peer is flooding or not speaking NDJSON).
        let mut limited = (&mut conn.0).take(MAX_REPLY_BYTES);
        let n = limited.read_until(b'\n', &mut reply).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "hook closed the connection",
            ));
        }
        if !reply.ends_with(b"\n") {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "hook reply exceeded the 64 KiB line cap or was truncated",
            ));
        }
        Ok(reply)
    }
}

#[async_trait::async_trait]
impl RoutingPolicy for SocketPolicy {
    async fn decide(
        &self,
        req: &RoutingRequest<'_>,
        candidates: &[Candidate<'_>],
        ctx: &RoutingContext<'_>,
        budget: Duration,
    ) -> PolicyResult {
        // The ONE shared hook wire projection — byte-identical JSON to the webhook's POST body, so a
        // hook graduates between transports without changing its logic. One line, newline-terminated.
        let mut line = serde_json::to_vec(&super::wire::build(req, candidates, ctx))?;
        line.reserve_exact(1); // to_vec returns an exact-fit Vec; avoid a guaranteed realloc
        line.push(b'\n');

        // Hard wall-clock deadline over the WHOLE exchange (connect + write + read): the caller also
        // wraps `decide` in its own timeout, but holding the budget here keeps the mutex hold time
        // bounded too. On timeout the half-exchanged connection is dropped (poisoned mid-protocol —
        // never reuse it), and the caller coerces the `Err` to the pool's `on_error`.
        let exchange = async {
            let mut guard = self.conn.lock().await;
            // Reuse the kept-alive connection; on ANY error retry ONCE on a fresh connection, so a
            // hook-binary restart costs zero failed requests (the cached half-dead connection is the
            // common failure after a restart, not an actual outage).
            if let Some(mut conn) = guard.take() {
                match Self::round_trip(&mut conn, &line).await {
                    Ok(reply) => {
                        *guard = Some(conn);
                        return Ok::<Vec<u8>, std::io::Error>(reply);
                    }
                    Err(e) => {
                        // Stale after a hook restart — fall through to a fresh connect. Debug (not
                        // warn): a single reconnect is normal across a hook restart, but a hook that
                        // crash-loops shows up as a steady stream of these.
                        tracing::debug!(error = %e, "socket hook: cached connection failed; reconnecting");
                    }
                }
            }
            let stream = UnixStream::connect(&self.path).await?;
            let (r, w) = stream.into_split();
            let mut conn: Conn = (BufReader::new(r), w);
            let reply = Self::round_trip(&mut conn, &line).await?;
            *guard = Some(conn);
            Ok(reply)
        };
        let reply =
            tokio::time::timeout(budget, exchange)
                .await
                .map_err(|_| -> super::PolicyError {
                    format!("socket hook deadline ({budget:?}) exceeded").into()
                })??;

        // Depth-guarded parse (MAX_JSON_DEPTH) + the shared normalizer — identical hostile-peer
        // posture and identical liberal-in-what-you-accept rules as the webhook transport.
        let parsed: super::wire::HookResponse = crate::json::parse(&reply)?;
        Ok(super::wire::normalize(parsed, candidates))
    }

    fn name(&self) -> &'static str {
        "socket"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::RoutingDecision;
    use tokio::io::AsyncReadExt;
    use tokio::net::UnixListener;

    /// A unique, short-pathed temp dir for socket files (UDS paths are length-capped ~104 bytes on
    /// macOS, so short names matter). No `tempfile` dev-dep: pid + a counter is unique enough here.
    struct TestDir(std::path::PathBuf);
    impl TestDir {
        fn new() -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static N: AtomicU64 = AtomicU64::new(0);
            let p = std::env::temp_dir().join(format!(
                "bb-sock-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&p).unwrap();
            Self(p)
        }
        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn tempdir() -> TestDir {
        TestDir::new()
    }

    /// Boot a mock hook binary on a fresh socket in a temp dir; every connection is served
    /// line-by-line with `reply` (a full line WITHOUT the newline; it is appended).
    async fn mock_hook(dir: &std::path::Path, reply: &'static str) -> String {
        let path = dir.join("hook.sock");
        let listener = UnixListener::bind(&path).unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let (r, mut w) = stream.into_split();
                    let mut reader = BufReader::new(r);
                    let mut line = String::new();
                    loop {
                        line.clear();
                        match reader.read_line(&mut line).await {
                            Ok(0) | Err(_) => break,
                            Ok(_) => {}
                        }
                        if w.write_all(format!("{reply}\n").as_bytes()).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        path.to_string_lossy().into_owned()
    }

    fn cand(idx: usize) -> Candidate<'static> {
        Candidate {
            idx,
            model: "m",
            provider: "p",
            weight: 1,
            context_max: None,
            tier: Some("large"),
            cost_per_mtok: Some(3.0),
            tags: &[],
            latency_ms: Some(42.0),
            available_concurrency: 4,
            budget_remaining: Some(1000),
            rate_headroom: Some(0.75),
        }
    }

    fn req() -> RoutingRequest<'static> {
        RoutingRequest {
            pool: "p",
            ingress_protocol: "anthropic",
            requested_model: None,
            message_count: 2,
            tool_count: 1,
            has_tools: true,
            total_chars: 1234,
            system_chars: 50,
            max_tokens: Some(256),
            stream: true,
            prompt: None,
            identity: None,
        }
    }

    fn ctx() -> RoutingContext<'static> {
        RoutingContext {
            pool: "p",
            budget_remaining: Some(500),
        }
    }

    /// TEMP timing probe (not an assertion) — measures the REAL per-decision cost of the socket
    /// transport through `SocketPolicy::decide()` (serialize + UDS round trip + parse + normalize,
    /// tokio + mutex + deadline included) against a mock Rust hook. Run:
    ///   cargo test --release --bin busbar socket_decide_timing -- --nocapture --ignored
    #[tokio::test]
    #[ignore]
    async fn socket_decide_timing() {
        let dir = tempdir();
        // Default: an in-process mock (flattering — no cross-process context switch). Set
        // BUSBAR_SOCKET_PROBE_PATH to a REAL external hook binary's socket for the honest number.
        let path = match std::env::var("BUSBAR_SOCKET_PROBE_PATH") {
            Ok(p) if !p.is_empty() => p,
            _ => mock_hook(dir.path(), r#"{"order":[2,0,1]}"#).await,
        };
        let policy = SocketPolicy::new(path);
        let cands = [cand(0), cand(1), cand(2)];
        let r = req();
        let c = ctx();
        let budget = Duration::from_millis(150);
        for _ in 0..2000 {
            policy.decide(&r, &cands, &c, budget).await.unwrap();
        }
        let mut xs = Vec::with_capacity(50_000);
        for _ in 0..50_000 {
            let t = std::time::Instant::now();
            policy.decide(&r, &cands, &c, budget).await.unwrap();
            xs.push(t.elapsed().as_nanos() as f64 / 1e3); // microseconds
        }
        xs.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let pc = |q: f64| xs[((q * xs.len() as f64) as usize).min(xs.len() - 1)];
        println!(
            "SOCKET decide() via busbar transport (3 cands, N=50000): median {:.2} us  p95 {:.2} us  p99 {:.2} us  min {:.2} us",
            xs[xs.len() / 2],
            pc(0.95),
            pc(0.99),
            xs[0]
        );
    }

    /// The happy path: hook returns an order → ranked Prefer; a second decide REUSES the connection.
    #[tokio::test]
    async fn returns_prefer_and_reuses_connection() {
        let dir = tempdir();
        let path = mock_hook(dir.path(), r#"{"order":[2,0,1]}"#).await;
        let policy = SocketPolicy::new(path);
        let cands = [cand(0), cand(1), cand(2)];
        for _ in 0..3 {
            let d = policy
                .decide(&req(), &cands, &ctx(), Duration::from_secs(2))
                .await
                .expect("ok decision");
            assert_eq!(d, RoutingDecision::Prefer(vec![2, 0, 1]));
        }
    }

    /// Explicit abstain and empty-object replies are the clean Abstain path, not errors.
    #[tokio::test]
    async fn abstain_and_empty_reply_abstain() {
        let dir = tempdir();
        for reply in [r#"{"abstain":true}"#, "{}"] {
            let path = mock_hook(dir.path(), reply).await;
            let policy = SocketPolicy::new(path);
            let d = policy
                .decide(&req(), &[cand(0)], &ctx(), Duration::from_secs(2))
                .await
                .unwrap();
            assert_eq!(d, RoutingDecision::Abstain);
            // Fresh socket path per case: remove so the next bind succeeds.
            let _ = std::fs::remove_file(dir.path().join("hook.sock"));
        }
    }

    /// Unknown idxs dropped, dups deduped — the shared normalizer applies to this transport too.
    #[tokio::test]
    async fn drops_unknown_idxs() {
        let dir = tempdir();
        let path = mock_hook(dir.path(), r#"{"order":[9,1,1,0]}"#).await;
        let policy = SocketPolicy::new(path);
        let d = policy
            .decide(&req(), &[cand(0), cand(1)], &ctx(), Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(d, RoutingDecision::Prefer(vec![1, 0]));
    }

    /// A malformed (non-JSON) reply is an `Err` → coerced to `on_error` by the seam, never a panic.
    #[tokio::test]
    async fn malformed_reply_is_err() {
        let dir = tempdir();
        let path = mock_hook(dir.path(), "not json at all").await;
        let policy = SocketPolicy::new(path);
        assert!(policy
            .decide(&req(), &[cand(0)], &ctx(), Duration::from_secs(2))
            .await
            .is_err());
    }

    /// No binary listening (dead path) → `Err` (→ `on_error`), fast — never a hang.
    #[tokio::test]
    async fn hook_down_is_err() {
        let dir = tempdir();
        let path = dir.path().join("nobody-home.sock");
        let policy = SocketPolicy::new(path.to_string_lossy().into_owned());
        assert!(policy
            .decide(&req(), &[cand(0)], &ctx(), Duration::from_millis(250))
            .await
            .is_err());
    }

    /// A hook that never replies is cut off by the budget (the in-transport deadline), not hung.
    #[tokio::test]
    async fn silent_hook_times_out() {
        let dir = tempdir();
        let path = dir.path().join("silent.sock");
        let listener = UnixListener::bind(&path).unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                // Read forever, never reply.
                tokio::spawn(async move {
                    let mut sink = Vec::new();
                    let _ = stream.read_to_end(&mut sink).await;
                });
            }
        });
        let policy = SocketPolicy::new(path.to_string_lossy().into_owned());
        let t = std::time::Instant::now();
        let r = policy
            .decide(&req(), &[cand(0)], &ctx(), Duration::from_millis(120))
            .await;
        assert!(r.is_err(), "a silent hook must surface as Err");
        assert!(
            t.elapsed() < Duration::from_secs(1),
            "the deadline must cut the exchange off promptly"
        );
    }

    /// A hook flooding MORE than the 64 KiB reply cap without a newline must surface as `Err`
    /// (bounded allocation, no hang) — the hostile-peer guard on the reply read.
    #[tokio::test]
    async fn oversized_reply_is_err_not_unbounded() {
        let dir = tempdir();
        let path = dir.path().join("flood.sock");
        let listener = UnixListener::bind(&path).unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let (r, mut w) = stream.into_split();
                    let mut reader = BufReader::new(r);
                    let mut line = String::new();
                    if reader.read_line(&mut line).await.is_ok() {
                        // 80 KiB of 'a' with no newline: past the cap, never a complete line.
                        let flood = vec![b'a'; 80 * 1024];
                        let _ = w.write_all(&flood).await;
                    }
                    // Keep the connection open so the reader hits the cap, not EOF.
                    tokio::time::sleep(Duration::from_secs(5)).await;
                });
            }
        });
        let policy = SocketPolicy::new(path.to_string_lossy().into_owned());
        let r = policy
            .decide(&req(), &[cand(0)], &ctx(), Duration::from_secs(2))
            .await;
        assert!(r.is_err(), "a flooding hook must surface as Err, got {r:?}");
    }

    /// After a DEADLINE-EXCEEDED decision (the connection is dropped mid-protocol), the NEXT
    /// decision must reconnect cleanly and succeed — a poisoned connection is never reused.
    #[tokio::test]
    async fn poisoned_connection_after_timeout_reconnects_cleanly() {
        let dir = tempdir();
        let path = dir.path().join("slowfast.sock");
        let listener = UnixListener::bind(&path).unwrap();
        // First connection: read the request, never reply (forces the deadline). Every LATER
        // connection: behave normally.
        tokio::spawn(async move {
            let mut first = true;
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let hang = std::mem::take(&mut first);
                tokio::spawn(async move {
                    let (r, mut w) = stream.into_split();
                    let mut reader = BufReader::new(r);
                    let mut line = String::new();
                    loop {
                        line.clear();
                        match reader.read_line(&mut line).await {
                            Ok(0) | Err(_) => break,
                            Ok(_) => {}
                        }
                        if hang {
                            tokio::time::sleep(Duration::from_secs(10)).await;
                            break;
                        }
                        if w.write_all(b"{\"order\":[0]}\n").await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        let policy = SocketPolicy::new(path.to_string_lossy().into_owned());
        let cands = [cand(0)];
        // Decision 1: the hook hangs -> deadline exceeded -> Err; the half-exchanged connection
        // must be discarded (it was moved into the timed-out future and dropped).
        let r1 = policy
            .decide(&req(), &cands, &ctx(), Duration::from_millis(100))
            .await;
        assert!(r1.is_err(), "hung hook must exceed the deadline");
        // Decision 2: a fresh connection must be made and succeed.
        let r2 = policy
            .decide(&req(), &cands, &ctx(), Duration::from_secs(2))
            .await
            .expect("post-timeout decision must reconnect cleanly");
        assert_eq!(r2, RoutingDecision::Prefer(vec![0]));
    }

    /// The hook binary RESTARTS between decisions: the cached connection is stale, and the
    /// retry-once-on-fresh-connection logic makes the next decision succeed with zero failures.
    #[tokio::test]
    async fn survives_hook_restart_with_zero_failed_decisions() {
        let dir = tempdir();
        let path = dir.path().join("hook.sock");
        let path_str = path.to_string_lossy().into_owned();

        // First hook process: serve exactly one connection, then drop it (simulates a restart).
        let listener = UnixListener::bind(&path).unwrap();
        let policy = SocketPolicy::new(path_str.clone());
        let cands = [cand(0), cand(1)];
        let serve_one = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (r, mut w) = stream.into_split();
            let mut reader = BufReader::new(r);
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            w.write_all(b"{\"order\":[1,0]}\n").await.unwrap();
            // Connection + listener drop here — the "old" binary is gone.
            drop(reader);
            drop(w);
            drop(listener);
        });
        let d = policy
            .decide(&req(), &cands, &ctx(), Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(d, RoutingDecision::Prefer(vec![1, 0]));
        serve_one.await.unwrap();

        // "Restarted" hook binary on the SAME path (rebind after removing the stale file).
        let _ = std::fs::remove_file(&path);
        let _path2 = mock_hook(dir.path(), r#"{"order":[0,1]}"#).await;

        // The cached connection is stale; the retry-once logic must transparently reconnect.
        let d = policy
            .decide(&req(), &cands, &ctx(), Duration::from_secs(2))
            .await
            .expect("post-restart decision must succeed via reconnect");
        assert_eq!(d, RoutingDecision::Prefer(vec![0, 1]));
    }

    /// The reject verb over the socket transport: the hook's `{"reject":{...}}` reply surfaces as
    /// a `RoutingDecision::Reject` with the clamped status + sanitized message.
    #[tokio::test]
    async fn reject_reply_surfaces_as_reject_decision() {
        let dir = tempdir();
        let path = mock_hook(
            dir.path(),
            r#"{"reject":{"status":451,"message":"PII detected"}}"#,
        )
        .await;
        let policy = SocketPolicy::new(path);
        let d = policy
            .decide(&req(), &[cand(0)], &ctx(), Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(
            d,
            RoutingDecision::Reject {
                status: 451,
                message: "PII detected".to_string()
            }
        );
    }

    /// End-to-end opt-in payload over the REAL socket wire: a hook that keys its decision on what
    /// it saw proves the prompt + identity projections (and tags) actually arrive — and that a
    /// default request carries none of them.
    #[tokio::test]
    async fn opt_in_payload_rides_the_socket_wire() {
        // A mock hook that INSPECTS the request line: replies order [1,0] iff the payload carries
        // the opt-in keys (system/messages/user + a tag), else abstains.
        async fn inspecting_hook(dir: &std::path::Path) -> String {
            let path = dir.join("hook.sock");
            let listener = UnixListener::bind(&path).unwrap();
            tokio::spawn(async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        break;
                    };
                    tokio::spawn(async move {
                        let (r, mut w) = stream.into_split();
                        let mut reader = BufReader::new(r);
                        let mut line = String::new();
                        loop {
                            line.clear();
                            match reader.read_line(&mut line).await {
                                Ok(0) | Err(_) => break,
                                Ok(_) => {}
                            }
                            let v: serde_json::Value =
                                serde_json::from_str(&line).unwrap_or_default();
                            let saw_all = v["request"]["system"] == "be brief"
                                && v["request"]["messages"][0]["text"] == "hello"
                                && v["request"]["user"]["key_name"] == "sales-team"
                                && v["candidates"][0]["tags"][0] == "eu";
                            let reply = if saw_all {
                                "{\"order\":[1,0]}\n"
                            } else {
                                "{\"abstain\":true}\n"
                            };
                            if w.write_all(reply.as_bytes()).await.is_err() {
                                break;
                            }
                        }
                    });
                }
            });
            path.to_string_lossy().into_owned()
        }

        static TAGS: std::sync::LazyLock<Vec<String>> =
            std::sync::LazyLock::new(|| vec!["eu".into()]);
        let dir = tempdir();
        let path = inspecting_hook(dir.path()).await;
        let policy = SocketPolicy::new(path);
        let mut c0 = cand(0);
        c0.tags = TAGS.as_slice();
        let cands = [c0, cand(1)];

        // Default request (no opt-ins): the hook must NOT see the keys → abstain.
        let d = policy
            .decide(&req(), &cands, &ctx(), Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(d, RoutingDecision::Abstain);

        // Opt-in request: prompt + identity populated (as `forward` does behind the flags).
        let mut r = req();
        r.prompt = Some(crate::routing::PromptProjection {
            system: Some("be brief".into()),
            messages: vec![("user".into(), "hello".into())],
        });
        r.identity = Some(crate::routing::CallerIdentity {
            key_id: Some("k-1".into()),
            key_name: Some("sales-team".into()),
            user: None,
        });
        let d = policy
            .decide(&r, &cands, &ctx(), Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(d, RoutingDecision::Prefer(vec![1, 0]));
    }
}
