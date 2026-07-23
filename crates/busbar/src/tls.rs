// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Native inbound TLS termination (+ optional mutual-TLS) for the client↔Busbar hop.
//!
//! This module is a thin transport wrapper around the *ingress* listener. It does NOT touch routing,
//! request translation, the breaker, or failover — it only decides, once at startup, whether the
//! accepted TCP stream is handed to axum as-is (plain HTTP, the historical default) or first put
//! through a rustls server handshake.
//!
//! ## Why we drive hyper directly here instead of `axum::serve`
//!
//! `axum::serve` in axum 0.7 is hardwired to a concrete `tokio::net::TcpListener` and constructs its
//! per-connection `IncomingStream` from private fields — there is no public `Listener` trait to
//! implement (that arrived in axum 0.8). Rather than bump axum (which would churn the Router/Service
//! types on the routing hot path this feature is contractually forbidden from touching), the TLS
//! branch reproduces axum::serve's accept loop over hyper-util directly:
//!   * accept on the `TcpListener`,
//!   * run the rustls handshake,
//!   * serve the connection with `hyper_util::server::conn::auto::Builder` (http/1.1) and
//!     `TowerToHyperService` bridging the cloned axum `Router`,
//!   * drain in-flight connections on shutdown via `hyper_util`'s `GracefulShutdown`.
//!
//! The plain-HTTP path in `main.rs` is left exactly as it was; only `cfg.tls == Some(_)` reaches
//! this module.
//!
//! ## Crypto provider
//!
//! rustls 0.23 requires a process-wide [`rustls::crypto::CryptoProvider`]. busbar already links
//! `ring` (via reqwest/hyper-rustls), so [`install_crypto_provider`] installs ring's provider once
//! at startup and the `ServerConfig` is built on it — exactly one provider in the process, never
//! aws-lc-rs.
//!
//! ## Failure model
//!
//! Any cert/key/CA load or parse error is fatal at startup (`die`) with a message naming the file;
//! key bytes are never logged. A handshake failure on a single connection is logged at debug and
//! drops only that connection — it never crashes the server or affects other clients.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

/// Hard wall-clock bound on the TLS handshake for a single accepted connection. A client that
/// connects then stalls (sends nothing / dribbles handshake bytes) must not park a task + FDs
/// indefinitely — this caps the pre-auth slowloris / handshake-flood surface. The cost is incurred
/// BEFORE mTLS client-cert verification, so this guards the unauthenticated edge.
/// Operator-tunable via `limits.tls_handshake_timeout_secs` (default 10s), read through the
/// process-wide `crate::limits` install. A function (not a `const`) so the configured value is read
/// per accepted connection; falls back to the historical 10s when limits aren't installed.
fn handshake_timeout() -> Duration {
    Duration::from_secs(crate::limits::tls_handshake_timeout_secs())
}

/// Max wall-clock time allowed BETWEEN inbound request-body frames before the connection is dropped.
/// The header-read timeout (`hardened_conn_builder`) covers ONLY the header phase - once headers are
/// complete an unauthenticated slow-loris can dribble the request BODY one byte at a time, holding a
/// connection task, an FD, AND (critically) one of the finite `max_inbound_concurrent` (default 8192)
/// permits indefinitely, starving real traffic. `DefaultBodyLimit` caps total SIZE, not TIME between
/// frames, so it does not help. This wraps every inbound body in a [`TimeoutBody`] that trips when no
/// frame arrives within this bound. Operator-tunable via `limits.request_body_read_timeout_secs`
/// (default 30s), read per connection through the process-wide `crate::limits` install; falls back to
/// the default when limits aren't installed (tests / pre-install).
fn body_read_timeout() -> Duration {
    Duration::from_secs(crate::limits::request_body_read_timeout_secs())
}

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::Router;
use http_body::{Body, Frame, SizeHint};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use hyper_util::server::graceful::GracefulShutdown;
use hyper_util::service::TowerToHyperService;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::config::TlsCfg;

/// Install ring's [`rustls::crypto::CryptoProvider`] as the process default.
///
/// Idempotent and safe to call alongside reqwest/hyper-rustls, which also use ring: a "provider
/// already installed" error is expected and ignored, because all we require is that *a ring provider*
/// is the process default before any `ServerConfig` is built. Must run before [`build_server_config`].
pub(crate) fn install_crypto_provider() {
    // Err(_) => some other code path already installed a provider. Since busbar only ever links ring,
    // that provider is ring too, so there is nothing to fix and nothing to warn about.
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Resolve a TLS secret reference to its PEM bytes, mapping any resolve error into a clear,
/// source-named message. Never logs contents.
fn read_pem(
    resolver: &crate::config::secret::SecretResolver,
    secret: &crate::config::SecretRef,
    what: &str,
) -> Result<Vec<u8>, String> {
    resolver
        .resolve(secret)
        .map_err(|e| format!("cannot resolve TLS {what} ({}): {e}", secret.describe()))
}

/// Parse the PEM certificate chain (leaf first). Errors name the secret source; cert bytes are
/// public, but we still avoid echoing them.
fn load_cert_chain(
    resolver: &crate::config::secret::SecretResolver,
    secret: &crate::config::SecretRef,
) -> Result<Vec<CertificateDer<'static>>, String> {
    let src = secret.describe();
    let bytes = read_pem(resolver, secret, "cert")?;
    let certs = CertificateDer::pem_slice_iter(&bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("cannot parse TLS cert ({src}): {e}"))?;
    if certs.is_empty() {
        return Err(format!(
            "TLS cert ({src}) contains no certificates (expected a PEM chain, leaf first)"
        ));
    }
    Ok(certs)
}

/// Parse the PEM private key, accepting PKCS#8, PKCS#1 (RSA), or SEC1 (EC) encodings. NEVER logs key
/// material - error messages name only the secret source.
fn load_private_key(
    resolver: &crate::config::secret::SecretResolver,
    secret: &crate::config::SecretRef,
) -> Result<PrivateKeyDer<'static>, String> {
    let src = secret.describe();
    let bytes = read_pem(resolver, secret, "key")?;
    // `PrivateKeyDer::from_pem_slice` accepts PKCS#8, PKCS#1 (RSA), and SEC1 (EC) sections, picking the
    // first private-key section it finds. `NoItemsFound` means none was present; any other variant is a
    // genuine parse error. Neither path echoes key material - error messages name only the source.
    use rustls::pki_types::pem::Error as PemError;
    PrivateKeyDer::from_pem_slice(&bytes).map_err(|e| match e {
        PemError::NoItemsFound => {
            format!("TLS key ({src}) contains no private key (expected PKCS#8 / PKCS#1 / SEC1 PEM)")
        }
        other => format!("cannot parse TLS key ({src}): {other}"),
    })
}

/// Build the client-cert verifier root store from the operator's CA bundle (mTLS).
fn load_client_roots(
    resolver: &crate::config::secret::SecretResolver,
    secret: &crate::config::SecretRef,
) -> Result<RootCertStore, String> {
    let src = secret.describe();
    let bytes = read_pem(resolver, secret, "client_ca")?;
    let cas = CertificateDer::pem_slice_iter(&bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("cannot parse TLS client_ca ({src}): {e}"))?;
    if cas.is_empty() {
        return Err(format!("TLS client_ca ({src}) contains no CA certificates"));
    }
    let mut roots = RootCertStore::empty();
    for ca in cas {
        roots
            .add(ca)
            .map_err(|e| format!("invalid CA certificate in TLS client_ca ({src}): {e}"))?;
    }
    Ok(roots)
}

/// Construct the rustls [`ServerConfig`] from the operator's [`TlsCfg`].
///
/// * `client_ca` present ⇒ a [`WebPkiClientVerifier`] is installed: the client MUST present a
///   certificate chaining to that CA or the handshake fails (mTLS required).
/// * `client_ca` absent ⇒ `with_no_client_auth()` (server-only TLS).
///
/// ALPN advertises only `http/1.1` — busbar's axum server speaks http/1.1, so we must not advertise
/// h2. Returns a clear, source-named error on any load/parse problem (the caller turns it into `die`).
pub(crate) fn build_server_config(
    tls: &TlsCfg,
    resolver: &crate::config::secret::SecretResolver,
) -> Result<ServerConfig, String> {
    let certs = load_cert_chain(resolver, &tls.cert)?;
    let key = load_private_key(resolver, &tls.key)?;

    let builder = ServerConfig::builder();

    let builder = match &tls.client_ca {
        Some(ca) => {
            let roots = load_client_roots(resolver, ca)?;
            let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
                .build()
                .map_err(|e| {
                    format!(
                        "cannot build client-cert verifier from TLS client_ca ({}): {e}",
                        ca.describe()
                    )
                })?;
            builder.with_client_cert_verifier(verifier)
        }
        None => builder.with_no_client_auth(),
    };

    let mut config = builder.with_single_cert(certs, key).map_err(|e| {
        format!(
            "TLS cert/key are not a valid pair (cert {}, key {}): {e}",
            tls.cert.describe(),
            tls.key.describe()
        )
    })?;

    // http/1.1 only — busbar's axum 0.7 server does not serve h2.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    Ok(config)
}

/// Serve `router` over TLS on `listener` until `shutdown` resolves, then drain in-flight connections.
///
/// Mirrors `axum::serve(listener, router).with_graceful_shutdown(shutdown)` for the TLS case:
/// each accepted connection is handshook with rustls and served with hyper's auto builder (http/1.1).
/// A handshake or accept error affects only that one connection — the accept loop continues, so a
/// rejected mTLS client (wrong/missing cert) never takes the server down or blocks other clients.
pub(crate) async fn serve(
    listener: TcpListener,
    router: Router,
    server_config: ServerConfig,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> io::Result<()> {
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let graceful = GracefulShutdown::new();
    let conn_builder = Arc::new(hardened_conn_builder());

    let mut shutdown = std::pin::pin!(shutdown);

    loop {
        let (stream, peer) = tokio::select! {
            biased;
            () = &mut shutdown => break,
            accepted = listener.accept() => match accepted {
                Ok(pair) => pair,
                Err(e) => {
                    // A transient accept error (e.g. fd exhaustion, peer reset mid-accept) must not
                    // kill the loop; log and keep serving.
                    tracing::debug!(error = %e, "tls: accept error; continuing");
                    continue;
                }
            },
        };

        let acceptor = acceptor.clone();
        let router = router.clone();
        let conn_builder = conn_builder.clone();
        let watcher = graceful.watcher();

        tokio::spawn(async move {
            serve_one(acceptor, conn_builder, watcher, stream, peer, router).await;
        });
    }

    // Stop accepting; drain in-flight connections (the watched futures complete on their own once
    // their requests finish or their clients hang up).
    graceful.shutdown().await;
    Ok(())
}

/// An inbound-body wrapper that bounds the wall-clock time between successive frames. Wraps the
/// hyper `Incoming` body; each `poll_frame` races the inner poll against a `body_read_timeout()`
/// timer that is RESET on every delivered frame. If no frame arrives within the bound, the body
/// yields an error, which hyper surfaces as a connection error - dropping the stalled connection and
/// freeing its task, FD, and inbound-concurrency permit. A body that keeps delivering frames on time
/// is passed through unchanged, so a slow-but-progressing large upload is never falsely killed; only
/// a stall (no bytes for `timeout`) trips it. `SizeHint`/`is_end_stream` delegate to the inner body
/// so framing/content-length behavior is identical to the unwrapped body.
struct TimeoutBody<B> {
    inner: B,
    timeout: Duration,
    // Lazily-armed inter-frame timer. Re-armed after every delivered frame; `None` until the first
    // poll so the timer is driven from the runtime clock inside the connection task.
    sleep: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl<B> TimeoutBody<B> {
    fn new(inner: B, timeout: Duration) -> Self {
        Self {
            inner,
            timeout,
            sleep: None,
        }
    }
}

/// The error a [`TimeoutBody`] yields when the inter-frame bound elapses. Boxed into the router's
/// body-error type; the message is generic (no client bytes) so it is safe to surface.
#[derive(Debug)]
struct BodyReadTimeout;

impl std::fmt::Display for BodyReadTimeout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "inbound request body read timed out (slow-loris body bound)"
        )
    }
}
impl std::error::Error for BodyReadTimeout {}

impl<B> Body for TimeoutBody<B>
where
    B: Body + Unpin,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Data = B::Data;
    type Error = Box<dyn std::error::Error + Send + Sync>;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = &mut *self;
        // Poll the underlying body first: a frame ready right now short-circuits the timer entirely.
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                // Progress: reset the inter-frame timer for the NEXT frame.
                this.sleep = None;
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e.into()))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => {
                // No frame yet: arm (or poll) the inter-frame timer. On elapse, fail the body so the
                // connection is dropped rather than parked indefinitely on a dribbling client.
                let timeout = this.timeout;
                let sleep = this
                    .sleep
                    .get_or_insert_with(|| Box::pin(tokio::time::sleep(timeout)));
                match sleep.as_mut().poll(cx) {
                    Poll::Ready(()) => Poll::Ready(Some(Err(Box::new(BodyReadTimeout)))),
                    Poll::Pending => Poll::Pending,
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// A hyper `Service` that wraps every inbound request's body in a [`TimeoutBody`] before delegating
/// to the axum router (bridged by `TowerToHyperService`). This is the seam that installs the
/// body-read slow-loris bound on BOTH the TLS and plain serve loops, without touching the router or
/// the routing hot path - the router sees an ordinary `http_body::Body`, just one that fails on a
/// stalled inbound stream.
#[derive(Clone)]
struct BodyTimeoutService {
    inner: TowerToHyperService<Router>,
    timeout: Duration,
}

impl BodyTimeoutService {
    fn new(router: Router, timeout: Duration) -> Self {
        Self {
            inner: TowerToHyperService::new(router),
            timeout,
        }
    }
}

impl hyper::service::Service<hyper::Request<hyper::body::Incoming>> for BodyTimeoutService {
    type Response = <TowerToHyperService<Router> as hyper::service::Service<
        hyper::Request<TimeoutBody<hyper::body::Incoming>>,
    >>::Response;
    type Error = <TowerToHyperService<Router> as hyper::service::Service<
        hyper::Request<TimeoutBody<hyper::body::Incoming>>,
    >>::Error;
    type Future = <TowerToHyperService<Router> as hyper::service::Service<
        hyper::Request<TimeoutBody<hyper::body::Incoming>>,
    >>::Future;

    fn call(&self, req: hyper::Request<hyper::body::Incoming>) -> Self::Future {
        let timeout = self.timeout;
        let req = req.map(|body| TimeoutBody::new(body, timeout));
        self.inner.call(req)
    }
}

/// Build the hyper auto connection builder shared by BOTH the plain-HTTP and TLS serve loops.
///
/// Bounds the HTTP/1 HEADER-read phase (slow-loris defense): a client that opens a connection and
/// then trickles request headers one byte at a time would otherwise hold the connection task + FD
/// indefinitely — `DefaultBodyLimit` only applies AFTER headers are fully received, so it does not
/// help here. `header_read_timeout` bounds ONLY the header phase, so it never truncates a
/// legitimately long response stream (an LLM completion can stream for minutes). 30s is far longer
/// than any real client needs to send its request line + headers, so it cannot false-positive on a
/// healthy connection. `header_read_timeout` requires a `Timer` (hyper panics otherwise), so the
/// Tokio timer is wired to drive it from the runtime clock.
fn hardened_conn_builder() -> ConnBuilder<TokioExecutor> {
    let mut builder = ConnBuilder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(std::time::Duration::from_secs(30));
    builder
}

/// Plain-HTTP serve loop — the no-`tls`-block default path. Mirrors `serve` (and the historical
/// `axum::serve(listener, router).with_graceful_shutdown(shutdown)`) but over the bare TCP stream
/// (no TLS handshake). Routed through the SAME `hardened_conn_builder` so the plain listener gets the
/// identical slow-loris header-read bound the TLS listener has — the previous `axum::serve` path
/// exposed no such timeout, leaving a plain-HTTP edge deployment open to header-trickle clients.
pub(crate) async fn serve_plain(
    listener: TcpListener,
    router: Router,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> io::Result<()> {
    let graceful = GracefulShutdown::new();
    let conn_builder = Arc::new(hardened_conn_builder());
    let mut shutdown = std::pin::pin!(shutdown);

    loop {
        let (stream, peer) = tokio::select! {
            biased;
            () = &mut shutdown => break,
            accepted = listener.accept() => match accepted {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::debug!(error = %e, "http: accept error; continuing");
                    continue;
                }
            },
        };

        let router = router.clone();
        let conn_builder = conn_builder.clone();
        let watcher = graceful.watcher();

        tokio::spawn(async move {
            serve_one_plain(conn_builder, watcher, stream, peer, router).await;
        });
    }

    graceful.shutdown().await;
    Ok(())
}

/// Serve a single accepted plain-TCP connection. Any failure is contained to this connection.
async fn serve_one_plain(
    conn_builder: Arc<ConnBuilder<TokioExecutor>>,
    watcher: hyper_util::server::graceful::Watcher,
    stream: tokio::net::TcpStream,
    peer: SocketAddr,
    router: Router,
) {
    // TCP_NODELAY parity with axum::serve (which sets it by default on accepted streams).
    if let Err(e) = stream.set_nodelay(true) {
        tracing::debug!(error = %e, %peer, "http: set_nodelay failed; continuing");
    }
    let service = BodyTimeoutService::new(router, body_read_timeout());
    let io = TokioIo::new(stream);
    let conn = conn_builder.serve_connection_with_upgrades(io, service);
    let conn = watcher.watch(conn);
    if let Err(e) = conn.await {
        tracing::debug!(error = %e, %peer, "http: connection error");
    }
}

/// Handshake + serve a single accepted TCP connection. Any failure is contained to this connection.
async fn serve_one(
    acceptor: TlsAcceptor,
    conn_builder: Arc<ConnBuilder<TokioExecutor>>,
    watcher: hyper_util::server::graceful::Watcher,
    stream: tokio::net::TcpStream,
    peer: SocketAddr,
    router: Router,
) {
    // TCP_NODELAY parity with axum::serve (which sets it by default on accepted streams).
    if let Err(e) = stream.set_nodelay(true) {
        tracing::debug!(error = %e, %peer, "tls: set_nodelay failed; continuing");
    }

    // Bound the handshake (see `handshake_timeout()`): on elapse the `accept` future is dropped, which
    // closes the half-open connection and frees the task + FDs. Cancel-safe — no state escapes.
    let tls_stream = match tokio::time::timeout(handshake_timeout(), acceptor.accept(stream)).await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            // Handshake failure (bad/missing client cert under mTLS, protocol mismatch, client gone).
            // Debug-level and dropped — never escalated. NEVER logs key/cert bytes.
            tracing::debug!(error = %e, %peer, "tls: handshake failed; dropping connection");
            return;
        }
        Err(_) => {
            tracing::debug!(%peer, "tls: handshake timed out; dropping connection");
            return;
        }
    };

    let service = BodyTimeoutService::new(router, body_read_timeout());
    let io = TokioIo::new(tls_stream);
    let conn = conn_builder.serve_connection_with_upgrades(io, service);
    let conn = watcher.watch(conn);

    if let Err(e) = conn.await {
        // Per-connection serving error (client reset, malformed request framing). Contained here.
        tracing::debug!(error = %e, %peer, "tls: connection error");
    }
}

#[cfg(test)]
mod tests {
    //! End-to-end TLS / mTLS transport tests. Each spins a real busbar TLS listener on an ephemeral
    //! port with rcgen-generated certs and drives it with a real reqwest https client over the wire —
    //! exercising the actual rustls handshake (incl. client-cert verification), not a mock.

    use std::net::SocketAddr;
    use std::time::Duration;

    use axum::routing::get;
    use axum::Router;
    use rcgen::{CertificateParams, CertifiedKey, IsCa, Issuer, KeyPair};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    use crate::config::TlsCfg;

    /// A trivial router standing in for busbar's real one — the TLS transport is protocol-agnostic,
    /// so a `/healthz` that returns 200 is enough to prove a request completed over the secure hop.
    fn test_router() -> Router {
        Router::new().route("/healthz", get(|| async { "ok" }))
    }

    /// Write `contents` to a uniquely-named temp file and return its path. Used to hand the
    /// PEM-on-disk config grammar the same file paths an operator would.
    fn temp_pem(tag: &str, contents: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        let uniq = format!(
            "busbar-tls-test-{tag}-{}-{:?}.pem",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        p.push(uniq);
        std::fs::write(&p, contents).unwrap();
        p
    }

    /// Generate a self-signed server cert for `localhost`/`127.0.0.1`. Returns (cert_pem, key_pem).
    fn gen_self_signed() -> (String, String) {
        let CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])
                .unwrap();
        (cert.pem(), signing_key.serialize_pem())
    }

    /// Generate a CA + a leaf signed by it (for mTLS). Returns (ca_cert_pem, leaf_cert_pem,
    /// leaf_key_pem). The leaf is the client identity; the CA is what the server verifies against.
    fn gen_ca_and_leaf(cn_sans: Vec<String>) -> (String, String, String) {
        let ca_kp = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_kp).unwrap();

        // rcgen 0.14: leaf signing goes through an `Issuer` (CA params + CA key) rather than
        // passing the CA cert + key positionally. `from_params` borrows the CA params and takes
        // ownership of the CA key pair, which we no longer need after this.
        let issuer = Issuer::from_params(&ca_params, ca_kp);
        let leaf_kp = KeyPair::generate().unwrap();
        let leaf_params = CertificateParams::new(cn_sans).unwrap();
        let leaf_cert = leaf_params.signed_by(&leaf_kp, &issuer).unwrap();

        (ca_cert.pem(), leaf_cert.pem(), leaf_kp.serialize_pem())
    }

    /// Boot a busbar TLS listener from a `TlsCfg` on an ephemeral port. Returns the bound address and
    /// a shutdown sender (drop or send to stop + drain). Mirrors `main`'s TLS branch exactly:
    /// install provider → build ServerConfig → `tls::serve`.
    async fn spawn_tls_server(tls: &TlsCfg) -> (SocketAddr, oneshot::Sender<()>) {
        super::install_crypto_provider();
        let server_config = super::build_server_config(
            tls,
            &crate::config::secret::SecretResolver::builtins_only(),
        )
        .expect("valid test TLS config");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = oneshot::channel::<()>();
        tokio::spawn(async move {
            let shutdown = async {
                let _ = rx.await;
            };
            super::serve(listener, test_router(), server_config, shutdown)
                .await
                .unwrap();
        });
        // Give the spawned task a tick to begin accepting before the client connects.
        tokio::time::sleep(Duration::from_millis(50)).await;
        (addr, tx)
    }

    /// TEST 1 — TLS happy path: a client trusting the server's self-signed cert completes an https
    /// request and gets 200.
    #[tokio::test]
    async fn tls_happy_path_trusted_client_gets_200() {
        let (cert_pem, key_pem) = gen_self_signed();
        let cert_file = temp_pem("srv-cert", &cert_pem);
        let key_file = temp_pem("srv-key", &key_pem);
        let tls = TlsCfg {
            cert: crate::config::SecretRef::file(cert_file.to_string_lossy().into_owned()),
            key: crate::config::SecretRef::file(key_file.to_string_lossy().into_owned()),
            client_ca: None,
        };
        let (addr, _stop) = spawn_tls_server(&tls).await;

        let client = reqwest::Client::builder()
            .add_root_certificate(reqwest::Certificate::from_pem(cert_pem.as_bytes()).unwrap())
            .build()
            .unwrap();
        let resp = client
            .get(format!("https://localhost:{}/healthz", addr.port()))
            .send()
            .await
            .expect("https request should succeed over TLS");
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.text().await.unwrap(), "ok");
    }

    /// TEST 2 — mTLS required + valid client cert: client presents a leaf signed by the configured
    /// CA ⇒ 200.
    #[tokio::test]
    async fn mtls_valid_client_cert_gets_200() {
        let (srv_cert_pem, srv_key_pem) = gen_self_signed();
        let (ca_pem, leaf_pem, leaf_key_pem) = gen_ca_and_leaf(vec!["busbar-client".into()]);

        let cert_file = temp_pem("m2-srv-cert", &srv_cert_pem);
        let key_file = temp_pem("m2-srv-key", &srv_key_pem);
        let ca_file = temp_pem("m2-ca", &ca_pem);
        let tls = TlsCfg {
            cert: crate::config::SecretRef::file(cert_file.to_string_lossy().into_owned()),
            key: crate::config::SecretRef::file(key_file.to_string_lossy().into_owned()),
            client_ca: Some(crate::config::SecretRef::file(
                ca_file.to_string_lossy().into_owned(),
            )),
        };
        let (addr, _stop) = spawn_tls_server(&tls).await;

        let identity =
            reqwest::Identity::from_pem(format!("{leaf_pem}{leaf_key_pem}").as_bytes()).unwrap();
        let client = reqwest::Client::builder()
            .add_root_certificate(reqwest::Certificate::from_pem(srv_cert_pem.as_bytes()).unwrap())
            .identity(identity)
            .use_rustls_tls()
            .build()
            .unwrap();
        let resp = client
            .get(format!("https://localhost:{}/healthz", addr.port()))
            .send()
            .await
            .expect("mTLS request with valid client cert should succeed");
        assert_eq!(resp.status(), 200);
    }

    /// TEST 3 — mTLS required + no/wrong client cert: the handshake is rejected, the server stays up,
    /// and a subsequent valid client still succeeds.
    #[tokio::test]
    async fn mtls_rejects_bad_client_then_serves_valid() {
        let (srv_cert_pem, srv_key_pem) = gen_self_signed();
        let (ca_pem, leaf_pem, leaf_key_pem) = gen_ca_and_leaf(vec!["busbar-client".into()]);

        let cert_file = temp_pem("m3-srv-cert", &srv_cert_pem);
        let key_file = temp_pem("m3-srv-key", &srv_key_pem);
        let ca_file = temp_pem("m3-ca", &ca_pem);
        let tls = TlsCfg {
            cert: crate::config::SecretRef::file(cert_file.to_string_lossy().into_owned()),
            key: crate::config::SecretRef::file(key_file.to_string_lossy().into_owned()),
            client_ca: Some(crate::config::SecretRef::file(
                ca_file.to_string_lossy().into_owned(),
            )),
        };
        let (addr, _stop) = spawn_tls_server(&tls).await;
        let url = format!("https://localhost:{}/healthz", addr.port());

        // (a) Client presenting NO client cert ⇒ rejected (server requires one).
        let no_cert_client = reqwest::Client::builder()
            .add_root_certificate(reqwest::Certificate::from_pem(srv_cert_pem.as_bytes()).unwrap())
            .use_rustls_tls()
            .build()
            .unwrap();
        let err = no_cert_client.get(&url).send().await;
        assert!(
            err.is_err(),
            "mTLS server must reject a client with no certificate"
        );

        // (b) Client presenting a cert from a DIFFERENT CA ⇒ also rejected.
        let (_other_ca, wrong_leaf, wrong_key) = gen_ca_and_leaf(vec!["impostor".into()]);
        let wrong_identity =
            reqwest::Identity::from_pem(format!("{wrong_leaf}{wrong_key}").as_bytes()).unwrap();
        let wrong_client = reqwest::Client::builder()
            .add_root_certificate(reqwest::Certificate::from_pem(srv_cert_pem.as_bytes()).unwrap())
            .identity(wrong_identity)
            .use_rustls_tls()
            .build()
            .unwrap();
        let wrong = wrong_client.get(&url).send().await;
        assert!(
            wrong.is_err(),
            "mTLS server must reject a client cert from an untrusted CA"
        );

        // (c) Server survived both rejections and still serves a valid client.
        let good_identity =
            reqwest::Identity::from_pem(format!("{leaf_pem}{leaf_key_pem}").as_bytes()).unwrap();
        let good_client = reqwest::Client::builder()
            .add_root_certificate(reqwest::Certificate::from_pem(srv_cert_pem.as_bytes()).unwrap())
            .identity(good_identity)
            .use_rustls_tls()
            .build()
            .unwrap();
        let resp = good_client
            .get(&url)
            .send()
            .await
            .expect("server must remain up and serve a valid client after rejecting bad ones");
        assert_eq!(resp.status(), 200);
    }

    /// TEST 4a — config regression: with NO `tls` block the plain-HTTP path still works. Drives the
    /// historical `axum::serve` over a plain TcpListener (the exact `None` branch in `main`).
    #[tokio::test]
    async fn plain_http_still_works_without_tls() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = oneshot::channel::<()>();
        tokio::spawn(async move {
            let shutdown = async {
                let _ = rx.await;
            };
            axum::serve(listener, test_router())
                .with_graceful_shutdown(shutdown)
                .await
                .unwrap();
        });
        tokio::time::sleep(Duration::from_millis(50)).await;

        let resp = reqwest::get(format!("http://127.0.0.1:{}/healthz", addr.port()))
            .await
            .expect("plain HTTP must still work when tls is absent");
        assert_eq!(resp.status(), 200);
        let _ = tx.send(());
    }

    /// TEST 4b — fail-fast: a bad cert path produces a clear, file-named error from
    /// `build_server_config` (which `main` turns into `die`). No server is started.
    #[test]
    fn bad_cert_path_errors_clearly() {
        let tls = TlsCfg {
            cert: crate::config::SecretRef::file("/nonexistent/busbar/does-not-exist-cert.pem"),
            key: crate::config::SecretRef::file("/nonexistent/busbar/does-not-exist-key.pem"),
            client_ca: None,
        };
        let err = super::build_server_config(
            &tls,
            &crate::config::secret::SecretResolver::builtins_only(),
        )
        .expect_err("missing cert file must error");
        assert!(
            err.contains("cert") && err.contains("does-not-exist-cert.pem"),
            "error must name the offending file: {err}"
        );
    }

    /// TEST 4c — fail-fast: a syntactically invalid PEM cert errors with the file named, not a panic.
    #[test]
    fn malformed_cert_errors_clearly() {
        let cert_file = temp_pem("bad-cert", "-----BEGIN CERTIFICATE-----\nnot base64\n");
        let (_c, key_pem) = gen_self_signed();
        let key_file = temp_pem("ok-key", &key_pem);
        let tls = TlsCfg {
            cert: crate::config::SecretRef::file(cert_file.to_string_lossy().into_owned()),
            key: crate::config::SecretRef::file(key_file.to_string_lossy().into_owned()),
            client_ca: None,
        };
        let err = super::build_server_config(
            &tls,
            &crate::config::secret::SecretResolver::builtins_only(),
        )
        .expect_err("malformed cert must error");
        assert!(err.contains("cert"), "error must reference the cert: {err}");
    }

    /// TEST 5 - REGRESSION (P1 slow-loris BODY): the inbound body-read timeout trips on a stalled
    /// request body. Before the fix, only the header-read phase was bounded; a client that finished
    /// its headers then dribbled (here: never sent) the promised body would pin the connection task,
    /// its FD, and one of the finite inbound-concurrency permits INDEFINITELY. This drives the plain
    /// serve loop (same `BodyTimeoutService` seam the TLS loop uses) over a raw socket: send a POST
    /// with a `Content-Length` but NO body, and assert the server closes the connection promptly
    /// (well inside a generous deadline) rather than hanging forever. A short body-read timeout is
    /// installed process-wide for the test; only that one non-default limit is set, so the other
    /// limits-accessor tests (which assert defaults for OTHER fields) are unaffected.
    #[tokio::test]
    async fn body_read_timeout_trips_on_stalled_body() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Install a SHORT body-read timeout (1s) so the test is fast; leave every other limit at its
        // historical default so no other limits test is perturbed.
        let limits = crate::config::LimitsResolved {
            request_body_read_timeout_secs: 1,
            ..crate::config::LimitsResolved::default()
        };
        crate::limits::install(&limits);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = oneshot::channel::<()>();
        tokio::spawn(async move {
            let shutdown = async {
                let _ = rx.await;
            };
            // A route that WOULD read the body (POST /echo), so the server actually awaits body frames.
            let router = Router::new().route(
                "/echo",
                axum::routing::post(|body: String| async move { body }),
            );
            super::serve_plain(listener, router, shutdown)
                .await
                .unwrap();
        });
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut sock = tokio::net::TcpStream::connect(addr).await.unwrap();
        // Headers announce a 100-byte body; we send NONE of it, then stall.
        sock.write_all(b"POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\n\r\n")
            .await
            .unwrap();
        sock.flush().await.unwrap();

        // The server must close the connection (read yields EOF/reset) once the body-read bound (1s)
        // elapses with no body forthcoming. Bound the whole wait generously (5s): pre-fix this would
        // hang until the test's own deadline. `read` returning Ok(0) is a clean EOF; an Err is a
        // reset - either proves the server tore the stalled connection down.
        let mut buf = [0u8; 256];
        let outcome = tokio::time::timeout(Duration::from_secs(5), sock.read(&mut buf)).await;
        match outcome {
            Ok(Ok(0)) => {}  // clean EOF: server closed the stalled connection
            Ok(Ok(_n)) => {} // server may first write a 4xx/408-ish response, then close
            Ok(Err(_)) => {} // connection reset: also acceptable
            Err(_) => panic!(
                "body-read timeout did NOT trip: the server kept the stalled-body connection open \
                 past the deadline (slow-loris body regression)"
            ),
        }

        let _ = tx.send(());
    }
}
