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
use std::path::Path;
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

use axum::Router;
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

/// Read a file, mapping any I/O error into a clear, file-named message. Never logs contents.
fn read_pem(path: &str, what: &str) -> Result<Vec<u8>, String> {
    std::fs::read(Path::new(path)).map_err(|e| format!("cannot read TLS {what} '{path}': {e}"))
}

/// Parse the PEM certificate chain (leaf first). Errors name the file; cert bytes are public, but we
/// still avoid echoing them.
fn load_cert_chain(path: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    let bytes = read_pem(path, "cert_file")?;
    let certs = CertificateDer::pem_slice_iter(&bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("cannot parse TLS cert_file '{path}': {e}"))?;
    if certs.is_empty() {
        return Err(format!(
            "TLS cert_file '{path}' contains no certificates (expected a PEM chain, leaf first)"
        ));
    }
    Ok(certs)
}

/// Parse the PEM private key, accepting PKCS#8, PKCS#1 (RSA), or SEC1 (EC) encodings. NEVER logs key
/// material — error messages name only the file path.
fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>, String> {
    let bytes = read_pem(path, "key_file")?;
    // `PrivateKeyDer::from_pem_slice` accepts PKCS#8, PKCS#1 (RSA), and SEC1 (EC) sections, picking the
    // first private-key section it finds. `NoItemsFound` means none was present; any other variant is a
    // genuine parse error. Neither path echoes key material — error messages name only the file.
    use rustls::pki_types::pem::Error as PemError;
    PrivateKeyDer::from_pem_slice(&bytes).map_err(|e| match e {
        PemError::NoItemsFound => {
            format!("TLS key_file '{path}' contains no private key (expected PKCS#8 / PKCS#1 / SEC1 PEM)")
        }
        other => format!("cannot parse TLS key_file '{path}': {other}"),
    })
}

/// Build the client-cert verifier root store from the operator's CA bundle (mTLS).
fn load_client_roots(path: &str) -> Result<RootCertStore, String> {
    let bytes = read_pem(path, "client_ca_file")?;
    let cas = CertificateDer::pem_slice_iter(&bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("cannot parse TLS client_ca_file '{path}': {e}"))?;
    if cas.is_empty() {
        return Err(format!(
            "TLS client_ca_file '{path}' contains no CA certificates"
        ));
    }
    let mut roots = RootCertStore::empty();
    for ca in cas {
        roots
            .add(ca)
            .map_err(|e| format!("invalid CA certificate in TLS client_ca_file '{path}': {e}"))?;
    }
    Ok(roots)
}

/// Construct the rustls [`ServerConfig`] from the operator's [`TlsCfg`].
///
/// * `client_ca_file` present ⇒ a [`WebPkiClientVerifier`] is installed: the client MUST present a
///   certificate chaining to that CA or the handshake fails (mTLS required).
/// * `client_ca_file` absent ⇒ `with_no_client_auth()` (server-only TLS).
///
/// ALPN advertises only `http/1.1` — busbar's axum server speaks http/1.1, so we must not advertise
/// h2. Returns a clear, file-named error on any load/parse problem (the caller turns it into `die`).
pub(crate) fn build_server_config(tls: &TlsCfg) -> Result<ServerConfig, String> {
    let certs = load_cert_chain(&tls.cert_file)?;
    let key = load_private_key(&tls.key_file)?;

    let builder = ServerConfig::builder();

    let builder = match &tls.client_ca_file {
        Some(ca_path) => {
            let roots = load_client_roots(ca_path)?;
            let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
                .build()
                .map_err(|e| {
                    format!("cannot build client-cert verifier from TLS client_ca_file '{ca_path}': {e}")
                })?;
            builder.with_client_cert_verifier(verifier)
        }
        None => builder.with_no_client_auth(),
    };

    let mut config = builder.with_single_cert(certs, key).map_err(|e| {
        format!(
            "TLS cert/key are not a valid pair (cert_file '{}', key_file '{}'): {e}",
            tls.cert_file, tls.key_file
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
    let service = TowerToHyperService::new(router);
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

    let service = TowerToHyperService::new(router);
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
    use rcgen::{CertificateParams, CertifiedKey, IsCa, KeyPair};
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
        let CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])
                .unwrap();
        (cert.pem(), key_pair.serialize_pem())
    }

    /// Generate a CA + a leaf signed by it (for mTLS). Returns (ca_cert_pem, leaf_cert_pem,
    /// leaf_key_pem). The leaf is the client identity; the CA is what the server verifies against.
    fn gen_ca_and_leaf(cn_sans: Vec<String>) -> (String, String, String) {
        let ca_kp = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_kp).unwrap();

        let leaf_kp = KeyPair::generate().unwrap();
        let leaf_params = CertificateParams::new(cn_sans).unwrap();
        let leaf_cert = leaf_params.signed_by(&leaf_kp, &ca_cert, &ca_kp).unwrap();

        (ca_cert.pem(), leaf_cert.pem(), leaf_kp.serialize_pem())
    }

    /// Boot a busbar TLS listener from a `TlsCfg` on an ephemeral port. Returns the bound address and
    /// a shutdown sender (drop or send to stop + drain). Mirrors `main`'s TLS branch exactly:
    /// install provider → build ServerConfig → `tls::serve`.
    async fn spawn_tls_server(tls: &TlsCfg) -> (SocketAddr, oneshot::Sender<()>) {
        super::install_crypto_provider();
        let server_config = super::build_server_config(tls).expect("valid test TLS config");
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
            cert_file: cert_file.to_string_lossy().into_owned(),
            key_file: key_file.to_string_lossy().into_owned(),
            client_ca_file: None,
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
            cert_file: cert_file.to_string_lossy().into_owned(),
            key_file: key_file.to_string_lossy().into_owned(),
            client_ca_file: Some(ca_file.to_string_lossy().into_owned()),
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
            cert_file: cert_file.to_string_lossy().into_owned(),
            key_file: key_file.to_string_lossy().into_owned(),
            client_ca_file: Some(ca_file.to_string_lossy().into_owned()),
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
            cert_file: "/nonexistent/busbar/does-not-exist-cert.pem".into(),
            key_file: "/nonexistent/busbar/does-not-exist-key.pem".into(),
            client_ca_file: None,
        };
        let err = super::build_server_config(&tls).expect_err("missing cert file must error");
        assert!(
            err.contains("cert_file") && err.contains("does-not-exist-cert.pem"),
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
            cert_file: cert_file.to_string_lossy().into_owned(),
            key_file: key_file.to_string_lossy().into_owned(),
            client_ca_file: None,
        };
        let err = super::build_server_config(&tls).expect_err("malformed cert must error");
        assert!(
            err.contains("cert_file"),
            "error must reference cert_file: {err}"
        );
    }
}
