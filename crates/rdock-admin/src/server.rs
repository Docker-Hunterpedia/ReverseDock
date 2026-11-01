//! Listeners and the admin runtime. Sockets are bound before `start` returns, so a busy port
//! fails the start; everything else runs on a runtime of its own (ADR-0024), so admin traffic
//! can never take worker threads from the proxy. ReverseDock runs on Unix (Linux, macOS).

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::{Extension, Router};
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use rdock_model::config::TlsPolicy;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;
use tower_service::Service;

use crate::audit::Audit;
use crate::auth::Peer;
use crate::bootstrap::Bootstrap;
use crate::limits::LoginLimits;
use crate::passwords::Policy;
use crate::sessions::Sessions;
use crate::stream::Hub;
use crate::tokens::Tokens;
use crate::users::Users;
use crate::{Control, Settings, State, Transport, guard, routes};

/// Why the admin API could not start.
#[derive(Debug, thiserror::Error)]
pub enum StartError {
    /// The TCP address is in use or not available.
    #[error("cannot listen on the admin address {address}: {source}")]
    Bind {
        /// The admin address.
        address: std::net::SocketAddr,
        /// What the operating system said.
        source: io::Error,
    },
    /// The Unix socket could not be created.
    #[error("cannot create the admin socket {path}: {source}")]
    Socket {
        /// The socket path.
        path: PathBuf,
        /// What the operating system said.
        source: io::Error,
    },
    /// The certificate or key could not be loaded.
    #[error("admin TLS: {0}")]
    Certificate(#[from] rdock_tls::CertError),
    /// The TLS configuration could not be built.
    #[error("admin TLS: {0}")]
    Policy(#[from] rdock_tls::PolicyError),
    /// The admin runtime or its thread could not start.
    #[error("cannot start the admin runtime: {0}")]
    Runtime(io::Error),
    /// The users file, the bootstrap token or the password blocklist could not be read or
    /// written.
    #[error("admin state in {path}: {source}")]
    State {
        /// The admin state directory.
        path: PathBuf,
        /// What went wrong.
        source: io::Error,
    },
}

/// The running admin API. Dropping it does not stop it; send `true` on the stop channel.
pub struct Running {
    thread: std::thread::JoinHandle<()>,
}

impl Running {
    /// Waits until the admin runtime has stopped, without blocking the caller's runtime.
    pub async fn stopped(self) {
        let _ = tokio::task::spawn_blocking(move || self.thread.join()).await;
    }
}

/// The user store and the bootstrap token, which is issued only while no admin exists.
fn open_users(state_dir: &std::path::Path) -> std::io::Result<(Users, Bootstrap)> {
    let users = Users::open(state_dir)?;
    if users.has_admin() {
        return Ok((users, Bootstrap::inactive(state_dir)?));
    }
    let bootstrap = Bootstrap::issue(state_dir)?;
    tracing::warn!(
        file = %bootstrap.file().display(),
        "no admin user yet: create one with the single-use bootstrap token in this file (valid 24 hours)"
    );
    Ok((users, bootstrap))
}

/// Binds the listeners and serves them on a dedicated runtime until `stop` turns `true`.
/// Engine calls are sent to the caller's runtime, which must be a tokio runtime.
pub fn start(
    settings: Settings,
    control: Arc<dyn Control>,
    stop: watch::Receiver<bool>,
) -> Result<Running, StartError> {
    let address = settings.address;
    let tcp = std::net::TcpListener::bind(address)
        .and_then(|l| l.set_nonblocking(true).map(|()| l))
        .map_err(|source| StartError::Bind { address, source })?;
    let tls = settings.tls.as_ref().map(acceptor).transpose()?;
    // Without the socket the CLI falls back to the listener with an API token; a path too
    // long for a Unix socket (about 104 bytes on macOS) must not stop the proxy.
    let socket = settings.socket.as_deref().and_then(|path| match bind_socket(path) {
        Ok(socket) => Some(socket),
        Err(err) => {
            tracing::warn!(error = %err, "the CLI socket is off; `rdock reload` and `rdock status` need --admin and RDOCK_ADMIN_TOKEN");
            None
        }
    });
    let allowed_hosts = if settings.allowed_hosts.is_empty() {
        guard::default_hosts(address.ip())
    } else {
        settings.allowed_hosts
    };
    let state_error = |source| StartError::State {
        path: settings.state_dir.clone(),
        source,
    };
    let (users, bootstrap) = open_users(&settings.state_dir).map_err(state_error)?;
    let policy = Policy::new(&settings.passwords).map_err(state_error)?;
    let tokens = Tokens::open(&settings.state_dir).map_err(state_error)?;
    let audit = Audit::open(
        &settings.audit_dir,
        settings.audit.max_file_size.as_u64(),
        settings.audit.retention.as_std(),
        settings.audit.forward.as_ref(),
    )
    .map_err(|source| StartError::State {
        path: settings.audit_dir.clone(),
        source,
    })?;
    remove_shared_token(&settings.state_dir);
    let events = Hub::start(settings.feeds.as_ref().map(|f| f.events.clone()), "events");
    audit.set_events(events.clone());
    if let Some(feeds) = &settings.feeds {
        audit.set_alerts(feeds.alerts.clone());
    }
    let state = Arc::new(State {
        control,
        main: tokio::runtime::Handle::current(),
        allowed_hosts,
        users,
        bootstrap,
        policy,
        limits: LoginLimits::default(),
        sessions: Sessions::new(
            settings.sessions.idle.as_std(),
            settings.sessions.absolute.as_std(),
        ),
        mfa: settings.mfa,
        dashboard: settings.dashboard,
        tokens,
        token_rules: settings.tokens,
        metrics_open: settings.metrics_unauthenticated_on_loopback && address.ip().is_loopback(),
        audit,
        api_writes: settings.api_writes,
        logs: Hub::start(settings.feeds.as_ref().map(|f| f.logs.clone()), "logs"),
        events: events.clone(),
        quota: crate::stream::Quota::default(),
        telemetry: crate::telemetry::Telemetry::default(),
        hashing: rdock_limits::ConcurrencyLimiter::new(2, 16, Duration::from_secs(10), 1),
        config_work: crate::config_api::work_limiter(),
        api_rate: crate::caller::request_limiter(),
    });
    let threads = settings.threads.max(1);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(threads)
        .thread_name("rdock-admin")
        .enable_all()
        .build()
        .map_err(StartError::Runtime)?;
    let thread = std::thread::Builder::new()
        .name("rdock-admin".into())
        .spawn(move || {
            runtime.block_on(async move {
                let router = routes::router(state);
                let tcp = tokio::net::TcpListener::from_std(tcp);
                let Ok(tcp) = tcp else {
                    tracing::error!("cannot register the admin listener");
                    return;
                };
                let socket = socket.and_then(|(listener, path)| {
                    tokio::net::UnixListener::from_std(listener)
                        .ok()
                        .map(|l| (l, path))
                });
                let served = serve(router, tcp, tls, socket, stop);
                #[cfg(feature = "fault-injection")]
                let served = with_fault(served, threads);
                served.await;
            });
        })
        .map_err(StartError::Runtime)?;
    Ok(Running { thread })
}

/// Serves until `served` ends, interrupted by the fault `RDOCK_FAULT` asks for, if any.
#[cfg(feature = "fault-injection")]
async fn with_fault(served: impl std::future::Future<Output = ()>, threads: usize) {
    let mut served = std::pin::pin!(served);
    if let Some(fault) = crate::fault::from_env() {
        tokio::select! {
            () = &mut served => return,
            () = crate::fault::strike(fault, threads) => {}
        }
    }
    served.await;
}

/// Deletes the v0.1–v0.4 shared admin token (ADR-0024): API tokens replace it, and the CLI
/// uses the socket.
fn remove_shared_token(dir: &Path) {
    let path = dir.join("token");
    match std::fs::remove_file(&path) {
        Ok(()) => tracing::info!(
            file = %path.display(),
            "removed the old shared admin token; create an API token for scripts (POST /api/v1/tokens)"
        ),
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => {
            tracing::warn!(file = %path.display(), error = %err, "cannot remove the old shared admin token");
        }
    }
}

fn acceptor(files: &crate::TlsFiles) -> Result<TlsAcceptor, StartError> {
    let loaded = rdock_tls::load_certificate("admin", &files.cert_file, &files.key_file, None)?;
    let index = rdock_tls::CertIndex::build(&[loaded], Some("admin"));
    let resolver = Arc::new(rdock_tls::SniResolver::new(index));
    // TLS 1.3 only: the admin API has no old clients to serve.
    let config = rdock_tls::server_config(TlsPolicy::Modern, resolver, None)?;
    Ok(TlsAcceptor::from(config))
}

/// Removes a stale socket from an earlier run, binds, and restricts it to the owner.
fn bind_socket(path: &Path) -> Result<(std::os::unix::net::UnixListener, PathBuf), StartError> {
    use std::os::unix::fs::PermissionsExt;
    let fail = |source| StartError::Socket {
        path: path.to_owned(),
        source,
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(fail)?;
    }
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(fail(err)),
    }
    let listener = std::os::unix::net::UnixListener::bind(path).map_err(fail)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(fail)?;
    listener.set_nonblocking(true).map_err(fail)?;
    Ok((listener, path.to_owned()))
}

type Socket = (tokio::net::UnixListener, PathBuf);

/// Open TCP connections to the admin listener; more are closed as they arrive. Dashboards,
/// scripts and Prometheus need a handful; four streams per identity are allowed.
const MAX_CONNECTIONS: usize = 256;

/// Time to finish a TLS handshake or a request's headers, including the next request on a
/// kept-alive connection.
const HEADER_TIMEOUT: Duration = Duration::from_secs(10);

async fn serve(
    router: Router,
    tcp: tokio::net::TcpListener,
    tls: Option<TlsAcceptor>,
    socket: Option<Socket>,
    mut stop: watch::Receiver<bool>,
) {
    let tcp_router = router
        .clone()
        .layer(Extension(Transport::Tcp { tls: tls.is_some() }));
    let socket_router = router.layer(Extension(Transport::Socket));
    let open = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    loop {
        tokio::select! {
            changed = stop.changed() => if changed.is_err() || *stop.borrow() { break },
            accepted = tcp.accept() => match accepted {
                Ok((stream, address)) => {
                    // Over the cap the connection is closed at once: holding thousands of
                    // them would spend CPU the proxy shares (H-ENG-04, ASVS finding 11).
                    let Ok(permit) = open.clone().try_acquire_owned() else {
                        tracing::debug!(%address, "admin connection refused: too many open");
                        continue;
                    };
                    let router = tcp_router.clone();
                    let peer = Some(Peer(address));
                    match tls.clone() {
                        Some(acceptor) => {
                            tokio::spawn(async move {
                                let _permit = permit;
                                match tokio::time::timeout(HEADER_TIMEOUT, acceptor.accept(stream)).await {
                                    Ok(Ok(stream)) => connection(stream, router, peer).await,
                                    Ok(Err(err)) => tracing::debug!(error = %err, "admin TLS handshake failed"),
                                    Err(_) => tracing::debug!("admin TLS handshake timed out"),
                                }
                            });
                        }
                        None => {
                            tokio::spawn(async move {
                                let _permit = permit;
                                connection(stream, router, peer).await;
                            });
                        }
                    }
                }
                Err(err) => {
                    tracing::warn!(error = %err, "admin accept failed");
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            },
            accepted = accept_socket(socket.as_ref()) => match accepted {
                Ok(stream) => {
                    tokio::spawn(connection(stream, socket_router.clone(), None));
                }
                Err(err) => {
                    tracing::warn!(error = %err, "admin socket accept failed");
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            },
        }
    }
    if let Some((_, path)) = socket {
        let _ = std::fs::remove_file(path);
    }
}

async fn accept_socket(socket: Option<&Socket>) -> io::Result<tokio::net::UnixStream> {
    match socket {
        Some((listener, _)) => listener.accept().await.map(|(stream, _)| stream),
        None => std::future::pending().await,
    }
}

async fn connection<S>(stream: S, router: Router, peer: Option<Peer>)
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let service = hyper::service::service_fn(move |mut request: http::Request<Incoming>| {
        if let Some(peer) = peer {
            request.extensions_mut().insert(peer);
        }
        router.clone().call(request)
    });
    let mut builder = Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(HEADER_TIMEOUT);
    if let Err(err) = builder
        .serve_connection(TokioIo::new(stream), service)
        .await
    {
        tracing::debug!(error = %err, "admin connection ended with an error");
    }
}
