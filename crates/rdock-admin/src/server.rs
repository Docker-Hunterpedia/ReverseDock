//! Listeners and the admin runtime. Sockets are bound before `start` returns, so a busy port
//! fails the start; everything else runs on a runtime of its own (ADR-0024), so admin traffic
//! can never take worker threads from the proxy. ReverseDock runs on Unix (Linux, macOS).

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::{Extension, Router};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use hyper_util::service::TowerToHyperService;
use rdock_model::config::TlsPolicy;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;

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
    let socket = settings.socket.as_deref().map(bind_socket).transpose()?;
    let allowed_hosts = if settings.allowed_hosts.is_empty() {
        guard::default_hosts(address.ip())
    } else {
        settings.allowed_hosts.clone()
    };
    let state = Arc::new(State {
        control,
        main: tokio::runtime::Handle::current(),
        token: settings.token,
        allowed_hosts,
    });
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(settings.threads.max(1))
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
                serve(router, tcp, tls, socket, stop).await;
            });
        })
        .map_err(StartError::Runtime)?;
    Ok(Running { thread })
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
    loop {
        tokio::select! {
            changed = stop.changed() => if changed.is_err() || *stop.borrow() { break },
            accepted = tcp.accept() => match accepted {
                Ok((stream, _)) => {
                    let router = tcp_router.clone();
                    match tls.clone() {
                        Some(acceptor) => {
                            tokio::spawn(async move {
                                match acceptor.accept(stream).await {
                                    Ok(stream) => connection(stream, router).await,
                                    Err(err) => tracing::debug!(error = %err, "admin TLS handshake failed"),
                                }
                            });
                        }
                        None => {
                            tokio::spawn(connection(stream, router));
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
                    tokio::spawn(connection(stream, socket_router.clone()));
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

async fn connection<S>(stream: S, router: Router)
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let service = TowerToHyperService::new(router);
    if let Err(err) = Builder::new(TokioExecutor::new())
        .serve_connection(TokioIo::new(stream), service)
        .await
    {
        tracing::debug!(error = %err, "admin connection ended with an error");
    }
}
