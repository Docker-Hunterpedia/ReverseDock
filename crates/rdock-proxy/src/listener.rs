//! Listeners: sockets we bind and accept on ourselves, handing each connection to Pingora's
//! HTTP stack (ADR-0012). Owning the accept loop gives clear bind errors, per-listener TLS
//! settings, listener changes without a restart and a real connection drain on shutdown.

use std::any::Any;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use pingora::apps::{HttpServerOptions, ServerApp};
use pingora::listeners::TlsAccept;
use pingora::listeners::tls::{Acceptor, TlsSettings};
use pingora::protocols::http::v2::server::default_h2_options;
use pingora::protocols::l4::stream::Stream as L4Stream;
use pingora::protocols::tls::TlsRef;
use pingora::protocols::{GetSocketDigest, SocketDigest, Stream};
use pingora::proxy::HttpProxy;
use pingora::server::configuration::ServerConf;
use rdock_model::config::{ListenerTimeouts, TlsPolicy};
use rdock_model::values::ListenAddress;
use rdock_observability::Metrics;
use rdock_tls::SniResolver;
use tokio::io::AsyncReadExt;
use tokio::sync::watch;
use tokio::task::JoinSet;

use crate::conn::ConnStream;
use crate::proxy::{RdockProxy, Shared};

/// The HTTP/2 connection preface (RFC 9113 §3.4).
const H2_PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// SNI of a TLS connection, stored in Pingora's TLS digest for the access log.
#[derive(Debug, Clone)]
pub struct ServerName(pub String);

struct CaptureSni;

#[async_trait]
impl TlsAccept for CaptureSni {
    async fn handshake_complete_callback(
        &self,
        tls: &TlsRef,
    ) -> Option<Arc<dyn Any + Send + Sync>> {
        tls.server_name()
            .map(|name| Arc::new(ServerName(name.to_owned())) as Arc<dyn Any + Send + Sync>)
    }
}

/// Builds a TLS acceptor for `policy`. Pingora's `TlsSettings` is only used for its
/// handshake-complete callback; the rustls configuration is ours.
pub fn acceptor(policy: TlsPolicy, resolver: Arc<SniResolver>) -> Result<Acceptor, String> {
    let config = rdock_tls::server_config(policy, resolver.clone()).map_err(|e| e.to_string())?;
    let mut settings =
        TlsSettings::with_callbacks(Box::new(CaptureSni)).map_err(|e| e.to_string())?;
    settings.set_cert_resolver(resolver);
    let mut acceptor = settings.build();
    acceptor.acceptor = pingora::tls::TlsAcceptor::from(config);
    Ok(acceptor)
}

/// Binds a listening socket. `:port` binds all interfaces, IPv6 and IPv4 when available.
pub fn bind(address: &ListenAddress) -> io::Result<std::net::TcpListener> {
    let listener = match address.ip() {
        Some(ip) => std::net::TcpListener::bind(SocketAddr::new(ip, address.port()))?,
        None => std::net::TcpListener::bind(SocketAddr::new(
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            address.port(),
        ))
        .or_else(|_| {
            std::net::TcpListener::bind(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                address.port(),
            ))
        })?,
    };
    listener.set_nonblocking(true)?;
    Ok(listener)
}

/// The HTTP engine of one listener.
pub fn http_engine(
    name: Arc<str>,
    shared: Arc<Shared>,
    timeouts: &ListenerTimeouts,
) -> Arc<HttpProxy<RdockProxy>> {
    let conf = Arc::new(ServerConf {
        // Attempts per request: one retry for a pooled connection that closed under us.
        max_retries: 2,
        ..ServerConf::default()
    });
    let mut proxy = pingora::proxy::http_proxy(&conf, RdockProxy::new(name, shared));
    let mut options = HttpServerOptions::default();
    options.h2c = true;
    options.h2_idle_timeout = Some(timeouts.idle.as_std());
    proxy.server_options = Some(options);
    proxy.h2_options = Some(default_h2_options());
    Arc::new(proxy)
}

/// Settings of a running listener that a reload may change in place.
#[derive(Clone)]
pub struct Settings {
    /// TLS acceptor of an HTTPS listener.
    pub tls: Option<Arc<Acceptor>>,
    /// Client timeouts.
    pub timeouts: ListenerTimeouts,
}

/// A running listener.
pub struct Running {
    /// Bind address.
    pub address: ListenAddress,
    /// Changeable settings.
    pub settings: Arc<ArcSwap<Settings>>,
    stop: watch::Sender<Option<Duration>>,
    task: tokio::task::JoinHandle<()>,
}

impl Running {
    /// Starts accepting on `socket`.
    pub fn start(
        name: Arc<str>,
        address: ListenAddress,
        socket: tokio::net::TcpListener,
        settings: Settings,
        shared: Arc<Shared>,
    ) -> Self {
        let engine = http_engine(name.clone(), shared.clone(), &settings.timeouts);
        let settings = Arc::new(ArcSwap::from_pointee(settings));
        let (stop, stop_rx) = watch::channel(None);
        let task = tokio::spawn(accept_loop(
            name,
            socket,
            settings.clone(),
            engine,
            stop_rx,
            shared,
        ));
        Self {
            address,
            settings,
            stop,
            task,
        }
    }

    /// Stops accepting and waits up to `drain` for open connections to finish.
    pub async fn stop(self, drain: Duration) {
        let _ = self.stop.send(Some(drain));
        let _ = self.task.await;
    }
}

async fn accept_loop(
    name: Arc<str>,
    socket: tokio::net::TcpListener,
    settings: Arc<ArcSwap<Settings>>,
    engine: Arc<HttpProxy<RdockProxy>>,
    mut stop: watch::Receiver<Option<Duration>>,
    shared: Arc<Shared>,
) {
    let metrics: &Metrics = &shared.metrics;
    let (closing, closing_rx) = watch::channel(false);
    let mut connections = JoinSet::new();
    let drain = loop {
        while connections.try_join_next().is_some() {}
        tokio::select! {
            changed = stop.changed() => {
                let requested = *stop.borrow();
                if changed.is_err() || requested.is_some() {
                    break requested.unwrap_or_default();
                }
            }
            accepted = socket.accept() => match accepted {
                Ok((tcp, peer)) => {
                    metrics.connections_total.with_label_values(&[&name]).inc();
                    let current = settings.load_full();
                    connections.spawn(serve(
                        name.clone(),
                        tcp,
                        peer,
                        current,
                        engine.clone(),
                        closing_rx.clone(),
                        shared.clone(),
                    ));
                }
                Err(err) => {
                    // Out of file descriptors or similar: back off instead of spinning.
                    tracing::warn!(listener = %name, error = %err, "accept failed");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            },
        }
    };
    drop(socket);
    let _ = closing.send(true);
    engine.cleanup().await;
    let drained = tokio::time::timeout(drain, async {
        while connections.join_next().await.is_some() {}
    })
    .await;
    if drained.is_err() {
        tracing::info!(listener = %name, open = connections.len(), "drain time over, closing connections");
        connections.abort_all();
    }
}

/// Guard that keeps the open-connections gauge right however the task ends.
struct Open<'a>(&'a Metrics, &'a str);

impl Drop for Open<'_> {
    fn drop(&mut self) {
        self.0.connections.with_label_values(&[self.1]).dec();
    }
}

async fn serve(
    name: Arc<str>,
    tcp: tokio::net::TcpStream,
    _peer: SocketAddr,
    settings: Arc<Settings>,
    engine: Arc<HttpProxy<RdockProxy>>,
    closing: watch::Receiver<bool>,
    shared: Arc<Shared>,
) {
    shared.metrics.connections.with_label_values(&[&name]).inc();
    let _open = Open(&shared.metrics, &name);
    let _ = tcp.set_nodelay(true);
    #[cfg(unix)]
    let fd = std::os::unix::io::AsRawFd::as_raw_fd(&tcp);
    let mut l4: L4Stream = tcp.into();
    #[cfg(unix)]
    l4.set_socket_digest(SocketDigest::from_raw_fd(fd));
    let header_timeout = settings.timeouts.request_header.as_std();
    let stream: ConnStream = if let Some(acceptor) = &settings.tls {
        let handshake = tokio::time::timeout(header_timeout, acceptor.tls_handshake(l4)).await;
        let tls = match handshake {
            Ok(Ok(tls)) => tls,
            Ok(Err(err)) => {
                tracing::debug!(listener = %name, error = %err, "TLS handshake failed");
                shared
                    .metrics
                    .tls_handshake_errors
                    .with_label_values(&[&name])
                    .inc();
                return;
            }
            Err(_) => {
                shared
                    .metrics
                    .tls_handshake_errors
                    .with_label_values(&[&name])
                    .inc();
                return;
            }
        };
        let h2 = matches!(
            pingora::protocols::Ssl::selected_alpn_proto(&tls),
            Some(pingora::protocols::ALPN::H2)
        );
        ConnStream::new(Box::new(tls) as Stream, None, !h2, header_timeout)
    } else {
        let Ok(Some(first)) = tokio::time::timeout(header_timeout, read_preface(&mut l4)).await
        else {
            return;
        };
        l4.rewind(&first);
        let h2 = first.as_slice() == H2_PREFACE.as_slice();
        ConnStream::new(Box::new(l4) as Stream, Some(first), !h2, header_timeout)
    };
    engine.process_new(Box::new(stream), &closing).await;
}

/// Reads until the bytes are the full HTTP/2 preface or cannot be one. `None` means the client
/// closed the connection first.
async fn read_preface(stream: &mut L4Stream) -> Option<Vec<u8>> {
    let mut seen = Vec::with_capacity(H2_PREFACE.len());
    let mut buf = [0u8; 4096];
    loop {
        let n = stream.read(&mut buf).await.ok()?;
        if n == 0 {
            return None;
        }
        seen.extend_from_slice(&buf[..n]);
        let check = seen.len().min(H2_PREFACE.len());
        if seen.len() >= H2_PREFACE.len() || seen[..check] != H2_PREFACE[..check] {
            return Some(seen);
        }
    }
}
