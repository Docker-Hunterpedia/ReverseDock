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
use pingora::protocols::http::v2::server::{H2Options, default_h2_options};
use pingora::protocols::l4::stream::Stream as L4Stream;
use pingora::protocols::tls::TlsRef;
use pingora::protocols::{GetSocketDigest, SocketDigest, Stream};
use pingora::proxy::HttpProxy;
use pingora::server::configuration::ServerConf;
use rdock_middleware::ClientIdentity;
use rdock_model::config::{
    FloodLimit, ListenerHttp2, ListenerProtocol, ListenerSocket, ListenerTimeouts, ProxyProtocolIn,
    StartTls,
};
use rdock_model::values::ListenAddress;
use rdock_observability::Metrics;
use rdock_tls::ListenerResolver;
use tokio::io::AsyncReadExt;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, oneshot, watch};
use tokio::task::JoinSet;

use crate::conn::ConnStream;
use crate::proxy::{RdockProxy, Shared};
use crate::runtime::ListenerTls;

/// The HTTP/2 connection preface (RFC 9113 §3.4).
const H2_PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// What the TLS handshake established, stored in Pingora's TLS digest: the SNI for the access
/// log, and the client certificate that the listener verified.
#[derive(Debug, Clone, Default)]
pub struct Handshake {
    /// Server name the client asked for.
    pub sni: Option<String>,
    /// The verified client certificate (only listeners with `client_auth` ask for one).
    pub client_cert: Option<Arc<ClientIdentity>>,
}

struct CaptureHandshake;

#[async_trait]
impl TlsAccept for CaptureHandshake {
    async fn handshake_complete_callback(
        &self,
        tls: &TlsRef,
    ) -> Option<Arc<dyn Any + Send + Sync>> {
        let handshake = Handshake {
            sni: tls.server_name().map(str::to_owned),
            client_cert: tls.peer_certificate_der().and_then(identity).map(Arc::new),
        };
        Some(Arc::new(handshake))
    }
}

/// The fields of a client certificate. rustls has already verified it, so it parses; `None`
/// would only mean a certificate x509-parser cannot read, which then counts as absent.
fn identity(der: &[u8]) -> Option<ClientIdentity> {
    use std::fmt::Write;
    use x509_parser::extensions::GeneralName;
    use x509_parser::prelude::FromDer;

    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(der).ok()?;
    let mut identity = ClientIdentity {
        common_name: cert
            .subject()
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .map(str::to_owned),
        subject: cert.subject().to_string(),
        issuer: cert.issuer().to_string(),
        not_before: cert.validity().not_before.timestamp(),
        not_after: cert.validity().not_after.timestamp(),
        sha256: ring::digest::digest(&ring::digest::SHA256, der)
            .as_ref()
            .iter()
            .fold(String::new(), |mut hex, b| {
                let _ = write!(hex, "{b:02x}");
                hex
            }),
        der_base64: base64::engine::Engine::encode(&base64::engine::general_purpose::STANDARD, der),
        ..ClientIdentity::default()
    };
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for name in &san.value.general_names {
            match name {
                GeneralName::DNSName(dns) => identity.dns.push((*dns).to_owned()),
                GeneralName::URI(uri) => identity.uris.push((*uri).to_owned()),
                GeneralName::RFC822Name(email) => identity.emails.push((*email).to_owned()),
                GeneralName::IPAddress(bytes) => {
                    let ip = match bytes.len() {
                        4 => <[u8; 4]>::try_from(*bytes).ok().map(IpAddr::from),
                        16 => <[u8; 16]>::try_from(*bytes).ok().map(IpAddr::from),
                        _ => None,
                    };
                    identity.ips.extend(ip.map(|ip| ip.to_string()));
                }
                _ => {}
            }
        }
    }
    Some(identity)
}

/// Builds a TLS acceptor for `tls`. Pingora's `TlsSettings` is only used for its
/// handshake-complete callback; the rustls configuration is ours.
///
/// Resumption comes from `tickets`: one ticketer and session cache per security class, shared
/// with the other listeners of that class and kept across reloads (H-PERF-02).
pub fn acceptor(
    tls: &ListenerTls,
    resolver: Arc<ListenerResolver>,
    tickets: &rdock_tls::TicketRegistry,
) -> Result<Acceptor, String> {
    let verifier = match &tls.client_auth {
        Some(auth) => Some(auth.verifier().map_err(|e| e.to_string())?),
        None => None,
    };
    let resumption = tickets
        .resumption(&tls.class(), tls.file_keys.clone())
        .map_err(|e| e.to_string())?;
    let config = rdock_tls::server_config(tls.policy, resolver.clone(), verifier, &resumption)
        .map_err(|e| e.to_string())?;
    let mut settings =
        TlsSettings::with_callbacks(Box::new(CaptureHandshake)).map_err(|e| e.to_string())?;
    settings.set_cert_resolver(resolver);
    let mut acceptor = settings.build();
    acceptor.acceptor = pingora::tls::TlsAcceptor::from(config);
    Ok(acceptor)
}

/// Binds a listening socket with the default options. `:port` binds all interfaces, IPv6 and
/// IPv4 when available.
pub fn bind(address: &ListenAddress) -> io::Result<std::net::TcpListener> {
    bind_with(address, &ListenerSocket::default())
}

/// The addresses to try for `address`: the address itself, or for `:port` the IPv6 and then
/// the IPv4 wildcard.
fn bind_addresses(address: &ListenAddress) -> Vec<SocketAddr> {
    match address.ip() {
        Some(ip) => vec![SocketAddr::new(ip, address.port())],
        None => vec![
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), address.port()),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), address.port()),
        ],
    }
}

/// Tries each address in turn; the last error if none binds.
fn bind_first<T>(
    address: &ListenAddress,
    bind: impl Fn(SocketAddr) -> io::Result<T>,
) -> io::Result<T> {
    let mut last = io::Error::new(io::ErrorKind::AddrNotAvailable, "no address to bind");
    for addr in bind_addresses(address) {
        match bind(addr) {
            Ok(socket) => return Ok(socket),
            Err(err) => last = err,
        }
    }
    Err(last)
}

/// A socket with the options that must be set before `bind`.
fn new_socket(
    addr: SocketAddr,
    kind: socket2::Type,
    protocol: socket2::Protocol,
    options: &ListenerSocket,
) -> io::Result<socket2::Socket> {
    let socket = socket2::Socket::new(socket2::Domain::for_address(addr), kind, Some(protocol))?;
    // What the standard library's `bind` set before v0.9: a restart can bind an address
    // whose old connections are still in TIME_WAIT.
    #[cfg(unix)]
    if kind == socket2::Type::STREAM {
        socket.set_reuse_address(true)?;
    }
    #[cfg(unix)]
    if options.reuse_port {
        socket.set_reuse_port(true)?;
    }
    if addr.is_ipv6()
        && let Some(only) = options.ipv6_only
    {
        socket.set_only_v6(only)?;
    }
    set_buffers(&socket, options)?;
    Ok(socket)
}

/// `SO_RCVBUF` and `SO_SNDBUF`, when set. Before `listen`, so the TCP window scale is
/// negotiated with the receive buffer.
fn set_buffers(socket: &socket2::Socket, options: &ListenerSocket) -> io::Result<()> {
    if let Some(size) = options.receive_buffer {
        socket.set_recv_buffer_size(usize::try_from(size.as_u64()).unwrap_or(usize::MAX))?;
    }
    if let Some(size) = options.send_buffer {
        socket.set_send_buffer_size(usize::try_from(size.as_u64()).unwrap_or(usize::MAX))?;
    }
    Ok(())
}

/// The listen backlog as the system call takes it.
fn backlog(options: &ListenerSocket) -> i32 {
    i32::try_from(options.effective_backlog()).unwrap_or(i32::MAX)
}

/// `TCP_FASTOPEN` on a listening socket: the queue of pending Fast Open requests (0 turns it
/// off). Validation refuses it on other platforms.
#[cfg(target_os = "linux")]
fn set_fast_open(socket: &socket2::Socket, queue: u32) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let queue = usize::try_from(queue).unwrap_or(usize::MAX);
    pingora::protocols::l4::ext::set_tcp_fastopen_backlog(socket.as_raw_fd(), queue)
        .map_err(|e| io::Error::other(e.to_string()))
}

#[cfg(not(target_os = "linux"))]
fn set_fast_open(_socket: &socket2::Socket, _queue: u32) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "TCP Fast Open is only supported on Linux",
    ))
}

/// Binds a TCP listening socket with `options` (ADR-0031). `:port` binds all interfaces,
/// IPv6 and IPv4 when available. The backlog is `socket.backlog`, 4096 by default; the
/// standard library's `bind`, used before v0.9, always asked for 128.
pub fn bind_with(
    address: &ListenAddress,
    options: &ListenerSocket,
) -> io::Result<std::net::TcpListener> {
    bind_first(address, |addr| {
        let socket = new_socket(addr, socket2::Type::STREAM, socket2::Protocol::TCP, options)?;
        socket.bind(&addr.into())?;
        socket.listen(backlog(options))?;
        if let Some(queue) = options.fast_open {
            set_fast_open(&socket, queue)?;
            warn_if_fast_open_is_off();
        }
        socket.set_nonblocking(true)?;
        Ok(socket.into())
    })
}

/// Fast Open needs the server bit of `net.ipv4.tcp_fastopen`; without it the option is set
/// but clients fall back to a normal handshake.
fn warn_if_fast_open_is_off() {
    if let Ok(text) = std::fs::read_to_string("/proc/sys/net/ipv4/tcp_fastopen")
        && let Ok(value) = text.trim().parse::<u32>()
        && value & 2 == 0
    {
        tracing::warn!(
            sysctl = value,
            "`socket.fast_open` is set, but the kernel does not accept Fast Open as a server; set net.ipv4.tcp_fastopen to 3"
        );
    }
}

/// Binds a UDP socket with the default options. `:port` binds all interfaces, IPv6 and IPv4
/// when available.
pub fn bind_udp(address: &ListenAddress) -> io::Result<std::net::UdpSocket> {
    bind_udp_with(address, &ListenerSocket::default())
}

/// Binds a UDP socket with `options` (buffers, `ipv6_only`, `dscp`; validation refuses the
/// TCP options).
pub fn bind_udp_with(
    address: &ListenAddress,
    options: &ListenerSocket,
) -> io::Result<std::net::UdpSocket> {
    bind_first(address, |addr| {
        let socket = new_socket(addr, socket2::Type::DGRAM, socket2::Protocol::UDP, options)?;
        socket.bind(&addr.into())?;
        if let Some(dscp) = options.dscp {
            set_dscp(&socket, addr, dscp)?;
        }
        socket.set_nonblocking(true)?;
        Ok(socket.into())
    })
}

/// DSCP as the top six bits of IPv4's TOS byte or IPv6's traffic class. `addr` is the local
/// address; an IPv6 socket that serves IPv4 clients (mapped addresses) gets both.
fn set_dscp(socket: &socket2::Socket, addr: SocketAddr, dscp: u8) -> io::Result<()> {
    let value = u32::from(dscp) << 2;
    if addr.is_ipv6() {
        socket.set_tclass_v6(value)?;
        // Dual-stack sockets: IPv4 clients' packets carry the IPv4 TOS byte. A socket that is
        // IPv6-only refuses this, which is fine.
        let _ = socket.set_tos_v4(value);
        Ok(())
    } else {
        socket.set_tos_v4(value)
    }
}

/// Changes the options of a running listening socket (`control` is a duplicate of its
/// descriptor) that apply without binding again: the backlog (`listen` again), the buffers
/// and Fast Open; DSCP of a UDP socket. `reuse_port` and `ipv6_only` are set before `bind`, so
/// a change of those keeps the running socket as it is (the reload says so).
pub(crate) fn update_running(
    control: &socket2::Socket,
    udp: bool,
    old: &ListenerSocket,
    new: &ListenerSocket,
) -> io::Result<()> {
    if old.receive_buffer != new.receive_buffer || old.send_buffer != new.send_buffer {
        set_buffers(control, new)?;
    }
    if udp {
        if old.dscp != new.dscp
            && let Some(dscp) = new.dscp
            && let Some(addr) = control.local_addr()?.as_socket()
        {
            set_dscp(control, addr, dscp)?;
        }
        return Ok(());
    }
    if old.effective_backlog() != new.effective_backlog() {
        // Linux applies the new length to a socket that is already listening.
        control.listen(backlog(new))?;
    }
    if old.fast_open != new.fast_open {
        set_fast_open(control, new.fast_open.unwrap_or(0))?;
    }
    Ok(())
}

/// Options of accepted TCP connections: keep-alive, `TCP_USER_TIMEOUT` and DSCP.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ConnectionOptions {
    keepalive: Option<rdock_model::config::TcpKeepalive>,
    user_timeout: Option<Duration>,
    dscp: Option<u8>,
}

impl ConnectionOptions {
    /// The per-connection part of a listener's socket options.
    #[must_use]
    pub fn of(socket: &ListenerSocket) -> Self {
        Self {
            keepalive: socket.keepalive,
            user_timeout: socket
                .user_timeout
                .map(rdock_model::values::Duration::as_std),
            dscp: socket.dscp,
        }
    }

    /// Sets them on an accepted connection; nothing (no system call) when none is set. A
    /// failure is logged and the connection served anyway.
    fn apply(&self, tcp: &tokio::net::TcpStream, listener: &str) {
        if *self == Self::default() {
            return;
        }
        let socket = socket2::SockRef::from(tcp);
        let result = (|| -> io::Result<()> {
            if let Some(k) = self.keepalive {
                let mut params = socket2::TcpKeepalive::new();
                if let Some(idle) = k.idle {
                    params = params.with_time(idle.as_std());
                }
                if let Some(interval) = k.interval {
                    params = params.with_interval(interval.as_std());
                }
                if let Some(count) = k.count {
                    params = params.with_retries(count);
                }
                socket.set_tcp_keepalive(&params)?;
            }
            #[cfg(target_os = "linux")]
            if let Some(timeout) = self.user_timeout {
                socket.set_tcp_user_timeout(Some(timeout))?;
            }
            if let Some(dscp) = self.dscp {
                let local = tcp.local_addr()?;
                set_dscp(&socket, local, dscp)?;
            }
            Ok(())
        })();
        if let Err(err) = result {
            tracing::debug!(listener, error = %err, "cannot set connection socket options");
        }
    }
}

/// The bound on concurrent TLS handshakes of a listener (`tls.max_handshakes`).
#[derive(Debug, Clone)]
pub struct Handshakes {
    limit: u32,
    permits: Arc<Semaphore>,
}

impl Handshakes {
    /// A bound of `limit` handshakes.
    #[must_use]
    pub fn new(limit: u32) -> Self {
        Self {
            limit,
            permits: Arc::new(Semaphore::new(usize::try_from(limit).unwrap_or(usize::MAX))),
        }
    }

    /// The bound.
    #[must_use]
    pub fn limit(&self) -> u32 {
        self.limit
    }
}

/// A TLS connection between accept and the end of its handshake: counted in
/// `rdock_tls_handshakes_in_flight`, and holding a permit of the listener's bound if it has one.
struct InHandshake {
    gauge: rdock_observability::IntGauge,
    permit: Option<OwnedSemaphorePermit>,
}

impl InHandshake {
    fn new(metrics: &Metrics, listener: &str, permit: Option<OwnedSemaphorePermit>) -> Self {
        let gauge = metrics
            .tls_handshakes_in_flight
            .with_label_values(&[listener]);
        gauge.inc();
        Self { gauge, permit }
    }
}

impl Drop for InHandshake {
    fn drop(&mut self) {
        self.gauge.dec();
        drop(self.permit.take());
    }
}

/// A bound socket, before its listener starts.
#[derive(Debug)]
pub enum Socket {
    /// `http`, `https` and `tcp` listeners.
    Tcp(tokio::net::TcpListener),
    /// `udp` listeners.
    Udp(tokio::net::UdpSocket),
}

impl Socket {
    /// Binds `address` for a listener of `protocol` with `options`.
    ///
    /// # Errors
    ///
    /// The address cannot be bound, or an option cannot be set.
    pub fn bind(
        address: &ListenAddress,
        protocol: ListenerProtocol,
        options: &ListenerSocket,
    ) -> io::Result<Self> {
        Ok(if protocol == ListenerProtocol::Udp {
            Self::Udp(tokio::net::UdpSocket::from_std(bind_udp_with(
                address, options,
            )?)?)
        } else {
            Self::Tcp(tokio::net::TcpListener::from_std(bind_with(
                address, options,
            )?)?)
        })
    }

    /// A listening socket handed over by another process (binary upgrade): `udp` says which
    /// kind it is. Must be called inside the runtime.
    ///
    /// # Errors
    ///
    /// The descriptor cannot be made non-blocking or registered with the runtime, or is not a
    /// socket of the expected kind.
    pub fn from_fd(fd: std::os::fd::OwnedFd, udp: bool) -> io::Result<Self> {
        let socket = socket2::Socket::from(fd);
        let kind = socket.r#type()?;
        let expected = if udp {
            socket2::Type::DGRAM
        } else {
            socket2::Type::STREAM
        };
        if kind != expected {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the handed-over socket is not of the expected kind",
            ));
        }
        socket.set_nonblocking(true)?;
        Ok(if udp {
            Self::Udp(tokio::net::UdpSocket::from_std(socket.into())?)
        } else {
            Self::Tcp(tokio::net::TcpListener::from_std(socket.into())?)
        })
    }

    /// A duplicate descriptor of the socket, to change its options while the listener runs.
    pub(crate) fn control(&self) -> io::Result<socket2::Socket> {
        match self {
            Self::Tcp(socket) => socket2::SockRef::from(socket).try_clone(),
            Self::Udp(socket) => socket2::SockRef::from(socket).try_clone(),
        }
    }
}

/// HTTP/2 options for `http2` (H-PERF-03). Unset values give exactly what Pingora's
/// `default_h2_options()` gave before v0.9: a 64 KiB header list and 100 streams
/// (`pingora-core` 0.9.1, `src/protocols/http/v2/server.rs` lines 56-57 and 69-74), the rest
/// h2 0.4.20's defaults. Only values that are set are sent in the SETTINGS frame, as before.
#[must_use]
pub fn h2_options(http2: &ListenerHttp2) -> H2Options {
    let mut options = default_h2_options();
    if let Some(size) = http2.max_header_list_size {
        options.max_header_list_size(u32::try_from(size.as_u64()).unwrap_or(u32::MAX));
    }
    match http2.max_concurrent_streams {
        Some(FloodLimit::Count(n)) => {
            options.max_concurrent_streams(n);
        }
        // h2's own default sends no limit; Pingora's 100 was set above, so start again from
        // h2's defaults and keep the header-list bound.
        Some(FloodLimit::Unlimited) => {
            let header_list = http2
                .max_header_list_size
                .map_or(64 * 1024, |s| u32::try_from(s.as_u64()).unwrap_or(u32::MAX));
            options = H2Options::default();
            options.max_header_list_size(header_list);
        }
        None => {}
    }
    let window =
        |size: rdock_model::values::ByteSize| u32::try_from(size.as_u64()).unwrap_or(u32::MAX);
    if let Some(size) = http2.initial_stream_window {
        options.initial_window_size(window(size));
    }
    if let Some(size) = http2.initial_connection_window {
        options.initial_connection_window_size(window(size));
    }
    // Validation keeps the frame size within 16384..=16777215, which h2 asserts.
    if let Some(size) = http2.max_frame_size {
        options.max_frame_size(window(size).clamp(16_384, 16_777_215));
    }
    match http2.max_pending_accept_reset_streams {
        Some(FloodLimit::Count(n)) => {
            options.max_pending_accept_reset_streams(usize::try_from(n).unwrap_or(usize::MAX));
        }
        Some(FloodLimit::Unlimited) => {
            options.max_pending_accept_reset_streams(usize::MAX);
        }
        None => {}
    }
    match http2.max_local_error_reset_streams {
        Some(FloodLimit::Count(n)) => {
            options.max_local_error_reset_streams(Some(usize::try_from(n).unwrap_or(usize::MAX)));
        }
        Some(FloodLimit::Unlimited) => {
            options.max_local_error_reset_streams(None);
        }
        None => {}
    }
    if let Some(size) = http2.max_send_buffer {
        // h2 asserts the size fits in a u32; validation keeps it at 16 MiB or less.
        options.max_send_buffer_size(usize::try_from(window(size)).unwrap_or(usize::MAX));
    }
    options
}

/// The HTTP engine of one listener.
pub fn http_engine(
    name: Arc<str>,
    shared: Arc<Shared>,
    timeouts: &ListenerTimeouts,
    http2: &ListenerHttp2,
) -> Arc<HttpProxy<RdockProxy>> {
    let idle = shared.runtime.load().limits.upstream_idle_connections;
    let conf = Arc::new(ServerConf {
        // Pingora keeps 128 idle upstream connections by default; under load every request
        // beyond them opened and closed its own backend connection (#86).
        upstream_keepalive_pool_size: usize::try_from(idle).unwrap_or(usize::MAX).max(1),
        // Attempts per request: one retry for a pooled connection that closed under us.
        // Retries are limited per request by `services.<s>.retries` (at most 10) and the
        // stale pooled-connection retry; this is only Pingora's outer bound.
        max_retries: 16,
        ..ServerConf::default()
    });
    let mut proxy = pingora::proxy::http_proxy(&conf, RdockProxy::new(name, shared));
    let mut options = HttpServerOptions::default();
    options.h2c = true;
    options.h2_idle_timeout = Some(timeouts.idle.as_std());
    proxy.server_options = Some(options);
    proxy.h2_options = Some(h2_options(http2));
    Arc::new(proxy)
}

/// Settings of a running listener that a reload may change in place.
#[derive(Clone)]
pub struct Settings {
    /// TLS acceptor of an HTTPS listener.
    pub tls: Option<Arc<Acceptor>>,
    /// Client timeouts.
    pub timeouts: ListenerTimeouts,
    /// Inbound PROXY protocol.
    pub proxy_protocol: Option<ProxyProtocolIn>,
    /// `http`, `https`, `tcp` or `udp`: what a new connection (or datagram) is served as.
    pub protocol: ListenerProtocol,
    /// `tcp` listeners: the protocol whose request to start TLS is answered.
    pub starttls: Option<StartTls>,
    /// Options set on each accepted connection.
    pub connection: ConnectionOptions,
    /// The bound on concurrent TLS handshakes, if the listener has one.
    pub handshakes: Option<Handshakes>,
    /// HTTP/2 settings; a change builds a new HTTP engine for new connections.
    pub http2: ListenerHttp2,
}

/// How a listener is asked to stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stop {
    /// How long open connections (or UDP sessions) may still run.
    pub drain: Duration,
    /// Hand the socket back instead of closing it, because another listener takes the same
    /// address over in this reload. A TCP listener's connections still drain; a UDP listener
    /// ends its sessions at once, since their replies leave from that socket.
    pub hand_off: bool,
}

impl Stop {
    /// Stop with `drain` and close the socket.
    #[must_use]
    pub const fn drain(drain: Duration) -> Self {
        Self {
            drain,
            hand_off: false,
        }
    }
}

/// A running listener.
pub struct Running {
    /// Bind address.
    pub address: ListenAddress,
    /// A UDP socket (a `udp` listener), not a TCP one.
    pub udp: bool,
    /// Changeable settings.
    pub settings: Arc<ArcSwap<Settings>>,
    /// A duplicate of the socket's descriptor, to change its options in place on a reload,
    /// and the options it has. Dropped when the listener stops, so it never keeps the socket
    /// open after the listener closed it.
    control: Option<(socket2::Socket, ListenerSocket)>,
    stop: watch::Sender<Option<Stop>>,
    /// Resolves once the listener's socket is closed (the sender is dropped) or handed back.
    released: oneshot::Receiver<Socket>,
    task: tokio::task::JoinHandle<()>,
    /// The HTTP engine new connections get (TCP listeners), and what it was built with.
    engine: Option<(Engine, (ListenerHttp2, Duration))>,
}

/// A listener's HTTP engine, replaced when its HTTP/2 settings or idle timeout change.
type Engine = Arc<ArcSwap<HttpProxy<RdockProxy>>>;

impl Running {
    /// Starts accepting on `socket` (or, for a UDP socket, receiving datagrams); `options`
    /// are the socket options it was bound (or last updated) with.
    pub fn start(
        name: Arc<str>,
        address: ListenAddress,
        (socket, options): (Socket, ListenerSocket),
        settings: Settings,
        shared: Arc<Shared>,
    ) -> Self {
        let (stop, stop_rx) = watch::channel(None);
        let (hand_back, released) = oneshot::channel();
        let udp = matches!(socket, Socket::Udp(_));
        let control = match socket.control() {
            Ok(control) => Some((control, options)),
            Err(err) => {
                tracing::warn!(listener = %name, error = %err, "cannot keep a handle on the socket; option changes will need a restart");
                None
            }
        };
        let key = (settings.http2, settings.timeouts.idle.as_std());
        let settings = Arc::new(ArcSwap::from_pointee(settings));
        let mut engine = None;
        let task = match socket {
            Socket::Tcp(socket) => {
                let current = settings.load();
                let built: Engine = Arc::new(ArcSwap::new(http_engine(
                    name.clone(),
                    shared.clone(),
                    &current.timeouts,
                    &current.http2,
                )));
                engine = Some((built.clone(), key));
                tokio::spawn(accept_loop(
                    name,
                    socket,
                    settings.clone(),
                    built,
                    (stop_rx, hand_back),
                    shared,
                ))
            }
            Socket::Udp(socket) => {
                tokio::spawn(crate::udp::serve(name, socket, stop_rx, hand_back, shared))
            }
        };
        Self {
            address,
            udp,
            settings,
            control,
            stop,
            released,
            task,
            engine,
        }
    }

    /// Builds a new HTTP engine for new connections when the HTTP/2 settings or the idle
    /// timeout changed; open connections keep the engine they started with.
    pub fn update_engine(
        &mut self,
        name: &str,
        http2: &ListenerHttp2,
        timeouts: &ListenerTimeouts,
        shared: &Arc<Shared>,
    ) {
        let Some((engine, key)) = self.engine.as_mut() else {
            return;
        };
        let wanted = (*http2, timeouts.idle.as_std());
        if *key == wanted {
            return;
        }
        engine.store(http_engine(
            Arc::from(name),
            shared.clone(),
            timeouts,
            http2,
        ));
        *key = wanted;
    }

    /// Applies changed socket options to the running socket: the backlog, the buffers and Fast
    /// Open (DSCP of a UDP socket). An option that is set before `bind` (`reuse_port`,
    /// `ipv6_only`) stays as it was.
    ///
    /// # Errors
    ///
    /// An option cannot be set.
    pub fn update_socket(&mut self, options: &ListenerSocket) -> io::Result<()> {
        let Some((control, current)) = self.control.as_mut() else {
            return Ok(());
        };
        if current == options {
            return Ok(());
        }
        update_running(control, self.udp, current, options)?;
        // What was not changed in place (set before `bind`) keeps its running value.
        let (reuse_port, ipv6_only) = (current.reuse_port, current.ipv6_only);
        *current = ListenerSocket {
            reuse_port,
            ipv6_only,
            ..*options
        };
        Ok(())
    }

    /// A new duplicate of the socket's descriptor and its options, for the next process in a
    /// binary upgrade.
    #[must_use]
    pub fn handle(&self) -> Option<(std::os::fd::OwnedFd, ListenerSocket)> {
        let (control, options) = self.control.as_ref()?;
        let dup = control.try_clone().ok()?;
        Some((std::os::fd::OwnedFd::from(dup), *options))
    }

    /// The socket options the running socket has.
    #[must_use]
    pub fn socket_options(&self) -> Option<&ListenerSocket> {
        self.control.as_ref().map(|(_, options)| options)
    }

    /// Stops accepting (or opening UDP sessions); open connections (or sessions) may run for up
    /// to `drain`. A TCP listener closes its socket at once; a UDP listener keeps it until its
    /// sessions end, because their replies leave from it.
    #[must_use]
    pub fn stop(self, drain: Duration) -> Stopping {
        let _ = self.stop.send(Some(Stop::drain(drain)));
        Stopping {
            address: self.address,
            udp: self.udp,
            stop: self.stop,
            released: Some(self.released),
            task: self.task,
        }
    }

    /// Stops the listener and returns its socket, for another listener on the same address. A
    /// TCP listener's connections drain for up to `drain`; a UDP listener's sessions end first.
    /// `None` only if the socket could not be handed back (it is closed then).
    pub async fn hand_off(self, drain: Duration) -> (Option<Socket>, Stopping) {
        let _ = self.stop.send(Some(Stop {
            drain,
            hand_off: true,
        }));
        let socket = self.released.await.ok();
        let stopping = Stopping {
            address: self.address,
            udp: self.udp,
            stop: self.stop,
            released: None,
            task: self.task,
        };
        (socket, stopping)
    }
}

/// A listener that was asked to stop and may still be draining.
pub struct Stopping {
    /// Bind address.
    pub address: ListenAddress,
    /// A UDP listener.
    pub udp: bool,
    stop: watch::Sender<Option<Stop>>,
    released: Option<oneshot::Receiver<Socket>>,
    task: tokio::task::JoinHandle<()>,
}

impl Stopping {
    /// Waits until the listener's socket is closed.
    pub async fn released(&mut self) {
        if let Some(released) = self.released.take() {
            // The socket is never handed back here: only `Running::hand_off` asks for that.
            let _ = released.await;
        }
    }

    /// Ends the drain now (open UDP sessions end) and waits until the socket is closed.
    pub async fn end_now(&mut self) {
        let _ = self.stop.send(Some(Stop::drain(Duration::ZERO)));
        self.released().await;
    }

    /// Whether the listener's task has ended (drain over, socket closed).
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.task.is_finished()
    }

    /// Waits until the drain is over.
    pub async fn finished(self) {
        let _ = self.task.await;
    }
}

async fn accept_loop(
    name: Arc<str>,
    socket: tokio::net::TcpListener,
    settings: Arc<ArcSwap<Settings>>,
    engine: Engine,
    (mut stop, hand_back): (watch::Receiver<Option<Stop>>, oneshot::Sender<Socket>),
    shared: Arc<Shared>,
) {
    let metrics: &Metrics = &shared.metrics;
    let (closing, closing_rx) = watch::channel(false);
    let mut connections = JoinSet::new();
    let mut accepting = shared.accepting.subscribe();
    // A permit of `tls.max_handshakes` taken before the next accept: while none is free, new
    // connections wait in the kernel's backlog and established ones keep the CPU.
    let mut permit: Option<OwnedSemaphorePermit> = None;
    let request = loop {
        while connections.try_join_next().is_some() {}
        // Paused by a binary upgrade: new connections wait in the backlog, which both processes
        // share, so none is refused or reset.
        if !*accepting.borrow_and_update() {
            tokio::select! {
                changed = stop.changed() => {
                    let requested = *stop.borrow();
                    if changed.is_err() || requested.is_some() {
                        break requested.unwrap_or(Stop::drain(Duration::ZERO));
                    }
                }
                _ = accepting.changed() => {}
            }
            continue;
        }
        if permit.is_none()
            && let Some(bound) = settings.load().handshakes.clone()
        {
            if let Ok(p) = bound.permits.clone().try_acquire_owned() {
                permit = Some(p);
            } else {
                metrics
                    .tls_handshake_waits
                    .with_label_values(&[&name])
                    .inc();
                tokio::select! {
                    changed = stop.changed() => {
                        let requested = *stop.borrow();
                        if changed.is_err() || requested.is_some() {
                            break requested.unwrap_or(Stop::drain(Duration::ZERO));
                        }
                        continue;
                    }
                    acquired = bound.permits.clone().acquire_owned() => {
                        permit = acquired.ok();
                    }
                }
            }
        }
        tokio::select! {
            biased;
            changed = stop.changed() => {
                let requested = *stop.borrow();
                if changed.is_err() || requested.is_some() {
                    break requested.unwrap_or(Stop::drain(Duration::ZERO));
                }
            }
            _ = accepting.changed() => {}
            accepted = socket.accept() => match accepted {
                Ok((tcp, peer)) => {
                    metrics.connections_total.with_label_values(&[&name]).inc();
                    let current = settings.load_full();
                    // The permit goes with the connection if it still belongs to the
                    // listener's current bound (a reload may have changed it).
                    let taken = permit.take().filter(|_| current.handshakes.is_some());
                    connections.spawn(serve(
                        name.clone(),
                        tcp,
                        peer,
                        (current, taken),
                        engine.load_full(),
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
    // The accepting socket goes first, so its address is free (or taken over) while open
    // connections drain; dropping `hand_back` tells the reload it is closed.
    if request.hand_off {
        let _ = hand_back.send(Socket::Tcp(socket));
    } else {
        drop(socket);
        drop(hand_back);
    }
    drain_connections(
        &name,
        &settings,
        &engine,
        closing,
        connections,
        request.drain,
    )
    .await;
}

/// Ends a stopped listener's connections: HTTP/1 keep-alive off and HTTP/2 GOAWAY at once,
/// idle connections closed after a short grace, the rest closed at the end of `drain`.
async fn drain_connections(
    name: &str,
    settings: &ArcSwap<Settings>,
    engine: &Engine,
    closing: watch::Sender<bool>,
    mut connections: JoinSet<()>,
    drain: Duration,
) {
    // HTTP/1 keep-alive off for new sessions and GOAWAY on HTTP/2 connections, at once.
    let _ = closing.send(true);
    // Pingora's `cleanup` drops every connection still waiting in `read_request`, without an
    // answer (`pingora-proxy` 0.9.1, `src/lib.rs` lines 332-338). That is right for an idle
    // keep-alive connection, but not for one accepted a moment ago whose first request is on its
    // way (a binary upgrade stops this process just after it last accepted). Those get a short
    // grace first, never longer than the drain.
    let started = tokio::time::Instant::now();
    let grace = drain.min(CLEANUP_GRACE);
    let _ = tokio::time::timeout(grace, async {
        while connections.join_next().await.is_some() {}
    })
    .await;
    engine.load().cleanup().await;
    let drained = tokio::time::timeout(drain.saturating_sub(started.elapsed()), async {
        while connections.join_next().await.is_some() {}
    })
    .await;
    if drained.is_err() {
        let open = connections.len();
        if settings.load().protocol == ListenerProtocol::Tcp {
            tracing::warn!(listener = %name, aborted = open, "drain time over, closing {open} TCP connections");
        } else {
            tracing::info!(listener = %name, open, "drain time over, closing connections");
        }
        connections.abort_all();
    }
}

/// How long a stopping listener's connections that have not sent a request yet may still send
/// their first one before idle connections are closed (bounded by the drain).
const CLEANUP_GRACE: Duration = Duration::from_secs(2);

/// The TCP routes a connection on `name` may go to: always for a `tcp` listener (possibly none),
/// and for an `https` listener only when it has some, since it then hands matching
/// TLS connections to them by their `ClientHello`. `None` means the connection is served as HTTP without a TCP step.
fn tcp_routes_of(
    shared: &Shared,
    name: &str,
    settings: &Settings,
) -> Option<Arc<[Arc<crate::tcp::TcpRouteRuntime>]>> {
    let tcp = settings.protocol == ListenerProtocol::Tcp;
    if !tcp && settings.tls.is_none() {
        return None;
    }
    let routes = shared
        .runtime
        .load()
        .listeners
        .get(name)?
        .tcp_routes
        .clone();
    (tcp || !routes.is_empty()).then_some(routes)
}

/// Guard that keeps the open-connections gauge and count right however the task ends.
struct Open<'a>(&'a Shared, &'a str);

impl Drop for Open<'_> {
    fn drop(&mut self) {
        self.0
            .metrics
            .connections
            .with_label_values(&[self.1])
            .dec();
        self.0
            .open_connections
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

#[allow(clippy::too_many_lines)] // the steps of a connection, in order
async fn serve(
    name: Arc<str>,
    tcp: tokio::net::TcpStream,
    peer: SocketAddr,
    (settings, permit): (Arc<Settings>, Option<OwnedSemaphorePermit>),
    engine: Arc<HttpProxy<RdockProxy>>,
    closing: watch::Receiver<bool>,
    shared: Arc<Shared>,
) {
    shared.metrics.connections.with_label_values(&[&name]).inc();
    shared
        .open_connections
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let _open = Open(&shared, &name);
    let _ = tcp.set_nodelay(true);
    settings.connection.apply(&tcp, &name);
    // Until its handshake ends, a TLS connection counts as one in flight and holds its permit.
    let mut in_handshake = settings
        .tls
        .is_some()
        .then(|| InHandshake::new(&shared.metrics, &name, permit));
    // Only connections that may become TCP relays look up routes and pay for `getsockname`.
    let tcp_side = tcp_routes_of(&shared, &name, &settings)
        .map(|routes| (routes, tcp.local_addr().unwrap_or(peer)));
    #[cfg(unix)]
    let fd = std::os::unix::io::AsRawFd::as_raw_fd(&tcp);
    let mut l4: L4Stream = tcp.into();
    let header_timeout = settings.timeouts.request_header.as_std();
    // Everything before HTTP (PROXY header, TLS handshake, h2c preface) shares one deadline.
    let deadline = tokio::time::Instant::now() + header_timeout;
    let Ok(source) = crate::proxy_protocol::accept(
        &name,
        settings.proxy_protocol.as_ref(),
        peer,
        &mut l4,
        deadline,
        &shared.metrics,
    )
    .await
    else {
        return;
    };
    #[cfg(unix)]
    {
        let digest = SocketDigest::from_raw_fd(fd);
        if let Some(source) = source {
            crate::proxy_protocol::set_peer(&digest, source);
        }
        l4.set_socket_digest(digest);
    }
    if let Some((tcp_routes, local)) = tcp_side {
        let accepted = crate::tcp::Accepted {
            listener: name.clone(),
            client: source.unwrap_or(peer),
            local,
        };
        let context = crate::tcp::ListenerContext {
            routes: &tcp_routes,
            tls: settings.tls.as_deref(),
            starttls: settings.starttls,
            deadline,
        };
        if settings.protocol == ListenerProtocol::Tcp {
            // `tcp` listeners relay; the bound covers only `https` handshakes.
            drop(in_handshake.take());
            crate::tcp::serve(accepted, l4, context, &shared.metrics).await;
            return;
        }
        // A diverted connection is relayed for as long as it lasts, so it gives its permit
        // back first; one that stays here takes a permit again for its own handshake.
        let bounded = in_handshake.take().is_some_and(|h| h.permit.is_some());
        match crate::tcp::divert(accepted, l4, context, &shared.metrics).await {
            Some(stream) => l4 = stream,
            None => return,
        }
        let permit = match (bounded, settings.handshakes.as_ref()) {
            (true, Some(bound)) => bound.permits.clone().acquire_owned().await.ok(),
            _ => None,
        };
        in_handshake = Some(InHandshake::new(&shared.metrics, &name, permit));
    }
    let stream: ConnStream = if let Some(acceptor) = &settings.tls {
        let handshake = tokio::time::timeout_at(deadline, acceptor.tls_handshake(l4)).await;
        // The handshake is over, whatever its outcome: the permit and the gauge go.
        drop(in_handshake.take());
        let tls = match handshake {
            Ok(Ok(tls)) => tls,
            failed => {
                if let Ok(Err(err)) = &failed {
                    tracing::debug!(listener = %name, error = %err, "TLS handshake failed");
                }
                shared
                    .metrics
                    .tls_handshake_errors
                    .with_label_values(&[&name])
                    .inc();
                return;
            }
        };
        let alpn = pingora::protocols::Ssl::selected_alpn_proto(&tls);
        if let Some(pingora::protocols::ALPN::Custom(custom)) = &alpn
            && custom.protocol() == rdock_tls::challenge::ACME_TLS_ALPN
        {
            // A TLS-ALPN-01 validation: the handshake was the answer; no HTTP follows.
            return;
        }
        let h2 = matches!(alpn, Some(pingora::protocols::ALPN::H2));
        ConnStream::new(Box::new(tls) as Stream, None, !h2, header_timeout)
    } else {
        let Ok(Some(first)) = tokio::time::timeout_at(deadline, read_preface(&mut l4)).await else {
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

#[cfg(test)]
mod tests {
    use super::*;
    use rdock_model::config::TcpKeepalive;
    use rdock_model::values::{ByteSize, Duration as ModelDuration};

    fn loopback() -> ListenAddress {
        ListenAddress::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
    }

    #[test]
    fn bind_sets_the_options_before_listening() {
        let options = ListenerSocket {
            reuse_port: true,
            receive_buffer: Some(ByteSize::kib(256)),
            send_buffer: Some(ByteSize::kib(128)),
            ..ListenerSocket::default()
        };
        let listener = bind_with(&loopback(), &options).unwrap();
        let socket = socket2::SockRef::from(&listener);
        #[cfg(unix)]
        assert!(socket.reuse_port().unwrap());
        assert!(
            socket.reuse_address().unwrap(),
            "as the standard library set it"
        );
        // Linux doubles the requested size for its own bookkeeping.
        assert!(socket.recv_buffer_size().unwrap() >= 256 * 1024);
        assert!(socket.send_buffer_size().unwrap() >= 128 * 1024);
        // A second socket with SO_REUSEPORT binds the same address.
        let port = listener.local_addr().unwrap().port();
        let again = ListenAddress::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        assert!(bind_with(&again, &options).is_ok());
        assert!(bind(&again).is_err(), "without it the address is in use");
    }

    #[test]
    fn ipv6_only_applies_to_ipv6_sockets() {
        let v6 = ListenAddress::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0);
        let options = ListenerSocket {
            ipv6_only: Some(true),
            ..ListenerSocket::default()
        };
        // Some sandboxes have no IPv6.
        if let Ok(listener) = bind_with(&v6, &options) {
            assert!(socket2::SockRef::from(&listener).only_v6().unwrap());
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn accepted_connections_get_keepalive_user_timeout_and_dscp() {
        let options = ListenerSocket {
            keepalive: Some(TcpKeepalive {
                idle: Some(ModelDuration::from_secs(60)),
                interval: Some(ModelDuration::from_secs(10)),
                count: Some(3),
            }),
            user_timeout: Some(ModelDuration::from_secs(30)),
            dscp: Some(10),
            ..ListenerSocket::default()
        };
        let listener =
            tokio::net::TcpListener::from_std(bind_with(&loopback(), &options).unwrap()).unwrap();
        let addr = listener.local_addr().unwrap();
        let _client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (accepted, _) = listener.accept().await.unwrap();
        ConnectionOptions::of(&options).apply(&accepted, "test");
        let socket = socket2::SockRef::from(&accepted);
        assert!(socket.keepalive().unwrap());
        assert_eq!(
            socket.tcp_keepalive_time().unwrap(),
            Duration::from_secs(60)
        );
        assert_eq!(
            socket.tcp_keepalive_interval().unwrap(),
            Duration::from_secs(10)
        );
        assert_eq!(socket.tcp_keepalive_retries().unwrap(), 3);
        assert_eq!(
            socket.tcp_user_timeout().unwrap(),
            Some(Duration::from_secs(30))
        );
        assert_eq!(
            socket.tos_v4().unwrap(),
            10 << 2,
            "DSCP is the TOS byte's top six bits"
        );
    }

    #[test]
    fn running_sockets_take_a_new_backlog_and_buffers_in_place() {
        let listener = bind_with(&loopback(), &ListenerSocket::default()).unwrap();
        let control = socket2::SockRef::from(&listener).try_clone().unwrap();
        let new = ListenerSocket {
            backlog: Some(16),
            receive_buffer: Some(ByteSize::kib(512)),
            ..ListenerSocket::default()
        };
        update_running(&control, false, &ListenerSocket::default(), &new).unwrap();
        assert!(
            socket2::SockRef::from(&listener)
                .recv_buffer_size()
                .unwrap()
                >= 512 * 1024
        );
    }
}
