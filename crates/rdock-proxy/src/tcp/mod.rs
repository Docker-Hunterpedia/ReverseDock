//! TCP routes (M-L4-01, M-L4-02, ADR-0026): what a `tcp` listener does with a connection after
//! the PROXY protocol step, and what an `https` listener does with a ClientHello that one of
//! its TCP routes matches.
//!
//! Per connection, in order: the optional `starttls: postgres` answer, the ClientHello peek
//! (every byte put back), route selection, the route's middlewares, then passthrough (the
//! original bytes, unchanged) or termination (the listener's TLS settings and certificates),
//! the outbound PROXY header, and the relay.

mod compile;
pub mod relay;
pub mod rule;
pub mod starttls;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use pingora::listeners::tls::Acceptor;
use pingora::protocols::l4::stream::Stream as L4Stream;
use rdock_limits::{Admitted, ConcurrencyLimiter};
use rdock_model::config::StartTls;
use rdock_model::service::{ProxyProtocolVersion, TcpTimeouts};
use rdock_model::values::IpNetwork;
use rdock_observability::{IntGauge, Metrics};
use rdock_tls::challenge::ACME_TLS_ALPN;
use rdock_tls::clienthello::{self, ClientHello, Detected, PeekError};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;

pub(crate) use compile::compile_tcp;

use crate::proxy_protocol::{Outbound, Terminated};
use crate::runtime::{Candidate, ServiceRuntime};
use crate::upstream::{self, RequestKey};
use relay::{Counters, End, Limits};
use rule::{TcpFacts, TcpRule};

/// A TCP route, compiled.
#[derive(Debug)]
pub struct TcpRouteRuntime {
    /// Route name.
    pub name: Arc<str>,
    /// Effective priority (explicit, or the rule length).
    pub priority: i64,
    /// Length of the rule, the tie-breaker after the priority.
    pub length: usize,
    /// Compiled rule.
    pub rule: TcpRule,
    /// The rule has ``HostSNI(`*`)``, the only matcher for connections without TLS.
    pub any_sni: bool,
    /// The rule looks at the ClientHello (`HostSNI` with a name, `HostSNIRegexp`, `ALPN`,
    /// `ClientFingerprint`).
    pub reads_hello: bool,
    /// The rule has `ClientFingerprint`: the ClientHello's JA4 is computed for it.
    pub reads_fingerprint: bool,
    /// What happens to the bytes.
    pub mode: TcpMode,
    /// Target service.
    pub service: Arc<TcpServiceRuntime>,
    /// `ip_allow`, `ip_deny` and `in_flight`, in order.
    pub filters: Arc<[TcpFilter]>,
}

/// What a TCP route does with a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpMode {
    /// No `tls`: relays the bytes as they come, TLS or not.
    Relay,
    /// `tls.passthrough`: relays a TLS connection without terminating it.
    Passthrough,
    /// `tls`: terminates TLS with the listener's settings and relays the plaintext.
    Terminate,
}

/// A TCP service, compiled.
#[derive(Debug)]
pub struct TcpServiceRuntime {
    /// Service name.
    pub name: Arc<str>,
    /// Backends and their selection, shared with HTTP services' machinery.
    pub pool: Arc<ServiceRuntime>,
    /// PROXY protocol header sent to backends.
    pub proxy_protocol: Option<ProxyProtocolVersion>,
    /// Connect, idle and termination timeouts.
    pub timeouts: TcpTimeouts,
}

/// A middleware of a TCP route, applied to the client address before connecting.
#[derive(Debug)]
pub enum TcpFilter {
    /// `ip_allow`: only these networks.
    Allow(Vec<IpNetwork>),
    /// `ip_deny`: not these networks.
    Deny(Vec<IpNetwork>),
    /// `in_flight`: connections per client IP.
    InFlight(ConcurrencyLimiter),
}

impl TcpRouteRuntime {
    /// Whether the route takes a connection with these facts. Without TLS, only relaying
    /// routes with ``HostSNI(`*`)`` are candidates.
    fn takes(&self, facts: &TcpFacts<'_>) -> bool {
        let candidate = facts.hello.is_some() || (self.mode == TcpMode::Relay && self.any_sni);
        candidate && self.rule.matches(facts)
    }
}

/// The first route, in evaluation order, that takes the connection.
#[must_use]
pub fn select<'a>(
    routes: &'a [Arc<TcpRouteRuntime>],
    facts: &TcpFacts<'_>,
) -> Option<&'a Arc<TcpRouteRuntime>> {
    routes.iter().find(|r| r.takes(facts))
}

/// Whether choosing among `routes` needs the ClientHello. When no route reads it, needs TLS or
/// can do without ``HostSNI(`*`)``, nothing is read before connecting, so protocols where the
/// server speaks first (MySQL, SMTP) can be relayed.
#[must_use]
pub fn reads_hello(routes: &[Arc<TcpRouteRuntime>]) -> bool {
    routes
        .iter()
        .any(|r| r.mode != TcpMode::Relay || r.reads_hello || !r.any_sni)
}

/// An accepted connection, after the PROXY protocol step.
#[derive(Debug, Clone)]
pub(crate) struct Accepted {
    /// Listener name.
    pub listener: Arc<str>,
    /// The original client: the PROXY header's source, else the TCP peer.
    pub client: SocketAddr,
    /// The local address the client connected to.
    pub local: SocketAddr,
}

impl Accepted {
    fn client_ip(&self) -> IpAddr {
        crate::forwarded::canonical(self.client.ip())
    }
}

/// What a listener with TCP routes needs to know about itself.
pub(crate) struct ListenerContext<'a> {
    /// The routes, in evaluation order.
    pub routes: &'a [Arc<TcpRouteRuntime>],
    /// The TLS acceptor, when the listener has `tls`: terminates, and answers TLS-ALPN-01.
    pub tls: Option<&'a Acceptor>,
    /// `starttls` of the listener.
    pub starttls: Option<StartTls>,
    /// Everything before the relay (PROXY header, request to start TLS, ClientHello,
    /// handshake) must be done by then.
    pub deadline: Instant,
}

/// Serves one connection of a `tcp` listener.
pub(crate) async fn serve(
    conn: Accepted,
    mut stream: L4Stream,
    listener: ListenerContext<'_>,
    metrics: &Metrics,
) {
    let Ok(answered_ssl_request) = answer_starttls(&mut stream, &listener).await else {
        return;
    };
    let (hello, fingerprint) = if reads_hello(listener.routes) || listener.tls.is_some() {
        let Ok(read) = read_hello(
            &conn,
            &mut stream,
            listener.deadline,
            metrics,
            listener.routes,
        )
        .await
        else {
            return;
        };
        read
    } else {
        (None, None)
    };
    if let (Some(acceptor), Some(hello)) = (listener.tls, &hello)
        && offers_only_acme(hello)
    {
        answer_acme(stream, acceptor, listener.deadline).await;
        return;
    }
    let facts = TcpFacts {
        hello: hello.as_ref(),
        client_ip: conn.client_ip(),
        fingerprint: fingerprint.as_ref(),
    };
    let Some(route) = select(listener.routes, &facts) else {
        tracing::debug!(listener = %conn.listener, client = %conn.client, "no TCP route matches");
        reject(metrics, &conn, "no_route");
        return;
    };
    let route = route.clone();
    forward(
        &conn,
        stream,
        &route,
        hello.as_ref(),
        answered_ssl_request,
        &listener,
        metrics,
    )
    .await;
}

/// The connection is to be closed; whatever made it so is already counted.
struct Close;

/// The listener's `starttls` step: whether a request to start TLS was answered here.
async fn answer_starttls(
    stream: &mut L4Stream,
    listener: &ListenerContext<'_>,
) -> Result<bool, Close> {
    let Some(StartTls::Postgres) = listener.starttls else {
        return Ok(false);
    };
    match starttls::postgres(stream, listener.deadline).await {
        Ok(starttls::Negotiated::Tls) => Ok(true),
        Ok(starttls::Negotiated::Plain { read }) => {
            stream.rewind(&read);
            Ok(false)
        }
        Err(starttls::Closed) => Err(Close),
    }
}

/// On an `https` listener with TCP routes: relays the connection if a TCP route matches its
/// ClientHello and returns `None`; otherwise puts every byte back and returns the stream for
/// the HTTP engine.
pub(crate) async fn divert(
    conn: Accepted,
    mut stream: L4Stream,
    listener: ListenerContext<'_>,
    metrics: &Metrics,
    keep_facts: bool,
) -> Option<(L4Stream, Option<clienthello::HelloFacts>)> {
    let peeked = clienthello::peek(&mut stream, listener.deadline).await;
    stream.rewind(&peeked.bytes);
    // The listener computes fingerprints: the same peek serves them.
    let facts = if keep_facts {
        clienthello::facts(&peeked.bytes)
    } else {
        None
    };
    let Ok(Detected::Hello(hello)) = peeked.result else {
        // Not TLS, or a broken ClientHello: the TLS handshake refuses and counts it.
        return Some((stream, facts));
    };
    if offers_only_acme(&hello) {
        return Some((stream, facts));
    }
    let fingerprint = route_fingerprint(listener.routes, &peeked.bytes);
    let hello_facts = facts;
    let facts = TcpFacts {
        hello: Some(&hello),
        client_ip: conn.client_ip(),
        fingerprint: fingerprint.as_ref(),
    };
    let Some(route) = select(listener.routes, &facts).cloned() else {
        return Some((stream, hello_facts));
    };
    forward(
        &conn,
        stream,
        &route,
        Some(&hello),
        false,
        &listener,
        metrics,
    )
    .await;
    None
}

/// The JA4 of the peeked ClientHello, when a route matches on `ClientFingerprint`.
fn route_fingerprint(
    routes: &[Arc<TcpRouteRuntime>],
    bytes: &[u8],
) -> Option<rdock_middleware::ClientFingerprint> {
    if !routes.iter().any(|r| r.reads_fingerprint) {
        return None;
    }
    let facts = clienthello::facts(bytes)?;
    Some(rdock_middleware::ClientFingerprint {
        ja4: Some(Arc::from(rdock_tls::fingerprint::ja4(
            &facts,
            rdock_tls::fingerprint::Transport::Tcp,
        ))),
        ja3: None,
    })
}

/// Peeks the ClientHello and puts the bytes back; `None` when the connection does not start
/// with TLS. The JA4 comes with it when a route needs it.
async fn read_hello(
    conn: &Accepted,
    stream: &mut L4Stream,
    deadline: Instant,
    metrics: &Metrics,
    routes: &[Arc<TcpRouteRuntime>],
) -> Result<
    (
        Option<ClientHello>,
        Option<rdock_middleware::ClientFingerprint>,
    ),
    Close,
> {
    let peeked = clienthello::peek(stream, deadline).await;
    stream.rewind(&peeked.bytes);
    match peeked.result {
        Ok(Detected::Hello(hello)) => Ok((Some(hello), route_fingerprint(routes, &peeked.bytes))),
        Ok(Detected::NotTls) => Ok((None, None)),
        Err(PeekError::Hello(err)) => {
            tracing::debug!(listener = %conn.listener, client = %conn.client, error = %err, "unusable ClientHello");
            reject(metrics, conn, "bad_client_hello");
            Err(Close)
        }
        Err(err) => {
            tracing::debug!(listener = %conn.listener, client = %conn.client, error = %err, "no ClientHello");
            Err(Close)
        }
    }
}

/// A TLS-ALPN-01 validation handshake (RFC 8737): it offers `acme-tls/1` and nothing else.
fn offers_only_acme(hello: &ClientHello) -> bool {
    matches!(hello.alpn.as_slice(), [only] if only.as_slice() == ACME_TLS_ALPN)
}

/// The handshake is the whole answer to a TLS-ALPN-01 validation: the certificate resolver
/// serves the validation certificate.
async fn answer_acme(stream: L4Stream, acceptor: &Acceptor, deadline: Instant) {
    let _ = tokio::time::timeout_at(deadline, acceptor.acceptor.accept(stream)).await;
}

fn reject(metrics: &Metrics, conn: &Accepted, reason: &str) {
    metrics
        .tcp_rejected
        .with_label_values(&[&*conn.listener, reason])
        .inc();
}

/// Keeps `rdock_tcp_connections` right however the relay ends.
struct Open(IntGauge);

impl Open {
    fn new(gauge: IntGauge) -> Self {
        gauge.inc();
        Self(gauge)
    }
}

impl Drop for Open {
    fn drop(&mut self) {
        self.0.dec();
    }
}

/// Applies the route's middlewares, connects to a backend and relays.
async fn forward(
    conn: &Accepted,
    stream: L4Stream,
    route: &TcpRouteRuntime,
    hello: Option<&ClientHello>,
    answered_ssl_request: bool,
    listener: &ListenerContext<'_>,
    metrics: &Metrics,
) {
    let _admitted = match admit(&route.filters, conn.client_ip()).await {
        Ok(admitted) => admitted,
        Err(reason) => {
            tracing::debug!(listener = %conn.listener, route = %route.name, client = %conn.client, reason, "TCP connection refused");
            reject(metrics, conn, reason);
            return;
        }
    };
    let _open = Open::new(
        metrics
            .tcp_connections
            .with_label_values(&[&conn.listener, &route.name]),
    );
    let counters = Counters {
        inbound: metrics.tcp_bytes.with_label_values(&[&*route.name, "in"]),
        outbound: metrics.tcp_bytes.with_label_values(&[&*route.name, "out"]),
    };
    let timeouts = route.service.timeouts;
    let limits = Limits {
        idle: timeouts.idle.as_std(),
        termination_delay: timeouts.termination_delay.as_std(),
    };
    let end = match (route.mode, listener.tls) {
        (TcpMode::Terminate, Some(acceptor)) => {
            let Some(tls) =
                terminate(conn, stream, acceptor, hello, listener.deadline, metrics).await
            else {
                return;
            };
            let session = tls.get_ref().1;
            let version = session.protocol_version().and_then(version_name);
            let outbound = Outbound {
                alpn: session.alpn_protocol(),
                terminated: Some(Terminated {
                    sni: session.server_name(),
                    version,
                    client_cert: session.peer_certificates().is_some(),
                }),
            };
            let Some(backend) = connect(conn, route, outbound, false, metrics).await else {
                return;
            };
            relay::relay(tls, backend, limits, &counters).await
        }
        // Validation refuses termination on a listener without `tls`.
        (TcpMode::Terminate, None) => return,
        (TcpMode::Relay | TcpMode::Passthrough, _) => {
            let outbound = Outbound {
                alpn: hello.and_then(|h| h.alpn.first()).map(Vec::as_slice),
                terminated: None,
            };
            let Some(backend) = connect(conn, route, outbound, answered_ssl_request, metrics).await
            else {
                return;
            };
            relay::relay(stream, backend, limits, &counters).await
        }
    };
    match end {
        End::Finished => {}
        End::Idle => {
            tracing::debug!(listener = %conn.listener, route = %route.name, client = %conn.client, "idle TCP connection closed");
        }
        End::Failed(err) => {
            tracing::debug!(listener = %conn.listener, route = %route.name, client = %conn.client, error = %err, "TCP relay ended");
        }
    }
}

/// Checks the client address against the route's middlewares; the slots of `in_flight` are
/// held until the returned value is dropped.
async fn admit(filters: &[TcpFilter], client: IpAddr) -> Result<Vec<Admitted>, &'static str> {
    let mut held = Vec::new();
    for filter in filters {
        match filter {
            TcpFilter::Allow(networks) if !networks.iter().any(|n| n.contains(&client)) => {
                return Err("denied");
            }
            TcpFilter::Deny(networks) if networks.iter().any(|n| n.contains(&client)) => {
                return Err("denied");
            }
            TcpFilter::Allow(_) | TcpFilter::Deny(_) => {}
            TcpFilter::InFlight(limiter) => match limiter.admit(&client).await {
                Ok(admitted) => held.push(admitted),
                Err(_) => return Err("in_flight"),
            },
        }
    }
    Ok(held)
}

/// The TLS version as OpenSSL and HAProxy name it in the SSL TLV's version sub-TLV.
fn version_name(version: rustls::ProtocolVersion) -> Option<&'static str> {
    match version {
        rustls::ProtocolVersion::TLSv1_3 => Some("TLSv1.3"),
        rustls::ProtocolVersion::TLSv1_2 => Some("TLSv1.2"),
        _ => None,
    }
}

/// A stream to a backend: TCP or a Unix socket.
trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

/// Terminates the client's TLS with the listener's settings. The ALPN protocols offered are
/// the client's own (without `acme-tls/1`): the backend speaks whatever the client asked for,
/// and PostgreSQL clients with `sslnegotiation=direct` require ALPN `postgresql`.
async fn terminate(
    conn: &Accepted,
    stream: L4Stream,
    acceptor: &Acceptor,
    hello: Option<&ClientHello>,
    deadline: Instant,
    metrics: &Metrics,
) -> Option<pingora::tls::ServerTlsStream<L4Stream>> {
    let base = acceptor.acceptor.config();
    let offered: Vec<Vec<u8>> = hello
        .map(|h| {
            h.alpn
                .iter()
                .filter(|p| p.as_slice() != ACME_TLS_ALPN)
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    let mut config = rustls::ServerConfig::clone(base);
    config.alpn_protocols = offered;
    let tls = pingora::tls::TlsAcceptor::from(Arc::new(config));
    match tokio::time::timeout_at(deadline, tls.accept(stream)).await {
        Ok(Ok(tls)) => Some(tls),
        Ok(Err(err)) => {
            tracing::debug!(listener = %conn.listener, client = %conn.client, error = %err, "TLS handshake failed");
            metrics
                .tls_handshake_errors
                .with_label_values(&[&conn.listener])
                .inc();
            None
        }
        Err(_) => {
            metrics
                .tls_handshake_errors
                .with_label_values(&[&conn.listener])
                .inc();
            None
        }
    }
}

/// Connects to a backend of the route's service, then sends the PROXY header and, after an
/// answered PostgreSQL `SSLRequest` that is not terminated here, the same request.
async fn connect(
    conn: &Accepted,
    route: &TcpRouteRuntime,
    outbound: Outbound<'_>,
    replay_ssl_request: bool,
    metrics: &Metrics,
) -> Option<Box<dyn Io>> {
    let service = &route.service;
    let key = RequestKey {
        client_ip: Some(conn.client_ip()),
        ..RequestKey::default()
    };
    let Some(selected) = upstream::select(&service.pool, key) else {
        tracing::warn!(listener = %conn.listener, route = %route.name, service = %service.name, "no backend available");
        reject(metrics, conn, "no_backend");
        return None;
    };
    let candidate = &selected.member.candidate;
    let timeout = service.timeouts.connect.as_std();
    let opened = tokio::time::timeout(timeout, async {
        let mut backend = open(candidate).await?;
        greet(&mut backend, conn, service, outbound, replay_ssl_request).await?;
        Ok::<_, std::io::Error>(backend)
    })
    .await;
    match opened {
        Ok(Ok(backend)) => Some(backend),
        Ok(Err(err)) => {
            tracing::warn!(listener = %conn.listener, route = %route.name, backend = %candidate, error = %err, "cannot connect to the backend");
            reject(metrics, conn, "connect_failed");
            None
        }
        Err(_) => {
            tracing::warn!(listener = %conn.listener, route = %route.name, backend = %candidate, timeout = ?timeout, "connecting to the backend timed out");
            reject(metrics, conn, "connect_failed");
            None
        }
    }
}

async fn open(candidate: &Candidate) -> std::io::Result<Box<dyn Io>> {
    Ok(match candidate {
        Candidate::Tcp { addr, .. } => {
            let tcp = tokio::net::TcpStream::connect(addr).await?;
            tcp.set_nodelay(true)?;
            Box::new(tcp)
        }
        Candidate::Unix(path) => Box::new(tokio::net::UnixStream::connect(path).await?),
    })
}

/// The first bytes to a backend: the PROXY header, then the replayed `SSLRequest`, whose
/// answer must be `S`.
async fn greet(
    backend: &mut Box<dyn Io>,
    conn: &Accepted,
    service: &TcpServiceRuntime,
    outbound: Outbound<'_>,
    replay_ssl_request: bool,
) -> std::io::Result<()> {
    if let Some(version) = service.proxy_protocol {
        let header = crate::proxy_protocol::encode(version, conn.client, conn.local, outbound)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        backend.write_all(&header).await?;
    }
    if replay_ssl_request {
        backend.write_all(&starttls::SSL_REQUEST).await?;
        let mut answer = [0u8; 1];
        backend.read_exact(&mut answer).await?;
        if answer != *b"S" {
            return Err(std::io::Error::other(
                "the backend refused the PostgreSQL SSLRequest",
            ));
        }
    }
    backend.flush().await
}
