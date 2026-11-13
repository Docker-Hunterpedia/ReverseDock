//! The QUIC endpoint of an HTTP/3 listener (ADR-0032): binds the UDP socket of the listener's
//! address, accepts connections within the limits, runs `h3` on each, and hands every request
//! stream that passes our own validation to the listener's Pingora engine as a custom session.
//!
//! **Bounds** (each one holds without configuration):
//! - connections: `max_connections` per listener and `max_connections_per_client` per client
//!   address; beyond them a new connection is refused (`CONNECTION_REFUSED`) before any
//!   handshake work;
//! - address validation: `retry` (`auto` sends Retry while 100 or more handshakes are in
//!   progress). Before an address is validated quinn sends at most three times the bytes it
//!   received (RFC 9000 §8.1; quinn passes the interop runner's amplification test, run of
//!   2026-11-12);
//! - handshake: the listener's `timeouts.request_header`;
//! - streams: `max_concurrent_streams` request streams and 16 unidirectional streams at once;
//!   the HEADERS frame must arrive within `timeouts.request_header`; its decoded size is
//!   bounded by `max_header_size` in our decoder and in h3; flow control holds a stream to
//!   1 MiB and a connection to 4 MiB of unread data;
//! - resets: more than `max(100, max_concurrent_streams)` streams reset by the client, or
//!   refused as malformed, within 10 s close the connection with `H3_EXCESSIVE_LOAD`
//!   (the HTTP/2 Rapid Reset and `MadeYouReset` pattern);
//! - request bodies: `timeouts.read` between DATA frames, and after the first `timeouts.read`
//!   an average of at least 1 KiB/s ([`super::session`]), so a trickling stream cannot hold
//!   its upstream connection;
//! - idle: `max_idle`.
//!
//! **Stopping** (a reload that removes the listener, moves it, or turns HTTP/3 off; shutdown;
//! the old process of a binary upgrade): no new connections; every connection gets GOAWAY,
//! its requests in flight may finish for the drain, at most [`DRAIN_CAP`]; then the endpoint
//! closes and releases the socket. QUIC connections do not move between processes. A side that
//! cannot bind its UDP socket (another process or a draining side still holds it) keeps trying
//! every 250 ms; HTTPS serves meanwhile and `Alt-Svc` is not sent until the endpoint serves.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use bytes::Bytes;
use h3::quic::{RecvStream as _, SendStream as _};
use pingora::apps::HttpServerApp;
use pingora::protocols::Digest;
use pingora::protocols::http::ServerSession;
use pingora::protocols::tls::SslDigest;
use rdock_model::config::{Http3Congestion, Http3Retry, ListenerHttp3};
use rdock_model::values::ListenAddress;
use tokio::sync::watch;
use tokio::task::JoinSet;

use super::request::{self, Malformed};
use super::session::H3Session;
use super::stream::{RequestIo, code};
use crate::listener::{Engine, Handshake};
use crate::proxy::Shared;

/// The longest a stopping HTTP/3 side lets requests in flight finish after GOAWAY.
pub const DRAIN_CAP: Duration = Duration::from_secs(10);
/// How often a side that cannot bind its UDP socket tries again.
const BIND_RETRY: Duration = Duration::from_millis(250);
/// Unread request data quinn lets a client send on one stream, and on one connection.
const STREAM_WINDOW: u32 = 1 << 20;
const CONNECTION_WINDOW: u32 = 4 << 20;
/// Unidirectional streams a client may have open: control, QPACK encoder and decoder, and room
/// for reserved (grease) stream types.
const UNI_STREAMS: u32 = 16;
/// The window over which client resets are counted.
const RESET_WINDOW: Duration = Duration::from_secs(10);

/// The keys an HTTP/3 listener signs with: stateless resets and address-validation tokens.
/// Kept in the data directory (`quic.key`), so the next process (a restart or a binary upgrade)
/// answers the previous one's connections with a stateless reset and accepts its Retry tokens.
#[derive(Clone)]
pub struct QuicKeys {
    /// HMAC-SHA256 key of stateless reset tokens (RFC 9000 §10.3).
    pub reset: [u8; 32],
    /// HKDF input of the keys that protect Retry tokens.
    pub token: [u8; 32],
}

impl std::fmt::Debug for QuicKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("QuicKeys(..)")
    }
}

impl QuicKeys {
    /// Keys that live as long as the process.
    #[must_use]
    pub fn random() -> Self {
        let mut reset = [0u8; 32];
        let mut token = [0u8; 32];
        reset.copy_from_slice(&crate::server::random_key());
        token.copy_from_slice(&crate::server::random_key());
        Self { reset, token }
    }

    /// The text form stored in `quic.key`: 64 hex digits of the reset key, a newline, 64 of
    /// the token key.
    #[must_use]
    pub fn to_text(&self) -> String {
        use std::fmt::Write;
        let hex = |key: &[u8; 32]| {
            key.iter().fold(String::new(), |mut out, b| {
                let _ = write!(out, "{b:02x}");
                out
            })
        };
        format!("{}\n{}\n", hex(&self.reset), hex(&self.token))
    }

    /// Reads the text form.
    ///
    /// # Errors
    ///
    /// Not two lines of 64 hex digits.
    pub fn from_text(text: &str) -> Result<Self, String> {
        let parse = |line: Option<&str>| -> Result<[u8; 32], String> {
            let line = line.ok_or("missing line")?.trim();
            if line.len() != 64 {
                return Err("a key is not 64 hex digits".into());
            }
            let mut key = [0u8; 32];
            for (i, byte) in key.iter_mut().enumerate() {
                *byte = u8::from_str_radix(&line[2 * i..2 * i + 2], 16)
                    .map_err(|_| "a key is not hex".to_owned())?;
            }
            Ok(key)
        };
        let mut lines = text.lines();
        Ok(Self {
            reset: parse(lines.next())?,
            token: parse(lines.next())?,
        })
    }
}

/// What a side is started or updated with.
#[derive(Clone)]
pub struct SideConfig {
    /// The listener's HTTP/3 settings.
    pub settings: ListenerHttp3,
    /// The listener's rustls configuration for QUIC (built by `listener::quic_tls`).
    pub tls: Arc<rustls::ServerConfig>,
    /// The listener's client timeouts.
    pub timeouts: rdock_model::config::ListenerTimeouts,
}

/// A running HTTP/3 side of an `https` listener.
pub struct Side {
    /// The address it serves (or waits to bind).
    pub address: ListenAddress,
    config: Arc<ArcSwap<SideConfig>>,
    reconfigure: watch::Sender<u64>,
    stop: watch::Sender<Option<Duration>>,
    task: tokio::task::JoinHandle<()>,
}

impl Side {
    /// Starts serving HTTP/3 for listener `name` on the UDP port of `address`.
    pub fn start(
        name: Arc<str>,
        address: ListenAddress,
        config: SideConfig,
        keys: Arc<QuicKeys>,
        engine: Engine,
        shared: Arc<Shared>,
    ) -> Self {
        let config = Arc::new(ArcSwap::from_pointee(config));
        let (reconfigure, reconfigure_rx) = watch::channel(0);
        let (stop, stop_rx) = watch::channel(None);
        let task = tokio::spawn(run(Context {
            name,
            address,
            config: config.clone(),
            keys,
            engine,
            shared,
            stop: stop_rx,
            reconfigure: reconfigure_rx,
        }));
        Self {
            address,
            config,
            reconfigure,
            stop,
            task,
        }
    }

    /// New settings or TLS for connections accepted from now on; limits apply at once.
    pub fn update(&self, config: SideConfig) {
        self.config.store(Arc::new(config));
        self.reconfigure.send_modify(|n| *n += 1);
    }

    /// Stops: GOAWAY to every connection, requests in flight may finish for `drain` (at most
    /// [`DRAIN_CAP`]), then the endpoint closes. The handle resolves when the socket is closed.
    pub fn stop(self, drain: Duration) -> tokio::task::JoinHandle<()> {
        let _ = self.stop.send(Some(drain.min(DRAIN_CAP)));
        self.task
    }
}

struct Context {
    name: Arc<str>,
    address: ListenAddress,
    config: Arc<ArcSwap<SideConfig>>,
    keys: Arc<QuicKeys>,
    engine: Engine,
    shared: Arc<Shared>,
    stop: watch::Receiver<Option<Duration>>,
    reconfigure: watch::Receiver<u64>,
}

/// Connection counts of one side, for the limits and `retry: auto`.
#[derive(Default)]
struct Counts {
    open: AtomicUsize,
    half_open: AtomicUsize,
    per_client: Mutex<HashMap<IpAddr, u32>>,
}

/// Keeps the counts right however a connection task ends.
struct Slot {
    counts: Arc<Counts>,
    client: IpAddr,
    half_open: bool,
}

impl Slot {
    fn handshake_done(&mut self) {
        if std::mem::take(&mut self.half_open) {
            self.counts.half_open.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.handshake_done();
        self.counts.open.fetch_sub(1, Ordering::Relaxed);
        let mut per_client = self
            .counts
            .per_client
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(n) = per_client.get_mut(&self.client) {
            *n -= 1;
            if *n == 0 {
                per_client.remove(&self.client);
            }
        }
    }
}

fn varint(code: u64) -> quinn::VarInt {
    quinn::VarInt::from_u64(code).unwrap_or(quinn::VarInt::from_u32(0))
}

/// The client address as one IP (an IPv4-mapped IPv6 address counts as the IPv4 one).
fn client_ip(addr: SocketAddr) -> IpAddr {
    match addr.ip() {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 @ IpAddr::V4(_) => v4,
    }
}

/// The quinn server configuration for `config`.
fn server_config(config: &SideConfig, keys: &QuicKeys) -> Result<quinn::ServerConfig, String> {
    let s = &config.settings;
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(config.tls.clone())
        .map_err(|e| e.to_string())?;
    let token_key = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, &[]).extract(&keys.token);
    let mut server = quinn::ServerConfig::new(Arc::new(crypto), Arc::new(token_key));
    let mut transport = quinn::TransportConfig::default();
    transport
        .max_concurrent_bidi_streams(quinn::VarInt::from_u32(s.max_concurrent_streams))
        .max_concurrent_uni_streams(quinn::VarInt::from_u32(UNI_STREAMS))
        .max_idle_timeout(Some(
            quinn::IdleTimeout::try_from(s.max_idle.as_std()).map_err(|e| e.to_string())?,
        ))
        .stream_receive_window(quinn::VarInt::from_u32(STREAM_WINDOW))
        .receive_window(quinn::VarInt::from_u32(CONNECTION_WINDOW))
        .datagram_receive_buffer_size(None)
        .enable_segmentation_offload(s.gso);
    match s.congestion {
        Http3Congestion::Cubic => {
            transport
                .congestion_controller_factory(Arc::new(quinn::congestion::CubicConfig::default()));
        }
        Http3Congestion::Newreno => {
            transport.congestion_controller_factory(Arc::new(
                quinn::congestion::NewRenoConfig::default(),
            ));
        }
        Http3Congestion::Bbr => {
            transport
                .congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
        }
    }
    server
        .transport_config(Arc::new(transport))
        .migration(false)
        .max_incoming(
            usize::try_from(s.max_connections)
                .unwrap_or(usize::MAX)
                .min(1 << 16),
        );
    Ok(server)
}

fn endpoint_config(keys: &QuicKeys) -> quinn::EndpointConfig {
    let reset = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &keys.reset);
    quinn::EndpointConfig::new(Arc::new(reset))
}

fn bind(address: &ListenAddress) -> std::io::Result<std::net::UdpSocket> {
    let socket = crate::listener::bind_udp(address)?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

/// The side's life: bind (retrying), serve, drain.
#[allow(clippy::too_many_lines)] // the steps of the side, in order
async fn run(mut cx: Context) {
    let metrics = cx.shared.metrics.clone();
    let mut warned = false;
    let socket = loop {
        match bind(&cx.address) {
            Ok(socket) => break socket,
            Err(err) => {
                if !warned {
                    tracing::warn!(listener = %cx.name, address = %cx.address, error = %err, "cannot bind the UDP socket for HTTP/3; HTTPS serves meanwhile, retrying every 250 ms");
                    warned = true;
                }
                tokio::select! {
                    _ = cx.stop.changed() => return,
                    () = tokio::time::sleep(BIND_RETRY) => {}
                }
            }
        }
    };
    let current = cx.config.load_full();
    let server = match server_config(&current, &cx.keys) {
        Ok(server) => server,
        Err(err) => {
            tracing::error!(listener = %cx.name, error = %err, "cannot configure HTTP/3");
            return;
        }
    };
    let endpoint = match quinn::Endpoint::new(
        endpoint_config(&cx.keys),
        Some(server),
        socket,
        Arc::new(quinn::TokioRuntime),
    ) {
        Ok(endpoint) => endpoint,
        Err(err) => {
            tracing::error!(listener = %cx.name, error = %err, "cannot start the QUIC endpoint");
            return;
        }
    };
    let local = endpoint
        .local_addr()
        .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], cx.address.port())));
    tracing::info!(listener = %cx.name, address = %local, "serving HTTP/3 (experimental)");
    advertise(
        &cx.shared,
        &cx.name,
        Some(&current.settings),
        cx.address.port(),
    );

    let counts = Arc::new(Counts::default());
    let (closing, closing_rx) = watch::channel(false);
    let mut connections = JoinSet::new();
    let drain = loop {
        tokio::select! {
            biased;
            changed = cx.stop.changed() => {
                let requested = *cx.stop.borrow();
                if changed.is_err() || requested.is_some() {
                    break requested.unwrap_or(Duration::ZERO);
                }
            }
            _ = cx.reconfigure.changed() => {
                let current = cx.config.load_full();
                match server_config(&current, &cx.keys) {
                    Ok(server) => endpoint.set_server_config(Some(server)),
                    Err(err) => tracing::error!(listener = %cx.name, error = %err, "cannot apply the new HTTP/3 settings; new connections keep the previous ones"),
                }
                advertise(&cx.shared, &cx.name, Some(&current.settings), cx.address.port());
            }
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break Duration::ZERO };
                admit(&cx, incoming, &counts, &closing_rx, local, &mut connections);
            }
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    };
    advertise(&cx.shared, &cx.name, None, 0);
    // No new connections; GOAWAY to the open ones, whose requests may finish for the drain.
    endpoint.set_server_config(None);
    let _ = closing.send(true);
    let open = connections.len();
    if open > 0 {
        tracing::info!(listener = %cx.name, open, "HTTP/3 connections draining after GOAWAY");
    }
    let drained = tokio::time::timeout(drain, async {
        while connections.join_next().await.is_some() {}
    })
    .await;
    if drained.is_err() {
        let open = connections.len();
        tracing::info!(listener = %cx.name, open, "HTTP/3 drain time over, closing {open} connections");
        connections.abort_all();
        while connections.join_next().await.is_some() {}
    }
    endpoint.close(varint(code::NO_ERROR), b"");
    let _ = tokio::time::timeout(Duration::from_secs(1), endpoint.wait_idle()).await;
    drop(endpoint);
    metrics
        .http3_connections
        .with_label_values(&[&cx.name])
        .set(0);
    tracing::info!(listener = %cx.name, "HTTP/3 stopped");
}

/// Sets (or, with `None`, removes) the `Alt-Svc` value this listener's HTTP/1 and HTTP/2
/// responses carry.
fn advertise(shared: &Shared, name: &Arc<str>, settings: Option<&ListenerHttp3>, port: u16) {
    let value = settings.filter(|s| s.advertise).and_then(|s| {
        let port = s.advertise_port.unwrap_or(port);
        let max_age = s.advertise_max_age.as_std().as_secs();
        http::HeaderValue::from_str(&format!("h3=\":{port}\"; ma={max_age}")).ok()
    });
    shared.alt_svc.rcu(|current| {
        let mut next = (**current).clone();
        match &value {
            Some(v) => {
                next.insert(name.clone(), v.clone());
            }
            None => {
                next.remove(name);
            }
        }
        next
    });
}

/// Applies the limits and the Retry policy to a new connection, and accepts it.
fn admit(
    cx: &Context,
    incoming: quinn::Incoming,
    counts: &Arc<Counts>,
    closing: &watch::Receiver<bool>,
    local: SocketAddr,
    connections: &mut JoinSet<()>,
) {
    let metrics = &cx.shared.metrics;
    let config = cx.config.load_full();
    let settings = &config.settings;
    let closed = |reason: &str| {
        metrics
            .http3_connections_closed
            .with_label_values(&[&*cx.name, reason])
            .inc();
    };
    let remote = incoming.remote_address();
    let ip = client_ip(remote);
    if counts.open.load(Ordering::Relaxed) >= settings.max_connections as usize {
        closed("limit");
        incoming.refuse();
        return;
    }
    {
        let per_client = counts
            .per_client
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if per_client.get(&ip).copied().unwrap_or(0) >= settings.max_connections_per_client {
            drop(per_client);
            closed("client_limit");
            incoming.refuse();
            return;
        }
    }
    let wants_retry = match settings.retry {
        Http3Retry::Always => true,
        Http3Retry::Never => false,
        Http3Retry::Auto => {
            counts.half_open.load(Ordering::Relaxed) >= ListenerHttp3::RETRY_THRESHOLD
        }
    };
    if wants_retry && !incoming.remote_address_validated() && incoming.may_retry() {
        if incoming.retry().is_ok() {
            metrics.http3_retries.with_label_values(&[&cx.name]).inc();
        }
        return;
    }
    let connecting = match incoming.accept() {
        Ok(connecting) => connecting,
        Err(err) => {
            tracing::debug!(listener = %cx.name, error = %err, "QUIC connection not accepted");
            closed("handshake");
            return;
        }
    };
    counts.open.fetch_add(1, Ordering::Relaxed);
    counts.half_open.fetch_add(1, Ordering::Relaxed);
    *counts
        .per_client
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .entry(ip)
        .or_insert(0) += 1;
    let slot = Slot {
        counts: counts.clone(),
        client: ip,
        half_open: true,
    };
    connections.spawn(connection(Connection {
        name: cx.name.clone(),
        config,
        engine: cx.engine.clone(),
        shared: cx.shared.clone(),
        closing: closing.clone(),
        local,
        connecting,
        slot,
    }));
}

struct Connection {
    name: Arc<str>,
    config: Arc<SideConfig>,
    engine: Engine,
    shared: Arc<Shared>,
    closing: watch::Receiver<bool>,
    local: SocketAddr,
    connecting: quinn::Connecting,
    slot: Slot,
}

/// Counts client resets and malformed requests of one connection over 10 seconds.
pub struct Resets {
    count: AtomicU32,
    since: Mutex<Instant>,
    limit: u32,
}

impl Resets {
    fn new(max_concurrent_streams: u32) -> Self {
        Self {
            count: AtomicU32::new(0),
            since: Mutex::new(Instant::now()),
            limit: max_concurrent_streams.max(100),
        }
    }

    /// Counts one; whether the connection is now over the limit.
    pub fn add(&self) -> bool {
        let mut since = self
            .since
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if since.elapsed() > RESET_WINDOW {
            *since = Instant::now();
            self.count.store(0, Ordering::Relaxed);
        }
        drop(since);
        self.count.fetch_add(1, Ordering::Relaxed) + 1 > self.limit
    }
}

/// Why a connection ended, for `rdock_http3_connections_closed_total`.
fn close_reason(err: &h3::error::ConnectionError) -> &'static str {
    let text = err.to_string();
    if text.contains("timed out") || text.contains("Timeout") || text.contains("idle") {
        "idle"
    } else if text.contains("closed by peer")
        || text.contains("ApplicationClose")
        || text.contains("H3_NO_ERROR")
    {
        "client"
    } else {
        "protocol"
    }
}

#[allow(clippy::too_many_lines)] // the steps of a connection, in order
async fn connection(c: Connection) {
    let Connection {
        name,
        config,
        engine,
        shared,
        mut closing,
        local,
        connecting,
        mut slot,
    } = c;
    let metrics = shared.metrics.clone();
    let closed = |reason: &str| {
        metrics
            .http3_connections_closed
            .with_label_values(&[&*name, reason])
            .inc();
    };
    let deadline = config.timeouts.request_header.as_std();
    let conn = match tokio::time::timeout(deadline, connecting).await {
        Ok(Ok(conn)) => conn,
        Ok(Err(err)) => {
            tracing::debug!(listener = %name, error = %err, "QUIC handshake failed");
            closed("handshake");
            return;
        }
        Err(_) => {
            closed("handshake");
            return;
        }
    };
    slot.handshake_done();
    metrics
        .http3_connections_total
        .with_label_values(&[&name])
        .inc();
    let gauge = metrics.http3_connections.with_label_values(&[&name]);
    gauge.inc();
    let _gauge = scopeguard(move || gauge.dec());

    let facts = Arc::new(handshake_facts(&conn));
    let digest = digest(facts.client_cert.as_deref());
    let remote = conn.remote_address();
    let server = conn
        .local_ip()
        .map_or(local, |ip| SocketAddr::new(ip, local.port()));
    let max_header = config.settings.max_header_size.as_u64();
    let mut h3conn = match h3::server::builder()
        .max_field_section_size(max_header)
        .send_grease(true)
        .build::<_, Bytes>(h3_quinn::Connection::new(conn.clone()))
        .await
    {
        Ok(h3conn) => h3conn,
        Err(err) => {
            tracing::debug!(listener = %name, error = %err, "HTTP/3 connection setup failed");
            closed("protocol");
            return;
        }
    };
    let (closed_tx, closed_rx) = watch::channel(false);
    let resets = Arc::new(Resets::new(config.settings.max_concurrent_streams));
    let mut streams = JoinSet::new();
    let mut shutting_down = *closing.borrow();
    if shutting_down {
        let _ = h3conn.shutdown(0).await;
    }
    let reason = loop {
        // After GOAWAY, the connection ends with its last request (h3 0.0.8's `accept` returns
        // `None` only after the client's GOAWAY, not ours).
        if shutting_down && streams.is_empty() {
            break "drained";
        }
        tokio::select! {
            biased;
            changed = closing.changed(), if !shutting_down => {
                if changed.is_err() || *closing.borrow() {
                    shutting_down = true;
                    // GOAWAY: no new requests; those in flight finish.
                    let _ = h3conn.shutdown(0).await;
                }
            }
            accepted = h3conn.accept() => match accepted {
                Ok(Some(resolver)) => {
                    streams.spawn(request(Request {
                        name: name.clone(),
                        resolver,
                        conn: conn.clone(),
                        engine: engine.load_full(),
                        shared: shared.clone(),
                        facts: facts.clone(),
                        digest: digest.clone(),
                        peers: (remote, server),
                        closed: closed_rx.clone(),
                        max_header,
                        header_timeout: deadline,
                        resets: resets.clone(),
                    }));
                }
                Ok(None) => break if shutting_down { "drained" } else { "client" },
                Err(err) => {
                    tracing::debug!(listener = %name, error = %err, "HTTP/3 connection ended");
                    break close_reason(&err);
                }
            },
            Some(_) = streams.join_next(), if !streams.is_empty() => {
                if resets.count.load(Ordering::Relaxed) > resets.limit {
                    conn.close(varint(code::EXCESSIVE_LOAD), b"too many reset streams");
                    break "reset_flood";
                }
            }
        }
    };
    closed(reason);
    // Requests still running (the client went away, or GOAWAY with requests in flight) end
    // with the connection; the side bounds how long it waits for this task.
    while streams.join_next().await.is_some() {}
    conn.close(varint(code::NO_ERROR), b"");
    let _ = closed_tx.send(true);
}

/// Runs `f` on drop.
fn scopeguard(f: impl FnOnce()) -> impl Drop {
    struct Guard<F: FnOnce()>(Option<F>);
    impl<F: FnOnce()> Drop for Guard<F> {
        fn drop(&mut self) {
            if let Some(f) = self.0.take() {
                f();
            }
        }
    }
    Guard(Some(f))
}

/// SNI and the verified client certificate of a QUIC connection.
fn handshake_facts(conn: &quinn::Connection) -> Handshake {
    let sni = conn
        .handshake_data()
        .and_then(|d| d.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
        .and_then(|d| d.server_name);
    let client_cert = conn
        .peer_identity()
        .and_then(|i| {
            i.downcast::<Vec<rustls_pki_types::CertificateDer<'static>>>()
                .ok()
        })
        .and_then(|chain| chain.first().and_then(|c| crate::listener::identity(c)))
        .map(Arc::new);
    Handshake {
        sni,
        client_cert,
        fingerprint: std::sync::OnceLock::new(),
    }
}

/// The digest the pipeline reads: TLS 1.3 (QUIC uses nothing else, RFC 9001 §4.2). quinn does
/// not expose the negotiated cipher suite, so it reads `unknown`.
fn digest(client: Option<&rdock_middleware::ClientIdentity>) -> Digest {
    let ssl = SslDigest::new(
        "unknown",
        "TLSv1.3",
        client.and_then(|c| c.organizations.first().cloned()),
        client.map(|c| c.serial.clone()),
        client
            .map(|c| c.sha256.as_bytes().to_vec())
            .unwrap_or_default(),
    );
    Digest {
        ssl_digest: Some(Arc::new(ssl)),
        timing_digest: Vec::new(),
        proxy_digest: None,
        socket_digest: None,
    }
}

type Resolver = h3::server::RequestResolver<h3_quinn::Connection, Bytes>;

struct Request {
    name: Arc<str>,
    resolver: Resolver,
    conn: quinn::Connection,
    engine: Arc<pingora::proxy::HttpProxy<crate::proxy::RdockProxy>>,
    shared: Arc<Shared>,
    facts: Arc<Handshake>,
    digest: Digest,
    peers: (SocketAddr, SocketAddr),
    closed: watch::Receiver<bool>,
    max_header: u64,
    header_timeout: Duration,
    resets: Arc<Resets>,
}

/// One request stream: read and check its HEADERS frame, then run the pipeline.
async fn request(r: Request) {
    let Request {
        name,
        mut resolver,
        conn,
        engine,
        shared,
        facts,
        digest,
        peers,
        closed,
        max_header,
        header_timeout,
        resets,
    } = r;
    let malformed = |reason: &str| {
        shared
            .metrics
            .http3_malformed_requests
            .with_label_values(&[&*name, reason])
            .inc();
    };
    let frame = tokio::time::timeout(
        header_timeout,
        std::future::poll_fn(|cx| resolver.frame_stream.poll_next(cx)),
    )
    .await;
    let block = match frame {
        Ok(Ok(Some(h3::proto::frame::Frame::Headers(block)))) => block,
        Ok(other) => {
            // No HEADERS frame first, the stream ended or was reset, or a frame error: h3
            // answers as RFC 9114 requires (a stream or connection error).
            if !matches!(other, Ok(None)) {
                resets.add();
            }
            let _ = resolver.accept_with_frame(other);
            return;
        }
        Err(_) => {
            resets.add();
            resolver.frame_stream.reset(code::REQUEST_CANCELLED);
            resolver
                .frame_stream
                .stream
                .stop_sending(code::REQUEST_CANCELLED);
            return;
        }
    };
    let mapped = match request::map(&block, max_header) {
        Ok(mapped) => mapped,
        Err(err) => {
            malformed(err.label());
            resets.add();
            tracing::debug!(listener = %name, error = %err, "malformed HTTP/3 request");
            refuse(resolver, block, &err, &conn).await;
            return;
        }
    };
    // h3 builds its request stream from the same frame; it decodes it once more, within the
    // same limit.
    let resolved =
        match resolver.accept_with_frame(Ok(Some(h3::proto::frame::Frame::Headers(block)))) {
            Ok(resolved) => resolved.resolve().await,
            Err(err) => Err(err),
        };
    let stream = match resolved {
        Ok((_, stream)) => stream,
        Err(err) => {
            malformed("h3");
            resets.add();
            tracing::debug!(listener = %name, error = %err, "h3 refused an HTTP/3 request");
            return;
        }
    };
    let mut header = mapped.header;
    header.extensions_mut().insert(facts);
    let io: Box<dyn RequestIo> = Box::new(stream);
    let session = H3Session::new(io, header, mapped.content_length, digest, peers, closed)
        .with_resets(resets);
    let (_shutdown_tx, shutdown) = watch::channel(false);
    let _ = engine
        .process_new_http(ServerSession::new_custom(Box::new(session)), &shutdown)
        .await;
}

/// Answers a malformed request: 431 for a header section over the limit (RFC 9114 §4.2.2), a
/// connection error for a QPACK error (RFC 9204 §2.2), a stream reset with `H3_MESSAGE_ERROR`
/// otherwise (RFC 9114 §4.1.2). Nothing reaches the pipeline.
async fn refuse(mut resolver: Resolver, block: Bytes, err: &Malformed, conn: &quinn::Connection) {
    match err {
        Malformed::TooLarge { .. } => {
            // h3 decodes with the same limit and answers 431 itself; if it disagreed and
            // accepted the section, answer 431 here.
            if let Ok(resolved) =
                resolver.accept_with_frame(Ok(Some(h3::proto::frame::Frame::Headers(block))))
                && let Ok((_, mut stream)) = resolved.resolve().await
            {
                let mut response = http::Response::new(());
                *response.status_mut() = http::StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE;
                let _ = stream.send_response(response).await;
                let _ = stream.finish().await;
            }
        }
        _ if err.is_connection_error() => {
            conn.close(
                varint(code::QPACK_DECOMPRESSION_FAILED),
                b"cannot decode the header section",
            );
        }
        _ => {
            resolver.frame_stream.reset(code::MESSAGE_ERROR);
            resolver
                .frame_stream
                .stream
                .stop_sending(code::MESSAGE_ERROR);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_round_trip_through_their_text_form() {
        let keys = QuicKeys::random();
        let back = QuicKeys::from_text(&keys.to_text()).unwrap();
        assert_eq!(back.reset, keys.reset);
        assert_eq!(back.token, keys.token);
        assert!(QuicKeys::from_text("abc\n").is_err());
        assert!(QuicKeys::from_text(&"zz".repeat(64)).is_err());
        assert_ne!(keys.reset, keys.token);
    }

    #[test]
    fn resets_are_counted_over_a_window() {
        let resets = Resets::new(10);
        assert_eq!(resets.limit, 100);
        for _ in 0..100 {
            assert!(!resets.add());
        }
        assert!(resets.add());
        let wide = Resets::new(500);
        assert_eq!(wide.limit, 500);
    }

    #[test]
    fn mapped_ipv4_counts_as_ipv4() {
        let mapped: SocketAddr = "[::ffff:10.0.0.1]:443".parse().unwrap();
        assert_eq!(client_ip(mapped), "10.0.0.1".parse::<IpAddr>().unwrap());
        let v6: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        assert_eq!(client_ip(v6), "2001:db8::1".parse::<IpAddr>().unwrap());
    }
}
