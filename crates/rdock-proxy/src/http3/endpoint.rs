//! The QUIC endpoint of an HTTP/3 listener (ADR-0032): binds the UDP socket of the listener's
//! address, accepts connections within the limits, runs `h3` on each, and hands every request
//! stream that passes our own validation to the listener's Pingora engine as a custom session.
//!
//! **Bounds** (each one holds without configuration):
//! - connections: `max_connections` per listener and `max_connections_per_client` per client (an
//!   IPv4 address, or an IPv6 prefix of `client_ipv6_prefix` bits). A connection counts against
//!   its client only once its address is validated (a Retry token, or the completed handshake),
//!   so spoofed Initial packets cannot fill a client's allowance; a validated client over a
//!   limit is refused (`CONNECTION_REFUSED`, or `H3_EXCESSIVE_LOAD` once the handshake is done);
//! - address validation: `retry` (`auto` sends Retry while 100 or more handshakes are in
//!   progress). Whatever the setting, an unvalidated client is sent Retry, not refused, when
//!   the listener is full, when its client already holds `max_connections_per_client`
//!   connections or handshakes, and once half-open connections reach half of `max_connections`.
//!   Before an address is validated quinn sends at most three times the bytes it received (RFC
//!   9000 §8.1; quinn passes the interop runner's amplification test, run of 2026-11-12);
//! - handshake: the listener's `timeouts.request_header`;
//! - streams: `max_concurrent_streams` request streams and 16 unidirectional streams at once;
//!   the HEADERS frame must arrive within `timeouts.request_header`; its decoded size is
//!   bounded by `max_header_size` in our decoder and in h3;
//! - frames ([`super::frames`], [`super::quic`]): no frame other than DATA may declare more than
//!   `max_header_size` (HEADERS) or 16 KiB (everything else, and every frame on the control
//!   stream); the incomplete ones of a connection share a budget of `receive_window`, and one
//!   that has started must be complete within `timeouts.request_header`;
//! - memory: flow control holds a stream to `stream_receive_window` and a connection to
//!   `receive_window` of unread data, and quinn buffers at most `send_window` of response data
//!   per connection; the worst case is `max_connections × (2 × receive_window + send_window)`;
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

use super::quic::{self, Guarding};
use super::request::{self, Malformed};
use super::session::H3Session;
use super::stream::{RequestIo, code};
use crate::listener::{Engine, Handshake};
use crate::proxy::Shared;

/// The longest a stopping HTTP/3 side lets requests in flight finish after GOAWAY.
pub const DRAIN_CAP: Duration = Duration::from_secs(10);
/// How often a side that cannot bind its UDP socket tries again.
const BIND_RETRY: Duration = Duration::from_millis(250);
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
            let line = line.ok_or("missing line")?.trim().as_bytes();
            if line.len() != 64 {
                return Err("a key is not 64 hex digits".into());
            }
            let digit = |c: u8| -> Result<u8, String> {
                char::from(c)
                    .to_digit(16)
                    .and_then(|d| u8::try_from(d).ok())
                    .ok_or_else(|| "a key is not hex".to_owned())
            };
            let mut key = [0u8; 32];
            let (pairs, _) = line.as_chunks::<2>();
            for (byte, [high, low]) in key.iter_mut().zip(pairs) {
                *byte = (digit(*high)? << 4) | digit(*low)?;
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

/// Connections of one client: those whose address is validated, and handshakes from an
/// address not validated yet (which may be spoofed).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct ClientCount {
    validated: u32,
    pending: u32,
}

/// Connection counts of one side, for the limits and the Retry policy.
#[derive(Default)]
struct Counts {
    open: AtomicUsize,
    half_open: AtomicUsize,
    per_client: Mutex<HashMap<IpAddr, ClientCount>>,
}

impl Counts {
    fn clients(&self) -> std::sync::MutexGuard<'_, HashMap<IpAddr, ClientCount>> {
        self.per_client
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// How a connection counts against its client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Counted {
    /// A handshake from an address not validated yet.
    Pending,
    /// A validated address.
    Validated,
    /// Not (any more).
    No,
}

/// Keeps the counts right however a connection task ends.
struct Slot {
    counts: Arc<Counts>,
    client: IpAddr,
    half_open: bool,
    counted: Counted,
}

impl Slot {
    /// The handshake completed, which validates the address (RFC 9000 §8.1): the connection now
    /// counts against its client, unless the client is at `limit` (then `false`).
    fn handshake_done(&mut self, limit: u32) -> bool {
        if std::mem::take(&mut self.half_open) {
            self.counts.half_open.fetch_sub(1, Ordering::Relaxed);
        }
        if self.counted != Counted::Pending {
            return true;
        }
        let mut clients = self.counts.clients();
        let count = clients.entry(self.client).or_default();
        count.pending = count.pending.saturating_sub(1);
        if count.validated >= limit {
            self.counted = Counted::No;
            if *count == ClientCount::default() {
                clients.remove(&self.client);
            }
            return false;
        }
        count.validated += 1;
        self.counted = Counted::Validated;
        true
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        if std::mem::take(&mut self.half_open) {
            self.counts.half_open.fetch_sub(1, Ordering::Relaxed);
        }
        self.counts.open.fetch_sub(1, Ordering::Relaxed);
        let mut clients = self.counts.clients();
        if let Some(count) = clients.get_mut(&self.client) {
            match self.counted {
                Counted::Pending => count.pending = count.pending.saturating_sub(1),
                Counted::Validated => count.validated = count.validated.saturating_sub(1),
                Counted::No => {}
            }
            if *count == ClientCount::default() {
                clients.remove(&self.client);
            }
        }
    }
}

/// What a new connection gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Admission {
    Accept,
    Retry,
    Refuse(&'static str),
}

/// What [`admission`] decides on: the side's counts and the client's.
#[derive(Debug, Default, Clone, Copy)]
struct Seen {
    open: usize,
    half_open: usize,
    client: ClientCount,
}

/// The limits and the Retry policy for a connection from a client with `seen` counts, whose
/// address is `validated` (it presented a Retry or `NEW_TOKEN` token) and which `may_retry` (it
/// was not sent Retry already).
fn admission(s: &ListenerHttp3, seen: Seen, validated: bool, may_retry: bool) -> Admission {
    let full = seen.open >= usize::try_from(s.max_connections).unwrap_or(usize::MAX);
    let client_full = seen.client.validated >= s.max_connections_per_client;
    // Handshakes from a client's address that is not validated: spoofed packets can pile them
    // up, so they lead to Retry, never to a refusal.
    let piled_up = !validated && seen.client.pending >= s.max_connections_per_client;
    let threshold = match s.retry {
        Http3Retry::Always => 0,
        Http3Retry::Auto => ListenerHttp3::RETRY_THRESHOLD,
        // `never` drops the proactive threshold only: unvalidated handshakes may still not
        // take more than half of the listener.
        Http3Retry::Never => (usize::try_from(s.max_connections).unwrap_or(usize::MAX) / 2)
            .max(ListenerHttp3::RETRY_THRESHOLD),
    };
    let wants_retry = seen.half_open >= threshold;
    if !validated && may_retry && (full || client_full || piled_up || wants_retry) {
        return Admission::Retry;
    }
    if full {
        Admission::Refuse("limit")
    } else if client_full || piled_up {
        Admission::Refuse("client_limit")
    } else {
        Admission::Accept
    }
}

fn varint(code: u64) -> quinn::VarInt {
    quinn::VarInt::from_u64(code).unwrap_or(quinn::VarInt::from_u32(0))
}

/// The client a connection counts against: its IPv4 address (an IPv4-mapped IPv6 address
/// counts as the IPv4 one), or its IPv6 address cut to `prefix` bits (one subscriber's /64 by
/// default, RFC 6177).
fn client_key(addr: SocketAddr, prefix: u8) -> IpAddr {
    match addr.ip() {
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                IpAddr::V4(v4)
            } else {
                let bits = u32::from(prefix.min(128));
                let mask = u128::MAX.checked_shl(128 - bits).unwrap_or(0);
                IpAddr::V6(std::net::Ipv6Addr::from(u128::from(v6) & mask))
            }
        }
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
        .stream_receive_window(
            quinn::VarInt::from_u64(s.stream_receive_window.as_u64()).map_err(|e| e.to_string())?,
        )
        .receive_window(
            quinn::VarInt::from_u64(s.receive_window.as_u64()).map_err(|e| e.to_string())?,
        )
        // quinn's default is 10 MB, chosen by the client's `max_data` otherwise: rdock bounds
        // what a client that stops acknowledging can make it buffer (review fix M3).
        .send_window(s.send_window.as_u64())
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

/// Length of the connection IDs rdock issues (quinn's default length).
const CID_LEN: usize = 8;

/// Random connection IDs that any process of this data directory treats alike. quinn 0.11's
/// default generator signs its IDs with a key drawn per endpoint, so a new process (a restart or
/// a binary upgrade) would drop the previous one's packets as "invalid CID" instead of answering
/// them with the stateless reset its shared reset key allows (RFC 9000 §10.3). With random IDs,
/// a packet for an unknown connection is answered with a reset (quinn sends at most one per
/// 20 ms, each smaller than the packet that caused it).
struct RandomCids;

impl quinn::ConnectionIdGenerator for RandomCids {
    fn generate_cid(&mut self) -> quinn::ConnectionId {
        use ring::rand::SecureRandom as _;
        let mut bytes = [0u8; CID_LEN];
        if ring::rand::SystemRandom::new().fill(&mut bytes).is_err() {
            bytes.fill_with(|| fastrand::u8(..));
        }
        quinn::ConnectionId::new(&bytes)
    }

    fn cid_len(&self) -> usize {
        CID_LEN
    }

    fn cid_lifetime(&self) -> Option<Duration> {
        None
    }
}

fn endpoint_config(keys: &QuicKeys) -> quinn::EndpointConfig {
    let reset = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &keys.reset);
    let mut config = quinn::EndpointConfig::new(Arc::new(reset));
    config.cid_generator(|| Box::new(RandomCids));
    config
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
    let ip = client_key(remote, settings.client_ipv6_prefix);
    let validated = incoming.remote_address_validated();
    let seen = Seen {
        open: counts.open.load(Ordering::Relaxed),
        half_open: counts.half_open.load(Ordering::Relaxed),
        client: counts.clients().get(&ip).copied().unwrap_or_default(),
    };
    match admission(settings, seen, validated, incoming.may_retry()) {
        Admission::Accept => {}
        Admission::Retry => {
            if incoming.retry().is_ok() {
                metrics.http3_retries.with_label_values(&[&cx.name]).inc();
            }
            return;
        }
        Admission::Refuse(reason) => {
            closed(reason);
            incoming.refuse();
            return;
        }
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
    let counted = {
        let mut clients = counts.clients();
        let count = clients.entry(ip).or_default();
        if validated {
            count.validated += 1;
            Counted::Validated
        } else {
            count.pending += 1;
            Counted::Pending
        }
    };
    let slot = Slot {
        counts: counts.clone(),
        client: ip,
        half_open: true,
        counted,
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

/// The GOAWAY identifier that accepts every request up to `last` (the last request stream
/// accepted, if any): RFC 9114 §5.2 rejects the requests whose stream id is the identifier or
/// greater, so it must be past `last`. h3 0.0.8's `shutdown(n)` sends `last + 4n` (stream ids
/// of client requests step by 4), or 0 before any request; `shutdown(1)` sends this value.
fn goaway_id(last: Option<u64>) -> u64 {
    last.map_or(0, |id| id.saturating_add(4))
}

/// The u64 form of an h3 stream id.
fn stream_number(id: h3::quic::StreamId) -> u64 {
    h3::proto::varint::VarInt::from(id).into_inner()
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
    if !slot.handshake_done(config.settings.max_connections_per_client) {
        // The address is validated now, and its client is at its limit.
        conn.close(varint(code::EXCESSIVE_LOAD), b"too many connections");
        closed("client_limit");
        return;
    }
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
    let guarding = Arc::new(Guarding::new(
        max_header,
        config.settings.receive_window.as_u64(),
        deadline,
        config.settings.max_concurrent_streams,
    ));
    let mut h3conn = match h3::server::builder()
        .max_field_section_size(max_header)
        .send_grease(true)
        .build::<_, Bytes>(quic::Conn::new(conn.clone(), guarding.clone()))
        .await
    {
        Ok(h3conn) => h3conn,
        Err(err) => {
            tracing::debug!(listener = %name, error = %err, "HTTP/3 connection setup failed");
            closed(if guarding.closed_for.load(Ordering::Relaxed) == 0 {
                "protocol"
            } else {
                "frame_limit"
            });
            return;
        }
    };
    let (closed_tx, closed_rx) = watch::channel(false);
    let resets = Arc::new(Resets::new(config.settings.max_concurrent_streams));
    let mut streams = JoinSet::new();
    // The last request stream accepted, and the GOAWAY identifier once sent.
    let mut last: Option<u64> = None;
    let mut announced: Option<u64> = None;
    if *closing.borrow() {
        let _ = h3conn.shutdown(1).await;
        announced = Some(goaway_id(last));
    }
    let reason = loop {
        // After GOAWAY, the connection ends with its last request (h3 0.0.8's `accept` returns
        // `None` only after the client's GOAWAY, not ours).
        if announced.is_some() && streams.is_empty() {
            break "drained";
        }
        tokio::select! {
            biased;
            changed = closing.changed(), if announced.is_none() => {
                if changed.is_err() || *closing.borrow() {
                    // GOAWAY: no new requests; every request accepted so far finishes.
                    let _ = h3conn.shutdown(1).await;
                    announced = Some(goaway_id(last));
                }
            }
            accepted = h3conn.accept() => match accepted {
                Ok(Some(mut resolver)) => {
                    let id = stream_number(resolver.frame_stream.stream.recv_id());
                    if announced.is_some_and(|goaway| id >= goaway) {
                        // At or past the GOAWAY identifier: the client was told this request
                        // is not processed, so it is not (RFC 9114 §5.2).
                        resolver.frame_stream.stream.stop_sending(code::REQUEST_REJECTED);
                        resolver.frame_stream.reset(code::REQUEST_REJECTED);
                        drop(guarding.take_stopped(id));
                        continue;
                    }
                    last = Some(last.map_or(id, |l| l.max(id)));
                    let (stopped, delivered) = guarding.take_stopped(id).unzip();
                    let handled = request(Request {
                        name: name.clone(),
                        resolver,
                        conn: conn.clone(),
                        engine: engine.load_full(),
                        shared: shared.clone(),
                        facts: facts.clone(),
                        digest: digest.clone(),
                        peers: (remote, server),
                        closed: closed_rx.clone(),
                        stopped,
                        max_header,
                        header_timeout: deadline,
                        resets: resets.clone(),
                    });
                    // A request counts as in flight until its response is delivered: the
                    // session ends when the last bytes and the FIN are queued, but closing the
                    // connection then would discard what the client has not acknowledged yet
                    // (quinn's `Connection::close` abandons unsent and unacknowledged stream
                    // data), and a drain closes the connection when no request is in flight.
                    streams.spawn(async move {
                        handled.await;
                        if let Some(delivered) = delivered {
                            let _ = delivered.await;
                        }
                    });
                }
                Ok(None) => break if announced.is_some() { "drained" } else { "client" },
                Err(err) => {
                    tracing::debug!(listener = %name, error = %err, "HTTP/3 connection ended");
                    break if guarding.closed_for.load(Ordering::Relaxed) == 0 {
                        close_reason(&err)
                    } else {
                        "frame_limit"
                    };
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
    if reason != "drained" {
        // The connection is gone (or going): sessions waiting on their upstream end now.
        let _ = closed_tx.send(true);
    }
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

type Resolver = h3::server::RequestResolver<quic::Conn, Bytes>;

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
    stopped: Option<quic::Stopped>,
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
        stopped,
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
    let bodiless = BODILESS.contains(&header.method) && mapped.content_length.is_none();
    let io: Box<dyn RequestIo> = Box::new(stream);
    let mut session = H3Session::new(io, header, mapped.content_length, digest, peers, closed)
        .with_resets(resets)
        .with_stopped(stopped);
    if bodiless {
        // A request of a method without a body usually ends with its HEADERS frame, but the
        // FIN may come in the next packet: wait for the stream's next event (bounded by the
        // header timeout, the time the request head may take) so the upstream request is not
        // sent with an empty chunked body (review fix L4).
        session.settle_body(header_timeout).await;
    }
    let (_shutdown_tx, shutdown) = watch::channel(false);
    let _ = engine
        .process_new_http(ServerSession::new_custom(Box::new(session)), &shutdown)
        .await;
}

/// Methods whose requests have no body by convention (RFC 9110 §9.3): a request of one of them
/// without `content-length` waits for its end before it is forwarded.
const BODILESS: [http::Method; 5] = [
    http::Method::GET,
    http::Method::HEAD,
    http::Method::OPTIONS,
    http::Method::DELETE,
    http::Method::TRACE,
];

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
    fn mapped_ipv4_counts_as_ipv4_and_ipv6_counts_by_prefix() {
        let mapped: SocketAddr = "[::ffff:10.0.0.1]:443".parse().unwrap();
        assert_eq!(
            client_key(mapped, 64),
            "10.0.0.1".parse::<IpAddr>().unwrap()
        );
        let v4: SocketAddr = "10.0.0.2:443".parse().unwrap();
        assert_eq!(client_key(v4, 64), "10.0.0.2".parse::<IpAddr>().unwrap());
        // One /64: the same client, whatever the interface identifier.
        let a: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let b: SocketAddr = "[2001:db8::ffff:2]:443".parse().unwrap();
        let other: SocketAddr = "[2001:db8:0:1::1]:443".parse().unwrap();
        assert_eq!(client_key(a, 64), client_key(b, 64));
        assert_eq!(client_key(a, 64), "2001:db8::".parse::<IpAddr>().unwrap());
        assert_ne!(client_key(a, 64), client_key(other, 64));
        // A /48 groups both; /128 counts each address.
        assert_eq!(client_key(a, 48), client_key(other, 48));
        assert_ne!(client_key(a, 128), client_key(b, 128));
        assert_eq!(client_key(a, 128), "2001:db8::1".parse::<IpAddr>().unwrap());
    }

    fn settings(retry: Http3Retry, max: u32, per_client: u32) -> ListenerHttp3 {
        ListenerHttp3 {
            retry,
            max_connections: max,
            max_connections_per_client: per_client,
            ..ListenerHttp3::default()
        }
    }

    fn seen(open: usize, half_open: usize, validated: u32, pending: u32) -> Seen {
        Seen {
            open,
            half_open,
            client: ClientCount { validated, pending },
        }
    }

    #[test]
    fn unvalidated_handshakes_never_lock_a_client_out() {
        let s = settings(Http3Retry::Auto, 1000, 1);
        // The first connection of a client is accepted.
        assert_eq!(
            admission(&s, seen(0, 0, 0, 0), false, true),
            Admission::Accept
        );
        // A handshake from its address is in progress (perhaps spoofed): the next attempt is
        // asked to prove its address, not refused.
        assert_eq!(
            admission(&s, seen(1, 1, 0, 1), false, true),
            Admission::Retry
        );
        // Back with a Retry token: validated, and nothing validated counts yet: accepted.
        assert_eq!(
            admission(&s, seen(1, 1, 0, 1), true, false),
            Admission::Accept
        );
        // A validated connection holds the client's allowance: a validated attempt is refused,
        // an unvalidated one is sent Retry first.
        assert_eq!(
            admission(&s, seen(1, 0, 1, 0), true, false),
            Admission::Refuse("client_limit")
        );
        assert_eq!(
            admission(&s, seen(1, 0, 1, 0), false, true),
            Admission::Retry
        );
    }

    #[test]
    fn a_full_listener_retries_unvalidated_clients_and_refuses_validated_ones() {
        for retry in [Http3Retry::Auto, Http3Retry::Never, Http3Retry::Always] {
            let s = settings(retry, 10, 5);
            assert_eq!(
                admission(&s, seen(10, 0, 0, 0), false, true),
                Admission::Retry,
                "{retry:?}"
            );
            assert_eq!(
                admission(&s, seen(10, 0, 0, 0), true, false),
                Admission::Refuse("limit"),
                "{retry:?}"
            );
        }
    }

    #[test]
    fn retry_never_still_bounds_unvalidated_handshakes() {
        let s = settings(Http3Retry::Never, 1000, 100);
        assert_eq!(
            admission(&s, seen(400, 499, 0, 0), false, true),
            Admission::Accept
        );
        assert_eq!(
            admission(&s, seen(500, 500, 0, 0), false, true),
            Admission::Retry,
            "half of max_connections half-open"
        );
        let auto = settings(Http3Retry::Auto, 1000, 100);
        assert_eq!(
            admission(&auto, seen(100, 100, 0, 0), false, true),
            Admission::Retry
        );
        assert_eq!(
            admission(&auto, seen(99, 99, 0, 0), false, true),
            Admission::Accept
        );
        let always = settings(Http3Retry::Always, 1000, 100);
        assert_eq!(
            admission(&always, seen(0, 0, 0, 0), false, true),
            Admission::Retry
        );
        assert_eq!(
            admission(&always, seen(0, 0, 0, 0), true, false),
            Admission::Accept
        );
    }

    #[test]
    fn a_connection_counts_against_its_client_once_validated() {
        let counts = Arc::new(Counts::default());
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        counts.open.fetch_add(2, Ordering::Relaxed);
        counts.half_open.fetch_add(2, Ordering::Relaxed);
        counts.clients().insert(
            ip,
            ClientCount {
                validated: 0,
                pending: 2,
            },
        );
        let slot = |counted| Slot {
            counts: counts.clone(),
            client: ip,
            half_open: true,
            counted,
        };
        let (mut a, mut b) = (slot(Counted::Pending), slot(Counted::Pending));
        assert!(a.handshake_done(1));
        assert_eq!(
            counts.clients()[&ip],
            ClientCount {
                validated: 1,
                pending: 1
            }
        );
        // The second handshake completes while the client is at its limit of 1.
        assert!(!b.handshake_done(1));
        assert_eq!(
            counts.clients()[&ip],
            ClientCount {
                validated: 1,
                pending: 0
            }
        );
        assert_eq!(counts.half_open.load(Ordering::Relaxed), 0);
        drop(b);
        drop(a);
        assert!(counts.clients().is_empty());
        assert_eq!(counts.open.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn goaway_accepts_every_request_up_to_the_last() {
        assert_eq!(goaway_id(None), 0);
        assert_eq!(goaway_id(Some(0)), 4);
        assert_eq!(goaway_id(Some(8)), 12);
    }

    #[test]
    fn a_key_file_with_other_text_is_refused_without_a_panic() {
        // 64 bytes that are not 64 ASCII characters: "é" is two bytes.
        let line = format!("{}é{}", "a".repeat(31), "b".repeat(31));
        assert_eq!(line.len(), 64);
        let text = format!("{line}\n{}\n", "c".repeat(64));
        assert!(QuicKeys::from_text(&text).is_err());
        assert!(QuicKeys::from_text(&format!("{}\n{}\n", "0".repeat(64), "G".repeat(64))).is_err());
    }
}
