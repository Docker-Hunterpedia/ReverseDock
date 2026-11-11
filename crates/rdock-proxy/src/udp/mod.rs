//! UDP routes (M-L4-04, ADR-0030): what a `udp` listener does with a datagram.
//!
//! A **session** is one client address (IP and port) on one listener. It owns a socket
//! connected to one backend, chosen by the service's balancer when the session starts and
//! kept for its whole life, and one task that relays the backend's datagrams back to the
//! client through the listener's socket. The kernel delivers only that backend's datagrams to
//! the connected socket, and an ICMP "port unreachable" comes back as a refused send or
//! receive, which ends the session and feeds passive health.
//!
//! Per datagram, the listener's receive loop looks the client up; a datagram of a live session
//! goes into the session's bounded queue (full: dropped and counted). A datagram from an
//! unknown client opens a session only after, in order: a route matches (`ClientIP` rules), the
//! route's `ip_allow`/`ip_deny` admit the client, the listener's session caps have room, and
//! a backend is available. Anything else is dropped and counted in `rdock_udp_dropped_total`,
//! never answered: rdock sends a client nothing but the backend's replies on its own session.
//!
//! A session ends after `timeouts.idle` without a datagram in either direction, after
//! `responses` replies, when its backend refuses, or when its listener closes. Replies leave
//! from the listener's socket; on a wildcard bind (`:53`) of a host with several addresses the
//! kernel picks their source address by route, so such listeners should name their address.

mod compile;

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use bytes::Bytes;
use rdock_balancer::{EjectPolicy, InFlight};
use rdock_model::config::UdpSessions;
use rdock_model::values::IpNetwork;
use rdock_observability::{IntCounter, Metrics};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;
use tokio::time::Instant;

pub(crate) use compile::compile_udp;

use crate::proxy::Shared;
use crate::runtime::{Candidate, Member, ServiceRuntime};
use crate::tcp::rule::{TcpFacts, TcpRule};
use crate::upstream::{self, RequestKey};

/// Receive buffer of a listener and of each session: holds any UDP datagram (the largest
/// payload is 65,527 bytes over IPv6, 65,507 over IPv4).
pub const DATAGRAM_BUFFER: usize = 64 * 1024;

/// Datagrams from the client waiting for a session's upstream socket; more are dropped.
pub const SESSION_QUEUE: usize = 64;

/// A UDP route, compiled.
#[derive(Debug)]
pub struct UdpRouteRuntime {
    /// Route name.
    pub name: Arc<str>,
    /// Effective priority (explicit, or the rule length).
    pub priority: i64,
    /// Length of the rule, the tie-breaker after the priority.
    pub length: usize,
    /// Compiled `ClientIP` rule; `None` takes every datagram.
    pub rule: Option<TcpRule>,
    /// Target service.
    pub service: Arc<UdpServiceRuntime>,
    /// `ip_allow` and `ip_deny`, in order.
    pub filters: Arc<[UdpFilter]>,
}

impl UdpRouteRuntime {
    /// Whether a datagram from `client` matches the route's rule.
    #[must_use]
    pub fn matches(&self, client: IpAddr) -> bool {
        self.rule.as_ref().is_none_or(|rule| {
            rule.matches(&TcpFacts {
                hello: None,
                client_ip: client,
            })
        })
    }

    /// Whether the route's middlewares admit `client`.
    #[must_use]
    pub fn admits(&self, client: IpAddr) -> bool {
        self.filters.iter().all(|filter| match filter {
            UdpFilter::Allow(networks) => networks.iter().any(|n| n.contains(&client)),
            UdpFilter::Deny(networks) => !networks.iter().any(|n| n.contains(&client)),
        })
    }
}

/// A UDP service, compiled.
#[derive(Debug)]
pub struct UdpServiceRuntime {
    /// Service name.
    pub name: Arc<str>,
    /// Backends and their selection, shared with the HTTP services' machinery.
    pub pool: Arc<ServiceRuntime>,
    /// A session without datagrams for this long ends.
    pub idle: Duration,
    /// A session ends after this many replies.
    pub responses: Option<u32>,
    /// A session is detached from its client address after this many datagrams from it.
    pub requests: Option<u32>,
    /// Passive health: ejection policy and the largest ejected share, in percent.
    pub passive: Option<(EjectPolicy, u32)>,
}

/// A middleware of a UDP route, applied to the client address before a session is created.
#[derive(Debug)]
pub enum UdpFilter {
    /// `ip_allow`: only these networks.
    Allow(Vec<IpNetwork>),
    /// `ip_deny`: not these networks.
    Deny(Vec<IpNetwork>),
}

/// The first route, in evaluation order, that takes a datagram from `client`.
#[must_use]
pub fn select(routes: &[Arc<UdpRouteRuntime>], client: IpAddr) -> Option<&Arc<UdpRouteRuntime>> {
    routes.iter().find(|r| r.matches(client))
}

/// One live session in the listener's table.
struct Entry {
    id: u64,
    queue: mpsc::Sender<Bytes>,
    /// Datagrams from the client queued so far.
    forwarded: u32,
    /// The service's `requests`: the entry is removed (the session detached) once
    /// `forwarded` reaches it.
    requests: Option<u32>,
}

/// The sessions of one listener.
#[derive(Default)]
struct Table {
    /// Sessions that still take the client's datagrams.
    by_client: HashMap<SocketAddr, Entry>,
    /// Open sessions per client IP, detached ones included.
    per_ip: HashMap<IpAddr, u32>,
    /// Open sessions, detached ones included.
    total: usize,
    next_id: u64,
}

type SharedTable = Arc<Mutex<Table>>;

fn lock(table: &SharedTable) -> std::sync::MutexGuard<'_, Table> {
    table.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What a listener's receive loop needs.
struct Listener {
    name: Arc<str>,
    socket: Arc<UdpSocket>,
    shared: Arc<Shared>,
    table: SharedTable,
    closed: watch::Receiver<bool>,
}

impl Listener {
    fn drop_datagram(&self, reason: &str) {
        drop_datagram(&self.shared.metrics, &self.name, reason);
    }
}

fn drop_datagram(metrics: &Metrics, listener: &str, reason: &str) {
    metrics
        .udp_dropped
        .with_label_values(&[listener, reason])
        .inc();
}

/// Serves a `udp` listener until `stop` asks for it to close; then lets the open sessions run
/// for up to the drain time (new clients are refused) and closes the rest.
pub(crate) async fn serve(
    name: Arc<str>,
    socket: UdpSocket,
    mut stop: watch::Receiver<Option<Duration>>,
    shared: Arc<Shared>,
) {
    let (close, closed) = watch::channel(false);
    let listener = Listener {
        name,
        socket: Arc::new(socket),
        shared,
        table: SharedTable::default(),
        closed,
    };
    let mut sessions = JoinSet::new();
    let mut buf = vec![0u8; DATAGRAM_BUFFER];
    let mut deadline: Option<Instant> = None;
    loop {
        while sessions.try_join_next().is_some() {}
        if deadline.is_some() && sessions.is_empty() {
            break;
        }
        let drain_over = async {
            match deadline {
                Some(at) => tokio::time::sleep_until(at).await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            changed = stop.changed(), if deadline.is_none() => {
                let requested = *stop.borrow();
                if changed.is_err() || requested.is_some() {
                    deadline = Some(Instant::now() + requested.unwrap_or_default());
                }
            }
            () = drain_over => {
                let open = sessions.len();
                if open > 0 {
                    tracing::warn!(listener = %listener.name, aborted = open, "drain time over, closing {open} UDP sessions");
                }
                break;
            }
            Some(_) = sessions.join_next(), if !sessions.is_empty() => {}
            received = listener.socket.recv_from(&mut buf) => match received {
                Ok((n, client)) => {
                    let datagram = buf.get(..n).unwrap_or_default();
                    if let Some(session) = listener.datagram(datagram, client, deadline.is_some()) {
                        sessions.spawn(session);
                    }
                }
                Err(err) => {
                    // An ICMP error for an earlier reply, or out of memory: never fatal.
                    tracing::debug!(listener = %listener.name, error = %err, "UDP receive failed");
                    if !is_transient(&err) {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                }
            },
        }
    }
    let _ = close.send(true);
    while sessions.join_next().await.is_some() {}
}

/// Errors a UDP socket reports for an earlier datagram (an ICMP answer), not about itself.
fn is_transient(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::NetworkUnreachable
    )
}

/// `EMSGSIZE`: the datagram is larger than the destination's address family allows.
fn is_oversize(err: &io::Error) -> bool {
    #[cfg(target_os = "linux")]
    const EMSGSIZE: i32 = 90;
    #[cfg(windows)]
    const EMSGSIZE: i32 = 10040;
    #[cfg(not(any(target_os = "linux", windows)))]
    const EMSGSIZE: i32 = 40;
    err.raw_os_error() == Some(EMSGSIZE)
}

impl Listener {
    /// Handles one datagram from `client`; returns the task of a new session.
    fn datagram(
        &self,
        datagram: &[u8],
        client: SocketAddr,
        closing: bool,
    ) -> Option<impl std::future::Future<Output = ()> + Send + 'static> {
        {
            let mut table = lock(&self.table);
            if let Some(entry) = table.by_client.get_mut(&client) {
                match entry.queue.try_send(Bytes::copy_from_slice(datagram)) {
                    Ok(()) => {
                        entry.forwarded = entry.forwarded.saturating_add(1);
                        if entry.requests.is_some_and(|limit| entry.forwarded >= limit) {
                            table.by_client.remove(&client);
                        }
                        return None;
                    }
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        drop(table);
                        self.drop_datagram("queue_full");
                        return None;
                    }
                    // The session is ending; this datagram opens the next one.
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        table.by_client.remove(&client);
                    }
                }
            }
        }
        if closing {
            self.drop_datagram("closing");
            return None;
        }
        self.open(datagram, client)
    }

    /// Opens a session for a datagram from an unknown client, or drops it.
    fn open(
        &self,
        datagram: &[u8],
        client: SocketAddr,
    ) -> Option<impl std::future::Future<Output = ()> + Send + 'static> {
        let ip = crate::forwarded::canonical(client.ip());
        let runtime = self.shared.runtime.load();
        let Some(listener) = runtime.listeners.get(&*self.name) else {
            self.drop_datagram("no_route");
            return None;
        };
        let Some(route) = select(&listener.udp_routes, ip).cloned() else {
            tracing::trace!(listener = %self.name, %client, "no UDP route matches");
            self.drop_datagram("no_route");
            return None;
        };
        if !route.admits(ip) {
            self.drop_datagram("denied");
            return None;
        }
        let caps = listener.udp_sessions;
        drop(runtime);
        if let Some(reason) = self.full(&caps, ip) {
            self.drop_datagram(reason);
            return None;
        }
        let service = route.service.clone();
        let key = RequestKey {
            client_ip: Some(ip),
            ..RequestKey::default()
        };
        let Some(selected) = upstream::select(&service.pool, key) else {
            tracing::debug!(listener = %self.name, route = %route.name, service = %service.name, "no UDP backend available");
            self.drop_datagram("no_backend");
            return None;
        };
        let member = selected.member;
        let upstream = match open_upstream(&member.candidate) {
            Ok(socket) => socket,
            Err(err) => {
                tracing::warn!(listener = %self.name, route = %route.name, backend = %member.candidate, error = %err, "cannot open a UDP socket to the backend");
                self.drop_datagram("socket_error");
                return None;
            }
        };
        let (queue, queued) = mpsc::channel(SESSION_QUEUE);
        // The channel is new and empty.
        let _ = queue.try_send(Bytes::copy_from_slice(datagram));
        let id = {
            let mut table = lock(&self.table);
            let id = table.next_id;
            table.next_id = table.next_id.wrapping_add(1);
            // With `requests: 1` the session is detached at once: it never takes a second
            // datagram, and its channel closes once the first one is sent.
            if service.requests.is_none_or(|limit| limit > 1) {
                table.by_client.insert(
                    client,
                    Entry {
                        id,
                        queue,
                        forwarded: 1,
                        requests: service.requests,
                    },
                );
            }
            *table.per_ip.entry(ip).or_default() += 1;
            table.total += 1;
            id
        };
        let metrics = &self.shared.metrics;
        let gauge = metrics
            .udp_sessions
            .with_label_values(&[&*self.name, &*route.name]);
        gauge.inc();
        let session = Session {
            guard: Guard {
                table: self.table.clone(),
                id,
                client,
                ip,
                gauge,
            },
            listener: self.name.clone(),
            route,
            in_flight: member.state.begin(),
            member,
            upstream,
            socket: self.socket.clone(),
            metrics: metrics.clone(),
            closed: self.closed.clone(),
        };
        Some(session.run(queued))
    }

    /// Which cap a new session from `ip` would exceed, if any.
    fn full(&self, caps: &UdpSessions, ip: IpAddr) -> Option<&'static str> {
        let table = lock(&self.table);
        if caps
            .max
            .get()
            .is_some_and(|max| table.total >= usize::try_from(max).unwrap_or(usize::MAX))
        {
            return Some("session_limit");
        }
        if caps
            .max_per_client
            .get()
            .is_some_and(|max| table.per_ip.get(&ip).copied().unwrap_or(0) >= max)
        {
            return Some("client_limit");
        }
        None
    }
}

/// A socket connected to the backend, on an ephemeral port of the backend's address family.
fn open_upstream(candidate: &Candidate) -> io::Result<UdpSocket> {
    let Candidate::Tcp { addr, .. } = candidate else {
        return Err(io::Error::other("UDP backends need an IP address and port"));
    };
    let local = match addr {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let socket = std::net::UdpSocket::bind(local)?;
    socket.connect(addr)?;
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket)
}

/// Removes a session from its listener's table and keeps the gauge right, however the
/// session's task ends (also when it is aborted).
struct Guard {
    table: SharedTable,
    id: u64,
    client: SocketAddr,
    ip: IpAddr,
    gauge: rdock_observability::IntGauge,
}

impl Drop for Guard {
    fn drop(&mut self) {
        self.gauge.dec();
        let mut table = lock(&self.table);
        if table
            .by_client
            .get(&self.client)
            .is_some_and(|e| e.id == self.id)
        {
            table.by_client.remove(&self.client);
        }
        if let Some(count) = table.per_ip.get_mut(&self.ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                table.per_ip.remove(&self.ip);
            }
        }
        table.total = table.total.saturating_sub(1);
    }
}

/// How a session ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum End {
    Idle,
    Responses,
    BackendUnreachable,
    Error,
    Closed,
}

impl End {
    fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Responses => "responses",
            Self::BackendUnreachable => "backend_unreachable",
            Self::Error => "error",
            Self::Closed => "closed",
        }
    }
}

/// Datagram and byte counters of one direction of a route.
struct Direction {
    datagrams: IntCounter,
    bytes: IntCounter,
    count: u64,
    total: u64,
}

impl Direction {
    fn new(metrics: &Metrics, route: &str, direction: &str) -> Self {
        Self {
            datagrams: metrics.udp_datagrams.with_label_values(&[route, direction]),
            bytes: metrics.udp_bytes.with_label_values(&[route, direction]),
            count: 0,
            total: 0,
        }
    }

    fn add(&mut self, len: usize) {
        let len = u64::try_from(len).unwrap_or(u64::MAX);
        self.datagrams.inc();
        self.bytes.inc_by(len);
        self.count += 1;
        self.total = self.total.saturating_add(len);
    }
}

/// One session: relays queued client datagrams to the backend and the backend's datagrams
/// back to the client.
struct Session {
    guard: Guard,
    listener: Arc<str>,
    route: Arc<UdpRouteRuntime>,
    member: Arc<Member>,
    in_flight: InFlight,
    upstream: UdpSocket,
    socket: Arc<UdpSocket>,
    metrics: Metrics,
    closed: watch::Receiver<bool>,
}

impl Session {
    async fn run(mut self, mut queued: mpsc::Receiver<Bytes>) {
        let started = Instant::now();
        let route = self.route.name.clone();
        let mut inbound = Direction::new(&self.metrics, &route, "in");
        let mut outbound = Direction::new(&self.metrics, &route, "out");
        let end = self.relay(&mut queued, &mut inbound, &mut outbound).await;
        if end == End::BackendUnreachable {
            drop_datagram(&self.metrics, &self.listener, "backend_unreachable");
            if let Some((policy, max_percent)) = self.route.service.passive {
                let _ = self.route.service.pool.pool.failure(
                    &self.member.state,
                    policy,
                    max_percent,
                    std::time::Instant::now(),
                );
            }
        }
        self.metrics
            .udp_session_ends
            .with_label_values(&[&*route, end.as_str()])
            .inc();
        tracing::debug!(
            listener = %self.listener,
            route = %route,
            service = %self.route.service.name,
            client = %self.guard.client,
            backend = %self.member.candidate,
            datagrams_in = inbound.count,
            bytes_in = inbound.total,
            datagrams_out = outbound.count,
            bytes_out = outbound.total,
            duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            end = end.as_str(),
            "UDP session ended"
        );
        drop(self.in_flight);
    }

    async fn relay(
        &mut self,
        queued: &mut mpsc::Receiver<Bytes>,
        inbound: &mut Direction,
        outbound: &mut Direction,
    ) -> End {
        let service = self.route.service.clone();
        let mut buf = vec![0u8; DATAGRAM_BUFFER];
        let mut last = Instant::now();
        let mut replies: u32 = 0;
        // Closed once the session is detached (`requests`) or its listener's table dropped it.
        let mut queue_open = true;
        loop {
            if *self.closed.borrow() {
                return End::Closed;
            }
            tokio::select! {
                _ = self.closed.changed() => return End::Closed,
                datagram = queued.recv(), if queue_open => {
                    let Some(datagram) = datagram else {
                        queue_open = false;
                        continue;
                    };
                    match self.upstream.send(&datagram).await {
                        Ok(_) => {
                            inbound.add(datagram.len());
                            last = Instant::now();
                        }
                        Err(err) if err.kind() == io::ErrorKind::ConnectionRefused => {
                            return End::BackendUnreachable;
                        }
                        Err(err) if is_oversize(&err) => {
                            drop_datagram(&self.metrics, &self.listener, "oversize");
                        }
                        Err(err) => {
                            tracing::debug!(listener = %self.listener, route = %self.route.name, error = %err, "UDP send to the backend failed");
                            drop_datagram(&self.metrics, &self.listener, "socket_error");
                        }
                    }
                }
                received = self.upstream.recv(&mut buf) => match received {
                    Ok(n) => {
                        last = Instant::now();
                        if replies == 0 {
                            self.member.state.success(std::time::Instant::now());
                        }
                        replies = replies.saturating_add(1);
                        let reply = buf.get(..n).unwrap_or_default();
                        match self.socket.try_send_to(reply, self.guard.client) {
                            Ok(_) => outbound.add(n),
                            Err(err) if is_oversize(&err) => {
                                drop_datagram(&self.metrics, &self.listener, "oversize");
                            }
                            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                                drop_datagram(&self.metrics, &self.listener, "queue_full");
                            }
                            Err(err) => {
                                tracing::debug!(listener = %self.listener, client = %self.guard.client, error = %err, "UDP reply failed");
                                drop_datagram(&self.metrics, &self.listener, "socket_error");
                            }
                        }
                        if service.responses.is_some_and(|limit| replies >= limit) {
                            return End::Responses;
                        }
                    }
                    Err(err) if err.kind() == io::ErrorKind::ConnectionRefused => {
                        return End::BackendUnreachable;
                    }
                    Err(err) => {
                        tracing::debug!(listener = %self.listener, route = %self.route.name, error = %err, "UDP receive from the backend failed");
                        return End::Error;
                    }
                },
                () = tokio::time::sleep_until(last + service.idle) => return End::Idle,
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn route(name: &str, rule: Option<&str>, filters: Vec<UdpFilter>) -> Arc<UdpRouteRuntime> {
        let pool = ServiceRuntime {
            name: Arc::from("s"),
            scheme: rdock_model::service::Scheme::default(),
            backends: Vec::new(),
            balancer: rdock_balancer::Balancer::Random,
            hash_on: crate::runtime::HashOn::Nothing,
            sticky: None,
            pool: Arc::default(),
            live: Arc::default(),
            health: crate::runtime::HealthRuntime::default(),
            split: Vec::new(),
            split_balancer: rdock_balancer::RoundRobin::default(),
            respond: None,
            retries: None,
            max_requests: None,
            max_per_backend: None,
            members: arc_swap::ArcSwapOption::empty(),
            timeouts: rdock_model::service::Timeouts::default(),
            tls: crate::runtime::UpstreamTls::default(),
            pass_host_header: false,
        };
        Arc::new(UdpRouteRuntime {
            name: Arc::from(name),
            priority: 0,
            length: 0,
            rule: rule.map(|r| TcpRule::compile(&rdock_rules::parse(r).unwrap()).unwrap()),
            service: Arc::new(UdpServiceRuntime {
                name: Arc::from("s"),
                pool: Arc::new(pool),
                idle: Duration::from_secs(60),
                responses: None,
                requests: None,
                passive: None,
            }),
            filters: filters.into(),
        })
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn routes_match_by_client_ip_and_a_route_without_rule_takes_everything() {
        let routes = [
            route(
                "lan",
                Some("ClientIP(`10.0.0.0/8`) && !ClientIP(`10.9.0.0/16`)"),
                Vec::new(),
            ),
            route("any", None, Vec::new()),
        ];
        let name = |client: &str| select(&routes, ip(client)).map(|r| r.name.to_string());
        assert_eq!(name("10.1.2.3").as_deref(), Some("lan"));
        assert_eq!(name("10.9.2.3").as_deref(), Some("any"));
        assert_eq!(name("192.0.2.1").as_deref(), Some("any"));
        assert_eq!(select(&routes[..1], ip("192.0.2.1")).map(|r| &r.name), None);
    }

    #[test]
    fn ip_filters_apply_in_order() {
        let net = |s: &str| s.parse::<IpNetwork>().unwrap();
        let r = route(
            "r",
            None,
            vec![
                UdpFilter::Allow(vec![net("10.0.0.0/8")]),
                UdpFilter::Deny(vec![net("10.0.0.0/24")]),
            ],
        );
        assert!(r.admits(ip("10.1.0.1")));
        assert!(!r.admits(ip("10.0.0.1")));
        assert!(!r.admits(ip("192.0.2.1")));
    }

    #[test]
    fn a_datagram_too_large_for_ipv4_is_recognised_as_oversize() {
        let target = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let err = sender
            .send_to(&vec![0u8; 65_520], target.local_addr().unwrap())
            .unwrap_err();
        assert!(is_oversize(&err), "{err:?}");
        assert!(!is_oversize(&io::Error::from(
            io::ErrorKind::ConnectionRefused
        )));
        // The buffer holds the largest datagram IPv4 allows.
        sender
            .send_to(&vec![1u8; 65_507], target.local_addr().unwrap())
            .unwrap();
        let mut buf = vec![0u8; DATAGRAM_BUFFER];
        assert_eq!(target.recv(&mut buf).unwrap(), 65_507);
    }
}
