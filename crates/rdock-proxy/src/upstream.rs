//! Backends: name resolution with background refresh, backend selection and Pingora peers.
//!
//! Pingora's `HttpPeer::new` resolves names synchronously and panics on failure, so every peer
//! is built from an address resolved here. Names are resolved when a configuration is applied
//! and refreshed every few seconds, so container restarts with new IPs are picked up; a failed
//! lookup keeps the previous addresses.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::time::Duration;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use pingora::http::RequestHeader;
use pingora::upstreams::peer::HttpPeer;
use rdock_balancer::Choice;
use rdock_middleware::{FetchError, Fetched, HttpClient, ServiceClient};
use rdock_model::route::RouteTimeouts;
use rdock_model::service::Scheme;

use crate::runtime::{Candidate, HashOn, Member, ServiceRuntime, StickyRuntime};

/// How often DNS names of backends are resolved again.
pub const DNS_REFRESH: Duration = Duration::from_secs(10);
/// Time allowed for one lookup.
pub const DNS_TIMEOUT: Duration = Duration::from_secs(2);
/// Concurrent HTTP/2 streams per upstream connection.
const H2_STREAMS: usize = 100;

type Cell = ArcSwap<Vec<SocketAddr>>;

/// Resolved addresses of backend host names, shared by every configuration generation.
#[derive(Debug, Default)]
pub struct Dns {
    cells: Mutex<HashMap<(String, u16), Weak<Cell>>>,
}

impl Dns {
    /// The address cell for `host:port`, shared with earlier generations while they are alive.
    pub fn cell(&self, host: &str, port: u16) -> Arc<Cell> {
        let mut cells = self.cells.lock().unwrap_or_else(PoisonError::into_inner);
        let key = (host.to_owned(), port);
        if let Some(cell) = cells.get(&key).and_then(Weak::upgrade) {
            return cell;
        }
        let cell = Arc::new(ArcSwap::from_pointee(Vec::new()));
        cells.insert(key, Arc::downgrade(&cell));
        cell
    }

    fn live(&self, only_empty: bool) -> Vec<((String, u16), Arc<Cell>)> {
        let mut cells = self.cells.lock().unwrap_or_else(PoisonError::into_inner);
        cells.retain(|_, cell| cell.strong_count() > 0);
        cells
            .iter()
            .filter_map(|(key, cell)| cell.upgrade().map(|c| (key.clone(), c)))
            .filter(|(_, c)| !only_empty || c.load().is_empty())
            .collect()
    }

    /// Resolves every name in use. Failed lookups keep the previous addresses.
    pub async fn refresh(&self) {
        resolve_all(self.live(false)).await;
    }

    /// Resolves names that have no address yet (new backends).
    pub async fn resolve_new(&self) {
        resolve_all(self.live(true)).await;
    }
}

async fn resolve_all(cells: Vec<((String, u16), Arc<Cell>)>) {
    let mut tasks = tokio::task::JoinSet::new();
    for ((host, port), cell) in cells {
        tasks.spawn(async move {
            let lookup =
                tokio::time::timeout(DNS_TIMEOUT, tokio::net::lookup_host((host.as_str(), port)));
            match lookup.await {
                Ok(Ok(addrs)) => {
                    let mut addrs: Vec<SocketAddr> = addrs.collect();
                    addrs.sort();
                    addrs.dedup();
                    if !addrs.is_empty() && **cell.load() != addrs {
                        tracing::debug!(%host, port, ?addrs, "backend addresses changed");
                        cell.store(Arc::new(addrs));
                    }
                }
                Ok(Err(err)) => tracing::warn!(%host, port, error = %err, "cannot resolve backend"),
                Err(_) => tracing::warn!(%host, port, "backend lookup timed out"),
            }
        });
    }
    while tasks.join_next().await.is_some() {}
}

/// The backend chosen for a request.
#[derive(Debug)]
pub struct Selected {
    /// The backend.
    pub member: Arc<Member>,
    /// `Set-Cookie` value to send, when the sticky cookie is missing, stale or names a backend
    /// that is gone.
    pub set_cookie: Option<String>,
}

/// What a request contributes to backend selection.
#[derive(Debug, Clone, Copy, Default)]
pub struct RequestKey<'a> {
    /// The request.
    pub request: Option<&'a RequestHeader>,
    /// The client address.
    pub client_ip: Option<IpAddr>,
}

/// Picks a backend of `service` for a request.
#[must_use]
pub fn select(service: &ServiceRuntime, key: RequestKey<'_>) -> Option<Selected> {
    let members = service.members();
    if let (Some(sticky), Some(request)) = (&service.sticky, key.request)
        && let Some(found) = sticky_member(sticky, &members, request)
    {
        return Some(found);
    }
    let choices: Vec<Choice<'_>> = members
        .iter()
        .map(|m| Choice {
            id: &m.id,
            weight: m.weight,
            in_flight: m.state.in_flight(),
        })
        .collect();
    let hash = hash_input(&service.hash_on, key);
    let index = service.balancer.pick(&choices, hash.as_deref())?;
    let member = members.get(index)?.clone();
    let set_cookie = service.sticky.as_ref().and_then(|sticky| {
        member
            .sticky
            .as_ref()
            .map(|token| format!("{}={token}{}", sticky.name, sticky.attributes))
    });
    Some(Selected { member, set_cookie })
}

/// The backend a valid sticky cookie names, if it is still in the pool.
fn sticky_member(
    sticky: &StickyRuntime,
    members: &[Arc<Member>],
    request: &RequestHeader,
) -> Option<Selected> {
    let value = cookie(request, &sticky.name)?;
    let live = || members.iter().filter(|m| m.weight > 0);
    if let Some(member) = live().find(|m| m.sticky.as_deref() == Some(value)) {
        return Some(Selected {
            member: member.clone(),
            set_cookie: None,
        });
    }
    // Cookies from before a key rotation name the right backend but get a fresh value.
    let member = live().find(|m| sticky.keys.matches(value, &m.id).is_some())?;
    Some(Selected {
        member: member.clone(),
        set_cookie: member
            .sticky
            .as_ref()
            .map(|token| format!("{}={token}{}", sticky.name, sticky.attributes)),
    })
}

fn hash_input(on: &HashOn, key: RequestKey<'_>) -> Option<Vec<u8>> {
    match on {
        HashOn::Nothing => None,
        HashOn::ClientIp => key.client_ip.map(|ip| ip.to_string().into_bytes()),
        HashOn::Header(name) => key
            .request?
            .headers
            .get(name)
            .map(|v| v.as_bytes().to_vec()),
        HashOn::Cookie(name) => cookie(key.request?, name).map(|v| v.as_bytes().to_vec()),
    }
}

/// The value of cookie `name` in the request's `Cookie` headers.
fn cookie<'a>(request: &'a RequestHeader, name: &str) -> Option<&'a str> {
    request
        .headers
        .get_all(http::header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(n, _)| *n == name)
        .map(|(_, v)| v.trim_matches('"'))
}

/// The Pingora peer for one attempt.
pub fn peer(
    service: &ServiceRuntime,
    candidate: &Candidate,
    route: &RouteTimeouts,
) -> pingora::Result<HttpPeer> {
    let tls = service.scheme == Scheme::Https;
    let mut peer = match candidate {
        Candidate::Tcp { host, addr } => {
            let sni = service.tls.server_name.clone().unwrap_or_else(|| {
                host.trim_start_matches('[')
                    .trim_end_matches(']')
                    .to_owned()
            });
            HttpPeer::new(*addr, tls, sni)
        }
        Candidate::Unix(path) => {
            let sni = service
                .tls
                .server_name
                .clone()
                .unwrap_or_else(|| "localhost".to_owned());
            HttpPeer::new_uds(&path.to_string_lossy(), tls, sni)?
        }
    };
    let timeouts = &service.timeouts;
    let options = &mut peer.options;
    options.connection_timeout = Some(route.connect.unwrap_or(timeouts.connect).as_std());
    options.read_timeout = Some(route.read.unwrap_or(timeouts.read).as_std());
    options.write_timeout = Some(route.write.unwrap_or(timeouts.write).as_std());
    options.idle_timeout = Some(timeouts.idle.as_std());
    match service.scheme {
        Scheme::Http => {}
        Scheme::Https => {
            options.set_http_version(2, 1);
            options.max_h2_streams = H2_STREAMS;
        }
        Scheme::H2c => {
            options.set_http_version(2, 2);
            options.max_h2_streams = H2_STREAMS;
        }
    }
    options.verify_cert = service.tls.verify;
    options.verify_hostname = service.tls.verify;
    options.ca.clone_from(&service.tls.ca);
    peer.group_key = service.tls.group_key;
    Ok(peer)
}

/// Lets middlewares fetch pages from a service (custom error pages).
#[derive(Debug)]
pub struct ServiceFetcher {
    /// The service.
    pub service: Arc<ServiceRuntime>,
    /// Client used for the request.
    pub client: Arc<HttpClient>,
}

#[async_trait]
impl ServiceClient for ServiceFetcher {
    async fn send(&self, req: RequestHeader) -> Result<Fetched, FetchError> {
        let selected = select(&self.service, RequestKey::default()).ok_or_else(|| {
            FetchError::Connect(format!("service `{}` has no backend", self.service.name))
        })?;
        let _in_flight = selected.member.state.begin();
        let peer = peer(
            &self.service,
            &selected.member.candidate,
            &RouteTimeouts::default(),
        )
        .map_err(|e| FetchError::Connect(e.to_string()))?;
        self.client
            .send(&peer, req, self.service.timeouts.read.as_std(), 1024 * 1024)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cells_are_shared_and_resolved() {
        let dns = Dns::default();
        let a = dns.cell("localhost", 8080);
        let b = dns.cell("localhost", 8080);
        assert!(Arc::ptr_eq(&a, &b));
        dns.resolve_new().await;
        assert!(a.load().iter().all(|addr| addr.port() == 8080));
        assert!(!a.load().is_empty(), "localhost resolves");
        drop((a, b));
        assert!(dns.live(false).is_empty(), "dropped cells are forgotten");
    }
}
