//! Backends: name resolution with background refresh, backend selection and Pingora peers.
//!
//! Pingora's `HttpPeer::new` resolves names synchronously and panics on failure, so every peer
//! is built from an address resolved here. Names are resolved when a configuration is applied
//! and refreshed every few seconds, so container restarts with new IPs are picked up; a failed
//! lookup keeps the previous addresses.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use pingora::http::RequestHeader;
use pingora::upstreams::peer::HttpPeer;
use rdock_balancer::{Availability, Choice, SlowStart};
use rdock_middleware::{FetchError, Fetched, HttpClient, ServiceClient};
use rdock_model::route::RouteTimeouts;
use rdock_model::service::{RetryOn, Scheme};

use crate::runtime::{Candidate, Failover, HashOn, Member, ServiceRuntime, StickyRuntime};

pub use crate::dns::{Dns, SrvTarget};

/// Concurrent HTTP/2 streams per upstream connection.
const H2_STREAMS: usize = 100;

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
    /// Backends this request already tried; others are preferred.
    pub tried: &'a [String],
}

/// The service that serves a request to `service`: itself, or for a `split` service a
/// target chosen by weight (smooth round-robin), followed through nested splits.
#[must_use]
pub fn resolve(service: &Arc<ServiceRuntime>) -> Arc<ServiceRuntime> {
    let mut current = service.clone();
    while !current.split.is_empty() {
        let choices: Vec<Choice<'_>> = current
            .split
            .iter()
            .map(|(target, weight)| Choice {
                id: &target.name,
                weight: *weight,
                in_flight: 0,
                latency: None,
            })
            .collect();
        let Some(index) = current.split_balancer.pick(&choices) else {
            break;
        };
        let next = current.split[index].0.clone();
        current = next;
    }
    current
}

/// Picks a backend of `service` for a request.
///
/// Backends that are unhealthy, ejected, paused, drained or at `max_connections_per_backend`
/// are left out. Of the rest, the priority tier in use is taken (`failover: strict`: the first
/// tier with an available backend; `spill`: a tier drawn by the tiers' health, Envoy's
/// priority levels), then backends this request has not tried yet, then backends in the
/// preferred zone when one of them is left (`locality: prefer`). With `when_all_down:
/// fail_open`, an empty result falls back to every backend of the first tier (ADR-0022).
/// A sticky cookie naming one of those wins over the policy.
#[must_use]
pub fn select(service: &ServiceRuntime, key: RequestKey<'_>) -> Option<Selected> {
    let members = service.members();
    let now = Instant::now();
    let draw =
        matches!(service.selection.failover, Failover::Spill(_)).then(|| fastrand::f64() * 100.0);
    let mut pool = eligible(service, &members, now, draw);
    if draw.is_some() && pool.iter().all(|m| key.tried.contains(&m.id)) {
        // The drawn tier was tried already: any tier that gets traffic will do.
        pool = eligible(service, &members, now, None);
    }
    if pool.iter().any(|m| !key.tried.contains(&m.id)) {
        pool.retain(|m| !key.tried.contains(&m.id));
    }
    if service.selection.zone.is_some() && pool.iter().any(|m| m.local) {
        pool.retain(|m| m.local);
    }
    if let (Some(sticky), Some(request)) = (&service.sticky, key.request)
        && let Some(found) = sticky_member(sticky, &pool, request)
    {
        claim_trial(&found.member, now);
        return Some(found);
    }
    let slow = service.health.slow_start.as_ref();
    let peak = service.selection.peak.is_some();
    let choices: Vec<Choice<'_>> = pool
        .iter()
        .map(|m| Choice {
            id: &m.id,
            weight: weight(m, slow, now),
            in_flight: m.state.in_flight(),
            latency: peak.then(|| m.state.latency()),
        })
        .collect();
    let hash = hash_input(&service.hash_on, key);
    let index = service.balancer.pick(&choices, hash.as_deref())?;
    let member = pool.get(index)?.clone();
    claim_trial(&member, now);
    let set_cookie = service.sticky.as_ref().and_then(|sticky| {
        member
            .sticky
            .as_ref()
            .map(|token| format!("{}={token}{}", sticky.name, sticky.attributes))
    });
    Some(Selected { member, set_cookie })
}

/// The weight a backend competes with: its configured weight, or with slow start configured,
/// that weight in thousandths reduced by the ramp, so that weight 1 ramps too.
fn weight(member: &Member, slow: Option<&SlowStart>, now: Instant) -> u32 {
    match slow {
        None => member.weight,
        Some(_) => SlowStart::scaled(member.weight, member.state.ramp(slow, now).unwrap_or(1.0)),
    }
}

/// The backends of the tier in use. `draw` (0 to 100) picks the tier under `failover:
/// spill`; `None` returns every tier that gets traffic.
fn eligible(
    service: &ServiceRuntime,
    members: &[Arc<Member>],
    now: Instant,
    draw: Option<f64>,
) -> Vec<Arc<Member>> {
    let has_room = |m: &Member| {
        service
            .max_per_backend
            .is_none_or(|max| m.state.in_flight() < max)
    };
    // Drained backends are out even when failing open: draining is an operator's decision.
    let candidates = || {
        members
            .iter()
            .filter(|m| m.weight > 0 && !m.state.is_drained())
    };
    // Per tier, in priority order: the available backends and how many there are in all.
    let mut tiers: Vec<(u8, Vec<Arc<Member>>, usize)> = Vec::new();
    for member in candidates() {
        let index = match tiers.binary_search_by_key(&member.priority, |t| t.0) {
            Ok(i) => i,
            Err(i) => {
                tiers.insert(i, (member.priority, Vec::new(), 0));
                i
            }
        };
        tiers[index].2 += 1;
        if has_room(member) && member.state.availability(now) != Availability::Down {
            tiers[index].1.push(member.clone());
        }
    }
    let chosen: Vec<Arc<Member>> = match service.selection.failover {
        Failover::Strict => tiers
            .iter()
            .find(|t| !t.1.is_empty())
            .map(|t| t.1.clone())
            .unwrap_or_default(),
        Failover::Spill(factor) => {
            let counts: Vec<(usize, usize)> = tiers.iter().map(|t| (t.1.len(), t.2)).collect();
            let loads = rdock_balancer::tier_loads(&counts, factor);
            match draw {
                None => tiers
                    .iter()
                    .zip(&loads)
                    .filter(|(_, load)| **load > 0.0)
                    .flat_map(|(t, _)| t.1.iter().cloned())
                    .collect(),
                Some(point) => {
                    let mut left = point;
                    tiers
                        .iter()
                        .zip(&loads)
                        .filter(|(t, load)| **load > 0.0 && !t.1.is_empty())
                        .find(|(_, load)| {
                            left -= **load;
                            left < 0.0
                        })
                        .or_else(|| {
                            tiers
                                .iter()
                                .zip(&loads)
                                .rfind(|(t, load)| **load > 0.0 && !t.1.is_empty())
                        })
                        .map(|(t, _)| t.1.clone())
                        .unwrap_or_default()
                }
            }
        }
    };
    if !chosen.is_empty() || !service.health.fail_open {
        return chosen;
    }
    // Fail open: every backend of the first tier, whatever its health.
    let first = candidates().map(|m| m.priority).min();
    candidates()
        .filter(|m| Some(m.priority) == first)
        .cloned()
        .collect()
}

/// A request sent to a half-open backend is its trial.
fn claim_trial(member: &Member, now: Instant) {
    if member.state.availability(now) == Availability::Trial {
        member.state.start_trial(now);
    }
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
    peer.client_cert_key.clone_from(&service.tls.client_cert);
    peer.group_key = service.tls.group_key;
    Ok(peer)
}

/// How long an attempt may wait for its connection. When a failed connect would be retried
/// on another backend (`retries.on` has `connect`, attempts are left and an untried backend
/// is eligible), the attempt is not the last one and gives up after
/// `timeouts.connect_attempt`; otherwise it waits the full `connect` (ADR-0026).
#[must_use]
pub fn connect_budget(
    connect: Duration,
    service: &ServiceRuntime,
    retries_made: u32,
    tried: &[String],
) -> Duration {
    let retried_on_connect = service
        .retries
        .as_ref()
        .is_some_and(|r| r.on.contains(&RetryOn::Connect) && retries_made < r.attempts);
    if retried_on_connect && has_untried(service, tried) {
        connect.min(service.timeouts.connect_attempt.as_std())
    } else {
        connect
    }
}

/// Whether a backend this request has not tried yet would be eligible now.
pub(crate) fn has_untried(service: &ServiceRuntime, tried: &[String]) -> bool {
    let members = service.members();
    eligible(service, &members, Instant::now(), None)
        .iter()
        .any(|m| !tried.contains(&m.id))
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
