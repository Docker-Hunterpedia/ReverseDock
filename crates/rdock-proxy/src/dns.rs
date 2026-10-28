//! Backend name resolution (M-LB-10, ADR-0022): host names resolved with hickory and refreshed
//! when their records expire (TTL bounded to 1 s … 5 min), with the system resolver as fallback
//! (container names, `/etc/hosts`); `srv://` backends from SRV records with their priorities,
//! weights and ports. A failed lookup keeps the previous answer.
//!
//! Pingora's `HttpPeer::new` resolves names synchronously and panics on failure, so every peer
//! is built from an address resolved here.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock, PoisonError, Weak};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use hickory_resolver::TokioResolver;
use hickory_resolver::proto::rr::{RData, RecordType};

/// How often the refresh task looks for expired names.
pub const DNS_TICK: Duration = Duration::from_secs(1);
/// Time allowed for one lookup.
pub const DNS_TIMEOUT: Duration = Duration::from_secs(2);
/// Answers are kept at least this long, whatever their TTL.
const MIN_TTL: Duration = Duration::from_secs(1);
/// Answers are refreshed at least this often, whatever their TTL.
const MAX_TTL: Duration = Duration::from_secs(300);
/// TTL assumed for answers of the system resolver, which does not report one.
const SYSTEM_TTL: Duration = Duration::from_secs(10);
/// Wait before trying a failed name again.
const RETRY: Duration = Duration::from_secs(5);

/// Resolved addresses of one `host:port`.
pub type Cell = ArcSwap<Vec<SocketAddr>>;
/// Resolved targets of one SRV name.
pub type SrvCell = ArcSwap<Vec<SrvTarget>>;

/// One target of an SRV record, resolved.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SrvTarget {
    /// Lower is preferred; higher priorities are only used when no lower one is available.
    pub priority: u16,
    /// Relative share within the priority.
    pub weight: u16,
    /// Target host, for SNI and `Host`.
    pub host: String,
    /// Resolved address and the record's port.
    pub addr: SocketAddr,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Key {
    Host(String, u16),
    Srv(String),
}

/// Resolved backend names, shared by every configuration generation.
#[derive(Debug, Default)]
pub struct Dns {
    hosts: Mutex<HashMap<(String, u16), Weak<Cell>>>,
    srv: Mutex<HashMap<String, Weak<SrvCell>>>,
    due: Mutex<HashMap<Key, Instant>>,
    resolver: OnceLock<Option<TokioResolver>>,
}

impl Dns {
    /// The address cell for `host:port`, shared with earlier generations while they are alive.
    pub fn cell(&self, host: &str, port: u16) -> Arc<Cell> {
        shared(&self.hosts, (host.to_owned(), port))
    }

    /// The target cell for the SRV name `name`.
    pub fn srv_cell(&self, name: &str) -> Arc<SrvCell> {
        shared(&self.srv, name.to_owned())
    }

    /// Resolves the names whose answers expired.
    pub async fn refresh(&self) {
        self.resolve(false).await;
    }

    /// Resolves names that have no answer yet (new backends).
    pub async fn resolve_new(&self) {
        self.resolve(true).await;
    }

    fn resolver(&self) -> Option<&TokioResolver> {
        self.resolver
            .get_or_init(|| {
                TokioResolver::builder_tokio()
                    .and_then(hickory_resolver::ResolverBuilder::build)
                    .map_err(|e| tracing::warn!(error = %e, "no DNS resolver configuration; using the system lookup"))
                    .ok()
            })
            .as_ref()
    }

    fn is_due(&self, key: &Key, empty: bool, only_new: bool, now: Instant) -> bool {
        if only_new {
            return empty;
        }
        let due = self.due.lock().unwrap_or_else(PoisonError::into_inner);
        empty || due.get(key).is_none_or(|at| *at <= now)
    }

    fn schedule(&self, key: Key, after: Duration) {
        self.due
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(key, Instant::now() + after);
    }

    async fn resolve(&self, only_new: bool) {
        let now = Instant::now();
        let hosts = live(&self.hosts);
        let srv = live(&self.srv);
        {
            let mut due = self.due.lock().unwrap_or_else(PoisonError::into_inner);
            due.retain(|key, _| match key {
                Key::Host(h, p) => hosts.iter().any(|((hh, pp), _)| hh == h && pp == p),
                Key::Srv(n) => srv.iter().any(|(nn, _)| nn == n),
            });
        }
        let mut tasks = Vec::new();
        for ((host, port), cell) in hosts {
            let key = Key::Host(host.clone(), port);
            if self.is_due(&key, cell.load().is_empty(), only_new, now) {
                tasks.push(Box::pin(self.refresh_host(host, port, cell))
                    as std::pin::Pin<
                        Box<dyn std::future::Future<Output = ()> + Send + '_>,
                    >);
            }
        }
        for (name, cell) in srv {
            let key = Key::Srv(name.clone());
            if self.is_due(&key, cell.load().is_empty(), only_new, now) {
                tasks.push(Box::pin(self.refresh_srv(name, cell)));
            }
        }
        futures_util::future::join_all(tasks).await;
    }

    async fn refresh_host(&self, host: String, port: u16, cell: Arc<Cell>) {
        let key = Key::Host(host.clone(), port);
        if let Some((addrs, ttl)) = self.lookup_host(&host, port).await {
            if **cell.load() != addrs {
                tracing::debug!(%host, port, ?addrs, "backend addresses changed");
                cell.store(Arc::new(addrs));
            }
            self.schedule(key, ttl);
        } else {
            tracing::warn!(%host, port, "cannot resolve backend");
            self.schedule(key, RETRY);
        }
    }

    async fn refresh_srv(&self, name: String, cell: Arc<SrvCell>) {
        let key = Key::Srv(name.clone());
        if let Some((targets, ttl)) = self.lookup_srv(&name).await {
            if **cell.load() != targets {
                tracing::debug!(%name, targets = targets.len(), "SRV targets changed");
                cell.store(Arc::new(targets));
            }
            self.schedule(key, ttl);
        } else {
            tracing::warn!(%name, "cannot resolve SRV backend");
            self.schedule(key, RETRY);
        }
    }

    /// Addresses of `host` and how long they are valid.
    async fn lookup_host(&self, host: &str, port: u16) -> Option<(Vec<SocketAddr>, Duration)> {
        if let Some(resolver) = self.resolver()
            && let Ok(Ok(answer)) =
                tokio::time::timeout(DNS_TIMEOUT, resolver.lookup_ip(host)).await
        {
            let mut addrs: Vec<SocketAddr> =
                answer.iter().map(|ip| SocketAddr::new(ip, port)).collect();
            if !addrs.is_empty() {
                addrs.sort();
                addrs.dedup();
                return Some((addrs, ttl(answer.valid_until())));
            }
        }
        // Names the system knows but DNS does not: `/etc/hosts`, some container networks.
        let system = tokio::time::timeout(DNS_TIMEOUT, tokio::net::lookup_host((host, port))).await;
        let mut addrs: Vec<SocketAddr> = system.ok()?.ok()?.collect();
        addrs.sort();
        addrs.dedup();
        (!addrs.is_empty()).then_some((addrs, SYSTEM_TTL))
    }

    /// The resolved targets of an SRV name and how long they are valid.
    async fn lookup_srv(&self, name: &str) -> Option<(Vec<SrvTarget>, Duration)> {
        let resolver = self.resolver()?;
        let fqdn = if name.ends_with('.') {
            name.to_owned()
        } else {
            format!("{name}.")
        };
        let answer = tokio::time::timeout(DNS_TIMEOUT, resolver.lookup(fqdn, RecordType::SRV))
            .await
            .ok()?
            .ok()?;
        let mut valid = ttl(answer.valid_until());
        let mut targets = Vec::new();
        for record in answer.answers() {
            let RData::SRV(srv) = &record.data else {
                continue;
            };
            let host = srv.target.to_utf8().trim_end_matches('.').to_owned();
            // A target of "." means the service is decidedly not available here (RFC 2782).
            if host.is_empty() {
                continue;
            }
            let Some((addrs, host_ttl)) = self.lookup_host(&host, srv.port).await else {
                continue;
            };
            valid = valid.min(host_ttl);
            for addr in addrs {
                targets.push(SrvTarget {
                    priority: srv.priority,
                    weight: srv.weight,
                    host: host.clone(),
                    addr,
                });
            }
        }
        targets.sort();
        (!targets.is_empty()).then_some((targets, valid))
    }
}

fn ttl(valid_until: Instant) -> Duration {
    valid_until
        .saturating_duration_since(Instant::now())
        .clamp(MIN_TTL, MAX_TTL)
}

fn shared<K: std::hash::Hash + Eq, T>(
    map: &Mutex<HashMap<K, Weak<ArcSwap<Vec<T>>>>>,
    key: K,
) -> Arc<ArcSwap<Vec<T>>> {
    let mut cells = map.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(cell) = cells.get(&key).and_then(Weak::upgrade) {
        return cell;
    }
    let cell = Arc::new(ArcSwap::from_pointee(Vec::new()));
    cells.insert(key, Arc::downgrade(&cell));
    cell
}

fn live<K: Clone + std::hash::Hash + Eq, T>(map: &Mutex<HashMap<K, Weak<T>>>) -> Vec<(K, Arc<T>)> {
    let mut cells = map.lock().unwrap_or_else(PoisonError::into_inner);
    cells.retain(|_, cell| cell.strong_count() > 0);
    cells
        .iter()
        .filter_map(|(key, cell)| cell.upgrade().map(|c| (key.clone(), c)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cells_are_shared_resolved_and_forgotten() {
        let dns = Dns::default();
        let a = dns.cell("localhost", 8080);
        let b = dns.cell("localhost", 8080);
        assert!(Arc::ptr_eq(&a, &b));
        dns.resolve_new().await;
        assert!(!a.load().is_empty(), "localhost resolves");
        assert!(a.load().iter().all(|addr| addr.port() == 8080));
        drop((a, b));
        assert!(live(&dns.hosts).is_empty(), "dropped cells are forgotten");
    }

    #[test]
    fn ttls_are_bounded() {
        let now = Instant::now();
        assert_eq!(ttl(now), MIN_TTL);
        assert_eq!(ttl(now + Duration::from_secs(86_400)), MAX_TTL);
        let thirty = ttl(now + Duration::from_secs(30));
        assert!(thirty <= Duration::from_secs(30) && thirty >= Duration::from_secs(29));
    }
}
