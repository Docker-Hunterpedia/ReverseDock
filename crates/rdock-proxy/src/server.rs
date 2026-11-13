//! The data plane as a whole: applies compiled configurations (binding new listeners before
//! anything changes), keeps backend names resolved, and shuts down with a drain.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use arc_swap::ArcSwap;
use rdock_middleware::HttpClient;
use rdock_model::Config;
use rdock_model::config::ListenerSocket;
use rdock_model::values::ListenAddress;
use rdock_observability::Metrics;
use rdock_tls::{CertIndex, SniResolver};
use tokio::sync::Mutex;

use crate::compile::{CompileEnv, Compiled, compile};
use crate::dns::DNS_TICK;
use crate::forwarded::CloudflareRanges;
use crate::gate::Mode;
use crate::listener::{self, Running, Settings, Stopping};
use crate::proxy::Shared;
use crate::runtime::{ListenerTls, Runtime};
use crate::upstream::Dns;

/// Why a configuration could not be applied. Nothing changed when this is returned.
#[derive(Debug, thiserror::Error)]
pub enum ApplyError {
    /// A listener address could not be bound.
    #[error("cannot listen on {address} (listener `{name}`): {source}")]
    Bind {
        /// Listener name.
        name: String,
        /// Address.
        address: ListenAddress,
        /// The listener's protocol (`udp` binds a UDP socket, the others a TCP one).
        protocol: rdock_model::config::ListenerProtocol,
        /// Underlying error.
        #[source]
        source: std::io::Error,
    },
    /// The TLS configuration of a listener could not be built.
    #[error("listener `{name}`: {message}")]
    Tls {
        /// Listener name.
        name: String,
        /// What went wrong.
        message: String,
    },
}

/// A listener as reported by `rdock status`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ListenerStatus {
    /// Name.
    pub name: String,
    /// Bind address.
    pub address: String,
    /// TLS policy, for HTTPS listeners.
    pub tls: Option<String>,
    /// Number of routes.
    pub routes: usize,
}

struct State {
    running: BTreeMap<String, (Running, Option<ListenerTls>)>,
    /// `udp` listeners a reload removed whose sessions still drain. They keep their socket,
    /// since the sessions' replies leave from it, until the drain ends or a later reload needs
    /// the port for another `udp` listener (their sessions then end at once).
    draining: Vec<Stopping>,
}

/// Sockets and acceptors made ready before a configuration is published.
#[derive(Default)]
struct Prepared {
    /// New sockets with the options they have.
    sockets: BTreeMap<String, (listener::Socket, ListenerSocket)>,
    acceptors: BTreeMap<String, Arc<pingora::listeners::tls::Acceptor>>,
    /// New listener → the running listener whose socket it takes over: same address and
    /// transport, given up by this reload (removed, or moved to another address).
    hand_offs: BTreeMap<String, String>,
}

/// What a listener should look like after an apply.
struct Wanted {
    name: String,
    address: ListenAddress,
    tls: Option<ListenerTls>,
    timeouts: rdock_model::config::ListenerTimeouts,
    proxy_protocol: Option<rdock_model::config::ProxyProtocolIn>,
    protocol: rdock_model::config::ListenerProtocol,
    starttls: Option<rdock_model::config::StartTls>,
    socket: ListenerSocket,
    max_handshakes: Option<u32>,
}

/// The data plane.
pub struct DataPlane {
    shared: Arc<Shared>,
    resolver: Arc<SniResolver>,
    dns: Arc<Dns>,
    client: Arc<HttpClient>,
    cloudflare: CloudflareRanges,
    backends: rdock_balancer::Registry,
    checkers: crate::health::Checkers,
    sticky_key: Vec<u8>,
    live: Arc<rdock_observability::live::Live>,
    caches: rdock_cache::Registry,
    quotas: Arc<rdock_limits::quota::QuotaRegistry>,
    plugins: Arc<rdock_plugin_api::Registry>,
    state: Mutex<State>,
    generation: AtomicU64,
}

impl std::fmt::Debug for DataPlane {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DataPlane").finish_non_exhaustive()
    }
}

impl DataPlane {
    /// A data plane with no listeners. `empty` is served until the first `apply`.
    #[must_use]
    pub fn new(metrics: Metrics, empty: Runtime) -> Self {
        let resolver = Arc::new(SniResolver::new(CertIndex::default()));
        let client = Arc::new(HttpClient::default());
        let caches = rdock_cache::Registry::new(Some(rdock_cache::CacheMetrics {
            requests: metrics.cache_requests.clone(),
            objects: metrics.cache_objects.clone(),
            bytes: metrics.cache_bytes.clone(),
            evictions: metrics.cache_evictions.clone(),
            lock_waits: metrics.cache_lock_waits.clone(),
            dropped: metrics.cache_dropped.clone(),
        }));
        Self {
            shared: Arc::new(Shared {
                runtime: ArcSwap::from_pointee(empty),
                metrics,
                challenges: resolver.challenges(),
                client: client.clone(),
                in_flight: Arc::default(),
                spool: std::sync::OnceLock::new(),
            }),
            resolver,
            dns: Arc::new(Dns::default()),
            client,
            cloudflare: Arc::new(ArcSwap::from_pointee(Vec::new())),
            backends: rdock_balancer::Registry::default(),
            checkers: crate::health::Checkers::default(),
            sticky_key: random_key(),
            live: Arc::default(),
            caches,
            quotas: Arc::default(),
            plugins: Arc::default(),
            state: Mutex::new(State {
                running: BTreeMap::new(),
                draining: Vec::new(),
            }),
            generation: AtomicU64::new(0),
        }
    }

    /// Opens the spool directory for held request bodies (`<data dir>/spool`) and removes the
    /// files an earlier run left there. Without it, held bodies stay in memory.
    ///
    /// # Errors
    ///
    /// The directory cannot be created, opened or emptied.
    pub fn open_spool(&self, path: &std::path::Path) -> std::io::Result<()> {
        let spool = rdock_middleware::Spool::open(path)?;
        // A second call keeps the first spool.
        let _ = self.shared.spool.set(Arc::new(spool));
        Ok(())
    }

    /// Puts disk cache stores without a `path` under `dir` (`<data dir>/cache/<name>`).
    pub fn set_cache_dir(&self, dir: std::path::PathBuf) {
        self.caches.set_default_dir(dir);
    }

    /// Writes quota counters under `dir` (`<data dir>/quota`) and starts writing changed
    /// counters every second whose `flush_interval` has passed. Call once, inside the runtime.
    pub fn set_quota_dir(&self, dir: std::path::PathBuf) {
        self.quotas.set_dir(dir);
        let quotas = Arc::downgrade(&self.quotas);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(1));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                let Some(quotas) = quotas.upgrade() else {
                    return;
                };
                // File writes stay off the request threads' runtime workers.
                let _ = tokio::task::spawn_blocking(move || quotas.flush_due()).await;
            }
        });
    }

    /// The quota counters, for the admin API (read and reset).
    #[must_use]
    pub fn quotas(&self) -> &Arc<rdock_limits::quota::QuotaRegistry> {
        &self.quotas
    }

    /// The process's cache stores, for the admin API (stats and purges).
    #[must_use]
    pub fn caches(&self) -> &rdock_cache::Registry {
        &self.caches
    }

    /// The spool for held request bodies, once [`Self::open_spool`] has run.
    #[must_use]
    pub fn spool(&self) -> Option<Arc<rdock_middleware::Spool>> {
        self.shared.spool.get().cloned()
    }

    /// The native plugins `type: plugin` middlewares may name (`rdock::run(registry)`).
    #[must_use]
    pub fn with_plugins(mut self, plugins: Arc<rdock_plugin_api::Registry>) -> Self {
        self.plugins = plugins;
        self
    }

    /// Signs sticky cookies with `key` instead of a key that lives only as long as the process.
    #[must_use]
    pub fn with_sticky_key(mut self, key: Vec<u8>) -> Self {
        self.sticky_key = key;
        self
    }

    /// The certificate resolver, for automatically issued certificates.
    #[must_use]
    pub fn resolver(&self) -> Arc<SniResolver> {
        self.resolver.clone()
    }

    /// ACME challenge answers served by the listeners.
    #[must_use]
    pub fn challenges(&self) -> Arc<rdock_tls::Challenges> {
        self.shared.challenges.clone()
    }

    /// Cloudflare's edge ranges, which the range sync keeps current. Empty until it starts.
    #[must_use]
    pub fn cloudflare_ranges(&self) -> CloudflareRanges {
        self.cloudflare.clone()
    }

    /// Metrics of the data plane.
    #[must_use]
    pub fn metrics(&self) -> &Metrics {
        &self.shared.metrics
    }

    /// The configuration being served.
    #[must_use]
    pub fn runtime(&self) -> Arc<Runtime> {
        self.shared.runtime.load_full()
    }

    /// Compiles `config` for this data plane (the next generation number).
    pub fn compile(&self, config: &Config) -> Compiled {
        let previous = self.runtime();
        compile(
            config,
            &CompileEnv {
                mode: Mode::Run,
                generation: self.generation.load(Ordering::SeqCst) + 1,
                dns: &self.dns,
                client: self.client.clone(),
                previous: Some(&previous),
                cloudflare: &self.cloudflare,
                backends: &self.backends,
                sticky_key: &self.sticky_key,
                live: &self.live,
                caches: Some(&self.caches),
                plugins: &self.plugins,
                metrics: Some(&self.shared.metrics),
                quotas: Some(&self.quotas),
            },
        )
    }

    /// Live traffic rings of the routes and services in use (ADR-0024).
    #[must_use]
    pub fn live(&self) -> Arc<rdock_observability::live::Live> {
        self.live.clone()
    }

    /// Applies `runtime`. New listener sockets are bound first; if any bind fails, nothing
    /// changes. Removed listeners stop accepting and drain for `drain`.
    ///
    /// An address that this reload gives up (its listener is removed or moves) and that a new
    /// listener of the same transport wants is handed over: the old listener stops accepting
    /// and passes its socket on, so the new one never fails to bind it and no datagram or
    /// connection attempt in the kernel's queue is lost. A replaced `udp` listener ends its
    /// sessions at once (their replies would leave from the socket the new listener now owns);
    /// a replaced TCP listener's connections drain as usual. A removed TCP listener closes its
    /// socket before this returns; a removed `udp` listener keeps it while its sessions drain,
    /// unless a later reload needs the port, which then ends the drain.
    pub async fn apply(&self, runtime: Runtime, drain: Duration) -> Result<(), ApplyError> {
        let mut state = self.state.lock().await;
        state.draining.retain(|d| !d.is_finished());
        let mut prepared = self.prepare(&mut state, &runtime).await?;
        self.dns.resolve_new().await;
        take_over(&mut state, &mut prepared, &runtime, drain).await?;
        let wanted = self.publish(runtime);
        let stopping = self.reconcile(&mut state, wanted, prepared);
        for old in stopping {
            let mut old = old.stop(drain);
            if old.udp {
                state.draining.push(old);
            } else {
                old.released().await;
                tokio::spawn(old.finished());
            }
        }
        Ok(())
    }

    /// Binds new sockets and builds new TLS acceptors, without changing the served
    /// configuration. A `udp` bind that fails because a draining `udp` listener holds the port
    /// ends that listener's drain and is tried once more: its sessions belong to a listener the
    /// configuration no longer has.
    async fn prepare(&self, state: &mut State, runtime: &Runtime) -> Result<Prepared, ApplyError> {
        let mut prepared = Prepared::default();
        let mut released = released_addresses(state, runtime);
        for (name, listener) in &runtime.listeners {
            let running = state.running.get(name);
            let udp = listener.protocol == rdock_model::config::ListenerProtocol::Udp;
            let same_address =
                running.is_some_and(|(r, _)| r.address == listener.address && r.udp == udp);
            if let Some(tls) = &listener.tls
                && !(same_address && running.is_some_and(|(_, p)| p.as_ref() == Some(tls)))
            {
                let acceptor = listener::acceptor(tls, self.resolver.for_listener(name)).map_err(
                    |message| ApplyError::Tls {
                        name: name.clone(),
                        message,
                    },
                )?;
                prepared.acceptors.insert(name.clone(), Arc::new(acceptor));
            }
            if same_address {
                continue;
            }
            if let Some(i) = released
                .iter()
                .position(|(address, u, _)| *address == listener.address && *u == udp)
            {
                let (_, _, old) = released.swap_remove(i);
                prepared.hand_offs.insert(name.clone(), old);
                continue;
            }
            let bind_error = |source| ApplyError::Bind {
                name: name.clone(),
                address: listener.address,
                protocol: listener.protocol,
                source,
            };
            let options = &listener.socket;
            let socket = match listener::Socket::bind(&listener.address, listener.protocol, options)
            {
                Ok(socket) => socket,
                Err(err)
                    if udp
                        && err.kind() == std::io::ErrorKind::AddrInUse
                        && end_draining_on(state, listener.address.port()).await =>
                {
                    listener::Socket::bind(&listener.address, listener.protocol, options)
                        .map_err(bind_error)?
                }
                Err(err) => return Err(bind_error(err)),
            };
            prepared.sockets.insert(name.clone(), (socket, *options));
        }
        // Every bind succeeded: listeners that keep their socket get the options that can
        // change in place (backlog, buffers, Fast Open). Options set before `bind`
        // (`reuse_port`, `ipv6_only`) keep their running value until the address changes or
        // rdock restarts; the engine's reload report says so.
        for (name, listener) in &runtime.listeners {
            let udp = listener.protocol == rdock_model::config::ListenerProtocol::Udp;
            if let Some((running, _)) = state.running.get_mut(name)
                && running.address == listener.address
                && running.udp == udp
            {
                running
                    .update_socket(&listener.socket)
                    .map_err(|source| ApplyError::Bind {
                        name: name.clone(),
                        address: listener.address,
                        protocol: listener.protocol,
                        source,
                    })?;
            }
        }
        Ok(prepared)
    }

    /// Whether a listener of `protocol` could bind `address` now: nothing else holds it, or
    /// only a draining `udp` listener of this process that a reload would end. Used to decide
    /// when to retry a listener that could not bind (the engine's bind retry).
    pub async fn can_bind(
        &self,
        address: &ListenAddress,
        protocol: rdock_model::config::ListenerProtocol,
    ) -> bool {
        let udp = protocol == rdock_model::config::ListenerProtocol::Udp;
        let state = self.state.lock().await;
        if udp
            && state
                .draining
                .iter()
                .any(|d| d.udp && !d.is_finished() && d.address.port() == address.port())
        {
            return true;
        }
        drop(state);
        if udp {
            listener::bind_udp(address).is_ok()
        } else {
            listener::bind(address).is_ok()
        }
    }

    /// Makes `runtime` the served configuration; returns what each listener should look like.
    fn publish(&self, runtime: Runtime) -> Vec<Wanted> {
        self.resolver.swap(runtime.certificates.clone());
        self.resolver
            .swap_scoped(runtime.listener_certificates.clone());
        for (name, expiry) in &runtime.cert_expiry {
            self.shared
                .metrics
                .cert_expiry
                .with_label_values(&[name])
                .set(*expiry);
        }
        let wanted = runtime
            .listeners
            .iter()
            .map(|(name, l)| Wanted {
                name: name.clone(),
                address: l.address,
                tls: l.tls.clone(),
                timeouts: l.timeouts,
                proxy_protocol: l.proxy_protocol.clone(),
                protocol: l.protocol,
                starttls: l.starttls,
                socket: l.socket,
                max_handshakes: l.max_handshakes,
            })
            .collect();
        let generation = runtime.generation;
        self.checkers
            .restart(&runtime, &self.client, &self.shared.metrics);
        self.shared.runtime.store(Arc::new(runtime));
        self.generation.store(generation, Ordering::SeqCst);
        self.shared
            .metrics
            .config_generation
            .set(i64::try_from(generation).unwrap_or(i64::MAX));
        wanted
    }

    /// Starts, updates and removes listeners; returns the ones to drain.
    fn reconcile(
        &self,
        state: &mut State,
        wanted: Vec<Wanted>,
        mut prepared: Prepared,
    ) -> Vec<Running> {
        let names: std::collections::BTreeSet<&String> = wanted.iter().map(|w| &w.name).collect();
        let removed: Vec<String> = state
            .running
            .keys()
            .filter(|n| !names.contains(n))
            .cloned()
            .collect();
        let mut stopping = Vec::new();
        for name in removed {
            if let Some((running, _)) = state.running.remove(&name) {
                tracing::info!(listener = %name, "listener removed");
                stopping.push(running);
            }
        }
        for w in wanted {
            let tls = match (&w.tls, prepared.acceptors.remove(&w.name)) {
                (Some(_), Some(new)) => Some(new),
                (Some(_), None) => state
                    .running
                    .get(&w.name)
                    .and_then(|(r, _)| r.settings.load().tls.clone()),
                (None, _) => None,
            };
            // An unchanged bound keeps its semaphore, so handshakes in progress stay counted.
            let handshakes = w.max_handshakes.map(|limit| {
                state
                    .running
                    .get(&w.name)
                    .and_then(|(r, _)| r.settings.load().handshakes.clone())
                    .filter(|current| current.limit() == limit)
                    .unwrap_or_else(|| listener::Handshakes::new(limit))
            });
            let settings = Settings {
                tls,
                timeouts: w.timeouts,
                proxy_protocol: w.proxy_protocol,
                protocol: w.protocol,
                starttls: w.starttls,
                connection: listener::ConnectionOptions::of(&w.socket),
                handshakes,
            };
            if let Some(socket) = prepared.sockets.remove(&w.name) {
                let running = Running::start(
                    Arc::from(w.name.as_str()),
                    w.address,
                    socket,
                    settings,
                    self.shared.clone(),
                );
                tracing::info!(listener = %w.name, address = %w.address, tls = w.tls.is_some(), "listening");
                if let Some((old, _)) = state.running.insert(w.name, (running, w.tls)) {
                    stopping.push(old);
                }
            } else if let Some((running, stored)) = state.running.get_mut(&w.name) {
                running.settings.store(Arc::new(settings));
                *stored = w.tls;
            }
        }
        stopping
    }

    /// Keeps backend names resolved until `stop` fires.
    pub async fn refresh_dns(&self, mut stop: tokio::sync::watch::Receiver<bool>) {
        loop {
            tokio::select! {
                _ = stop.changed() => return,
                () = tokio::time::sleep(DNS_TICK) => self.dns.refresh().await,
            }
        }
    }

    /// Stops every listener, letting open requests finish for up to `drain`.
    pub async fn shutdown(&self, drain: Duration) {
        let (running, draining): (Vec<Running>, Vec<Stopping>) = {
            let mut state = self.state.lock().await;
            (
                std::mem::take(&mut state.running)
                    .into_values()
                    .map(|(r, _)| r)
                    .collect(),
                std::mem::take(&mut state.draining),
            )
        };
        let mut tasks = tokio::task::JoinSet::new();
        for listener in running {
            tasks.spawn(listener.stop(drain).finished());
        }
        for listener in draining {
            tasks.spawn(listener.finished());
        }
        while tasks.join_next().await.is_some() {}
        // Requests are over: what the quotas counted is final for this run.
        let quotas = self.quotas.clone();
        let _ = tokio::task::spawn_blocking(move || quotas.flush_all()).await;
    }

    /// Listeners whose running socket kept an option that is set before `bind` and that the
    /// served configuration changed: (listener, `reuse_port` or `ipv6_only`).
    pub async fn kept_socket_options(&self) -> Vec<(String, &'static str)> {
        let runtime = self.runtime();
        let state = self.state.lock().await;
        let mut out = Vec::new();
        for (name, (running, _)) in &state.running {
            let (Some(wanted), Some(has)) = (runtime.listeners.get(name), running.socket_options())
            else {
                continue;
            };
            if wanted.socket.reuse_port != has.reuse_port {
                out.push((name.clone(), "reuse_port"));
            }
            if wanted.socket.ipv6_only != has.ipv6_only {
                out.push((name.clone(), "ipv6_only"));
            }
        }
        out
    }

    /// Listeners currently serving.
    pub async fn listeners(&self) -> Vec<ListenerStatus> {
        let runtime = self.runtime();
        let state = self.state.lock().await;
        state
            .running
            .iter()
            .map(|(name, (running, policy))| ListenerStatus {
                name: name.clone(),
                address: running.address.to_string(),
                tls: policy
                    .as_ref()
                    .map(|t| format!("{:?}", t.policy).to_ascii_lowercase()),
                routes: runtime.listeners.get(name).map_or(0, |l| {
                    l.routes.len() + l.tcp_routes.len() + l.udp_routes.len()
                }),
            })
            .collect()
    }
}

/// The addresses of running listeners that `runtime` gives up: the listener is removed, moves
/// to another address or changes transport. (address, UDP, listener name).
fn released_addresses(state: &State, runtime: &Runtime) -> Vec<(ListenAddress, bool, String)> {
    state
        .running
        .iter()
        .filter(|(name, (running, _))| {
            !runtime.listeners.get(*name).is_some_and(|l| {
                l.address == running.address
                    && (l.protocol == rdock_model::config::ListenerProtocol::Udp) == running.udp
            })
        })
        .map(|(name, (running, _))| (running.address, running.udp, name.clone()))
        .collect()
}

/// Ends the drain of the draining `udp` listeners on `port` and waits until their sockets are
/// closed; whether there was one.
async fn end_draining_on(state: &mut State, port: u16) -> bool {
    let mut ended = false;
    for draining in &mut state.draining {
        if draining.udp && draining.address.port() == port && !draining.is_finished() {
            tracing::info!(address = %draining.address, "a new listener needs the port; ending the drain of the removed UDP listener");
            draining.end_now().await;
            ended = true;
        }
    }
    state.draining.retain(|d| !d.is_finished());
    ended
}

/// Takes the sockets of the listeners `prepared.hand_offs` names out of `state` and gives them
/// to their successors. Runs after every bind has succeeded, so nothing can fail after the old
/// listeners stopped: a socket that is not handed back (the listener's task ended without it,
/// which does not happen) is bound afresh, and only that bind could still fail.
async fn take_over(
    state: &mut State,
    prepared: &mut Prepared,
    runtime: &Runtime,
    drain: Duration,
) -> Result<(), ApplyError> {
    for (new, old) in std::mem::take(&mut prepared.hand_offs) {
        let Some((protocol, options)) = runtime.listeners.get(&new).map(|l| (l.protocol, l.socket))
        else {
            continue;
        };
        let Some((running, _)) = state.running.remove(&old) else {
            continue;
        };
        let address = running.address;
        let udp = running.udp;
        let had = running.socket_options().copied();
        tracing::info!(listener = %new, from = %old, %address, "taking over the socket of a replaced listener");
        let (socket, stopping) = running.hand_off(drain).await;
        tokio::spawn(stopping.finished());
        let bind_error = |source| ApplyError::Bind {
            name: new.clone(),
            address,
            protocol,
            source,
        };
        let taken = match (socket, had) {
            // The socket keeps what was set before `bind`; the rest follows the new listener.
            (Some(socket), Some(had)) => {
                let control = socket.control().map_err(bind_error)?;
                listener::update_running(&control, udp, &had, &options).map_err(bind_error)?;
                let kept = ListenerSocket {
                    reuse_port: had.reuse_port,
                    ipv6_only: had.ipv6_only,
                    ..options
                };
                (socket, kept)
            }
            (Some(socket), None) => (socket, options),
            (None, _) => (
                listener::Socket::bind(&address, protocol, &options).map_err(bind_error)?,
                options,
            ),
        };
        prepared.sockets.insert(new, taken);
    }
    Ok(())
}

/// 32 random bytes.
#[must_use]
pub fn random_key() -> Vec<u8> {
    use ring::rand::SecureRandom;
    let mut key = vec![0; 32];
    // The system random source does not fail on supported platforms; a zero key would still
    // only make sticky cookies predictable, never let a client choose a backend it cannot reach.
    if ring::rand::SystemRandom::new().fill(&mut key).is_err() {
        tracing::error!("the system random source failed; sticky cookies use a fixed key");
    }
    key
}
