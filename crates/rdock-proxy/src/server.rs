//! The data plane as a whole: applies compiled configurations (binding new listeners before
//! anything changes), keeps backend names resolved, and shuts down with a drain.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use arc_swap::ArcSwap;
use rdock_middleware::HttpClient;
use rdock_model::Config;
use rdock_model::config::TlsPolicy;
use rdock_model::values::ListenAddress;
use rdock_observability::Metrics;
use rdock_tls::{CertIndex, SniResolver};
use tokio::sync::Mutex;

use crate::compile::{CompileEnv, Compiled, compile};
use crate::gate::Mode;
use crate::listener::{self, Running, Settings};
use crate::proxy::Shared;
use crate::runtime::Runtime;
use crate::upstream::{DNS_REFRESH, Dns};

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
    running: BTreeMap<String, (Running, Option<TlsPolicy>)>,
}

/// Sockets and acceptors made ready before a configuration is published.
#[derive(Default)]
struct Prepared {
    sockets: BTreeMap<String, tokio::net::TcpListener>,
    acceptors: BTreeMap<String, Arc<pingora::listeners::tls::Acceptor>>,
}

/// What a listener should look like after an apply.
struct Wanted {
    name: String,
    address: ListenAddress,
    tls: Option<TlsPolicy>,
    timeouts: rdock_model::config::ListenerTimeouts,
}

/// The data plane.
pub struct DataPlane {
    shared: Arc<Shared>,
    resolver: Arc<SniResolver>,
    dns: Arc<Dns>,
    client: Arc<HttpClient>,
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
        Self {
            shared: Arc::new(Shared {
                runtime: ArcSwap::from_pointee(empty),
                metrics,
            }),
            resolver: Arc::new(SniResolver::new(CertIndex::default())),
            dns: Arc::new(Dns::default()),
            client: Arc::new(HttpClient::default()),
            state: Mutex::new(State {
                running: BTreeMap::new(),
            }),
            generation: AtomicU64::new(0),
        }
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
            },
        )
    }

    /// Applies `runtime`. New listener sockets are bound first; if any bind fails, nothing
    /// changes. Removed listeners stop accepting and drain for `drain`.
    pub async fn apply(&self, runtime: Runtime, drain: Duration) -> Result<(), ApplyError> {
        let mut state = self.state.lock().await;
        let prepared = self.prepare(&state, &runtime)?;
        self.dns.resolve_new().await;
        let wanted = self.publish(runtime);
        let stopping = self.reconcile(&mut state, wanted, prepared);
        drop(state);
        for old in stopping {
            tokio::spawn(old.stop(drain));
        }
        Ok(())
    }

    /// Binds new sockets and builds new TLS acceptors, without changing anything.
    fn prepare(&self, state: &State, runtime: &Runtime) -> Result<Prepared, ApplyError> {
        let mut prepared = Prepared::default();
        for (name, listener) in &runtime.listeners {
            let running = state.running.get(name);
            let same_address = running.is_some_and(|(r, _)| r.address == listener.address);
            if let Some(policy) = listener.tls
                && !(same_address && running.is_some_and(|(_, p)| *p == Some(policy)))
            {
                let acceptor =
                    listener::acceptor(policy, self.resolver.clone()).map_err(|message| {
                        ApplyError::Tls {
                            name: name.clone(),
                            message,
                        }
                    })?;
                prepared.acceptors.insert(name.clone(), Arc::new(acceptor));
            }
            if !same_address {
                let bind_error = |source| ApplyError::Bind {
                    name: name.clone(),
                    address: listener.address,
                    source,
                };
                let socket = listener::bind(&listener.address).map_err(bind_error)?;
                let socket = tokio::net::TcpListener::from_std(socket).map_err(bind_error)?;
                prepared.sockets.insert(name.clone(), socket);
            }
        }
        Ok(prepared)
    }

    /// Makes `runtime` the served configuration; returns what each listener should look like.
    fn publish(&self, runtime: Runtime) -> Vec<Wanted> {
        self.resolver.swap(runtime.certificates.clone());
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
                tls: l.tls,
                timeouts: l.timeouts,
            })
            .collect();
        let generation = runtime.generation;
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
            let tls = match (w.tls, prepared.acceptors.remove(&w.name)) {
                (Some(_), Some(new)) => Some(new),
                (Some(_), None) => state
                    .running
                    .get(&w.name)
                    .and_then(|(r, _)| r.settings.load().tls.clone()),
                (None, _) => None,
            };
            let settings = Settings {
                tls,
                timeouts: w.timeouts,
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
                () = tokio::time::sleep(DNS_REFRESH) => self.dns.refresh().await,
            }
        }
    }

    /// Stops every listener, letting open requests finish for up to `drain`.
    pub async fn shutdown(&self, drain: Duration) {
        let running: Vec<Running> = {
            let mut state = self.state.lock().await;
            std::mem::take(&mut state.running)
                .into_values()
                .map(|(r, _)| r)
                .collect()
        };
        let mut tasks = tokio::task::JoinSet::new();
        for listener in running {
            tasks.spawn(listener.stop(drain));
        }
        while tasks.join_next().await.is_some() {}
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
                tls: policy.map(|p| format!("{p:?}").to_ascii_lowercase()),
                routes: runtime.listeners.get(name).map_or(0, |l| l.routes.len()),
            })
            .collect()
    }
}
