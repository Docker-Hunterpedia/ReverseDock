//! What a plugin knows about a request ([`Facts`]), its typed per-request [`State`], and the
//! [`Ctx`] that carries both into every hook.

use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use http::StatusCode;

/// The consumer (API client, user) a request is attributed to, when an authenticating
/// middleware earlier in the chain set one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Consumer {
    name: Arc<str>,
    groups: Arc<[Arc<str>]>,
}

impl Consumer {
    /// A consumer with groups.
    #[must_use]
    pub fn new(name: Arc<str>, groups: Arc<[Arc<str>]>) -> Self {
        Self { name, groups }
    }

    /// A consumer without groups.
    #[must_use]
    pub fn named(name: &str) -> Self {
        Self::new(Arc::from(name), Arc::from([]))
    }

    /// Its name (`consumers.<name>`).
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Its groups.
    pub fn groups(&self) -> impl Iterator<Item = &str> {
        self.groups.iter().map(|g| &**g)
    }

    /// Whether it belongs to `group`.
    #[must_use]
    pub fn in_group(&self, group: &str) -> bool {
        self.groups.iter().any(|g| &**g == group)
    }
}

/// The backend chosen for the current attempt, known from `upstream_request` on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upstream {
    service: Arc<str>,
    backend: String,
    addr: Option<SocketAddr>,
    attempt: u32,
}

impl Upstream {
    /// An upstream (used by the proxy and by tests).
    #[must_use]
    pub fn new(service: Arc<str>, backend: String, addr: Option<SocketAddr>, attempt: u32) -> Self {
        Self {
            service,
            backend,
            addr,
            attempt,
        }
    }

    /// Name of the service.
    #[must_use]
    pub fn service(&self) -> &str {
        &self.service
    }

    /// The backend as configured (`10.0.0.5:8080`, `unix:/run/app.sock`).
    #[must_use]
    pub fn backend(&self) -> &str {
        &self.backend
    }

    /// Its resolved socket address; `None` for Unix sockets.
    #[must_use]
    pub fn addr(&self) -> Option<SocketAddr> {
        self.addr
    }

    /// Attempt number, from 0 (retries increase it).
    #[must_use]
    pub fn attempt(&self) -> u32 {
        self.attempt
    }
}

/// Facts about a request that a plugin may read.
///
/// ```
/// use rdock_plugin_api::{Consumer, Facts};
///
/// let facts = Facts::new("192.0.2.7".parse().unwrap(), "api", "req-1")
///     .with_tls(true)
///     .with_consumer(Some(Consumer::named("acme")));
/// assert!(facts.tls());
/// assert_eq!(facts.consumer().map(Consumer::name), Some("acme"));
/// assert!(facts.upstream().is_none());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Facts {
    client_ip: IpAddr,
    tls: bool,
    route: Arc<str>,
    request_id: Arc<str>,
    consumer: Option<Consumer>,
    upstream: Option<Upstream>,
}

impl Facts {
    /// Facts for a request from `client_ip` on `route` (used by the proxy and by tests).
    #[must_use]
    pub fn new(
        client_ip: IpAddr,
        route: impl Into<Arc<str>>,
        request_id: impl Into<Arc<str>>,
    ) -> Self {
        Self {
            client_ip,
            tls: false,
            route: route.into(),
            request_id: request_id.into(),
            consumer: None,
            upstream: None,
        }
    }

    /// Sets the client address.
    #[must_use]
    pub fn with_client_ip(mut self, client_ip: IpAddr) -> Self {
        self.client_ip = client_ip;
        self
    }

    /// Sets whether the client connection uses TLS.
    #[must_use]
    pub fn with_tls(mut self, tls: bool) -> Self {
        self.tls = tls;
        self
    }

    /// Sets the consumer.
    #[must_use]
    pub fn with_consumer(mut self, consumer: Option<Consumer>) -> Self {
        self.consumer = consumer;
        self
    }

    /// Sets the chosen backend.
    #[must_use]
    pub fn with_upstream(mut self, upstream: Option<Upstream>) -> Self {
        self.upstream = upstream;
        self
    }

    /// The client's IP address, after trusted-proxy handling (`X-Forwarded-For` and the PROXY
    /// protocol from trusted sources only).
    #[must_use]
    pub fn client_ip(&self) -> IpAddr {
        self.client_ip
    }

    /// Whether the client connection uses TLS.
    #[must_use]
    pub fn tls(&self) -> bool {
        self.tls
    }

    /// Name of the matched route.
    #[must_use]
    pub fn route(&self) -> &str {
        &self.route
    }

    /// The request id, also sent upstream as `X-Request-ID`.
    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    /// The consumer, when an authenticating middleware earlier in the chain set one.
    #[must_use]
    pub fn consumer(&self) -> Option<&Consumer> {
        self.consumer.as_ref()
    }

    /// The backend of the current attempt: set in `upstream_request` and later phases.
    #[must_use]
    pub fn upstream(&self) -> Option<&Upstream> {
        self.upstream.as_ref()
    }
}

/// Typed per-request state: at most one value per type, private to one plugin instance in one
/// route's chain (two instances of the same plugin never see each other's state).
#[derive(Default)]
pub struct State {
    values: HashMap<TypeId, Box<dyn Any + Send + Sync>>,
}

impl fmt::Debug for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("State")
            .field("values", &self.values.len())
            .finish()
    }
}

impl State {
    /// The value of type `T`, if one was set.
    #[must_use]
    pub fn get<T: Any>(&self) -> Option<&T> {
        self.values.get(&TypeId::of::<T>())?.downcast_ref()
    }

    /// The value of type `T`, mutably.
    pub fn get_mut<T: Any>(&mut self) -> Option<&mut T> {
        self.values.get_mut(&TypeId::of::<T>())?.downcast_mut()
    }

    /// Sets the value of type `T`, returning the earlier one.
    pub fn insert<T: Any + Send + Sync>(&mut self, value: T) -> Option<T> {
        self.values
            .insert(TypeId::of::<T>(), Box::new(value))
            .and_then(|old| old.downcast().ok())
            .map(|b| *b)
    }

    /// Removes and returns the value of type `T`.
    pub fn remove<T: Any>(&mut self) -> Option<T> {
        self.values
            .remove(&TypeId::of::<T>())
            .and_then(|old| old.downcast().ok())
            .map(|b| *b)
    }
}

enum StateRef<'a> {
    Mut(&'a mut State),
    Ref(Option<&'a State>),
}

/// What every hook gets besides the head or body: the request's [`Facts`] and the plugin's
/// typed [`State`].
///
/// State survives from one phase to a later one only when the plugin declared
/// [`crate::Capabilities::with_state`]; otherwise each hook starts with empty state.
///
/// ```
/// use rdock_plugin_api::{Ctx, Facts, State};
///
/// let facts = Facts::new("198.51.100.1".parse().unwrap(), "web", "id-7");
/// let mut state = State::default();
/// let mut cx = Ctx::new(&facts, &mut state);
/// cx.set_state(3_u32);
/// *cx.state_mut::<u32>().unwrap() += 1;
/// assert_eq!(cx.state::<u32>(), Some(&4));
/// assert_eq!(cx.state::<String>(), None, "one value per type");
/// assert_eq!(cx.route(), "web");
/// ```
pub struct Ctx<'a> {
    facts: &'a Facts,
    state: StateRef<'a>,
}

impl fmt::Debug for Ctx<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ctx")
            .field("facts", self.facts)
            .finish_non_exhaustive()
    }
}

impl<'a> Ctx<'a> {
    /// A context for a hook that may change state (used by the proxy and the test harness).
    #[must_use]
    pub fn new(facts: &'a Facts, state: &'a mut State) -> Self {
        Self {
            facts,
            state: StateRef::Mut(state),
        }
    }

    /// A read-only context, for the `log` phase (used by the proxy and the test harness).
    #[must_use]
    pub fn read_only(facts: &'a Facts, state: Option<&'a State>) -> Self {
        Self {
            facts,
            state: StateRef::Ref(state),
        }
    }

    /// The request's facts.
    #[must_use]
    pub fn facts(&self) -> &Facts {
        self.facts
    }

    /// See [`Facts::client_ip`].
    #[must_use]
    pub fn client_ip(&self) -> IpAddr {
        self.facts.client_ip
    }

    /// See [`Facts::tls`].
    #[must_use]
    pub fn tls(&self) -> bool {
        self.facts.tls
    }

    /// See [`Facts::route`].
    #[must_use]
    pub fn route(&self) -> &str {
        &self.facts.route
    }

    /// See [`Facts::request_id`].
    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.facts.request_id
    }

    /// See [`Facts::consumer`].
    #[must_use]
    pub fn consumer(&self) -> Option<&Consumer> {
        self.facts.consumer.as_ref()
    }

    /// See [`Facts::upstream`].
    #[must_use]
    pub fn upstream(&self) -> Option<&Upstream> {
        self.facts.upstream.as_ref()
    }

    /// The plugin's state of type `T`, if set in this or an earlier phase.
    #[must_use]
    pub fn state<T: Any>(&self) -> Option<&T> {
        match &self.state {
            StateRef::Mut(state) => state.get(),
            StateRef::Ref(state) => state.and_then(State::get),
        }
    }

    /// The plugin's state of type `T`, mutably.
    pub fn state_mut<T: Any>(&mut self) -> Option<&mut T> {
        match &mut self.state {
            StateRef::Mut(state) => state.get_mut(),
            StateRef::Ref(_) => None,
        }
    }

    /// Sets the plugin's state of type `T`, replacing an earlier value. A read-only context
    /// (the `log` phase, which receives `&Ctx`) cannot be changed.
    pub fn set_state<T: Any + Send + Sync>(&mut self, value: T) {
        if let StateRef::Mut(state) = &mut self.state {
            state.insert(value);
        }
    }

    /// Takes the plugin's state of type `T` out.
    pub fn take_state<T: Any>(&mut self) -> Option<T> {
        match &mut self.state {
            StateRef::Mut(state) => state.remove(),
            StateRef::Ref(_) => None,
        }
    }
}

/// What the `log` phase knows about a finished request.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LogSummary {
    /// Status sent to the client; `None` when nothing could be sent.
    pub status: Option<StatusCode>,
    /// Request body bytes read from the client.
    pub bytes_in: u64,
    /// Response body bytes sent to the client.
    pub bytes_out: u64,
    /// Time from the request head to the end of the response.
    pub duration: Duration,
    /// Time from the start of the last backend attempt to the end, if a backend was tried.
    pub upstream_duration: Option<Duration>,
    /// The error that ended the request, if any.
    pub error: Option<String>,
}

impl LogSummary {
    /// A summary (used by the proxy and by tests); counters start at zero.
    #[must_use]
    pub fn new(status: Option<StatusCode>, duration: Duration) -> Self {
        Self {
            status,
            bytes_in: 0,
            bytes_out: 0,
            duration,
            upstream_duration: None,
            error: None,
        }
    }

    /// Sets the byte counters.
    #[must_use]
    pub fn with_bytes(mut self, bytes_in: u64, bytes_out: u64) -> Self {
        self.bytes_in = bytes_in;
        self.bytes_out = bytes_out;
        self
    }

    /// Sets the upstream duration.
    #[must_use]
    pub fn with_upstream_duration(mut self, duration: Option<Duration>) -> Self {
        self.upstream_duration = duration;
        self
    }

    /// Sets the error.
    #[must_use]
    pub fn with_error(mut self, error: Option<String>) -> Self {
        self.error = error;
        self
    }
}
