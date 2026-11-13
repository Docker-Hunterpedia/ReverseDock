//! The wasmtime host (feature `wasm`): one engine with fuel and epoch interruption, components
//! checked against the `filter` world when they are loaded, and a fresh instance per request.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use http::{HeaderName, HeaderValue, StatusCode};
use rdock_plugin_api as api;
use wasmtime::component::{Component, HasSelf, InstancePre, Linker, types::ComponentItem};
use wasmtime::{Engine, ResourceLimiter, Store, Trap};

#[allow(missing_docs, clippy::all, clippy::pedantic)]
mod bindings {
    // Only the imports and the types: the exports are looked up by name with the safe typed
    // API, because the world's generated export wrappers use `unsafe`.
    wasmtime::component::bindgen!({
        path: "wit",
        inline: "package rdock:host;
                 world host {
                     import rdock:plugin/types@0.1.0;
                     import rdock:plugin/log@0.1.0;
                     import rdock:plugin/clock@0.1.0;
                     import rdock:plugin/random@0.1.0;
                     import rdock:plugin/config@0.1.0;
                 }",
        world: "rdock:host/host",
        imports: { default: trappable },
    });
}

use bindings::rdock::plugin::{clock, config, log, random, types};

/// The epoch ticker's period: the resolution of the per-call deadline.
const TICK: Duration = Duration::from_millis(1);

/// The import names of the capabilities.
const TYPES: &str = "rdock:plugin/types@0.1.0";
const LOG: &str = "rdock:plugin/log@0.1.0";
const CLOCK: &str = "rdock:plugin/clock@0.1.0";
const RANDOM: &str = "rdock:plugin/random@0.1.0";
const CONFIG: &str = "rdock:plugin/config@0.1.0";

/// Log lines one instance (one request) may write; later lines are dropped.
const LOG_LINES_PER_INSTANCE: u32 = 32;
/// The longest log line kept.
const LOG_LINE_MAX: usize = 1024;

/// Per-call limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Fuel per call (about one unit per WebAssembly instruction).
    pub fuel: u64,
    /// Wall-clock deadline per call (epoch interruption; resolution 1 ms).
    pub timeout: Duration,
    /// The largest linear memory, in bytes.
    pub memory: u64,
}

/// The capabilities a plugin is granted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Grants {
    /// `rdock:plugin/log`.
    pub log: bool,
    /// `rdock:plugin/clock`.
    pub clock: bool,
    /// `rdock:plugin/random`.
    pub random: bool,
}

/// Everything about a plugin besides its bytes.
#[derive(Debug, Clone)]
pub struct Settings {
    /// The middleware's name (log lines, errors).
    pub name: String,
    /// Limits per call.
    pub limits: Limits,
    /// Granted capabilities.
    pub grants: Grants,
    /// The plugin's `config`, as JSON text.
    pub config: String,
}

/// Why a component was refused when it was loaded.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CompileError {
    /// The engine could not be created.
    #[error("the WebAssembly engine could not be created: {0}")]
    Engine(String),
    /// Not a valid component (a core module, another format, invalid code).
    #[error("not a valid WebAssembly component: {0}")]
    Invalid(String),
    /// It imports something the host does not provide or grant.
    #[error("{0}")]
    Import(String),
    /// It lacks an export of the `filter` world, or one has the wrong type.
    #[error("{0}")]
    Export(String),
    /// A trial instantiation failed (memory over the limit, a trap in its start function).
    #[error("instantiating it failed: {0}")]
    Instantiate(String),
}

/// Why a call into a plugin failed. The middleware's `on_error` decides what follows.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CallError {
    /// The call used up its fuel.
    #[error("the plugin ran out of fuel")]
    Fuel,
    /// The call ran past its deadline.
    #[error("the plugin ran past its deadline")]
    Timeout,
    /// The plugin tried to grow its memory past the limit.
    #[error("the plugin tried to grow its memory past the limit")]
    Memory,
    /// The plugin trapped.
    #[error("the plugin trapped: {0}")]
    Trap(String),
    /// The plugin returned an edit or a reply the host refuses.
    #[error("the plugin returned an invalid result: {0}")]
    Invalid(String),
}

impl CallError {
    /// A short label for metrics: `fuel`, `timeout`, `memory`, `trap` or `invalid`.
    #[must_use]
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Fuel => "fuel",
            Self::Timeout => "timeout",
            Self::Memory => "memory",
            Self::Trap(_) => "trap",
            Self::Invalid(_) => "invalid",
        }
    }
}

/// The one engine, with its epoch ticker.
fn engine() -> Result<&'static Engine, CompileError> {
    static ENGINE: OnceLock<Result<Engine, String>> = OnceLock::new();
    ENGINE
        .get_or_init(|| {
            let mut config = wasmtime::Config::new();
            config
                .wasm_component_model(true)
                .consume_fuel(true)
                .epoch_interruption(true)
                .max_wasm_stack(512 * 1024);
            let engine = Engine::new(&config).map_err(|e| format!("{e:#}"))?;
            let ticker = engine.weak();
            std::thread::Builder::new()
                .name("rdock-wasm-epoch".into())
                .spawn(move || {
                    while let Some(engine) = ticker.upgrade() {
                        engine.increment_epoch();
                        drop(engine);
                        std::thread::sleep(TICK);
                    }
                })
                .map_err(|e| format!("starting the epoch thread: {e}"))?;
            Ok(engine)
        })
        .as_ref()
        .map_err(|e| CompileError::Engine(e.clone()))
}

/// The store's data: the limiter and what the imports need.
struct HostState {
    name: Arc<str>,
    config: Arc<str>,
    memory_max: usize,
    memory_hit: bool,
    log_lines: u32,
}

impl ResourceLimiter for HostState {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        if desired > self.memory_max {
            self.memory_hit = true;
            return Err(wasmtime::Error::msg("memory limit reached"));
        }
        Ok(true)
    }

    fn table_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        Ok(desired <= 100_000)
    }

    fn instances(&self) -> usize {
        32
    }

    fn tables(&self) -> usize {
        32
    }

    fn memories(&self) -> usize {
        1
    }
}

impl types::Host for HostState {}

impl log::Host for HostState {
    fn write(&mut self, level: log::Level, message: String) -> wasmtime::Result<()> {
        if self.log_lines >= LOG_LINES_PER_INSTANCE {
            return Ok(());
        }
        self.log_lines += 1;
        let mut end = message.len().min(LOG_LINE_MAX);
        while !message.is_char_boundary(end) {
            end -= 1;
        }
        let message = &message[..end];
        let name = &*self.name;
        match level {
            log::Level::Error => {
                tracing::error!(target: "rdock::wasm", middleware = name, "{message}");
            }
            log::Level::Warn => {
                tracing::warn!(target: "rdock::wasm", middleware = name, "{message}");
            }
            log::Level::Info => {
                tracing::info!(target: "rdock::wasm", middleware = name, "{message}");
            }
            log::Level::Debug => {
                tracing::debug!(target: "rdock::wasm", middleware = name, "{message}");
            }
            log::Level::Trace => {
                tracing::trace!(target: "rdock::wasm", middleware = name, "{message}");
            }
        }
        Ok(())
    }
}

impl clock::Host for HostState {
    fn now_ms(&mut self) -> wasmtime::Result<u64> {
        let since = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        Ok(u64::try_from(since.as_millis()).unwrap_or(u64::MAX))
    }
}

impl random::Host for HostState {
    fn next_u64(&mut self) -> wasmtime::Result<u64> {
        use ring::rand::SecureRandom as _;
        let mut bytes = [0; 8];
        ring::rand::SystemRandom::new()
            .fill(&mut bytes)
            .map_err(|_| wasmtime::Error::msg("the system random generator failed"))?;
        Ok(u64::from_le_bytes(bytes))
    }
}

impl config::Host for HostState {
    fn get(&mut self) -> wasmtime::Result<String> {
        Ok(self.config.to_string())
    }
}

struct Inner {
    name: Arc<str>,
    config: Arc<str>,
    limits: Limits,
    deadline_ticks: u64,
    pre: InstancePre<HostState>,
    instances: AtomicU64,
}

/// A loaded, checked plugin; cheap to clone.
#[derive(Clone)]
pub struct Plugin {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for Plugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Plugin")
            .field("name", &self.inner.name)
            .field("limits", &self.inner.limits)
            .finish_non_exhaustive()
    }
}

/// What is wrong with the component's imports, if anything: capabilities it was not granted
/// and interfaces rdock does not provide (WASI among them).
fn check_imports<'a>(names: impl Iterator<Item = &'a str>, grants: Grants) -> Option<String> {
    let mut ungranted = Vec::new();
    let mut unknown = Vec::new();
    for name in names {
        match name {
            TYPES | CONFIG => {}
            LOG if grants.log => {}
            CLOCK if grants.clock => {}
            RANDOM if grants.random => {}
            LOG => ungranted.push(("log", name)),
            CLOCK => ungranted.push(("clock", name)),
            RANDOM => ungranted.push(("random", name)),
            other => unknown.push(format!("`{other}`")),
        }
    }
    let mut out = Vec::new();
    if !ungranted.is_empty() {
        let names: Vec<String> = ungranted.iter().map(|(_, n)| format!("`{n}`")).collect();
        let caps: Vec<&str> = ungranted.iter().map(|(c, _)| *c).collect();
        out.push(format!(
            "the component imports {}; grant it with `capabilities: [{}]` or rebuild the plugin without it",
            names.join(", "),
            caps.join(", ")
        ));
    }
    if !unknown.is_empty() {
        let wasi = if unknown.iter().any(|n| n.starts_with("`wasi:")) {
            " (rdock gives plugins no WASI: no files, network, environment or clocks; build a `no_std` guest, see the WASM plugins guide)"
        } else {
            ""
        };
        out.push(format!(
            "the component imports {}, which rdock does not provide{wasi}",
            unknown.join(", ")
        ));
    }
    (!out.is_empty()).then(|| out.join("; "))
}

impl Plugin {
    /// Compiles `bytes` (a component, binary or text) and checks it against the `filter`
    /// world and the grants: imports, exports and a trial instantiation within the limits.
    /// Call this only on bytes whose digest and signature were checked
    /// ([`crate::artifact::load`]).
    pub fn compile(bytes: &[u8], settings: &Settings) -> Result<Self, CompileError> {
        let engine = engine()?;
        let component =
            Component::new(engine, bytes).map_err(|e| CompileError::Invalid(format!("{e:#}")))?;
        let ty = component.component_type();
        if let Some(why) = check_imports(ty.imports(engine).map(|(name, _)| name), settings.grants)
        {
            return Err(CompileError::Import(why));
        }
        for export in ["on-request", "on-response"] {
            match ty.get_export(engine, export) {
                Some(ComponentItem::ComponentFunc(_)) => {}
                Some(_) => {
                    return Err(CompileError::Export(format!(
                        "the component's export `{export}` is not a function"
                    )));
                }
                None => {
                    return Err(CompileError::Export(format!(
                        "the component does not export `{export}` (world `rdock:plugin/filter@0.1.0`)"
                    )));
                }
            }
        }
        let mut linker = Linker::<HostState>::new(engine);
        let add = |r: wasmtime::Result<()>| r.map_err(|e| CompileError::Import(format!("{e:#}")));
        add(types::add_to_linker::<_, HasSelf<_>>(&mut linker, |s| s))?;
        add(config::add_to_linker::<_, HasSelf<_>>(&mut linker, |s| s))?;
        if settings.grants.log {
            add(log::add_to_linker::<_, HasSelf<_>>(&mut linker, |s| s))?;
        }
        if settings.grants.clock {
            add(clock::add_to_linker::<_, HasSelf<_>>(&mut linker, |s| s))?;
        }
        if settings.grants.random {
            add(random::add_to_linker::<_, HasSelf<_>>(&mut linker, |s| s))?;
        }
        let pre = linker
            .instantiate_pre(&component)
            .map_err(|e| CompileError::Import(format!("{e:#}")))?;
        let tick_nanos = TICK.as_nanos().max(1);
        let deadline_ticks = u64::try_from(settings.limits.timeout.as_nanos().div_ceil(tick_nanos))
            .unwrap_or(u64::MAX);
        let plugin = Self {
            inner: Arc::new(Inner {
                name: Arc::from(settings.name.as_str()),
                config: Arc::from(settings.config.as_str()),
                limits: settings.limits,
                deadline_ticks: deadline_ticks.saturating_add(1),
                pre,
                instances: AtomicU64::new(0),
            }),
        };
        // A trial run: the memory it starts with fits, its start code finishes, and both
        // exports have the world's types.
        let mut instance = plugin
            .instantiate()
            .map_err(|e| CompileError::Instantiate(e.to_string()))?;
        instance
            .component
            .get_typed_func::<(&types::Facts, &types::Request), (types::RequestAction,)>(
                &mut instance.store,
                "on-request",
            )
            .map_err(|e| CompileError::Export(format!("`on-request`: {e:#}")))?;
        instance
            .component
            .get_typed_func::<(&types::Facts, &types::Response), (Vec<types::ResponseEdit>,)>(
                &mut instance.store,
                "on-response",
            )
            .map_err(|e| CompileError::Export(format!("`on-response`: {e:#}")))?;
        Ok(plugin)
    }

    /// How many instances were created (trial included).
    #[must_use]
    pub fn instances_created(&self) -> u64 {
        self.inner.instances.load(Ordering::Relaxed)
    }

    /// A fresh instance for one request.
    pub fn instantiate(&self) -> Result<Instance, CallError> {
        let inner = &self.inner;
        let engine = inner.pre.engine();
        let mut store = Store::new(
            engine,
            HostState {
                name: inner.name.clone(),
                config: inner.config.clone(),
                memory_max: usize::try_from(inner.limits.memory).unwrap_or(usize::MAX),
                memory_hit: false,
                log_lines: 0,
            },
        );
        store.limiter(|s| s);
        store.epoch_deadline_trap();
        arm(&mut store, inner)?;
        inner.instances.fetch_add(1, Ordering::Relaxed);
        let instance = inner
            .pre
            .instantiate(&mut store)
            .map_err(|e| classify(&store, &e))?;
        Ok(Instance {
            store,
            component: instance,
            plugin: self.inner.clone(),
        })
    }
}

/// Fresh fuel and a fresh deadline for one call.
fn arm(store: &mut Store<HostState>, inner: &Inner) -> Result<(), CallError> {
    store.data_mut().memory_hit = false;
    store
        .set_fuel(inner.limits.fuel)
        .map_err(|e| CallError::Trap(format!("{e:#}")))?;
    store.set_epoch_deadline(inner.deadline_ticks);
    Ok(())
}

fn classify(store: &Store<HostState>, error: &wasmtime::Error) -> CallError {
    if store.data().memory_hit {
        return CallError::Memory;
    }
    match error.downcast_ref::<Trap>() {
        Some(Trap::OutOfFuel) => CallError::Fuel,
        Some(Trap::Interrupt) => CallError::Timeout,
        Some(trap) => CallError::Trap(trap.to_string()),
        None => CallError::Trap(format!("{error:#}")),
    }
}

/// The request's facts as the plugin sees them.
#[derive(Debug, Clone, Copy)]
pub struct Facts<'a> {
    /// The client's address.
    pub client_ip: std::net::IpAddr,
    /// The matched route.
    pub route: &'a str,
    /// The request ID.
    pub request_id: &'a str,
    /// Whether the client uses TLS.
    pub tls: bool,
    /// The authenticated consumer, if any.
    pub consumer: Option<&'a str>,
}

impl Facts<'_> {
    fn guest(&self) -> types::Facts {
        types::Facts {
            client_ip: self.client_ip.to_string(),
            route: self.route.to_owned(),
            request_id: self.request_id.to_owned(),
            tls: self.tls,
            consumer: self.consumer.map(str::to_owned),
        }
    }
}

fn guest_headers(headers: &http::HeaderMap) -> Vec<types::Header> {
    headers
        .iter()
        .map(|(name, value)| types::Header {
            name: name.as_str().to_owned(),
            value: value.as_bytes().to_vec(),
        })
        .collect()
}

fn header(h: &types::Header) -> Result<(HeaderName, HeaderValue), CallError> {
    let name = HeaderName::from_bytes(h.name.as_bytes())
        .map_err(|_| CallError::Invalid(format!("invalid header name {:?}", h.name)))?;
    let value = HeaderValue::from_bytes(&h.value)
        .map_err(|_| CallError::Invalid(format!("invalid value for header `{name}`")))?;
    Ok((name, value))
}

fn head_error(what: &str, e: &api::HeadError) -> CallError {
    CallError::Invalid(format!("{what}: {e}"))
}

/// One request's instance: created for the request phase, kept for the response phase.
pub struct Instance {
    store: Store<HostState>,
    component: wasmtime::component::Instance,
    plugin: Arc<Inner>,
}

impl std::fmt::Debug for Instance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Instance")
            .field("plugin", &self.plugin.name)
            .finish_non_exhaustive()
    }
}

impl Instance {
    /// Runs `on-request`, applies its edits to `req` and returns its reply, if it answered.
    /// On an error nothing is applied.
    pub fn on_request(
        &mut self,
        facts: &Facts<'_>,
        req: &mut api::RequestHead,
    ) -> Result<Option<api::Response>, CallError> {
        let request = types::Request {
            method: req.method().as_str().to_owned(),
            path: req.path().to_owned(),
            query: req.query().map(str::to_owned),
            headers: guest_headers(req.headers()),
        };
        arm(&mut self.store, &self.plugin)?;
        let func = self
            .component
            .get_typed_func::<(&types::Facts, &types::Request), (types::RequestAction,)>(
                &mut self.store,
                "on-request",
            )
            .map_err(|e| CallError::Trap(format!("{e:#}")))?;
        let (action,) = func
            .call(&mut self.store, (&facts.guest(), &request))
            .map_err(|e| classify(&self.store, &e))?;
        func.post_return(&mut self.store)
            .map_err(|e| classify(&self.store, &e))?;
        match action {
            types::RequestAction::Continue(edits) => {
                // Edits apply to a copy so that an invalid one leaves the request untouched.
                let mut edited = req.clone();
                for edit in &edits {
                    apply_request_edit(&mut edited, edit)?;
                }
                *req = edited;
                Ok(None)
            }
            types::RequestAction::Respond(reply) => {
                let status = StatusCode::from_u16(reply.status)
                    .ok()
                    .filter(|s| (200..=599).contains(&s.as_u16()))
                    .ok_or_else(|| {
                        CallError::Invalid(format!("reply status {} is not 200-599", reply.status))
                    })?;
                let mut response = api::Response::new(status);
                for h in &reply.headers {
                    let (name, value) = header(h)?;
                    response = response.with_header(name, value);
                }
                if !reply.body.is_empty() {
                    response = response.with_body(reply.body);
                }
                Ok(Some(response))
            }
        }
    }

    /// Runs `on-response` and applies its edits to `resp`. On an error nothing is applied.
    pub fn on_response(
        &mut self,
        facts: &Facts<'_>,
        resp: &mut api::ResponseHead,
    ) -> Result<(), CallError> {
        let response = types::Response {
            status: resp.status().as_u16(),
            headers: guest_headers(resp.headers()),
        };
        arm(&mut self.store, &self.plugin)?;
        let func = self
            .component
            .get_typed_func::<(&types::Facts, &types::Response), (Vec<types::ResponseEdit>,)>(
                &mut self.store,
                "on-response",
            )
            .map_err(|e| CallError::Trap(format!("{e:#}")))?;
        let (edits,) = func
            .call(&mut self.store, (&facts.guest(), &response))
            .map_err(|e| classify(&self.store, &e))?;
        func.post_return(&mut self.store)
            .map_err(|e| classify(&self.store, &e))?;
        let mut edited = resp.clone();
        for edit in &edits {
            apply_response_edit(&mut edited, edit)?;
        }
        *resp = edited;
        Ok(())
    }
}

fn apply_request_edit(
    req: &mut api::RequestHead,
    edit: &types::RequestEdit,
) -> Result<(), CallError> {
    match edit {
        types::RequestEdit::SetHeader(h) => {
            let (name, value) = header(h)?;
            req.set_header(name, value)
                .map_err(|e| head_error("set-header", &e))
        }
        types::RequestEdit::AppendHeader(h) => {
            let (name, value) = header(h)?;
            req.append_header(name, value)
                .map_err(|e| head_error("append-header", &e))
        }
        types::RequestEdit::RemoveHeader(name) => req
            .remove_header(name.as_str())
            .map(|_| ())
            .map_err(|e| head_error("remove-header", &e)),
        types::RequestEdit::SetPath(path) => {
            req.set_path(path).map_err(|e| head_error("set-path", &e))
        }
        types::RequestEdit::SetQuery(query) => req
            .set_query(query.as_deref())
            .map_err(|e| head_error("set-query", &e)),
    }
}

fn apply_response_edit(
    resp: &mut api::ResponseHead,
    edit: &types::ResponseEdit,
) -> Result<(), CallError> {
    match edit {
        types::ResponseEdit::SetHeader(h) => {
            let (name, value) = header(h)?;
            resp.set_header(name, value)
                .map_err(|e| head_error("set-header", &e))
        }
        types::ResponseEdit::AppendHeader(h) => {
            let (name, value) = header(h)?;
            resp.append_header(name, value)
                .map_err(|e| head_error("append-header", &e))
        }
        types::ResponseEdit::RemoveHeader(name) => resp
            .remove_header(name.as_str())
            .map(|_| ())
            .map_err(|e| head_error("remove-header", &e)),
        types::ResponseEdit::SetStatus(status) => {
            let status = StatusCode::from_u16(*status)
                .map_err(|_| CallError::Invalid(format!("status {status} is not valid")))?;
            resp.set_status(status)
                .map_err(|e| head_error("set-status", &e))
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::testing::{self, Guest};
    use std::time::Instant;

    fn settings(limits: Limits) -> Settings {
        Settings {
            name: "test".into(),
            limits,
            grants: Grants::default(),
            config: "{}".into(),
        }
    }

    fn limits() -> Limits {
        Limits {
            fuel: 10_000_000,
            timeout: Duration::from_millis(100),
            memory: 1024 * 1024,
        }
    }

    fn facts() -> Facts<'static> {
        Facts {
            client_ip: "192.0.2.1".parse().unwrap(),
            route: "r",
            request_id: "id-1",
            tls: false,
            consumer: None,
        }
    }

    fn compile(guest: &Guest<'_>, limits: Limits) -> Result<Plugin, CompileError> {
        Plugin::compile(guest.wat().as_bytes(), &settings(limits))
    }

    fn run_request(
        plugin: &Plugin,
        path: &str,
    ) -> Result<(api::RequestHead, Option<api::Response>), CallError> {
        let mut req = api::RequestHead::get(path).unwrap();
        let mut instance = plugin.instantiate()?;
        let reply = instance.on_request(&facts(), &mut req)?;
        Ok((req, reply))
    }

    #[test]
    fn the_header_plugin_edits_requests_and_responses() {
        let plugin = compile(&Guest::header(), limits()).unwrap();
        let mut req = api::RequestHead::get("/x?a=1").unwrap();
        let mut instance = plugin.instantiate().unwrap();
        assert_eq!(instance.on_request(&facts(), &mut req).unwrap(), None);
        assert_eq!(req.header("x-wasm"), Some("yes"));
        assert!(req.is_changed());
        // The same instance serves the response phase.
        let mut resp = api::ResponseHead::new(StatusCode::OK);
        instance.on_response(&facts(), &mut resp).unwrap();
        assert_eq!(resp.header("x-wasm-response"), Some("yes"));
    }

    #[test]
    fn a_plugin_can_answer() {
        let plugin = compile(&Guest::header(), limits()).unwrap();
        let (req, reply) = run_request(&plugin, "/blocked").unwrap();
        assert!(!req.is_changed());
        let reply = reply.unwrap();
        assert_eq!(reply.status(), StatusCode::FORBIDDEN);
        assert_eq!(reply.headers()["content-type"], "text/plain");
        assert_eq!(reply.body().unwrap().as_ref(), b"denied by wasm\n");
    }

    #[test]
    fn every_request_gets_a_fresh_instance() {
        let plugin = compile(&Guest::header(), limits()).unwrap();
        let trial = plugin.instances_created();
        for _ in 0..3 {
            run_request(&plugin, "/").unwrap();
        }
        assert_eq!(plugin.instances_created(), trial + 3);
    }

    #[test]
    fn fuel_exhaustion_is_reported() {
        let guest = Guest {
            on_request: testing::LOOP,
            ..Guest::default()
        };
        let plugin = compile(
            &guest,
            Limits {
                fuel: 100_000,
                ..limits()
            },
        )
        .unwrap();
        assert_eq!(run_request(&plugin, "/").unwrap_err(), CallError::Fuel);
    }

    #[test]
    fn an_infinite_loop_is_interrupted_at_its_deadline() {
        let guest = Guest {
            on_request: testing::LOOP,
            ..Guest::default()
        };
        let timeout = Duration::from_millis(30);
        let plugin = compile(
            &guest,
            Limits {
                fuel: u64::MAX,
                timeout,
                ..limits()
            },
        )
        .unwrap();
        let started = Instant::now();
        assert_eq!(run_request(&plugin, "/").unwrap_err(), CallError::Timeout);
        let took = started.elapsed();
        assert!(took >= timeout, "{took:?}");
        // Generous: the epoch thread ticks every millisecond, CI machines are slow.
        assert!(took < timeout + Duration::from_millis(500), "{took:?}");
    }

    #[test]
    fn memory_growth_past_the_limit_is_refused() {
        let guest = Guest {
            on_request: testing::GROW,
            ..Guest::default()
        };
        let plugin = compile(&guest, limits()).unwrap();
        assert_eq!(run_request(&plugin, "/").unwrap_err(), CallError::Memory);
        // A module whose initial memory is over the limit is refused when it is loaded.
        let err = compile(
            &Guest::header(),
            Limits {
                memory: 1024,
                ..limits()
            },
        )
        .unwrap_err();
        assert!(matches!(err, CompileError::Instantiate(_)), "{err}");
    }

    #[test]
    fn a_trap_is_an_error() {
        let guest = Guest {
            on_request: testing::TRAP,
            on_response: testing::TRAP,
            ..Guest::default()
        };
        let plugin = compile(&guest, limits()).unwrap();
        assert!(matches!(run_request(&plugin, "/"), Err(CallError::Trap(_))));
        let mut instance = plugin.instantiate().unwrap();
        let mut resp = api::ResponseHead::new(StatusCode::OK);
        assert!(matches!(
            instance.on_response(&facts(), &mut resp),
            Err(CallError::Trap(_))
        ));
        assert!(!resp.is_changed());
    }

    #[test]
    fn protected_headers_cannot_be_set() {
        let body = HEADER_ON_REQUEST_CONTENT_LENGTH;
        let guest = Guest {
            on_request: body,
            ..Guest::default()
        };
        let plugin = compile(&guest, limits()).unwrap();
        let err = run_request(&plugin, "/").unwrap_err();
        assert!(matches!(err, CallError::Invalid(_)), "{err}");
        assert!(err.to_string().contains("content-length"), "{err}");
    }

    /// `set-header content-length: yes`.
    const HEADER_ON_REQUEST_CONTENT_LENGTH: &str = r"
        (i32.store8 (i32.const 512) (i32.const 0))
        (i32.store (i32.const 516) (i32.const 640))
        (i32.store (i32.const 520) (i32.const 1))
        (i32.store8 (i32.const 640) (i32.const 0))
        (i32.store (i32.const 644) (i32.const 80))
        (i32.store (i32.const 648) (i32.const 14))
        (i32.store (i32.const 652) (i32.const 32))
        (i32.store (i32.const 656) (i32.const 3))
        (i32.const 512)
    ";

    const CLOCK_IMPORT: &str = r#"
        (import "rdock:plugin/clock@0.1.0" (instance $clock (export "now-ms" (func (result u64)))))
        (core func $now (canon lower (func $clock "now-ms")))
        (core instance $env (export "now" (func $now)))
    "#;

    #[test]
    fn capabilities_must_be_granted() {
        let guest = Guest {
            imports: CLOCK_IMPORT,
            core_imports: r#"(import "env" "now" (func $now (result i64)))"#,
            on_request: "(drop (call $now)) (i32.store8 (i32.const 512) (i32.const 0)) (i32.store (i32.const 520) (i32.const 0)) (i32.const 512)",
            ..Guest::default()
        };
        let err = compile(&guest, limits()).unwrap_err();
        assert!(matches!(err, CompileError::Import(_)), "{err}");
        assert!(err.to_string().contains("capabilities: [clock]"), "{err}");
        let mut granted = settings(limits());
        granted.grants.clock = true;
        let plugin = Plugin::compile(guest.wat().as_bytes(), &granted).unwrap();
        run_request(&plugin, "/").unwrap();
    }

    #[test]
    fn wasi_and_unknown_imports_are_refused() {
        let guest = Guest {
            imports: r#"
                (import "wasi:cli/environment@0.2.0" (instance $wasi (export "get-arguments" (func))))
                (core func $f (canon lower (func $wasi "get-arguments")))
                (core instance $env (export "f" (func $f)))
            "#,
            core_imports: r#"(import "env" "f" (func))"#,
            ..Guest::default()
        };
        let err = compile(&guest, limits()).unwrap_err();
        assert!(
            err.to_string().contains("`wasi:cli/environment@0.2.0`"),
            "{err}"
        );
        assert!(err.to_string().contains("no WASI"), "{err}");
    }

    #[test]
    fn core_modules_and_missing_exports_are_refused() {
        let err = Plugin::compile(b"(module)", &settings(limits())).unwrap_err();
        assert!(matches!(err, CompileError::Invalid(_)), "{err}");
        let err = Plugin::compile(b"(component)", &settings(limits())).unwrap_err();
        assert!(matches!(err, CompileError::Export(_)), "{err}");
        assert!(err.to_string().contains("on-request"), "{err}");
    }
}
