//! `agent`: asks an out-of-process service (a WAF, a policy engine) whether a request may
//! continue (F-EXT-04, ADR-0030).
//!
//! Two protocols share one middleware:
//! - `rdock`: a `POST` of a JSON document describing the request (`schema/agent.v1.json`);
//!   the agent answers a JSON verdict.
//! - `forward`: the request is replayed to the agent as an ordinary HTTP request (same method,
//!   path, query, the allowed headers and the body); a 2xx allows, any other answer is sent
//!   to the client. A WAF reverse-proxy image understands this.
//!
//! The body goes to the agent through the proxy's held-body mechanism, so nothing of it
//! reaches the backend before the verdict. A request without a body (or whose body is not
//! sent: `max_body: 0`, or `on_oversize: skip` with a declared length above `max_body`) is
//! decided in the `request` phase, before the backend is even chosen; a request with a body
//! is decided in `request_body`, when the backend already has the request head. The agent's
//! header changes can only be applied in the first case.
//!
//! Failures (unreachable, timeout, an invalid answer) follow `on_error` (default `deny`: fail
//! closed) and feed a circuit breaker; while it is open, `on_error` applies without calling.

use std::fmt;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use base64::Engine;
use bytes::Bytes;
use http::Method;
use http::header::{HeaderName, HeaderValue};
use pingora::http::RequestHeader;
use rdock_model::middleware::{
    AgentBreaker, AgentConfig, AgentOnError, AgentOversize, AgentProtocol,
};
use serde::Deserialize;
use url::Url;

use crate::client::{ClientTls, FetchError, Fetched, HttpClient};
use crate::held::HeldBody;
use crate::phase::{BodyHold, BodyVerdict, Capabilities};
use crate::{Body, BuildEnv, BuildError, Context, Flow, Middleware, Reply};

/// Largest agent answer read (a verdict document, or the refusal sent to the client).
const MAX_ANSWER: usize = 1024 * 1024;

/// Headers sent to the agent by default (an allow-list: no credentials).
const DEFAULT_HEADERS: [&str; 8] = [
    "accept",
    "accept-encoding",
    "accept-language",
    "cache-control",
    "content-type",
    "origin",
    "referer",
    "user-agent",
];

/// Headers never sent to the agent from the client (framing and hop-by-hop; rdock sets its
/// own `Host`, `Content-Length` and forwarding headers).
const NEVER_SENT: [&str; 11] = [
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "content-length",
    "host",
    "http2-settings",
    "expect",
];

/// Response headers of a refusal passed on to the client.
const REFUSAL_HEADERS: [&str; 7] = [
    "content-type",
    "content-language",
    "cache-control",
    "location",
    "retry-after",
    "www-authenticate",
    "x-request-id",
];

/// Response headers a JSON verdict may not set on the client's answer.
const FRAMING: [&str; 8] = [
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "content-length",
];

// -- the circuit breaker ----------------------------------------------------------------------

/// Whether a call may go to the agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Admission {
    /// Closed: call.
    Call,
    /// Half open: this call is the trial.
    Trial,
    /// Open: do not call.
    Open,
}

#[derive(Debug, Default)]
struct BreakerState {
    failures: u32,
    first_failure: Option<Instant>,
    open_until: Option<Instant>,
    trial_since: Option<Instant>,
}

/// Opens after `failures` failed calls in a row within `window`; stays open `open_for`; then
/// lets one trial call through.
#[derive(Debug)]
struct Breaker {
    config: AgentBreaker,
    /// A trial that never reported back (its request was cancelled) is forgotten after this.
    trial_timeout: Duration,
    state: Mutex<BreakerState>,
    gauge: Option<rdock_observability::IntGauge>,
}

impl Breaker {
    fn new(
        config: AgentBreaker,
        timeout: Duration,
        gauge: Option<rdock_observability::IntGauge>,
    ) -> Self {
        if let Some(gauge) = &gauge {
            gauge.set(0);
        }
        Self {
            config,
            trial_timeout: timeout.saturating_mul(2),
            state: Mutex::new(BreakerState::default()),
            gauge,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BreakerState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn admit(&self, now: Instant) -> Admission {
        if self.config.failures == 0 {
            return Admission::Call;
        }
        let mut state = self.lock();
        match state.open_until {
            None => Admission::Call,
            Some(until) if now < until => Admission::Open,
            Some(_) => {
                let trial_lost = state
                    .trial_since
                    .is_none_or(|since| now.duration_since(since) > self.trial_timeout);
                if trial_lost {
                    state.trial_since = Some(now);
                    Admission::Trial
                } else {
                    Admission::Open
                }
            }
        }
    }

    fn success(&self) {
        if self.config.failures == 0 {
            return;
        }
        let mut state = self.lock();
        let was_open = state.open_until.is_some();
        *state = BreakerState::default();
        drop(state);
        if was_open {
            tracing::info!("an agent answered again; its circuit breaker is closed");
        }
        if let Some(gauge) = &self.gauge {
            gauge.set(0);
        }
    }

    fn failure(&self, now: Instant) {
        if self.config.failures == 0 {
            return;
        }
        let mut state = self.lock();
        if state.open_until.is_some() {
            // The trial failed (or a call admitted before the breaker opened): stay open.
            state.open_until = Some(now + self.config.open_for.as_std());
            state.trial_since = None;
            return;
        }
        let within = state
            .first_failure
            .is_some_and(|first| now.duration_since(first) <= self.config.window.as_std());
        if within {
            state.failures += 1;
        } else {
            state.first_failure = Some(now);
            state.failures = 1;
        }
        if state.failures >= self.config.failures {
            state.open_until = Some(now + self.config.open_for.as_std());
            drop(state);
            if let Some(gauge) = &self.gauge {
                gauge.set(1);
            }
        }
    }
}

// -- the request as the agent sees it --------------------------------------------------------

/// The request head kept from the `request` phase for a decision in `request_body`.
#[derive(Debug, Clone)]
struct Snapshot {
    method: Method,
    /// Path and query as the client sent them (after earlier middlewares).
    target: String,
    version: http::Version,
    headers: Vec<(HeaderName, HeaderValue)>,
    authority: String,
    client_ip: IpAddr,
    tls: bool,
    route: Arc<str>,
    request_id: Arc<str>,
}

/// The JSON document of `protocol: rdock` (`schema/agent.v1.json`).
#[derive(serde::Serialize)]
struct Document<'a> {
    version: u8,
    request: DocRequest<'a>,
    client: DocClient,
    route: &'a str,
    request_id: &'a str,
    body: Option<DocBody>,
    body_skipped: bool,
}

#[derive(serde::Serialize)]
struct DocRequest<'a> {
    method: &'a str,
    path: &'a str,
    query: Option<&'a str>,
    http_version: &'static str,
    host: &'a str,
    scheme: &'static str,
    headers: Vec<(&'a str, String)>,
}

#[derive(serde::Serialize)]
struct DocClient {
    ip: String,
    tls: bool,
}

#[derive(serde::Serialize)]
struct DocBody {
    length: usize,
    base64: String,
}

/// Header values in a verdict: one string or a list of strings.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Values {
    One(String),
    Many(Vec<String>),
}

impl Values {
    fn iter(&self) -> impl Iterator<Item = &str> {
        let (one, many): (Option<&str>, &[String]) = match self {
            Self::One(v) => (Some(v.as_str()), &[]),
            Self::Many(v) => (None, v.as_slice()),
        };
        one.into_iter().chain(many.iter().map(String::as_str))
    }
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Action {
    Allow,
    Deny,
}

/// A JSON verdict of `protocol: rdock`. Unknown fields are ignored.
#[derive(Debug, Deserialize)]
struct VerdictDoc {
    action: Action,
    #[serde(default)]
    status: Option<u16>,
    #[serde(default)]
    headers: std::collections::BTreeMap<String, Values>,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    set_request_headers: std::collections::BTreeMap<String, Values>,
}

/// What the agent decided.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Verdict {
    /// Continue, with these headers for the upstream request (already filtered).
    Allow(Vec<(HeaderName, HeaderValue)>),
    /// Answer the client.
    Deny(Reply),
}

/// Why a call failed.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Failure {
    Timeout,
    Error(String),
}

/// Parses a JSON verdict; header changes outside `allowed` are dropped and reported.
fn parse_verdict(
    body: &[u8],
    allowed: &[HeaderName],
    ignored: &mut Vec<(&'static str, String)>,
) -> Result<Verdict, String> {
    let doc: VerdictDoc =
        serde_json::from_slice(body).map_err(|e| format!("invalid verdict: {e}"))?;
    match doc.action {
        Action::Allow => {
            let mut out = Vec::new();
            for (name, values) in &doc.set_request_headers {
                let Ok(header) = HeaderName::from_bytes(name.as_bytes()) else {
                    ignored.push(("invalid", name.clone()));
                    continue;
                };
                if !allowed.contains(&header) {
                    ignored.push(("not_allowed", name.clone()));
                    continue;
                }
                for value in values.iter() {
                    match HeaderValue::from_str(value) {
                        Ok(v) => out.push((header.clone(), v)),
                        Err(_) => ignored.push(("invalid", name.clone())),
                    }
                }
            }
            Ok(Verdict::Allow(out))
        }
        Action::Deny => {
            let status = doc.status.unwrap_or(403);
            if !(200..=599).contains(&status) {
                return Err(format!(
                    "invalid verdict: status {status} is not 200 to 599"
                ));
            }
            let mut headers = Vec::new();
            for (name, values) in &doc.headers {
                let header = HeaderName::from_bytes(name.as_bytes())
                    .map_err(|_| format!("invalid verdict: `{name}` is not a header name"))?;
                if FRAMING.contains(&header.as_str()) {
                    continue;
                }
                for value in values.iter() {
                    let value = HeaderValue::from_str(value).map_err(|_| {
                        format!("invalid verdict: the value of `{name}` is not a header value")
                    })?;
                    headers.push((header.clone(), value));
                }
            }
            Ok(Verdict::Deny(Reply {
                status,
                headers,
                body: doc.body.map(|b| Body::Bytes(Bytes::from(b))),
            }))
        }
    }
}

/// Which of the client's headers go to the agent.
#[derive(Debug, Clone)]
struct HeaderPolicy {
    all: bool,
    extra: Vec<HeaderName>,
}

impl HeaderPolicy {
    fn sends(&self, name: &HeaderName) -> bool {
        if NEVER_SENT.contains(&name.as_str()) {
            return false;
        }
        self.all || DEFAULT_HEADERS.contains(&name.as_str()) || self.extra.contains(name)
    }
}

// -- the middleware ---------------------------------------------------------------------------

/// The `agent` middleware.
pub(crate) struct Agent {
    name: Arc<str>,
    address: Url,
    protocol: AgentProtocol,
    timeout: Duration,
    on_error: AgentOnError,
    max_body: u64,
    on_oversize: AgentOversize,
    headers: HeaderPolicy,
    settable: Vec<HeaderName>,
    breaker: Breaker,
    tls: ClientTls,
    client: Arc<HttpClient>,
    metrics: Option<rdock_observability::Metrics>,
}

impl fmt::Debug for Agent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Agent")
            .field("name", &self.name)
            .field("address", &self.address.as_str())
            .field("protocol", &self.protocol)
            .field("max_body", &self.max_body)
            .finish_non_exhaustive()
    }
}

fn header_names(list: &[String]) -> Result<Vec<HeaderName>, BuildError> {
    list.iter()
        .filter(|n| *n != "*")
        .map(|n| {
            HeaderName::from_bytes(n.as_bytes())
                .map_err(|_| BuildError::Invalid(format!("`{n}` is not a valid header name")))
        })
        .collect()
}

impl Agent {
    pub(crate) fn new(
        name: &str,
        config: &AgentConfig,
        env: &BuildEnv<'_>,
    ) -> Result<Self, BuildError> {
        let tls = match &config.tls {
            Some(tls) => ClientTls::load(tls).map_err(BuildError::Invalid)?,
            None => ClientTls::default(),
        };
        let metrics = env.metrics.cloned();
        let gauge = metrics
            .as_ref()
            .map(|m| m.agent_breaker_open.with_label_values(&[name]));
        Ok(Self {
            name: Arc::from(name),
            address: config.address.as_url().clone(),
            protocol: config.protocol,
            timeout: config.timeout.as_std(),
            on_error: config.on_error,
            max_body: config.max_body.as_u64(),
            on_oversize: config.on_oversize,
            headers: HeaderPolicy {
                all: config.request_headers.iter().any(|h| h == "*"),
                extra: header_names(&config.request_headers)?,
            },
            settable: header_names(&config.response_headers)?,
            breaker: Breaker::new(config.breaker, config.timeout.as_std(), gauge),
            tls,
            client: env.client.clone(),
            metrics,
        })
    }

    fn count(&self, result: &str) {
        if let Some(m) = &self.metrics {
            m.agent_requests
                .with_label_values(&[&*self.name, result])
                .inc();
        }
    }

    fn count_ignored(&self, reason: &str, by: u64) {
        if let (Some(m), true) = (&self.metrics, by > 0) {
            m.agent_ignored_headers
                .with_label_values(&[&*self.name, reason])
                .inc_by(by);
        }
    }

    fn snapshot(&self, req: &RequestHeader, cx: &Context) -> Snapshot {
        Snapshot {
            method: req.method.clone(),
            target: req
                .uri
                .path_and_query()
                .map_or("/", |p| p.as_str())
                .to_owned(),
            version: req.version,
            headers: req
                .headers
                .iter()
                .filter(|(name, _)| self.headers.sends(name))
                .map(|(n, v)| (n.clone(), v.clone()))
                .collect(),
            authority: cx.authority.clone(),
            client_ip: cx.client_ip,
            tls: cx.tls,
            route: cx.route.clone(),
            request_id: cx.request_id.clone(),
        }
    }

    /// Asks the agent (or applies `on_error` when the breaker is open or the call fails).
    async fn consult(&self, snap: &Snapshot, body: Option<Bytes>, skipped: bool) -> Verdict {
        if !matches!(self.protocol, AgentProtocol::Rdock | AgentProtocol::Forward) {
            // Planned protocols: the gate refuses them for `rdock run` (ADR-0014); built only
            // for `rdock validate`, and never lets a request through.
            return Verdict::Deny(Reply::status(501));
        }
        let now = Instant::now();
        let admission = self.breaker.admit(now);
        if admission == Admission::Open {
            self.count("breaker_open");
            return self.on_failure(&Failure::Error("circuit breaker open".into()), 503);
        }
        let started = Instant::now();
        let answer = tokio::time::timeout(self.timeout, self.call(snap, body, skipped)).await;
        if let Some(m) = &self.metrics {
            m.agent_duration
                .with_label_values(&[&self.name])
                .observe(started.elapsed().as_secs_f64());
        }
        let outcome = match answer {
            Err(_) | Ok(Err(FetchError::Timeout)) => Err(Failure::Timeout),
            Ok(Err(e)) => Err(Failure::Error(e.to_string())),
            Ok(Ok(fetched)) => self.interpret(fetched),
        };
        match outcome {
            Ok(verdict) => {
                self.breaker.success();
                self.count(match verdict {
                    Verdict::Allow(_) => "allow",
                    Verdict::Deny(_) => "deny",
                });
                verdict
            }
            Err(failure) => {
                self.breaker.failure(Instant::now());
                let (result, status) = match failure {
                    Failure::Timeout => ("timeout", 504),
                    Failure::Error(_) => ("error", 502),
                };
                self.count(result);
                self.on_failure(&failure, status)
            }
        }
    }

    fn on_failure(&self, failure: &Failure, status: u16) -> Verdict {
        let why = match failure {
            Failure::Timeout => "timed out".to_owned(),
            Failure::Error(e) => e.clone(),
        };
        match self.on_error {
            AgentOnError::Deny => {
                tracing::warn!(agent = %self.name, address = %self.address, error = %why, status, "the agent did not answer; the request is refused (on_error: deny)");
                Verdict::Deny(Reply::status(status))
            }
            AgentOnError::Allow => {
                tracing::warn!(agent = %self.name, address = %self.address, error = %why, "the agent did not answer; the request passes unchecked (on_error: allow)");
                Verdict::Allow(Vec::new())
            }
        }
    }

    /// Reads the agent's answer.
    #[allow(
        clippy::single_match_else,
        reason = "one arm per protocol; more are planned"
    )]
    fn interpret(&self, fetched: Fetched) -> Result<Verdict, Failure> {
        let status = fetched.header.status.as_u16();
        match self.protocol {
            AgentProtocol::Forward => {
                if (200..300).contains(&status) {
                    let mut headers = Vec::new();
                    for name in &self.settable {
                        for value in fetched.header.headers.get_all(name) {
                            headers.push((name.clone(), value.clone()));
                        }
                    }
                    return Ok(Verdict::Allow(headers));
                }
                let headers = fetched
                    .header
                    .headers
                    .iter()
                    .filter(|(name, _)| REFUSAL_HEADERS.contains(&name.as_str()))
                    .map(|(name, value)| (name.clone(), value.clone()))
                    .collect();
                Ok(Verdict::Deny(Reply {
                    status,
                    headers,
                    body: Some(Body::Bytes(fetched.body)),
                }))
            }
            _ => {
                if status != 200 {
                    return Err(Failure::Error(format!(
                        "the agent answered {status}, not 200 with a verdict"
                    )));
                }
                let mut ignored = Vec::new();
                let verdict = parse_verdict(&fetched.body, &self.settable, &mut ignored)
                    .map_err(Failure::Error)?;
                for (reason, name) in &ignored {
                    tracing::debug!(agent = %self.name, header = %name, reason, "ignored a header from the agent");
                    self.count_ignored(reason, 1);
                }
                Ok(verdict)
            }
        }
    }

    /// The HTTP exchange with the agent.
    #[allow(
        clippy::single_match_else,
        reason = "one arm per protocol; more are planned"
    )]
    async fn call(
        &self,
        snap: &Snapshot,
        body: Option<Bytes>,
        skipped: bool,
    ) -> Result<Fetched, FetchError> {
        let peer = self
            .client
            .peer_with(&self.address, self.timeout, &self.tls)
            .await?;
        let agent_host = match (self.address.host_str(), self.address.port()) {
            (Some(h), Some(p)) => format!("{h}:{p}"),
            (Some(h), None) => h.to_owned(),
            (None, _) => return Err(FetchError::Resolve(self.address.to_string())),
        };
        let failed = |e: Box<pingora::Error>| FetchError::Connect(e.to_string());
        let (req, payload) = match self.protocol {
            AgentProtocol::Forward => {
                let base = self.address.path().trim_end_matches('/');
                let target = format!("{base}{}", snap.target);
                let mut req = RequestHeader::build(snap.method.clone(), target.as_bytes(), None)
                    .map_err(failed)?;
                for (name, value) in &snap.headers {
                    req.append_header(name.clone(), value.clone())
                        .map_err(failed)?;
                }
                let proto = if snap.tls { "https" } else { "http" };
                let host = if snap.authority.is_empty() {
                    agent_host.as_str()
                } else {
                    snap.authority.as_str()
                };
                req.insert_header(http::header::HOST, host)
                    .map_err(failed)?;
                req.insert_header("x-forwarded-for", snap.client_ip.to_string())
                    .map_err(failed)?;
                req.insert_header("x-forwarded-proto", proto)
                    .map_err(failed)?;
                req.insert_header("x-forwarded-host", snap.authority.as_str())
                    .map_err(failed)?;
                req.insert_header("x-request-id", &*snap.request_id)
                    .map_err(failed)?;
                if skipped {
                    req.insert_header("x-rdock-body-skipped", "1")
                        .map_err(failed)?;
                }
                (req, body)
            }
            _ => {
                let target = match self.address.query() {
                    Some(q) => format!("{}?{q}", self.address.path()),
                    None => self.address.path().to_owned(),
                };
                let mut req =
                    RequestHeader::build(Method::POST, target.as_bytes(), None).map_err(failed)?;
                req.insert_header(http::header::HOST, agent_host.as_str())
                    .map_err(failed)?;
                req.insert_header(http::header::CONTENT_TYPE, "application/json")
                    .map_err(failed)?;
                req.insert_header(http::header::ACCEPT, "application/json")
                    .map_err(failed)?;
                req.insert_header("x-request-id", &*snap.request_id)
                    .map_err(failed)?;
                let document = document(snap, body.as_ref(), skipped);
                (req, Some(Bytes::from(document)))
            }
        };
        match payload {
            Some(data) if !data.is_empty() || self.protocol != AgentProtocol::Forward => {
                let mut req = req;
                req.insert_header(http::header::CONTENT_LENGTH, data.len())
                    .map_err(failed)?;
                self.client
                    .send_with_body(&peer, req, data, self.timeout, MAX_ANSWER)
                    .await
                    .map(|(fetched, _)| fetched)
            }
            _ => self.client.send(&peer, req, self.timeout, MAX_ANSWER).await,
        }
    }

    /// Applies an allowed verdict's headers to the request (before its head leaves).
    fn apply(&self, headers: &[(HeaderName, HeaderValue)], req: &mut RequestHeader) {
        for name in &self.settable {
            if headers.iter().any(|(n, _)| n == name) {
                req.remove_header(name);
            }
        }
        for (name, value) in headers {
            let _ = req.append_header(name.clone(), value.clone());
        }
    }
}

/// The `protocol: rdock` document.
fn document(snap: &Snapshot, body: Option<&Bytes>, skipped: bool) -> Vec<u8> {
    let (path, query) = match snap.target.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (snap.target.as_str(), None),
    };
    let version = match snap.version {
        http::Version::HTTP_09 => "HTTP/0.9",
        http::Version::HTTP_10 => "HTTP/1.0",
        http::Version::HTTP_2 => "HTTP/2",
        http::Version::HTTP_3 => "HTTP/3",
        _ => "HTTP/1.1",
    };
    let doc = Document {
        version: 1,
        request: DocRequest {
            method: snap.method.as_str(),
            path,
            query,
            http_version: version,
            host: &snap.authority,
            scheme: if snap.tls { "https" } else { "http" },
            headers: snap
                .headers
                .iter()
                .map(|(n, v)| {
                    (
                        n.as_str(),
                        String::from_utf8_lossy(v.as_bytes()).into_owned(),
                    )
                })
                .collect(),
        },
        client: DocClient {
            ip: snap.client_ip.to_string(),
            tls: snap.tls,
        },
        route: &snap.route,
        request_id: &snap.request_id,
        body: body.map(|b| DocBody {
            length: b.len(),
            base64: base64::engine::general_purpose::STANDARD.encode(b),
        }),
        body_skipped: skipped,
    };
    serde_json::to_vec(&doc).unwrap_or_default()
}

/// The `Content-Length` of a request, if valid.
fn declared_length(req: &RequestHeader) -> Option<u64> {
    req.headers
        .get(http::header::CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .trim()
        .parse()
        .ok()
}

#[async_trait]
impl Middleware for Agent {
    fn capabilities(&self) -> Capabilities {
        if self.max_body == 0 {
            Capabilities::DEFAULT
        } else {
            Capabilities::DEFAULT
                .with_state()
                .with_body(BodyHold::new(self.max_body))
        }
    }

    async fn request(&self, req: &mut RequestHeader, cx: &mut Context) -> Flow {
        // Client copies of the headers the agent may set are never trusted, whenever the
        // verdict comes.
        for name in &self.settable {
            req.remove_header(name);
        }
        let mut skipped = false;
        if cx.has_body && self.max_body > 0 {
            match declared_length(req) {
                Some(length) if length > self.max_body => match self.on_oversize {
                    AgentOversize::Reject => {
                        self.count("oversize");
                        return Flow::Reply(Reply::status(413));
                    }
                    AgentOversize::Skip => {
                        cx.waive_body_hold();
                        skipped = true;
                    }
                },
                _ => {
                    // Decided when the body is complete (`request_body`).
                    cx.set_state(self.snapshot(req, cx));
                    return Flow::Next;
                }
            }
        }
        let snap = self.snapshot(req, cx);
        match self.consult(&snap, None, skipped && cx.has_body).await {
            Verdict::Allow(headers) => {
                self.apply(&headers, req);
                Flow::Next
            }
            Verdict::Deny(reply) => Flow::Reply(reply),
        }
    }

    async fn request_body(&self, body: &HeldBody, cx: &mut Context) -> BodyVerdict {
        let Some(snap) = cx.take_state::<Snapshot>() else {
            return BodyVerdict::Continue;
        };
        let bytes = match body.bytes().await {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::error!(agent = %self.name, error = %e, "reading a held body failed");
                return BodyVerdict::Reply(Reply::status(500));
            }
        };
        match self.consult(&snap, Some(bytes), false).await {
            Verdict::Allow(headers) => {
                if !headers.is_empty() {
                    tracing::debug!(agent = %self.name, "headers from the agent came after the request head left; not applied");
                    self.count_ignored("too_late", headers.len() as u64);
                }
                BodyVerdict::Continue
            }
            Verdict::Deny(reply) => BodyVerdict::Reply(reply),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn names(list: &[&'static str]) -> Vec<HeaderName> {
        list.iter().map(|n| HeaderName::from_static(n)).collect()
    }

    #[test]
    fn verdicts_parse_and_filter_header_changes() {
        let mut ignored = Vec::new();
        let allowed = names(&["x-user"]);
        let verdict = parse_verdict(
            br#"{"action":"allow","set_request_headers":{"x-user":"alice","x-admin":"yes","bad name":"x"},"future":1}"#,
            &allowed,
            &mut ignored,
        )
        .unwrap();
        assert_eq!(
            verdict,
            Verdict::Allow(vec![(
                HeaderName::from_static("x-user"),
                HeaderValue::from_static("alice")
            )])
        );
        assert_eq!(
            ignored,
            [
                ("invalid", "bad name".to_owned()),
                ("not_allowed", "x-admin".to_owned())
            ]
        );

        let verdict = parse_verdict(
            br#"{"action":"deny","status":429,"headers":{"retry-after":"5","content-length":"1","set-cookie":["a=1","b=2"]},"body":"slow down"}"#,
            &allowed,
            &mut ignored,
        )
        .unwrap();
        let Verdict::Deny(reply) = verdict else {
            panic!("deny");
        };
        assert_eq!(reply.status, 429);
        let headers: Vec<_> = reply
            .headers
            .iter()
            .map(|(n, v)| (n.as_str(), v.to_str().unwrap()))
            .collect();
        assert_eq!(
            headers,
            [
                ("retry-after", "5"),
                ("set-cookie", "a=1"),
                ("set-cookie", "b=2")
            ]
        );
        assert_eq!(
            crate::test_support::reply_bytes(&reply),
            Some(&b"slow down"[..])
        );

        let deny = parse_verdict(br#"{"action":"deny"}"#, &allowed, &mut ignored).unwrap();
        assert_eq!(
            deny,
            Verdict::Deny(Reply {
                status: 403,
                headers: vec![],
                body: None
            })
        );
        for bad in [
            &br#"{"action":"maybe"}"#[..],
            br#"{"status":403}"#,
            br#"{"action":"deny","status":99}"#,
            br#"{"action":"deny","headers":{"x":"a\nb"}}"#,
            b"not json",
        ] {
            assert!(
                parse_verdict(bad, &allowed, &mut ignored).is_err(),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn only_allowed_headers_go_to_the_agent() {
        let default = HeaderPolicy {
            all: false,
            extra: Vec::new(),
        };
        assert!(default.sends(&HeaderName::from_static("user-agent")));
        assert!(!default.sends(&http::header::AUTHORIZATION));
        assert!(!default.sends(&http::header::COOKIE));
        assert!(!default.sends(&http::header::HOST));
        let listed = HeaderPolicy {
            all: false,
            extra: names(&["cookie"]),
        };
        assert!(listed.sends(&http::header::COOKIE));
        assert!(!listed.sends(&http::header::AUTHORIZATION));
        let all = HeaderPolicy {
            all: true,
            extra: Vec::new(),
        };
        assert!(all.sends(&http::header::AUTHORIZATION));
        assert!(!all.sends(&http::header::TRANSFER_ENCODING));
        assert!(!all.sends(&http::header::CONTENT_LENGTH));
    }

    #[test]
    fn the_breaker_opens_after_failures_in_a_window_and_tries_again_later() {
        let config = AgentBreaker {
            failures: 3,
            window: rdock_model::values::Duration::from_secs(10),
            open_for: rdock_model::values::Duration::from_secs(30),
        };
        let breaker = Breaker::new(config, Duration::from_secs(1), None);
        let t0 = Instant::now();
        breaker.failure(t0);
        breaker.failure(t0 + Duration::from_secs(1));
        assert_eq!(breaker.admit(t0 + Duration::from_secs(2)), Admission::Call);
        // A failure outside the window starts counting again.
        breaker.failure(t0 + Duration::from_secs(20));
        assert_eq!(breaker.admit(t0 + Duration::from_secs(20)), Admission::Call);
        breaker.failure(t0 + Duration::from_secs(21));
        breaker.failure(t0 + Duration::from_secs(22));
        assert_eq!(breaker.admit(t0 + Duration::from_secs(23)), Admission::Open);
        // After open_for: one trial, others wait.
        let later = t0 + Duration::from_secs(60);
        assert_eq!(breaker.admit(later), Admission::Trial);
        assert_eq!(breaker.admit(later), Admission::Open);
        // A failed trial opens it again; a lost trial is retried after twice the timeout.
        breaker.failure(later);
        assert_eq!(
            breaker.admit(later + Duration::from_secs(29)),
            Admission::Open
        );
        let again = later + Duration::from_secs(31);
        assert_eq!(breaker.admit(again), Admission::Trial);
        assert_eq!(
            breaker.admit(again + Duration::from_secs(3)),
            Admission::Trial
        );
        breaker.success();
        assert_eq!(
            breaker.admit(again + Duration::from_secs(3)),
            Admission::Call
        );
        // `failures: 0` turns it off.
        let off = Breaker::new(
            AgentBreaker {
                failures: 0,
                ..config
            },
            Duration::from_secs(1),
            None,
        );
        for _ in 0..10 {
            off.failure(t0);
        }
        assert_eq!(off.admit(t0), Admission::Call);
    }

    #[test]
    fn the_document_describes_the_request() {
        let snap = Snapshot {
            method: Method::POST,
            target: "/login?next=%2F".into(),
            version: http::Version::HTTP_2,
            headers: vec![(
                HeaderName::from_static("user-agent"),
                HeaderValue::from_static("t"),
            )],
            authority: "app.example.com".into(),
            client_ip: "192.0.2.4".parse().unwrap(),
            tls: true,
            route: Arc::from("app"),
            request_id: Arc::from("id-1"),
        };
        let doc: serde_json::Value =
            serde_json::from_slice(&document(&snap, Some(&Bytes::from_static(b"a=1")), false))
                .unwrap();
        assert_eq!(
            doc,
            serde_json::json!({
                "version": 1,
                "request": {
                    "method": "POST", "path": "/login", "query": "next=%2F",
                    "http_version": "HTTP/2", "host": "app.example.com", "scheme": "https",
                    "headers": [["user-agent", "t"]]
                },
                "client": { "ip": "192.0.2.4", "tls": true },
                "route": "app", "request_id": "id-1",
                "body": { "length": 3, "base64": "YT0x" },
                "body_skipped": false
            })
        );
    }
}
