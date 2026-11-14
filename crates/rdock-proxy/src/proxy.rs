//! The Pingora `ProxyHttp` implementation: limits, client IP, routing, middlewares, upstream
//! selection, error pages, access log and metrics.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderName, HeaderValue, Version};
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::modules::http::HttpModules;
use pingora::protocols::http::bridge::grpc_web::GrpcWebCtx;
use pingora::proxy::{FailToProxy, ProxyHttp, Session};
use pingora::upstreams::peer::HttpPeer;
use pingora::{Error, ErrorSource, ErrorType};
use rdock_balancer::{Ejection, RetryPermit};
use rdock_cache::pingora_types::{
    CacheKey, CacheMeta, ForcedFreshness, HashBinary, HitHandler, NoCacheReason, RespCacheable,
};
use rdock_middleware::{
    Answered, Body, BodyHolder, Chain, Context as MwContext, HoldError, LogSummary, Released,
    Reply, Upstream,
};
use rdock_model::service::{LatencyMeasure, RetryOn};
use rdock_observability::{AccessRecord, Metrics, rfc3339};

use crate::errorpage;
use crate::forwarded::{self, Forwarding};
use crate::router::{Facts, normalize_host};
use crate::runtime::{
    Candidate, ListenerRuntime, Member, MirrorRuntime, RouteRuntime, Runtime, ServiceRuntime,
};
use crate::upstream;

/// `X-Content-Type-Options` of every answer rdock writes itself (its error pages, redirects,
/// middleware and `respond` bodies): clients must not guess another type than the one sent.
const NOSNIFF: &str = "nosniff";

/// State shared by every listener.
#[derive(Debug)]
pub struct Shared {
    /// The configuration being served.
    pub runtime: ArcSwap<Runtime>,
    /// Metrics.
    pub metrics: Metrics,
    /// ACME challenge answers.
    pub challenges: Arc<rdock_tls::Challenges>,
    /// Client for mirrored requests.
    pub client: Arc<rdock_middleware::HttpClient>,
    /// Requests in flight across listeners, for `security.limits.max_in_flight`.
    pub in_flight: Arc<std::sync::atomic::AtomicU32>,
    /// Spool directory for held request bodies over 64 KiB; unset, they stay in memory.
    pub spool: std::sync::OnceLock<Arc<rdock_middleware::Spool>>,
    /// Whether listeners accept new connections (and `udp` listeners read datagrams). A binary
    /// upgrade starts the new process with `false` and pauses the old one between `ready` and
    /// `serving`; connections wait in the kernel's backlog meanwhile.
    pub accepting: tokio::sync::watch::Sender<bool>,
    /// Client connections open across TCP listeners (a draining process reports them).
    pub open_connections: std::sync::atomic::AtomicU64,
    /// Serve without the HTTP caches. A binary upgrade sets it in the old process from the
    /// start of the handover: the new process owns the cache directories from then on (its
    /// start-up walk removes unfinished files) and the old one only drains.
    pub cache_bypass: std::sync::atomic::AtomicBool,
    /// The `Alt-Svc` value of each listener whose HTTP/3 endpoint serves and advertises
    /// (ADR-0032), added to its HTTP/1 and HTTP/2 responses.
    #[cfg(feature = "http3")]
    pub alt_svc: ArcSwap<std::collections::HashMap<Arc<str>, HeaderValue>>,
}

/// One request counted in [`Shared::in_flight`] until dropped.
#[derive(Debug)]
pub struct InFlightSlot {
    counter: Arc<std::sync::atomic::AtomicU32>,
    count: u32,
}

impl InFlightSlot {
    fn take(counter: &Arc<std::sync::atomic::AtomicU32>) -> Self {
        let count = counter.fetch_add(1, std::sync::atomic::Ordering::AcqRel) + 1;
        Self {
            counter: counter.clone(),
            count,
        }
    }

    /// Requests in flight, this one included, when it started.
    fn count(&self) -> u32 {
        self.count
    }
}

impl Drop for InFlightSlot {
    fn drop(&mut self) {
        self.counter
            .fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

/// The proxy of one listener.
#[derive(Debug)]
pub struct RdockProxy {
    listener: Arc<str>,
    shared: Arc<Shared>,
}

impl RdockProxy {
    /// Adds this listener's HTTP/3 advertisement (`Alt-Svc`, RFC 9114 §3.1.1) to an HTTP/1 or
    /// HTTP/2 response while its QUIC endpoint serves with `advertise` on (ADR-0032). It
    /// replaces a backend's `Alt-Svc`: clients reach the proxy, not the backend.
    #[cfg(feature = "http3")]
    fn advertise_http3(&self, session: &Session, resp: &mut ResponseHeader) {
        if is_http3(session) {
            return;
        }
        if let Some(value) = self.shared.alt_svc.load().get(&self.listener) {
            let _ = resp.insert_header(http::header::ALT_SVC, value.clone());
        }
    }

    /// Counts an answered HTTP/3 request in `rdock_http3_requests_total`.
    fn count_http3(&self, session: &Session, status: u16) {
        if is_http3(session) {
            self.shared
                .metrics
                .http3_requests
                .with_label_values(&[&*self.listener, rdock_observability::status_class(status)])
                .inc();
        }
    }

    /// Without the `http3` feature there is nothing to advertise.
    #[cfg(not(feature = "http3"))]
    #[allow(clippy::unused_self)]
    fn advertise_http3(&self, _session: &Session, _resp: &mut ResponseHeader) {}

    /// Per-backend answer counts and time to response headers (M-OBS-02). Label values come
    /// from the configuration and resolved addresses, so their number stays bounded.
    fn observe_backend(&self, service: &ServiceRuntime, ctx: &RequestCtx, status: u16) {
        let metrics = &self.shared.metrics;
        if let Some(member) = &ctx.member {
            metrics
                .backend_requests
                .with_label_values(&[
                    &*service.name,
                    &member.id,
                    rdock_observability::status_class(status),
                ])
                .inc();
        }
        if let Some(started) = ctx.attempt_started {
            metrics
                .upstream_duration
                .with_label_values(&[&*service.name])
                .observe(started.elapsed().as_secs_f64());
        }
    }

    /// Feeds the outcome of an attempt to passive health.
    fn report(&self, service: &ServiceRuntime, member: Option<&Arc<Member>>, ok: bool) {
        let (Some(passive), Some(member)) = (&service.health.passive, member) else {
            return;
        };
        if passive.outlier.is_some() {
            member.state.record_outcome(ok);
        }
        let now = Instant::now();
        let metrics = &self.shared.metrics;
        if ok {
            if member.state.success(now) {
                tracing::info!(service = %service.name, backend = %member.id, "backend recovered");
                metrics.feeds.events.send(serde_json::json!({
                    "type": "backend", "service": &*service.name, "backend": member.id, "state": "up",
                    "reason": "recovered",
                }));
                crate::alerting::backend_up(metrics, service, member);
                metrics
                    .backend_up
                    .with_label_values(&[&*service.name, &member.id])
                    .set(1);
            }
            return;
        }
        match service
            .pool
            .failure(&member.state, passive.policy, passive.max_percent, now)
        {
            Ejection::Ejected(time) => {
                tracing::warn!(
                    service = %service.name,
                    backend = %member.id,
                    seconds = time.as_secs(),
                    "backend ejected after repeated failures"
                );
                metrics.feeds.events.send(serde_json::json!({
                    "type": "backend", "service": &*service.name, "backend": member.id, "state": "down",
                    "reason": "ejected after repeated failures", "seconds": time.as_secs(),
                }));
                crate::alerting::backend_down(
                    metrics,
                    service,
                    member,
                    "ejected after repeated failures",
                );
                metrics
                    .backend_ejections
                    .with_label_values(&[&*service.name, &member.id])
                    .inc();
                metrics
                    .backend_up
                    .with_label_values(&[&*service.name, &member.id])
                    .set(0);
            }
            Ejection::Refused => tracing::warn!(
                service = %service.name,
                backend = %member.id,
                "backend keeps failing, but max_ejection_percent of the pool is already ejected"
            ),
            Ejection::None => {}
        }
    }

    /// Feeds `peak_ewma` the latency of the current attempt: its time so far, or for a failed
    /// attempt at least [`rdock_balancer::FAILURE_PENALTY`], so that a backend that fails fast
    /// does not look fast.
    fn sample(service: &ServiceRuntime, ctx: &RequestCtx, ok: bool) {
        let (Some(peak), Some(member), Some(started)) =
            (service.selection.peak, &ctx.member, ctx.attempt_started)
        else {
            return;
        };
        let now = Instant::now();
        let latency = member.state.latency();
        if ok {
            latency.observe(now.saturating_duration_since(started), peak.decay, now);
        } else {
            latency.observe_failure(now.saturating_duration_since(started), peak.decay, now);
        }
    }

    /// `measure: last_byte`: the sample of an attempt that answered, when its response ends; a
    /// response cut short is a failure.
    fn sample_at_end(ctx: &mut RequestCtx, ok: bool) {
        if std::mem::take(&mut ctx.sample_at_end)
            && let Some(service) = &ctx.service
        {
            Self::sample(service, ctx, ok);
        }
    }

    /// Whether this failure may be retried, and if so takes a retry from the budget. Connect
    /// failures are retried for any method (nothing reached the backend); other failures only
    /// for idempotent methods unless `retry_non_idempotent`; never after the client saw a
    /// response or when the body exceeded the replay buffer.
    fn take_retry(
        &self,
        session: &Session,
        ctx: &mut RequestCtx,
        service: &ServiceRuntime,
        kind: RetryOn,
    ) -> bool {
        let Some(retries) = &service.retries else {
            return false;
        };
        let method_ok = kind == RetryOn::Connect
            || retries.retry_non_idempotent
            || session.req_header().method.is_idempotent();
        if !retries.on.contains(&kind)
            || ctx.retries >= retries.attempts
            || !method_ok
            || session.response_written().is_some()
            || session.as_ref().retry_buffer_truncated()
        {
            return false;
        }
        let metrics = &self.shared.metrics;
        // A request holds at most one permit: the previous retry's goes back first.
        ctx.retry_permit = None;
        let Some(permit) = service.pool.try_retry(retries.budget_percent) else {
            metrics
                .retry_budget_exhausted
                .with_label_values(&[&*service.name])
                .inc();
            return false;
        };
        ctx.retries += 1;
        ctx.retry_permit = Some(permit);
        metrics
            .retries
            .with_label_values(&[&*service.name, retry_reason(kind)])
            .inc();
        true
    }

    /// Sends the mirrored copy in the background; its answer is read and dropped.
    fn send_mirror(&self, mirror: &MirrorRuntime, request: &RequestHeader, copy: MirrorCopy) {
        let metrics = self.shared.metrics.clone();
        let target = upstream::resolve(&mirror.service);
        let count = |outcome: &str| {
            metrics
                .mirrors
                .with_label_values(&[&*target.name, outcome])
                .inc();
        };
        let Some(body) = copy.body() else {
            count("too_large");
            return;
        };
        let Ok(slot) = mirror.slots.clone().try_acquire_owned() else {
            count("dropped");
            return;
        };
        let Some(selected) = upstream::select(&target, upstream::RequestKey::default()) else {
            count("no_backend");
            return;
        };
        let mut req = request.clone();
        for name in HOP_BY_HOP {
            req.remove_header(*name);
        }
        let candidate = &selected.member.candidate;
        let replace_host =
            !target.pass_host_header || !req.headers.contains_key(http::header::HOST);
        if replace_host
            && req
                .insert_header(
                    http::header::HOST,
                    backend_authority(target.scheme, candidate),
                )
                .is_err()
        {
            return;
        }
        let timeouts = rdock_model::route::RouteTimeouts::default();
        let Ok(peer) = upstream::peer(&target, candidate, &timeouts) else {
            return;
        };
        let client = self.shared.client.clone();
        let timeout = target.timeouts.read.as_std();
        let metrics = self.shared.metrics.clone();
        tokio::spawn(async move {
            let _slot = slot;
            let _in_flight = selected.member.state.begin();
            let result = if body.is_empty() {
                client
                    .send(&peer, req, timeout, MIRROR_BODY)
                    .await
                    .map(drop)
            } else {
                client
                    .send_with_body(&peer, req, body, timeout, MIRROR_BODY)
                    .await
                    .map(drop)
            };
            let outcome = match result {
                Ok(()) | Err(rdock_middleware::FetchError::TooLarge(_)) => "sent",
                Err(_) => "failed",
            };
            metrics
                .mirrors
                .with_label_values(&[&*target.name, outcome])
                .inc();
        });
    }

    /// The proxy for listener `listener`.
    #[must_use]
    pub fn new(listener: Arc<str>, shared: Arc<Shared>) -> Self {
        Self { listener, shared }
    }
}

/// Per-request state.
#[derive(Debug)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent per-request facts, not a state machine"
)]
pub struct RequestCtx {
    started: Instant,
    started_at: SystemTime,
    runtime: Arc<Runtime>,
    /// Set by `early_request_filter`; `None` only for a request refused before that.
    request_id: Option<Arc<str>>,
    peer: Option<IpAddr>,
    client_ip: Option<IpAddr>,
    tls: bool,
    /// The `Host` header (or the URI's authority) as sent; moved into the middleware context
    /// when the route's `request` phase starts, and empty after that.
    authority: String,
    host: String,
    path: String,
    query_len: usize,
    route: Option<Arc<RouteRuntime>>,
    /// The service the request goes to: the route's, or the target a `split` chose.
    service: Option<Arc<ServiceRuntime>>,
    /// The request body kept for a mirrored copy; `None` when this request is not mirrored.
    mirror: Option<MirrorCopy>,
    /// gRPC-Web translation state, for routes with the `grpc_web` middleware.
    grpc_web: Option<GrpcWebCtx>,
    /// Counted against `security.limits.max_in_flight`.
    slot: Option<InFlightSlot>,
    /// OpenTelemetry spans of this request.
    trace: Option<crate::trace::Trace>,
    /// When the current upstream attempt started.
    attempt_started: Option<Instant>,
    mw: Option<MwContext>,
    upstream: Option<Candidate>,
    member: Option<Arc<Member>>,
    in_flight: Option<rdock_balancer::InFlight>,
    /// Retries made so far, backends tried, and the budget permit of the running retry.
    retries: u32,
    tried: Vec<String>,
    retry_permit: Option<RetryPermit>,
    /// `upstream_response_filter` turned a status into a retry already counted.
    status_retry: bool,
    /// `peak_ewma` with `measure: last_byte`: the attempt answered and its sample is taken
    /// when the response ends.
    sample_at_end: bool,
    set_cookie: Option<String>,
    body_bytes: u64,
    sent_replacement: bool,
    error: Option<String>,
    /// The request body held for the chain's `request_body` phase; `None` when no middleware
    /// asked for it or the request has no body.
    hold: Option<Hold>,
    /// A middleware's answer from a phase that runs while proxying (`upstream_request`,
    /// `request_body`), sent by `fail_to_proxy`.
    answer: Option<Answered>,
    /// rdock refused the request while proxying (an answer above, or a held body that was too
    /// large or too slow): not the backend's fault, and never retried.
    refused: bool,
    /// The HTTP cache state, on routes with a `cache` middleware.
    cache: Option<crate::cache::CacheCtx>,
}

/// A held request body: being collected, or released to the backend (kept for a retry, which
/// replays the client's body through `request_body_filter` and must send the same bytes).
#[derive(Debug)]
enum Hold {
    Collecting(BodyHolder),
    Released(Bytes),
}

impl RequestCtx {
    /// The request's ID; empty for a request refused before it got one.
    fn request_id(&self) -> &str {
        self.request_id.as_deref().unwrap_or_default()
    }
}

/// How rdock's own answers are rendered for this request: the route's `errors.format`, or
/// `defaults.errors.format` before a route is chosen.
fn error_format(ctx: &RequestCtx) -> rdock_model::config::ErrorFormat {
    ctx.route
        .as_ref()
        .map_or(ctx.runtime.errors, |route| route.errors)
}

// `pingora::Result` carries errors boxed.
#[allow(clippy::unnecessary_box_returns)]
fn status_error(status: u16, why: &'static str) -> Box<Error> {
    Error::explain(ErrorType::HTTPStatus(status), why)
}

/// Request IDs accepted from trusted proxies: visible ASCII, at most 128 bytes.
fn valid_request_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && value.bytes().all(|b| b.is_ascii_graphic())
}

impl RdockProxy {
    /// The answer to an ACME HTTP-01 challenge request, served before any route or redirect.
    fn http01_answer(&self, req: &RequestHeader) -> Option<Arc<str>> {
        if req.method != http::Method::GET && req.method != http::Method::HEAD {
            return None;
        }
        self.shared.challenges.http01_answer(req.uri.path())
    }

    /// Answers rdock gives itself before routing: ACME HTTP-01 challenges on plain listeners,
    /// and the listener's `ping` path for load-balancer monitors (W-CF-07).
    fn built_in_answer(&self, listener: &ListenerRuntime, req: &RequestHeader) -> Option<Reply> {
        let text = |body: Bytes| Reply {
            status: 200,
            headers: vec![
                (
                    http::header::CONTENT_TYPE,
                    HeaderValue::from_static("text/plain"),
                ),
                (
                    http::header::CACHE_CONTROL,
                    HeaderValue::from_static("no-store"),
                ),
            ],
            body: Some(Body::Bytes(body)),
            problem: None,
            extensions: None,
        };
        if listener.tls.is_none()
            && let Some(answer) = self.http01_answer(req)
        {
            return Some(text(Bytes::copy_from_slice(answer.as_bytes())));
        }
        let probe = req.method == http::Method::GET || req.method == http::Method::HEAD;
        (probe && listener.ping.as_deref() == Some(req.uri.path()))
            .then(|| text(Bytes::from_static(b"OK\n")))
    }

    fn listener<'a>(&self, runtime: &'a Runtime) -> Option<&'a ListenerRuntime> {
        runtime.listeners.get(&*self.listener)
    }

    /// Checks size limits and `Host` before anything else looks at the request.
    fn check_request(runtime: &Runtime, req: &RequestHeader) -> pingora::Result<()> {
        let limits = &runtime.limits;
        if req.raw_path().len() as u64 > limits.max_uri_bytes.as_u64() {
            return Err(status_error(414, "request target too long"));
        }
        if req.headers.len() > usize::try_from(limits.max_headers).unwrap_or(usize::MAX) {
            return Err(status_error(431, "too many request headers"));
        }
        let header_bytes: usize = req
            .headers
            .iter()
            .map(|(n, v)| n.as_str().len() + v.len() + 4)
            .sum::<usize>()
            + req.raw_path().len()
            + req.method.as_str().len()
            + 12;
        if header_bytes as u64 > limits.max_header_bytes.as_u64() {
            return Err(status_error(431, "request headers too large"));
        }
        if req.version == Version::HTTP_11
            && !req.headers.contains_key(http::header::HOST)
            && req.uri.authority().is_none()
        {
            return Err(status_error(400, "HTTP/1.1 request without Host"));
        }
        // RFC 9112 §3.2: a `Host` that is not `host [":" port]` is answered 400. Routing,
        // `X-Forwarded-Host` and the backend would otherwise see a value that is not a host.
        let host = match req.headers.get(http::header::HOST) {
            Some(value) => Some(value.to_str().ok().unwrap_or("\u{0}")),
            None => req.uri.authority().map(http::uri::Authority::as_str),
        };
        if host.is_some_and(|h| !valid_authority(h)) {
            return Err(status_error(400, "invalid Host"));
        }
        // A WebSocket handshake carries no body (RFC 6455 §4.1). Its body would pass the
        // body-holding middlewares unseen, since an upgrade is a stream, yet reach a backend
        // that declines the upgrade as an ordinary request body.
        if is_websocket_handshake(req) && declares_body(req) {
            return Err(status_error(400, "WebSocket handshake with a request body"));
        }
        // RFC 9110 §10.1.1: only `100-continue` is defined; anything else (including obfuscated
        // spellings a backend might still honour) is refused.
        if req
            .headers
            .get_all(http::header::EXPECT)
            .iter()
            .any(|v| !v.as_bytes().eq_ignore_ascii_case(b"100-continue"))
        {
            return Err(status_error(417, "unsupported Expect"));
        }
        Ok(())
    }

    /// Writes a response produced by rdock (redirects, middleware answers, 404). Bodies in
    /// memory are sent at once, files chunk by chunk; both pass the response compression and
    /// the `bandwidth` throttle chosen by the middlewares.
    ///
    /// `chain` is the route's chain and the position of the middleware that answered: the
    /// response phases run for the middlewares before it (all of them for answers that are not
    /// a middleware's).
    async fn reply(
        &self,
        session: &mut Session,
        ctx: &mut RequestCtx,
        reply: Reply,
        chain: Option<(&Chain, usize)>,
    ) -> pingora::Result<()> {
        let mut reply = reply;
        if reply.problem.is_some()
            && reply.status >= 400
            && error_format(ctx) != rdock_model::config::ErrorFormat::Html
            && reply.body.as_ref().is_some_and(|b| b.as_bytes().is_some())
        {
            // A middleware's plain stand-in for the standard page.
            reply.body = None;
            reply
                .headers
                .retain(|(name, _)| *name != http::header::CONTENT_TYPE);
        }
        let mut resp = ResponseHeader::build(reply.status, Some(reply.headers.len() + 4))?;
        let retry_after = reply
            .headers
            .iter()
            .find(|(n, _)| *n == http::header::RETRY_AFTER)
            .and_then(|(_, v)| v.to_str().ok()?.trim().parse::<u64>().ok());
        for (name, value) in reply.headers {
            resp.append_header(name, value)?;
        }
        // Every answer rdock writes itself says how to read it; a static file's own `nosniff`
        // setting decides for files. Proxied responses never pass here.
        let own_body = !matches!(reply.body, Some(Body::File(_)));
        if own_body
            && !resp
                .headers
                .contains_key(http::header::X_CONTENT_TYPE_OPTIONS)
        {
            resp.insert_header(http::header::X_CONTENT_TYPE_OPTIONS, NOSNIFF)?;
        }
        let body = if let Some(body) = reply.body {
            body
        } else {
            let accept = session
                .req_header()
                .headers
                .get(http::header::ACCEPT)
                .and_then(|v| v.to_str().ok());
            let page = errorpage::render(&errorpage::ErrorInfo {
                status: reply.status,
                request_id: ctx.request_id(),
                accept,
                format: error_format(ctx),
                kind: reply.problem,
                retry_after,
                extensions: reply.extensions.as_deref(),
            });
            resp.insert_header(http::header::CONTENT_TYPE, page.content_type)?;
            resp.insert_header(http::header::CACHE_CONTROL, "no-store")?;
            if let Some(language) = page.language {
                resp.insert_header(http::header::CONTENT_LANGUAGE, language)?;
            }
            Body::Bytes(page.body)
        };
        // RFC 9110 §8.6: a 304 must not carry a Content-Length other than the full one.
        if !matches!(reply.status, 204 | 304) {
            resp.insert_header(http::header::CONTENT_LENGTH, body.len())?;
        }
        if let (Some(cx), Some((chain, upto))) = (ctx.mw.as_mut(), chain) {
            chain.response(upto, &mut resp, cx).await;
        }
        if let Some(cc) = ctx.cache.as_mut() {
            crate::cache::decorate(session, &mut resp, cc);
        }
        let body = ctx
            .mw
            .as_mut()
            .and_then(|cx| cx.replace_body.take())
            .map_or(body, Body::Bytes);
        resp.insert_header("x-request-id", ctx.request_id())?;
        self.advertise_http3(session, &mut resp);
        let head = session.req_header().method == http::Method::HEAD;
        let compressed = ctx.mw.as_ref().is_some_and(|cx| cx.compression.is_some());
        if compressed && !head && session.req_header().version == Version::HTTP_11 {
            // `compress` removed the length; HTTP/1.0 clients get a close-delimited body.
            resp.insert_header(http::header::TRANSFER_ENCODING, "chunked")?;
        }
        session.write_response_header(Box::new(resp), head).await?;
        if !head {
            send_body(session, ctx.mw.as_mut(), chain, body).await?;
        }
        Ok(())
    }

    /// The route's `request` phase, a service that answers itself, then the body hold and the
    /// mirror for requests that go on to the backend. `Ok(true)` when an answer was sent.
    async fn run_request_phase(
        &self,
        session: &mut Session,
        ctx: &mut RequestCtx,
        route: &Arc<RouteRuntime>,
        client_ip: IpAddr,
    ) -> pingora::Result<bool> {
        let mut cx = MwContext::new(
            client_ip,
            ctx.tls,
            route.name.clone(),
            ctx.request_id.clone().unwrap_or_else(|| Arc::from("")),
            // Read only up to here; the middleware context takes it instead of a copy.
            std::mem::take(&mut ctx.authority),
        );
        cx.client_cert = client_identity(session);
        cx.fingerprint = connection_fingerprint(
            session,
            self.listener(&ctx.runtime),
            &ctx.runtime.fingerprint_headers,
        );
        cx.has_body = !session.is_body_empty() && !is_upgrade(session.req_header());
        cx.priority_class = route.priority_class;
        let chain = &route.middlewares;
        chain.start(&mut cx);
        let answered = chain.request(session.req_header_mut(), &mut cx).await;
        ctx.mw = Some(cx);
        if let Err(answer) = answered {
            self.reply(session, ctx, answer.reply, Some((chain, answer.index)))
                .await?;
            return Ok(true);
        }
        // A service that answers itself (`respond`, e.g. a share of a split with an invalid
        // backend) replies like a middleware would, so access logs, metrics and the route's
        // response middlewares (`compress`, `headers`) apply.
        if let Some(status) = ctx.service.as_ref().and_then(|s| s.respond) {
            self.reply(
                session,
                ctx,
                Reply::status(status),
                Some((chain, chain.len())),
            )
            .await?;
            return Ok(true);
        }
        start_hold(session, ctx, route, &self.shared.spool)?;
        start_mirror(session.req_header(), ctx, route);
        Ok(false)
    }

    /// One chunk of a held body (ADR-0030, "Pipeline and body phase"). While collecting,
    /// nothing goes upstream (an empty chunk, which Pingora does not write); at the end of the
    /// stream the chain's `request_body` phase runs and the whole body, or its replacement,
    /// leaves in one piece. A middleware's answer, an oversize or a slow body abort the
    /// upstream request: the backend has the request head and sees the connection closed (or
    /// the HTTP/2 stream reset) without a byte of the body.
    async fn hold_chunk(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut RequestCtx,
    ) -> pingora::Result<()> {
        match ctx.hold.as_mut() {
            None => return Ok(()),
            Some(Hold::Released(bytes)) => {
                // A retry replays the client's body: send what was released the first time.
                *body = if end_of_stream {
                    (!bytes.is_empty()).then(|| bytes.clone())
                } else {
                    Some(Bytes::new())
                };
                return Ok(());
            }
            Some(Hold::Collecting(holder)) => {
                if let Some(chunk) = body.take()
                    && let Err(e) = holder.push(&chunk).await
                {
                    return Err(self.hold_failed(ctx, &e));
                }
                // The next read gives up when the hold's time is up.
                if let (Some(left), Some(listener)) =
                    (holder.remaining(), self.listener(&ctx.runtime))
                {
                    let read = listener.timeouts.read.as_std();
                    session.set_read_timeout(Some(left.min(read).max(Duration::from_millis(1))));
                }
                if !end_of_stream {
                    *body = Some(Bytes::new());
                    return Ok(());
                }
            }
        }
        let Some(Hold::Collecting(holder)) = ctx.hold.take() else {
            return Ok(());
        };
        let held = match holder.finish().await {
            Ok(held) => held,
            Err(e) => return Err(self.hold_failed(ctx, &e)),
        };
        let released = match (ctx.route.clone(), ctx.mw.as_mut()) {
            (Some(route), Some(cx)) => match route.middlewares.request_body(held, cx).await {
                Ok(released) => released,
                Err(answer) => {
                    let status = answer.reply.status;
                    ctx.answer = Some(answer);
                    ctx.refused = true;
                    ctx.mirror = None;
                    return Err(status_error(
                        status,
                        "a middleware answered the request body",
                    ));
                }
            },
            // Not reached: a body is held only for a matched route.
            _ => Released {
                body: held,
                replaced: false,
            },
        };
        let bytes = match released.body.bytes().await {
            Ok(bytes) => bytes,
            Err(e) => return Err(self.hold_failed(ctx, &HoldError::Io(e))),
        };
        // Restores the listener's read timeout for the rest of the exchange.
        if let Some(listener) = self.listener(&ctx.runtime) {
            session.set_read_timeout(Some(listener.timeouts.read.as_std()));
        }
        *body = (!bytes.is_empty()).then(|| bytes.clone());
        ctx.hold = Some(Hold::Released(bytes));
        Ok(())
    }

    /// The error for a body that could not be held: `413`, `408` or `500`.
    // `pingora::Result` carries errors boxed.
    #[allow(clippy::unnecessary_box_returns)]
    fn hold_failed(&self, ctx: &mut RequestCtx, e: &HoldError) -> Box<Error> {
        ctx.refused = true;
        ctx.mirror = None;
        match e {
            HoldError::TooLarge => status_error(413, "request body too large to hold"),
            HoldError::TimedOut => status_error(408, "the request body did not arrive in time"),
            HoldError::Io(io) => {
                tracing::error!(error = %io, listener = %self.listener, "holding a request body failed");
                status_error(500, "holding the request body failed")
            }
        }
    }

    /// The access-log record of a finished request.
    #[allow(clippy::too_many_lines)] // one field after the other
    fn access_record(
        &self,
        session: &Session,
        e: Option<&Error>,
        ctx: &mut RequestCtx,
        status: u16,
        elapsed: Duration,
    ) -> AccessRecord {
        let log = &ctx.runtime.access_log;
        let route = ctx.route.as_ref();
        let service = ctx.service.as_ref();
        let req = session.req_header();
        let header = |name: &str| {
            req.headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(|v| {
                    if log.redacts(name) {
                        "***".to_owned()
                    } else {
                        v.to_owned()
                    }
                })
        };
        let ssl = session.digest().and_then(|d| d.ssl_digest.clone());
        let tls_facts = handshake(session);
        let fingerprint = tls_facts.and_then(|h| h.fingerprint.get().cloned());
        let wanted = ctx.runtime.geoip_log;
        let geo = (wanted.country || wanted.asn)
            .then(|| Some(ctx.runtime.geoip.as_ref()?.lookup(ctx.client_ip?)))
            .flatten()
            .unwrap_or_default();
        AccessRecord {
            ts: rfc3339(ctx.started_at),
            request_id: ctx.request_id().to_owned(),
            client_ip: ctx.client_ip.map(|ip| ip.to_string()).unwrap_or_default(),
            proxy_peer: session
                .digest()
                .and_then(crate::proxy_protocol::proxy_peer)
                .map(|peer| peer.to_string()),
            method: req.method.to_string(),
            host: ctx.host.clone(),
            path: ctx.path.clone(),
            query_len: ctx.query_len,
            proto: if session.is_http2() {
                "HTTP/2".into()
            } else if is_http3(session) {
                "HTTP/3".into()
            } else {
                format!("{:?}", req.version)
            },
            status,
            bytes_in: session.body_bytes_read(),
            bytes_out: session.body_bytes_sent(),
            duration_ms: elapsed.as_secs_f64() * 1000.0,
            listener: self.listener.to_string(),
            route: route.map(|r| r.name.to_string()),
            service: service.map(|s| s.name.to_string()),
            upstream: ctx.upstream.as_ref().map(ToString::to_string),
            tried: {
                let current = ctx.member.as_ref().map(|m| m.id.as_str());
                ctx.tried
                    .iter()
                    .filter(|t| Some(t.as_str()) != current)
                    .cloned()
                    .collect()
            },
            tls_version: ssl.as_ref().map(|s| s.version.to_string()),
            tls_cipher: ssl.as_ref().map(|s| s.cipher.to_string()),
            sni: tls_facts.and_then(|h| h.sni.clone()),
            user: ctx.mw.as_ref().and_then(|cx| cx.user.clone()),
            consumer: ctx
                .mw
                .as_ref()
                .and_then(|cx| cx.consumer.as_ref())
                .map(|c| c.name.to_string()),
            key_id: ctx
                .mw
                .as_ref()
                .and_then(|cx| cx.key_id.as_ref())
                .map(ToString::to_string),
            user_agent: header("user-agent"),
            referer: header("referer").map(|r| r.split('?').next().unwrap_or_default().to_owned()),
            cf_ray: header("cf-ray"),
            error: ctx.error.take().or_else(|| e.map(ToString::to_string)),
            cache_status: ctx.cache.as_ref().and_then(|c| c.label).map(str::to_owned),
            ja4: fingerprint
                .as_ref()
                .and_then(|f| f.ja4.as_deref())
                .map(str::to_owned),
            ja3: fingerprint
                .as_ref()
                .and_then(|f| f.ja3.as_deref())
                .map(str::to_owned),
            country: geo
                .country_str()
                .filter(|_| wanted.country)
                .map(str::to_owned),
            asn: geo.asn.filter(|_| wanted.asn),
            abuse: ctx.mw.as_ref().and_then(|cx| cx.abuse).map(str::to_owned),
            admission: ctx
                .mw
                .as_ref()
                .and_then(|cx| cx.admission)
                .map(str::to_owned),
            spiffe_id: ctx
                .mw
                .as_ref()
                .and_then(|cx| cx.spiffe_id.as_deref())
                .map(str::to_owned),
        }
    }
}

#[async_trait]
impl ProxyHttp for RdockProxy {
    type CTX = RequestCtx;

    fn new_ctx(&self) -> RequestCtx {
        RequestCtx {
            started: Instant::now(),
            started_at: SystemTime::now(),
            runtime: self.shared.runtime.load_full(),
            request_id: None,
            peer: None,
            client_ip: None,
            tls: false,
            authority: String::new(),
            host: String::new(),
            path: String::new(),
            query_len: 0,
            route: None,
            service: None,
            mirror: None,
            grpc_web: None,
            slot: None,
            trace: None,
            attempt_started: None,
            mw: None,
            upstream: None,
            member: None,
            in_flight: None,
            retries: 0,
            tried: Vec::new(),
            retry_permit: None,
            status_retry: false,
            sample_at_end: false,
            set_cookie: None,
            body_bytes: 0,
            sent_replacement: false,
            error: None,
            hold: None,
            answer: None,
            refused: false,
            cache: None,
        }
    }

    fn init_downstream_modules(&self, _modules: &mut HttpModules) {
        // Compression is done by the `compress` middleware, which streams and honours q-values.
    }

    async fn early_request_filter(
        &self,
        session: &mut Session,
        ctx: &mut RequestCtx,
    ) -> pingora::Result<()> {
        let runtime = ctx.runtime.clone();
        if let Some(max) = runtime.limits.max_in_flight {
            let slot = InFlightSlot::take(&self.shared.in_flight);
            if slot.count() > max {
                return Err(status_error(503, "the proxy is at max_in_flight"));
            }
            ctx.slot = Some(slot);
        }
        if let Some(listener) = self.listener(&runtime) {
            let t = &listener.timeouts;
            session.set_keepalive(Some(t.idle.as_std().as_secs().max(1)));
            session.set_read_timeout(Some(t.read.as_std()));
            session.set_write_timeout(Some(t.write.as_std()));
        }
        ctx.tls = session.digest().is_some_and(|d| d.ssl_digest.is_some());
        ctx.peer = session
            .client_addr()
            .and_then(pingora::protocols::l4::socket::SocketAddr::as_inet)
            .map(std::net::SocketAddr::ip);
        strip_connection_nominations(session.req_header_mut());
        let req = session.req_header();
        ctx.authority = req
            .headers
            .get(http::header::HOST)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
            .or_else(|| req.uri.authority().map(|a| a.as_str().to_owned()))
            .unwrap_or_default();
        ctx.host = normalize_host(rdock_middleware_host(&ctx.authority));
        if let Some(tracer) = &ctx.runtime.tracer {
            ctx.trace = Some(crate::trace::Trace::start(
                tracer,
                req,
                ctx.tls,
                session.is_http2(),
                &ctx.host,
            ));
        }
        req.uri.path().clone_into(&mut ctx.path);
        ctx.query_len = req.uri.query().map_or(0, str::len);
        let peer = ctx.peer.unwrap_or(IpAddr::from([0, 0, 0, 0]));
        let trusted = runtime.client_ip.is_trusted(peer);
        ctx.client_ip = Some(runtime.client_ip.client_ip(peer, &req.headers));
        let incoming_id = req
            .headers
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .filter(|v| trusted && valid_request_id(v))
            .map(Arc::from);
        // Encoded on the stack and copied once into the shared string.
        ctx.request_id = Some(incoming_id.unwrap_or_else(|| {
            Arc::from(
                &*uuid::Uuid::now_v7()
                    .hyphenated()
                    .encode_lower(&mut uuid::Uuid::encode_buffer()),
            )
        }));
        Self::check_request(&runtime, req)
    }

    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut RequestCtx,
    ) -> pingora::Result<bool> {
        let runtime = ctx.runtime.clone();
        let Some(listener) = self.listener(&runtime) else {
            return Err(status_error(503, "listener is not configured"));
        };
        if let Some(reply) = self.built_in_answer(listener, session.req_header()) {
            self.reply(session, ctx, reply, None).await?;
            return Ok(true);
        }
        if runtime.ambiguous_paths == rdock_model::settings::AmbiguousPaths::Reject
            && rdock_rules::path::ambiguous(session.req_header().uri.path())
        {
            return Err(status_error(400, "ambiguous request path"));
        }
        if runtime.encoded_separators == rdock_model::settings::EncodedSeparators::Reject
            && rdock_rules::path::has_encoded_separator(session.req_header().uri.path())
        {
            return Err(status_error(400, "encoded separator in the request path"));
        }
        let normalized = rdock_rules::path::normalize(session.req_header().uri.path())
            .map_err(|_| status_error(400, "invalid request path"))?;
        if normalized.forwarded != session.req_header().uri.path() {
            set_path(session.req_header_mut(), &normalized.forwarded)?;
        }
        let query: Vec<(String, String)> = session
            .req_header()
            .uri
            .query()
            .map(|q| {
                url::form_urlencoded::parse(q.as_bytes())
                    .into_owned()
                    .collect()
            })
            .unwrap_or_default();
        let client_ip = ctx.client_ip.unwrap_or(IpAddr::from([0, 0, 0, 0]));
        let fingerprint = listener
            .fingerprint
            .as_ref()
            .and_then(|_| handshake(session))
            .and_then(|h| h.fingerprint.get().cloned());
        let route = {
            let req = session.req_header();
            let facts = Facts {
                host: &ctx.host,
                path: &normalized.routing,
                method: req.method.as_str(),
                headers: &req.headers,
                query: &query,
                client_ip,
                fingerprint: fingerprint.as_deref(),
            };
            // Only the routes that can match this host, in evaluation order (the index
            // keeps the result of a scan over every route).
            listener
                .route_index
                .candidates(&ctx.host)
                .filter_map(|i| listener.routes.get(i))
                .find(|r| r.rule.matches(&facts))
                .cloned()
        };
        let Some(route) = route else {
            if let Some(redirect) = &listener.https_redirect
                && redirect.hosts.contains(&ctx.host)
            {
                let reply = https_redirect(session.req_header(), &ctx.authority, redirect.port);
                self.reply(session, ctx, reply, None).await?;
                return Ok(true);
            }
            self.reply(session, ctx, Reply::status(404), None).await?;
            return Ok(true);
        };
        let peer = ctx.peer.unwrap_or(client_ip);
        forwarded::apply(
            session.req_header_mut(),
            &Forwarding {
                peer,
                client_ip,
                trusted: runtime.client_ip.is_trusted(peer),
                tls: ctx.tls,
                host: Some(ctx.authority.as_str()).filter(|a| !a.is_empty()),
            },
        );
        session
            .req_header_mut()
            .insert_header("x-request-id", ctx.request_id())?;
        if let Some(trace) = &ctx.trace {
            trace.route(session.req_header().method.as_str(), &route.name, client_ip);
        }
        start_route(session, ctx, &route)?;
        if let Some(policy) = &route.cache {
            let url = crate::cache::public_url(
                ctx.tls,
                &ctx.host,
                &normalized.forwarded,
                session.req_header().uri.query(),
            );
            ctx.cache = Some(crate::cache::CacheCtx::new(policy.clone(), url));
        }
        ctx.route = Some(route.clone());
        self.run_request_phase(session, ctx, &route, client_ip)
            .await
    }

    async fn request_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut RequestCtx,
    ) -> pingora::Result<()> {
        let route_max = ctx.route.as_ref().and_then(|r| r.max_body);
        if let (Some(max), Some(chunk)) = (
            route_max.or(ctx.runtime.limits.max_body_bytes),
            body.as_ref(),
        ) {
            ctx.body_bytes += chunk.len() as u64;
            if ctx.body_bytes > max.as_u64() {
                // A refused request is not mirrored, and its body copy is incomplete anyway.
                ctx.mirror = None;
                ctx.refused = true;
                return Err(status_error(413, "request body too large"));
            }
        }
        if ctx.hold.is_some() {
            self.hold_chunk(session, body, end_of_stream, ctx).await?;
        }
        // The mirror gets what the backend gets.
        if let (Some(copy), Some(chunk)) = (ctx.mirror.as_mut(), body.as_ref()) {
            copy.push(chunk);
        }
        Ok(())
    }

    fn request_cache_filter(
        &self,
        session: &mut Session,
        ctx: &mut RequestCtx,
    ) -> pingora::Result<()> {
        let mirrored = ctx.mirror.is_some();
        if self
            .shared
            .cache_bypass
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            return Ok(());
        }
        if let Some(cc) = ctx.cache.as_mut() {
            crate::cache::enable(session, cc, mirrored);
        }
        Ok(())
    }

    fn cache_key_callback(
        &self,
        session: &Session,
        ctx: &mut RequestCtx,
    ) -> pingora::Result<CacheKey> {
        let (Some(route), Some(cc)) = (ctx.route.as_ref(), ctx.cache.as_ref()) else {
            return Err(Error::explain(
                ErrorType::InternalError,
                "cache enabled without a policy",
            ));
        };
        let consumer = cc
            .policy
            .key_consumer
            .then(|| crate::cache::identity(ctx.mw.as_ref()).key());
        Ok(crate::cache::cache_key(
            session,
            cc,
            &route.name,
            ctx.tls,
            &ctx.host,
            consumer.as_deref(),
        ))
    }

    fn cache_miss(&self, session: &mut Session, ctx: &mut RequestCtx) {
        session.cache.cache_miss();
        if let Some(cc) = ctx.cache.as_mut() {
            crate::cache::note_miss(session, cc);
        }
    }

    async fn cache_hit_filter(
        &self,
        session: &mut Session,
        meta: &CacheMeta,
        _hit_handler: &mut HitHandler,
        is_fresh: bool,
        ctx: &mut RequestCtx,
    ) -> pingora::Result<Option<ForcedFreshness>> {
        Ok(ctx
            .cache
            .as_mut()
            .and_then(|cc| crate::cache::hit_filter(session.req_header(), meta, is_fresh, cc)))
    }

    async fn proxy_upstream_filter(
        &self,
        session: &mut Session,
        ctx: &mut RequestCtx,
    ) -> pingora::Result<bool> {
        let only_if_cached = ctx.cache.as_mut().is_some_and(|cc| {
            let refuse = cc.only_if_cached();
            cc.only_if_cached_miss |= refuse;
            refuse
        });
        if !only_if_cached {
            return Ok(true);
        }
        // RFC 9111 §5.2.1.7: nothing usable is stored, and the client forbids the origin.
        let route = ctx.route.clone();
        let chain = route
            .as_ref()
            .map(|r| (&r.middlewares, r.middlewares.len()));
        self.reply(session, ctx, Reply::status(504), chain).await?;
        Ok(false)
    }

    fn response_cache_filter(
        &self,
        session: &Session,
        resp: &ResponseHeader,
        ctx: &mut RequestCtx,
    ) -> pingora::Result<RespCacheable> {
        Ok(match ctx.cache.as_mut() {
            Some(cc) => crate::cache::response_cacheable(session, resp, cc),
            None => RespCacheable::Uncacheable(NoCacheReason::Custom("no cache policy")),
        })
    }

    fn cache_vary_filter(
        &self,
        meta: &CacheMeta,
        _ctx: &mut RequestCtx,
        req: &RequestHeader,
    ) -> Option<HashBinary> {
        crate::cache::variance(meta, req)
    }

    fn should_serve_stale(
        &self,
        _session: &mut Session,
        ctx: &mut RequestCtx,
        error: Option<&Error>,
    ) -> bool {
        ctx.cache
            .as_mut()
            .is_some_and(|cc| crate::cache::serve_stale(error, cc))
    }

    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut RequestCtx,
    ) -> pingora::Result<Box<HttpPeer>> {
        let (Some(route), Some(service)) = (ctx.route.clone(), ctx.service.clone()) else {
            return Err(status_error(404, "no route"));
        };
        // The first attempt of a request counts against the pool's limit; retries of a request
        // already in flight do not.
        if ctx.in_flight.is_none()
            && service
                .max_requests
                .is_some_and(|max| service.pool.in_flight() >= max)
        {
            return Err(status_error(503, "the service is at max_requests"));
        }
        if ctx.retry_permit.is_some() {
            // A retry replays the body read so far from Pingora's buffer (it is retried only
            // while that buffer holds all of it), so the counts start again.
            ctx.body_bytes = 0;
            if let Some(copy) = ctx.mirror.as_mut() {
                *copy = MirrorCopy::default();
            }
            if let Some(Hold::Collecting(holder)) = ctx.hold.as_mut() {
                holder.reset();
            }
            tokio::time::sleep(backoff(ctx.retries)).await;
        }
        let key = upstream::RequestKey {
            request: Some(session.req_header()),
            client_ip: ctx.client_ip,
            tried: &ctx.tried,
        };
        let selected = upstream::select(&service, key)
            .ok_or_else(|| status_error(503, "the service has no available backend"))?;
        if selected.panic {
            self.shared
                .metrics
                .panic_selections
                .with_label_values(&[&*service.name])
                .inc();
        }
        ctx.tried.push(selected.member.id.clone());
        let mut peer = upstream::peer(&service, &selected.member.candidate, &route.timeouts)?;
        if let Some(connect) = peer.options.connection_timeout {
            peer.options.connection_timeout = Some(upstream::connect_budget(
                connect,
                &service,
                ctx.retries,
                &ctx.tried,
            ));
        }
        if let Some(per_try) = per_try_timeout(session, ctx, &service) {
            let read = peer.options.read_timeout.unwrap_or(per_try);
            peer.options.read_timeout = Some(read.min(per_try));
        }
        ctx.sample_at_end = false;
        ctx.in_flight = Some(selected.member.state.begin());
        ctx.upstream = Some(selected.member.candidate.clone());
        ctx.member = Some(selected.member);
        ctx.set_cookie = selected.set_cookie;
        ctx.attempt_started = Some(Instant::now());
        let flags = route.middlewares.flags();
        if (flags.upstream_request || flags.log)
            && let (Some(cx), Some(member)) = (ctx.mw.as_mut(), &ctx.member)
        {
            cx.upstream = Some(Upstream {
                service: service.name.clone(),
                backend: member.id.clone(),
                addr: match &member.candidate {
                    Candidate::Tcp { addr, .. } => Some(*addr),
                    Candidate::Unix(_) => None,
                },
                attempt: ctx.retries,
            });
        }
        if let Some(trace) = ctx.trace.as_mut()
            && let Some(candidate) = &ctx.upstream
        {
            let host = backend_authority(service.scheme, candidate);
            trace.attempt(session.req_header(), candidate, &host, ctx.retries);
        }
        Ok(Box::new(peer))
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut RequestCtx,
    ) -> pingora::Result<()> {
        let (Some(service), Some(candidate)) = (&ctx.service, &ctx.upstream) else {
            return Ok(());
        };
        // HTTP/1.0 clients may omit Host; backends (and HTTP/2) need one.
        let missing = !upstream_request.headers.contains_key(http::header::HOST)
            && upstream_request.uri.authority().is_none();
        if !service.pass_host_header || missing {
            upstream_request.insert_header(
                http::header::HOST,
                backend_authority(service.scheme, candidate),
            )?;
        }
        join_cookies(upstream_request);
        if let Some(trace) = &ctx.trace {
            trace.inject(upstream_request);
        }
        let Some(route) = ctx.route.as_ref() else {
            return Ok(());
        };
        let flags = route.middlewares.flags();
        if ctx.hold.is_some() && flags.request_body.is_some_and(|h| h.replaces) {
            // The head leaves before the body is known: a replaced body cannot keep the
            // client's length. Pingora then sends HTTP/1.1 chunked; HTTP/2 frames the stream.
            upstream_request.remove_header(&http::header::CONTENT_LENGTH);
        }
        if flags.upstream_request
            && let Some(cx) = ctx.mw.as_mut()
            && let Err(answer) = route
                .middlewares
                .upstream_request(upstream_request, cx)
                .await
        {
            let status = answer.reply.status;
            ctx.answer = Some(answer);
            ctx.refused = true;
            return Err(status_error(
                status,
                "a middleware answered the upstream request",
            ));
        }
        Ok(())
    }

    async fn upstream_response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut RequestCtx,
    ) -> pingora::Result<()> {
        strip_response_hop_by_hop(upstream_response);
        if let Some(cc) = ctx.cache.as_mut() {
            crate::cache::upstream_response(session, upstream_response, cc).await;
        }
        let status = upstream_response.status.as_u16();
        if let Some(trace) = ctx.trace.as_mut() {
            trace.response(status);
        }
        let Some(service) = ctx.service.clone() else {
            return Ok(());
        };
        self.observe_backend(&service, ctx, status);
        let failed = service
            .health
            .passive
            .as_ref()
            .is_some_and(|p| p.statuses.contains(&status));
        self.report(&service, ctx.member.as_ref(), !failed);
        if let Some(peak) = service.selection.peak {
            // Without passive health, the statuses it would count are 502, 503 and 504.
            let bad = failed || (service.health.passive.is_none() && matches!(status, 502..=504));
            let at_end = peak.measure == LatencyMeasure::LastByte;
            if bad || !at_end {
                Self::sample(&service, ctx, !bad);
            }
            // An upgraded connection's lifetime is not a latency.
            ctx.sample_at_end = at_end && !bad && status != 101;
        }
        if let Some(retries) = &service.retries
            && let Some(kind) = retries
                .on
                .iter()
                .copied()
                .find(|k| k.status() == Some(status))
        {
            if status == 503
                && let (Some(member), Some(wait)) = (
                    &ctx.member,
                    retry_after(upstream_response, SystemTime::now()),
                )
            {
                member.state.pause(Instant::now() + wait.min(MAX_PAUSE));
            }
            if self.take_retry(session, ctx, &service, kind) {
                ctx.status_retry = true;
                let mut e = Error::create(
                    ErrorType::HTTPStatus(status),
                    ErrorSource::Upstream,
                    Some("retrying the backend's answer".into()),
                    None,
                );
                e.set_retry(true);
                return Err(e);
            }
        }
        Ok(())
    }

    async fn response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut RequestCtx,
    ) -> pingora::Result<()> {
        if let Some(grpc_web) = ctx.grpc_web.as_mut() {
            grpc_web.response_header_filter(upstream_response);
        }
        // An HTTP/1.0 backend must not turn the client's HTTP/1.1 connection into HTTP/1.0.
        if !session.is_http2() {
            upstream_response.set_version(Version::HTTP_11);
        }
        let stored = ctx.cache.is_some() && crate::cache::from_store(session);
        if let (Some(route), Some(cx)) = (&ctx.route, ctx.mw.as_mut()) {
            // A cache hit is rdock's answer, not the backend's.
            if !stored {
                cx.backend =
                    rdock_middleware::BackendOutcome::Responded(upstream_response.status.as_u16());
            }
            let chain = &route.middlewares;
            chain.response(chain.len(), upstream_response, cx).await;
        }
        if let Some(cookie) = ctx.set_cookie.take() {
            upstream_response.append_header(http::header::SET_COOKIE, cookie)?;
        }
        if let Some(cc) = ctx.cache.as_mut() {
            crate::cache::decorate(session, upstream_response, cc);
            if crate::cache::from_store(session) {
                // A stored response's ID belongs to the request that filled the cache.
                upstream_response.insert_header("x-request-id", ctx.request_id())?;
            }
        }
        if !upstream_response.headers.contains_key("x-request-id") {
            upstream_response.insert_header("x-request-id", ctx.request_id())?;
        }
        self.advertise_http3(session, upstream_response);
        Ok(())
    }

    fn response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut RequestCtx,
    ) -> pingora::Result<Option<Duration>> {
        let Some(cx) = ctx.mw.as_mut() else {
            return Ok(None);
        };
        if let Some(page) = cx.replace_body.clone() {
            *body = (!ctx.sent_replacement).then_some(page);
            ctx.sent_replacement = true;
            return Ok(None);
        }
        // Body middlewares see the backend's bytes before compression and the throttle.
        if let Some(route) = &ctx.route {
            let chain = &route.middlewares;
            chain.response_body(chain.len(), body, end_of_stream, cx);
        }
        if let Some(encoder) = cx.compression.as_mut() {
            let chunk = body.take().unwrap_or_default();
            if !chunk.is_empty() || end_of_stream {
                let encoded = encoder.encode(&chunk, end_of_stream).map_err(|e| {
                    Error::because(ErrorType::InternalError, "compression failed", e)
                })?;
                *body = Some(encoded);
            }
        }
        if let (Some(throttle), Some(chunk)) = (&cx.throttle, body.as_ref()) {
            let wait = throttle.take(chunk.len());
            if !wait.is_zero() {
                return Ok(Some(wait));
            }
        }
        Ok(None)
    }

    async fn response_trailer_filter(
        &self,
        _session: &mut Session,
        upstream_trailers: &mut http::HeaderMap,
        ctx: &mut RequestCtx,
    ) -> pingora::Result<Option<Bytes>> {
        // gRPC-Web carries the trailers as a final body frame.
        match ctx.grpc_web.as_mut() {
            Some(grpc_web) => grpc_web.response_trailer_filter(upstream_trailers),
            None => Ok(None),
        }
    }

    fn suppress_error_log(&self, _session: &Session, _ctx: &RequestCtx, _error: &Error) -> bool {
        // Failures are reported in the access log.
        true
    }

    fn fail_to_connect(
        &self,
        session: &mut Session,
        _peer: &HttpPeer,
        ctx: &mut RequestCtx,
        e: Box<Error>,
    ) -> Box<Error> {
        if let Some(service) = &ctx.service {
            let kind = if matches!(e.etype(), ErrorType::ConnectTimedout) {
                "timeout"
            } else {
                "connect"
            };
            self.shared
                .metrics
                .upstream_errors
                .with_label_values(&[&*service.name, kind])
                .inc();
            if let Some(trace) = ctx.trace.as_mut() {
                trace.failed(kind);
            }
            self.report(service, ctx.member.as_ref(), false);
            Self::sample(service, ctx, false);
            if let Some(cx) = ctx.mw.as_mut() {
                cx.backend = rdock_middleware::BackendOutcome::Failed;
            }
        }
        let mut e = e;
        let service = ctx.service.clone();
        // A timed-out connect is retried only on a backend not tried yet: waiting again on the
        // same address cannot help (ADR-0028). A refused connect is quick and may be repeated.
        let timed_out = matches!(e.etype(), ErrorType::ConnectTimedout);
        if let Some(service) = service
            && (!timed_out || upstream::has_untried(&service, &ctx.tried))
            && self.take_retry(session, ctx, &service, RetryOn::Connect)
        {
            e.set_retry(true);
        }
        e
    }

    fn error_while_proxy(
        &self,
        peer: &HttpPeer,
        session: &mut Session,
        e: Box<Error>,
        ctx: &mut RequestCtx,
        client_reused: bool,
    ) -> Box<Error> {
        if ctx.refused {
            // rdock refused the request itself (body hold, a middleware's answer): not the
            // backend's failure, and not worth another attempt.
            let mut e = e;
            e.set_retry(false);
            return e;
        }
        // A reset or timeout before the response headers counts against the backend; a failure
        // on a reused pooled connection is the pool's, not the backend's, and a client that went
        // away is nobody's.
        if session.response_written().is_none()
            && !client_reused
            && e.esource() != &ErrorSource::Downstream
            && let Some(service) = &ctx.service
        {
            self.report(service, ctx.member.as_ref(), false);
            if let Some(cx) = ctx.mw.as_mut() {
                cx.backend = rdock_middleware::BackendOutcome::Failed;
            }
            if !ctx.status_retry {
                // A retried status was sampled when it arrived.
                ctx.sample_at_end = false;
                Self::sample(service, ctx, false);
            }
        }
        if let Some(trace) = ctx.trace.as_mut() {
            trace.failed(e.etype().as_str());
        }
        let mut e = e.more_context(format!("Peer: {peer}"));
        if std::mem::take(&mut ctx.status_retry) {
            // A retry of a backend status, already checked and counted.
            return e;
        }
        // Never retry once the client saw a response, or when the body cannot be replayed.
        // A reused pooled connection that closed under us is retried once for idempotent
        // requests, as Pingora does; everything else follows `retries`.
        if session.response_written().is_some() || session.as_ref().retry_buffer_truncated() {
            e.set_retry(false);
            return e;
        }
        if client_reused
            && session.req_header().method.is_idempotent()
            && pooled_connection_failed(&e)
        {
            // Bounded by Pingora's `max_retries` (set in `listener.rs`): each attempt takes
            // another pooled connection or opens a new one.
            e.set_retry(true);
            return e;
        }
        let kind = if matches!(
            e.etype(),
            ErrorType::ReadTimedout | ErrorType::WriteTimedout
        ) {
            RetryOn::Timeout
        } else {
            RetryOn::Reset
        };
        let service = ctx.service.clone();
        let retry = service.is_some_and(|service| self.take_retry(session, ctx, &service, kind));
        e.set_retry(retry);
        e
    }

    async fn fail_to_proxy(
        &self,
        session: &mut Session,
        e: &Error,
        ctx: &mut RequestCtx,
    ) -> FailToProxy {
        let code = error_status(e);
        if let Some(answer) = ctx.answer.take() {
            // A middleware answered while the request was being proxied.
            let status = answer.reply.status;
            if session.response_written().is_none() {
                let route = ctx.route.clone();
                let chain = route.as_ref().map(|r| (&r.middlewares, answer.index));
                if let Err(err) = self.reply(session, ctx, answer.reply, chain).await {
                    tracing::debug!(error = %err, "cannot send a middleware's answer");
                }
            }
            return FailToProxy {
                error_code: status,
                can_reuse_downstream: false,
            };
        }
        ctx.error = Some(e.to_string());
        if code > 0 && session.response_written().is_none() {
            let accept = session
                .req_header()
                .headers
                .get(http::header::ACCEPT)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            let mut page = None;
            if let (Some(route), Some(cx)) = (&ctx.route, &ctx.mw) {
                page = route.middlewares.error_page(code, cx).await;
            }
            let retry_after = matches!(code, 503 | 429).then_some(5);
            let page = page.map_or_else(
                || {
                    errorpage::render(&errorpage::ErrorInfo {
                        status: code,
                        request_id: ctx.request_id(),
                        accept: accept.as_deref(),
                        format: error_format(ctx),
                        kind: None,
                        retry_after,
                        extensions: None,
                    })
                },
                |(content_type, body)| errorpage::Page {
                    content_type,
                    body,
                    language: None,
                },
            );
            let (content_type, body) = (page.content_type, page.body);
            if let Ok(mut resp) = ResponseHeader::build(code, Some(5)) {
                let _ = resp.insert_header(http::header::CONTENT_TYPE, content_type);
                if let Some(language) = page.language {
                    let _ = resp.insert_header(http::header::CONTENT_LANGUAGE, language);
                }
                let _ = resp.insert_header(http::header::CACHE_CONTROL, "no-store");
                let _ = resp.insert_header(http::header::X_CONTENT_TYPE_OPTIONS, NOSNIFF);
                let _ = resp.insert_header("x-request-id", ctx.request_id());
                self.advertise_http3(session, &mut resp);
                if let Some(cc) = ctx.cache.as_mut() {
                    crate::cache::decorate(session, &mut resp, cc);
                }
                if let Some(seconds) = retry_after {
                    let _ = resp.insert_header(http::header::RETRY_AFTER, seconds.to_string());
                }
                let _ = resp.set_content_length(body.len());
                if let Err(err) = session
                    .as_downstream_mut()
                    .write_error_response(resp, body)
                    .await
                {
                    tracing::debug!(error = %err, "cannot send the error page");
                }
            }
        }
        FailToProxy {
            error_code: code,
            can_reuse_downstream: false,
        }
    }

    async fn logging(&self, session: &mut Session, e: Option<&Error>, ctx: &mut RequestCtx) {
        Self::sample_at_end(ctx, e.is_none());
        ctx.in_flight = None;
        // Frees a held body now; a spool file has no name and goes with its descriptor.
        ctx.hold = None;
        if let (Some(copy), Some(route)) = (ctx.mirror.take(), &ctx.route)
            && let Some(mirror) = &route.mirror
        {
            self.send_mirror(mirror, session.req_header(), copy);
        }
        let status = session
            .response_written()
            .map_or_else(|| e.map_or(0, error_status), |r| r.status.as_u16());
        if let Some(mut trace) = ctx.trace.take() {
            trace.finish(status);
        }
        self.count_http3(session, status);
        let route = ctx.route.as_ref();
        let route_name = route.map_or("", |r| &*r.name);
        let service = ctx.service.clone();
        let service_name = service.as_ref().map_or("", |s| &*s.name);
        let elapsed = ctx.started.elapsed();
        if let (Some(route), Some(cx)) = (route, ctx.mw.as_mut())
            && route.middlewares.flags().log
        {
            let summary = LogSummary {
                status,
                bytes_in: session.body_bytes_read() as u64,
                bytes_out: session.body_bytes_sent() as u64,
                duration: elapsed,
                upstream_duration: ctx.attempt_started.map(|t| t.elapsed()),
                error: ctx.error.clone().or_else(|| e.map(ToString::to_string)),
            };
            route.middlewares.log(&summary, cx);
        }
        if let Some(cc) = ctx.cache.as_mut() {
            crate::cache::observe(session, cc, route_name);
        }
        self.shared.metrics.observe_request(
            (&self.listener, route_name, service_name),
            session.req_header().method.as_str(),
            status,
            elapsed.as_secs_f64(),
        );
        if let Some(consumer) = ctx.mw.as_ref().and_then(|cx| cx.consumer.as_ref()) {
            self.shared
                .metrics
                .observe_consumer(&consumer.name, route_name, status);
        }
        if let Some(meter) = &ctx.runtime.metering {
            let cx = ctx.mw.as_ref();
            let consumer = cx.and_then(|cx| cx.consumer.as_ref());
            if consumer.is_some() || meter.all_requests() {
                // Only a queue push: the sinks' tasks do the sending (ADR-0030).
                meter.record(&rdock_observability::metering::MeterEvent {
                    id: uuid::Uuid::now_v7().to_string(),
                    time: std::time::SystemTime::now(),
                    consumer: consumer.map(|c| c.name.to_string()),
                    groups: consumer
                        .map(|c| c.groups.iter().map(ToString::to_string).collect())
                        .unwrap_or_default(),
                    key_id: cx
                        .and_then(|cx| cx.key_id.as_ref())
                        .map(ToString::to_string),
                    route: route_name.to_owned(),
                    service: service_name.to_owned(),
                    method: session.req_header().method.to_string(),
                    status,
                    bytes_in: session.body_bytes_read() as u64,
                    bytes_out: session.body_bytes_sent() as u64,
                    duration_ms: elapsed.as_secs_f64() * 1000.0,
                    cache_status: ctx.cache.as_ref().and_then(|c| c.label).map(str::to_owned),
                });
            }
        }
        let route_ring = route.map(|r| &r.live).filter(|r| r.is_recording());
        let service_ring = service
            .as_ref()
            .map(|s| &s.live)
            .filter(|r| r.is_recording());
        // Off unless the admin API or a threshold alert reads the rings.
        if route_ring.is_some() || service_ring.is_some() {
            let sample = rdock_observability::live::Sample {
                status,
                elapsed,
                bytes_in: session.body_bytes_read() as u64,
                bytes_out: session.body_bytes_sent() as u64,
            };
            let now = std::time::SystemTime::now();
            for ring in route_ring.into_iter().chain(service_ring) {
                ring.record(sample, now);
            }
        }
        let feed = &self.shared.metrics.feeds.logs;
        // Building the record is about twenty allocations; skip it when nobody reads it.
        if !ctx.runtime.access_log.enabled() && !feed.watched() {
            return;
        }
        let record = self.access_record(session, e, ctx, status, elapsed);
        ctx.runtime.access_log.write(&record);
        if feed.watched()
            && let Ok(entry) = serde_json::to_value(&record)
        {
            feed.send(entry);
        }
    }
}

/// The verified client certificate of the connection. Client-sent identity headers are
/// removed first: only the `client_cert` middleware sets them.
fn client_identity(session: &mut Session) -> Option<Arc<rdock_middleware::ClientIdentity>> {
    for name in rdock_middleware::IDENTITY_HEADERS {
        session.req_header_mut().remove_header(name);
    }
    handshake(session).and_then(|h| h.client_cert.clone())
}

/// What the TLS handshake of the connection established: from Pingora's TLS digest for HTTP/1
/// and HTTP/2, from the request's extensions for HTTP/3, whose custom session cannot carry our
/// value in the digest (`SslDigestExtension::set` is crate-private in Pingora 0.9.1).
fn handshake(session: &Session) -> Option<&crate::listener::Handshake> {
    session
        .digest()
        .and_then(|d| d.ssl_digest.as_ref())
        .and_then(|s| s.extension.get::<crate::listener::Handshake>())
        .or_else(|| {
            session
                .is_custom()
                .then(|| {
                    session
                        .req_header()
                        .extensions
                        .get::<Arc<crate::listener::Handshake>>()
                })
                .flatten()
                .map(AsRef::as_ref)
        })
}

/// Whether the request came over HTTP/3 (an `https` listener's QUIC side, ADR-0032).
fn is_http3(session: &Session) -> bool {
    session.is_custom() && session.req_header().version == Version::HTTP_3
}

/// The TLS client fingerprints of the connection. Every listener's fingerprint headers are
/// removed from what the client sent, on every listener; the listener's own are then set to
/// the computed values when it computes them.
fn connection_fingerprint(
    session: &mut Session,
    listener: Option<&ListenerRuntime>,
    all_headers: &[String],
) -> Option<Arc<rdock_middleware::ClientFingerprint>> {
    for name in all_headers {
        session.req_header_mut().remove_header(name.as_str());
    }
    let wanted = listener.and_then(|l| l.fingerprint.as_ref())?;
    let found = handshake(session).and_then(|h| h.fingerprint.get().cloned());
    let req = session.req_header_mut();
    for (header, value) in [
        (&wanted.header, found.as_ref().and_then(|f| f.ja4.clone())),
        (
            &wanted.ja3_header,
            found.as_ref().and_then(|f| f.ja3.clone()),
        ),
    ] {
        let Some(name) = header else { continue };
        req.remove_header(name.as_str());
        if let Some(value) = value {
            let _ = req.insert_header(name.clone(), value.as_ref());
        }
    }
    found
}

/// Sends a reply body: one write for bytes in memory, chunk by chunk for a file.
async fn send_body(
    session: &mut Session,
    mut cx: Option<&mut MwContext>,
    chain: Option<(&Chain, usize)>,
    body: Body,
) -> pingora::Result<()> {
    let mut file = match body {
        Body::Bytes(bytes) => return send_chunk(session, cx, chain, bytes, true).await,
        Body::File(file) => file,
    };
    loop {
        let chunk = file
            .next_chunk()
            .await
            .map_err(|e| Error::because(ErrorType::ReadError, "reading a static file failed", e))?;
        let end = file.is_finished();
        send_chunk(session, cx.as_deref_mut(), chain, chunk, end).await?;
        if end {
            return Ok(());
        }
    }
}

/// Writes one chunk of a reply body through the chain's `response_body` phase and the
/// response compression, then waits as long as the `bandwidth` throttle asks.
async fn send_chunk(
    session: &mut Session,
    cx: Option<&mut MwContext>,
    chain: Option<(&Chain, usize)>,
    chunk: Bytes,
    end: bool,
) -> pingora::Result<()> {
    let Some(cx) = cx else {
        return session.write_response_body(Some(chunk), end).await;
    };
    let chunk = match chain {
        Some((chain, upto)) if chain.flags().response_body => {
            let mut body = Some(chunk);
            chain.response_body(upto, &mut body, end, cx);
            let chunk = body.unwrap_or_default();
            if chunk.is_empty() && !end {
                return Ok(());
            }
            chunk
        }
        _ => chunk,
    };
    let chunk = match cx.compression.as_mut() {
        Some(encoder) => encoder
            .encode(&chunk, end)
            .map_err(|e| Error::because(ErrorType::InternalError, "compression failed", e))?,
        None => chunk,
    };
    let wait = cx
        .throttle
        .as_ref()
        .map_or(Duration::ZERO, |throttle| throttle.take(chunk.len()));
    session.write_response_body(Some(chunk), end).await?;
    if !wait.is_zero() {
        tokio::time::sleep(wait).await;
    }
    Ok(())
}

/// Per-request state that follows from the matched route: the service (a `split` picks its
/// target here), gRPC-Web translation and the route's body limit.
fn start_route(
    session: &mut Session,
    ctx: &mut RequestCtx,
    route: &RouteRuntime,
) -> pingora::Result<()> {
    ctx.service = route.service.as_ref().map(upstream::resolve);
    if route.grpc_web {
        let mut grpc_web = GrpcWebCtx::default();
        grpc_web.init();
        // Turns `application/grpc-web` into `application/grpc`; other requests pass.
        grpc_web.request_header_filter(session.req_header_mut());
        ctx.grpc_web = Some(grpc_web);
    }
    // A declared length over the limit is refused before anything is sent; chunked
    // bodies are counted as they arrive (`request_body_filter`).
    if let Some(max) = route.max_body.or(ctx.runtime.limits.max_body_bytes)
        && let Some(length) = session
            .req_header()
            .headers
            .get(http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
        && length > max.as_u64()
    {
        return Err(status_error(413, "request body too large"));
    }
    Ok(())
}

/// Starts holding the request body when the route's chain asks for it and the request has one
/// (upgrades are streams, not bodies). A declared length over the limit is refused before the
/// backend is contacted.
fn start_hold(
    session: &mut Session,
    ctx: &mut RequestCtx,
    route: &RouteRuntime,
    spool: &std::sync::OnceLock<Arc<rdock_middleware::Spool>>,
) -> pingora::Result<()> {
    if route.middlewares.flags().request_body.is_none()
        || session.is_body_empty()
        || is_upgrade(session.req_header())
    {
        return Ok(());
    }
    // Middlewares may waive their hold in the `request` phase (an agent that decided from the
    // head alone); the strictest of the remaining holds applies.
    let Some(hold) = ctx
        .mw
        .as_ref()
        .and_then(|cx| route.middlewares.hold_for(cx))
    else {
        return Ok(());
    };
    let limit = route
        .max_body
        .or(ctx.runtime.limits.max_body_bytes)
        .map_or(u64::MAX, rdock_model::values::ByteSize::as_u64)
        .min(hold.max);
    if declared_length(session.req_header()).is_some_and(|length| length > limit) {
        return Err(status_error(413, "request body too large to hold"));
    }
    // The spool is shared by the process; only a route that holds a body takes a handle.
    let spool = spool.get().cloned();
    ctx.hold = Some(Hold::Collecting(BodyHolder::new(hold, limit, spool)));
    Ok(())
}

/// `Content-Length` of a request, if it has a valid one.
fn declared_length(req: &RequestHeader) -> Option<u64> {
    req.headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
}

/// Whether this request is mirrored. Called once the middlewares let the request through: a
/// request they refused (authentication, IP allow list, rate limit) never reaches the route's
/// service, so it must not reach the mirror either.
fn start_mirror(req: &RequestHeader, ctx: &mut RequestCtx, route: &RouteRuntime) {
    if let Some(mirror) = &route.mirror
        && fastrand::u32(0..100) < mirror.percent
        && !is_upgrade(req)
    {
        ctx.mirror = Some(MirrorCopy::default());
    }
}

/// Largest request body copied to a mirror (Pingora's replay buffer is the same size).
const MIRROR_BODY: usize = 64 * 1024;

/// Request headers that belong to the client's connection, not to a copy.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// The request body of a mirrored request, up to [`MIRROR_BODY`].
#[derive(Debug, Default)]
struct MirrorCopy {
    body: bytes::BytesMut,
    too_large: bool,
}

impl MirrorCopy {
    fn push(&mut self, chunk: &[u8]) {
        if self.too_large || self.body.len() + chunk.len() > MIRROR_BODY {
            self.too_large = true;
            self.body.clear();
        } else {
            self.body.extend_from_slice(chunk);
        }
    }

    fn body(self) -> Option<Bytes> {
        (!self.too_large).then(|| self.body.freeze())
    }
}

/// Reports what an outlier detector did with `backend` of `service`: logs, events, alerts and
/// metrics, as a failure ejection does.
pub(crate) fn outlier_ejected(
    service: &ServiceRuntime,
    backend: &str,
    detector: rdock_balancer::Detector,
    result: Ejection,
    metrics: &rdock_observability::Metrics,
) {
    let reason = match detector {
        rdock_balancer::Detector::SuccessRate => "ejected as an outlier by success rate",
        rdock_balancer::Detector::FailurePercentage => {
            "ejected as an outlier by failure percentage"
        }
    };
    match result {
        Ejection::Ejected(time) => {
            tracing::warn!(
                service = %service.name,
                backend = %backend,
                detector = detector.as_str(),
                seconds = time.as_secs(),
                "backend ejected as an outlier"
            );
            metrics.feeds.events.send(serde_json::json!({
                "type": "backend", "service": &*service.name, "backend": backend, "state": "down",
                "reason": reason, "seconds": time.as_secs(),
            }));
            if let Some(member) = service.members().iter().find(|m| m.id == backend) {
                crate::alerting::backend_down(metrics, service, member, reason);
            }
            metrics
                .backend_ejections
                .with_label_values(&[&*service.name, backend])
                .inc();
            metrics
                .outlier_ejections
                .with_label_values(&[&*service.name, backend, detector.as_str()])
                .inc();
            metrics
                .backend_up
                .with_label_values(&[&*service.name, backend])
                .set(0);
        }
        Ejection::Refused => tracing::warn!(
            service = %service.name,
            backend = %backend,
            detector = detector.as_str(),
            "backend is an outlier, but max_ejection_percent of the pool is already ejected"
        ),
        Ejection::None => {}
    }
}

/// `retries.per_try_timeout` when it applies to the attempt about to start (ADR-0031): the
/// request may be retried on a timeout (attempts left, an idempotent method or
/// `retry_non_idempotent`, not an upgrade, a body Pingora can still replay) and a backend it
/// has not tried is available. Otherwise the attempt is the last one and waits
/// `timeouts.read`.
///
/// Pingora 0.9 sets the read timeout of an attempt once, from the peer, and applies it to every
/// read: the response headers and each read of the body (`proxy_h1.rs`, `proxy_h2.rs`). No hook
/// reaches the upstream session after the headers, so the bound also covers pauses in the body
/// of such an attempt.
fn per_try_timeout(
    session: &Session,
    ctx: &RequestCtx,
    service: &ServiceRuntime,
) -> Option<Duration> {
    let retries = service.retries.as_ref()?;
    let per_try = retries.per_try_timeout?.as_std();
    let req = session.req_header();
    let retryable = retries.on.contains(&RetryOn::Timeout)
        && ctx.retries < retries.attempts
        && (retries.retry_non_idempotent || req.method.is_idempotent())
        && !is_upgrade(req)
        && !session.as_ref().retry_buffer_truncated();
    (retryable && upstream::has_untried(service, &ctx.tried)).then_some(per_try)
}

/// Whether `e` is a connection-level failure of an upstream connection, the kind a pooled
/// keep-alive connection the backend closed while it sat idle produces: Pingora's own
/// "reused only" verdict (the connection closed or reset while the response headers were
/// read), or a closed connection, or an operating-system read or write error (`EPIPE`,
/// `ECONNRESET`) at any point before the response. Timeouts and TLS errors are not.
fn pooled_connection_failed(e: &Error) -> bool {
    if e.esource() != &ErrorSource::Upstream {
        return false;
    }
    if matches!(e.retry, pingora::RetryType::ReusedOnly) {
        return true;
    }
    match e.etype() {
        ErrorType::ConnectionClosed => true,
        ErrorType::ReadError | ErrorType::WriteError => e
            .root_cause()
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.raw_os_error().is_some()),
        _ => false,
    }
}

/// Whether a request is a protocol upgrade as Pingora forwards one: `CONNECT`, or an HTTP/1.1
/// WebSocket handshake (`Upgrade: websocket`). Pingora removes any other `Upgrade` before the
/// backend sees the request, and reads the body of such a request like any other, so it is
/// held and inspected like any other.
fn is_upgrade(req: &RequestHeader) -> bool {
    req.method == http::Method::CONNECT || is_websocket_handshake(req)
}

/// The same test as Pingora's `is_websocket_upgrade_request` (0.9.1, `proxy_common.rs`).
fn is_websocket_handshake(req: &RequestHeader) -> bool {
    req.version == Version::HTTP_11
        && req
            .headers
            .get(http::header::UPGRADE)
            .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"websocket"))
}

/// Joins several `Cookie` fields into one with `"; "`. HTTP/2 clients may split cookies into
/// fields of their own, which must be joined before an HTTP/1.1 hop (RFC 9113 §8.2.3); a
/// backend that reads only the first field would otherwise see other cookies than rdock's
/// middlewares did. One field, or a value that is not text, is left as it is.
fn join_cookies(req: &mut RequestHeader) {
    let fields = req.headers.get_all(http::header::COOKIE);
    if fields.iter().nth(1).is_none() {
        return;
    }
    let parts: Option<Vec<&str>> = fields.iter().map(|v| v.to_str().ok()).collect();
    let Some(joined) = parts.map(|p| p.join("; ")) else {
        return;
    };
    if let Ok(value) = HeaderValue::from_str(&joined) {
        let _ = req.insert_header(http::header::COOKIE, value);
    }
}

/// `Connection` options that are not header names rdock may act on early: the standard
/// connection options, hop-by-hop and framing fields (Pingora handles them), and the names
/// Pingora refuses to see nominated (it answers 400 for those, which must stay so).
const CONNECTION_KEPT: [&str; 13] = [
    "close",
    // Framing: Pingora reads the body by it; left to its sanitizer as before.
    "content-length",
    "keep-alive",
    "upgrade",
    "te",
    "trailer",
    "transfer-encoding",
    "proxy-connection",
    "http2-settings",
    "host",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
];

/// Most `Connection` options Pingora accepts (`MAX_CONNECTION_NOMINATIONS`, 0.9.1); a header
/// with more is left for it to refuse.
const MAX_NOMINATIONS: usize = 10;

/// Removes the client's own fields that its `Connection` header nominates, and the
/// nominations with them, before rdock writes its headers (RFC 9110 §7.6.1). Pingora removes
/// nominated fields only after the request phase, from the request rdock has already
/// decorated, so a client could otherwise have `X-Real-IP`, `X-Request-Id`, identity or
/// fingerprint headers that rdock sets removed on the way to the backend. Options that are
/// not plain header names, the standard ones and the ones Pingora refuses are left for
/// Pingora.
fn strip_connection_nominations(req: &mut RequestHeader) {
    if !req.headers.contains_key(http::header::CONNECTION) {
        return;
    }
    let tokens: Vec<String> = req
        .headers
        .get_all(http::header::CONNECTION)
        .iter()
        .flat_map(|v| v.as_bytes().split(|b| *b == b','))
        .map(|t| String::from_utf8_lossy(t.trim_ascii()).into_owned())
        .filter(|t| !t.is_empty())
        .collect();
    if tokens.len() >= MAX_NOMINATIONS {
        return;
    }
    let mut kept = Vec::new();
    let mut stripped = false;
    for token in tokens {
        let lower = token.to_ascii_lowercase();
        let name = (!CONNECTION_KEPT.contains(&lower.as_str()))
            .then(|| HeaderName::from_bytes(lower.as_bytes()).ok())
            .flatten();
        match name {
            Some(name) => {
                req.remove_header(&name);
                stripped = true;
            }
            None => kept.push(token),
        }
    }
    if !stripped {
        return;
    }
    req.remove_header(&http::header::CONNECTION);
    if !kept.is_empty()
        && let Ok(value) = HeaderValue::from_str(&kept.join(", "))
    {
        let _ = req.insert_header(http::header::CONNECTION, value);
    }
}

/// Whether `authority` is `host [":" port]` (RFC 9112 §3.2, RFC 3986 §3.2.2): an IPv6
/// literal in brackets, or a name of letters, digits, `-`, `.` and `_` (container and service
/// names use `_`), with an optional numeric port. An empty value is left to the `Host` checks
/// above. Percent-encoded names, userinfo, paths and everything else are refused.
fn valid_authority(authority: &str) -> bool {
    if authority.is_empty() {
        return true;
    }
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let Some((literal, after)) = rest.split_once(']') else {
            return false;
        };
        if literal.parse::<std::net::Ipv6Addr>().is_err() {
            return false;
        }
        match after {
            "" => return true,
            _ => match after.strip_prefix(':') {
                Some(port) => ("", port),
                None => return false,
            },
        }
    } else {
        match authority.split_once(':') {
            Some((host, port)) => (host, port),
            None => (authority, ""),
        }
    };
    let host_ok = host
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_'));
    let port_ok = port.len() <= 5 && port.bytes().all(|b| b.is_ascii_digit());
    host_ok && port_ok && (!host.is_empty() || authority.starts_with('['))
}

/// Whether a request declares a body (a `Content-Length` above zero, or any
/// `Transfer-Encoding`).
fn declares_body(req: &RequestHeader) -> bool {
    req.headers.contains_key(http::header::TRANSFER_ENCODING)
        || req
            .headers
            .get_all(http::header::CONTENT_LENGTH)
            .iter()
            .any(|v| {
                v.as_bytes()
                    .iter()
                    .any(|b| b.is_ascii_digit() && *b != b'0')
            })
}

/// Longest pause a backend's `Retry-After` can cause.
const MAX_PAUSE: Duration = Duration::from_secs(60);

fn retry_reason(kind: RetryOn) -> &'static str {
    match kind {
        RetryOn::Connect => "connect",
        RetryOn::Reset => "reset",
        RetryOn::Timeout => "timeout",
        RetryOn::BadGateway => "502",
        RetryOn::ServiceUnavailable => "503",
        RetryOn::GatewayTimeout => "504",
    }
}

/// Fully jittered exponential backoff before retry `n` (1-based): a random time up to
/// 25 ms × 2ⁿ⁻¹, capped at 250 ms (Envoy's defaults).
fn backoff(n: u32) -> Duration {
    let ceiling = 25u64
        .saturating_mul(1 << n.saturating_sub(1).min(8))
        .min(250);
    Duration::from_millis(fastrand::u64(..=ceiling))
}

/// `Retry-After` as seconds or an HTTP date (RFC 9110 §10.2.3).
fn retry_after(resp: &ResponseHeader, now: SystemTime) -> Option<Duration> {
    let value = resp
        .headers
        .get(http::header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim();
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }
    httpdate::parse_http_date(value)
        .ok()?
        .duration_since(now)
        .ok()
}

/// `Host` for a backend: its configured name, with the port unless it is the scheme's default.
pub(crate) fn backend_authority(
    scheme: rdock_model::service::Scheme,
    candidate: &Candidate,
) -> String {
    use rdock_model::service::Scheme;
    match candidate {
        Candidate::Tcp { host, addr } => {
            let default = matches!(
                (scheme, addr.port()),
                (Scheme::Https | Scheme::H3, 443) | (Scheme::Http | Scheme::H2c, 80)
            );
            if default {
                host.clone()
            } else {
                format!("{host}:{}", addr.port())
            }
        }
        Candidate::Unix(_) => "localhost".to_owned(),
    }
}

/// The host part of an authority (`a.test:8080` → `a.test`, `[::1]:80` → `[::1]`).
fn rdock_middleware_host(authority: &str) -> &str {
    if authority.starts_with('[') {
        return authority
            .find(']')
            .map_or(authority, |end| &authority[..=end]);
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if port.bytes().all(|b| b.is_ascii_digit()) => host,
        _ => authority,
    }
}

/// Maps an error to the status sent to the client: timeouts towards the backend are 504, other
/// backend failures 502, a client that went away 0 (nothing is sent).
fn error_status(e: &Error) -> u16 {
    match e.etype() {
        ErrorType::HTTPStatus(code) => *code,
        ErrorType::ConnectTimedout
        | ErrorType::ReadTimedout
        | ErrorType::WriteTimedout
        | ErrorType::TLSHandshakeTimedout
            if e.esource() == &ErrorSource::Upstream =>
        {
            504
        }
        _ => match e.esource() {
            ErrorSource::Upstream => 502,
            ErrorSource::Downstream => match e.etype() {
                ErrorType::WriteError | ErrorType::ReadError | ErrorType::ConnectionClosed => 0,
                ErrorType::ReadTimedout | ErrorType::WriteTimedout => 408,
                _ => 400,
            },
            ErrorSource::Internal | ErrorSource::Unset => 500,
        },
    }
}

/// The automatic redirect to HTTPS: 301 for GET, 308 otherwise (method and body are kept).
fn https_redirect(req: &RequestHeader, authority: &str, port: u16) -> Reply {
    let host = rdock_middleware_host(authority);
    let path = req.uri.path_and_query().map_or("/", |p| p.as_str());
    let location = if port == 443 {
        format!("https://{host}{path}")
    } else {
        format!("https://{host}:{port}{path}")
    };
    let status = if req.method == http::Method::GET {
        301
    } else {
        308
    };
    let mut reply = Reply::status(status);
    reply.body = Some(Body::Bytes(Bytes::new()));
    if let Ok(value) = HeaderValue::from_str(&location) {
        reply.headers.push((http::header::LOCATION, value));
    }
    reply
}

/// Replaces the request path, keeping query and authority.
fn set_path(req: &mut RequestHeader, path: &str) -> pingora::Result<()> {
    let path_and_query = match req.uri.query() {
        Some(q) => format!("{path}?{q}"),
        None => path.to_owned(),
    };
    let mut parts = req.uri.clone().into_parts();
    parts.path_and_query = Some(
        path_and_query
            .parse()
            .map_err(|_| status_error(400, "invalid request path"))?,
    );
    let uri =
        http::Uri::from_parts(parts).map_err(|_| status_error(400, "invalid request path"))?;
    req.set_uri(uri);
    Ok(())
}

/// Fuzzing entry point (`tests/fuzz`, target `backend_response`): what rdock does with a
/// backend's response head before anything else reads it: the connection-specific headers it
/// removes, and the pause a `503` with `Retry-After` asks for (capped like a real pause).
#[doc(hidden)]
pub fn fuzz_backend_response(resp: &mut ResponseHeader) -> Option<Duration> {
    strip_response_hop_by_hop(resp);
    retry_after(resp, SystemTime::now()).map(|wait| wait.min(MAX_PAUSE))
}

/// Removes connection-specific headers from a backend response (Pingora only cleans requests).
fn strip_response_hop_by_hop(resp: &mut ResponseHeader) {
    if resp.status.as_u16() == 101 {
        return;
    }
    let nominated: Vec<String> = resp
        .headers
        .get_all(http::header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|t| t.trim().to_ascii_lowercase())
        .filter(|t| !t.is_empty() && t != "close" && t != "keep-alive")
        .collect();
    for name in nominated {
        resp.remove_header(&name);
    }
    for name in ["keep-alive", "proxy-connection", "upgrade"] {
        resp.remove_header(name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_errors_to_statuses() {
        let up = |t: ErrorType| {
            let mut e = Error::new(t);
            e.esource = ErrorSource::Upstream;
            error_status(&e)
        };
        assert_eq!(up(ErrorType::ConnectRefused), 502);
        assert_eq!(up(ErrorType::ConnectTimedout), 504);
        assert_eq!(up(ErrorType::ReadTimedout), 504);
        assert_eq!(error_status(&Error::new(ErrorType::HTTPStatus(431))), 431);
        let mut gone = Error::new(ErrorType::ConnectionClosed);
        gone.esource = ErrorSource::Downstream;
        assert_eq!(error_status(&gone), 0);
    }

    fn head(method: &str, headers: &[(&str, &str)]) -> RequestHeader {
        let mut req = RequestHeader::build(method, b"/", None).unwrap();
        for (name, value) in headers {
            req.append_header((*name).to_owned(), *value).unwrap();
        }
        req
    }

    fn checked(headers: &[(&str, &str)]) -> Option<u16> {
        let req = head("POST", headers);
        RdockProxy::check_request(&Runtime::empty(), &req)
            .err()
            .map(|e| error_status(&e))
    }

    #[test]
    fn only_websocket_handshakes_and_connect_are_upgrades() {
        assert!(is_upgrade(&head("GET", &[("upgrade", "websocket")])));
        assert!(is_upgrade(&head("GET", &[("upgrade", "WebSocket")])));
        assert!(is_upgrade(&head("CONNECT", &[])));
        // Pingora strips these and forwards the request, body and all.
        assert!(!is_upgrade(&head("POST", &[("upgrade", "x")])));
        assert!(!is_upgrade(&head("POST", &[("upgrade", "h2c")])));
        let mut h10 = head("GET", &[("upgrade", "websocket")]);
        h10.set_version(Version::HTTP_10);
        assert!(!is_upgrade(&h10));
    }

    #[test]
    fn websocket_handshakes_with_a_body_are_refused() {
        let ws = [("host", "a.test"), ("upgrade", "websocket")];
        assert_eq!(checked(&ws), None);
        assert_eq!(checked(&[ws[0], ws[1], ("content-length", "0")]), None);
        assert_eq!(
            checked(&[ws[0], ws[1], ("content-length", "12")]),
            Some(400)
        );
        assert_eq!(
            checked(&[ws[0], ws[1], ("transfer-encoding", "chunked")]),
            Some(400)
        );
        assert_eq!(
            checked(&[ws[0], ("upgrade", "x"), ("content-length", "12")]),
            None,
            "not an upgrade: its body is held like any other"
        );
    }

    #[test]
    fn host_must_be_a_host_and_port() {
        for good in [
            "a.test",
            "A.Test.",
            "a.test:8080",
            "my_service",
            "192.0.2.1:80",
            "[2001:db8::1]",
            "[::1]:443",
            "a.test:",
        ] {
            assert_eq!(checked(&[("host", good)]), None, "{good}");
        }
        for bad in [
            "a/b.example.com",
            "a?b.example.com",
            "a\\b.example.com",
            "a b",
            "a%2eb",
            "a#b",
            "u@a.test",
            "a.test:80:80",
            "a.test:http",
            "a.test:123456",
            "[zz::1]",
            "[::1]x",
            "::1",
        ] {
            assert_eq!(checked(&[("host", bad)]), Some(400), "{bad}");
        }
    }

    #[test]
    fn connection_cannot_remove_headers_rdock_sets_later() {
        let mut req = head(
            "GET",
            &[
                ("connection", "keep-alive, X-Real-IP, x-request-id"),
                ("connection", "X-Consumer-Name"),
                ("x-real-ip", "203.0.113.9"),
                ("x-custom", "kept"),
            ],
        );
        strip_connection_nominations(&mut req);
        // The client's own nominated fields go now, as RFC 9110 asks; the nominations go with
        // them, so Pingora does not remove what rdock writes afterwards.
        assert!(req.headers.get("x-real-ip").is_none());
        assert_eq!(
            req.headers.get_all("connection").iter().collect::<Vec<_>>(),
            vec!["keep-alive"]
        );
        assert!(req.headers.get("x-custom").is_some());
        // Nominations Pingora refuses are left for it to refuse.
        let mut protected = head("GET", &[("connection", "X-Forwarded-For, X-Real-IP")]);
        strip_connection_nominations(&mut protected);
        assert_eq!(protected.headers["connection"], "X-Forwarded-For");
        let mut malformed = head("GET", &[("connection", "\"X-Real-IP\"")]);
        strip_connection_nominations(&mut malformed);
        assert_eq!(malformed.headers["connection"], "\"X-Real-IP\"");
        let mut none = head("GET", &[("connection", "close")]);
        strip_connection_nominations(&mut none);
        assert_eq!(none.headers["connection"], "close");
    }

    #[test]
    fn every_expect_field_is_checked() {
        let host = ("host", "a.test");
        assert_eq!(checked(&[host, ("expect", "100-continue")]), None);
        assert_eq!(
            checked(&[host, ("expect", "100-continue"), ("expect", "foo")]),
            Some(417)
        );
    }

    #[test]
    fn split_cookie_fields_are_joined() {
        let mut req = head("GET", &[("cookie", "a=1"), ("cookie", "b=2")]);
        join_cookies(&mut req);
        assert_eq!(
            req.headers.get_all("cookie").iter().collect::<Vec<_>>(),
            vec!["a=1; b=2"]
        );
        let mut one = head("GET", &[("cookie", "a=1; b=2")]);
        join_cookies(&mut one);
        assert_eq!(one.headers["cookie"], "a=1; b=2");
    }

    #[test]
    fn connection_failures_of_pooled_connections_are_recognised() {
        let up = |etype: ErrorType, cause: Option<std::io::Error>| {
            let mut e = match cause {
                Some(io) => *Error::because(etype, "x", io),
                None => *Error::new(etype),
            };
            e.esource = ErrorSource::Upstream;
            e
        };
        let pipe = || Some(std::io::Error::from_raw_os_error(32));
        // The CI failure: EPIPE while writing the body to a reused connection.
        assert!(pooled_connection_failed(&up(ErrorType::WriteError, pipe())));
        assert!(pooled_connection_failed(&up(ErrorType::ReadError, pipe())));
        assert!(pooled_connection_failed(&up(
            ErrorType::ConnectionClosed,
            None
        )));
        let mut reused_only = up(ErrorType::ReadError, None);
        reused_only.retry = pingora::RetryType::ReusedOnly;
        assert!(pooled_connection_failed(&reused_only));
        // Not connection failures: timeouts, TLS-level read errors, the client's side.
        assert!(!pooled_connection_failed(&up(
            ErrorType::ReadTimedout,
            None
        )));
        assert!(!pooled_connection_failed(&up(
            ErrorType::WriteTimedout,
            None
        )));
        assert!(!pooled_connection_failed(&up(
            ErrorType::ReadError,
            Some(std::io::Error::other("tls"))
        )));
        let mut downstream = up(ErrorType::WriteError, pipe());
        downstream.esource = ErrorSource::Downstream;
        assert!(!pooled_connection_failed(&downstream));
    }

    #[test]
    fn https_redirects_keep_path_and_choose_codes() {
        let req = RequestHeader::build("GET", b"/a?b", None).unwrap();
        let reply = https_redirect(&req, "app.test:80", 443);
        assert_eq!(reply.status, 301);
        assert_eq!(reply.headers[0].1, "https://app.test/a?b");
        let post = RequestHeader::build("POST", b"/", None).unwrap();
        let reply = https_redirect(&post, "app.test", 8443);
        assert_eq!(reply.status, 308);
        assert_eq!(reply.headers[0].1, "https://app.test:8443/");
    }

    #[test]
    fn strips_response_hop_by_hop_headers() {
        let mut resp = ResponseHeader::build(200, None).unwrap();
        resp.insert_header("connection", "x-secret, close").unwrap();
        resp.insert_header("x-secret", "1").unwrap();
        resp.insert_header("keep-alive", "timeout=5").unwrap();
        resp.insert_header("x-kept", "1").unwrap();
        strip_response_hop_by_hop(&mut resp);
        assert!(resp.headers.get("x-secret").is_none());
        assert!(resp.headers.get("keep-alive").is_none());
        assert!(resp.headers.get("x-kept").is_some());
    }

    #[test]
    fn request_ids_are_bounded() {
        assert!(valid_request_id("abc-123"));
        assert!(!valid_request_id(""));
        assert!(!valid_request_id("has space"));
        assert!(!valid_request_id(&"a".repeat(129)));
    }
}
