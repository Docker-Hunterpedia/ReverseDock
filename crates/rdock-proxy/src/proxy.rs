//! The Pingora `ProxyHttp` implementation: limits, client IP, routing, middlewares, upstream
//! selection, error pages, access log and metrics.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderValue, Version};
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::modules::http::HttpModules;
use pingora::proxy::{FailToProxy, ProxyHttp, Session};
use pingora::upstreams::peer::HttpPeer;
use pingora::{Error, ErrorSource, ErrorType};
use rdock_middleware::{Context as MwContext, Flow, Middleware, Reply};
use rdock_observability::{AccessRecord, Metrics, rfc3339};

use crate::errorpage;
use crate::forwarded::{self, Forwarding};
use crate::router::{Facts, normalize_host};
use crate::runtime::{Candidate, ListenerRuntime, RouteRuntime, Runtime};
use crate::upstream;

/// State shared by every listener.
#[derive(Debug)]
pub struct Shared {
    /// The configuration being served.
    pub runtime: ArcSwap<Runtime>,
    /// Metrics.
    pub metrics: Metrics,
    /// ACME challenge answers.
    pub challenges: Arc<rdock_tls::Challenges>,
}

/// The proxy of one listener.
#[derive(Debug)]
pub struct RdockProxy {
    listener: Arc<str>,
    shared: Arc<Shared>,
}

impl RdockProxy {
    /// The proxy for listener `listener`.
    #[must_use]
    pub fn new(listener: Arc<str>, shared: Arc<Shared>) -> Self {
        Self { listener, shared }
    }
}

/// Per-request state.
#[derive(Debug)]
pub struct RequestCtx {
    started: Instant,
    started_at: SystemTime,
    runtime: Arc<Runtime>,
    request_id: Arc<str>,
    peer: Option<IpAddr>,
    client_ip: Option<IpAddr>,
    tls: bool,
    authority: String,
    host: String,
    path: String,
    query_len: usize,
    route: Option<Arc<RouteRuntime>>,
    mw: Option<MwContext>,
    upstream: Option<Candidate>,
    in_flight: Option<rdock_balancer::InFlight>,
    set_cookie: Option<String>,
    body_bytes: u64,
    sent_replacement: bool,
    error: Option<String>,
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
        // RFC 9110 §10.1.1: only `100-continue` is defined; anything else (including obfuscated
        // spellings a backend might still honour) is refused.
        if req
            .headers
            .get(http::header::EXPECT)
            .is_some_and(|v| !v.as_bytes().eq_ignore_ascii_case(b"100-continue"))
        {
            return Err(status_error(417, "unsupported Expect"));
        }
        if let Some(max) = limits.max_body_bytes
            && let Some(length) = req
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

    /// Writes a complete response produced by rdock (redirects, middleware answers, 404).
    async fn reply(
        &self,
        session: &mut Session,
        ctx: &mut RequestCtx,
        reply: Reply,
        chain: &[Arc<dyn Middleware>],
    ) -> pingora::Result<()> {
        let mut resp = ResponseHeader::build(reply.status, Some(reply.headers.len() + 4))?;
        for (name, value) in reply.headers {
            resp.append_header(name, value)?;
        }
        let body = if let Some(body) = reply.body {
            body
        } else {
            let accept = session
                .req_header()
                .headers
                .get(http::header::ACCEPT)
                .and_then(|v| v.to_str().ok());
            let (content_type, body) = errorpage::render(reply.status, &ctx.request_id, accept);
            resp.insert_header(http::header::CONTENT_TYPE, content_type)?;
            resp.insert_header(http::header::CACHE_CONTROL, "no-store")?;
            body
        };
        resp.set_content_length(body.len())?;
        if let Some(cx) = ctx.mw.as_mut() {
            for mw in chain.iter().rev() {
                mw.response(&mut resp, cx).await;
            }
        }
        let body = ctx
            .mw
            .as_mut()
            .and_then(|cx| cx.replace_body.take())
            .unwrap_or(body);
        resp.insert_header("x-request-id", &*ctx.request_id)?;
        let head = session.req_header().method == http::Method::HEAD;
        session.write_response_header(Box::new(resp), head).await?;
        if !head {
            session.write_response_body(Some(body), true).await?;
        }
        Ok(())
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
            request_id: Arc::from(""),
            peer: None,
            client_ip: None,
            tls: false,
            authority: String::new(),
            host: String::new(),
            path: String::new(),
            query_len: 0,
            route: None,
            mw: None,
            upstream: None,
            in_flight: None,
            set_cookie: None,
            body_bytes: 0,
            sent_replacement: false,
            error: None,
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
        let req = session.req_header();
        ctx.authority = req
            .headers
            .get(http::header::HOST)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
            .or_else(|| req.uri.authority().map(|a| a.as_str().to_owned()))
            .unwrap_or_default();
        ctx.host = normalize_host(rdock_middleware_host(&ctx.authority));
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
        ctx.request_id = incoming_id.unwrap_or_else(|| Arc::from(uuid::Uuid::now_v7().to_string()));
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
        if listener.tls.is_none()
            && let Some(answer) = self.http01_answer(session.req_header())
        {
            let reply = Reply {
                status: 200,
                headers: vec![(
                    http::header::CONTENT_TYPE,
                    HeaderValue::from_static("text/plain"),
                )],
                body: Some(Bytes::copy_from_slice(answer.as_bytes())),
            };
            self.reply(session, ctx, reply, &[]).await?;
            return Ok(true);
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
        let route = {
            let req = session.req_header();
            let facts = Facts {
                host: &ctx.host,
                path: &normalized.routing,
                method: req.method.as_str(),
                headers: &req.headers,
                query: &query,
                client_ip,
            };
            listener
                .routes
                .iter()
                .find(|r| r.rule.matches(&facts))
                .cloned()
        };
        let Some(route) = route else {
            if let Some(redirect) = &listener.https_redirect
                && redirect.hosts.contains(&ctx.host)
            {
                let reply = https_redirect(session.req_header(), &ctx.authority, redirect.port);
                self.reply(session, ctx, reply, &[]).await?;
                return Ok(true);
            }
            self.reply(session, ctx, Reply::status(404), &[]).await?;
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
            .insert_header("x-request-id", &*ctx.request_id)?;
        ctx.route = Some(route.clone());
        let mut cx = MwContext::new(
            client_ip,
            ctx.tls,
            route.name.clone(),
            ctx.request_id.clone(),
            ctx.authority.clone(),
        );
        for (i, mw) in route.middlewares.iter().enumerate() {
            if let Flow::Reply(reply) = mw.request(session.req_header_mut(), &mut cx).await {
                ctx.mw = Some(cx);
                self.reply(session, ctx, reply, &route.middlewares[..i])
                    .await?;
                return Ok(true);
            }
        }
        ctx.mw = Some(cx);
        Ok(false)
    }

    async fn request_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
        ctx: &mut RequestCtx,
    ) -> pingora::Result<()> {
        if let (Some(max), Some(chunk)) = (ctx.runtime.limits.max_body_bytes, body.as_ref()) {
            ctx.body_bytes += chunk.len() as u64;
            if ctx.body_bytes > max.as_u64() {
                return Err(status_error(413, "request body too large"));
            }
        }
        Ok(())
    }

    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut RequestCtx,
    ) -> pingora::Result<Box<HttpPeer>> {
        let route = ctx
            .route
            .clone()
            .ok_or_else(|| status_error(404, "no route"))?;
        let key = upstream::RequestKey {
            request: Some(session.req_header()),
            client_ip: ctx.client_ip,
        };
        let selected = upstream::select(&route.service, key)
            .ok_or_else(|| status_error(503, "the service has no available backend"))?;
        let peer = upstream::peer(&route.service, &selected.member.candidate, &route.timeouts)?;
        ctx.in_flight = Some(selected.member.state.begin());
        ctx.upstream = Some(selected.member.candidate.clone());
        ctx.set_cookie = selected.set_cookie;
        Ok(Box::new(peer))
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut RequestCtx,
    ) -> pingora::Result<()> {
        let (Some(route), Some(candidate)) = (&ctx.route, &ctx.upstream) else {
            return Ok(());
        };
        // HTTP/1.0 clients may omit Host; backends (and HTTP/2) need one.
        let missing = !upstream_request.headers.contains_key(http::header::HOST)
            && upstream_request.uri.authority().is_none();
        if !route.service.pass_host_header || missing {
            upstream_request.insert_header(
                http::header::HOST,
                backend_authority(route.service.scheme, candidate),
            )?;
        }
        Ok(())
    }

    async fn upstream_response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        _ctx: &mut RequestCtx,
    ) -> pingora::Result<()> {
        strip_response_hop_by_hop(upstream_response);
        Ok(())
    }

    async fn response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut RequestCtx,
    ) -> pingora::Result<()> {
        // An HTTP/1.0 backend must not turn the client's HTTP/1.1 connection into HTTP/1.0.
        if !session.is_http2() {
            upstream_response.set_version(Version::HTTP_11);
        }
        if let (Some(route), Some(cx)) = (&ctx.route, ctx.mw.as_mut()) {
            for mw in route.middlewares.iter().rev() {
                mw.response(upstream_response, cx).await;
            }
        }
        if let Some(cookie) = ctx.set_cookie.take() {
            upstream_response.append_header(http::header::SET_COOKIE, cookie)?;
        }
        if !upstream_response.headers.contains_key("x-request-id") {
            upstream_response.insert_header("x-request-id", &*ctx.request_id)?;
        }
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
        if let Some(gzip) = cx.compression.as_mut() {
            let chunk = body.take().unwrap_or_default();
            if !chunk.is_empty() || end_of_stream {
                let encoded = gzip
                    .encode(&chunk, end_of_stream)
                    .map_err(|e| Error::because(ErrorType::InternalError, "gzip failed", e))?;
                *body = Some(encoded);
            }
        }
        Ok(None)
    }

    fn suppress_error_log(&self, _session: &Session, _ctx: &RequestCtx, _error: &Error) -> bool {
        // Failures are reported in the access log.
        true
    }

    fn fail_to_connect(
        &self,
        _session: &mut Session,
        _peer: &HttpPeer,
        ctx: &mut RequestCtx,
        e: Box<Error>,
    ) -> Box<Error> {
        if let Some(route) = &ctx.route {
            let kind = if matches!(e.etype(), ErrorType::ConnectTimedout) {
                "timeout"
            } else {
                "connect"
            };
            self.shared
                .metrics
                .upstream_errors
                .with_label_values(&[&*route.service.name, kind])
                .inc();
        }
        e
    }

    fn error_while_proxy(
        &self,
        peer: &HttpPeer,
        session: &mut Session,
        e: Box<Error>,
        _ctx: &mut RequestCtx,
        client_reused: bool,
    ) -> Box<Error> {
        let mut e = e.more_context(format!("Peer: {peer}"));
        // Retry only an idempotent request whose body can be replayed, only when the failure was
        // a reused connection closing under us, and never once the client saw a response.
        if session.response_written().is_some()
            || !session.req_header().method.is_idempotent()
            || session.as_ref().retry_buffer_truncated()
        {
            e.set_retry(false);
        } else {
            e.retry.decide_reuse(client_reused);
        }
        e
    }

    async fn fail_to_proxy(
        &self,
        session: &mut Session,
        e: &Error,
        ctx: &mut RequestCtx,
    ) -> FailToProxy {
        let code = error_status(e);
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
                for mw in route.middlewares.iter() {
                    if let Some(found) = mw.error_page(code, cx).await {
                        page = Some(found);
                        break;
                    }
                }
            }
            let (content_type, body) =
                page.unwrap_or_else(|| errorpage::render(code, &ctx.request_id, accept.as_deref()));
            if let Ok(mut resp) = ResponseHeader::build(code, Some(4)) {
                let _ = resp.insert_header(http::header::CONTENT_TYPE, content_type);
                let _ = resp.insert_header(http::header::CACHE_CONTROL, "no-store");
                let _ = resp.insert_header("x-request-id", &*ctx.request_id);
                if code == 503 || code == 429 {
                    let _ = resp.insert_header(http::header::RETRY_AFTER, "5");
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
        ctx.in_flight = None;
        let status = session
            .response_written()
            .map_or_else(|| e.map_or(0, error_status), |r| r.status.as_u16());
        let route = ctx.route.as_ref();
        let route_name = route.map_or("", |r| &*r.name);
        let service_name = route.map_or("", |r| &*r.service.name);
        let elapsed = ctx.started.elapsed();
        self.shared.metrics.observe_request(
            (&self.listener, route_name, service_name),
            session.req_header().method.as_str(),
            status,
            elapsed.as_secs_f64(),
        );
        let log = &ctx.runtime.access_log;
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
        let record = AccessRecord {
            ts: rfc3339(ctx.started_at),
            request_id: ctx.request_id.to_string(),
            client_ip: ctx.client_ip.map(|ip| ip.to_string()).unwrap_or_default(),
            method: req.method.to_string(),
            host: ctx.host.clone(),
            path: ctx.path.clone(),
            query_len: ctx.query_len,
            proto: if session.is_http2() {
                "HTTP/2".into()
            } else {
                format!("{:?}", req.version)
            },
            status,
            bytes_in: session.body_bytes_read(),
            bytes_out: session.body_bytes_sent(),
            duration_ms: elapsed.as_secs_f64() * 1000.0,
            listener: self.listener.to_string(),
            route: route.map(|r| r.name.to_string()),
            service: route.map(|r| r.service.name.to_string()),
            upstream: ctx.upstream.as_ref().map(ToString::to_string),
            tls_version: ssl.as_ref().map(|s| s.version.to_string()),
            tls_cipher: ssl.as_ref().map(|s| s.cipher.to_string()),
            sni: ssl
                .as_ref()
                .and_then(|s| s.extension.get::<crate::listener::ServerName>())
                .map(|s| s.0.clone()),
            user: ctx.mw.as_ref().and_then(|cx| cx.user.clone()),
            user_agent: header("user-agent"),
            referer: header("referer").map(|r| r.split('?').next().unwrap_or_default().to_owned()),
            cf_ray: header("cf-ray"),
            error: ctx.error.take().or_else(|| e.map(ToString::to_string)),
        };
        log.write(&record);
    }
}

/// `Host` for a backend: its configured name, with the port unless it is the scheme's default.
fn backend_authority(scheme: rdock_model::service::Scheme, candidate: &Candidate) -> String {
    use rdock_model::service::Scheme;
    match candidate {
        Candidate::Tcp { host, addr } => {
            let default = matches!(
                (scheme, addr.port()),
                (Scheme::Https, 443) | (Scheme::Http | Scheme::H2c, 80)
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
    reply.body = Some(Bytes::new());
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
