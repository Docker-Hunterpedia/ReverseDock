//! The spans of one request (M-OBS-01): a server span from the first hook to the access log,
//! and one client span per upstream attempt, whose context goes upstream in `traceparent`.

use std::net::IpAddr;
use std::sync::Arc;

use opentelemetry::trace::TraceContextExt;
use pingora::http::RequestHeader;
use rdock_observability::otel::{self, Span};
use rdock_observability::{KeyValue, Tracer};

use crate::runtime::Candidate;

/// Tracing state of a request.
pub(crate) struct Trace {
    tracer: Arc<Tracer>,
    server: opentelemetry::Context,
    client: Option<Span>,
}

impl std::fmt::Debug for Trace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Trace").finish_non_exhaustive()
    }
}

impl Trace {
    /// Starts the server span, continuing the client's trace if it sent `traceparent`.
    pub(crate) fn start(
        tracer: &Arc<Tracer>,
        req: &RequestHeader,
        tls: bool,
        http2: bool,
        host: &str,
    ) -> Self {
        let mut attributes = vec![
            KeyValue::new("http.request.method", req.method.to_string()),
            KeyValue::new("url.path", req.uri.path().to_owned()),
            KeyValue::new("url.scheme", if tls { "https" } else { "http" }),
            KeyValue::new("server.address", host.to_owned()),
            KeyValue::new("network.protocol.version", if http2 { "2" } else { "1.1" }),
        ];
        if let Some(agent) = req
            .headers
            .get(http::header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
        {
            attributes.push(KeyValue::new("user_agent.original", agent.to_owned()));
        }
        Self {
            tracer: tracer.clone(),
            server: tracer.server(&req.headers, req.method.as_str(), attributes),
            client: None,
        }
    }

    /// Names the server span after the matched route.
    pub(crate) fn route(&self, method: &str, route: &str, client: IpAddr) {
        otel::set_route(&self.server, method, route);
        self.server
            .span()
            .set_attribute(KeyValue::new("client.address", client.to_string()));
    }

    /// Starts the client span of an attempt (`resend` is 0 for the first).
    pub(crate) fn attempt(
        &mut self,
        req: &RequestHeader,
        candidate: &Candidate,
        host: &str,
        resend: u32,
    ) {
        let mut attributes = vec![
            KeyValue::new("http.request.method", req.method.to_string()),
            KeyValue::new("server.address", host.to_owned()),
            KeyValue::new("url.full", format!("{candidate}{}", req.uri.path())),
        ];
        if let Candidate::Tcp { addr, .. } = candidate {
            attributes.push(KeyValue::new("server.port", i64::from(addr.port())));
            attributes.push(KeyValue::new("network.peer.address", addr.ip().to_string()));
        }
        if resend > 0 {
            attributes.push(KeyValue::new(
                "http.request.resend_count",
                i64::from(resend),
            ));
        }
        if let Some(mut previous) = self.client.take() {
            otel::fail(&mut previous, "retried");
        }
        self.client = Some(
            self.tracer
                .client(&self.server, req.method.as_str(), attributes),
        );
    }

    /// Adds `traceparent` of the current attempt to the upstream request.
    pub(crate) fn inject(&self, upstream: &mut RequestHeader) {
        let Some(client) = &self.client else {
            return;
        };
        let mut headers = http::HeaderMap::new();
        otel::inject(&self.server, client, &mut headers);
        for (name, value) in &headers {
            let _ = upstream.insert_header(name.clone(), value.clone());
        }
    }

    /// The backend answered `status`.
    pub(crate) fn response(&mut self, status: u16) {
        if let Some(mut client) = self.client.take() {
            otel::finish(&mut client, status, true);
        }
    }

    /// The attempt failed without an answer.
    pub(crate) fn failed(&mut self, error_type: &str) {
        if let Some(mut client) = self.client.take() {
            otel::fail(&mut client, error_type);
        }
    }

    /// Ends the request with the status the client got.
    pub(crate) fn finish(&mut self, status: u16) {
        self.failed("aborted");
        otel::end_server(&self.server, status);
    }
}
