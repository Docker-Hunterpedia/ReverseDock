//! `forward_auth`: asks an authentication service (Authelia, Authentik, oauth2-proxy…) whether a
//! request may continue, the way Traefik's `forwardAuth` does.
//!
//! The service gets a GET with the client's headers and `X-Forwarded-Method/-Proto/-Host/-Uri`.
//! A 2xx lets the request continue, with `copy_headers` taken from the answer (after removing
//! any the client sent itself, so they cannot be forged). Any other answer goes back to the
//! client as it is. If the service cannot be reached the request fails closed: 502, or 504 on
//! timeout.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use http::{HeaderName, HeaderValue, Method};
use pingora::http::RequestHeader;
use rdock_model::middleware::ForwardAuthConfig;
use url::Url;

use crate::client::{FetchError, HttpClient};
use crate::{BuildError, Context, Flow, Middleware, Reply};

/// Largest auth-service response body passed to the client.
const MAX_BODY: usize = 1024 * 1024;

/// Headers never copied between the client, the auth service and the backend.
const HOP_BY_HOP: [&str; 10] = [
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
];

/// The `forward_auth` middleware.
#[derive(Debug)]
pub(crate) struct ForwardAuth {
    address: Url,
    copy_headers: Vec<HeaderName>,
    request_headers: Vec<HeaderName>,
    timeout: Duration,
    trust_forward_header: bool,
    client: Arc<HttpClient>,
}

fn names(list: &[String]) -> Result<Vec<HeaderName>, BuildError> {
    list.iter()
        .map(|n| {
            HeaderName::from_bytes(n.as_bytes())
                .map_err(|_| BuildError::Invalid(format!("`{n}` is not a valid header name")))
        })
        .collect()
}

impl ForwardAuth {
    pub(crate) fn new(
        config: &ForwardAuthConfig,
        client: Arc<HttpClient>,
    ) -> Result<Self, BuildError> {
        Ok(Self {
            address: config.address.as_url().clone(),
            copy_headers: names(&config.copy_headers)?,
            request_headers: names(&config.request_headers)?,
            timeout: config.timeout.as_std(),
            trust_forward_header: config.trust_forward_header,
            client,
        })
    }

    /// The request sent to the auth service.
    fn auth_request(&self, req: &RequestHeader, cx: &Context) -> Option<RequestHeader> {
        let target = match self.address.query() {
            Some(q) => format!("{}?{q}", self.address.path()),
            None => self.address.path().to_owned(),
        };
        let mut auth = RequestHeader::build(Method::GET, target.as_bytes(), None).ok()?;
        for (name, value) in &req.headers {
            let wanted = self.request_headers.is_empty()
                || self.request_headers.contains(name)
                || name.as_str().starts_with("x-forwarded-");
            if wanted && !HOP_BY_HOP.contains(&name.as_str()) {
                let _ = auth.append_header(name.clone(), value.clone());
            }
        }
        let host = match (self.address.host_str(), self.address.port()) {
            (Some(h), Some(p)) => format!("{h}:{p}"),
            (Some(h), None) => h.to_owned(),
            (None, _) => return None,
        };
        let uri = req
            .uri
            .path_and_query()
            .map_or("/", |p| p.as_str())
            .to_owned();
        let proto = if cx.tls { "https" } else { "http" };
        let facts = [
            ("x-forwarded-method", req.method.as_str().to_owned()),
            ("x-forwarded-proto", proto.to_owned()),
            ("x-forwarded-host", cx.authority.clone()),
            ("x-forwarded-uri", uri),
        ];
        for (name, value) in facts {
            if self.trust_forward_header && auth.headers.contains_key(name) {
                continue;
            }
            if let Ok(value) = HeaderValue::from_str(&value) {
                let _ = auth.insert_header(name, value);
            }
        }
        let _ = auth.insert_header(http::header::HOST, host);
        Some(auth)
    }

    /// The auth service's refusal, passed to the client.
    fn refusal(&self, status: u16, headers: &http::HeaderMap, body: bytes::Bytes) -> Reply {
        let mut out = Vec::new();
        for (name, value) in headers {
            if HOP_BY_HOP.contains(&name.as_str()) {
                continue;
            }
            let value = if name == http::header::LOCATION {
                value
                    .to_str()
                    .ok()
                    .and_then(|l| self.address.join(l).ok())
                    .and_then(|u| HeaderValue::from_str(u.as_str()).ok())
                    .unwrap_or_else(|| value.clone())
            } else {
                value.clone()
            };
            out.push((name.clone(), value));
        }
        Reply {
            status,
            headers: out,
            body: Some(body),
        }
    }
}

#[async_trait]
impl Middleware for ForwardAuth {
    async fn request(&self, req: &mut RequestHeader, cx: &mut Context) -> Flow {
        let Some(auth) = self.auth_request(req, cx) else {
            return Flow::Reply(Reply::status(502));
        };
        let result = match self.client.peer_for(&self.address, self.timeout).await {
            Ok(peer) => self.client.send(&peer, auth, self.timeout, MAX_BODY).await,
            Err(e) => Err(e),
        };
        let fetched = match result {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!(error = %e, address = %self.address, "forward authentication failed");
                let status = if e == FetchError::Timeout { 504 } else { 502 };
                return Flow::Reply(Reply::status(status));
            }
        };
        let status = fetched.header.status.as_u16();
        if !(200..300).contains(&status) {
            return Flow::Reply(self.refusal(status, &fetched.header.headers, fetched.body));
        }
        for name in &self.copy_headers {
            req.remove_header(name);
            for value in fetched.header.headers.get_all(name) {
                let _ = req.append_header(name.clone(), value.clone());
            }
        }
        Flow::Next
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::test_support::{cx, header, request};

    /// A one-shot HTTP/1.1 server answering every request with `response`; returns the
    /// request it received.
    async fn auth_server(response: &'static str) -> (SocketAddr, tokio::task::JoinHandle<String>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0; 8192];
            let n = socket.read(&mut buf).await.unwrap();
            socket.write_all(response.as_bytes()).await.unwrap();
            socket.shutdown().await.unwrap();
            String::from_utf8_lossy(&buf[..n]).into_owned()
        });
        (addr, task)
    }

    fn middleware(addr: SocketAddr, timeout: Duration) -> ForwardAuth {
        ForwardAuth::new(
            &ForwardAuthConfig {
                address: format!("http://{addr}/verify?rd=1").parse().unwrap(),
                copy_headers: vec!["Remote-User".into()],
                request_headers: Vec::new(),
                timeout: rdock_model::values::Duration::from_millis(
                    u64::try_from(timeout.as_millis()).unwrap(),
                ),
                trust_forward_header: false,
            },
            Arc::new(HttpClient::default()),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn allows_and_copies_headers_without_trusting_the_client() {
        let (addr, server) = auth_server(
            "HTTP/1.1 200 OK\r\nRemote-User: alice\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .await;
        let mw = middleware(addr, Duration::from_secs(2));
        let mut req = request(
            "POST",
            "/app?x=1",
            &[("remote-user", "mallory"), ("cookie", "session=1")],
        );
        let flow = mw.request(&mut req, &mut cx()).await;
        assert_eq!(flow, Flow::Next);
        assert_eq!(header(&req.headers, "remote-user"), Some("alice"));
        let seen = server.await.unwrap().to_ascii_lowercase();
        assert!(seen.starts_with("get /verify?rd=1 http/1.1"), "{seen}");
        assert!(seen.contains("x-forwarded-method: post"), "{seen}");
        assert!(seen.contains("x-forwarded-uri: /app?x=1"), "{seen}");
        assert!(seen.contains("cookie: session=1"), "{seen}");
    }

    #[tokio::test]
    async fn refusals_reach_the_client_and_outages_fail_closed() {
        let (addr, _server) = auth_server(
            "HTTP/1.1 302 Found\r\nLocation: /login\r\nContent-Length: 2\r\nConnection: close\r\n\r\nno",
        )
        .await;
        let mw = middleware(addr, Duration::from_secs(2));
        let mut req = request("GET", "/", &[]);
        let Flow::Reply(reply) = mw.request(&mut req, &mut cx()).await else {
            panic!("refusal expected")
        };
        assert_eq!(reply.status, 302);
        let location = reply
            .headers
            .iter()
            .find(|(n, _)| n == http::header::LOCATION)
            .map(|(_, v)| v.to_str().unwrap().to_owned());
        assert_eq!(location, Some(format!("http://{addr}/login")));
        assert_eq!(reply.body.as_deref(), Some(&b"no"[..]));

        let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead = closed.local_addr().unwrap();
        drop(closed);
        let mw = middleware(dead, Duration::from_secs(2));
        assert_eq!(
            mw.request(&mut request("GET", "/", &[]), &mut cx()).await,
            Flow::Reply(Reply::status(502))
        );
    }
}
