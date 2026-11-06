//! A fake HTTP API for testing API clients such as the DNS-01 adapters: an in-process HTTP/1
//! server on `127.0.0.1:0` with a route table, a record of every request, and failures
//! injected per route.
//!
//! ```no_run
//! # async fn demo() {
//! use rdock_testkit::fake_api::{FakeApi, Reply};
//! let api = FakeApi::start().await;
//! api.route("GET", "/zones/{zone}", |_, params| {
//!     Reply::json(200, serde_json::json!({ "zone": { "name": params["zone"] } }))
//! });
//! api.fail("GET", "/zones/{zone}", 1, Reply::too_many_requests(1));
//! // … point the client at `api.url()`, then inspect `api.requests()`.
//! # }
//! ```
//!
//! Routes are tried in the order they were added; a path pattern is a list of `/`-separated
//! segments where `{name}` matches any one segment and is passed to the handler. A request no
//! route matches gets `404` with `{"error": "no fake route"}`. Guards run before the routes and
//! can answer instead of them (an authentication check, for example).

use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http::{HeaderMap, Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use serde_json::Value;

/// Path parameters captured by `{name}` segments.
pub type Params = HashMap<String, String>;

type Handler = Arc<dyn Fn(&Recorded, &Params) -> Reply + Send + Sync>;
type Guard = Arc<dyn Fn(&Recorded) -> Option<Reply> + Send + Sync>;

/// One request the fake received.
#[derive(Debug, Clone)]
pub struct Recorded {
    /// The method.
    pub method: Method,
    /// The path, without the query.
    pub path: String,
    /// The raw query string, if any.
    pub query: Option<String>,
    /// The request headers.
    pub headers: HeaderMap,
    /// The request body.
    pub body: Bytes,
}

impl Recorded {
    /// `METHOD /path?query`, the way the request line reads.
    pub fn line(&self) -> String {
        match &self.query {
            Some(query) => format!("{} {}?{query}", self.method, self.path),
            None => format!("{} {}", self.method, self.path),
        }
    }

    /// A header value as text, if present.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    /// The body parsed as JSON (`Value::Null` when it is empty or not JSON).
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }

    /// The decoded query parameter `name`.
    pub fn query_param(&self, name: &str) -> Option<String> {
        url_decode_pairs(self.query.as_deref()?)
            .into_iter()
            .find_map(|(key, value)| (key == name).then_some(value))
    }
}

/// An answer: status, headers and body.
#[derive(Debug, Clone)]
pub struct Reply {
    status: StatusCode,
    headers: Vec<(String, String)>,
    body: Bytes,
}

impl Reply {
    /// A JSON answer.
    #[allow(clippy::needless_pass_by_value)] // takes `json!(…)` temporaries
    pub fn json(status: u16, body: Value) -> Self {
        Self::status(status)
            .header("content-type", "application/json")
            .body(body.to_string())
    }

    /// An answer with this status and no body.
    pub fn status(status: u16) -> Self {
        Self {
            status: StatusCode::from_u16(status).unwrap(),
            headers: Vec::new(),
            body: Bytes::new(),
        }
    }

    /// `429 Too Many Requests` with `Retry-After: <seconds>`.
    pub fn too_many_requests(retry_after_seconds: u64) -> Self {
        Self::json(429, serde_json::json!({ "error": "rate limited" }))
            .header("retry-after", &retry_after_seconds.to_string())
    }

    /// `503 Service Unavailable`.
    pub fn server_error() -> Self {
        Self::json(503, serde_json::json!({ "error": "unavailable" }))
    }

    /// Adds a header.
    #[must_use]
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    /// Replaces the body.
    #[must_use]
    pub fn body(mut self, body: impl Into<Bytes>) -> Self {
        self.body = body.into();
        self
    }

    fn into_response(self) -> Response<Full<Bytes>> {
        let mut response = Response::builder().status(self.status);
        for (name, value) in &self.headers {
            response = response.header(name, value);
        }
        response.body(Full::new(self.body)).unwrap()
    }
}

struct Route {
    method: Method,
    pattern: Vec<String>,
    handler: Handler,
}

struct Failure {
    method: Method,
    pattern: Vec<String>,
    remaining: usize,
    reply: Reply,
}

#[derive(Default)]
struct State {
    guards: Vec<Guard>,
    routes: Vec<Route>,
    failures: Vec<Failure>,
    requests: Vec<Recorded>,
}

impl State {
    fn answer(&mut self, request: &Recorded) -> Reply {
        if let Some(failure) = self.failures.iter_mut().find(|f| {
            f.remaining > 0
                && f.method == request.method
                && captures(&f.pattern, &request.path).is_some()
        }) {
            failure.remaining -= 1;
            return failure.reply.clone();
        }
        if let Some(reply) = self.guards.iter().find_map(|guard| guard(request)) {
            return reply;
        }
        for route in &self.routes {
            if route.method != request.method {
                continue;
            }
            if let Some(params) = captures(&route.pattern, &request.path) {
                return (route.handler)(request, &params);
            }
        }
        Reply::json(404, serde_json::json!({ "error": "no fake route" }))
    }
}

/// The running fake API. Dropping it leaves the server running until the test's runtime ends.
#[derive(Clone)]
pub struct FakeApi {
    url: String,
    state: Arc<Mutex<State>>,
}

impl FakeApi {
    /// Starts a fake on a free loopback port.
    pub async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let state: Arc<Mutex<State>> = Arc::default();
        let shared = state.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let state = shared.clone();
                tokio::spawn(async move {
                    let service = service_fn(move |request| serve(request, state.clone()));
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        Self { url, state }
    }

    /// `http://127.0.0.1:<port>`.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Answers `method` requests matching `pattern` with `handler`.
    pub fn route(
        &self,
        method: &str,
        pattern: &str,
        handler: impl Fn(&Recorded, &Params) -> Reply + Send + Sync + 'static,
    ) {
        self.state.lock().unwrap().routes.push(Route {
            method: method.parse().unwrap(),
            pattern: segments(pattern),
            handler: Arc::new(handler),
        });
    }

    /// Runs `guard` before the routes; when it returns a reply, that is the answer.
    pub fn guard(&self, guard: impl Fn(&Recorded) -> Option<Reply> + Send + Sync + 'static) {
        self.state.lock().unwrap().guards.push(Arc::new(guard));
    }

    /// Answers the next `times` requests matching `method` and `pattern` with `reply`, before
    /// guards and routes run.
    pub fn fail(&self, method: &str, pattern: &str, times: usize, reply: Reply) {
        self.state.lock().unwrap().failures.push(Failure {
            method: method.parse().unwrap(),
            pattern: segments(pattern),
            remaining: times,
            reply,
        });
    }

    /// Every request received so far, in order.
    pub fn requests(&self) -> Vec<Recorded> {
        self.state.lock().unwrap().requests.clone()
    }

    /// The request lines received so far (`METHOD /path?query`).
    pub fn lines(&self) -> Vec<String> {
        self.requests().iter().map(Recorded::line).collect()
    }
}

async fn serve(
    request: Request<Incoming>,
    state: Arc<Mutex<State>>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let (parts, body) = request.into_parts();
    let body = body
        .collect()
        .await
        .map(http_body_util::Collected::to_bytes)
        .unwrap_or_default();
    let recorded = Recorded {
        method: parts.method,
        path: parts.uri.path().to_owned(),
        query: parts.uri.query().map(str::to_owned),
        headers: parts.headers,
        body,
    };
    let mut state = state.lock().unwrap();
    let reply = state.answer(&recorded);
    state.requests.push(recorded);
    Ok(reply.into_response())
}

fn segments(path: &str) -> Vec<String> {
    path.trim_matches('/')
        .split('/')
        .map(str::to_owned)
        .collect()
}

/// The `{name}` captures when `path` matches `pattern`.
fn captures(pattern: &[String], path: &str) -> Option<Params> {
    let parts = segments(path);
    if parts.len() != pattern.len() {
        return None;
    }
    let mut params = Params::new();
    for (want, have) in pattern.iter().zip(&parts) {
        match want.strip_prefix('{').and_then(|w| w.strip_suffix('}')) {
            Some(name) => {
                params.insert(name.to_owned(), percent_decode(have));
            }
            None if want == have => {}
            None => return None,
        }
    }
    Some(params)
}

fn url_decode_pairs(query: &str) -> Vec<(String, String)> {
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            (
                percent_decode(key),
                percent_decode(&value.replace('+', " ")),
            )
        })
        .collect()
}

fn percent_decode(text: &str) -> String {
    percent_encoding::percent_decode_str(text)
        .decode_utf8_lossy()
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn get(url: &str) -> (u16, HeaderMap, String) {
        let client =
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .build_http::<Full<Bytes>>();
        let response = client.get(url.parse().unwrap()).await.unwrap();
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, headers, String::from_utf8_lossy(&body).into_owned())
    }

    #[tokio::test]
    async fn routes_capture_segments_and_record_requests() {
        let api = FakeApi::start().await;
        api.route("GET", "/zones/{zone}", |request, params| {
            Reply::json(
                200,
                serde_json::json!({ "zone": params["zone"], "q": request.query_param("name") }),
            )
        });
        let (status, _, body) = get(&format!("{}/zones/a.example?name=x%2By", api.url())).await;
        assert_eq!(status, 200);
        assert_eq!(body, r#"{"q":"x+y","zone":"a.example"}"#);
        let (status, _, _) = get(&format!("{}/other", api.url())).await;
        assert_eq!(status, 404);
        assert_eq!(
            api.lines(),
            ["GET /zones/a.example?name=x%2By", "GET /other"]
        );
    }

    #[tokio::test]
    async fn failures_come_first_then_guards_then_routes() {
        let api = FakeApi::start().await;
        api.route("GET", "/x", |_, _| Reply::status(204));
        api.guard(|request| {
            (request.header("authorization") != Some("Bearer ok")).then(|| Reply::status(401))
        });
        api.fail("GET", "/x", 1, Reply::too_many_requests(7));
        let (status, headers, _) = get(&format!("{}/x", api.url())).await;
        assert_eq!(status, 429);
        assert_eq!(headers["retry-after"], "7");
        let (status, _, _) = get(&format!("{}/x", api.url())).await;
        assert_eq!(status, 401, "the guard answers once the failure is spent");
    }
}
