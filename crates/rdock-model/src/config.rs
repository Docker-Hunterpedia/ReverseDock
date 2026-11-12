//! The configuration root, defaults, listeners and manual certificates.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::path::PathBuf;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::acme::{Acme, AcmeSetting};
use crate::middleware::Middleware;
use crate::providers::Providers;
use crate::route::{Route, RouteTls, TcpRoute, TlsMode, UdpRoute};
use crate::service::{Service, TcpService, UdpService};
use crate::settings::{Admin, Lifecycle, Observability, Security};
use crate::values::{Duration, IpNetwork, ListenAddress};

/// A complete ReverseDock configuration, as written in `rdock.yaml`.
///
/// Every section is optional. Names of listeners, routes, services, middlewares and
/// certificates are map keys; other objects refer to them by name.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct Config {
    /// JSON Schema reference for editors. Ignored by ReverseDock.
    #[serde(rename = "$schema")]
    pub schema: Option<String>,
    /// Configuration format version. Only `1` exists; omit it to use the latest.
    pub version: Option<u32>,
    /// Sockets to accept traffic on. When empty, `web` (`:80`) and `websecure` (`:443`, TLS)
    /// are used.
    pub listeners: BTreeMap<String, Listener>,
    /// Defaults applied to routes that do not set a value.
    pub defaults: Defaults,
    /// Automatic certificates (ACME). On by default with Let's Encrypt, HTTP-01 and TLS-ALPN-01;
    /// `false` turns it off.
    pub acme: Option<AcmeSetting>,
    /// HTTP routes: which requests go to which service, through which middlewares.
    pub routes: BTreeMap<String, Route>,
    /// Backend pools that routes send traffic to.
    pub services: BTreeMap<String, Service>,
    /// Reusable request and response policies.
    pub middlewares: BTreeMap<String, Middleware>,
    /// HTTP cache stores, used by `cache` middlewares.
    pub caches: BTreeMap<String, crate::cache::CacheStore>,
    /// API clients and users that requests are attributed to, with their API keys (stored
    /// hashed). The `api` provider may add consumers and keys (`rdock consumers`).
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub consumers: BTreeMap<String, crate::gateway::Consumer>,
    /// TCP routes (SNI routing, passthrough, plain TCP).
    pub tcp_routes: BTreeMap<String, TcpRoute>,
    /// TCP backend pools.
    pub tcp_services: BTreeMap<String, TcpService>,
    /// UDP routes: which `udp` listener's datagrams go to which UDP service.
    pub udp_routes: BTreeMap<String, UdpRoute>,
    /// UDP backend pools.
    pub udp_services: BTreeMap<String, UdpService>,
    /// Certificates you provide yourself.
    pub certificates: BTreeMap<String, Certificate>,
    /// Dynamic configuration sources (file, Docker, Swarm, Kubernetes).
    pub providers: Providers,
    /// Client IP trust and request limits.
    pub security: Security,
    /// Admin API and dashboard.
    pub admin: Admin,
    /// Logs, metrics and traces.
    pub observability: Observability,
    /// Start-up and shutdown behaviour.
    pub lifecycle: Lifecycle,
}

impl Config {
    /// The ACME settings in effect: the defaults when `acme` is omitted or `true`, none when it
    /// is `false`.
    #[must_use]
    pub fn effective_acme(&self) -> Option<Cow<'_, Acme>> {
        match &self.acme {
            None | Some(AcmeSetting::Enabled(true)) => Some(Cow::Owned(Acme::default())),
            Some(AcmeSetting::Enabled(false)) => None,
            Some(AcmeSetting::Settings(acme)) => Some(Cow::Borrowed(&**acme)),
        }
    }

    /// The listeners `route` attaches to: its own `listeners`; otherwise, for a route served
    /// without TLS (`tls: off`), the plain-HTTP listeners; otherwise `defaults.listeners`
    /// (ADR-0021). A `tls: off` route on an HTTPS listener could never be served.
    ///
    /// Listeners contributed by a provider (`name@kubernetes`: a Gateway's internal port,
    /// ADR-0029) are never attached implicitly: a route reaches one only by naming it.
    #[must_use]
    pub fn route_listeners(&self, route: &Route) -> Vec<String> {
        if let Some(listeners) = &route.listeners {
            return listeners.clone();
        }
        let plain_route = match &route.tls {
            None => self.defaults.tls == TlsMode::Off,
            Some(RouteTls::Mode(mode)) => *mode == TlsMode::Off,
            Some(RouteTls::Options(_)) => false,
        };
        if plain_route {
            let plain: Vec<String> = self
                .effective_listeners()
                .iter()
                .filter(|(name, l)| {
                    !name.contains('@') && l.effective_protocol() == ListenerProtocol::Http
                })
                .map(|(name, _)| name.clone())
                .collect();
            if !plain.is_empty() {
                return plain;
            }
        }
        self.defaults.listeners.clone()
    }

    /// The listeners in effect: the configured ones, or `web` (`:80`) and `websecure`
    /// (`:443`, TLS) when none are configured.
    #[must_use]
    pub fn effective_listeners(&self) -> Cow<'_, BTreeMap<String, Listener>> {
        if !self.listeners.is_empty() {
            return Cow::Borrowed(&self.listeners);
        }
        let mut implicit = BTreeMap::new();
        implicit.insert("web".to_owned(), Listener::new(ListenAddress::any(80)));
        let mut websecure = Listener::new(ListenAddress::any(443));
        websecure.tls = Some(ListenerTls::default());
        implicit.insert("websecure".to_owned(), websecure);
        Cow::Owned(implicit)
    }
}

/// Defaults applied to routes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct Defaults {
    /// Listeners used by routes that do not name any.
    pub listeners: Vec<String>,
    /// Redirect plain HTTP requests to HTTPS for hosts that have a TLS route.
    pub redirect_http_to_https: bool,
    /// TLS for routes that do not set `tls`: `auto` (automatic certificates) or `off`.
    pub tls: TlsMode,
    /// Certificate (a key of `certificates`) served when no other certificate matches the
    /// requested name, or when the client sends no name (SNI).
    pub certificate: Option<String>,
    /// How answers rdock produces itself (404 without a route, 401/403/429 from middlewares,
    /// 502/503/504) are rendered, for routes that do not set `errors`.
    #[serde(skip_serializing_if = "ErrorSettings::is_default")]
    pub errors: ErrorSettings,
}

impl Default for Defaults {
    fn default() -> Self {
        Self {
            listeners: vec!["websecure".to_owned()],
            redirect_http_to_https: true,
            tls: TlsMode::Auto,
            certificate: None,
            errors: ErrorSettings::default(),
        }
    }
}

/// How rdock renders the answers it produces itself (F-GW-04, ADR-0030). Pages of an `errors`
/// middleware and a `maintenance` file take precedence where they apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct ErrorSettings {
    /// `html`: an HTML page, or a small JSON object for clients that ask for JSON and not
    /// HTML (the behaviour before v0.8). `problem`: `application/problem+json` (RFC 9457) for
    /// every client that accepts JSON, which includes `*/*` and a missing `Accept`; HTML only
    /// for clients that ask for HTML and no JSON type (browsers). `auto`: problem details for
    /// clients that ask for JSON and not HTML, HTML otherwise.
    pub format: ErrorFormat,
}

impl ErrorSettings {
    /// Whether these are the defaults.
    #[must_use]
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

/// The format of rdock's own error answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ErrorFormat {
    /// HTML, or the pre-v0.8 JSON object for clients that ask for JSON.
    #[default]
    Html,
    /// RFC 9457 problem details unless the client asks for HTML only.
    Problem,
    /// RFC 9457 problem details for clients that prefer JSON, HTML otherwise.
    Auto,
}

/// A socket ReverseDock accepts connections on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Listener {
    /// Address to bind, e.g. `:443` or `127.0.0.1:8080`.
    pub address: ListenAddress,
    /// Protocol. Inferred when omitted: `https` if `tls` is set, otherwise `http`.
    #[serde(default)]
    pub protocol: Option<ListenerProtocol>,
    /// TLS termination settings.
    #[serde(default)]
    pub tls: Option<ListenerTls>,
    /// Accept the PROXY protocol (v1 or v2) from these sources only.
    #[serde(default)]
    pub proxy_protocol: Option<ProxyProtocolIn>,
    /// `tcp` listeners: answer a protocol's request to start TLS before reading the TLS
    /// ClientHello. Off by default.
    #[serde(default)]
    pub starttls: Option<StartTls>,
    /// Client-side timeouts.
    #[serde(default)]
    pub timeouts: ListenerTimeouts,
    /// A path answered `200 OK` for any host before routing, for load-balancer health
    /// monitors such as Cloudflare Load Balancing, e.g. `/rdock/ping`.
    #[serde(default)]
    pub ping: Option<String>,
    /// `udp` listeners: how many sessions (client address and port, each with its own
    /// upstream socket) may exist at once. Capped by default even when omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sessions: Option<UdpSessions>,
}

impl Listener {
    /// A plain listener on `address`.
    #[must_use]
    pub fn new(address: ListenAddress) -> Self {
        Self {
            address,
            protocol: None,
            tls: None,
            proxy_protocol: None,
            starttls: None,
            timeouts: ListenerTimeouts::default(),
            ping: None,
            sessions: None,
        }
    }

    /// The protocol in effect, inferring `https`/`http` from `tls` when not set.
    #[must_use]
    pub fn effective_protocol(&self) -> ListenerProtocol {
        self.protocol.unwrap_or(if self.tls.is_some() {
            ListenerProtocol::Https
        } else {
            ListenerProtocol::Http
        })
    }
}

/// Listener protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ListenerProtocol {
    /// Plain HTTP/1.1 and h2c.
    Http,
    /// HTTP over TLS (HTTP/1.1 and HTTP/2).
    Https,
    /// Raw TCP, optionally with TLS termination or SNI passthrough.
    Tcp,
    /// UDP datagrams, relayed per client address (a session) to a UDP service.
    Udp,
}

/// Session caps of a `udp` listener. Both are on by default: a UDP source address can be
/// forged, so without a cap anyone could make the listener open sockets until it runs out of
/// file descriptors (each session holds one socket and one task). Datagrams that would open
/// a session over a cap are dropped and counted in `rdock_udp_dropped_total`, never answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct UdpSessions {
    /// Sessions of the whole listener. Default 4096: Envoy caps UDP sessions per cluster at
    /// 1,024 by default (`max_connections` circuit breaker, checked 2026-11-11 in
    /// docs/research/v0.8-cache-extensibility.md §5.1); a listener here stands for a cluster
    /// and may serve several clients' DNS bursts, and 4,096 sockets stay far below the
    /// container default of 1,048,576 open files. `unlimited` removes the cap.
    pub max: SessionLimit,
    /// Sessions per client IP address (any source port). Default 64, so one source (or one
    /// forged address) can take at most 1/64 of the listener's default budget; a resolver
    /// that forwards many parallel queries from one address may need more. `unlimited`
    /// removes the cap.
    pub max_per_client: SessionLimit,
}

impl Default for UdpSessions {
    fn default() -> Self {
        Self {
            max: SessionLimit::Count(4096),
            max_per_client: SessionLimit::Count(64),
        }
    }
}

/// A session cap: a number of sessions, or `unlimited`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionLimit {
    /// At most this many (at least 1).
    Count(u32),
    /// No cap.
    Unlimited,
}

impl SessionLimit {
    /// The cap, `None` when unlimited.
    #[must_use]
    pub const fn get(self) -> Option<u32> {
        match self {
            Self::Count(n) => Some(n),
            Self::Unlimited => None,
        }
    }
}

impl Serialize for SessionLimit {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Count(n) => serializer.serialize_u32(*n),
            Self::Unlimited => serializer.serialize_str("unlimited"),
        }
    }
}

impl<'de> Deserialize<'de> for SessionLimit {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Count(u64),
            Word(String),
        }
        match Raw::deserialize(deserializer)? {
            Raw::Count(0) => Err(serde::de::Error::custom(
                "a session cap must be at least 1; write `unlimited` for no cap",
            )),
            Raw::Count(n) => u32::try_from(n)
                .map(Self::Count)
                .map_err(|_| serde::de::Error::custom("too large; write `unlimited` for no cap")),
            Raw::Word(w) if w == "unlimited" => Ok(Self::Unlimited),
            Raw::Word(w) => Err(serde::de::Error::custom(format!(
                "`{w}` is not a number of sessions or `unlimited`"
            ))),
        }
    }
}

impl JsonSchema for SessionLimit {
    fn schema_name() -> Cow<'static, str> {
        Cow::Borrowed("SessionLimit")
    }

    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "description": "A number of sessions (at least 1), or `unlimited`.",
            "oneOf": [
                { "type": "integer", "minimum": 1, "maximum": 4_294_967_295_u64 },
                { "type": "string", "enum": ["unlimited"] }
            ]
        })
    }
}

/// Protocols whose own request to start TLS a `tcp` listener answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StartTls {
    /// PostgreSQL: answer the 8-byte `SSLRequest` with `S` (and a `GSSENCRequest` with `N`),
    /// so clients with the default `sslnegotiation=postgres` reach TCP routes that read SNI.
    Postgres,
}

/// Timeouts for the client side of a listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct ListenerTimeouts {
    /// Time allowed to receive the complete request headers, counted from their first byte
    /// (protects against slow-header attacks).
    pub request_header: Duration,
    /// Longest wait for data from the client while a request or upgraded connection is open.
    pub read: Duration,
    /// Longest wait for the client to accept data.
    pub write: Duration,
    /// How long an idle keep-alive connection is kept open.
    pub idle: Duration,
}

impl Default for ListenerTimeouts {
    fn default() -> Self {
        Self {
            request_header: Duration::from_secs(10),
            read: Duration::from_secs(60),
            write: Duration::from_secs(60),
            idle: Duration::from_secs(60),
        }
    }
}

/// TLS termination settings of a listener.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct ListenerTls {
    /// TLS versions and cipher suites.
    pub policy: TlsPolicy,
    /// Client certificates (mTLS). A certificate is always verified against these roots.
    pub client_auth: Option<ClientAuth>,
    /// Certificates (keys of `certificates`) served by this listener only. When set, the
    /// listener presents the one matching the requested name, or the first one, and these
    /// certificates are not served by any other listener. Empty, the default: the listener
    /// serves the shared certificates (`certificates`, automatic ones, `defaults.certificate`).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub certificates: Vec<String>,
}

/// Client certificate verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClientAuth {
    /// `required` refuses handshakes without a valid certificate; `optional` accepts them
    /// without one, but verifies a certificate that is sent.
    #[serde(default)]
    pub mode: ClientAuthMode,
    /// PEM files with the CA certificates that sign client certificates.
    #[serde(default)]
    pub ca_files: Vec<std::path::PathBuf>,
    /// Also trust Cloudflare's CA for global Authenticated Origin Pulls.
    #[serde(default)]
    pub cloudflare: bool,
}

/// Whether a client certificate is required.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ClientAuthMode {
    /// Every connection needs a valid certificate.
    #[default]
    Required,
    /// A certificate is optional; routes can demand one with the `client_cert` middleware.
    Optional,
}

/// TLS policies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TlsPolicy {
    /// TLS 1.3 only.
    Modern,
    /// TLS 1.2 and 1.3 with forward-secret AEAD ciphers (Mozilla "intermediate").
    #[default]
    Intermediate,
}

/// Inbound PROXY protocol settings (v1 and v2). A header is read only from `trusted` sources;
/// a connection from anywhere else that starts with a PROXY header is closed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProxyProtocolIn {
    /// Sources allowed to send a PROXY header, as IP addresses or CIDR networks. Others are
    /// rejected when they send one.
    pub trusted: Vec<IpNetwork>,
    /// Also accept connections from `trusted` sources that send no header. Off by default: a
    /// load balancer that stops sending headers would otherwise make every client look like
    /// the load balancer itself to IP filters, rate limits and logs.
    #[serde(default)]
    pub optional: bool,
}

/// A certificate and private key provided as files. Changes to the files are picked up
/// automatically.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Certificate {
    /// PEM certificate chain, leaf first.
    pub cert_file: PathBuf,
    /// PEM private key (PKCS#8, PKCS#1 or SEC1; PKCS#8 may be encrypted).
    pub key_file: PathBuf,
    /// Password of an encrypted key. Reference a secret instead of writing it here:
    /// `"${file:/run/secrets/key_password}"`.
    #[serde(default)]
    pub key_password: Option<String>,
}
