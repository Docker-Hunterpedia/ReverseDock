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
use crate::settings::{Admin, Lifecycle, Observability, RuntimeSettings, Security};
use crate::values::{ByteSize, Duration, IpNetwork, ListenAddress};

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
    /// The proxy's worker threads; read at start, so a change needs a restart.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime: Option<RuntimeSettings>,
    /// In-place binary upgrades (`rdock upgrade`, `SIGUSR2`): the binary, the drain bound and
    /// the start timeout.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upgrade: Option<crate::settings::Upgrade>,
    /// External secret stores that secret fields can reference (`${vault:…}`).
    #[serde(skip_serializing_if = "crate::secrets::Secrets::is_empty")]
    pub secrets: crate::secrets::Secrets,
    /// The proxy's own zone and whether services prefer backends in it (H-HA-05).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locality: Option<crate::settings::Locality>,
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
    /// Options of the listening socket and of the connections it accepts (ADR-0031). Unset
    /// options keep the kernel's behaviour, except `backlog`, which defaults to 4096.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socket: Option<ListenerSocket>,
    /// HTTP/2 settings of `http` (h2c) and `https` listeners (H-PERF-03, ADR-0031). Unset
    /// values keep the behaviour before v0.9.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http2: Option<ListenerHttp2>,
}

/// HTTP/2 settings of a listener (RFC 9113 §6.5.2). Unset values keep what Pingora 0.9.1 and
/// h2 0.4.20 do; the limits that protect against stream and reset floods can only be removed
/// by writing `unlimited`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct ListenerHttp2 {
    /// Streams a client may have open at once (`SETTINGS_MAX_CONCURRENT_STREAMS`). Default 100
    /// (Pingora's bound); at most 10000 unless `unlimited`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_concurrent_streams: Option<FloodLimit>,
    /// Flow-control window of each stream (`SETTINGS_INITIAL_WINDOW_SIZE`): how much request
    /// body a client may send before rdock reads it. Default 65535 bytes (the protocol's
    /// initial value); at most 2^31-1.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial_stream_window: Option<ByteSize>,
    /// Flow-control window of the whole connection. Default 65535 bytes; 65535 to 2^31-1.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial_connection_window: Option<ByteSize>,
    /// Largest frame payload rdock accepts (`SETTINGS_MAX_FRAME_SIZE`). Default 16384; 16384
    /// to 16777215 (RFC 9113 §6.5.2).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_frame_size: Option<ByteSize>,
    /// Largest decoded request header list (`SETTINGS_MAX_HEADER_LIST_SIZE`). Default 64KiB
    /// (Pingora's bound); 1KiB to 16MiB.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_header_list_size: Option<ByteSize>,
    /// Streams a client may reset before rdock accepted them, at once (the HTTP/2 Rapid Reset
    /// mitigation, CVE-2023-44487). Default 20 (h2's); at most 10000 unless `unlimited`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_pending_accept_reset_streams: Option<FloodLimit>,
    /// Streams rdock resets because the client misbehaved before the connection is closed (the
    /// `MadeYouReset` mitigation, CVE-2025-8671). Default 1024 (h2's); at most 100000 unless
    /// `unlimited`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_local_error_reset_streams: Option<FloodLimit>,
    /// Response data buffered per stream for a client that reads slowly. Default 400KiB (h2's);
    /// 16KiB to 16MiB.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_send_buffer: Option<ByteSize>,
}

/// A limit that guards against a flood: a number, or `unlimited` to remove it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FloodLimit {
    /// At most this many.
    Count(u32),
    /// No limit.
    Unlimited,
}

impl Serialize for FloodLimit {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Count(n) => serializer.serialize_u32(*n),
            Self::Unlimited => serializer.serialize_str("unlimited"),
        }
    }
}

impl<'de> Deserialize<'de> for FloodLimit {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Count(u64),
            Word(String),
        }
        match Raw::deserialize(deserializer)? {
            Raw::Count(n) => u32::try_from(n)
                .map(Self::Count)
                .map_err(|_| serde::de::Error::custom("too large; write `unlimited` for no limit")),
            Raw::Word(w) if w == "unlimited" => Ok(Self::Unlimited),
            Raw::Word(w) => Err(serde::de::Error::custom(format!(
                "`{w}` is not a number or `unlimited`"
            ))),
        }
    }
}

impl JsonSchema for FloodLimit {
    fn schema_name() -> Cow<'static, str> {
        Cow::Borrowed("FloodLimit")
    }

    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "description": "A number, or `unlimited` to remove the limit.",
            "oneOf": [
                { "type": "integer", "minimum": 1, "maximum": 4_294_967_295_u64 },
                { "type": "string", "enum": ["unlimited"] }
            ]
        })
    }
}

/// Socket options of a listener. Options that do not apply to the listener's transport are
/// refused, and so are options this platform cannot set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct ListenerSocket {
    /// TCP: how many connections the kernel holds that have completed their handshake and
    /// that ReverseDock has not accepted yet. Default 4096, Linux's `net.core.somaxconn`
    /// default since 5.4, which also caps it (before v0.9 it was 128).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backlog: Option<u32>,
    /// TCP: `SO_REUSEPORT`, so several sockets (or processes) can bind the same address and
    /// the kernel spreads connections over them. Off by default: with it, another process of
    /// the same user can bind the address unnoticed. Refused on `udp` listeners.
    pub reuse_port: bool,
    /// `SO_RCVBUF`: the receive buffer, set before `listen` so the TCP window scale is
    /// negotiated with it. Unset: the kernel's automatic sizing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receive_buffer: Option<ByteSize>,
    /// `SO_SNDBUF`: the send buffer. Unset: the kernel's automatic sizing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub send_buffer: Option<ByteSize>,
    /// TCP keep-alive probes on accepted connections. Unset: off, as the kernel does.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keepalive: Option<TcpKeepalive>,
    /// TCP: `TCP_USER_TIMEOUT` on accepted connections, how long sent data may stay
    /// unacknowledged before the connection is dropped. Linux only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_timeout: Option<Duration>,
    /// TCP: accept TCP Fast Open with this many pending requests (`TCP_FASTOPEN`). The kernel
    /// must allow it for servers (`net.ipv4.tcp_fastopen` bit 2). Linux only; off by default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fast_open: Option<u32>,
    /// `IPV6_V6ONLY` for an IPv6 or all-interfaces (`:port`) address: `true` serves IPv6 only,
    /// `false` IPv6 and IPv4. Unset: the system's default (`net.ipv6.bindv6only`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv6_only: Option<bool>,
    /// DSCP value (0–63) of the traffic sent on accepted connections (the top six bits of
    /// IPv4's TOS byte or IPv6's traffic class).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dscp: Option<u8>,
}

impl ListenerSocket {
    /// The listen backlog when `backlog` is not set.
    pub const DEFAULT_BACKLOG: u32 = 4096;

    /// The listen backlog in effect.
    #[must_use]
    pub fn effective_backlog(&self) -> u32 {
        self.backlog.unwrap_or(Self::DEFAULT_BACKLOG)
    }
}

/// TCP keep-alive on accepted connections (`SO_KEEPALIVE`). Unset values keep the kernel's
/// (Linux: 7200 s idle, 75 s between probes, 9 probes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct TcpKeepalive {
    /// Idle time before the first probe (`TCP_KEEPIDLE`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idle: Option<Duration>,
    /// Time between probes (`TCP_KEEPINTVL`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interval: Option<Duration>,
    /// Unanswered probes before the connection is dropped (`TCP_KEEPCNT`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<u32>,
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
            socket: None,
            http2: None,
        }
    }

    /// The socket options, with the defaults when `socket` is omitted.
    #[must_use]
    pub fn socket(&self) -> ListenerSocket {
        self.socket.unwrap_or_default()
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
    /// `https` listeners: TLS handshakes in progress at once. While the bound is reached, new
    /// connections wait in the listen backlog instead of taking CPU from established ones.
    /// Unset: no bound (ADR-0031).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_handshakes: Option<u32>,
    /// Session tickets (stateless resumption, H-PERF-02). On by default, with keys shared by
    /// every listener of the same security class and kept across reloads and binary upgrades.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tickets: Option<TlsTickets>,
    /// Sessions kept in memory for resumption by session ID (TLS 1.2, and TLS 1.3 when
    /// tickets are off), shared like the ticket keys. Default 256 sessions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_cache: Option<TlsSessionCache>,
}

impl ListenerTls {
    /// The ticket settings, with the defaults when `tickets` is omitted.
    #[must_use]
    pub fn tickets(&self) -> TlsTickets {
        self.tickets.clone().unwrap_or_default()
    }

    /// The session cache settings, with the defaults when `session_cache` is omitted.
    #[must_use]
    pub fn session_cache(&self) -> TlsSessionCache {
        self.session_cache.unwrap_or_default()
    }
}

/// TLS session tickets. A ticket lets a returning client skip the full handshake. Listeners
/// share ticket keys only when their TLS policy, client authentication (mode and CA
/// certificates), certificate scope and these settings are equal, so a session from a listener
/// without client authentication can never be resumed on one that requires it. 0-RTT (early
/// data) is never accepted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct TlsTickets {
    /// Issue and accept tickets.
    pub enabled: bool,
    /// How often a new ticket key is made; the previous key still decrypts for one more
    /// interval, so tickets live at most twice this (announced to clients, capped at 7 days by
    /// RFC 8446 §4.6.1). Default 6h, rustls's own default; at most 84h.
    pub rotate: Duration,
    /// Keys you provide, to share tickets between instances: one or more 32-byte keys in base64,
    /// one per line (`openssl rand -base64 32`), the first current, the others still accepted.
    /// The file must not be readable by the group or others, is read again when it changes, and
    /// rotating it is then your job (a warning when it is older than 24 hours). Without it, keys
    /// are generated, live in memory only and are handed to the next process in a binary
    /// upgrade.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_file: Option<PathBuf>,
}

impl Default for TlsTickets {
    fn default() -> Self {
        Self {
            enabled: true,
            rotate: Duration::from_secs(6 * 60 * 60),
            key_file: None,
        }
    }
}

/// The in-memory session cache of a TLS listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct TlsSessionCache {
    /// Sessions kept (0 turns the cache off). Default 256, rustls's default.
    pub size: u32,
}

impl Default for TlsSessionCache {
    fn default() -> Self {
        Self { size: 256 }
    }
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
