//! The configuration root, defaults, listeners and manual certificates.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::path::PathBuf;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::acme::{Acme, AcmeSetting};
use crate::middleware::Middleware;
use crate::providers::Providers;
use crate::route::{Route, TcpRoute, TlsMode};
use crate::service::{Service, TcpService};
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
    /// TCP routes (SNI routing, passthrough, plain TCP).
    pub tcp_routes: BTreeMap<String, TcpRoute>,
    /// TCP backend pools.
    pub tcp_services: BTreeMap<String, TcpService>,
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
}

impl Default for Defaults {
    fn default() -> Self {
        Self {
            listeners: vec!["websecure".to_owned()],
            redirect_http_to_https: true,
            tls: TlsMode::Auto,
            certificate: None,
        }
    }
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
    /// Client-side timeouts.
    #[serde(default)]
    pub timeouts: ListenerTimeouts,
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
            timeouts: ListenerTimeouts::default(),
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
    /// UDP datagrams.
    Udp,
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct ListenerTls {
    /// TLS versions and cipher suites.
    pub policy: TlsPolicy,
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

/// Inbound PROXY protocol settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProxyProtocolIn {
    /// Sources allowed to send a PROXY header. Others are rejected.
    pub trusted: Vec<IpNetwork>,
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
