//! Typed configuration values that are written as strings: durations, sizes, addresses,
//! networks, URLs and rate-limit keys.

use std::borrow::Cow;
use std::fmt;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;

use ipnet::IpNet;
use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A configuration value that could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct ValueError(String);

impl ValueError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

/// Implements `Serialize` (via `Display`) and `Deserialize` (via `FromStr`, strings only).
macro_rules! string_serde {
    ($ty:ty, $expecting:literal) => {
        impl Serialize for $ty {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.collect_str(self)
            }
        }

        impl<'de> Deserialize<'de> for $ty {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                struct StrVisitor;
                impl Visitor<'_> for StrVisitor {
                    type Value = $ty;
                    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                        f.write_str($expecting)
                    }
                    fn visit_str<E: de::Error>(self, value: &str) -> Result<$ty, E> {
                        value.parse().map_err(E::custom)
                    }
                }
                deserializer.deserialize_str(StrVisitor)
            }
        }
    };
}

/// Implements `JsonSchema` from a JSON literal.
macro_rules! schema {
    ($ty:ty, $name:literal, $schema:tt) => {
        impl JsonSchema for $ty {
            fn schema_name() -> Cow<'static, str> {
                $name.into()
            }
            fn json_schema(_: &mut SchemaGenerator) -> Schema {
                json_schema!($schema)
            }
        }
    };
}

// ---------------------------------------------------------------------------------------------
// Duration

/// A duration written as a sequence of numbers with units: `250ms`, `10s`, `5m`, `1h30m`, `7d`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Duration(std::time::Duration);

impl Duration {
    /// A duration of `secs` seconds.
    #[must_use]
    pub const fn from_secs(secs: u64) -> Self {
        Self(std::time::Duration::from_secs(secs))
    }

    /// A duration of `millis` milliseconds.
    #[must_use]
    pub const fn from_millis(millis: u64) -> Self {
        Self(std::time::Duration::from_millis(millis))
    }

    /// The standard-library duration.
    #[must_use]
    pub const fn as_std(self) -> std::time::Duration {
        self.0
    }

    /// Whether the duration is zero.
    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.0.is_zero()
    }
}

impl FromStr for Duration {
    type Err = ValueError;

    fn from_str(s: &str) -> Result<Self, ValueError> {
        if s.is_empty() {
            return Err(ValueError::new(
                "empty duration; write a value such as `10s`",
            ));
        }
        let bytes = s.as_bytes();
        let mut total: u64 = 0;
        let mut i = 0;
        while i < bytes.len() {
            let digits = i;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            if digits == i {
                return Err(ValueError::new(format!(
                    "invalid duration `{s}`: expected a number such as `10s`"
                )));
            }
            let number: u64 = s[digits..i]
                .parse()
                .map_err(|_| ValueError::new(format!("duration `{s}` is too large")))?;
            let unit_start = i;
            while i < bytes.len() && bytes[i].is_ascii_alphabetic() {
                i += 1;
            }
            let millis_per_unit: u64 = match &s[unit_start..i] {
                "ms" => 1,
                "s" => 1_000,
                "m" => 60_000,
                "h" => 3_600_000,
                "d" => 86_400_000,
                "" => {
                    return Err(ValueError::new(format!(
                        "duration `{s}` needs a unit (ms, s, m, h or d), e.g. `{number}s`"
                    )));
                }
                unit => {
                    return Err(ValueError::new(format!(
                        "unknown unit `{unit}` in duration `{s}` (use ms, s, m, h or d)"
                    )));
                }
            };
            total = number
                .checked_mul(millis_per_unit)
                .and_then(|millis| total.checked_add(millis))
                .ok_or_else(|| ValueError::new(format!("duration `{s}` is too large")))?;
        }
        Ok(Self::from_millis(total))
    }
}

impl fmt::Display for Duration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut millis = self.0.as_millis();
        if millis == 0 {
            return f.write_str("0s");
        }
        for (unit, size) in [
            ("d", 86_400_000),
            ("h", 3_600_000),
            ("m", 60_000),
            ("s", 1_000),
            ("ms", 1),
        ] {
            let count = millis / size;
            if count > 0 {
                write!(f, "{count}{unit}")?;
                millis %= size;
            }
        }
        Ok(())
    }
}

string_serde!(Duration, "a duration such as `10s`, `250ms` or `1h30m`");
schema!(Duration, "Duration", {
    "type": "string",
    "pattern": "^([0-9]+(ms|s|m|h|d))+$",
    "description": "Duration made of numbers with units: ms, s, m, h, d.",
    "examples": ["10s", "250ms", "1h30m"]
});

// ---------------------------------------------------------------------------------------------
// ByteSize

/// A size in bytes: a plain number or a number with a unit (`32KiB`, `100MiB`, `10MB`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct ByteSize(u64);

const SIZE_UNITS: [(&str, u64); 9] = [
    ("B", 1),
    ("KB", 1_000),
    ("MB", 1_000_000),
    ("GB", 1_000_000_000),
    ("TB", 1_000_000_000_000),
    ("KiB", 1 << 10),
    ("MiB", 1 << 20),
    ("GiB", 1 << 30),
    ("TiB", 1 << 40),
];

impl ByteSize {
    /// `kib` kibibytes.
    #[must_use]
    pub const fn kib(kib: u64) -> Self {
        Self(kib << 10)
    }

    /// `mib` mebibytes.
    #[must_use]
    pub const fn mib(mib: u64) -> Self {
        Self(mib << 20)
    }

    /// The size in bytes.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

impl FromStr for ByteSize {
    type Err = ValueError;

    fn from_str(s: &str) -> Result<Self, ValueError> {
        let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
        let (number, unit) = s.split_at(split);
        if number.is_empty() {
            return Err(ValueError::new(format!(
                "invalid size `{s}`: write a number with an optional unit, e.g. `32KiB`"
            )));
        }
        let factor = if unit.is_empty() {
            1
        } else {
            SIZE_UNITS.iter().find(|(name, _)| *name == unit).map(|(_, factor)| *factor).ok_or_else(
                || {
                    ValueError::new(format!(
                        "unknown unit `{unit}` in size `{s}` (use B, KB, MB, GB, TB, KiB, MiB, GiB or TiB)"
                    ))
                },
            )?
        };
        number
            .parse::<u64>()
            .ok()
            .and_then(|n| n.checked_mul(factor))
            .map(Self)
            .ok_or_else(|| ValueError::new(format!("size `{s}` is too large")))
    }
}

impl fmt::Display for ByteSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (unit, size) in [
            ("TiB", 1u64 << 40),
            ("GiB", 1 << 30),
            ("MiB", 1 << 20),
            ("KiB", 1 << 10),
        ] {
            if self.0 != 0 && self.0.is_multiple_of(size) {
                return write!(f, "{}{unit}", self.0 / size);
            }
        }
        write!(f, "{}B", self.0)
    }
}

impl Serialize for ByteSize {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for ByteSize {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SizeVisitor;
        impl Visitor<'_> for SizeVisitor {
            type Value = ByteSize;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a size in bytes, or a size with a unit such as `32KiB`")
            }
            fn visit_u64<E: de::Error>(self, value: u64) -> Result<ByteSize, E> {
                Ok(ByteSize(value))
            }
            fn visit_i64<E: de::Error>(self, value: i64) -> Result<ByteSize, E> {
                u64::try_from(value)
                    .map(ByteSize)
                    .map_err(|_| E::custom("size cannot be negative"))
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<ByteSize, E> {
                value.parse().map_err(E::custom)
            }
        }
        deserializer.deserialize_any(SizeVisitor)
    }
}

schema!(ByteSize, "ByteSize", {
    "anyOf": [
        { "type": "integer", "minimum": 0 },
        { "type": "string", "pattern": "^[0-9]+(B|KB|MB|GB|TB|KiB|MiB|GiB|TiB)?$" }
    ],
    "description": "Size in bytes, optionally with a unit (KB = 1000, KiB = 1024).",
    "examples": ["32KiB", "100MiB", 1_048_576]
});

// ---------------------------------------------------------------------------------------------
// ListenAddress

/// Where a listener binds: `:443` (all interfaces), `0.0.0.0:80`, `127.0.0.1:2080` or
/// `[::1]:2080`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ListenAddress {
    ip: Option<IpAddr>,
    port: u16,
}

impl ListenAddress {
    /// An address on all interfaces.
    #[must_use]
    pub const fn any(port: u16) -> Self {
        Self { ip: None, port }
    }

    /// An address on one IP.
    #[must_use]
    pub const fn new(ip: IpAddr, port: u16) -> Self {
        Self { ip: Some(ip), port }
    }

    /// The IP, or `None` for all interfaces.
    #[must_use]
    pub const fn ip(&self) -> Option<IpAddr> {
        self.ip
    }

    /// The port.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// Whether the address only accepts local connections.
    #[must_use]
    pub fn is_loopback(&self) -> bool {
        self.ip.is_some_and(|ip| ip.is_loopback())
    }

    /// Whether two addresses would compete for the same socket.
    #[must_use]
    pub fn overlaps(&self, other: &Self) -> bool {
        if self.port != other.port {
            return false;
        }
        match (self.ip, other.ip) {
            // IPv4 and IPv6 sockets are separate; a dual-stack clash surfaces when binding.
            (Some(a), Some(b)) if a.is_ipv4() != b.is_ipv4() => false,
            (Some(a), Some(b)) => a == b || a.is_unspecified() || b.is_unspecified(),
            _ => true,
        }
    }
}

impl FromStr for ListenAddress {
    type Err = ValueError;

    fn from_str(s: &str) -> Result<Self, ValueError> {
        let address = if let Some(port) = s.strip_prefix(':') {
            port.parse().map(Self::any).ok()
        } else {
            s.parse::<SocketAddr>()
                .ok()
                .map(|a| Self::new(a.ip(), a.port()))
        };
        match address {
            Some(a) if a.port == 0 => Err(ValueError::new(format!(
                "listen address `{s}` uses port 0; choose a fixed port"
            ))),
            Some(a) => Ok(a),
            None => Err(ValueError::new(format!(
                "invalid listen address `{s}`: use `:443`, `0.0.0.0:80`, `127.0.0.1:2080` or `[::1]:2080`"
            ))),
        }
    }
}

impl fmt::Display for ListenAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.ip {
            None => write!(f, ":{}", self.port),
            Some(ip) => write!(f, "{}", SocketAddr::new(ip, self.port)),
        }
    }
}

string_serde!(
    ListenAddress,
    "a listen address such as `:443` or `127.0.0.1:2080`"
);
schema!(ListenAddress, "ListenAddress", {
    "type": "string",
    "pattern": "^(\\[[0-9A-Fa-f:.]+\\]|[0-9.]+)?:[0-9]{1,5}$",
    "description": "Listen address: `:port` for all interfaces, or `ip:port`.",
    "examples": [":443", "127.0.0.1:2080", "[::1]:2080"]
});

// ---------------------------------------------------------------------------------------------
// BackendAddress

/// Where a backend is reached: `host:port`, `ip:port`, `[ipv6]:port` or
/// `unix:///absolute/path.sock`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum BackendAddress {
    /// A TCP address; the host is an IP literal or a DNS name.
    Tcp {
        /// IP literal or DNS name.
        host: String,
        /// Port.
        port: u16,
    },
    /// A Unix domain socket.
    Unix(PathBuf),
}

impl FromStr for BackendAddress {
    type Err = ValueError;

    fn from_str(s: &str) -> Result<Self, ValueError> {
        if let Some(path) = s.strip_prefix("unix://") {
            return if path.starts_with('/') {
                Ok(Self::Unix(PathBuf::from(path)))
            } else {
                Err(ValueError::new(format!(
                    "unix socket path in `{s}` must be absolute, e.g. `unix:///run/app.sock`"
                )))
            };
        }
        if s.contains("://") {
            return Err(ValueError::new(format!(
                "`{s}` is a URL; write only `host:port` here and set the protocol with the service's `scheme`"
            )));
        }
        let parsed = if let Some(rest) = s.strip_prefix('[') {
            rest.split_once("]:")
                .filter(|(ip, _)| ip.parse::<Ipv6Addr>().is_ok())
                .map(|(ip, port)| (ip.to_owned(), port))
        } else {
            // IPv6 literals must be bracketed; without brackets the port is ambiguous.
            s.rsplit_once(':')
                .filter(|(host, _)| {
                    is_host_name(host) || host.parse::<std::net::Ipv4Addr>().is_ok()
                })
                .map(|(host, port)| (host.to_owned(), port))
        };
        let Some((host, port)) = parsed else {
            return Err(ValueError::new(format!(
                "invalid backend address `{s}`: use `host:port`, `10.0.0.5:8080`, `[::1]:8080` or `unix:///run/app.sock`"
            )));
        };
        match port.parse::<u16>() {
            Ok(port) if port > 0 => Ok(Self::Tcp { host, port }),
            _ => Err(ValueError::new(format!(
                "invalid port in backend address `{s}`"
            ))),
        }
    }
}

/// RFC 9110 token, the syntax of header names, methods and cookie names.
pub(crate) fn is_token(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c))
}

/// DNS names and container names: labels of letters, digits, `-` and `_`.
fn is_host_name(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        })
}

impl fmt::Display for BackendAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp { host, port } if host.contains(':') => write!(f, "[{host}]:{port}"),
            Self::Tcp { host, port } => write!(f, "{host}:{port}"),
            Self::Unix(path) => write!(f, "unix://{}", path.display()),
        }
    }
}

string_serde!(
    BackendAddress,
    "a backend address such as `app:3000` or `unix:///run/app.sock`"
);
schema!(BackendAddress, "BackendAddress", {
    "type": "string",
    "description": "Backend address: `host:port`, `[ipv6]:port` or `unix:///absolute/path.sock`.",
    "examples": ["app:3000", "10.0.0.5:8080", "unix:///run/app.sock"]
});

// ---------------------------------------------------------------------------------------------
// IpNetwork and TrustedProxy

/// An IP address or CIDR range, such as `10.0.0.0/8`, `2001:db8::/32` or `192.0.2.7`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpNetwork(IpNet);

impl IpNetwork {
    /// Whether `ip` is inside the network.
    #[must_use]
    pub fn contains(&self, ip: &IpAddr) -> bool {
        self.0.contains(ip)
    }
}

impl FromStr for IpNetwork {
    type Err = ValueError;

    fn from_str(s: &str) -> Result<Self, ValueError> {
        s.parse::<IpNet>()
            .or_else(|_| s.parse::<IpAddr>().map(IpNet::from))
            .map(Self)
            .map_err(|_| ValueError::new(format!("`{s}` is not an IP address or CIDR range")))
    }
}

impl fmt::Display for IpNetwork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

string_serde!(
    IpNetwork,
    "an IP address or CIDR range such as `10.0.0.0/8`"
);
schema!(IpNetwork, "IpNetwork", {
    "type": "string",
    "description": "IP address or CIDR range.",
    "examples": ["10.0.0.0/8", "2001:db8::/32", "192.0.2.7"]
});

/// A proxy whose forwarded headers are trusted: `cloudflare` (ranges synced automatically) or
/// an IP network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TrustedProxy {
    /// Cloudflare's published edge ranges.
    Cloudflare,
    /// A fixed network.
    Network(IpNetwork),
}

impl FromStr for TrustedProxy {
    type Err = ValueError;

    fn from_str(s: &str) -> Result<Self, ValueError> {
        if s == "cloudflare" {
            return Ok(Self::Cloudflare);
        }
        s.parse().map(Self::Network).map_err(|_| {
            ValueError::new(format!(
                "`{s}` is not `cloudflare`, an IP address or a CIDR range"
            ))
        })
    }
}

impl fmt::Display for TrustedProxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cloudflare => f.write_str("cloudflare"),
            Self::Network(net) => net.fmt(f),
        }
    }
}

string_serde!(TrustedProxy, "`cloudflare`, an IP address or a CIDR range");
schema!(TrustedProxy, "TrustedProxy", {
    "type": "string",
    "description": "`cloudflare` (edge ranges synced automatically) or an IP address/CIDR range.",
    "examples": ["cloudflare", "10.0.0.0/8"]
});

// ---------------------------------------------------------------------------------------------
// URLs

/// An `http://` or `https://` URL.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HttpUrl(url::Url);

impl HttpUrl {
    /// The parsed URL.
    #[must_use]
    pub fn as_url(&self) -> &url::Url {
        &self.0
    }

    /// Whether requests to the URL are encrypted or stay on this machine: `https://`, or
    /// `http://` to `localhost` or a loopback address.
    #[must_use]
    pub fn is_https_or_loopback(&self) -> bool {
        self.0.scheme() == "https"
            || match self.0.host() {
                Some(url::Host::Domain(name)) => name.eq_ignore_ascii_case("localhost"),
                Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
                Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
                None => false,
            }
    }
}

impl FromStr for HttpUrl {
    type Err = ValueError;

    fn from_str(s: &str) -> Result<Self, ValueError> {
        let url =
            url::Url::parse(s).map_err(|e| ValueError::new(format!("invalid URL `{s}`: {e}")))?;
        if matches!(url.scheme(), "http" | "https") && url.has_host() {
            Ok(Self(url))
        } else {
            Err(ValueError::new(format!(
                "`{s}` must be an http:// or https:// URL"
            )))
        }
    }
}

impl fmt::Display for HttpUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0.as_str())
    }
}

string_serde!(HttpUrl, "an http:// or https:// URL");
schema!(HttpUrl, "HttpUrl", {
    "type": "string",
    "format": "uri",
    "pattern": "^https?://",
    "examples": ["http://authelia:9091/api/verify"]
});

/// An endpoint of a container engine API: `unix:///var/run/docker.sock`, `tcp://host:2375`,
/// `http(s)://…` or `npipe:////./pipe/docker_engine`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Endpoint(url::Url);

impl Endpoint {
    /// The parsed URL.
    #[must_use]
    pub fn as_url(&self) -> &url::Url {
        &self.0
    }
}

impl FromStr for Endpoint {
    type Err = ValueError;

    fn from_str(s: &str) -> Result<Self, ValueError> {
        let url = url::Url::parse(s)
            .map_err(|e| ValueError::new(format!("invalid endpoint `{s}`: {e}")))?;
        if matches!(url.scheme(), "unix" | "tcp" | "http" | "https" | "npipe") {
            Ok(Self(url))
        } else {
            Err(ValueError::new(format!(
                "endpoint `{s}` must use unix://, tcp://, http://, https:// or npipe://"
            )))
        }
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0.as_str())
    }
}

string_serde!(
    Endpoint,
    "an endpoint such as `unix:///var/run/docker.sock`"
);
schema!(Endpoint, "Endpoint", {
    "type": "string",
    "examples": ["unix:///var/run/docker.sock", "tcp://socket-proxy:2375"]
});

// ---------------------------------------------------------------------------------------------
// RateLimitKey

/// What a limit counts by: `client_ip`, `route`, `header:<Name>` or `cookie:<name>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub enum RateLimitKey {
    /// The client IP after trusted-proxy resolution.
    #[default]
    ClientIp,
    /// One shared bucket per route.
    Route,
    /// The value of a request header, e.g. an API key.
    Header(String),
    /// The value of a cookie, e.g. a session.
    Cookie(String),
}

impl FromStr for RateLimitKey {
    type Err = ValueError;

    fn from_str(s: &str) -> Result<Self, ValueError> {
        match s {
            "client_ip" => Ok(Self::ClientIp),
            "route" => Ok(Self::Route),
            _ => match (s.strip_prefix("header:"), s.strip_prefix("cookie:")) {
                (Some(name), _) if is_token(name) => Ok(Self::Header(name.to_owned())),
                (_, Some(name)) if is_token(name) => Ok(Self::Cookie(name.to_owned())),
                _ => Err(ValueError::new(format!(
                    "invalid key `{s}`: use `client_ip`, `route`, `header:<Name>` or `cookie:<name>`"
                ))),
            },
        }
    }
}

impl fmt::Display for RateLimitKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClientIp => f.write_str("client_ip"),
            Self::Route => f.write_str("route"),
            Self::Header(name) => write!(f, "header:{name}"),
            Self::Cookie(name) => write!(f, "cookie:{name}"),
        }
    }
}

string_serde!(
    RateLimitKey,
    "`client_ip`, `route`, `header:<Name>` or `cookie:<name>`"
);
schema!(RateLimitKey, "RateLimitKey", {
    "type": "string",
    "pattern": "^(client_ip|route|(header|cookie):[A-Za-z0-9!#$%&'*+.^_`|~-]+)$",
    "examples": ["client_ip", "header:X-Api-Key"]
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_parse_and_print_canonically() {
        let cases = [
            ("10s", "10s", 10_000),
            ("250ms", "250ms", 250),
            ("1h30m", "1h30m", 5_400_000),
            ("90s", "1m30s", 90_000),
            ("0s", "0s", 0),
            ("2d", "2d", 172_800_000),
        ];
        for (input, printed, millis) in cases {
            let d: Duration = input.parse().unwrap();
            assert_eq!(d.as_std().as_millis(), millis, "{input}");
            assert_eq!(d.to_string(), printed);
        }
        for bad in [
            "",
            "10",
            "s",
            "10x",
            "1.5s",
            "10 s",
            "99999999999999999999s",
        ] {
            assert!(bad.parse::<Duration>().is_err(), "{bad}");
        }
        assert!(
            "10".parse::<Duration>()
                .unwrap_err()
                .to_string()
                .contains("`10s`")
        );
    }

    #[test]
    fn sizes_accept_decimal_and_binary_units() {
        assert_eq!("32KiB".parse::<ByteSize>().unwrap(), ByteSize::kib(32));
        assert_eq!("100MiB".parse::<ByteSize>().unwrap().to_string(), "100MiB");
        assert_eq!("10MB".parse::<ByteSize>().unwrap().as_u64(), 10_000_000);
        assert_eq!("512".parse::<ByteSize>().unwrap().to_string(), "512B");
        for bad in ["", "KiB", "10kb", "1.5MiB", "-1"] {
            assert!(bad.parse::<ByteSize>().is_err(), "{bad}");
        }
        let from_int: ByteSize = serde_json::from_value(serde_json::json!(4096)).unwrap();
        assert_eq!(from_int, ByteSize::kib(4));
    }

    #[test]
    fn listen_addresses() {
        let any: ListenAddress = ":443".parse().unwrap();
        assert_eq!(
            (any.ip(), any.port(), any.to_string()),
            (None, 443, ":443".into())
        );
        let v6: ListenAddress = "[::1]:2080".parse().unwrap();
        assert!(v6.is_loopback());
        assert_eq!(v6.to_string(), "[::1]:2080");
        assert!(any.overlaps(&"127.0.0.1:443".parse().unwrap()));
        assert!(
            !"127.0.0.1:443"
                .parse::<ListenAddress>()
                .unwrap()
                .overlaps(&"10.0.0.1:443".parse().unwrap())
        );
        let v4: ListenAddress = "0.0.0.0:443".parse().unwrap();
        assert!(!v4.overlaps(&"[::]:443".parse().unwrap()));
        for bad in ["443", "localhost:80", ":0", ":70000", "127.0.0.1"] {
            assert!(bad.parse::<ListenAddress>().is_err(), "{bad}");
        }
    }

    #[test]
    fn backend_addresses() {
        assert_eq!(
            "app:3000".parse::<BackendAddress>().unwrap(),
            BackendAddress::Tcp {
                host: "app".into(),
                port: 3000
            }
        );
        assert_eq!(
            "my_app.internal:80"
                .parse::<BackendAddress>()
                .unwrap()
                .to_string(),
            "my_app.internal:80"
        );
        assert_eq!(
            "[2001:db8::1]:443"
                .parse::<BackendAddress>()
                .unwrap()
                .to_string(),
            "[2001:db8::1]:443"
        );
        assert_eq!(
            "unix:///run/x.sock".parse::<BackendAddress>().unwrap(),
            BackendAddress::Unix("/run/x.sock".into())
        );
        assert!(
            "http://app:3000"
                .parse::<BackendAddress>()
                .unwrap_err()
                .to_string()
                .contains("scheme")
        );
        for bad in [
            "app",
            "app:0",
            "app:http",
            ":80",
            "unix://relative.sock",
            "bad host:80",
            "2001:db8::1:443",
        ] {
            assert!(bad.parse::<BackendAddress>().is_err(), "{bad}");
        }
    }

    #[test]
    fn networks_proxies_urls_and_keys() {
        assert!(
            "10.0.0.0/8"
                .parse::<IpNetwork>()
                .unwrap()
                .contains(&"10.1.2.3".parse().unwrap())
        );
        assert_eq!(
            "192.0.2.7".parse::<IpNetwork>().unwrap().to_string(),
            "192.0.2.7/32"
        );
        assert_eq!(
            "cloudflare".parse::<TrustedProxy>().unwrap(),
            TrustedProxy::Cloudflare
        );
        assert!("cloudfare".parse::<TrustedProxy>().is_err());
        assert!("ftp://x".parse::<HttpUrl>().is_err());
        assert!("unix:///var/run/docker.sock".parse::<Endpoint>().is_ok());
        assert_eq!(
            "header:X-Api-Key".parse::<RateLimitKey>().unwrap(),
            RateLimitKey::Header("X-Api-Key".into())
        );
        assert!("header:".parse::<RateLimitKey>().is_err());
    }
}
