//! HTTP and TCP routes.

use std::collections::BTreeMap;
use std::fmt;

use rdock_rules::{Expr, Matcher};
use schemars::JsonSchema;
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

use crate::values::Duration;

/// An HTTP route: which requests it matches, which middlewares run, which service answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Route {
    /// Requests this route handles: a Traefik v3 rule or a structured match.
    #[serde(rename = "match")]
    pub matcher: MatchSpec,
    /// Listeners the route is attached to. Defaults to `defaults.listeners`.
    #[serde(default)]
    pub listeners: Option<Vec<String>>,
    /// Higher priorities are evaluated first. `0` uses the rule length, like Traefik.
    #[serde(default)]
    pub priority: i64,
    /// Middlewares applied in order (`name` or `name@provider`).
    #[serde(default)]
    pub middlewares: Vec<String>,
    /// Service that handles matching requests (`name` or `name@provider`).
    pub service: String,
    /// TLS for this route: `auto`, `off` or detailed settings. Defaults to `defaults.tls`.
    #[serde(default)]
    pub tls: Option<RouteTls>,
    /// Upstream timeouts for this route, overriding the service's.
    #[serde(default)]
    pub timeouts: RouteTimeouts,
    /// Set to `false` to keep the route defined but inactive.
    #[serde(default = "crate::defaults::yes")]
    pub enabled: bool,
}

/// Upstream timeouts of a route. Unset values come from the service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct RouteTimeouts {
    /// Establishing a connection.
    pub connect: Option<Duration>,
    /// Waiting for response data.
    pub read: Option<Duration>,
    /// Sending request data.
    pub write: Option<Duration>,
}

/// How a route selects requests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(untagged)]
pub enum MatchSpec {
    /// A rule in Traefik v3 syntax, e.g. ``Host(`app.example.com`) && PathPrefix(`/api`)``.
    Rule(String),
    /// Conditions that must all hold; lists inside one condition are alternatives.
    Structured(StructuredMatch),
}

impl<'de> Deserialize<'de> for MatchSpec {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct MatchVisitor;
        impl<'de> Visitor<'de> for MatchVisitor {
            type Value = MatchSpec;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a rule such as \"Host(`example.com`)\" or a match object with hosts, path, methods…")
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<MatchSpec, E> {
                Ok(MatchSpec::Rule(value.to_owned()))
            }
            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<MatchSpec, A::Error> {
                StructuredMatch::deserialize(de::value::MapAccessDeserializer::new(map))
                    .map(MatchSpec::Structured)
            }
        }
        deserializer.deserialize_any(MatchVisitor)
    }
}

/// Structured match conditions. All given conditions must hold.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct StructuredMatch {
    /// Any of these hosts (`example.com`, `*.example.com`).
    pub hosts: Vec<String>,
    /// Exact path.
    pub path: Option<String>,
    /// Path prefix.
    pub path_prefix: Option<String>,
    /// Path regular expression.
    pub path_regex: Option<String>,
    /// Any of these methods.
    pub methods: Vec<String>,
    /// Header name → exact value; all must match.
    pub headers: BTreeMap<String, String>,
    /// Query parameter → exact value; all must match.
    pub query: BTreeMap<String, String>,
    /// Any of these client IPs or CIDR ranges.
    pub client_ips: Vec<String>,
}

impl StructuredMatch {
    /// The equivalent rule expression, or `None` when no condition is set.
    #[must_use]
    pub fn to_expr(&self) -> Option<Expr> {
        let mut all = Vec::new();
        any_of(&mut all, self.hosts.iter().cloned().map(Matcher::Host));
        all.extend(self.path.clone().map(|p| Expr::Matcher(Matcher::Path(p))));
        all.extend(
            self.path_prefix
                .clone()
                .map(|p| Expr::Matcher(Matcher::PathPrefix(p))),
        );
        all.extend(
            self.path_regex
                .clone()
                .map(|p| Expr::Matcher(Matcher::PathRegexp(p))),
        );
        any_of(&mut all, self.methods.iter().cloned().map(Matcher::Method));
        all.extend(self.headers.iter().map(|(name, value)| {
            Expr::Matcher(Matcher::Header {
                name: name.clone(),
                value: value.clone(),
            })
        }));
        all.extend(self.query.iter().map(|(key, value)| {
            Expr::Matcher(Matcher::Query {
                key: key.clone(),
                value: Some(value.clone()),
            })
        }));
        any_of(
            &mut all,
            self.client_ips.iter().cloned().map(Matcher::ClientIp),
        );
        match all.len() {
            0 => None,
            1 => all.pop(),
            _ => Some(Expr::And(all)),
        }
    }
}

/// Pushes one matcher, or an `Or` of several, onto `all`.
fn any_of(all: &mut Vec<Expr>, matchers: impl Iterator<Item = Matcher>) {
    let mut items: Vec<Expr> = matchers.map(Expr::Matcher).collect();
    match items.len() {
        0 => {}
        1 => all.append(&mut items),
        _ => all.push(Expr::Or(items)),
    }
}

/// TLS of a route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(untagged)]
pub enum RouteTls {
    /// `auto` or `off`.
    Mode(TlsMode),
    /// Detailed settings.
    Options(RouteTlsOptions),
}

impl<'de> Deserialize<'de> for RouteTls {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct TlsVisitor;
        impl<'de> Visitor<'de> for TlsVisitor {
            type Value = RouteTls;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(
                    "`auto`, `off` or an object with auto, dns_provider, domains or certificate",
                )
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<RouteTls, E> {
                match value {
                    "auto" => Ok(RouteTls::Mode(TlsMode::Auto)),
                    "off" => Ok(RouteTls::Mode(TlsMode::Off)),
                    other => Err(E::invalid_value(de::Unexpected::Str(other), &self)),
                }
            }
            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<RouteTls, A::Error> {
                RouteTlsOptions::deserialize(de::value::MapAccessDeserializer::new(map))
                    .map(RouteTls::Options)
            }
        }
        deserializer.deserialize_any(TlsVisitor)
    }
}

/// `auto` issues certificates automatically; `off` serves the route without TLS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TlsMode {
    /// Automatic certificates (ACME) for the route's hosts.
    #[default]
    Auto,
    /// No TLS.
    Off,
}

/// Detailed TLS settings of a route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RouteTlsOptions {
    /// Issue certificates automatically.
    #[serde(default = "crate::defaults::yes")]
    pub auto: bool,
    /// DNS provider (a key of `acme.dns_providers`) for DNS-01; required for wildcards.
    #[serde(default)]
    pub dns_provider: Option<String>,
    /// Names to put on the certificate instead of the route's hosts.
    #[serde(default)]
    pub domains: Vec<String>,
    /// A certificate from `certificates` to use instead of automatic issuance.
    #[serde(default)]
    pub certificate: Option<String>,
}

/// A TCP route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TcpRoute {
    /// Rule with TCP matchers: ``HostSNI(`db.example.com`)``, ``HostSNI(`*`)``, `ClientIP`, `ALPN`.
    #[serde(rename = "match")]
    pub matcher: String,
    /// Listeners (`tcp` or `https`) the route is attached to.
    #[serde(default)]
    pub listeners: Option<Vec<String>>,
    /// Higher priorities are evaluated first. `0` uses the rule length.
    #[serde(default)]
    pub priority: i64,
    /// TCP service (a key of `tcp_services`).
    pub service: String,
    /// TLS handling.
    #[serde(default)]
    pub tls: Option<TcpRouteTls>,
}

/// TLS handling of a TCP route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct TcpRouteTls {
    /// Forward the encrypted stream without terminating TLS (routing by SNI only).
    pub passthrough: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn structured_match_builds_the_equivalent_rule() {
        let spec = StructuredMatch {
            hosts: vec!["a.example.com".into(), "b.example.com".into()],
            path_prefix: Some("/api".into()),
            methods: vec!["GET".into()],
            ..StructuredMatch::default()
        };
        assert_eq!(
            spec.to_expr().unwrap().to_string(),
            "(Host(`a.example.com`) || Host(`b.example.com`)) && PathPrefix(`/api`) && Method(`GET`)"
        );
        assert_eq!(StructuredMatch::default().to_expr(), None);
    }

    #[test]
    fn match_and_tls_accept_string_or_object() {
        let rule: MatchSpec = serde_json::from_value(serde_json::json!("Host(`a`)")).unwrap();
        assert_eq!(rule, MatchSpec::Rule("Host(`a`)".into()));
        let structured: MatchSpec =
            serde_json::from_value(serde_json::json!({"hosts": ["a"]})).unwrap();
        assert!(matches!(structured, MatchSpec::Structured(_)));
        let tls: RouteTls = serde_json::from_value(serde_json::json!("off")).unwrap();
        assert_eq!(tls, RouteTls::Mode(TlsMode::Off));
        let tls: RouteTls =
            serde_json::from_value(serde_json::json!({"dns_provider": "cf"})).unwrap();
        assert!(matches!(
            tls,
            RouteTls::Options(RouteTlsOptions { auto: true, .. })
        ));
        assert!(serde_json::from_value::<RouteTls>(serde_json::json!("on")).is_err());
    }
}
