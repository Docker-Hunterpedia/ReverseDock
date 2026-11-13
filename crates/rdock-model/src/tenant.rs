//! Tenants (H-SEC-07, ADR-0031): a scope over the admin API's objects by name prefix, with
//! the host names the tenant's routes may claim. Enforcement lives in the admin API
//! (authorization) and in the validation of the API provider's objects; the data plane does
//! not know tenants.
//!
//! **Host claims.** A claim is a host name (`shop.example.com`) or a wildcard
//! (`*.shop.example.com`). An exact claim covers that one name. A wildcard claim covers every
//! name with one or more labels in front of its base (`a.shop.example.com`,
//! `a.b.shop.example.com`), never the base itself and never a name that merely ends with the
//! same characters (`evilshop.example.com`, `evil-shop.example.com`). Hosts and claims are
//! compared in lower case, without a trailing dot; internationalized names must be written in
//! their A-label form (`xn--…`), other non-ASCII text is refused, so two spellings of one
//! name cannot pass for different names.
//!
//! **A route is inside its claims** when every request it can match has a `Host` covered by
//! a claim: a `Host` matcher inside a claim, an `&&` with at least one such operand, or an
//! `||` whose operands all are. `HostRegexp`, a negation, `*` and rules without a `Host`
//! matcher cannot be proven inside and are refused.

use std::collections::BTreeMap;

use rdock_rules::{Expr, Matcher};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::values::IpNetwork;

/// One tenant.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct Tenant {
    /// The start of the names of the tenant's objects in the admin API (routes, services,
    /// middlewares). Defaults to `<tenant>-`. No tenant's prefix may start another's.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    /// The host names the tenant's routes may match: `shop.example.com` or
    /// `*.shop.example.com` (any name below it, not the name itself). Claims of two tenants
    /// may not overlap.
    pub hosts: Vec<String>,
    /// Objects outside the prefix that the tenant's objects may reference (`name` for the
    /// configuration file's, `name@provider` for a provider's).
    #[serde(skip_serializing_if = "TenantShared::is_empty")]
    pub shared: TenantShared,
    /// Networks the tenant's backends must be in. Empty: any address except loopback,
    /// link-local, unspecified and `localhost`; set: only IP literals inside these networks
    /// (DNS names and SRV records are refused, since they can resolve anywhere).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub backend_networks: Vec<IpNetwork>,
    /// Planned: listeners the tenant owns.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub listeners: Vec<String>,
    /// Planned: certificates the tenant owns.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub certificates: Vec<String>,
    /// Planned: a `tenant` label on the core metrics.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub metrics_label: bool,
    /// Planned: a dashboard view limited to the tenant.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub dashboard: bool,
}

/// Objects outside a tenant's prefix that its objects may reference.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct TenantShared {
    /// Services.
    pub services: Vec<String>,
    /// Middlewares.
    pub middlewares: Vec<String>,
    /// Cache stores (`caches`), for `cache` middlewares.
    pub caches: Vec<String>,
}

impl TenantShared {
    /// Whether nothing is shared.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.services.is_empty() && self.middlewares.is_empty() && self.caches.is_empty()
    }
}

impl Tenant {
    /// The prefix of tenant `name`'s objects.
    #[must_use]
    pub fn prefix_of(&self, name: &str) -> String {
        self.prefix.clone().unwrap_or_else(|| format!("{name}-"))
    }
}

/// The tenants by name.
pub type Tenants = BTreeMap<String, Tenant>;

/// A host name or a wildcard, normalized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPattern {
    /// `*.` in front.
    pub wildcard: bool,
    /// The name, or the part after `*.`.
    pub base: String,
}

impl HostPattern {
    /// Parses `example.com` or `*.example.com`: lower-cased, one trailing dot removed, ASCII
    /// letters, digits, `-` and `.` only, no empty label.
    ///
    /// # Errors
    ///
    /// Why the text is not a host name or wildcard.
    pub fn parse(text: &str) -> Result<Self, String> {
        let text = text.trim();
        if !text.is_ascii() {
            return Err(format!(
                "`{text}` is not ASCII: write an internationalized name in its A-label form (`xn--…`)"
            ));
        }
        let lower = text.to_ascii_lowercase();
        let lower = lower.strip_suffix('.').unwrap_or(&lower);
        let (wildcard, base) = match lower.strip_prefix("*.") {
            Some(rest) => (true, rest),
            None => (false, lower),
        };
        let valid = !base.is_empty()
            && base.len() <= 253
            && base.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            });
        if !valid {
            return Err(format!(
                "`{text}` is not a host name or `*.` followed by one"
            ));
        }
        Ok(Self {
            wildcard,
            base: base.to_owned(),
        })
    }

    /// Whether every host this pattern matches is a host `claim` covers. A route's wildcard
    /// matches one label; a claim's wildcard covers any depth, so both readings are inside.
    #[must_use]
    pub fn inside(&self, claim: &Self) -> bool {
        let below = |name: &str, base: &str| {
            name.len() > base.len()
                && name.ends_with(base)
                && name.as_bytes()[name.len() - base.len() - 1] == b'.'
        };
        match (claim.wildcard, self.wildcard) {
            (false, false) => self.base == claim.base,
            (false, true) => false,
            (true, false) => below(&self.base, &claim.base),
            (true, true) => self.base == claim.base || below(&self.base, &claim.base),
        }
    }

    /// Whether some host is matched by both patterns (read as claims: wildcards at any depth).
    #[must_use]
    pub fn overlaps(&self, other: &Self) -> bool {
        self.inside(other) || other.inside(self)
    }
}

impl std::fmt::Display for HostPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.wildcard {
            f.write_str("*.")?;
        }
        f.write_str(&self.base)
    }
}

/// Whether `host` (a route's `Host` value or a certificate domain) is covered by one of
/// `claims`. `*` and invalid names are not.
#[must_use]
pub fn host_claimed(host: &str, claims: &[HostPattern]) -> bool {
    HostPattern::parse(host).is_ok_and(|p| claims.iter().any(|c| p.inside(c)))
}

/// Whether every request `expr` matches has a `Host` covered by `claims` (see the module
/// documentation).
#[must_use]
pub fn rule_inside(expr: &Expr, claims: &[HostPattern]) -> bool {
    match expr {
        Expr::Matcher(Matcher::Host(host)) => host_claimed(host, claims),
        Expr::Matcher(_) | Expr::Not(_) => false,
        Expr::And(items) => items.iter().any(|e| rule_inside(e, claims)),
        Expr::Or(items) => !items.is_empty() && items.iter().all(|e| rule_inside(e, claims)),
    }
}

/// The tenant whose prefix starts `name` (a bare API object name), if any.
#[must_use]
pub fn owner<'a>(tenants: &'a Tenants, name: &str) -> Option<(&'a str, &'a Tenant)> {
    tenants
        .iter()
        .find(|(t, tenant)| name.starts_with(&tenant.prefix_of(t)))
        .map(|(t, tenant)| (t.as_str(), tenant))
}

/// Middleware types a tenant's objects may not use, with the reason: they read files on the
/// proxy's machine, call out to other services, or run code.
pub const FORBIDDEN_TYPES: [(&str, &str); 7] = [
    ("forward_auth", "calls out to another service"),
    ("agent", "calls out to another service"),
    ("plugin", "runs native code compiled into the binary"),
    ("wasm", "loads a module from a file"),
    ("static", "serves files from the proxy's file system"),
    ("oidc", "calls out to an identity provider"),
    ("cloudflare_access", "calls out to Cloudflare for its keys"),
];

/// Fields of otherwise allowed middleware types that a tenant's objects may not set:
/// `(type, field, reason)`.
pub const FORBIDDEN_FIELDS: [(&str, &str, &str); 6] = [
    ("jwt", "jwks_url", "calls out to fetch keys"),
    ("jwt", "jwks_file", "reads a file"),
    ("basic_auth", "users_file", "reads a file"),
    ("errors", "file", "reads a file"),
    ("maintenance", "file", "reads a file"),
    ("validate", "openapi", "reads a file"),
];

/// Service fields a tenant's objects may not set: upstream TLS files.
pub const FORBIDDEN_SERVICE_TLS_FIELDS: [&str; 3] = ["ca_file", "cert_file", "key_file"];

/// Where a `${…}` reference would be taken literally (regular-expression replacements), so a
/// tenant may write one there.
fn verbatim(key: &str) -> bool {
    key == "replacement"
}

/// Paths (`a.b[2].c`, relative to the object) of strings holding a `${…}` reference, which
/// would read an environment variable, a file or a Vault secret on the proxy's machine.
#[must_use]
pub fn references(value: &serde_json::Value) -> Vec<String> {
    fn walk(value: &serde_json::Value, path: &str, out: &mut Vec<String>) {
        match value {
            serde_json::Value::String(text) if text.contains("${") => out.push(path.to_owned()),
            serde_json::Value::Object(map) => {
                for (key, child) in map {
                    if verbatim(key) {
                        continue;
                    }
                    let next = if path.is_empty() {
                        key.clone()
                    } else {
                        format!("{path}.{key}")
                    };
                    walk(child, &next, out);
                }
            }
            serde_json::Value::Array(items) => {
                for (i, child) in items.iter().enumerate() {
                    walk(child, &format!("{path}[{i}]"), out);
                }
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    walk(value, "", &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(text: &str) -> HostPattern {
        HostPattern::parse(text).unwrap()
    }

    #[test]
    fn claims_cover_exactly_what_they_say() {
        let exact = p("shop.example.com");
        let wild = p("*.shop.example.com");
        assert!(p("shop.example.com").inside(&exact));
        assert!(
            p("SHOP.Example.COM.").inside(&exact),
            "case and a trailing dot"
        );
        assert!(!p("a.shop.example.com").inside(&exact));
        assert!(!p("*.shop.example.com").inside(&exact));
        assert!(p("a.shop.example.com").inside(&wild));
        assert!(p("a.b.shop.example.com").inside(&wild));
        assert!(p("*.shop.example.com").inside(&wild));
        assert!(p("*.a.shop.example.com").inside(&wild));
        assert!(!p("shop.example.com").inside(&wild), "not the base itself");
        assert!(!p("evilshop.example.com").inside(&wild));
        assert!(!p("evil-shop.example.com").inside(&exact));
        assert!(!p("*.example.com").inside(&wild), "a broader wildcard");
        assert!(!host_claimed("*", std::slice::from_ref(&wild)));
        assert!(HostPattern::parse("bücher.example").is_err());
        assert!(p("xn--bcher-kva.example").inside(&p("*.example")));
        for bad in [
            "", "*.", "a..b", "-a.com", "a b.com", "a.com:80", "*.*.com", "a*.com",
        ] {
            assert!(HostPattern::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn overlaps_are_symmetric() {
        assert!(p("*.example.com").overlaps(&p("a.example.com")));
        assert!(p("a.example.com").overlaps(&p("*.example.com")));
        assert!(p("*.example.com").overlaps(&p("*.a.example.com")));
        assert!(!p("example.com").overlaps(&p("*.example.com")));
        assert!(!p("a.example.com").overlaps(&p("b.example.com")));
    }

    #[test]
    fn rules_are_inside_only_when_every_branch_is() {
        let claims = [p("shop.example.com"), p("*.shop.example.com")];
        let inside = |rule: &str| rule_inside(&rdock_rules::parse(rule).unwrap(), &claims);
        assert!(inside("Host(`shop.example.com`)"));
        assert!(inside("Host(`a.shop.example.com`) && PathPrefix(`/api`)"));
        assert!(inside("PathPrefix(`/api`) && Host(`a.shop.example.com`)"));
        assert!(inside(
            "Host(`shop.example.com`) || Host(`b.shop.example.com`)"
        ));
        assert!(!inside(
            "Host(`shop.example.com`) || Host(`other.example.com`)"
        ));
        assert!(!inside("PathPrefix(`/`)"));
        assert!(!inside("Host(`*.example.com`)"));
        assert!(!inside("!Host(`other.example.com`)"));
        assert!(!inside("HostRegexp(`^.+\\.shop\\.example\\.com$`)"));
        assert!(!inside("Host(`shop.example.com`) || PathPrefix(`/`)"));
    }

    #[test]
    fn references_are_found_except_in_replacements() {
        let value = serde_json::json!({
            "type": "redirect", "regex": "^/(.*)", "replacement": "/${1}",
            "headers": { "x": "${env:SECRET}" }, "list": ["a", "${file:/etc/passwd}"]
        });
        assert_eq!(references(&value), vec!["headers.x", "list[1]"]);
    }
}
