//! Tenants (H-SEC-07, ADR-0031): the `tenants` section itself, and every API-provider object
//! under a tenant's prefix against its tenant's rules, whoever wrote it.

use std::net::IpAddr;

use super::{Validator, reference_key};
use crate::addresses::BackendPolicy;
use crate::diagnostics::{Diagnostic, path_index, path_key};
use crate::middleware::Middleware;
use crate::route::{MatchSpec, RouteTls};
use crate::service::Service;
use crate::tenant::{
    FORBIDDEN_FIELDS, FORBIDDEN_SERVICE_TLS_FIELDS, FORBIDDEN_TYPES, HostPattern, Tenant,
    TenantLimits, references, rule_inside,
};
use crate::values::BackendAddress;

/// The provider whose objects tenants own.
const API: &str = "@api";

/// A tenant's checked claims, prefix and shared names.
struct Scope<'a> {
    name: &'a str,
    tenant: &'a Tenant,
    prefix: String,
    claims: Vec<HostPattern>,
}

impl Scope<'_> {
    /// Whether a merged reference names one of the tenant's own API objects.
    fn own(&self, reference: &str) -> bool {
        reference
            .strip_suffix(API)
            .is_some_and(|bare| bare.starts_with(&self.prefix))
    }

    fn shared(list: &[String], reference: &str) -> bool {
        list.iter()
            .any(|s| reference_key(s) == reference_key(reference))
    }
}

impl Validator<'_> {
    pub(super) fn check_tenants(&mut self) {
        let tenants = &self.config.tenants;
        if tenants.is_empty() {
            return;
        }
        let mut scopes: Vec<Scope<'_>> = Vec::new();
        for (name, tenant) in tenants {
            let path = path_key("tenants", name);
            self.check_name("tenants", name);
            let prefix = tenant.prefix_of(name);
            let prefix_ok = !prefix.is_empty()
                && prefix.len() < super::MAX_NAME_LEN
                && prefix.starts_with(|c: char| c.is_ascii_alphanumeric())
                && prefix
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
            if !prefix_ok {
                self.error(
                    format!("{path}.prefix"),
                    format!("`{prefix}` cannot start an object name: use letters, digits, `-`, `_` or `.`, starting with a letter or digit"),
                );
            }
            let mut claims = Vec::new();
            for (i, host) in tenant.hosts.iter().enumerate() {
                let at = path_index(&format!("{path}.hosts"), i);
                match HostPattern::parse(host) {
                    Ok(claim) if claim.wildcard && !claim.base.contains('.') => {
                        self.push(
                            Diagnostic::error(
                                at,
                                format!("`{host}` claims a whole top-level domain"),
                            )
                            .with_hint("claim `*.example.com` or narrower"),
                        );
                    }
                    Ok(claim) => claims.push(claim),
                    Err(message) => self.error(at, message),
                }
            }
            self.check_tenant_settings(&path, tenant);
            if tenant.hosts.is_empty() {
                self.warning(
                    format!("{path}.hosts"),
                    "no host claims: the tenant can define services and middlewares, but no route",
                );
            }
            scopes.push(Scope {
                name,
                tenant,
                prefix,
                claims,
            });
        }
        // Ownership must be unambiguous: one tenant per object name and per host.
        for (i, a) in scopes.iter().enumerate() {
            for b in &scopes[i + 1..] {
                if a.prefix.starts_with(&b.prefix) || b.prefix.starts_with(&a.prefix) {
                    self.push(
                        Diagnostic::error(
                            format!("{}.prefix", path_key("tenants", b.name)),
                            format!(
                                "the prefixes of `{}` (`{}`) and `{}` (`{}`) overlap: an object name could belong to both",
                                a.name, a.prefix, b.name, b.prefix
                            ),
                        )
                        .with_hint("give each tenant a prefix that does not start another's, e.g. ending with `-`"),
                    );
                }
                for ca in &a.claims {
                    for cb in &b.claims {
                        if ca.overlaps(cb) {
                            self.error(
                                format!("{}.hosts", path_key("tenants", b.name)),
                                format!(
                                    "`{cb}` overlaps `{ca}` of tenant `{}`: a host can be claimed by one tenant only",
                                    a.name
                                ),
                            );
                        }
                    }
                }
            }
        }
        if self.merged {
            self.check_tenant_objects(&scopes);
            self.check_tenant_counts(&scopes);
            self.check_claimed_hosts_elsewhere(&scopes);
        }
    }

    /// `backend_networks` and `limits` of one tenant.
    fn check_tenant_settings(&mut self, path: &str, tenant: &Tenant) {
        for (i, network) in tenant.backend_networks.iter().enumerate() {
            let risky: [(&str, &str); 5] = [
                ("127.0.0.0/8", "loopback: the proxy's own machine"),
                ("::1/128", "loopback: the proxy's own machine"),
                (
                    "169.254.0.0/16",
                    "link-local, where cloud metadata services live",
                ),
                ("fe80::/10", "link-local"),
                ("fd00:ec2::/32", "AWS's IPv6 metadata range"),
            ];
            for (range, what) in risky {
                if range
                    .parse::<ipnet::IpNet>()
                    .is_ok_and(|r| network.overlaps(&r))
                {
                    self.push(
                        Diagnostic::warning(
                            path_index(&format!("{path}.backend_networks"), i),
                            format!("`{network}` lets the tenant reach {what} ({range})"),
                        )
                        .with_hint("list only the networks of the tenant's own backends"),
                    );
                }
            }
        }
        let limits = &tenant.limits;
        self.check_not_zero(
            &format!("{path}.limits.max_body"),
            limits.max_body.as_u64() == 0,
        );
        for (field, value) in [
            ("max_routes", limits.max_routes),
            ("max_services", limits.max_services),
            ("max_middlewares", limits.max_middlewares),
            ("max_tls_names", limits.max_tls_names),
        ] {
            if value > TenantLimits::MAX_COUNT {
                self.error(
                    format!("{path}.limits.{field}"),
                    format!("at most {}", TenantLimits::MAX_COUNT),
                );
            }
        }
    }

    /// The object-count and certificate-name ceilings of `tenants.<name>.limits`. Objects are
    /// counted in name order, so the ones refused are always the same.
    fn check_tenant_counts(&mut self, scopes: &[Scope<'_>]) {
        let config = self.config;
        for scope in scopes {
            let limits = scope.tenant.limits;
            let own = |key: &&String| {
                key.strip_suffix(API)
                    .is_some_and(|b| b.starts_with(&scope.prefix))
            };
            let sections: [(&str, Vec<&String>, u32); 3] = [
                (
                    "routes",
                    config.routes.keys().filter(own).collect(),
                    limits.max_routes,
                ),
                (
                    "services",
                    config.services.keys().filter(own).collect(),
                    limits.max_services,
                ),
                (
                    "middlewares",
                    config.middlewares.keys().filter(own).collect(),
                    limits.max_middlewares,
                ),
            ];
            for (section, keys, max) in sections {
                for key in keys.iter().skip(usize::try_from(max).unwrap_or(usize::MAX)) {
                    self.push(
                        Diagnostic::error(
                            path_key(section, key),
                            format!("tenant `{}` may have at most {max} {section}", scope.name),
                        )
                        .with_hint(format!(
                            "an administrator can raise `tenants.{}.limits.max_{section}`",
                            scope.name
                        )),
                    );
                }
            }
            let mut names = std::collections::BTreeSet::new();
            for (key, route) in config.routes.iter().filter(|(k, _)| own(k)) {
                if !super::wants_auto_tls(config, route) {
                    continue;
                }
                let mut hosts = Vec::new();
                if let Some(expr) = route_expr(route) {
                    hosts_of(&expr, &mut hosts);
                }
                if let Some(RouteTls::Options(tls)) = &route.tls {
                    hosts.extend(tls.domains.iter().cloned());
                }
                let before = names.len();
                names.extend(
                    hosts
                        .iter()
                        .filter_map(|h| HostPattern::parse(h).ok())
                        .map(|h| h.to_string()),
                );
                let max = usize::try_from(limits.max_tls_names).unwrap_or(usize::MAX);
                if names.len() > max && before < names.len() {
                    self.push(
                        Diagnostic::error(
                            format!("{}.match", path_key("routes", key)),
                            format!(
                                "tenant `{}` may have automatic certificates for at most {max} host names",
                                scope.name
                            ),
                        )
                        .with_hint(format!(
                            "every name is an order on the shared ACME account; use fewer names, or an administrator can raise `tenants.{}.limits.max_tls_names`",
                            scope.name
                        )),
                    );
                }
            }
        }
    }

    /// Host claims bind the API provider's objects only: a route of the file or of another
    /// provider may still match a claimed host. That is allowed (those writers are trusted)
    /// but rarely meant, so it is a warning.
    fn check_claimed_hosts_elsewhere(&mut self, scopes: &[Scope<'_>]) {
        for (key, route) in &self.config.routes {
            if key.ends_with(API) {
                continue;
            }
            let Some(expr) = route_expr(route) else {
                continue;
            };
            let mut hosts = Vec::new();
            hosts_of(&expr, &mut hosts);
            for scope in scopes {
                if let Some(host) = hosts.iter().find(|h| {
                    HostPattern::parse(h).is_ok_and(|p| scope.claims.iter().any(|c| p.overlaps(c)))
                }) {
                    self.push(
                        Diagnostic::warning(
                            format!("{}.match", path_key("routes", key)),
                            format!(
                                "`{host}` is claimed by tenant `{}`, but this route is not the tenant's: claims bind only objects written through the admin API",
                                scope.name
                            ),
                        )
                        .with_hint("if the route should win, give it the `priority` it needs; otherwise remove the host or the claim"),
                    );
                }
            }
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one pass over the three sections, each with its own rules"
    )]
    fn check_tenant_objects(&mut self, scopes: &[Scope<'_>]) {
        let scope_of = |key: &str| {
            let bare = key.strip_suffix(API)?;
            scopes.iter().find(|s| bare.starts_with(&s.prefix))
        };
        let config = self.config;
        for (key, route) in &config.routes {
            let Some(scope) = scope_of(key) else { continue };
            let path = path_key("routes", key);
            if let Some(expr) = route_expr(route)
                && !rule_inside(&expr, &scope.claims)
            {
                self.push(
                    Diagnostic::error(
                        format!("{path}.match"),
                        format!(
                            "this rule is not inside the host claims of tenant `{}`",
                            scope.name
                        ),
                    )
                    .with_hint(format!(
                        "match a claimed host with `Host(…)` (claims: {}); `||` needs a claimed host in every branch, `HostRegexp`, `!` and `*` are not accepted",
                        claim_list(scope)
                    )),
                );
            }
            if let Some(RouteTls::Options(tls)) = &route.tls {
                if tls.certificate.is_some() {
                    self.tenant_refused(
                        &format!("{path}.tls.certificate"),
                        scope,
                        "a certificate from `certificates`",
                        "tenant-owned certificates are planned; use automatic certificates",
                    );
                }
                for (i, domain) in tls.domains.iter().enumerate() {
                    if !crate::tenant::host_claimed(domain, &scope.claims) {
                        self.error(
                            path_index(&format!("{path}.tls.domains"), i),
                            format!(
                                "`{domain}` is not inside the host claims of tenant `{}`",
                                scope.name
                            ),
                        );
                    }
                }
            }
            let cap = scope.tenant.limits.max_body;
            if route.max_body.is_some_and(|m| m > cap) {
                self.tenant_over_body(&format!("{path}.max_body"), scope);
            }
            if route.priority_class == crate::route::PriorityClass::Critical
                && !scope.tenant.allow_critical
            {
                for reference in &route.middlewares {
                    if matches!(
                        config.middlewares.get(reference_key(reference)),
                        Some(Middleware::Admission(_))
                    ) && !scope.own(reference_key(reference))
                    {
                        self.push(
                            Diagnostic::error(
                                format!("{path}.priority_class"),
                                format!(
                                    "tenant `{}` cannot mark routes `critical` on the shared `admission` middleware `{reference}`",
                                    scope.name
                                ),
                            )
                            .with_hint(format!(
                                "use `normal` or `sheddable`, define an `admission` middleware of the tenant's own, or an administrator can set `tenants.{}.allow_critical`",
                                scope.name
                            )),
                        );
                    }
                }
            }
            if let Some(service) = &route.service {
                self.tenant_reference(&format!("{path}.service"), scope, "service", service);
            }
            if let Some(mirror) = &route.mirror {
                self.tenant_reference(
                    &format!("{path}.mirror.service"),
                    scope,
                    "service",
                    &mirror.service,
                );
            }
            for (i, middleware) in route.middlewares.iter().enumerate() {
                self.tenant_reference(
                    &path_index(&format!("{path}.middlewares"), i),
                    scope,
                    "middleware",
                    middleware,
                );
            }
            self.tenant_secret_references(&path, scope, serde_json::to_value(route).ok());
        }
        for (key, service) in &config.services {
            let Some(scope) = scope_of(key) else { continue };
            let path = path_key("services", key);
            self.check_tenant_service(&path, scope, service);
            self.tenant_secret_references(&path, scope, serde_json::to_value(service).ok());
        }
        for (key, middleware) in &config.middlewares {
            let Some(scope) = scope_of(key) else { continue };
            let path = path_key("middlewares", key);
            let value = serde_json::to_value(middleware).unwrap_or_default();
            let kind = value["type"].as_str().unwrap_or_default();
            if let Some((_, why)) = FORBIDDEN_TYPES.iter().find(|(t, _)| *t == kind) {
                self.tenant_refused(&path, scope, &format!("`type: {kind}`"), why);
            }
            for (t, field, why) in FORBIDDEN_FIELDS {
                if t == kind && value.get(field).is_some_and(|v| !v.is_null()) {
                    self.tenant_refused(
                        &format!("{path}.{field}"),
                        scope,
                        &format!("`{field}`"),
                        why,
                    );
                }
            }
            match middleware {
                Middleware::Errors(e) => {
                    if let Some(service) = &e.service {
                        self.tenant_reference(
                            &format!("{path}.service"),
                            scope,
                            "service",
                            service,
                        );
                    }
                }
                Middleware::HoldBody(h) if h.max > scope.tenant.limits.max_body => {
                    self.tenant_over_body(&format!("{path}.max"), scope);
                }
                Middleware::Transform(t) if t.max_body > scope.tenant.limits.max_body => {
                    self.tenant_over_body(&format!("{path}.max_body"), scope);
                }
                Middleware::Validate(v) if v.max_body > scope.tenant.limits.max_body => {
                    self.tenant_over_body(&format!("{path}.max_body"), scope);
                }
                Middleware::Cache(c) if !Scope::shared(&scope.tenant.shared.caches, &c.store) => {
                    self.error(
                        format!("{path}.store"),
                        format!(
                            "cache store `{}` is not shared with tenant `{}`",
                            c.store, scope.name
                        ),
                    );
                }
                _ => {}
            }
            self.tenant_secret_references(&path, scope, Some(value));
        }
    }

    fn check_tenant_service(&mut self, path: &str, scope: &Scope<'_>, service: &Service) {
        for (i, target) in service.split.iter().enumerate() {
            self.tenant_reference(
                &format!("{}.service", path_index(&format!("{path}.split"), i)),
                scope,
                "service",
                &target.service,
            );
        }
        if let Some(tls) = &service.tls {
            let set = [
                tls.ca_file.is_some(),
                tls.cert_file.is_some(),
                tls.key_file.is_some(),
            ];
            for (field, set) in FORBIDDEN_SERVICE_TLS_FIELDS.iter().zip(set) {
                if set {
                    self.tenant_refused(
                        &format!("{path}.tls.{field}"),
                        scope,
                        &format!("`tls.{field}`"),
                        "reads a file",
                    );
                }
            }
        }
        let networks = &scope.tenant.backend_networks;
        let policy = BackendPolicy::of(networks);
        for (i, backend) in service.backends.iter().enumerate() {
            let at = format!("{}.address", path_index(&format!("{path}.backends"), i));
            let problem = match &backend.address {
                BackendAddress::Unix(_) => {
                    Some("it is a Unix socket on the proxy's machine".to_owned())
                }
                BackendAddress::Tcp { host, .. } => {
                    let literal = host.trim_start_matches('[').trim_end_matches(']');
                    match literal.parse::<IpAddr>() {
                        Ok(IpAddr::V6(v6)) if v6.to_ipv4_mapped().is_some() => Some(format!(
                            "`{v6}` is an IPv4-mapped IPv6 address: write the IPv4 address itself"
                        )),
                        Ok(ip) => policy.refusal(ip),
                        // The parser already refuses numeric spellings for everyone; this is
                        // the same rule, kept here so a tenant never depends on it.
                        Err(_) if crate::addresses::looks_numeric(host) => Some(format!(
                            "`{host}` is a non-canonical IP address, not a DNS name"
                        )),
                        Err(_) if crate::addresses::is_loopback_name(host) => {
                            Some(format!("`{host}` names the proxy's own machine"))
                        }
                        Err(_) if !networks.is_empty() => Some(
                            "it is a DNS name, while `backend_networks` asks for IP literals"
                                .to_owned(),
                        ),
                        // Every address it resolves to is checked when it resolves.
                        Err(_) => None,
                    }
                }
                BackendAddress::Srv(_) => (!networks.is_empty()).then(|| {
                    "it is an SRV record, while `backend_networks` asks for IP literals".to_owned()
                }),
            };
            if let Some(problem) = problem {
                self.push(
                    Diagnostic::error(
                        at,
                        format!(
                            "tenant `{}` cannot send traffic to this address: {problem}",
                            scope.name
                        ),
                    )
                    .with_hint(if networks.is_empty() {
                        "without `backend_networks` a tenant reaches global unicast addresses only; an administrator can list the networks it may reach in `tenants.<name>.backend_networks`"
                    } else {
                        "use an IP address inside `backend_networks`"
                    }),
                );
            }
        }
    }

    /// A reference from a tenant's object: to its own API objects, or to an object its
    /// tenant shares.
    fn tenant_reference(&mut self, path: &str, scope: &Scope<'_>, kind: &str, reference: &str) {
        if scope.own(reference) {
            return;
        }
        let shared = match kind {
            "service" => &scope.tenant.shared.services,
            _ => &scope.tenant.shared.middlewares,
        };
        if Scope::shared(shared, reference) {
            return;
        }
        self.push(
            Diagnostic::error(
                path,
                format!(
                    "{kind} `{reference}` is outside tenant `{}`: not under `{}` and not shared",
                    scope.name, scope.prefix
                ),
            )
            .with_hint(format!(
                "name your own {kind}s `{}…`, or ask an administrator to list it in `tenants.{}.shared`",
                scope.prefix, scope.name
            )),
        );
    }

    fn tenant_secret_references(
        &mut self,
        path: &str,
        scope: &Scope<'_>,
        value: Option<serde_json::Value>,
    ) {
        for at in references(&value.unwrap_or_default()) {
            self.tenant_refused(
                &format!("{path}.{at}"),
                scope,
                "a `${…}` reference",
                "reads an environment variable, a file or a Vault secret on the proxy's machine",
            );
        }
    }

    fn tenant_over_body(&mut self, path: &str, scope: &Scope<'_>) {
        self.push(
            Diagnostic::error(
                path,
                format!(
                    "above the body limit of tenant `{}` ({})",
                    scope.name, scope.tenant.limits.max_body
                ),
            )
            .with_hint(format!(
                "an administrator can raise `tenants.{}.limits.max_body`",
                scope.name
            )),
        );
    }

    fn tenant_refused(&mut self, path: &str, scope: &Scope<'_>, what: &str, why: &str) {
        self.push(
            Diagnostic::error(
                path,
                format!("tenant `{}` cannot use {what}: it {why}", scope.name),
            )
            .with_hint("tenant objects may not read files, call out or run code; an administrator can define it outside the tenant and share it"),
        );
    }
}

/// The expression of a route's match, if it parses.
fn route_expr(route: &crate::route::Route) -> Option<rdock_rules::Expr> {
    match &route.matcher {
        MatchSpec::Rule(rule) => rdock_rules::parse(rule).ok(),
        MatchSpec::Structured(s) => s.to_expr(),
    }
}

/// Every `Host` value in `expr`.
fn hosts_of(expr: &rdock_rules::Expr, out: &mut Vec<String>) {
    match expr {
        rdock_rules::Expr::Matcher(rdock_rules::Matcher::Host(host)) => out.push(host.clone()),
        rdock_rules::Expr::Matcher(_) => {}
        rdock_rules::Expr::Not(inner) => hosts_of(inner, out),
        rdock_rules::Expr::And(items) | rdock_rules::Expr::Or(items) => {
            for item in items {
                hosts_of(item, out);
            }
        }
    }
}

fn claim_list(scope: &Scope<'_>) -> String {
    if scope.claims.is_empty() {
        return "none".to_owned();
    }
    scope
        .claims
        .iter()
        .map(|c| format!("`{c}`"))
        .collect::<Vec<_>>()
        .join(", ")
}
