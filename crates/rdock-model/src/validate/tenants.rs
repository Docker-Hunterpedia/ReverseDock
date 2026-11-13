//! Tenants (H-SEC-07, ADR-0031): the `tenants` section itself, and every API-provider object
//! under a tenant's prefix against its tenant's rules, whoever wrote it.

use std::net::IpAddr;

use super::{Validator, reference_key};
use crate::diagnostics::{Diagnostic, path_index, path_key};
use crate::middleware::Middleware;
use crate::route::{MatchSpec, RouteTls};
use crate::service::Service;
use crate::tenant::{
    FORBIDDEN_FIELDS, FORBIDDEN_SERVICE_TLS_FIELDS, FORBIDDEN_TYPES, HostPattern, Tenant,
    references, rule_inside,
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
            let expr = match &route.matcher {
                MatchSpec::Rule(rule) => rdock_rules::parse(rule).ok(),
                MatchSpec::Structured(s) => s.to_expr(),
            };
            if let Some(expr) = expr
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
        for (i, backend) in service.backends.iter().enumerate() {
            let at = format!("{}.address", path_index(&format!("{path}.backends"), i));
            let problem = match &backend.address {
                BackendAddress::Unix(_) => {
                    Some("it is a Unix socket on the proxy's machine".to_owned())
                }
                BackendAddress::Tcp { host, .. } => {
                    let ip = host
                        .trim_start_matches('[')
                        .trim_end_matches(']')
                        .parse::<IpAddr>()
                        .ok();
                    match ip {
                        Some(ip) if !networks.is_empty() => {
                            (!networks.iter().any(|n| n.contains(&ip)))
                                .then(|| format!("`{ip}` is outside `backend_networks`"))
                        }
                        Some(ip) if local(ip) => Some(format!(
                            "`{ip}` is a loopback, link-local or unspecified address"
                        )),
                        None if !networks.is_empty() => Some(
                            "it is a DNS name, while `backend_networks` asks for IP literals"
                                .to_owned(),
                        ),
                        None if host.eq_ignore_ascii_case("localhost")
                            || host.to_ascii_lowercase().ends_with(".localhost") =>
                        {
                            Some("`localhost` is the proxy's own machine".to_owned())
                        }
                        Some(_) | None => None,
                    }
                }
                BackendAddress::Srv(_) => (!networks.is_empty()).then(|| {
                    "it is an SRV record, while `backend_networks` asks for IP literals".to_owned()
                }),
            };
            if let Some(problem) = problem {
                self.error(
                    at,
                    format!(
                        "tenant `{}` cannot send traffic to this address: {problem}",
                        scope.name
                    ),
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

fn local(ip: IpAddr) -> bool {
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 @ IpAddr::V4(_) => v4,
    };
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_link_local() || v4.is_unspecified(),
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.is_unspecified() || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}
