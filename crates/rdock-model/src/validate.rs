//! Semantic validation: references, rules, listeners and risky settings.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use rdock_rules::{Context, Expr, check_host};
use regex::RegexBuilder;

use crate::acme::{Challenge, DnsProvider, KnownCa};
use crate::config::{Config, Listener, ListenerProtocol};
use crate::diagnostics::{Diagnostic, path_index, path_key};
use crate::middleware::{
    BasicAuthConfig, CorsConfig, ErrorsConfig, ForwardAuthConfig, HeaderRules, Middleware,
    RateLimitConfig, RedirectConfig, StripPrefixConfig,
};
use crate::route::{MatchSpec, Route, RouteTls, TlsMode};
use crate::service::{LbPolicy, SameSite, Scheme, Service};
use crate::settings::ClientIpHeader;
use crate::values::{TrustedProxy, is_token};
use rdock_rules::closest_match;

/// Providers that can own objects referenced as `name@provider`.
const PROVIDERS: [&str; 5] = ["file", "docker", "swarm", "kubernetes", "api"];
const MAX_NAME_LEN: usize = 63;
const MAX_RETRY_ATTEMPTS: u32 = 10;
const REGEX_SIZE_LIMIT: usize = 1 << 20;

impl Config {
    /// Checks references, rules, listeners and settings.
    ///
    /// The configuration can be applied when no returned diagnostic is an error. Warnings
    /// point at settings that work but are probably not intended or are risky.
    #[must_use]
    pub fn validate(&self) -> Vec<Diagnostic> {
        let mut v = Validator {
            config: self,
            listeners: self.effective_listeners().into_owned(),
            out: Vec::new(),
        };
        v.check_version();
        v.check_listeners();
        v.check_defaults();
        v.check_routes();
        v.check_services();
        v.check_middlewares();
        v.check_tcp();
        v.check_certificates();
        v.check_acme();
        v.check_security();
        v.check_admin();
        v.check_observability();
        v.check_providers();
        v.out
    }
}

/// The service name of a reference to an object in this file (`name` or `name@file`).
fn local_name(reference: &str) -> Option<&str> {
    match reference.split_once('@') {
        None => Some(reference),
        Some((name, "file")) => Some(name),
        Some(_) => None,
    }
}

/// Password hash formats accepted by basic authentication.
#[derive(Clone, Copy, PartialEq, Eq)]
enum HashStrength {
    /// argon2id or bcrypt.
    Strong,
    /// Apache MD5 (`$apr1$`), MD5-crypt (`$1$`) or SHA-1 (`{SHA}`): fast to brute-force,
    /// accepted because Traefik and `htpasswd` produce them.
    Weak,
}

fn hash_strength(hash: &str) -> Option<HashStrength> {
    if ["$argon2id$", "$2a$", "$2b$", "$2x$", "$2y$"]
        .iter()
        .any(|prefix| hash.starts_with(prefix))
    {
        Some(HashStrength::Strong)
    } else if ["$apr1$", "$1$", "{SHA}"]
        .iter()
        .any(|prefix| hash.starts_with(prefix))
    {
        Some(HashStrength::Weak)
    } else {
        None
    }
}

/// Parses `404` or `500-599`.
fn status_range(value: &str) -> Option<(u16, u16)> {
    let (from, to) = value.split_once('-').unwrap_or((value, value));
    let (from, to) = (
        from.trim().parse::<u16>().ok()?,
        to.trim().parse::<u16>().ok()?,
    );
    ((100..=599).contains(&from) && (100..=599).contains(&to) && from <= to).then_some((from, to))
}

fn protocol_name(protocol: ListenerProtocol) -> &'static str {
    match protocol {
        ListenerProtocol::Http => "http",
        ListenerProtocol::Https => "https",
        ListenerProtocol::Tcp => "tcp",
        ListenerProtocol::Udp => "udp",
    }
}

struct Validator<'a> {
    config: &'a Config,
    listeners: BTreeMap<String, Listener>,
    out: Vec<Diagnostic>,
}

impl Validator<'_> {
    fn push(&mut self, diagnostic: Diagnostic) {
        self.out.push(diagnostic);
    }

    fn error(&mut self, path: impl Into<String>, message: impl Into<String>) {
        self.push(Diagnostic::error(path, message));
    }

    fn warning(&mut self, path: impl Into<String>, message: impl Into<String>) {
        self.push(Diagnostic::warning(path, message));
    }

    fn check_name(&mut self, section: &str, name: &str) {
        let valid = !name.is_empty()
            && name.len() <= MAX_NAME_LEN
            && name.starts_with(|c: char| c.is_ascii_alphanumeric())
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
        if !valid {
            self.push(
                Diagnostic::error(path_key(section, name), format!("invalid name `{name}`")).with_hint(
                    "names start with a letter or digit and use letters, digits, `-`, `_` or `.` \
                     (at most 63 characters; `@` is reserved for provider references)",
                ),
            );
        }
    }

    /// Checks `name` or `name@provider`. Objects of other providers are resolved at runtime.
    fn check_reference<T>(
        &mut self,
        path: &str,
        kind: &str,
        reference: &str,
        known: &BTreeMap<String, T>,
    ) {
        let (name, provider) = match reference.split_once('@') {
            Some((name, provider)) => (name, Some(provider)),
            None => (reference, None),
        };
        if let Some(provider) = provider
            && !PROVIDERS.contains(&provider)
        {
            self.push(
                Diagnostic::error(
                    path,
                    format!("unknown provider `{provider}` in `{reference}`"),
                )
                .with_hint(format!("providers are {}", PROVIDERS.join(", "))),
            );
            return;
        }
        if provider.is_some_and(|p| p != "file") || known.contains_key(name) {
            return;
        }
        let hint = match closest_match(name, known.keys().map(String::as_str)) {
            Some(near) => format!("did you mean `{near}`?"),
            None if known.is_empty() => format!("no {kind}s are defined in this file"),
            None => format!(
                "defined {kind}s: {}",
                known
                    .keys()
                    .map(String::as_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        };
        self.push(
            Diagnostic::error(path, format!("{kind} `{name}` does not exist")).with_hint(hint),
        );
    }

    fn check_regex(&mut self, path: &str, pattern: &str) {
        if let Err(e) = RegexBuilder::new(pattern)
            .size_limit(REGEX_SIZE_LIMIT)
            .build()
        {
            let detail = e.to_string();
            let last = detail
                .lines()
                .rfind(|l| !l.trim().is_empty())
                .unwrap_or(&detail)
                .trim();
            self.error(path, format!("invalid regular expression: {last}"));
        }
    }

    fn check_starts_with_slash(&mut self, path: &str, value: &str) {
        if !value.starts_with('/') {
            self.error(path, format!("`{value}` must start with `/`"));
        }
    }

    fn check_not_zero(&mut self, path: &str, is_zero: bool) {
        if is_zero {
            self.error(path, "must be greater than zero");
        }
    }

    // -- sections ------------------------------------------------------------------------------

    fn check_version(&mut self) {
        if let Some(version) = self.config.version
            && version != 1
        {
            self.error(
                "version",
                format!("unsupported configuration version {version}; only 1 exists"),
            );
        }
    }

    fn check_listeners(&mut self) {
        let entries: Vec<(&String, &Listener)> = self.config.listeners.iter().collect();
        for (i, (name, listener)) in entries.iter().enumerate() {
            let path = path_key("listeners", name);
            self.check_name("listeners", name);
            let timeouts = &listener.timeouts;
            for (field, value) in [
                ("request_header", timeouts.request_header),
                ("read", timeouts.read),
                ("write", timeouts.write),
                ("idle", timeouts.idle),
            ] {
                self.check_not_zero(&format!("{path}.timeouts.{field}"), value.is_zero());
            }
            let protocol = listener.effective_protocol();
            if listener.tls.is_some()
                && matches!(protocol, ListenerProtocol::Http | ListenerProtocol::Udp)
            {
                self.push(
                    Diagnostic::error(
                        format!("{path}.tls"),
                        format!("`{}` listeners cannot terminate TLS", protocol_name(protocol)),
                    )
                    .with_hint("remove `protocol` (https is inferred from `tls`) or set it to `https` or `tcp`"),
                );
            }
            if listener
                .proxy_protocol
                .as_ref()
                .is_some_and(|p| p.trusted.is_empty())
            {
                self.push(
                    Diagnostic::error(
                        format!("{path}.proxy_protocol.trusted"),
                        "no trusted sources",
                    )
                    .with_hint("list the load balancers allowed to send PROXY protocol headers"),
                );
            }
            let udp = protocol == ListenerProtocol::Udp;
            for (other_name, other) in &entries[i + 1..] {
                let other_udp = other.effective_protocol() == ListenerProtocol::Udp;
                if udp == other_udp && listener.address.overlaps(&other.address) {
                    self.error(
                        format!("{path}.address"),
                        format!(
                            "`{}` overlaps listener `{other_name}` (`{}`)",
                            listener.address, other.address
                        ),
                    );
                }
            }
        }
    }

    fn check_defaults(&mut self) {
        let defaults = &self.config.defaults;
        let uses_defaults = self.config.routes.values().any(|r| r.listeners.is_none());
        if defaults.listeners.is_empty() && uses_defaults {
            self.error(
                "defaults.listeners",
                "routes without `listeners` need at least one default listener",
            );
        }
        for (i, name) in defaults.listeners.iter().enumerate() {
            self.check_http_listener(&path_index("defaults.listeners", i), name);
        }
    }

    /// The listener must exist and speak HTTP.
    fn check_http_listener(&mut self, path: &str, name: &str) {
        match self.listeners.get(name).map(Listener::effective_protocol) {
            None => {
                let near = closest_match(name, self.listeners.keys().map(String::as_str))
                    .map(|n| format!("did you mean `{n}`?"));
                let mut d = Diagnostic::error(path, format!("listener `{name}` does not exist"));
                if let Some(hint) = near {
                    d = d.with_hint(hint);
                }
                self.push(d);
            }
            Some(p @ (ListenerProtocol::Tcp | ListenerProtocol::Udp)) => self.error(
                path,
                format!(
                    "listener `{name}` is `{}`; HTTP routes need an http or https listener",
                    protocol_name(p)
                ),
            ),
            Some(_) => {}
        }
    }

    fn check_routes(&mut self) {
        for (name, route) in &self.config.routes {
            let path = path_key("routes", name);
            self.check_name("routes", name);
            for (field, value) in [
                ("connect", route.timeouts.connect),
                ("read", route.timeouts.read),
                ("write", route.timeouts.write),
            ] {
                self.check_not_zero(
                    &format!("{path}.timeouts.{field}"),
                    value.is_some_and(crate::values::Duration::is_zero),
                );
            }
            let expr = self.parse_http_match(&format!("{path}.match"), &route.matcher);
            if let Some(listeners) = &route.listeners {
                if listeners.is_empty() {
                    self.error(
                        format!("{path}.listeners"),
                        "the route is not attached to any listener",
                    );
                }
                for (i, listener) in listeners.iter().enumerate() {
                    self.check_http_listener(
                        &path_index(&format!("{path}.listeners"), i),
                        listener,
                    );
                }
            }
            self.check_reference(
                &format!("{path}.service"),
                "service",
                &route.service,
                &self.config.services,
            );
            for (i, middleware) in route.middlewares.iter().enumerate() {
                let p = path_index(&format!("{path}.middlewares"), i);
                self.check_reference(&p, "middleware", middleware, &self.config.middlewares);
            }
            self.check_route_tls(&path, route, expr.as_ref());
        }
    }

    fn parse_http_match(&mut self, path: &str, spec: &MatchSpec) -> Option<Expr> {
        let expr = match spec {
            MatchSpec::Rule(rule) => match rdock_rules::parse(rule) {
                Ok(expr) => expr,
                Err(err) => {
                    self.push(
                        Diagnostic::error(path, format!("invalid rule: {}", err.kind))
                            .with_hint(err.render(rule)),
                    );
                    return None;
                }
            },
            MatchSpec::Structured(structured) => {
                if let Some(expr) = structured.to_expr() {
                    expr
                } else {
                    self.push(Diagnostic::error(path, "the match is empty").with_hint(
                        "set at least one of hosts, path, path_prefix, path_regex, methods, headers, query or client_ips",
                    ));
                    return None;
                }
            }
        };
        for err in expr.validate(Context::Http) {
            self.error(path, err.to_string());
        }
        Some(expr)
    }

    fn check_route_tls(&mut self, path: &str, route: &Route, expr: Option<&Expr>) {
        let tls_path = format!("{path}.tls");
        let options = match &route.tls {
            Some(RouteTls::Options(options)) => Some(options),
            _ => None,
        };
        if let Some(options) = options {
            if let Some(provider) = &options.dns_provider {
                let defined = self
                    .config
                    .acme
                    .as_ref()
                    .is_some_and(|a| a.dns_providers.contains_key(provider));
                if !defined {
                    self.push(
                        Diagnostic::error(
                            format!("{tls_path}.dns_provider"),
                            format!("DNS provider `{provider}` is not defined"),
                        )
                        .with_hint("add it under `acme.dns_providers`"),
                    );
                }
            }
            if let Some(certificate) = &options.certificate {
                let p = format!("{tls_path}.certificate");
                self.check_reference(&p, "certificate", certificate, &self.config.certificates);
                if options.dns_provider.is_some() {
                    self.error(
                        &tls_path,
                        "`certificate` and `dns_provider` cannot be combined",
                    );
                }
            }
            for (i, domain) in options.domains.iter().enumerate() {
                if let Err(message) = check_host(domain) {
                    self.error(path_index(&format!("{tls_path}.domains"), i), message);
                }
            }
        }
        let auto = match &route.tls {
            None => self.config.defaults.tls == TlsMode::Auto,
            Some(RouteTls::Mode(mode)) => *mode == TlsMode::Auto,
            Some(RouteTls::Options(o)) => o.auto && o.certificate.is_none(),
        };
        let listeners = route
            .listeners
            .as_ref()
            .unwrap_or(&self.config.defaults.listeners);
        let serves_tls = listeners.iter().any(|l| {
            self.listeners
                .get(l)
                .is_some_and(|l| l.effective_protocol() == ListenerProtocol::Https)
        });
        let Some(expr) = expr else { return };
        if !auto || !serves_tls {
            return;
        }
        let domains: Vec<&str> = options
            .map(|o| o.domains.iter().map(String::as_str).collect())
            .unwrap_or_default();
        let hosts = if domains.is_empty() {
            expr.positive_hosts()
        } else {
            domains
        };
        if hosts.is_empty() {
            self.push(
                Diagnostic::warning(&tls_path, "automatic HTTPS needs a host name, but the route has no Host(`…`) and no tls.domains")
                    .with_hint("add Host(`app.example.com`) to the match, list names in tls.domains, or set `tls: off`"),
            );
        }
        let has_dns = options.is_some_and(|o| o.dns_provider.is_some());
        if let Some(wildcard) = hosts.iter().find(|h| h.starts_with("*."))
            && !has_dns
        {
            self.push(
                Diagnostic::error(
                    &tls_path,
                    format!("the wildcard `{wildcard}` needs a DNS-01 certificate"),
                )
                .with_hint(
                    "set `tls: { dns_provider: <name> }` with a provider from acme.dns_providers",
                ),
            );
        }
        if hosts.contains(&"*") {
            self.warning(
                &tls_path,
                "Host(`*`) cannot get a certificate; these requests use the default certificate",
            );
        }
    }

    fn check_services(&mut self) {
        for (name, service) in &self.config.services {
            let path = path_key("services", name);
            self.check_name("services", name);
            self.check_service_targets(&path, name, service);
            self.check_service_policies(&path, service);
        }
        self.check_split_cycles();
    }

    fn check_service_targets(&mut self, path: &str, name: &str, service: &Service) {
        match (service.backends.is_empty(), service.split.is_empty()) {
            (true, true) => self.push(
                Diagnostic::error(path, "the service has no backends")
                    .with_hint("add `backends: [{ address: \"app:3000\" }]` or a weighted `split`"),
            ),
            (false, false) => self.error(path, "set either `backends` or `split`, not both"),
            _ => {}
        }
        for (i, backend) in service.backends.iter().enumerate() {
            if backend.weight == 0 {
                self.error(
                    format!("{}.weight", path_index(&format!("{path}.backends"), i)),
                    "weight must be at least 1",
                );
            }
        }
        for (i, target) in service.split.iter().enumerate() {
            let p = path_index(&format!("{path}.split"), i);
            if target.service == name {
                self.error(
                    format!("{p}.service"),
                    "a service cannot split traffic to itself",
                );
            } else {
                self.check_reference(
                    &format!("{p}.service"),
                    "service",
                    &target.service,
                    &self.config.services,
                );
            }
            if target.weight == 0 {
                self.error(format!("{p}.weight"), "weight must be at least 1");
            }
        }
    }

    fn check_service_policies(&mut self, path: &str, service: &Service) {
        let lb = &service.load_balancer;
        match (lb.policy, &lb.hash_on) {
            (LbPolicy::HeaderHash | LbPolicy::CookieHash, None) => {
                self.error(
                    format!("{path}.load_balancer.hash_on"),
                    "this policy needs `hash_on` (a header or cookie name)",
                );
            }
            (LbPolicy::HeaderHash | LbPolicy::CookieHash, Some(name)) if !is_token(name) => {
                self.error(
                    format!("{path}.load_balancer.hash_on"),
                    format!("`{name}` is not a valid header or cookie name"),
                );
            }
            (LbPolicy::HeaderHash | LbPolicy::CookieHash, Some(_)) | (_, None) => {}
            (_, Some(_)) => self.warning(
                format!("{path}.load_balancer.hash_on"),
                "`hash_on` is only used by header_hash and cookie_hash",
            ),
        }
        self.check_service_health(path, service);
        self.check_service_retries(path, service);
        let t = &service.timeouts;
        for (field, zero) in [
            ("connect", t.connect.is_zero()),
            ("read", t.read.is_zero()),
            ("write", t.write.is_zero()),
            ("idle", t.idle.is_zero()),
        ] {
            self.check_not_zero(&format!("{path}.timeouts.{field}"), zero);
        }
        self.check_service_tls(path, service);
    }

    fn check_service_health(&mut self, path: &str, service: &Service) {
        if let Some(health) = &service.health {
            if let Some(active) = &health.active {
                let p = format!("{path}.health.active");
                self.check_starts_with_slash(&format!("{p}.path"), &active.path);
                self.check_not_zero(&format!("{p}.interval"), active.interval.is_zero());
                self.check_not_zero(&format!("{p}.timeout"), active.timeout.is_zero());
                self.check_not_zero(&format!("{p}.healthy"), active.healthy == 0);
                self.check_not_zero(&format!("{p}.unhealthy"), active.unhealthy == 0);
                if active.timeout >= active.interval && !active.interval.is_zero() {
                    self.warning(
                        format!("{p}.timeout"),
                        "the probe timeout is not shorter than the interval",
                    );
                }
                if status_range(&active.expected_status).is_none() {
                    self.error(
                        format!("{p}.expected_status"),
                        format!(
                            "`{}` is not a status code or range like `200-399`",
                            active.expected_status
                        ),
                    );
                }
                if active.port == Some(0) {
                    self.error(format!("{p}.port"), "port must be between 1 and 65535");
                }
            }
            if let Some(passive) = &health.passive {
                let p = format!("{path}.health.passive");
                self.check_not_zero(&format!("{p}.failures"), passive.failures == 0);
                self.check_not_zero(&format!("{p}.window"), passive.window.is_zero());
                self.check_not_zero(&format!("{p}.ejection"), passive.ejection.is_zero());
            }
        }
    }

    fn check_service_retries(&mut self, path: &str, service: &Service) {
        if let Some(retries) = &service.retries {
            let p = format!("{path}.retries");
            if retries.attempts == 0 {
                self.warning(
                    format!("{p}.attempts"),
                    "attempts is 0, so retries are disabled",
                );
            }
            if retries.attempts > MAX_RETRY_ATTEMPTS {
                self.error(
                    format!("{p}.attempts"),
                    format!("at most {MAX_RETRY_ATTEMPTS} attempts are allowed"),
                );
            }
            if retries.budget_percent > 100 {
                self.error(format!("{p}.budget_percent"), "must be between 0 and 100");
            }
            if retries.on.is_empty() {
                self.error(
                    format!("{p}.on"),
                    "list at least one of connect, reset, timeout",
                );
            }
            if retries.retry_non_idempotent {
                self.warning(format!("{p}.retry_non_idempotent"), "retrying POST or PATCH can repeat side effects; enable only for idempotent backends");
            }
        }
    }

    fn check_service_tls(&mut self, path: &str, service: &Service) {
        if let Some(tls) = &service.tls {
            let p = format!("{path}.tls");
            if service.scheme != Scheme::Https {
                self.warning(&p, "TLS settings are only used with `scheme: https`");
            }
            if !tls.verify {
                self.warning(
                    format!("{p}.verify"),
                    "backend certificates are not verified; traffic can be intercepted",
                );
            }
            if tls.cert_file.is_some() != tls.key_file.is_some() {
                self.error(&p, "set both `cert_file` and `key_file` for upstream mTLS");
            }
        }
        if let Some(sticky) = &service.sticky {
            let p = format!("{path}.sticky.cookie");
            if !is_token(&sticky.cookie.name) {
                self.error(
                    format!("{p}.name"),
                    format!("`{}` is not a valid cookie name", sticky.cookie.name),
                );
            }
            if sticky.cookie.same_site == SameSite::None && !sticky.cookie.secure {
                self.error(
                    format!("{p}.same_site"),
                    "SameSite=None requires `secure: true`",
                );
            }
        }
    }

    /// Reports chains of `split` services that lead back to themselves, once per cycle, with an
    /// iterative depth-first search over services defined in this file.
    fn check_split_cycles(&mut self) {
        let services = &self.config.services;
        let edges: BTreeMap<&str, Vec<&str>> = services
            .iter()
            .map(|(name, service)| {
                let targets = service
                    .split
                    .iter()
                    .filter_map(|target| local_name(&target.service))
                    .filter(|target| services.contains_key(*target))
                    .collect();
                (name.as_str(), targets)
            })
            .collect();
        let mut done: BTreeSet<&str> = BTreeSet::new();
        let mut cycles: Vec<Vec<&str>> = Vec::new();
        for &root in edges.keys() {
            if done.contains(root) {
                continue;
            }
            // Each entry is a service on the current path and the index of its next edge.
            let mut path: Vec<(&str, usize)> = vec![(root, 0)];
            while let Some(&(node, next_edge)) = path.last() {
                let Some(&target) = edges.get(node).and_then(|targets| targets.get(next_edge))
                else {
                    done.insert(node);
                    path.pop();
                    continue;
                };
                if let Some(last) = path.last_mut() {
                    last.1 += 1;
                }
                if let Some(start) = path.iter().position(|(name, _)| *name == target) {
                    let mut cycle: Vec<&str> =
                        path[start..].iter().map(|(name, _)| *name).collect();
                    cycle.push(target);
                    cycles.push(cycle);
                } else if !done.contains(target) {
                    path.push((target, 0));
                }
            }
        }
        for cycle in cycles {
            self.error(
                format!("{}.split", path_key("services", cycle[0])),
                format!("split services form a cycle: {}", cycle.join(" → ")),
            );
        }
    }

    fn check_header_rules(&mut self, path: &str, rules: &HeaderRules) {
        let names = rules
            .set
            .iter()
            .chain(&rules.add)
            .map(|(k, v)| (k, Some(v)))
            .chain(rules.remove.iter().map(|k| (k, None)));
        for (name, value) in names {
            if !is_token(name) {
                self.error(path, format!("`{name}` is not a valid header name"));
            }
            if value.is_some_and(|v| v.contains(['\r', '\n'])) {
                self.error(path, format!("the value of `{name}` contains a line break"));
            }
        }
    }

    fn check_middlewares(&mut self) {
        for (name, middleware) in &self.config.middlewares {
            let path = path_key("middlewares", name);
            self.check_name("middlewares", name);
            match middleware {
                Middleware::Headers(h) => {
                    self.check_header_rules(&format!("{path}.request"), &h.request);
                    self.check_header_rules(&format!("{path}.response"), &h.response);
                }
                Middleware::Redirect(r) => self.check_redirect(&path, r),
                Middleware::Rewrite(r) => self.check_regex(&format!("{path}.regex"), &r.regex),
                Middleware::StripPrefix(s) => self.check_strip_prefix(&path, s),
                Middleware::AddPrefix(a) => {
                    self.check_starts_with_slash(&format!("{path}.prefix"), &a.prefix);
                }
                Middleware::ReplacePath(r) => {
                    self.check_starts_with_slash(&format!("{path}.path"), &r.path);
                }
                Middleware::BasicAuth(b) => self.check_basic_auth(&path, b),
                Middleware::ForwardAuth(f) => self.check_forward_auth(&path, f),
                Middleware::IpAllow(list) | Middleware::IpDeny(list) => {
                    if list.cidrs.is_empty() {
                        self.error(
                            format!("{path}.cidrs"),
                            "list at least one IP address or range",
                        );
                    }
                }
                Middleware::RateLimit(r) => self.check_rate_limit(&path, r),
                Middleware::Cors(c) => self.check_cors(&path, c),
                Middleware::Compress(c) => {
                    if c.algorithms.is_empty() {
                        self.error(format!("{path}.algorithms"), "list at least one algorithm");
                    }
                }
                Middleware::Errors(e) => self.check_error_pages(&path, e),
                Middleware::Maintenance(m) => {
                    if !(400..=599).contains(&m.status) {
                        self.error(
                            format!("{path}.status"),
                            "use a 4xx or 5xx status, usually 503",
                        );
                    }
                }
            }
        }
    }

    fn check_redirect(&mut self, path: &str, redirect: &RedirectConfig) {
        match (&redirect.scheme, &redirect.regex, &redirect.replacement) {
            (Some(_), None, None) => {}
            (None, Some(regex), Some(_)) => self.check_regex(&format!("{path}.regex"), regex),
            _ => self.error(path, "set `scheme`, or `regex` together with `replacement`"),
        }
        if redirect.port == Some(0) {
            self.error(format!("{path}.port"), "port must be between 1 and 65535");
        }
    }

    fn check_strip_prefix(&mut self, path: &str, strip: &StripPrefixConfig) {
        if strip.prefixes.is_empty() {
            self.error(format!("{path}.prefixes"), "list at least one prefix");
        }
        for (i, prefix) in strip.prefixes.iter().enumerate() {
            self.check_starts_with_slash(&path_index(&format!("{path}.prefixes"), i), prefix);
        }
    }

    /// Hashes only: a plain-text password is reported by user name, never echoed.
    fn check_basic_auth(&mut self, path: &str, auth: &BasicAuthConfig) {
        if auth.users.is_empty() && auth.users_file.is_none() {
            self.error(path, "add `users` or `users_file`");
        }
        for (i, entry) in auth.users.iter().enumerate() {
            let entry_path = path_index(&format!("{path}.users"), i);
            match entry.split_once(':') {
                Some((user, hash)) if !user.is_empty() => match hash_strength(hash) {
                    Some(HashStrength::Strong) => {}
                    Some(HashStrength::Weak) => self.push(
                        Diagnostic::warning(&entry_path, format!("the password of `{user}` uses a weak hash"))
                            .with_hint("MD5 and SHA-1 hashes are fast to brute-force; create a bcrypt hash with `htpasswd -nbB user password`"),
                    ),
                    None => self.push(
                        Diagnostic::error(&entry_path, format!("the password of `{user}` is not an argon2id, bcrypt, MD5 or SHA-1 hash"))
                            .with_hint("plain-text passwords are never accepted; create a hash with `htpasswd -nbB user password`"),
                    ),
                },
                _ => self.error(entry_path, "expected `user:hash`"),
            }
        }
    }

    fn check_forward_auth(&mut self, path: &str, auth: &ForwardAuthConfig) {
        for (field, headers) in [
            ("copy_headers", &auth.copy_headers),
            ("request_headers", &auth.request_headers),
        ] {
            for (i, header) in headers.iter().enumerate() {
                if !is_token(header) {
                    self.error(
                        path_index(&format!("{path}.{field}"), i),
                        format!("`{header}` is not a valid header name"),
                    );
                }
            }
        }
        self.check_not_zero(&format!("{path}.timeout"), auth.timeout.is_zero());
    }

    fn check_rate_limit(&mut self, path: &str, limit: &RateLimitConfig) {
        self.check_not_zero(&format!("{path}.average"), limit.average == 0);
        self.check_not_zero(&format!("{path}.burst"), limit.burst == Some(0));
        self.check_not_zero(&format!("{path}.period"), limit.period.is_zero());
    }

    fn check_error_pages(&mut self, path: &str, errors: &ErrorsConfig) {
        for (i, status) in errors.status.iter().enumerate() {
            if status_range(status).is_none() {
                self.error(
                    path_index(&format!("{path}.status"), i),
                    format!("`{status}` is not a status code or range like `500-599`"),
                );
            }
        }
        match (&errors.file, &errors.service) {
            (Some(_), None) => {
                if errors.path.is_some() {
                    self.warning(format!("{path}.path"), "`path` is only used with `service`");
                }
            }
            (None, Some(service)) => {
                self.check_reference(
                    &format!("{path}.service"),
                    "service",
                    service,
                    &self.config.services,
                );
            }
            _ => self.error(path, "set either `file` or `service`"),
        }
    }

    fn check_cors(&mut self, path: &str, cors: &CorsConfig) {
        if cors.allowed_origins.is_empty() {
            self.error(
                format!("{path}.allowed_origins"),
                "list at least one origin, or `*`",
            );
        }
        for (i, origin) in cors.allowed_origins.iter().enumerate() {
            let valid = origin == "*"
                || url::Url::parse(origin).is_ok_and(|u| {
                    matches!(u.scheme(), "http" | "https")
                        && u.has_host()
                        && u.path() == "/"
                        && u.query().is_none()
                        && u.fragment().is_none()
                        && !origin.ends_with('/')
                });
            if !valid {
                self.error(
                    path_index(&format!("{path}.allowed_origins"), i),
                    format!("`{origin}` is not an origin like `https://app.example.com`"),
                );
            }
        }
        if cors.allow_credentials && cors.allowed_origins.iter().any(|o| o == "*") {
            self.error(
                format!("{path}.allow_credentials"),
                "browsers reject credentials with the `*` origin; list the origins",
            );
        }
        for (field, values) in [
            ("allowed_methods", &cors.allowed_methods),
            ("allowed_headers", &cors.allowed_headers),
            ("exposed_headers", &cors.exposed_headers),
        ] {
            for (i, value) in values.iter().enumerate() {
                if !is_token(value) {
                    self.error(
                        path_index(&format!("{path}.{field}"), i),
                        format!("`{value}` is not a valid token"),
                    );
                }
            }
        }
    }

    fn check_tcp(&mut self) {
        for (name, route) in &self.config.tcp_routes {
            let path = path_key("tcp_routes", name);
            self.check_name("tcp_routes", name);
            match rdock_rules::parse(&route.matcher) {
                Ok(expr) => {
                    for err in expr.validate(Context::Tcp) {
                        self.error(format!("{path}.match"), err.to_string());
                    }
                }
                Err(err) => self.push(
                    Diagnostic::error(
                        format!("{path}.match"),
                        format!("invalid rule: {}", err.kind),
                    )
                    .with_hint(err.render(&route.matcher)),
                ),
            }
            match &route.listeners {
                None => self.push(
                    Diagnostic::error(format!("{path}.listeners"), "TCP routes need `listeners`")
                        .with_hint("name a `tcp` listener, or an `https` listener for SNI routing"),
                ),
                Some(listeners) => {
                    for (i, listener) in listeners.iter().enumerate() {
                        let p = path_index(&format!("{path}.listeners"), i);
                        match self.listeners.get(listener).map(Listener::effective_protocol) {
                            None => self.error(p, format!("listener `{listener}` does not exist")),
                            Some(ListenerProtocol::Tcp | ListenerProtocol::Https) => {}
                            Some(other) => self.error(p, format!("listener `{listener}` is `{}`; TCP routes need a tcp or https listener", protocol_name(other))),
                        }
                    }
                }
            }
            self.check_reference(
                &format!("{path}.service"),
                "TCP service",
                &route.service,
                &self.config.tcp_services,
            );
        }
        for (name, service) in &self.config.tcp_services {
            let path = path_key("tcp_services", name);
            self.check_name("tcp_services", name);
            if service.backends.is_empty() {
                self.error(format!("{path}.backends"), "the service has no backends");
            }
            for (i, backend) in service.backends.iter().enumerate() {
                if backend.weight == 0 {
                    self.error(
                        format!("{}.weight", path_index(&format!("{path}.backends"), i)),
                        "weight must be at least 1",
                    );
                }
            }
        }
    }

    fn check_certificates(&mut self) {
        for (name, certificate) in &self.config.certificates {
            let path = path_key("certificates", name);
            self.check_name("certificates", name);
            if certificate.cert_file.as_os_str().is_empty() {
                self.error(format!("{path}.cert_file"), "path is empty");
            }
            if certificate.key_file.as_os_str().is_empty() {
                self.error(format!("{path}.key_file"), "path is empty");
            }
            if let Some(password) = &certificate.key_password {
                self.check_secret(&format!("{path}.key_password"), password, "key_password");
            }
        }
        if let Some(default) = &self.config.defaults.certificate {
            self.check_reference(
                "defaults.certificate",
                "certificate",
                default,
                &self.config.certificates,
            );
        }
    }

    fn check_acme(&mut self) {
        let Some(acme) = &self.config.acme else {
            return;
        };
        if let Some(email) = &acme.email
            && (!email.contains('@') || email.contains(char::is_whitespace))
        {
            self.error("acme.email", format!("`{email}` is not an email address"));
        }
        if acme.challenges.is_empty() {
            self.error("acme.challenges", "list at least one challenge type");
        }
        let unique: HashSet<_> = acme.challenges.iter().collect();
        if unique.len() != acme.challenges.len() {
            self.warning("acme.challenges", "a challenge type is listed twice");
        }
        if acme.challenges.contains(&Challenge::Dns01) && acme.dns_providers.is_empty() {
            self.error(
                "acme.dns_providers",
                "dns-01 is enabled but no DNS provider is defined",
            );
        }
        for (name, provider) in &acme.dns_providers {
            let path = path_key("acme.dns_providers", name);
            self.check_name("acme.dns_providers", name);
            match provider {
                DnsProvider::Cloudflare { api_token } => {
                    self.check_secret(&format!("{path}.api_token"), api_token, "cf_token");
                }
            }
        }
        if let Some(eab) = &acme.eab {
            if eab.key_id.is_empty() {
                self.error("acme.eab.key_id", "key_id is empty");
            }
            self.check_secret("acme.eab.hmac_key", &eab.hmac_key, "eab_hmac");
        }
        if matches!(
            acme.ca,
            crate::acme::CaRef::Known(KnownCa::Zerossl | KnownCa::Google)
        ) && acme.eab.is_none()
        {
            self.push(
                Diagnostic::error(
                    "acme.eab",
                    "this certificate authority requires external account binding",
                )
                .with_hint("add `eab: { key_id, hmac_key }` from the CA's dashboard"),
            );
        }
    }

    /// Secrets must be present and should be references, not literals.
    fn check_secret(&mut self, path: &str, value: &str, file_name: &str) {
        if value.is_empty() {
            self.error(path, "the secret is empty");
        } else if !value.starts_with("${") {
            self.push(
                Diagnostic::warning(path, "a secret is written in the configuration file")
                    .with_hint(format!("store it as a file and reference it: \"${{file:/run/secrets/{file_name}}}\"")),
            );
        }
    }

    fn check_security(&mut self) {
        let security = &self.config.security;
        let unique: HashSet<_> = security.trusted_proxies.iter().collect();
        if unique.len() != security.trusted_proxies.len() {
            self.warning("security.trusted_proxies", "an entry is listed twice");
        }
        let trusts_cloudflare = security.trusted_proxies.contains(&TrustedProxy::Cloudflare);
        match security.client_ip_header {
            ClientIpHeader::CfConnectingIp if !trusts_cloudflare => self.push(
                Diagnostic::error(
                    "security.client_ip_header",
                    "`cf-connecting-ip` needs `cloudflare` in trusted_proxies",
                )
                .with_hint("otherwise any client could choose its own IP by sending the header"),
            ),
            ClientIpHeader::XForwardedFor | ClientIpHeader::XRealIp
                if security.trusted_proxies.is_empty() =>
            {
                self.warning(
                    "security.client_ip_header",
                    "no trusted proxies are configured, so forwarded headers are ignored",
                );
            }
            _ => {}
        }
        let limits = &security.limits;
        for (field, size) in [
            ("max_header_bytes", Some(limits.max_header_bytes)),
            ("max_body_bytes", limits.max_body_bytes),
            ("max_uri_bytes", Some(limits.max_uri_bytes)),
        ] {
            self.check_not_zero(
                &format!("security.limits.{field}"),
                size.is_some_and(|s| s.as_u64() == 0),
            );
        }
        self.check_not_zero("security.limits.max_headers", limits.max_headers == 0);
    }

    fn check_admin(&mut self) {
        let admin = &self.config.admin;
        if !admin.enabled {
            return;
        }
        let overlaps: Vec<String> = self
            .listeners
            .iter()
            .filter(|(_, l)| {
                l.effective_protocol() != ListenerProtocol::Udp
                    && l.address.overlaps(&admin.listener)
            })
            .map(|(name, _)| name.clone())
            .collect();
        for name in overlaps {
            self.error(
                "admin.listener",
                format!("`{}` overlaps listener `{name}`", admin.listener),
            );
        }
        if !admin.listener.is_loopback() {
            self.push(
                Diagnostic::warning("admin.listener", format!("the admin API is reachable from the network on `{}`", admin.listener))
                    .with_hint("keep it on 127.0.0.1, or expose it only through a route with authentication (ADR-0007)"),
            );
        }
    }

    fn check_observability(&mut self) {
        let observability = &self.config.observability;
        if let Some(tracing) = &observability.tracing
            && !(0.0..=1.0).contains(&tracing.sample_ratio)
        {
            self.error(
                "observability.tracing.sample_ratio",
                "must be between 0 and 1",
            );
        }
        for (i, header) in observability.access_log.redact.iter().enumerate() {
            if !is_token(header) {
                self.error(
                    path_index("observability.access_log.redact", i),
                    format!("`{header}` is not a valid header name"),
                );
            }
        }
    }

    fn check_providers(&mut self) {
        let providers = &self.config.providers;
        if let Some(file) = &providers.file {
            if file.paths.is_empty() {
                self.error(
                    "providers.file.paths",
                    "list at least one file or glob pattern",
                );
            }
            for (i, path) in file.paths.iter().enumerate() {
                if path.trim().is_empty() {
                    self.error(path_index("providers.file.paths", i), "path is empty");
                }
            }
        }
        let network_ok = |n: &String| {
            !n.is_empty()
                && n.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        };
        if let Some(docker) = &providers.docker {
            if docker.network.as_ref().is_some_and(|n| !network_ok(n)) {
                self.error("providers.docker.network", "invalid Docker network name");
            }
            for (entrypoint, listener) in &docker.entrypoints {
                if !self.listeners.contains_key(listener) {
                    self.error(
                        path_key("providers.docker.entrypoints", entrypoint),
                        format!("listener `{listener}` does not exist"),
                    );
                }
            }
        }
        if let Some(swarm) = &providers.swarm
            && swarm.network.as_ref().is_some_and(|n| !network_ok(n))
        {
            self.error("providers.swarm.network", "invalid Docker network name");
        }
        if let Some(kubernetes) = &providers.kubernetes {
            let class = &kubernetes.gateway_class;
            let valid = !class.is_empty()
                && class.len() <= 253
                && class.chars().all(|c| {
                    c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '.')
                });
            if !valid {
                self.error(
                    "providers.kubernetes.gateway_class",
                    "must be a lowercase DNS subdomain name",
                );
            }
        }
    }
}

#[cfg(test)]
mod tests;
