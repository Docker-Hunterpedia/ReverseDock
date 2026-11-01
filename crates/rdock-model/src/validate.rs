//! Semantic validation: references, rules, listeners and risky settings.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::net::IpAddr;

use rdock_rules::{Context, Expr, check_host};
use regex::RegexBuilder;

use crate::acme::{AcmeProfile, Challenge, DnsProvider, KnownCa, Webhook};
use crate::config::{Config, Listener, ListenerProtocol};
use crate::diagnostics::{Diagnostic, path_index, path_key};
use crate::middleware::{
    BasicAuthConfig, CorsConfig, ErrorsConfig, ForwardAuthConfig, HeaderRules, Middleware,
    RateLimitConfig, RedirectConfig, StripPrefixConfig,
};
use crate::route::{MatchSpec, Route, RouteTls, TlsMode};
use crate::service::{HealthMode, LbPolicy, SameSite, Scheme, Service};
use crate::settings::ClientIpHeader;
use crate::values::is_token;
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
        self.validate_as(false)
    }

    /// Validates a configuration that already holds other providers' objects under
    /// `name@provider` keys (ADR-0018): those keys are accepted, and references to them must
    /// exist like references to this file's objects.
    #[must_use]
    pub fn validate_merged(&self) -> Vec<Diagnostic> {
        self.validate_as(true)
    }

    fn validate_as(&self, merged: bool) -> Vec<Diagnostic> {
        let mut v = Validator {
            config: self,
            listeners: self.effective_listeners().into_owned(),
            merged,
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

/// The key a reference names: `name@file` is the file's `name`; other references are keys as
/// written (`name`, or `name@docker` in a merged configuration).
fn reference_key(reference: &str) -> &str {
    reference.strip_suffix("@file").unwrap_or(reference)
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
#[must_use]
pub fn status_range(value: &str) -> Option<(u16, u16)> {
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
    /// Other providers' objects are present as `name@provider` keys.
    merged: bool,
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

    fn check_name(&mut self, section: &str, key: &str) {
        let name = match key.split_once('@') {
            Some((name, provider))
                if self.merged && provider != "file" && PROVIDERS.contains(&provider) =>
            {
                name
            }
            _ => key,
        };
        let valid = !name.is_empty()
            && name.len() <= MAX_NAME_LEN
            && name.starts_with(|c: char| c.is_ascii_alphanumeric())
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
        if !valid {
            self.push(
                Diagnostic::error(path_key(section, key), format!("invalid name `{name}`")).with_hint(
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
        let other_provider = provider.is_some_and(|p| p != "file");
        if other_provider && !self.merged {
            return;
        }
        if known.contains_key(reference_key(reference)) {
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
            if let Some(ping) = &listener.ping {
                self.check_starts_with_slash(&format!("{path}.ping"), ping);
            }
            if let Some(auth) = listener.tls.as_ref().and_then(|t| t.client_auth.as_ref())
                && auth.ca_files.is_empty()
                && !auth.cloudflare
            {
                self.error(
                    format!("{path}.tls.client_auth"),
                    "list `ca_files` or set `cloudflare: true`: certificates are always verified",
                );
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
            if let Some(mirror) = &route.mirror {
                let p = format!("{path}.mirror");
                self.check_reference(
                    &format!("{p}.service"),
                    "service",
                    &mirror.service,
                    &self.config.services,
                );
                if !(1..=100).contains(&mirror.percent) {
                    self.error(format!("{p}.percent"), "must be between 1 and 100");
                }
                if mirror.service == route.service {
                    self.warning(
                        format!("{p}.service"),
                        "the mirror is the route's own service, so it gets every request twice",
                    );
                }
            }
            let grpc_web = route
                .middlewares
                .iter()
                .any(|m| matches!(self.config.middlewares.get(m), Some(Middleware::GrpcWeb(_))));
            if grpc_web
                && self
                    .config
                    .services
                    .get(&route.service)
                    .is_some_and(|s| s.scheme == Scheme::Http && s.split.is_empty())
            {
                self.error(
                    format!("{path}.middlewares"),
                    "gRPC-Web is translated to gRPC, which needs HTTP/2: set the service `scheme` to `h2c` or `https`",
                );
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
                    .effective_acme()
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
        let listeners = self.config.route_listeners(route);
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
        // With `defaults.certificate`, a route without host names is served that certificate.
        if hosts.is_empty() && self.config.defaults.certificate.is_none() {
            self.push(
                Diagnostic::warning(&tls_path, "automatic HTTPS needs a host name, but the route has no Host(`…`) and no tls.domains")
                    .with_hint("add Host(`app.example.com`) to the match, list names in tls.domains, or set `tls: off`"),
            );
        }
        let acme = self.config.effective_acme();
        let has_dns = options.is_some_and(|o| o.dns_provider.is_some())
            || acme.as_ref().is_some_and(|a| a.dns_provider.is_some());
        if let Some(acme) = &acme {
            self.check_ip_hosts(&tls_path, &hosts, acme.profile, has_dns);
        }
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
                if passive.max_ejection_percent > 100 {
                    self.error(
                        format!("{p}.max_ejection_percent"),
                        "a percentage is at most 100",
                    );
                }
                for (i, status) in passive.statuses.iter().enumerate() {
                    if !(500..=599).contains(status) {
                        self.error(
                            path_index(&format!("{p}.statuses"), i),
                            "only 5xx answers count as backend failures",
                        );
                    }
                }
            }
            if let Some(active) = &health.active {
                let p = format!("{path}.health.active");
                if active.mode == HealthMode::Grpc && service.scheme == Scheme::Http {
                    self.error(
                        format!("{p}.mode"),
                        "gRPC health checks need HTTP/2: set the service `scheme` to `h2c` or `https`",
                    );
                }
                if active.mode != HealthMode::Http
                    && (active.expected_body.is_some() || !active.headers.is_empty())
                {
                    self.warning(
                        format!("{p}.mode"),
                        "`expected_body` and `headers` are only used by HTTP checks",
                    );
                }
            }
        }
        if !service.backends.is_empty() && service.backends.iter().all(|b| b.backup) {
            self.error(
                format!("{path}.backends"),
                "every backend is a backup; at least one must be a primary",
            );
        }
        if service.max_requests == Some(0) {
            self.error(format!("{path}.max_requests"), "must be at least 1");
        }
        if service.max_connections_per_backend == Some(0) {
            self.error(
                format!("{path}.max_connections_per_backend"),
                "must be at least 1",
            );
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
                    "list at least one of connect, reset, timeout, 502, 503, 504",
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
            if !sticky.cookie.path.starts_with('/') {
                self.error(format!("{p}.path"), "the path must start with `/`");
            }
            if let Some(secret) = &sticky.cookie.secret {
                self.check_secret(&format!("{p}.secret"), secret, "sticky_key");
            }
            for (i, secret) in sticky.cookie.previous_secrets.iter().enumerate() {
                self.check_secret(
                    &path_index(&format!("{p}.previous_secrets"), i),
                    secret,
                    "sticky_key_old",
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
                    .map(|target| reference_key(&target.service))
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
                Middleware::GrpcWeb(_) => {}
                Middleware::Jwt(j) => self.check_jwt(&path, j),
                Middleware::ClientCert(c) => {
                    for (i, pattern) in c.allow.iter().enumerate() {
                        if pattern.trim().is_empty() {
                            self.error(
                                path_index(&format!("{path}.allow"), i),
                                "a pattern is empty",
                            );
                        }
                    }
                    if !c.required && !c.allow.is_empty() {
                        self.warning(
                            format!("{path}.allow"),
                            "`allow` is checked only when a certificate is sent, because `required` is false",
                        );
                    }
                }
                Middleware::InFlight(f) => {
                    if f.amount == 0 {
                        self.error(format!("{path}.amount"), "must be at least 1");
                    }
                    if f.queue > 0 && f.queue_timeout.is_zero() {
                        self.error(
                            format!("{path}.queue_timeout"),
                            "a queue needs a timeout above zero",
                        );
                    }
                }
                Middleware::Bandwidth(b) => {
                    if b.rate.as_u64() == 0 {
                        self.error(format!("{path}.rate"), "must be above zero");
                    }
                }
            }
        }
    }

    fn check_jwt(&mut self, path: &str, jwt: &crate::middleware::JwtConfig) {
        let hmac = jwt.algorithms.iter().any(|a| a.is_hmac());
        let public = jwt.algorithms.iter().any(|a| !a.is_hmac());
        if jwt.algorithms.is_empty() {
            self.error(format!("{path}.algorithms"), "list at least one algorithm");
        }
        if public && jwt.jwks_url.is_none() && jwt.jwks_file.is_none() {
            self.error(
                format!("{path}.jwks_url"),
                "public-key algorithms need `jwks_url` or `jwks_file`",
            );
        }
        if hmac && jwt.hmac_secret.is_none() {
            self.error(
                format!("{path}.hmac_secret"),
                "HS256/HS384/HS512 need `hmac_secret`",
            );
        }
        if !hmac && jwt.hmac_secret.is_some() {
            self.warning(
                format!("{path}.hmac_secret"),
                "`hmac_secret` is unused: no HS algorithm is listed in `algorithms`",
            );
        }
        if let Some(secret) = &jwt.hmac_secret {
            self.check_secret(&format!("{path}.hmac_secret"), secret, "jwt_secret");
        }
        if jwt.issuer.trim().is_empty() {
            self.error(
                format!("{path}.issuer"),
                "set the expected issuer, or `any`",
            );
        } else if jwt.issuer == "any" {
            self.warning(
                format!("{path}.issuer"),
                "tokens from any issuer are accepted (RFC 8725 §3.8 advises checking it)",
            );
        }
        if jwt.audiences.is_empty() {
            self.error(
                format!("{path}.audiences"),
                "list the accepted audiences, or `[any]`",
            );
        } else if jwt.audiences.iter().any(|a| a == "any") {
            self.warning(
                format!("{path}.audiences"),
                "tokens for any audience are accepted (RFC 8725 §3.9 advises checking it)",
            );
        }
        if let Some(url) = &jwt.jwks_url
            && url.as_url().scheme() != "https"
            && !url.as_url().host_str().is_some_and(|h| {
                h == "localhost"
                    || h.parse::<std::net::IpAddr>()
                        .is_ok_and(|ip| ip.is_loopback())
            })
        {
            self.error(
                format!("{path}.jwks_url"),
                "keys must be fetched over https",
            );
        }
        for (claim, header) in &jwt.claims_to_headers {
            if !is_token(header) {
                self.error(
                    format!("{path}.claims_to_headers.{claim}"),
                    format!("`{header}` is not a header name"),
                );
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
                            .with_hint("MD5 and SHA-1 hashes are fast to brute-force; create an argon2id entry with `rdock hash --user <name>`"),
                    ),
                    None => self.push(
                        Diagnostic::error(&entry_path, format!("the password of `{user}` is not an argon2id, bcrypt, MD5 or SHA-1 hash"))
                            .with_hint("plain-text passwords are never accepted; create one with `rdock hash --user <name>`"),
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
        let config = self.config;
        if let Some(webhook) = &config.observability.alerts.webhook {
            self.check_webhook("observability.alerts.webhook", webhook, "alert_token");
        }
        let Some(acme) = config.effective_acme() else {
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
        if let Some(name) = &acme.dns_provider
            && !acme.dns_providers.contains_key(name)
        {
            self.push(
                Diagnostic::error(
                    "acme.dns_provider",
                    format!("DNS provider `{name}` is not defined"),
                )
                .with_hint("add it under `acme.dns_providers`"),
            );
        }
        for (i, resolver) in acme.dns_resolvers.iter().enumerate() {
            if crate::acme::parse_resolver(resolver).is_none() {
                self.error(
                    path_index("acme.dns_resolvers", i),
                    format!("`{resolver}` is not an IP address or `ip:port`"),
                );
            }
        }
        if acme.dns_propagation_timeout.is_zero() {
            self.error(
                "acme.dns_propagation_timeout",
                "the timeout must be longer than zero",
            );
        }
        for (name, provider) in &acme.dns_providers {
            self.check_name("acme.dns_providers", name);
            self.check_dns_provider(&path_key("acme.dns_providers", name), provider);
        }
        if let Some(eab) = &acme.eab {
            if eab.key_id.is_empty() {
                self.error("acme.eab.key_id", "key_id is empty");
            }
            self.check_secret("acme.eab.hmac_key", &eab.hmac_key, "eab_hmac");
        }
        if acme.ca == crate::acme::CaRef::Known(KnownCa::Buypass) {
            self.push(
                Diagnostic::error(
                    "acme.ca",
                    "Buypass stopped issuing certificates on 2025-10-16",
                )
                .with_hint("use `letsencrypt`, `zerossl`, `google` or another CA's directory URL"),
            );
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

    fn check_dns_provider(&mut self, path: &str, provider: &DnsProvider) {
        match provider {
            DnsProvider::Cloudflare { api_token, zone_id } => {
                self.check_secret(&format!("{path}.api_token"), api_token, "cf_token");
                if zone_id.as_deref().is_some_and(str::is_empty) {
                    self.error(format!("{path}.zone_id"), "zone_id is empty");
                }
            }
            DnsProvider::Exec {
                command, timeout, ..
            } => {
                if !command.is_absolute() {
                    self.push(
                        Diagnostic::error(
                            format!("{path}.command"),
                            format!("`{}` is not an absolute path", command.display()),
                        )
                        .with_hint(
                            "programs are run without a shell or PATH lookup; write the full path",
                        ),
                    );
                }
                if timeout.is_zero() {
                    self.error(
                        format!("{path}.timeout"),
                        "the timeout must be longer than zero",
                    );
                }
            }
            DnsProvider::Webhook(webhook) => self.check_webhook(path, webhook, "dns_webhook_token"),
        }
    }

    fn check_webhook(&mut self, path: &str, webhook: &Webhook, token_file: &str) {
        if !webhook.url.is_https_or_loopback() {
            self.push(
                Diagnostic::error(
                    format!("{path}.url"),
                    format!("`{}` is not encrypted", webhook.url),
                )
                .with_hint("use an https:// URL; http:// is allowed only for localhost"),
            );
        }
        if let Some(token) = &webhook.token {
            self.check_secret(&format!("{path}.token"), token, token_file);
        }
        if webhook.timeout.is_zero() {
            self.error(
                format!("{path}.timeout"),
                "the timeout must be longer than zero",
            );
        }
    }

    /// Public IP addresses need short-lived certificates and an HTTP or TLS challenge.
    fn check_ip_hosts(
        &mut self,
        tls_path: &str,
        hosts: &[&str],
        profile: Option<AcmeProfile>,
        dns: bool,
    ) {
        let Some(ip) = hosts.iter().find_map(|h| public_ip(h)) else {
            return;
        };
        if dns {
            self.push(
                Diagnostic::error(
                    tls_path,
                    format!("DNS-01 cannot validate the IP address `{ip}`"),
                )
                .with_hint("use http-01 or tls-alpn-01 for IP addresses, or a manual certificate"),
            );
        } else if profile != Some(AcmeProfile::Shortlived) {
            self.push(
                Diagnostic::warning(
                    tls_path,
                    format!("an automatic certificate for the IP address `{ip}` needs `acme.profile: shortlived`"),
                )
                .with_hint("set `acme.profile: shortlived`, or provide a certificate under `certificates`"),
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
        match security.client_ip_header {
            // The header is only read from trusted peers: Cloudflare's edge, or the network of a
            // `cloudflared` tunnel connector. With no trusted peer it would never be used.
            ClientIpHeader::CfConnectingIp if security.trusted_proxies.is_empty() => self.push(
                Diagnostic::error(
                    "security.client_ip_header",
                    "`cf-connecting-ip` needs trusted_proxies",
                )
                .with_hint(
                    "add `cloudflare`, or the network of `cloudflared` behind a Cloudflare Tunnel",
                ),
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
        self.check_not_zero(
            "security.limits.upstream_idle_connections",
            limits.upstream_idle_connections == 0,
        );
    }

    fn check_admin_passwords(&mut self) {
        let passwords = &self.config.admin.passwords;
        if !(8..=128).contains(&passwords.min_length) {
            self.error("admin.passwords.min_length", "must be between 8 and 128");
        }
        let cost = passwords.argon2;
        for (field, value, range) in [
            ("memory_kib", cost.memory_kib, 19_456..=262_144),
            ("iterations", cost.iterations, 2..=10),
            ("parallelism", cost.parallelism, 1..=8),
        ] {
            if !range.contains(&value) {
                self.push(
                    Diagnostic::error(
                        format!("admin.passwords.argon2.{field}"),
                        format!("must be between {} and {}", range.start(), range.end()),
                    )
                    .with_hint("the minimum is the OWASP recommendation for Argon2id (ADR-0024)"),
                );
            }
        }
        let sessions = self.config.admin.sessions;
        let bounds =
            std::time::Duration::from_secs(5 * 60)..=std::time::Duration::from_secs(12 * 60 * 60);
        for (field, value) in [("idle", sessions.idle), ("absolute", sessions.absolute)] {
            if !bounds.contains(&value.as_std()) {
                self.error(
                    format!("admin.sessions.{field}"),
                    "must be between 5m and 12h",
                );
            }
        }
        if sessions.idle > sessions.absolute {
            self.error("admin.sessions.idle", "must not be longer than `absolute`");
        }
        if !(1..=365).contains(&self.config.admin.tokens.default_expiry_days) {
            self.error(
                "admin.tokens.default_expiry_days",
                "must be between 1 and 365",
            );
        }
        let audit = &self.config.admin.audit;
        let days = audit.retention.as_std().as_secs() / 86_400;
        if !(1..=3650).contains(&days) {
            self.error("admin.audit.retention", "must be between 1d and 3650d");
        }
        let size = audit.max_file_size.as_u64();
        if !(1 << 20..=1 << 30).contains(&size) {
            self.error("admin.audit.max_file_size", "must be between 1MiB and 1GiB");
        }
        if let Some(forward) = &audit.forward
            && forward
                .syslog
                .rsplit_once(':')
                .is_none_or(|(host, port)| host.is_empty() || port.parse::<u16>().is_err())
        {
            self.error("admin.audit.forward.syslog", "write it as `host:port`");
        }
        let passwords = &self.config.admin.passwords;
        if passwords
            .blocklist_file
            .as_ref()
            .is_some_and(|path| path.as_os_str().is_empty())
        {
            self.error("admin.passwords.blocklist_file", "path is empty");
        }
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
            if admin.tls.is_none() {
                self.push(
                    Diagnostic::error("admin.listener", format!("the admin API on `{}` is reachable from the network without TLS", admin.listener))
                        .with_hint("keep it on 127.0.0.1, or set `admin.tls`: browsers do not keep secure cookies on plain HTTP to a network address (ADR-0024)"),
                );
            } else {
                self.push(
                    Diagnostic::warning(
                        "admin.listener",
                        format!(
                            "the admin API is reachable from the network on `{}`",
                            admin.listener
                        ),
                    )
                    .with_hint(
                        "limit who can reach it with a firewall; it still requires authentication",
                    ),
                );
            }
            if admin.listener.ip().is_none_or(|ip| ip.is_unspecified())
                && admin.allowed_hosts.is_empty()
            {
                self.error(
                    "admin.allowed_hosts",
                    "list the host names the admin API is reached by when it listens on all interfaces",
                );
            }
        }
        if let Some(tls) = &admin.tls {
            for (field, path) in [("cert_file", &tls.cert_file), ("key_file", &tls.key_file)] {
                if path.as_os_str().is_empty() {
                    self.error(format!("admin.tls.{field}"), "path is empty");
                }
            }
        }
        if !(1..=16).contains(&admin.threads) {
            self.error("admin.threads", "must be between 1 and 16");
        }
        self.check_admin_passwords();
        for (i, host) in admin.allowed_hosts.iter().enumerate() {
            if host.is_empty()
                || (host.contains(['/', ' ', ':']) && host.parse::<std::net::Ipv6Addr>().is_err())
            {
                self.error(
                    format!("admin.allowed_hosts[{i}]"),
                    format!("`{host}` is not a host name or IP address"),
                );
            }
        }
    }

    fn check_alerts(&mut self) {
        use crate::settings::AlertChannel;
        let alerts = &self.config.observability.alerts;
        let minute = std::time::Duration::from_secs(60);
        if !(minute..=std::time::Duration::from_secs(86_400))
            .contains(&alerts.min_interval.as_std())
        {
            self.error(
                "observability.alerts.min_interval",
                "must be between 1m and 24h",
            );
        }
        let window_ok = |w: crate::values::Duration| {
            (minute..=std::time::Duration::from_secs(900)).contains(&w.as_std())
        };
        if let Some(rule) = alerts.rules.error_rate {
            if !(1..=100).contains(&rule.percent) {
                self.error(
                    "observability.alerts.rules.error_rate.percent",
                    "must be between 1 and 100",
                );
            }
            if !window_ok(rule.window) {
                self.error(
                    "observability.alerts.rules.error_rate.window",
                    "must be between 1m and 15m (the live data rdock keeps)",
                );
            }
        }
        if let Some(rule) = alerts.rules.latency
            && !window_ok(rule.window)
        {
            self.error(
                "observability.alerts.rules.latency.window",
                "must be between 1m and 15m (the live data rdock keeps)",
            );
        }
        let channels: Vec<(String, AlertChannel)> = alerts
            .channels
            .iter()
            .map(|(n, c)| (n.clone(), c.clone()))
            .collect();
        for (name, channel) in channels {
            self.check_alert_channel(&name, &channel);
        }
    }

    fn check_alert_channel(&mut self, name: &str, channel: &crate::settings::AlertChannel) {
        use crate::settings::{AlertChannel, SmtpTls};
        {
            let path = format!("observability.alerts.channels.{name}");
            if name.is_empty()
                || !name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
            {
                self.error(
                    path.clone(),
                    "use letters, digits, `-` and `_` in channel names",
                );
            }
            let http = match channel {
                AlertChannel::Slack {
                    url,
                    allow_private_targets,
                    ..
                }
                | AlertChannel::Discord {
                    url,
                    allow_private_targets,
                    ..
                }
                | AlertChannel::SlackCompatible {
                    url,
                    allow_private_targets,
                    ..
                }
                | AlertChannel::Webhook {
                    url,
                    allow_private_targets,
                    ..
                } => Some((url.clone(), *allow_private_targets)),
                AlertChannel::Smtp { .. } => None,
            };
            if let Some((url, allow_private)) = http
                && !url.starts_with("${")
            {
                match url::Url::parse(&url) {
                    Ok(parsed) if parsed.scheme() == "https" => {}
                    Ok(parsed) if parsed.scheme() == "http" && allow_private => {}
                    Ok(_) => self.push(
                        Diagnostic::error(format!("{path}.url"), "use an https:// URL")
                            .with_hint("plain http is accepted only with allow_private_targets: true, for a relay inside your network"),
                    ),
                    Err(err) => self.error(format!("{path}.url"), format!("not a URL: {err}")),
                }
                self.push(
                    Diagnostic::warning(
                        format!("{path}.url"),
                        "the webhook URL is a secret written in the file",
                    )
                    .with_hint("write it as ${file:/run/secrets/…} or ${env:…}"),
                );
            }
            if let AlertChannel::Webhook {
                secret: Some(secret),
                ..
            } = &channel
                && !secret.starts_with("${")
                && !secret.starts_with("whsec_")
            {
                self.error(
                    format!("{path}.secret"),
                    "Standard Webhooks secrets start with `whsec_`",
                );
            }
            if let AlertChannel::Smtp {
                host,
                tls,
                username,
                password,
                from,
                to,
                ..
            } = &channel
            {
                let loopback = host == "localhost"
                    || host
                        .parse::<std::net::IpAddr>()
                        .is_ok_and(|ip| ip.is_loopback());
                if *tls == SmtpTls::None && !loopback {
                    self.push(
                        Diagnostic::error(format!("{path}.tls"), "plain SMTP sends passwords and alerts unencrypted")
                            .with_hint("use starttls or implicit; `none` is allowed only for a relay on this machine"),
                    );
                }
                if username.is_some() != password.is_some() {
                    self.error(
                        format!("{path}.password"),
                        "set both username and password, or neither",
                    );
                }
                if from.trim().is_empty() || to.is_empty() {
                    self.error(path.clone(), "set `from` and at least one address in `to`");
                }
            }
        }
    }

    fn check_observability(&mut self) {
        self.check_alerts();
        let observability = &self.config.observability;
        if !(0.0..=1.0).contains(&observability.access_log.sample) {
            self.error("observability.access_log.sample", "must be between 0 and 1");
        }
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

/// The address, when `host` is an IP address a public CA can certify (not loopback or private).
fn public_ip(host: &str) -> Option<IpAddr> {
    let literal = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    let ip: IpAddr = literal.parse().ok()?;
    let local = match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unique_local() || v6.is_unicast_link_local(),
    };
    (!local).then_some(ip)
}

#[cfg(test)]
mod tests;
