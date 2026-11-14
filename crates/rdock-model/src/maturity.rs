//! Maturity levels (ADR-0033): one registry of every user-visible feature area with its level,
//! the release it appeared in and where it lives in the configuration.
//!
//! The registry is data. Validation (the `experimental` opt-in), `rdock version`, the JSON
//! Schema (`x-rdock-maturity`), the website's badges and its "Stability and maturity" page, the
//! log lines at load and the `rdock_experimental_feature_in_use` metric all read it, so a level
//! is stated in exactly one place.
//!
//! - **Experimental**: no promise; may change or be removed in any release. Refused unless
//!   named in the top-level `experimental` list.
//! - **Beta**: not removed without a deprecation; details may change in a minor release with a
//!   migration note.
//! - **Stable**: covered by the stability promise (`docs/10-stability.md`).

use std::fmt::{self, Write as _};

use serde::{Serialize, Serializer};

use crate::config::{Config, ListenerProtocol};
use crate::diagnostics::{Diagnostic, path_key};
use crate::middleware::{LimitScope, Middleware};
use crate::service::{Failover, LbPolicy, SlowStart};
use crate::values::RateLimitKey;

/// How much a feature is promised (ADR-0033).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Level {
    /// No promise; needs the `experimental` opt-in.
    Experimental,
    /// Not removed without a deprecation; may change in a minor release with a note.
    Beta,
    /// Covered by the stability promise.
    Stable,
}

impl Level {
    /// `experimental`, `beta` or `stable`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Experimental => "experimental",
            Self::Beta => "beta",
            Self::Stable => "stable",
        }
    }
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Finds where a feature is used in a configuration: the paths of the settings that use it.
pub type Detect = fn(&Config, &mut Vec<String>);

/// One feature area.
#[derive(Debug, Clone, Copy)]
pub struct Feature {
    /// Stable identifier; for an experimental feature also the name to list under
    /// `experimental`.
    pub id: &'static str,
    /// The maturity level.
    pub level: Level,
    /// The milestone it appeared in, e.g. `v0.8`.
    pub since: &'static str,
    /// One line on what it is.
    pub summary: &'static str,
    /// The cargo feature a build needs for it, when it is not in every build.
    pub cargo_feature: Option<&'static str>,
    /// Where it lives in the configuration, as schema locations: dotted keys, `*` for any map
    /// key or list item, and `key=value` for one value of an enumeration or one `type` of a
    /// tagged object (`middlewares.*.type=wasm`). Empty for features outside the file (a
    /// client library).
    pub locations: &'static [&'static str],
    /// Finds its use in a configuration. Stable features are not looked for: nothing is said
    /// about them at run time.
    pub detect: Option<Detect>,
}

impl Serialize for Feature {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct View<'a> {
            id: &'a str,
            level: Level,
            since: &'a str,
            summary: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            cargo_feature: Option<&'a str>,
            locations: &'a [&'a str],
        }
        View {
            id: self.id,
            level: self.level,
            since: self.since,
            summary: self.summary,
            cargo_feature: self.cargo_feature,
            locations: self.locations,
        }
        .serialize(serializer)
    }
}

/// The top-level key that opts into experimental features.
pub const OPT_IN_KEY: &str = "experimental";

/// What "experimental" means, for diagnostics and docs.
pub const EXPERIMENTAL_MEANING: &str = "experimental features may change or be removed in any release, including a patch release, and are not covered by the stability promise (docs: Project › Stability and maturity)";

/// Every feature area. Order: stable, beta, experimental, each roughly by milestone. The
/// completeness test in this module fails when a top-level section, a middleware `type`, a
/// provider or a cargo-feature-gated setting is not listed here.
pub static FEATURES: &[Feature] = &[
    // --- Stable ---------------------------------------------------------------------------
    Feature {
        id: "config-file",
        level: Level::Stable,
        since: "v0.1",
        summary: "The configuration file itself: schema v1, `version`, `$schema` and the `experimental` opt-in",
        cargo_feature: None,
        locations: &["$schema", "version", "experimental"],
        detect: None,
    },
    Feature {
        id: "http-proxy",
        level: Level::Stable,
        since: "v0.1",
        summary: "HTTP/1.1, HTTP/2 and h2c proxying: listeners, routes and rules, services, defaults, manual certificates, client IP trust, the v0.1 middlewares",
        cargo_feature: None,
        locations: &[
            "listeners",
            "defaults",
            "routes",
            "services",
            "certificates",
            "security",
            "lifecycle",
            "middlewares",
            "middlewares.*.type=headers",
            "middlewares.*.type=redirect",
            "middlewares.*.type=rewrite",
            "middlewares.*.type=strip_prefix",
            "middlewares.*.type=add_prefix",
            "middlewares.*.type=replace_path",
            "middlewares.*.type=basic_auth",
            "middlewares.*.type=forward_auth",
            "middlewares.*.type=ip_allow",
            "middlewares.*.type=ip_deny",
            "middlewares.*.type=rate_limit",
            "middlewares.*.type=cors",
            "middlewares.*.type=compress",
            "middlewares.*.type=errors",
            "middlewares.*.type=maintenance",
        ],
        detect: None,
    },
    Feature {
        id: "observability",
        level: Level::Stable,
        since: "v0.1",
        summary: "Access log, Prometheus metrics and OpenTelemetry traces",
        cargo_feature: None,
        locations: &["observability"],
        detect: None,
    },
    Feature {
        id: "file-provider",
        level: Level::Stable,
        since: "v0.1",
        summary: "The file provider with watching, reload and the last-known-good copy",
        cargo_feature: None,
        locations: &["providers", "providers.file"],
        detect: None,
    },
    Feature {
        id: "docker-provider",
        level: Level::Stable,
        since: "v0.2",
        summary: "The Docker provider with `rdock.*` and Traefik labels and zero-config mode",
        cargo_feature: None,
        locations: &["providers.docker"],
        detect: None,
    },
    Feature {
        id: "automatic-https",
        level: Level::Stable,
        since: "v0.3",
        summary: "Automatic certificates over ACME (HTTP-01, TLS-ALPN-01, DNS-01), ARI renewal and the local CA",
        cargo_feature: None,
        locations: &["acme"],
        detect: None,
    },
    Feature {
        id: "reliability",
        level: Level::Stable,
        since: "v0.4",
        summary: "Health checks, passive ejection, retries, sticky sessions, splits, mirroring, limits, client certificates, JWT and gRPC-Web",
        cargo_feature: None,
        locations: &[
            "services.*.health",
            "services.*.retries",
            "services.*.sticky",
            "services.*.split",
            "routes.*.mirror",
            "middlewares.*.type=in_flight",
            "middlewares.*.type=bandwidth",
            "middlewares.*.type=jwt",
            "middlewares.*.type=client_cert",
            "middlewares.*.type=grpc_web",
        ],
        detect: None,
    },
    Feature {
        id: "admin-api",
        level: Level::Stable,
        since: "v0.5",
        summary: "The admin API under `/api/v1`, the configuration API and the local CLI",
        cargo_feature: None,
        locations: &["admin"],
        detect: None,
    },
    Feature {
        id: "users-and-audit",
        level: Level::Stable,
        since: "v0.5",
        summary: "Dashboard users, second factors, sessions, API tokens and the audit log",
        cargo_feature: None,
        locations: &[
            "admin.passwords",
            "admin.mfa",
            "admin.sessions",
            "admin.tokens",
            "admin.audit",
        ],
        detect: None,
    },
    Feature {
        id: "dashboard",
        level: Level::Stable,
        since: "v0.5",
        summary: "The embedded dashboard",
        cargo_feature: None,
        locations: &["admin.dashboard"],
        detect: None,
    },
    Feature {
        id: "swarm-provider",
        level: Level::Stable,
        since: "v0.6",
        summary: "The Docker Swarm provider",
        cargo_feature: None,
        locations: &["providers.swarm"],
        detect: None,
    },
    Feature {
        id: "tcp-routes",
        level: Level::Stable,
        since: "v0.6",
        summary: "TCP routes: SNI routing, TLS passthrough and termination, STARTTLS",
        cargo_feature: None,
        locations: &[
            "tcp_routes",
            "tcp_services",
            "listeners.*.protocol=tcp",
            "listeners.*.starttls",
        ],
        detect: None,
    },
    Feature {
        id: "static-files",
        level: Level::Stable,
        since: "v0.6",
        summary: "Static files from ReverseDock's own file system (`type: static`)",
        cargo_feature: None,
        locations: &["middlewares.*.type=static"],
        detect: None,
    },
    Feature {
        id: "dns-01-providers",
        level: Level::Stable,
        since: "v0.6",
        summary: "DNS-01 adapters (Cloudflare, RFC 2136, Route 53, Google Cloud DNS, Azure DNS, deSEC, webhook)",
        cargo_feature: None,
        locations: &["acme.dns_provider", "acme.dns_providers"],
        detect: None,
    },
    Feature {
        id: "gateway-api",
        level: Level::Stable,
        since: "v0.7",
        summary: "The Kubernetes Gateway API controller (the conformance profiles it passes)",
        cargo_feature: None,
        locations: &["providers.kubernetes", "providers.kubernetes.gateway"],
        detect: None,
    },
    // --- Beta -----------------------------------------------------------------------------
    Feature {
        id: "alerts",
        level: Level::Beta,
        since: "v0.5",
        summary: "Alert channels (Slack, Discord, webhooks, SMTP) and alert rules",
        cargo_feature: None,
        locations: &["observability.alerts"],
        detect: Some(detect_alerts),
    },
    Feature {
        id: "proxy-protocol",
        level: Level::Beta,
        since: "v0.6",
        summary: "PROXY protocol v1/v2 from trusted sources and to TCP backends",
        cargo_feature: None,
        locations: &[
            "listeners.*.proxy_protocol",
            "tcp_services.*.proxy_protocol",
        ],
        detect: Some(detect_proxy_protocol),
    },
    Feature {
        id: "kubernetes-ingress",
        level: Level::Beta,
        since: "v0.7",
        summary: "Translation of Kubernetes Ingress objects and ingress-nginx annotations",
        cargo_feature: None,
        locations: &["providers.kubernetes.ingress"],
        detect: Some(detect_ingress),
    },
    Feature {
        id: "fixed-responses",
        level: Level::Beta,
        since: "v0.7",
        summary: "Services that answer a fixed status (`respond`)",
        cargo_feature: None,
        locations: &["services.*.respond"],
        detect: Some(detect_respond),
    },
    Feature {
        id: "http-cache",
        level: Level::Beta,
        since: "v0.8",
        summary: "The RFC 9111 HTTP cache in memory or on disk, with purge by URL and tag",
        cargo_feature: None,
        locations: &["caches", "middlewares.*.type=cache"],
        detect: Some(detect_cache),
    },
    Feature {
        id: "native-plugins",
        level: Level::Beta,
        since: "v0.8",
        summary: "Native Rust plugins compiled into your own binary (`type: plugin`, the `rdock-plugin-api` SDK)",
        cargo_feature: None,
        locations: &["middlewares.*.type=plugin"],
        detect: Some(detect_plugin),
    },
    Feature {
        id: "agents",
        level: Level::Beta,
        since: "v0.8",
        summary: "Out-of-process agents such as a WAF (`type: agent`)",
        cargo_feature: None,
        locations: &["middlewares.*.type=agent"],
        detect: Some(detect_agent),
    },
    Feature {
        id: "consumers",
        level: Level::Beta,
        since: "v0.8",
        summary: "Consumers, API keys, quotas, usage metering and limits keyed by consumer group",
        cargo_feature: None,
        locations: &[
            "consumers",
            "middlewares.*.type=api_key",
            "middlewares.*.type=quota",
            "observability.metering",
        ],
        detect: Some(detect_consumers),
    },
    Feature {
        id: "oidc",
        level: Level::Beta,
        since: "v0.8",
        summary: "OpenID Connect login for browsers (`type: oidc`)",
        cargo_feature: None,
        locations: &["middlewares.*.type=oidc"],
        detect: Some(detect_oidc),
    },
    Feature {
        id: "validation-and-transformation",
        level: Level::Beta,
        since: "v0.8",
        summary: "Request validation against JSON Schema and OpenAPI, header and JSON Patch transformation, problem-details answers",
        cargo_feature: None,
        locations: &[
            "middlewares.*.type=validate",
            "middlewares.*.type=transform",
            "defaults.errors",
            "routes.*.errors",
        ],
        detect: Some(detect_validation),
    },
    Feature {
        id: "hold-body",
        level: Level::Beta,
        since: "v0.8",
        summary: "Holding the whole request body before it is forwarded (`type: hold_body`)",
        cargo_feature: None,
        locations: &["middlewares.*.type=hold_body"],
        detect: Some(detect_hold_body),
    },
    Feature {
        id: "cloudflare-access",
        level: Level::Beta,
        since: "v0.8",
        summary: "Verifying Cloudflare Access tokens (`type: cloudflare_access`)",
        cargo_feature: None,
        locations: &["middlewares.*.type=cloudflare_access"],
        detect: Some(detect_cloudflare_access),
    },
    Feature {
        id: "udp",
        level: Level::Beta,
        since: "v0.8",
        summary: "UDP listeners, routes and services",
        cargo_feature: None,
        locations: &[
            "udp_routes",
            "udp_services",
            "listeners.*.protocol=udp",
            "listeners.*.sessions",
        ],
        detect: Some(detect_udp),
    },
    Feature {
        id: "vault",
        level: Level::Beta,
        since: "v0.8",
        summary: "Secrets read from Vault or OpenBao (`${vault:…}` references)",
        cargo_feature: None,
        locations: &["secrets"],
        detect: Some(detect_vault),
    },
    Feature {
        id: "balancing",
        level: Level::Beta,
        since: "v0.9",
        summary: "Latency-aware balancing (`peak_ewma`), outlier detection, the long form of slow start, priority tiers, zones and per-try timeouts",
        cargo_feature: None,
        locations: &[
            "locality",
            "services.*.load_balancer.policy=peak_ewma",
            "services.*.load_balancer.decay",
            "services.*.load_balancer.measure",
            "services.*.failover",
            "services.*.overprovisioning",
            "services.*.locality",
            "services.*.health.passive.outlier",
            "services.*.retries.per_try_timeout",
            "services.*.backends.*.priority",
            "services.*.backends.*.zone",
            "services.*.backends.*.for_zones",
        ],
        detect: Some(detect_balancing),
    },
    Feature {
        id: "tls-fingerprints",
        level: Level::Beta,
        since: "v0.9",
        summary: "JA4 and JA3 TLS client fingerprints",
        cargo_feature: None,
        locations: &["listeners.*.tls.fingerprint"],
        detect: Some(detect_fingerprints),
    },
    Feature {
        id: "geoip",
        level: Level::Beta,
        since: "v0.9",
        summary: "GeoIP databases for country, continent and ASN rules",
        cargo_feature: None,
        locations: &["geoip"],
        detect: Some(detect_geoip),
    },
    Feature {
        id: "abuse",
        level: Level::Beta,
        since: "v0.9",
        summary: "Abuse counters and bans (`type: abuse`)",
        cargo_feature: None,
        locations: &["middlewares.*.type=abuse"],
        detect: Some(detect_abuse),
    },
    Feature {
        id: "client-cert-identity",
        level: Level::Beta,
        since: "v0.9",
        summary: "Identity rules on client certificates and SPIFFE IDs",
        cargo_feature: None,
        locations: &[
            "middlewares.*.type=client_cert.subjects",
            "middlewares.*.type=client_cert.organizations",
            "middlewares.*.type=client_cert.dns",
            "middlewares.*.type=client_cert.uris",
            "middlewares.*.type=client_cert.emails",
            "middlewares.*.type=client_cert.serials",
            "middlewares.*.type=client_cert.sha256",
            "middlewares.*.type=client_cert.spiffe",
        ],
        detect: Some(detect_client_cert_identity),
    },
    Feature {
        id: "binary-upgrade",
        level: Level::Beta,
        since: "v0.9",
        summary: "Replacing the binary in place by handing the listeners over (`rdock upgrade`)",
        cargo_feature: None,
        locations: &["upgrade"],
        detect: Some(detect_upgrade),
    },
    Feature {
        id: "cluster",
        level: Level::Beta,
        since: "v0.9",
        summary: "A cluster with a control plane, staged rollout and shared certificates (`rdock control`)",
        cargo_feature: None,
        locations: &["cluster", "control"],
        detect: Some(detect_cluster),
    },
    Feature {
        id: "cluster-limits",
        level: Level::Beta,
        since: "v0.9",
        summary: "Rate limits and quotas shared between the instances of a cluster (`scope: cluster`)",
        cargo_feature: None,
        locations: &[
            "cluster.limits",
            "middlewares.*.type=rate_limit.scope",
            "middlewares.*.type=quota.scope",
        ],
        detect: Some(detect_cluster_limits),
    },
    Feature {
        id: "admission-control",
        level: Level::Beta,
        since: "v0.9",
        summary: "Adaptive concurrency limits and load shedding by priority class (`type: admission`)",
        cargo_feature: None,
        locations: &["middlewares.*.type=admission", "routes.*.priority_class"],
        detect: Some(detect_admission),
    },
    Feature {
        id: "tenants",
        level: Level::Beta,
        since: "v0.9",
        summary: "Tenants of the admin API",
        cargo_feature: None,
        locations: &["tenants"],
        detect: Some(detect_tenants),
    },
    Feature {
        id: "tuning",
        level: Level::Beta,
        since: "v0.9",
        summary: "Listener socket and HTTP/2 options, the TLS handshake bound, shared TLS session resumption and runtime threads",
        cargo_feature: None,
        locations: &[
            "runtime",
            "listeners.*.socket",
            "listeners.*.http2",
            "listeners.*.tls.max_handshakes",
            "listeners.*.tls.tickets",
            "listeners.*.tls.session_cache",
        ],
        detect: Some(detect_tuning),
    },
    Feature {
        id: "go-client",
        level: Level::Beta,
        since: "v0.5",
        summary: "The Go client of the admin API (`clients/go`, generated; not tagged yet)",
        cargo_feature: None,
        locations: &[],
        detect: None,
    },
    Feature {
        id: "terraform-provider",
        level: Level::Beta,
        since: "v0.8",
        summary: "The Terraform and OpenTofu provider (`clients/terraform`; not published yet)",
        cargo_feature: None,
        locations: &[],
        detect: None,
    },
    // --- Experimental ---------------------------------------------------------------------
    Feature {
        id: "wasm",
        level: Level::Experimental,
        since: "v0.8",
        summary: "Sandboxed WebAssembly plugins (`type: wasm`); the host ABI is `0.x`",
        cargo_feature: Some("wasm"),
        locations: &["middlewares.*.type=wasm"],
        detect: Some(detect_wasm),
    },
    Feature {
        id: "http3",
        level: Level::Experimental,
        since: "v0.9",
        summary: "HTTP/3 over QUIC on `https` listeners (`http3.enabled`)",
        cargo_feature: Some("http3"),
        locations: &["listeners.*.http3"],
        detect: Some(detect_http3),
    },
];

/// The feature with this id.
#[must_use]
pub fn feature(id: &str) -> Option<&'static Feature> {
    FEATURES.iter().find(|f| f.id == id)
}

/// The ids of the experimental features: the names `experimental` accepts.
pub fn experimental_ids() -> impl Iterator<Item = &'static str> {
    FEATURES
        .iter()
        .filter(|f| f.level == Level::Experimental)
        .map(|f| f.id)
}

/// The feature a schema location is listed under exactly, e.g. `middlewares.*.type=wasm`.
#[must_use]
pub fn listed(location: &str) -> Option<&'static Feature> {
    FEATURES.iter().find(|f| f.locations.contains(&location))
}

/// The feature that covers a schema location: the one listing it, or else the one listing its
/// nearest parent (`listeners.*.http3.enabled` → `http3`).
#[must_use]
pub fn covering(location: &str) -> Option<&'static Feature> {
    let mut current = location;
    loop {
        if let Some(found) = listed(current) {
            return Some(found);
        }
        let (parent, _) = current.rsplit_once('.')?;
        current = parent;
    }
}

/// A feature below stable that a configuration uses, with the paths that use it.
#[derive(Debug, Clone, Serialize)]
pub struct InUse {
    /// The feature.
    pub feature: &'static Feature,
    /// Where: e.g. `middlewares.filter`, `listeners.websecure.http3.enabled`.
    pub paths: Vec<String>,
}

/// Every experimental and beta feature `config` uses, in registry order.
#[must_use]
pub fn in_use(config: &Config) -> Vec<InUse> {
    FEATURES
        .iter()
        .filter(|f| f.level != Level::Stable)
        .filter_map(|feature| {
            let detect = feature.detect?;
            let mut paths = Vec::new();
            detect(config, &mut paths);
            (!paths.is_empty()).then_some(InUse { feature, paths })
        })
        .collect()
}

/// The `experimental` opt-in: an experimental feature in use and not named is an error; an
/// unknown name is an error; a name that is not experimental, or not in use, is a warning.
pub(crate) fn check_opt_in(config: &Config, merged: bool, out: &mut Vec<Diagnostic>) {
    let used = in_use(config);
    for use_ in used
        .iter()
        .filter(|u| u.feature.level == Level::Experimental)
    {
        let id = use_.feature.id;
        if config.experimental.iter().any(|n| n == id) {
            continue;
        }
        for path in &use_.paths {
            let mut hint = format!(
                "add `{OPT_IN_KEY}: [{id}]` at the top of the file to use it; {EXPERIMENTAL_MEANING}"
            );
            if let Some(cargo) = use_.feature.cargo_feature {
                let _ = write!(
                    hint,
                    "\nit also needs a build with the `{cargo}` cargo feature (`rdock version` lists what this build includes)"
                );
            }
            out.push(
                Diagnostic::error(
                    path.clone(),
                    format!(
                        "the experimental feature `{id}` ({}) is used but not enabled",
                        use_.feature.summary_short()
                    ),
                )
                .with_hint(hint)
                .with_code("experimental_not_enabled"),
            );
        }
    }
    for (i, name) in config.experimental.iter().enumerate() {
        let path = crate::diagnostics::path_index(OPT_IN_KEY, i);
        match feature(name) {
            None => {
                let mut d = Diagnostic::error(
                    path,
                    format!("`{name}` is not an experimental feature of this version"),
                );
                d = match rdock_rules::closest_match(name, experimental_ids()) {
                    Some(near) => d.with_hint(format!("did you mean `{near}`?")),
                    None => d.with_hint(format!(
                        "the experimental features are: {}",
                        experimental_ids().collect::<Vec<_>>().join(", ")
                    )),
                };
                out.push(d.with_code("experimental_unknown"));
            }
            Some(f) if f.level != Level::Experimental => out.push(
                Diagnostic::warning(
                    path,
                    format!("`{name}` is {} now and needs no opt-in", f.level),
                )
                .with_hint(format!("remove `{name}` from `{OPT_IN_KEY}`"))
                .with_code("experimental_not_needed"),
            ),
            Some(f) if !used.iter().any(|u| u.feature.id == f.id) => {
                let hint = if merged {
                    format!("remove `{name}` from `{OPT_IN_KEY}`")
                } else {
                    format!(
                        "remove `{name}` from `{OPT_IN_KEY}`, unless a provider's objects (labels, the API) use it"
                    )
                };
                out.push(
                    Diagnostic::warning(
                        path,
                        format!("the experimental feature `{name}` is enabled but not used"),
                    )
                    .with_hint(hint)
                    .with_code("experimental_unused"),
                );
            }
            Some(_) => {}
        }
    }
}

impl Feature {
    /// The summary up to its first parenthesis or comma-free clause, for one-line messages.
    #[must_use]
    pub fn summary_short(&self) -> &'static str {
        self.summary
            .split(" (")
            .next()
            .unwrap_or(self.summary)
            .split("; ")
            .next()
            .unwrap_or(self.summary)
    }
}

// --- Detection --------------------------------------------------------------------------------

fn middlewares_where(
    config: &Config,
    out: &mut Vec<String>,
    suffix: Option<&str>,
    matches: impl Fn(&Middleware) -> bool,
) {
    for (name, middleware) in &config.middlewares {
        if matches(middleware) {
            let path = path_key("middlewares", name);
            out.push(match suffix {
                Some(field) => format!("{path}.{field}"),
                None => path,
            });
        }
    }
}

fn detect_alerts(config: &Config, out: &mut Vec<String>) {
    for name in config.observability.alerts.channels.keys() {
        out.push(path_key("observability.alerts.channels", name));
    }
    if config.observability.alerts.webhook.is_some() {
        out.push("observability.alerts.webhook".to_owned());
    }
}

fn detect_proxy_protocol(config: &Config, out: &mut Vec<String>) {
    for (name, listener) in &config.listeners {
        if listener.proxy_protocol.is_some() {
            out.push(format!("{}.proxy_protocol", path_key("listeners", name)));
        }
    }
    for (name, service) in &config.tcp_services {
        if service.proxy_protocol.is_some() {
            out.push(format!("{}.proxy_protocol", path_key("tcp_services", name)));
        }
    }
}

fn detect_ingress(config: &Config, out: &mut Vec<String>) {
    if config
        .providers
        .kubernetes
        .as_ref()
        .is_some_and(|k| k.ingress.enabled)
    {
        out.push("providers.kubernetes.ingress".to_owned());
    }
}

fn detect_respond(config: &Config, out: &mut Vec<String>) {
    for (name, service) in &config.services {
        if service.respond.is_some() {
            out.push(format!("{}.respond", path_key("services", name)));
        }
    }
}

fn detect_cache(config: &Config, out: &mut Vec<String>) {
    for name in config.caches.keys() {
        out.push(path_key("caches", name));
    }
    middlewares_where(config, out, None, |m| matches!(m, Middleware::Cache(_)));
}

fn detect_plugin(config: &Config, out: &mut Vec<String>) {
    middlewares_where(config, out, None, |m| matches!(m, Middleware::Plugin(_)));
}

fn detect_agent(config: &Config, out: &mut Vec<String>) {
    middlewares_where(config, out, None, |m| matches!(m, Middleware::Agent(_)));
}

fn detect_consumers(config: &Config, out: &mut Vec<String>) {
    for name in config.consumers.keys() {
        out.push(path_key("consumers", name));
    }
    middlewares_where(config, out, None, |m| {
        matches!(m, Middleware::ApiKey(_) | Middleware::Quota(_))
    });
    middlewares_where(config, out, Some("key"), |m| match m {
        Middleware::RateLimit(r) => r.key == RateLimitKey::Group,
        Middleware::InFlight(f) => f.key == RateLimitKey::Group,
        Middleware::Bandwidth(b) => b.key == RateLimitKey::Group,
        _ => false,
    });
    if config.observability.metering.is_some() {
        out.push("observability.metering".to_owned());
    }
}

fn detect_oidc(config: &Config, out: &mut Vec<String>) {
    middlewares_where(config, out, None, |m| matches!(m, Middleware::Oidc(_)));
}

fn detect_validation(config: &Config, out: &mut Vec<String>) {
    middlewares_where(config, out, None, |m| {
        matches!(m, Middleware::Validate(_) | Middleware::Transform(_))
    });
    if config.defaults.errors != crate::config::ErrorSettings::default() {
        out.push("defaults.errors".to_owned());
    }
    for (name, route) in &config.routes {
        if route.errors.is_some() {
            out.push(format!("{}.errors", path_key("routes", name)));
        }
    }
}

fn detect_hold_body(config: &Config, out: &mut Vec<String>) {
    middlewares_where(config, out, None, |m| matches!(m, Middleware::HoldBody(_)));
}

fn detect_cloudflare_access(config: &Config, out: &mut Vec<String>) {
    middlewares_where(config, out, None, |m| {
        matches!(m, Middleware::CloudflareAccess(_))
    });
}

fn detect_udp(config: &Config, out: &mut Vec<String>) {
    for (name, listener) in &config.listeners {
        if listener.effective_protocol() == ListenerProtocol::Udp {
            out.push(path_key("listeners", name));
        }
    }
    for name in config.udp_routes.keys() {
        out.push(path_key("udp_routes", name));
    }
    for name in config.udp_services.keys() {
        out.push(path_key("udp_services", name));
    }
}

fn detect_vault(config: &Config, out: &mut Vec<String>) {
    if config.secrets.vault.is_some() {
        out.push("secrets.vault".to_owned());
    }
}

fn detect_balancing(config: &Config, out: &mut Vec<String>) {
    if config.locality.is_some() {
        out.push("locality".to_owned());
    }
    for (name, service) in &config.services {
        let path = path_key("services", name);
        let lb = &service.load_balancer;
        if lb.policy == LbPolicy::PeakEwma || lb.decay.is_some() || lb.measure.is_some() {
            out.push(format!("{path}.load_balancer"));
        }
        if service.failover == Failover::Spill || service.overprovisioning.is_some() {
            out.push(format!("{path}.failover"));
        }
        if service.locality.is_some() {
            out.push(format!("{path}.locality"));
        }
        if let Some(health) = &service.health {
            if health.passive.as_ref().is_some_and(|p| p.outlier.is_some()) {
                out.push(format!("{path}.health.passive.outlier"));
            }
            if matches!(health.slow_start, Some(SlowStart::Detailed(_))) {
                out.push(format!("{path}.health.slow_start"));
            }
        }
        if service
            .retries
            .as_ref()
            .is_some_and(|r| r.per_try_timeout.is_some())
        {
            out.push(format!("{path}.retries.per_try_timeout"));
        }
        for (i, backend) in service.backends.iter().enumerate() {
            if backend.priority.is_some() || backend.zone.is_some() || !backend.for_zones.is_empty()
            {
                out.push(crate::diagnostics::path_index(
                    &format!("{path}.backends"),
                    i,
                ));
            }
        }
    }
}

fn detect_fingerprints(config: &Config, out: &mut Vec<String>) {
    for (name, listener) in &config.listeners {
        if listener
            .tls
            .as_ref()
            .is_some_and(|t| t.fingerprint.is_some())
        {
            out.push(format!("{}.tls.fingerprint", path_key("listeners", name)));
        }
    }
}

fn detect_geoip(config: &Config, out: &mut Vec<String>) {
    if config.geoip.is_some() {
        out.push("geoip".to_owned());
    }
}

fn detect_abuse(config: &Config, out: &mut Vec<String>) {
    middlewares_where(config, out, None, |m| matches!(m, Middleware::Abuse(_)));
}

fn detect_client_cert_identity(config: &Config, out: &mut Vec<String>) {
    middlewares_where(config, out, None, |m| match m {
        Middleware::ClientCert(c) => {
            [
                &c.subjects,
                &c.organizations,
                &c.dns,
                &c.uris,
                &c.emails,
                &c.serials,
                &c.sha256,
            ]
            .iter()
            .any(|list| !list.is_empty())
                || c.spiffe.is_some()
        }
        _ => false,
    });
}

fn detect_upgrade(config: &Config, out: &mut Vec<String>) {
    if config.upgrade.is_some() {
        out.push("upgrade".to_owned());
    }
}

fn detect_cluster(config: &Config, out: &mut Vec<String>) {
    if config.cluster.is_some() {
        out.push("cluster".to_owned());
    }
    if config.control.is_some() {
        out.push("control".to_owned());
    }
}

fn detect_cluster_limits(config: &Config, out: &mut Vec<String>) {
    middlewares_where(config, out, Some("scope"), |m| match m {
        Middleware::RateLimit(r) => r.scope == LimitScope::Cluster,
        Middleware::Quota(q) => q.scope == LimitScope::Cluster,
        _ => false,
    });
}

fn detect_admission(config: &Config, out: &mut Vec<String>) {
    middlewares_where(config, out, None, |m| matches!(m, Middleware::Admission(_)));
    for (name, route) in &config.routes {
        if !route.priority_class.is_normal() {
            out.push(format!("{}.priority_class", path_key("routes", name)));
        }
    }
}

fn detect_tenants(config: &Config, out: &mut Vec<String>) {
    for name in config.tenants.keys() {
        out.push(path_key("tenants", name));
    }
}

fn detect_tuning(config: &Config, out: &mut Vec<String>) {
    if config.runtime.is_some() {
        out.push("runtime".to_owned());
    }
    for (name, listener) in &config.listeners {
        let path = path_key("listeners", name);
        if listener.socket.is_some() {
            out.push(format!("{path}.socket"));
        }
        if listener.http2.is_some() {
            out.push(format!("{path}.http2"));
        }
        if let Some(tls) = &listener.tls {
            for (set, field) in [
                (tls.max_handshakes.is_some(), "max_handshakes"),
                (tls.tickets.is_some(), "tickets"),
                (tls.session_cache.is_some(), "session_cache"),
            ] {
                if set {
                    out.push(format!("{path}.tls.{field}"));
                }
            }
        }
    }
}

fn detect_wasm(config: &Config, out: &mut Vec<String>) {
    middlewares_where(config, out, None, |m| matches!(m, Middleware::Wasm(_)));
}

fn detect_http3(config: &Config, out: &mut Vec<String>) {
    for (name, listener) in &config.listeners {
        if listener.http3.as_ref().is_some_and(|h| h.enabled) {
            out.push(format!("{}.http3.enabled", path_key("listeners", name)));
        }
    }
}

#[cfg(test)]
mod tests;
