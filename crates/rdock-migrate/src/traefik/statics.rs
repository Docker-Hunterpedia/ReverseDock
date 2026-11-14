//! Traefik's static ("install") configuration: `traefik.yml`, the `command:` flags of the
//! Compose service that runs Traefik, and its `TRAEFIK_*` environment variables (ADR-0033).
//!
//! Options follow Traefik's v3.7 install reference, read 2026-11-14:
//! entry points (<https://doc.traefik.io/traefik/reference/install-configuration/entrypoints/>),
//! ACME resolvers (<https://doc.traefik.io/traefik/reference/install-configuration/tls/certificate-resolvers/acme/>),
//! the Docker provider (<https://doc.traefik.io/traefik/reference/install-configuration/providers/docker/>;
//! `exposedByDefault` defaults to `true`) and the file provider
//! (<https://doc.traefik.io/traefik/reference/install-configuration/providers/others/file/>).
//! The three forms are one option tree: `--entryPoints.web.address=:80`,
//! `TRAEFIK_ENTRYPOINTS_WEB_ADDRESS=:80` and `entryPoints: {web: {address: ":80"}}`
//! (<https://doc.traefik.io/traefik/getting-started/configuration-overview/>, read 2026-11-14).
//! DNS provider credentials are lego's variables
//! (<https://go-acme.github.io/lego/dns/>, read 2026-11-14); their values are never read or
//! copied: the output refers to the variable, and the report says to set it.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value, json};

use crate::report::{Builder, Finding, ItemId, ItemKind, Source};

/// One static option as read: its key in lower case with dots, and where it came from.
#[derive(Debug, Clone)]
pub(crate) struct Option_ {
    pub(crate) key: String,
    pub(crate) value: String,
    pub(crate) source: Source,
}

/// What the static configuration says, for the output and for the label translation.
#[derive(Debug, Default)]
pub(crate) struct Static {
    /// Whether any static configuration was read.
    pub(crate) known: bool,
    /// `listeners`.
    pub(crate) listeners: Map<String, Value>,
    /// Entry points with TLS on every router (`http.tls`).
    pub(crate) tls_entrypoints: BTreeSet<String>,
    /// Entry points that redirect every request (`http.redirections`).
    pub(crate) redirecting: BTreeSet<String>,
    /// `defaults`.
    pub(crate) defaults: Map<String, Value>,
    /// `acme`.
    pub(crate) acme: Map<String, Value>,
    /// `providers`.
    pub(crate) providers: Map<String, Value>,
    /// `security`.
    pub(crate) security: Map<String, Value>,
    /// `observability`.
    pub(crate) observability: Map<String, Value>,
    /// `lifecycle`.
    pub(crate) lifecycle: Map<String, Value>,
    /// Traefik's `exposedByDefault` for the Docker provider, when the Docker provider is on.
    pub(crate) expose_by_default: Option<bool>,
}

impl Static {
    /// The sections to write with `--full`, in order.
    pub(crate) fn sections(&self) -> Vec<(&'static str, Value)> {
        let mut out = Vec::new();
        let pairs: [(&'static str, &Map<String, Value>); 7] = [
            ("listeners", &self.listeners),
            ("defaults", &self.defaults),
            ("acme", &self.acme),
            ("providers", &self.providers),
            ("security", &self.security),
            ("observability", &self.observability),
            ("lifecycle", &self.lifecycle),
        ];
        for (key, map) in pairs {
            if !map.is_empty() {
                out.push((key, Value::Object(map.clone())));
            }
        }
        out
    }
}

/// The options of a static configuration file (YAML), flattened.
pub(crate) fn from_file(file: &str, document: &Value) -> Vec<Option_> {
    let mut out = Vec::new();
    flatten(file, "", document, &mut out);
    out
}

fn flatten(file: &str, prefix: &str, value: &Value, out: &mut Vec<Option_>) {
    let mut push = |value: String| {
        out.push(Option_ {
            key: prefix.to_ascii_lowercase(),
            value,
            source: Source {
                file: file.to_owned(),
                line: None,
                scope: None,
                kind: ItemKind::Key,
                item: prefix.to_owned(),
            },
        });
    };
    match value {
        Value::Object(map) if map.is_empty() => push(String::new()),
        Value::Object(map) => {
            for (key, item) in map {
                let path = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                flatten(file, &path, item, out);
            }
        }
        Value::Array(items) if items.iter().all(|i| !i.is_object() && !i.is_array()) => {
            push(items.iter().map(text).collect::<Vec<_>>().join(","));
        }
        Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                flatten(file, &format!("{prefix}[{i}]"), item, out);
            }
        }
        Value::Null => push(String::new()),
        scalar => push(text(scalar)),
    }
}

fn text(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// The options among a Compose service's `command:` flags (`--a.b=c`, `--a.b c` is not Traefik
/// syntax and is read as a flag without a value followed by an argument).
pub(crate) fn from_flags(file: &str, scope: &str, flags: &[String]) -> Vec<Option_> {
    flags
        .iter()
        .filter_map(|flag| {
            let body = flag.strip_prefix("--")?;
            let (key, value) = body.split_once('=').unwrap_or((body, "true"));
            Some(Option_ {
                key: key.to_ascii_lowercase(),
                value: value.to_owned(),
                source: Source {
                    file: file.to_owned(),
                    line: None,
                    scope: Some(scope.to_owned()),
                    kind: ItemKind::Flag,
                    item: format!("--{key}"),
                },
            })
        })
        .collect()
}

/// The options among a Compose service's `TRAEFIK_*` variables
/// (`TRAEFIK_ENTRYPOINTS_WEB_ADDRESS` → `entrypoints.web.address`).
pub(crate) fn from_env(file: &str, scope: &str, env: &BTreeMap<String, String>) -> Vec<Option_> {
    env.iter()
        .filter_map(|(name, value)| {
            let rest = name.strip_prefix("TRAEFIK_")?;
            Some(Option_ {
                key: rest.to_ascii_lowercase().replace('_', "."),
                value: value.clone(),
                source: Source {
                    file: file.to_owned(),
                    line: None,
                    scope: Some(scope.to_owned()),
                    kind: ItemKind::Env,
                    item: name.clone(),
                },
            })
        })
        .collect()
}

/// lego's DNS providers that have an adapter here: (lego code, our type, fields as (our
/// field, lego variables in order of preference, secret)).
type DnsField = (&'static str, &'static [&'static str], bool);
const DNS_PROVIDERS: [(&str, &str, &[DnsField]); 6] = [
    (
        "cloudflare",
        "cloudflare",
        &[(
            "api_token",
            &["CF_DNS_API_TOKEN", "CLOUDFLARE_DNS_API_TOKEN"],
            true,
        )],
    ),
    (
        "digitalocean",
        "digitalocean",
        &[("api_token", &["DO_AUTH_TOKEN"], true)],
    ),
    (
        "hetzner",
        "hetzner",
        &[("api_token", &["HETZNER_API_TOKEN", "HETZNER_API_KEY"], true)],
    ),
    ("desec", "desec", &[("token", &["DESEC_TOKEN"], true)]),
    (
        "route53",
        "route53",
        &[
            ("access_key_id", &["AWS_ACCESS_KEY_ID"], true),
            ("secret_access_key", &["AWS_SECRET_ACCESS_KEY"], true),
            ("region", &["AWS_REGION"], false),
        ],
    ),
    (
        "gcloud",
        "google_cloud_dns",
        &[
            ("credentials_file", &["GCE_SERVICE_ACCOUNT_FILE"], false),
            ("project", &["GCE_PROJECT"], false),
        ],
    ),
];

/// Let's Encrypt's directories, by the name ReverseDock uses.
const LE_PRODUCTION: &str = "https://acme-v02.api.letsencrypt.org/directory";
const LE_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

/// Interprets every option, accounts for each in `b`, and fills `out`. `env_names` are the
/// variable names set on Traefik's service (never their values), to name the credential
/// variables a DNS provider reads.
#[allow(clippy::too_many_lines)] // one arm per option family reads best as one match
pub(crate) fn interpret(
    options: &[Option_],
    env_names: &BTreeSet<String>,
    b: &mut Builder,
    out: &mut Static,
) {
    if options.is_empty() {
        return;
    }
    out.known = true;
    let mut docker_item: Option<ItemId> = None;
    let mut swarm_item: Option<ItemId> = None;
    let mut first_email: Option<String> = None;
    for option in options {
        let id = b.item(option.source.clone());
        let key = option.key.as_str();
        let parts: Vec<&str> = key.split('.').collect();
        let value = option.value.trim();
        let finding = match parts.as_slice() {
            ["entrypoints", name, rest @ ..] => entrypoint(name, rest, value, out),
            ["certificatesresolvers", resolver, "acme", rest @ ..] => {
                acme(resolver, rest, value, env_names, &mut first_email, out)
            }
            ["certificatesresolvers", _, ..] => Finding::new(
                "traefik.static.unsupported",
                "only ACME certificate resolvers exist here (Tailscale and other resolver kinds have no equivalent)",
            ),
            ["providers", "docker", rest @ ..] => {
                docker_item.get_or_insert(id);
                docker("docker", rest, value, out)
            }
            ["providers", "swarm", rest @ ..] => {
                swarm_item.get_or_insert(id);
                docker("swarm", rest, value, out)
            }
            ["providers", "file", rest @ ..] => file_provider(rest, value, out),
            ["providers", "providersthrottleduration"] => Finding::new(
                "traefik.static.unsupported",
                "provider updates are applied as they come; there is no throttle setting",
            ),
            ["providers", "kubernetesingress" | "kubernetescrd" | "kubernetesgateway", ..] => {
                Finding::new(
                    "traefik.static.manual",
                    "Kubernetes is a different setup here: the Gateway API controller and Ingress translation (`providers.kubernetes`, Helm chart)",
                )
            }
            ["providers", other, ..] => Finding::new(
                "traefik.static.unsupported",
                format!("the `{other}` provider has no equivalent (providers: file, Docker, Swarm, Kubernetes)"),
            ),
            ["api", ..] => {
                let mut finding = Finding::new(
                    "traefik.static.manual",
                    "ReverseDock's API and dashboard are on the admin listener (`admin`), with users and tokens; nothing is written",
                )
                .hint("set `admin.enabled: true` and create a user with `rdock users add`");
                if parts.get(1) == Some(&"insecure") && value != "false" {
                    "Traefik's API without authentication (`api.insecure`) has no equivalent on purpose; the admin listener always needs a user or token".clone_into(&mut finding.message);
                    finding = finding.security();
                }
                finding
            }
            ["ping", ..] => Finding::new(
                "traefik.static.manual",
                "the health endpoint is per listener here: set `listeners.<name>.ping: /ping`",
            ),
            ["log", "level"] => Finding::new(
                "traefik.static.approximate",
                format!("the log level is a command-line setting: run `rdock run --log {}`", value.to_ascii_lowercase()),
            ),
            ["log", ..] => Finding::new(
                "traefik.static.unsupported",
                "logs go to standard error in the format of `--log-format`; there is no log file setting",
            ),
            ["accesslog"] => {
                out.observability
                    .entry("access_log")
                    .or_insert_with(|| json!({}));
                Finding::new("traefik.static.exact", "the access log is on (`observability.access_log`)")
                    .target("observability.access_log")
            }
            ["accesslog", "format"] => {
                let format = if value.eq_ignore_ascii_case("json") { "json" } else { "text" };
                set(&mut out.observability, &["access_log", "format"], json!(format));
                if format == "json" {
                    Finding::new("traefik.static.exact", "`observability.access_log.format: json`")
                } else {
                    Finding::new(
                        "traefik.static.approximate",
                        "`observability.access_log.format: text` (ReverseDock's text format is not Traefik's Common Log Format)",
                    )
                }
                .target("observability.access_log.format")
            }
            ["accesslog", ..] => Finding::new(
                "traefik.static.unsupported",
                "the access log goes to standard output, with the fields of ReverseDock's format; files, buffers, filters and field choices are not set here (`observability.access_log.redact` hides headers)",
            ),
            ["metrics", "prometheus"] => {
                set(&mut out.observability, &["metrics", "prometheus"], json!(true));
                Finding::new(
                    "traefik.static.approximate",
                    "`observability.metrics.prometheus: true`: metrics are served at `/metrics` on the admin listener, named `rdock_*`",
                )
                .target("observability.metrics.prometheus")
            }
            ["metrics", ..] => Finding::new(
                "traefik.static.unsupported",
                "metrics are Prometheus metrics on the admin listener; their names, buckets and other backends are not Traefik's",
            ),
            ["tracing", "otlp", "http", "endpoint"] => {
                set(&mut out.observability, &["tracing", "otlp"], json!(value));
                Finding::new(
                    "traefik.static.approximate",
                    "`observability.tracing.otlp` (OTLP over HTTP); span names and attributes are ReverseDock's",
                )
                .target("observability.tracing.otlp")
            }
            ["tracing", "samplerate"] => {
                set(
                    &mut out.observability,
                    &["tracing", "sample_ratio"],
                    value.parse::<f64>().map_or(json!(value), |r| json!(r)),
                );
                Finding::new("traefik.static.exact", "`observability.tracing.sample_ratio`")
                    .target("observability.tracing.sample_ratio")
            }
            ["tracing", ..] => Finding::new(
                "traefik.static.unsupported",
                "tracing sends OTLP over HTTP (`observability.tracing.otlp`) with a sample ratio; other settings have no equivalent",
            ),
            ["global", ..] => Finding::new(
                "traefik.static.unsupported",
                "ReverseDock has no update check and sends no usage data",
            ),
            ["serverstransport", ..] => Finding::new(
                "traefik.static.manual",
                "there is no global transport to backends: set `tls` (for example `verify: false`, `ca_file`) on each service",
            )
            .security(),
            ["experimental", ..] => Finding::new(
                "traefik.static.unsupported",
                "Traefik's experimental features (plugins, Yaegi, Fast Proxy…) have no equivalent; ReverseDock's own are named under `experimental`",
            ),
            ["core", "defaultrulesyntax"] => Finding::new(
                "traefik.static.manual",
                "Traefik v2 rules are not read: rewrite the rules in v3 syntax",
            ),
            ["hostresolver" | "spiffe" | "ocsp" | "tcpserverstransport" | "core", ..] => {
                Finding::new("traefik.static.unsupported", "this setting has no equivalent")
            }
            _ => Finding::new(
                "traefik.static.unknown",
                "not a Traefik v3.7 static option this tool knows",
            ),
        };
        b.account(id, finding);
    }
    // Traefik's default: every container with labels is exposed.
    for (provider, item) in [("docker", docker_item), ("swarm", swarm_item)] {
        let Some(item) = item else { continue };
        let Some(Value::Object(settings)) = out.providers.get_mut(provider) else {
            continue;
        };
        if settings.contains_key("expose_by_default") {
            continue;
        }
        settings.insert("expose_by_default".to_owned(), json!(true));
        if provider == "docker" {
            out.expose_by_default = Some(true);
        }
        b.raise(
            item,
            Finding::new(
                "traefik.static.expose_by_default",
                format!("the {provider} provider is on, and Traefik exposes every container by default (`exposedByDefault` unset is `true`): written as `providers.{provider}.expose_by_default: true`"),
            )
            .target(format!("providers.{provider}.expose_by_default"))
            .security(),
        );
    }
}

/// Sets `path` in `map`, creating objects on the way.
fn set(map: &mut Map<String, Value>, path: &[&str], value: Value) {
    let Some((last, parents)) = path.split_last() else {
        return;
    };
    let mut node = map;
    for parent in parents {
        let entry = node
            .entry((*parent).to_owned())
            .or_insert_with(|| Value::Object(Map::new()));
        if !entry.is_object() {
            *entry = Value::Object(Map::new());
        }
        let Value::Object(next) = entry else { return };
        node = next;
    }
    node.insert((*last).to_owned(), value);
}

fn list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_owned)
        .collect()
}

/// `entryPoints.<name>.…`.
#[allow(clippy::too_many_lines)] // one arm per option
fn entrypoint(name: &str, rest: &[&str], value: &str, out: &mut Static) -> Finding {
    let target = format!("listeners.{name}");
    match rest {
        ["address"] => {
            let (address, protocol) = value.rsplit_once('/').unwrap_or((value, "tcp"));
            set(&mut out.listeners, &[name, "address"], json!(address));
            match protocol.to_ascii_lowercase().as_str() {
                "udp" => {
                    set(&mut out.listeners, &[name, "protocol"], json!("udp"));
                    Finding::new("traefik.static.exact", format!("a UDP listener on `{address}`"))
                }
                _ => Finding::new("traefik.static.exact", format!("a listener on `{address}`")),
            }
            .target(format!("{target}.address"))
        }
        ["asdefault"] => {
            if value != "false" {
                let listeners = out
                    .defaults
                    .entry("listeners")
                    .or_insert_with(|| json!([]));
                if let Value::Array(items) = listeners {
                    items.push(json!(name));
                }
            }
            Finding::new("traefik.static.exact", "routes without listeners use it (`defaults.listeners`)")
                .target("defaults.listeners")
        }
        ["http", "redirections", "entrypoint", "to"] => {
            out.redirecting.insert(name.to_owned());
            out.defaults
                .insert("redirect_http_to_https".to_owned(), json!(true));
            Finding::new(
                "traefik.static.approximate",
                format!("`defaults.redirect_http_to_https: true` (ReverseDock's default): plain-HTTP requests for hosts that have an HTTPS route are redirected, permanently (301 for GET, 308 otherwise); Traefik redirects every request on `{name}` to `{value}`, temporarily unless `permanent` is set"),
            )
            .target("defaults.redirect_http_to_https")
        }
        ["http", "redirections", "entrypoint", "scheme"] if value.eq_ignore_ascii_case("https") => {
            Finding::new("traefik.static.exact", "redirects go to `https`").target("defaults.redirect_http_to_https")
        }
        ["http", "redirections", "entrypoint", "permanent"] if value != "false" => Finding::new(
            "traefik.static.exact",
            "the HTTPS redirect is permanent: 301 for GET, 308 otherwise, as Traefik's permanent redirect",
        )
        .target("defaults.redirect_http_to_https"),
        ["http", "redirections", "entrypoint", "permanent"] => Finding::new(
            "traefik.static.approximate",
            "the HTTPS redirect is always permanent (301 for GET, 308 otherwise); a temporary one needs a `redirect` middleware",
        )
        .target("defaults.redirect_http_to_https"),
        ["http", "redirections", ..] => Finding::new(
            "traefik.static.unsupported",
            "the HTTPS redirect has no scheme, priority or target settings; write a `redirect` middleware for other redirects",
        ),
        ["http", "tls"] | ["http", "tls", "certresolver"] => {
            out.tls_entrypoints.insert(name.to_owned());
            set(&mut out.listeners, &[name, "tls"], json!({}));
            if rest.len() == 3 {
                Finding::new(
                    "traefik.static.approximate",
                    "routes on this listener get automatic certificates from the one `acme` account (the resolver's name is not kept)",
                )
            } else {
                Finding::new("traefik.static.exact", "TLS on this listener (`tls: {}`)")
            }
            .target(format!("{target}.tls"))
        }
        ["http", "tls", "domains", ..] => Finding::new(
            "traefik.static.manual",
            "certificates for listed domains are requested per route here: add `tls.domains` to the routes that serve them (a wildcard needs `dns-01`)",
        ),
        ["http", "tls", "options"] => Finding::new(
            "traefik.static.manual",
            "set `listeners.<name>.tls.policy` and `client_auth` instead of TLS options",
        ),
        ["http", "middlewares"] => Finding::new(
            "traefik.static.manual",
            "listeners have no middleware list: add these middlewares to each route",
        ),
        ["http", "encodedcharacters", ..] => Finding::new(
            "traefik.static.unsupported",
            "encoded reserved characters in paths are always allowed and never act as separators (ADR-0014)",
        ),
        ["http", "maxheaderbytes"] => Finding::new(
            "traefik.static.manual",
            "the request header limit is `security.limits.max_header_bytes` (64 KiB by default)",
        ),
        ["forwardedheaders", "trustedips"] => {
            let entries = out
                .security
                .entry("trusted_proxies")
                .or_insert_with(|| json!([]));
            if let Value::Array(items) = entries {
                for ip in list(value) {
                    if !items.iter().any(|i| i.as_str() == Some(ip.as_str())) {
                        items.push(json!(ip));
                    }
                }
            }
            Finding::new(
                "traefik.static.approximate",
                "`security.trusted_proxies`: one list for every listener (Traefik: per entry point)",
            )
            .target("security.trusted_proxies")
            .security()
        }
        ["forwardedheaders", "insecure"] if value == "false" => {
            Finding::new("traefik.static.exact", "forwarded headers are trusted only from `security.trusted_proxies`")
        }
        ["forwardedheaders", "insecure"] => Finding::new(
            "traefik.static.manual",
            "trusting `X-Forwarded-*` from every client has no equivalent on purpose: list the proxies in front of ReverseDock in `security.trusted_proxies`",
        )
        .security(),
        ["forwardedheaders", ..] => Finding::new(
            "traefik.static.unsupported",
            "only the list of trusted proxies is set (`security.trusted_proxies`)",
        ),
        ["proxyprotocol", "trustedips"] => {
            set(&mut out.listeners, &[name, "proxy_protocol", "trusted"], json!(list(value)));
            Finding::new("traefik.static.exact", "PROXY protocol from these addresses (`proxy_protocol.trusted`)")
                .target(format!("{target}.proxy_protocol.trusted"))
                .security()
        }
        ["proxyprotocol", "insecure"] if value == "false" => {
            Finding::new("traefik.static.exact", "PROXY protocol only from trusted addresses")
        }
        ["proxyprotocol", "insecure"] => Finding::new(
            "traefik.static.manual",
            "accepting the PROXY protocol from every client has no equivalent on purpose: list the senders in `listeners.<name>.proxy_protocol.trusted`",
        )
        .security(),
        ["transport", "lifecycle", "gracetimeout"] => {
            out.lifecycle.insert("drain_timeout".to_owned(), json!(value));
            Finding::new(
                "traefik.static.approximate",
                "`lifecycle.drain_timeout`: one drain time for the whole proxy (Traefik: per entry point)",
            )
            .target("lifecycle.drain_timeout")
        }
        ["transport", "respondingtimeouts", ..] => Finding::new(
            "traefik.static.manual",
            "listener timeouts work differently here (header, idle and per-read limits): see `listeners.<name>.timeouts` before setting them",
        ),
        ["http3", ..] => Finding::new(
            "traefik.static.manual",
            "HTTP/3 is experimental here: it needs a build with the `http3` feature, `experimental: [http3]` and `listeners.<name>.http3`",
        ),
        ["http2", ..] => Finding::new(
            "traefik.static.manual",
            "HTTP/2 limits are `listeners.<name>.http2` settings with their own names",
        ),
        ["udp", "timeout"] => Finding::new(
            "traefik.static.manual",
            "the UDP session timeout is `udp_services.<name>.timeouts.idle` (60s by default; Traefik's is 3s)",
        ),
        _ => Finding::new(
            "traefik.static.unsupported",
            "this entry point setting has no equivalent",
        ),
    }
}

/// `certificatesResolvers.<name>.acme.…`: one ACME account here, so every resolver feeds it.
fn acme(
    resolver: &str,
    rest: &[&str],
    value: &str,
    env_names: &BTreeSet<String>,
    first_email: &mut Option<String>,
    out: &mut Static,
) -> Finding {
    let one_account = "several resolvers collapse into the one `acme` account";
    match rest {
        ["email"] => match first_email {
            Some(first) if first != value => Finding::new(
                "traefik.static.approximate",
                format!("{one_account}: the first resolver's email is used (resolver `{resolver}` has another)"),
            )
            .target("acme.email"),
            _ => {
                *first_email = Some(value.to_owned());
                out.acme.insert("email".to_owned(), json!(value));
                Finding::new("traefik.static.exact", "`acme.email`").target("acme.email")
            }
        },
        ["caserver"] => {
            if value == LE_STAGING {
                out.acme.insert("staging".to_owned(), json!(true));
                Finding::new("traefik.static.exact", "Let's Encrypt's staging directory (`acme.staging: true`)")
                    .target("acme.staging")
            } else if value == LE_PRODUCTION {
                Finding::new("traefik.static.exact", "Let's Encrypt, the default CA").target("acme.ca")
            } else {
                out.acme.insert("ca".to_owned(), json!(value));
                Finding::new("traefik.static.exact", "`acme.ca`: the same ACME directory").target("acme.ca")
            }
        }
        ["storage"] => Finding::new(
            "traefik.static.manual",
            "`acme.json` is not imported: certificates are requested again and kept in ReverseDock's data directory; mind the CA's rate limits when many names move at once",
        ),
        ["profile"] => {
            out.acme.insert("profile".to_owned(), json!(value.to_ascii_lowercase()));
            Finding::new("traefik.static.exact", "`acme.profile`").target("acme.profile")
        }
        ["httpchallenge"] | ["httpchallenge", "entrypoint"] => {
            challenge(out, "http-01");
            Finding::new(
                "traefik.static.exact",
                "the HTTP-01 challenge (answered on every plain-HTTP listener)",
            )
            .target("acme.challenges")
        }
        ["tlschallenge"] => {
            challenge(out, "tls-alpn-01");
            Finding::new("traefik.static.exact", "the TLS-ALPN-01 challenge").target("acme.challenges")
        }
        ["dnschallenge"] => {
            challenge(out, "dns-01");
            Finding::new("traefik.static.exact", "the DNS-01 challenge").target("acme.challenges")
        }
        ["dnschallenge", "provider"] => dns_provider(value, env_names, out),
        ["dnschallenge", "resolvers"] => {
            out.acme.insert("dns_resolvers".to_owned(), json!(list(value)));
            Finding::new("traefik.static.exact", "`acme.dns_resolvers`").target("acme.dns_resolvers")
        }
        ["dnschallenge", ..] => Finding::new(
            "traefik.static.unsupported",
            "propagation is checked against `acme.dns_resolvers` for up to `acme.dns_propagation_timeout`; delays and switches have no equivalent",
        ),
        ["eab", ..] => Finding::new(
            "traefik.static.credentials",
            "the external account binding is not copied: set `acme.eab` with the key ID and the HMAC key as a `${file:…}` or `${env:…}` reference",
        ),
        ["keytype" | "preferredchain" | "certificatesduration" | "cacertificates" | "casystemcertpool" | "caservername" | "clientresponseheadertimeout" | "clienttimeout", ..] => {
            Finding::new(
                "traefik.static.unsupported",
                "ReverseDock chooses the key type and chain and renews by ACME Renewal Information; this setting has no equivalent",
            )
        }
        _ => Finding::new(
            "traefik.static.unknown",
            "not an ACME resolver option this tool knows",
        ),
    }
}

fn challenge(out: &mut Static, name: &str) {
    let list = out.acme.entry("challenges").or_insert_with(|| json!([]));
    if let Value::Array(items) = list
        && !items.iter().any(|i| i.as_str() == Some(name))
    {
        items.push(json!(name));
    }
}

/// A lego DNS provider code as one of ReverseDock's DNS-01 adapters, with its credentials as
/// environment references.
fn dns_provider(code: &str, env_names: &BTreeSet<String>, out: &mut Static) -> Finding {
    challenge(out, "dns-01");
    let Some((_, kind, fields)) = DNS_PROVIDERS.iter().find(|(lego, ..)| *lego == code) else {
        return Finding::new(
            "traefik.static.manual",
            format!(
                "lego's `{code}` provider has no adapter here (Cloudflare, deSEC, Route 53, Google Cloud DNS, Azure DNS, DigitalOcean, Hetzner, RFC 2136, exec, webhook): configure `acme.dns_providers` by hand"
            ),
        );
    };
    let mut settings = Map::new();
    settings.insert("type".to_owned(), json!(kind));
    let mut variables = Vec::new();
    for (field, names, _secret) in *fields {
        let name = names
            .iter()
            .find(|n| env_names.contains(**n))
            .unwrap_or(&names[0]);
        settings.insert((*field).to_owned(), json!(format!("${{env:{name}}}")));
        variables.push(*name);
    }
    out.acme
        .entry("dns_providers")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .map(|providers| providers.insert(code.to_owned(), Value::Object(settings)));
    out.acme.insert("dns_provider".to_owned(), json!(code));
    let mut finding = Finding::new(
        "traefik.static.credentials",
        format!("`acme.dns_providers.{code}` (type `{kind}`) reads its credentials from {}; their values were not copied", variables.iter().map(|v| format!("`{v}`")).collect::<Vec<_>>().join(", ")),
    )
    .target(format!("acme.dns_providers.{code}"))
    .hint(format!("set {} in ReverseDock's environment (or replace the references with `${{file:…}}`)", variables.join(", ")));
    if code == "hetzner" {
        finding.message.push_str("; check that the token is for the API ReverseDock's Hetzner adapter uses (see the DNS challenge guide)");
    }
    finding
}

/// `providers.docker.…` and `providers.swarm.…`.
fn docker(provider: &str, rest: &[&str], value: &str, out: &mut Static) -> Finding {
    let settings = out.providers.entry(provider).or_insert_with(|| json!({}));
    let target = format!("providers.{provider}");
    let Value::Object(settings) = settings else {
        return Finding::new("traefik.static.unknown", "unexpected provider value");
    };
    match rest {
        [] if value == "false" => {
            out.providers.remove(provider);
            Finding::new(
                "traefik.static.exact",
                format!("the {provider} provider is off"),
            )
        }
        [] => Finding::new(
            "traefik.static.exact",
            format!("the {provider} provider, reading `traefik.*` labels too"),
        )
        .target(target),
        ["exposedbydefault"] => {
            let on = value != "false";
            settings.insert("expose_by_default".to_owned(), json!(on));
            if provider == "docker" {
                out.expose_by_default = Some(on);
            }
            let finding = Finding::new(
                "traefik.static.expose_by_default",
                format!("`{target}.expose_by_default: {on}`, as Traefik's `exposedByDefault`"),
            )
            .target(format!("{target}.expose_by_default"));
            if on { finding.security() } else { finding }
        }
        ["network"] => {
            settings.insert("network".to_owned(), json!(value));
            Finding::new("traefik.static.exact", format!("`{target}.network`"))
                .target(format!("{target}.network"))
        }
        ["endpoint"] => {
            settings.insert("endpoint".to_owned(), json!(value));
            Finding::new("traefik.static.exact", format!("`{target}.endpoint`"))
                .target(format!("{target}.endpoint"))
        }
        ["watch"] => Finding::new("traefik.static.exact", "events are always watched"),
        ["refreshseconds"] if provider == "swarm" => {
            settings.insert("poll_interval".to_owned(), json!(format!("{value}s")));
            Finding::new("traefik.static.exact", "`providers.swarm.poll_interval`")
                .target(format!("{target}.poll_interval"))
        }
        ["defaultrule"] => Finding::new(
            "traefik.static.manual",
            "there is no default rule: give each container a router rule (or `rdock.host`)",
        ),
        ["constraints"] => Finding::new(
            "traefik.static.manual",
            "there are no constraint expressions: choose containers with `traefik.enable` / `rdock.enable`",
        ),
        ["username" | "password", ..] => Finding::new(
            "traefik.static.credentials",
            "the engine API's credentials are not copied: put them in the endpoint's proxy or use a socket proxy",
        ),
        ["tls", ..] => Finding::new(
            "traefik.static.manual",
            "TLS to the engine API is not set here: reach it through a socket proxy or a Unix socket",
        ),
        _ => Finding::new(
            "traefik.static.unsupported",
            "this provider setting has no equivalent",
        ),
    }
}

/// `providers.file.…`.
fn file_provider(rest: &[&str], value: &str, out: &mut Static) -> Finding {
    let settings = out
        .providers
        .entry("file")
        .or_insert_with(|| json!({ "paths": [] }));
    let Value::Object(settings) = settings else {
        return Finding::new("traefik.static.unknown", "unexpected provider value");
    };
    match rest {
        ["directory" | "filename"] => {
            if let Some(Value::Array(paths)) = settings.get_mut("paths") {
                paths.push(json!(value));
            }
            Finding::new(
                "traefik.static.approximate",
                "`providers.file.paths`: the files there are Traefik dynamic configuration; migrate each one with `rdock migrate traefik <file>` and point this at the results",
            )
            .target("providers.file.paths")
        }
        ["watch"] => {
            settings.insert("watch".to_owned(), json!(value != "false"));
            Finding::new("traefik.static.exact", "`providers.file.watch`")
                .target("providers.file.watch")
        }
        [] => Finding::new("traefik.static.exact", "the file provider"),
        _ => Finding::new(
            "traefik.static.unsupported",
            "file templates (`debugLogGeneratedTemplate`) are not offered",
        ),
    }
}
