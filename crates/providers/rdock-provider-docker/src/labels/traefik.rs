//! The Traefik v3 label subset (W-DKR-03, architecture §11). Each supported label maps onto a
//! field of the model; every other `traefik.*` label is a warning naming it.
//!
//! Label names follow Traefik's Docker provider reference
//! (<https://doc.traefik.io/traefik/reference/routing-configuration/other-providers/docker/>,
//! checked 2026-10-28). Keys are compared in lower case, as Traefik does.

use serde_json::Value;

use super::native::{port, tls};
use super::tree::{list, scalar};
use super::{Draft, Scope};

/// Adds one `traefik.*` label to the draft.
pub(super) fn label(scope: &mut Scope<'_>, draft: &mut Draft, key: &str, value: &str) {
    if matches!(key, "traefik.enable" | "traefik.docker.network") {
        return;
    }
    let result = if let Some(rest) = key.strip_prefix("traefik.http.routers.") {
        split(rest).and_then(|(name, field)| router(scope, draft, name, field, value))
    } else if let Some(rest) = key.strip_prefix("traefik.http.services.") {
        split(rest).and_then(|(name, field)| service(draft, name, field, value))
    } else if let Some(rest) = key.strip_prefix("traefik.http.middlewares.") {
        split(rest).and_then(|(name, field)| middleware(draft, name, field, value))
    } else if key.starts_with("traefik.tcp.") || key.starts_with("traefik.udp.") {
        Err("TCP and UDP routing are not supported in this version (planned for v0.6)".to_owned())
    } else {
        Err(unsupported())
    };
    if let Err(message) = result {
        scope.warn(key, message);
    }
}

fn unsupported() -> String {
    "not in the supported Traefik label subset; the label is ignored".to_owned()
}

fn split(rest: &str) -> Result<(&str, &str), String> {
    rest.split_once('.')
        .filter(|(name, field)| !name.is_empty() && !field.is_empty())
        .ok_or_else(|| "the label needs an object name and a setting".to_owned())
}

fn router(
    scope: &Scope<'_>,
    draft: &mut Draft,
    name: &str,
    field: &str,
    value: &str,
) -> Result<(), String> {
    let route = draft.routes.entry(name.to_owned()).or_default();
    match field {
        "rule" => route.set("match", Value::String(value.to_owned())),
        "priority" => route.set("priority", scalar(value)),
        "service" => route.set("service", Value::String(value.to_owned())),
        "middlewares" => route.set("middlewares", list(value)),
        "entrypoints" => {
            let listeners: Vec<Value> = value
                .split(',')
                .map(str::trim)
                .filter(|e| !e.is_empty())
                .map(|e| {
                    Value::String(
                        scope
                            .settings
                            .entrypoints
                            .get(e)
                            .cloned()
                            .unwrap_or_else(|| e.to_owned()),
                    )
                })
                .collect();
            route.set("listeners", Value::Array(listeners))
        }
        "tls" => match value {
            "true" => auto_tls(route),
            "false" => route.set("tls", tls("off")),
            other => Err(format!("`{other}` is not `true` or `false`")),
        },
        // Any resolver means automatic certificates from the default ACME account.
        "tls.certresolver" => auto_tls(route),
        _ => match field.strip_prefix("tls.domains[") {
            Some(rest) => domain(route, rest, value),
            None => Err(unsupported()),
        },
    }
}

/// Automatic certificates, unless the route already has TLS settings (which default to
/// automatic).
fn auto_tls(route: &mut super::Tree) -> Result<(), String> {
    if route.has("tls") {
        return Ok(());
    }
    route.set("tls.auto", Value::Bool(true))
}

/// `tls.domains[n].main` and `tls.domains[n].sans`: the names on the certificate.
fn domain(route: &mut super::Tree, rest: &str, value: &str) -> Result<(), String> {
    let (index, field) = rest
        .split_once("].")
        .ok_or_else(|| "expected `tls.domains[n].main` or `tls.domains[n].sans`".to_owned())?;
    index
        .parse::<usize>()
        .map_err(|_| format!("`{index}` is not an index"))?;
    let names: Vec<&str> = match field {
        "main" => vec![value.trim()],
        "sans" => value
            .split(',')
            .map(str::trim)
            .filter(|n| !n.is_empty())
            .collect(),
        _ => return Err(unsupported()),
    };
    // Labels arrive sorted, so `domains[0].main` comes before `domains[0].sans`.
    for name in names {
        route.push("tls.domains", Value::String(name.to_owned()))?;
    }
    Ok(())
}

fn service(draft: &mut Draft, name: &str, field: &str, value: &str) -> Result<(), String> {
    let service = draft.services.entry(name.to_owned()).or_default();
    let Some(field) = field.strip_prefix("loadbalancer.") else {
        return Err(unsupported());
    };
    match field {
        "server.port" => {
            service.port = Some(port(value)?);
            Ok(())
        }
        "server.scheme" => service.tree.set("scheme", Value::String(value.to_owned())),
        "server.url" => {
            let (scheme, address) = value
                .split_once("://")
                .ok_or_else(|| format!("`{value}` is not a URL like `http://host:port`"))?;
            let address = address.trim_end_matches('/');
            service.address = Some(address.to_owned());
            service.tree.set("scheme", Value::String(scheme.to_owned()))
        }
        "passhostheader" => service.tree.set("pass_host_header", scalar(value)),
        "sticky.cookie" => match value {
            "true" => service.tree.set(
                "sticky.cookie.name",
                Value::String("rdock_sticky".to_owned()),
            ),
            _ => Err(format!("`{value}` is not `true`")),
        },
        "sticky.cookie.name" => service
            .tree
            .set("sticky.cookie.name", Value::String(value.to_owned())),
        "sticky.cookie.secure" => service.tree.set("sticky.cookie.secure", scalar(value)),
        "sticky.cookie.httponly" => service.tree.set("sticky.cookie.http_only", scalar(value)),
        "sticky.cookie.samesite" => service.tree.set(
            "sticky.cookie.same_site",
            Value::String(value.to_ascii_lowercase()),
        ),
        "sticky.cookie.maxage" => service.tree.set("sticky.cookie.max_age", seconds(value)),
        "strategy" => {
            let policy = match value.to_ascii_lowercase().as_str() {
                "wrr" => "round_robin",
                "p2c" => "p2c",
                "hrw" => "ip_hash",
                "leasttime" => "least_requests",
                other => {
                    return Err(format!(
                        "`{other}` is not `wrr`, `p2c`, `hrw` or `leasttime`"
                    ));
                }
            };
            service
                .tree
                .set("load_balancer.policy", Value::String(policy.to_owned()))
        }
        f if f.starts_with("healthcheck.") || f.starts_with("passivehealthcheck.") => {
            health(&mut service.tree, f, value)
        }
        "serverstransport" => {
            Err("servers transports are not supported; the backend's defaults are used".to_owned())
        }
        _ => Err(unsupported()),
    }
}

/// `healthcheck.*` and `passivehealthcheck.*` of a Traefik service.
fn health(tree: &mut super::Tree, field: &str, value: &str) -> Result<(), String> {
    match field {
        "healthcheck.path" => tree.set("health.active.path", Value::String(value.to_owned())),
        "healthcheck.interval" => {
            tree.set("health.active.interval", Value::String(value.to_owned()))
        }
        "healthcheck.timeout" => tree.set("health.active.timeout", Value::String(value.to_owned())),
        "healthcheck.port" => tree.set("health.active.port", scalar(value)),
        "healthcheck.mode" => match value.to_ascii_lowercase().as_str() {
            mode @ ("http" | "grpc") => {
                tree.set("health.active.mode", Value::String(mode.to_owned()))
            }
            other => Err(format!("`{other}` is not `http` or `grpc`")),
        },
        "healthcheck.status" => tree.set(
            "health.active.expected_status",
            Value::String(value.trim().to_owned()),
        ),
        "healthcheck.hostname" => {
            tree.set("health.active.hostname", Value::String(value.to_owned()))
        }
        "healthcheck.method" => tree.set(
            "health.active.method",
            Value::String(value.to_ascii_uppercase()),
        ),
        "healthcheck.followredirects" => match value {
            "false" => Ok(()),
            _ => Err(
                "redirects are never followed by health checks; the label is ignored".to_owned(),
            ),
        },
        "healthcheck.scheme" => {
            Err("health checks use the service's scheme; the label is ignored".to_owned())
        }
        "healthcheck.unhealthyinterval" => Err(
            "one interval is used for healthy and unhealthy backends; the label is ignored"
                .to_owned(),
        ),
        "passivehealthcheck.failurewindow" => tree.set("health.passive.window", seconds(value)),
        "passivehealthcheck.maxfailedattempts" => {
            tree.set("health.passive.failures", scalar(value))
        }
        _ => match field.strip_prefix("healthcheck.headers.") {
            Some(header) => tree.set(
                &format!("health.active.headers.{header}"),
                Value::String(value.to_owned()),
            ),
            None => Err(unsupported()),
        },
    }
}

/// A Traefik number of seconds as a duration (`3600` → `3600s`).
fn seconds(value: &str) -> Value {
    match value.trim().parse::<u64>() {
        Ok(n) => Value::String(format!("{n}s")),
        Err(_) => Value::String(value.to_owned()),
    }
}

/// How a label value becomes a model value.
#[derive(Clone, Copy)]
enum Kind {
    Text,
    Scalar,
    List,
    Seconds,
    Port,
}

/// Traefik middleware settings with a direct counterpart: (middleware, setting) → (our type,
/// our field, value kind).
const MIDDLEWARES: [(&str, &str, &str, &str, Kind); 24] = [
    ("redirectscheme", "scheme", "redirect", "scheme", Kind::Text),
    (
        "redirectscheme",
        "permanent",
        "redirect",
        "permanent",
        Kind::Scalar,
    ),
    ("redirectscheme", "port", "redirect", "port", Kind::Port),
    ("redirectregex", "regex", "redirect", "regex", Kind::Text),
    (
        "redirectregex",
        "replacement",
        "redirect",
        "replacement",
        Kind::Text,
    ),
    (
        "redirectregex",
        "permanent",
        "redirect",
        "permanent",
        Kind::Scalar,
    ),
    (
        "stripprefix",
        "prefixes",
        "strip_prefix",
        "prefixes",
        Kind::List,
    ),
    ("addprefix", "prefix", "add_prefix", "prefix", Kind::Text),
    ("replacepath", "path", "replace_path", "path", Kind::Text),
    ("replacepathregex", "regex", "rewrite", "regex", Kind::Text),
    (
        "replacepathregex",
        "replacement",
        "rewrite",
        "replacement",
        Kind::Text,
    ),
    ("basicauth", "users", "basic_auth", "users", Kind::List),
    ("basicauth", "realm", "basic_auth", "realm", Kind::Text),
    (
        "basicauth",
        "removeheader",
        "basic_auth",
        "remove_header",
        Kind::Scalar,
    ),
    (
        "ratelimit",
        "average",
        "rate_limit",
        "average",
        Kind::Scalar,
    ),
    ("ratelimit", "burst", "rate_limit", "burst", Kind::Scalar),
    ("ratelimit", "period", "rate_limit", "period", Kind::Seconds),
    (
        "ipallowlist",
        "sourcerange",
        "ip_allow",
        "cidrs",
        Kind::List,
    ),
    (
        "compress",
        "minresponsebodybytes",
        "compress",
        "min_size",
        Kind::Scalar,
    ),
    (
        "forwardauth",
        "address",
        "forward_auth",
        "address",
        Kind::Text,
    ),
    (
        "forwardauth",
        "trustforwardheader",
        "forward_auth",
        "trust_forward_header",
        Kind::Scalar,
    ),
    (
        "forwardauth",
        "authresponseheaders",
        "forward_auth",
        "copy_headers",
        Kind::List,
    ),
    (
        "forwardauth",
        "authrequestheaders",
        "forward_auth",
        "request_headers",
        Kind::List,
    ),
    ("errors", "status", "errors", "status", Kind::List),
];

fn middleware(draft: &mut Draft, name: &str, field: &str, value: &str) -> Result<(), String> {
    let (kind, setting) = field.split_once('.').unwrap_or((field, ""));
    let (our_type, our_field, value) = match (kind, setting) {
        ("headers", _) => {
            let tree = draft.middlewares.entry(name.to_owned()).or_default();
            set_type(tree, "headers")?;
            return headers(tree, setting, value);
        }
        ("compress", "") if value == "true" => ("compress", None, Value::Null),
        ("errors", "service") => ("errors", Some("service"), Value::String(value.to_owned())),
        ("errors", "query") => ("errors", Some("path"), Value::String(value.to_owned())),
        ("basicauth", "usersfile") => {
            return Err("`usersfile` cannot be set from labels: a container must not name files on the proxy's host".to_owned());
        }
        ("retry", _) => return retry(draft, name, setting, value),
        ("inflightreq", "amount") => ("in_flight", Some("amount"), scalar(value)),
        ("inflightreq", "sourcecriterion.requestheadername") => (
            "in_flight",
            Some("key"),
            Value::String(format!("header:{value}")),
        ),
        ("inflightreq", "sourcecriterion.ipstrategy.depth" | "sourcecriterion.requesthost") => {
            return Err("only the client IP and `requestHeaderName` are supported as keys; the client IP is used".to_owned());
        }
        ("passtlsclientcert", _) if setting == "pem" || setting.starts_with("info") => {
            let tree = draft.middlewares.entry(name.to_owned()).or_default();
            set_type(tree, "client_cert")?;
            if !tree.has("required") {
                tree.set("required", Value::Bool(false))?;
                tree.set("forward", Value::String("traefik".to_owned()))?;
            }
            return Ok(());
        }
        ("circuitbreaker", _) => {
            return Err("circuit-breaker expressions are not carried over; use `health.passive` and `max_requests` on the service".to_owned());
        }
        _ => {
            let (_, _, our_type, our_field, how) = MIDDLEWARES
                .iter()
                .find(|(k, s, ..)| *k == kind && *s == setting)
                .ok_or_else(unsupported)?;
            let value = match how {
                Kind::Text => Value::String(value.to_owned()),
                Kind::Scalar => scalar(value),
                Kind::List => list(value),
                Kind::Seconds => seconds(value),
                Kind::Port => Value::from(port(value)?),
            };
            (*our_type, Some(*our_field), value)
        }
    };
    let tree = draft.middlewares.entry(name.to_owned()).or_default();
    set_type(tree, our_type)?;
    match our_field {
        Some(field) => tree.set(field, value),
        None => Ok(()),
    }
}

/// Sets the middleware type once; a second, different type is an error.
fn set_type(tree: &mut super::Tree, kind: &str) -> Result<(), String> {
    if tree.has("type") {
        return Ok(());
    }
    tree.set("type", Value::String(kind.to_owned()))
}

/// The `headers` middleware: custom request and response headers and a few security headers.
fn headers(tree: &mut super::Tree, setting: &str, value: &str) -> Result<(), String> {
    let custom = |side: &str, header: &str| -> (String, Value) {
        if value.is_empty() {
            (format!("{side}.remove"), Value::String(header.to_owned()))
        } else {
            (
                format!("{side}.set.{header}"),
                Value::String(value.to_owned()),
            )
        }
    };
    let (path, value) = if let Some(header) = setting.strip_prefix("customrequestheaders.") {
        custom("request", header)
    } else if let Some(header) = setting.strip_prefix("customresponseheaders.") {
        custom("response", header)
    } else {
        match (setting, value) {
            ("stsseconds", v) => ("hsts.max_age".to_owned(), seconds(v)),
            ("stsincludesubdomains", v) => ("hsts.include_subdomains".to_owned(), scalar(v)),
            ("stspreload", v) => ("hsts.preload".to_owned(), scalar(v)),
            ("framedeny", "true") => (
                "response.set.X-Frame-Options".to_owned(),
                Value::String("DENY".to_owned()),
            ),
            ("contenttypenosniff", "true") => (
                "response.set.X-Content-Type-Options".to_owned(),
                Value::String("nosniff".to_owned()),
            ),
            ("browserxssfilter", "true") => (
                "response.set.X-XSS-Protection".to_owned(),
                Value::String("1; mode=block".to_owned()),
            ),
            ("framedeny" | "contenttypenosniff" | "browserxssfilter", _) => return Ok(()),
            _ => return Err(unsupported()),
        }
    };
    if path.ends_with(".remove") {
        return tree.push(&path, value);
    }
    tree.set(&path, value)
}

/// A Traefik `retry` middleware, waiting to be moved onto services.
#[derive(Debug, Default, Clone)]
pub(crate) struct Retry {
    attempts: Option<Value>,
    statuses: Vec<u16>,
    network: bool,
    non_idempotent: bool,
}

/// Traefik's `retry`: `attempts` counts every try, ours counts tries after the first.
fn retry(draft: &mut Draft, name: &str, setting: &str, value: &str) -> Result<(), String> {
    let retry = draft
        .retries
        .entry(name.to_owned())
        .or_insert_with(|| Retry {
            network: true,
            ..Retry::default()
        });
    match setting {
        "attempts" => {
            let total: u32 = value
                .trim()
                .parse()
                .map_err(|_| format!("`{value}` is not a number"))?;
            retry.attempts = Some(Value::from(total.saturating_sub(1)));
        }
        "status" => {
            for part in value.split(',').map(str::trim).filter(|p| !p.is_empty()) {
                let (from, to) = part.split_once('-').unwrap_or((part, part));
                let (Ok(from), Ok(to)) = (from.trim().parse::<u16>(), to.trim().parse::<u16>())
                else {
                    return Err(format!("`{part}` is not a status or range"));
                };
                retry
                    .statuses
                    .extend((from..=to).filter(|s| matches!(s, 502..=504)));
            }
            if retry.statuses.is_empty() {
                return Err("only 502, 503 and 504 are retried; the label is ignored".to_owned());
            }
        }
        "disableretryonnetworkerror" => retry.network = value != "true",
        "retrynonidempotentmethod" => retry.non_idempotent = value == "true",
        "initialinterval" => {
            return Err(
                "retries use a fixed jittered backoff (25 to 250 ms); the label is ignored"
                    .to_owned(),
            );
        }
        _ => return Err(unsupported()),
    }
    Ok(())
}

/// Moves the `retry` middlewares that routes use onto the routes' services.
pub(super) fn apply_retries(scope: &mut Scope<'_>, draft: &mut Draft) {
    let retries = std::mem::take(&mut draft.retries);
    if retries.is_empty() {
        return;
    }
    for (route_name, route) in &mut draft.routes {
        let service_name = match route.top_mut("service") {
            Some(Value::String(s)) => s.clone(),
            _ => continue,
        };
        let Some(Value::Array(list)) = route.top_mut("middlewares") else {
            continue;
        };
        let used: Vec<String> = list
            .iter()
            .filter_map(Value::as_str)
            .filter(|m| retries.contains_key(*m))
            .map(str::to_owned)
            .collect();
        list.retain(|m| m.as_str().is_none_or(|m| !retries.contains_key(m)));
        for middleware in used {
            let retry = &retries[&middleware];
            let Some(service) = draft.services.get_mut(&service_name) else {
                scope.warn_object(
                    "retry middleware",
                    &middleware,
                    &format!("route `{route_name}` uses a service from another container"),
                );
                continue;
            };
            let mut on: Vec<Value> = Vec::new();
            if retry.network {
                on.push(Value::String("connect".into()));
                on.push(Value::String("reset".into()));
            }
            let mut statuses = retry.statuses.clone();
            statuses.sort_unstable();
            statuses.dedup();
            on.extend(statuses.iter().map(|s| Value::String(s.to_string())));
            let tree = &mut service.tree;
            let _ = tree.set(
                "retries.attempts",
                retry.attempts.clone().unwrap_or(Value::from(1)),
            );
            let _ = tree.set("retries.on", Value::Array(on));
            if retry.non_idempotent {
                let _ = tree.set("retries.retry_non_idempotent", Value::Bool(true));
            }
        }
    }
}
