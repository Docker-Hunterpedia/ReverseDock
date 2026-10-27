//! Native labels: the `rdock.*` shorthand and full form (W-DKR-02).
//!
//! Shorthand: `rdock.host`, `rdock.path`, `rdock.port`, `rdock.tls` and `rdock.middlewares` make
//! one route and one service named after the container. Full form:
//! `rdock.routes.<name>.<field>`, `rdock.services.<name>.<field>` and
//! `rdock.middlewares.<name>.<field>`, where `<field>` is a dotted path of the YAML model.

use serde_json::Value;

use super::tree::{list, scalar};
use super::{Draft, Scope};

/// Labels read elsewhere: eligibility, network and the shorthand.
const HANDLED: [&str; 7] = [
    "rdock.enable",
    "rdock.network",
    "rdock.host",
    "rdock.path",
    "rdock.port",
    "rdock.tls",
    "rdock.middlewares",
];

/// Fields that would make ReverseDock read files on its own host; a container must not name
/// them.
const FILE_FIELDS: [&str; 2] = ["users_file", "file"];

/// Adds one `rdock.*` label to the draft.
pub(super) fn label(scope: &mut Scope<'_>, draft: &mut Draft, key: &str, value: &str) {
    if HANDLED.contains(&key) {
        return;
    }
    let Some(rest) = key.strip_prefix("rdock.") else {
        return;
    };
    let Some((section, rest)) = rest.split_once('.') else {
        scope.warn(key, "unknown label");
        return;
    };
    let Some((name, field)) = rest.split_once('.') else {
        scope.warn(
            key,
            "the label needs an object name and a field, like `rdock.routes.api.match`",
        );
        return;
    };
    let result = match section {
        "routes" => route(draft, name, field, value),
        "services" => service(draft, name, field, value),
        "middlewares" => middleware(draft, name, field, value),
        _ => Err("unknown label".to_owned()),
    };
    if let Err(message) = result {
        scope.warn(key, message);
    }
}

fn route(draft: &mut Draft, name: &str, field: &str, value: &str) -> Result<(), String> {
    let value = match field {
        "match" | "service" => Value::String(value.to_owned()),
        "middlewares" | "listeners" => list(value),
        "tls" => tls(value),
        "priority" | "enabled" => scalar(value),
        _ if field.starts_with("timeouts.") => scalar(value),
        _ => return Err(format!("routes have no `{field}` setting")),
    };
    draft
        .routes
        .entry(name.to_owned())
        .or_default()
        .set(field, value)
}

fn service(draft: &mut Draft, name: &str, field: &str, value: &str) -> Result<(), String> {
    let service = draft.services.entry(name.to_owned()).or_default();
    match field {
        "port" => {
            service.port = Some(port(value)?);
            Ok(())
        }
        "backends" | "split" => Err(format!(
            "`{field}` cannot be set from labels; the container is the backend"
        )),
        _ => service.tree.set(field, scalar(value)),
    }
}

fn middleware(draft: &mut Draft, name: &str, field: &str, value: &str) -> Result<(), String> {
    let last = field.rsplit('.').next().unwrap_or(field);
    if FILE_FIELDS.contains(&last) {
        return Err(format!(
            "`{last}` cannot be set from labels: a container must not name files on the proxy's host"
        ));
    }
    let value = if field == "type" {
        Value::String(value.to_owned())
    } else {
        scalar(value)
    };
    draft
        .middlewares
        .entry(name.to_owned())
        .or_default()
        .set(field, value)
}

/// `auto`, `off`, or `dns:<provider>` for DNS-01 certificates.
pub(super) fn tls(value: &str) -> Value {
    match value.strip_prefix("dns:") {
        Some(provider) => serde_json::json!({ "dns_provider": provider }),
        None => Value::String(value.to_owned()),
    }
}

pub(super) fn port(value: &str) -> Result<u16, String> {
    value
        .trim()
        .parse::<u16>()
        .ok()
        .filter(|p| *p != 0)
        .ok_or_else(|| format!("`{value}` is not a port number"))
}

/// The shorthand: one route and one service named after the container.
pub(super) fn shorthand(scope: &mut Scope<'_>, draft: &mut Draft) {
    let hosts: Vec<String> = scope
        .label("rdock.host")
        .map(|v| {
            v.split(',')
                .map(str::trim)
                .filter(|h| !h.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let path = scope
        .label("rdock.path")
        .map(str::trim)
        .filter(|p| !p.is_empty());
    let port_label = scope.label("rdock.port");
    let tls_label = scope.label("rdock.tls");
    let middlewares = scope.label("rdock.middlewares");
    let name = scope.default_name();
    if hosts.is_empty() && path.is_none() {
        for (label, set) in [
            ("rdock.tls", tls_label.is_some()),
            ("rdock.middlewares", middlewares.is_some()),
        ] {
            if set {
                scope.warn(
                    label,
                    "needs `rdock.host` or `rdock.path`; the label is ignored",
                );
            }
        }
        if let Some(value) = port_label {
            set_port(scope, draft, &name, value);
        }
        return;
    }
    if draft.routes.contains_key(&name) {
        scope.warn(
            "rdock.host",
            format!("the full form already declares route `{name}`; the shorthand is ignored"),
        );
        return;
    }
    let mut rule = hosts
        .iter()
        .map(|h| format!("Host(`{h}`)"))
        .collect::<Vec<_>>()
        .join(" || ");
    if hosts.len() > 1 && path.is_some() {
        rule = format!("({rule})");
    }
    if let Some(path) = path {
        let prefix = format!("PathPrefix(`{path}`)");
        rule = if rule.is_empty() {
            prefix
        } else {
            format!("{rule} && {prefix}")
        };
    }
    let route = draft.routes.entry(name.clone()).or_default();
    let mut fields = vec![
        ("match", Value::String(rule)),
        ("service", Value::String(name.clone())),
    ];
    if let Some(value) = tls_label {
        fields.push(("tls", tls(value)));
    }
    if let Some(value) = middlewares {
        fields.push(("middlewares", list(value)));
    }
    for (field, value) in fields {
        let _ = route.set(field, value);
    }
    draft.services.entry(name.clone()).or_default();
    if let Some(value) = port_label {
        set_port(scope, draft, &name, value);
    }
}

fn set_port(scope: &mut Scope<'_>, draft: &mut Draft, service: &str, value: &str) {
    match port(value) {
        Ok(port) => draft.services.entry(service.to_owned()).or_default().port = Some(port),
        Err(message) => scope.warn("rdock.port", message),
    }
}
