//! A Traefik dynamic configuration file (file provider): routers and middlewares go through the
//! shared label translator as the labels of one pseudo-container; services, servers transports,
//! TCP and UDP services and TLS certificates are built here, because a file can say what labels
//! cannot (several servers with weights, transports, addresses). Every leaf key is a source
//! item of the report.
//!
//! Semantics from Traefik's v3.7 reference, read 2026-11-14: the HTTP load balancer and the
//! weighted service (<https://doc.traefik.io/traefik/reference/routing-configuration/http/load-balancing/service/>),
//! servers transports (<https://doc.traefik.io/traefik/reference/routing-configuration/http/load-balancing/serverstransport/>),
//! TCP services and transports (<https://doc.traefik.io/traefik/reference/routing-configuration/tcp/service/>,
//! `…/tcp/serverstransport/`) and certificates
//! (<https://doc.traefik.io/traefik/reference/routing-configuration/http/tls/tls-certificates/>).

use std::collections::BTreeMap;

use serde_json::{Map, Value, json};

use super::LabelItem;
use crate::report::{Builder, Finding, ItemId, ItemKind, Source};

/// What the file says beyond the labels, applied to the translation afterwards.
#[derive(Debug, Default)]
pub(crate) struct Extra {
    /// HTTP services: every server (address, weight, scheme) by service name.
    pub(crate) backends: BTreeMap<String, Vec<Value>>,
    /// HTTP services that use a servers transport: service → transport name.
    pub(crate) uses_transport: BTreeMap<String, (String, ItemId)>,
    /// Servers transports: name → settings to merge into a service (`tls`, `timeouts`).
    pub(crate) transports: BTreeMap<String, Map<String, Value>>,
    /// Weighted services: name → `split`.
    pub(crate) splits: BTreeMap<String, Vec<Value>>,
    /// `basicAuth.usersFile` by middleware name.
    pub(crate) users_files: BTreeMap<String, String>,
    /// TCP services, whole.
    pub(crate) tcp_services: BTreeMap<String, Value>,
    /// UDP services, whole.
    pub(crate) udp_services: BTreeMap<String, Value>,
    /// `certificates`.
    pub(crate) certificates: Map<String, Value>,
    /// The certificate of `tls.stores.default.defaultCertificate`, for `defaults.certificate`.
    pub(crate) default_certificate: Option<String>,
}

/// A leaf of the file: its dotted path as written and its value.
struct Leaf {
    path: String,
    value: Value,
}

fn leaves(prefix: &str, value: &Value, out: &mut Vec<Leaf>) {
    match value {
        Value::Object(map) if !map.is_empty() => {
            for (key, item) in map {
                leaves(&join(prefix, key), item, out);
            }
        }
        Value::Array(items) if items.iter().any(|i| i.is_object() || i.is_array()) => {
            for (i, item) in items.iter().enumerate() {
                leaves(&format!("{prefix}[{i}]"), item, out);
            }
        }
        other => out.push(Leaf {
            path: prefix.to_owned(),
            value: other.clone(),
        }),
    }
}

fn join(prefix: &str, key: &str) -> String {
    if prefix.is_empty() {
        key.to_owned()
    } else {
        format!("{prefix}.{key}")
    }
}

/// A leaf value as label text: lists joined with commas, an empty object or null as `true`
/// (a section that is present: `tls: {}`, `compress: {}`).
fn label_text(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Array(items) => items.iter().map(label_text).collect::<Vec<_>>().join(","),
        Value::Null | Value::Object(_) => "true".to_owned(),
        other => other.to_string(),
    }
}

/// The path below `prefix` in lower case (`loadBalancer.healthCheck.path` → `loadbalancer.healthcheck.path`).
fn lower(path: &str) -> String {
    path.to_ascii_lowercase()
}

/// Reads the file: labels for routers and middlewares (with their items), and everything else
/// into `extra`, accounting for the keys it handles itself.
pub(crate) fn read(
    file: &str,
    document: &Value,
    b: &mut Builder,
    labels: &mut BTreeMap<String, String>,
    items: &mut Vec<LabelItem>,
    extra: &mut Extra,
) {
    let source = |path: &str| Source {
        file: file.to_owned(),
        line: None,
        scope: None,
        kind: ItemKind::Key,
        item: path.to_owned(),
    };
    let Value::Object(top) = document else { return };
    for (section, body) in top {
        let mut all = Vec::new();
        leaves(section, body, &mut all);
        for leaf in all {
            let id = b.item(source(&leaf.path));
            route_leaf(section, &leaf, id, b, labels, items, extra);
        }
    }
    // Servers transports apply to the services that use them.
    let uses = std::mem::take(&mut extra.uses_transport);
    for (service, (transport, id)) in uses {
        if extra.transports.contains_key(&transport) {
            b.account(
                id,
                Finding::new(
                    "traefik.file.exact",
                    format!(
                        "the settings of servers transport `{transport}` are written on the service"
                    ),
                )
                .target(format!("services.{service}")),
            );
            extra.uses_transport.insert(service, (transport, id));
        } else {
            b.account(
                id,
                Finding::new(
                    "traefik.file.manual",
                    format!("servers transport `{transport}` is not in this file: set `tls` and `timeouts` on the service by hand"),
                )
                .target(format!("services.{service}")),
            );
        }
    }
}

/// One leaf, by section.
#[allow(clippy::too_many_lines)]
fn route_leaf(
    section: &str,
    leaf: &Leaf,
    id: ItemId,
    b: &mut Builder,
    labels: &mut BTreeMap<String, String>,
    items: &mut Vec<LabelItem>,
    extra: &mut Extra,
) {
    let path = leaf.path.as_str();
    let parts: Vec<&str> = path.splitn(4, '.').collect();
    let lower_parts: Vec<String> = parts.iter().map(|p| p.to_ascii_lowercase()).collect();
    let kind = lower_parts.get(1).map(String::as_str).unwrap_or_default();
    let name = parts.get(2).copied().unwrap_or_default();
    let rest = parts.get(3).copied().unwrap_or_default();
    let rest_lower = lower(rest);
    let mut as_label = |label_section: &str, object: (&'static str, String)| {
        let key = format!("traefik.{label_section}.{kind}.{name}.{rest}");
        labels.insert(key.clone(), label_text(&leaf.value));
        items.push(LabelItem {
            id,
            container: "dynamic".to_owned(),
            key,
            value: label_text(&leaf.value),
            object: Some(object),
            problems: Vec::new(),
        });
    };
    match (section.to_ascii_lowercase().as_str(), kind) {
        ("http", "routers") if !name.is_empty() && !rest.is_empty() => {
            as_label("http", ("routes", name.to_owned()));
        }
        ("http", "middlewares") if !name.is_empty() && !rest.is_empty() => {
            if rest_lower == "basicauth.usersfile" {
                extra
                    .users_files
                    .insert(name.to_owned(), label_text(&leaf.value));
                b.account(
                    id,
                    Finding::new(
                        "traefik.file.users_file",
                        "`basic_auth.users_file`: the same file, named and never read or copied",
                    )
                    .target(format!("middlewares.{name}.users_file")),
                );
            } else {
                as_label("http", ("middlewares", name.to_owned()));
            }
        }
        ("http", "services") if !name.is_empty() && !rest.is_empty() => {
            http_service(name, rest, &rest_lower, &leaf.value, id, b, extra, &mut as_label);
        }
        ("http", "serverstransports") if !name.is_empty() && !rest.is_empty() => {
            let finding = transport(name, &rest_lower, &leaf.value, extra);
            b.account(id, finding);
        }
        ("tcp", "routers") if !name.is_empty() && !rest.is_empty() => {
            as_label("tcp", ("tcp_routes", name.to_owned()));
        }
        ("tcp", "middlewares") if !name.is_empty() && !rest.is_empty() => {
            as_label("tcp", ("middlewares", name.to_owned()));
        }
        ("tcp", "services") if !name.is_empty() && !rest.is_empty() => {
            let finding = l4_service("tcp", name, &rest_lower, &leaf.value, extra);
            b.account(id, finding);
        }
        ("udp", "routers") if !name.is_empty() && !rest.is_empty() => {
            as_label("udp", ("udp_routes", name.to_owned()));
        }
        ("udp", "services") if !name.is_empty() && !rest.is_empty() => {
            let finding = l4_service("udp", name, &rest_lower, &leaf.value, extra);
            b.account(id, finding);
        }
        ("tls", _) => {
            let finding = tls(path, &leaf.value, extra);
            b.account(id, finding);
        }
        ("tcp", "serverstransports") => b.account(
            id,
            Finding::new(
                "traefik.file.manual",
                "TCP servers transports are not read: set `proxy_protocol` and `timeouts` on the TCP services by hand",
            ),
        ),
        _ => b.account(
            id,
            Finding::new(
                "traefik.file.unsupported",
                "not a key of a Traefik v3.7 dynamic configuration this tool reads",
            ),
        ),
    }
}

/// `http.services.<name>.…`.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn http_service(
    name: &str,
    rest: &str,
    rest_lower: &str,
    value: &Value,
    id: ItemId,
    b: &mut Builder,
    extra: &mut Extra,
    as_label: &mut impl FnMut(&str, (&'static str, String)),
) {
    let target = format!("services.{name}");
    if let Some(server) = rest_lower.strip_prefix("loadbalancer.servers[") {
        let (index, field) = server.split_once("].").unwrap_or((server, ""));
        let index: usize = index.parse().unwrap_or(0);
        let backends = extra.backends.entry(name.to_owned()).or_default();
        while backends.len() <= index {
            backends.push(json!({}));
        }
        let finding = match field {
            "url" => {
                let url = label_text(value);
                match url.split_once("://") {
                    Some((scheme, rest)) => {
                        let (address, path) = rest.split_once('/').unwrap_or((rest, ""));
                        backends[index]["address"] = json!(address);
                        backends[index]["scheme"] = json!(scheme);
                        if path.is_empty() {
                            Finding::new("traefik.file.exact", format!("backend `{address}`"))
                        } else {
                            Finding::new(
                                "traefik.file.manual",
                                format!(
                                    "backend `{address}`: the URL's path `/{path}` is not kept (a backend address carries no path); add an `add_prefix` middleware to the routes if the backend needs it"
                                ),
                            )
                        }
                    }
                    None => Finding::new(
                        "traefik.file.manual",
                        format!("`{url}` is not a URL like `http://host:port`"),
                    ),
                }
            }
            "weight" => {
                backends[index]["weight"] = value.clone();
                Finding::new("traefik.file.exact", "the backend's `weight`")
            }
            "preservepath" => Finding::new(
                "traefik.file.unsupported",
                "a backend address carries no path, so there is none to preserve",
            ),
            _ => Finding::new("traefik.file.unsupported", "not a server option"),
        };
        b.account(id, finding.target(target));
        return;
    }
    if rest_lower == "loadbalancer.serverstransport" {
        extra
            .uses_transport
            .insert(name.to_owned(), (label_text(value), id));
        return;
    }
    if let Some(weighted) = rest_lower.strip_prefix("weighted.") {
        let finding = if let Some(entry) = weighted.strip_prefix("services[") {
            let (index, field) = entry.split_once("].").unwrap_or((entry, ""));
            let index: usize = index.parse().unwrap_or(0);
            let split = extra.splits.entry(name.to_owned()).or_default();
            while split.len() <= index {
                split.push(json!({ "weight": 1 }));
            }
            match field {
                "name" => {
                    split[index]["service"] = json!(label_text(value));
                    Finding::new(
                        "traefik.file.approximate",
                        "a target of `split`: requests are shared by weight, but the order of picks is not Traefik's smooth weighted round robin",
                    )
                }
                "weight" => {
                    split[index]["weight"] = value.clone();
                    Finding::new("traefik.file.exact", "the target's `weight`")
                }
                _ => Finding::new("traefik.file.unsupported", "not a weighted target option"),
            }
        } else {
            Finding::new(
                "traefik.file.unsupported",
                "sticky sessions and health checks of a weighted service are not carried over; set them on the services it splits between",
            )
        };
        b.account(id, finding.target(format!("{target}.split")));
        return;
    }
    if rest_lower.starts_with("mirroring.") {
        b.account(
            id,
            Finding::new(
                "traefik.file.manual",
                "mirroring services are not translated: set `mirror` (a service and a percentage) on the routes that use this service",
            )
            .target(target),
        );
        return;
    }
    if rest_lower.starts_with("failover.") {
        b.account(
            id,
            Finding::new(
                "traefik.file.manual",
                "failover services are not translated: give the fallback's servers `backup: true` (or a `priority`) in one service",
            )
            .target(target),
        );
        return;
    }
    if rest_lower.starts_with("highestrandomweight.") {
        b.account(
            id,
            Finding::new(
                "traefik.file.manual",
                "highest-random-weight services are not translated: one service with `load_balancer.policy: ip_hash` is the nearest",
            )
            .target(target),
        );
        return;
    }
    // `loadBalancer.*`: the same settings as the labels.
    let _ = rest;
    as_label("http", ("services", name.to_owned()));
}

/// `http.serversTransports.<name>.…` as service settings.
fn transport(name: &str, rest: &str, value: &Value, extra: &mut Extra) -> Finding {
    let settings = extra.transports.entry(name.to_owned()).or_default();
    let mut put = |section: &str, field: &str, v: Value| {
        let entry = settings
            .entry(section.to_owned())
            .or_insert_with(|| json!({}));
        if let Value::Object(map) = entry {
            map.entry(field.to_owned()).or_insert(v);
        }
    };
    match rest {
        "servername" => {
            put("tls", "server_name", json!(label_text(value)));
            Finding::new(
                "traefik.file.exact",
                "`tls.server_name` of the services that use it",
            )
        }
        "insecureskipverify" => {
            let off = label_text(value) == "true";
            put("tls", "verify", json!(!off));
            let finding = Finding::new(
                "traefik.file.exact",
                format!("`tls.verify: {}` of the services that use it", !off),
            );
            if off { finding.security() } else { finding }
        }
        "rootcas" => {
            let cas: Vec<String> = label_text(value).split(',').map(str::to_owned).collect();
            if cas.len() == 1 {
                put("tls", "ca_file", json!(cas[0]));
                Finding::new(
                    "traefik.file.exact",
                    "`tls.ca_file` of the services that use it",
                )
            } else {
                put("tls", "ca_file", json!(cas[0]));
                Finding::new(
                    "traefik.file.manual",
                    "`tls.ca_file` takes one bundle: the first file is used; concatenate the others into it",
                )
            }
        }
        "certificates[0].certfile" => {
            put("tls", "cert_file", json!(label_text(value)));
            Finding::new("traefik.file.exact", "`tls.cert_file` (client certificate)")
        }
        "certificates[0].keyfile" => {
            put("tls", "key_file", json!(label_text(value)));
            Finding::new("traefik.file.exact", "`tls.key_file` (client key)")
        }
        r if r.starts_with("certificates[") => Finding::new(
            "traefik.file.manual",
            "one client certificate per service: only the first is written",
        ),
        "forwardingtimeouts.dialtimeout" => {
            put("timeouts", "connect", duration(value));
            Finding::new(
                "traefik.file.exact",
                "`timeouts.connect` of the services that use it",
            )
        }
        "forwardingtimeouts.responseheadertimeout" => {
            put("timeouts", "read", duration(value));
            Finding::new(
                "traefik.file.approximate",
                "`timeouts.read`: the longest wait for any response data, not only for the headers",
            )
        }
        "forwardingtimeouts.idleconntimeout" => {
            put("timeouts", "idle", duration(value));
            Finding::new(
                "traefik.file.exact",
                "`timeouts.idle` of the services that use it",
            )
        }
        _ => Finding::new(
            "traefik.file.unsupported",
            "this transport setting has no equivalent (TLS versions, ciphers, SPIFFE, peer URI, connection pool and HTTP/2 switches are ReverseDock's)",
        ),
    }
}

/// A Traefik duration (`30s`, or a number of seconds) as ours.
fn duration(value: &Value) -> Value {
    match value {
        Value::Number(n) => json!(format!("{n}s")),
        other => json!(label_text(other)),
    }
}

/// `tcp.services.<name>.…` and `udp.services.<name>.…`.
fn l4_service(protocol: &str, name: &str, rest: &str, value: &Value, extra: &mut Extra) -> Finding {
    let services = if protocol == "tcp" {
        &mut extra.tcp_services
    } else {
        &mut extra.udp_services
    };
    let service = services
        .entry(name.to_owned())
        .or_insert_with(|| json!({ "backends": [] }));
    let target = format!("{protocol}_services.{name}");
    if let Some(server) = rest.strip_prefix("loadbalancer.servers[") {
        let (index, field) = server.split_once("].").unwrap_or((server, ""));
        let index: usize = index.parse().unwrap_or(0);
        let Some(Value::Array(backends)) = service.get_mut("backends") else {
            return Finding::new("traefik.file.unsupported", "unexpected service");
        };
        while backends.len() <= index {
            backends.push(json!({}));
        }
        return match field {
            "address" => {
                backends[index]["address"] = json!(label_text(value));
                Finding::new("traefik.file.exact", "a backend").target(target)
            }
            "weight" => {
                backends[index]["weight"] = value.clone();
                Finding::new("traefik.file.exact", "the backend's `weight`").target(target)
            }
            "tls" => Finding::new(
                "traefik.file.unsupported",
                "TLS to TCP backends is not offered; the backend gets the bytes as relayed",
            ),
            _ => Finding::new("traefik.file.unsupported", "not a server option"),
        };
    }
    match rest {
        "loadbalancer.proxyprotocol" if protocol == "tcp" => {
            service["proxy_protocol"] = json!("v2");
            Finding::new(
                "traefik.file.exact",
                "`proxy_protocol: v2` (an empty section is version 2)",
            )
            .target(target)
        }
        "loadbalancer.proxyprotocol.version" if protocol == "tcp" => {
            let version = if label_text(value) == "1" { "v1" } else { "v2" };
            service["proxy_protocol"] = json!(version);
            Finding::new("traefik.file.exact", format!("`proxy_protocol: {version}`"))
                .target(target)
        }
        "loadbalancer.terminationdelay" if protocol == "tcp" => match value.as_i64() {
            Some(ms) if ms >= 0 => {
                service["timeouts"] = json!({ "termination_delay": format!("{ms}ms") });
                Finding::new("traefik.file.exact", "`timeouts.termination_delay`").target(target)
            }
            _ => Finding::new(
                "traefik.file.unsupported",
                "a negative termination delay (no deadline) has no equivalent: half-closed connections always get one",
            ),
        },
        _ => Finding::new(
            "traefik.file.unsupported",
            format!(
                "this {} service setting has no equivalent (weighted and transport settings are not read)",
                protocol.to_ascii_uppercase()
            ),
        ),
    }
}

/// `tls.…`: certificates, the default certificate, options and stores.
fn tls(path: &str, value: &Value, extra: &mut Extra) -> Finding {
    let lower = path.to_ascii_lowercase();
    if let Some(entry) = lower.strip_prefix("tls.certificates[") {
        let (index, field) = entry.split_once("].").unwrap_or((entry, ""));
        let name = format!("cert-{index}");
        let cert = extra
            .certificates
            .entry(name.clone())
            .or_insert_with(|| json!({}));
        return match field {
            "certfile" => {
                cert["cert_file"] = json!(label_text(value));
                Finding::new(
                    "traefik.file.exact",
                    "a certificate, served for the names it holds",
                )
                .target(format!("certificates.{name}"))
            }
            "keyfile" => {
                cert["key_file"] = json!(label_text(value));
                Finding::new("traefik.file.exact", "the certificate's key")
                    .target(format!("certificates.{name}"))
            }
            "stores" => Finding::new(
                "traefik.file.unsupported",
                "there is one certificate store; every certificate is in it",
            ),
            _ => Finding::new("traefik.file.unsupported", "not a certificate option"),
        };
    }
    if let Some(field) = lower.strip_prefix("tls.stores.default.defaultcertificate.") {
        let cert = extra
            .certificates
            .entry("default".to_owned())
            .or_insert_with(|| json!({}));
        extra.default_certificate = Some("default".to_owned());
        return match field {
            "certfile" => {
                cert["cert_file"] = json!(label_text(value));
                Finding::new(
                    "traefik.file.approximate",
                    "written as `certificates.default`; it is the fallback certificate once `defaults.certificate: default` is set (written with `--full`)",
                )
                .target("certificates.default")
            }
            "keyfile" => {
                cert["key_file"] = json!(label_text(value));
                Finding::new("traefik.file.exact", "the default certificate's key")
                    .target("certificates.default")
            }
            _ => Finding::new("traefik.file.unsupported", "not a certificate option"),
        };
    }
    if lower.starts_with("tls.options.") {
        return Finding::new(
            "traefik.file.manual",
            "TLS options are listener settings here: set `listeners.<name>.tls.policy` (`modern` or `intermediate`) and `client_auth`",
        );
    }
    if lower.starts_with("tls.stores.") {
        return Finding::new(
            "traefik.file.unsupported",
            "a generated default certificate has no equivalent; set `defaults.certificate`",
        );
    }
    Finding::new(
        "traefik.file.unsupported",
        "not a TLS option this tool reads",
    )
}
