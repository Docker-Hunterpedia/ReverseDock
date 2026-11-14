//! The Traefik `tcp.*` label subset (M-L4-01, ADR-0026): routers, the load balancer's server
//! port, and the `ipAllowList` and `inFlightConn` middlewares.
//!
//! Label names follow Traefik's Docker provider reference
//! (<https://doc.traefik.io/traefik/reference/routing-configuration/other-providers/docker/>,
//! checked 2026-11-06). A router's `tls` terminates TLS with the listener's settings and
//! `tls.passthrough=true` relays it untouched; Traefik's TLS options, certificate resolvers and
//! servers transports have no counterpart on TCP routes and are reported. The PROXY protocol
//! version and the termination delay of a TCP service, and the `ipWhiteList` alias, follow the
//! v3.7 label list and TCP servers transport page
//! (<https://doc.traefik.io/traefik/reference/routing-configuration/tcp/serverstransport/>,
//! read 2026-11-14): an empty `proxyProtocol` means version 2, and the termination delay is
//! the deadline for closing both sides once one has stopped sending, in milliseconds.

use serde_json::Value;

use super::native::port;
use super::traefik::{listeners, set_type, split, unsupported};
use super::tree::{list, scalar};
use super::{Draft, Scope};

/// Adds one `traefik.tcp.*` label (`rest` is the part after `traefik.tcp.`) to the draft.
pub(super) fn label(
    scope: &Scope<'_>,
    draft: &mut Draft,
    rest: &str,
    value: &str,
) -> Result<(), String> {
    if let Some(rest) = rest.strip_prefix("routers.") {
        let (name, field) = split(rest)?;
        router(scope, draft, name, field, value)
    } else if let Some(rest) = rest.strip_prefix("services.") {
        let (name, field) = split(rest)?;
        service(draft, name, field, value)
    } else if let Some(rest) = rest.strip_prefix("middlewares.") {
        let (name, field) = split(rest)?;
        middleware(draft, name, field, value)
    } else {
        Err(unsupported())
    }
}

fn router(
    scope: &Scope<'_>,
    draft: &mut Draft,
    name: &str,
    field: &str,
    value: &str,
) -> Result<(), String> {
    let route = draft.tcp_routes.entry(name.to_owned()).or_default();
    match field {
        "rule" => route.set("match", Value::String(value.to_owned())),
        "priority" => route.set("priority", scalar(value)),
        "service" => route.set("service", Value::String(value.to_owned())),
        "middlewares" => route.set("middlewares", list(value)),
        "entrypoints" => route.set("listeners", listeners(scope, value)),
        "tls" => match value {
            "true" => route.set("tls", Value::Object(serde_json::Map::new())),
            "false" => Ok(()),
            other => Err(format!("`{other}` is not `true` or `false`")),
        },
        "tls.passthrough" => match value {
            "true" | "false" => route.set("tls.passthrough", scalar(value)),
            other => Err(format!("`{other}` is not `true` or `false`")),
        },
        "tls.options" | "tls.certresolver" => Err(format!(
            "`{field}` is not supported on TCP routers: the listener's TLS settings and certificates are used"
        )),
        _ if field.starts_with("tls.domains[") => Err(
            "`tls.domains` is not supported on TCP routers: certificates follow the `HostSNI` names"
                .to_owned(),
        ),
        _ => Err(unsupported()),
    }
}

fn service(draft: &mut Draft, name: &str, field: &str, value: &str) -> Result<(), String> {
    let service = draft.tcp_services.entry(name.to_owned()).or_default();
    match field {
        "loadbalancer.server.port" => {
            service.port = Some(port(value)?);
            Ok(())
        }
        "loadbalancer.server.tls" => Err(
            "TLS to TCP backends is not supported; the backend gets the bytes as relayed"
                .to_owned(),
        ),
        "loadbalancer.serverstransport" => Err(
            "servers transports are not supported on TCP services; the defaults are used"
                .to_owned(),
        ),
        "loadbalancer.proxyprotocol" => match value {
            "true" if service.tree.has("proxy_protocol") => Ok(()),
            "true" => service
                .tree
                .set("proxy_protocol", Value::String("v2".to_owned())),
            "false" => Ok(()),
            other => Err(format!("`{other}` is not `true` or `false`")),
        },
        "loadbalancer.proxyprotocol.version" => {
            let version = match value.trim() {
                "1" => "v1",
                "2" => "v2",
                other => return Err(format!("`{other}` is not `1` or `2`")),
            };
            service
                .tree
                .replace("proxy_protocol", Value::String(version.to_owned()))
        }
        "loadbalancer.terminationdelay" => {
            let millis: i64 = value
                .trim()
                .parse()
                .map_err(|_| format!("`{value}` is not a number of milliseconds"))?;
            if millis < 0 {
                return Err("a negative termination delay (no deadline) has no equivalent: half-closed connections always get one; the label is ignored".to_owned());
            }
            service.tree.set(
                "timeouts.termination_delay",
                Value::String(format!("{millis}ms")),
            )
        }
        _ => Err(unsupported()),
    }
}

fn middleware(draft: &mut Draft, name: &str, field: &str, value: &str) -> Result<(), String> {
    let (our_type, our_field, value) = match field {
        "ipallowlist.sourcerange" | "ipwhitelist.sourcerange" => ("ip_allow", "cidrs", list(value)),
        "inflightconn.amount" => ("in_flight", "amount", scalar(value)),
        _ => return Err(unsupported()),
    };
    let tree = draft.middlewares.entry(name.to_owned()).or_default();
    set_type(tree, our_type)?;
    tree.set(our_field, value)
}
