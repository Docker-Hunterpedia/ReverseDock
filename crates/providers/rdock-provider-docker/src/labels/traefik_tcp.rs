//! The Traefik `tcp.*` label subset (M-L4-01, ADR-0026): routers, the load balancer's server
//! port, and the `ipAllowList` and `inFlightConn` middlewares.
//!
//! Label names follow Traefik's Docker provider reference
//! (<https://doc.traefik.io/traefik/reference/routing-configuration/other-providers/docker/>,
//! checked 2026-11-06). A router's `tls` terminates TLS with the listener's settings and
//! `tls.passthrough=true` relays it untouched; Traefik's TLS options, certificate resolvers and
//! servers transports have no counterpart on TCP routes and are reported.

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
        _ => Err(unsupported()),
    }
}

fn middleware(draft: &mut Draft, name: &str, field: &str, value: &str) -> Result<(), String> {
    let (our_type, our_field, value) = match field {
        "ipallowlist.sourcerange" => ("ip_allow", "cidrs", list(value)),
        "inflightconn.amount" => ("in_flight", "amount", scalar(value)),
        _ => return Err(unsupported()),
    };
    let tree = draft.middlewares.entry(name.to_owned()).or_default();
    set_type(tree, our_type)?;
    tree.set(our_field, value)
}
