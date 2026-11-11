//! The Traefik `udp.*` label subset (M-L4-04, ADR-0030): a router's entry points and service,
//! and the load balancer's server port.
//!
//! Label names follow Traefik's Docker provider reference
//! (<https://doc.traefik.io/traefik/reference/routing-configuration/other-providers/docker/>,
//! checked 2026-11-11). Traefik's UDP routers have no rule, priority or middlewares, and its
//! UDP session timeout is an entry point setting (`entryPoints.<name>.udp.timeout`, static
//! configuration, default 3 s), which labels cannot carry: sessions here end after the UDP
//! service's `timeouts.idle` (60 s by default). Every other `traefik.udp.*` label is reported.

use serde_json::Value;

use super::native::port;
use super::traefik::{listeners, split, unsupported};
use super::{Draft, Scope};

/// Adds one `traefik.udp.*` label (`rest` is the part after `traefik.udp.`) to the draft.
pub(super) fn label(
    scope: &Scope<'_>,
    draft: &mut Draft,
    rest: &str,
    value: &str,
) -> Result<(), String> {
    if let Some(rest) = rest.strip_prefix("routers.") {
        let (name, field) = split(rest)?;
        let (field, value) = match field {
            "entrypoints" => ("listeners", listeners(scope, value)),
            "service" => ("service", Value::String(value.to_owned())),
            _ => return Err(unsupported()),
        };
        draft
            .udp_routes
            .entry(name.to_owned())
            .or_default()
            .set(field, value)
    } else if let Some(rest) = rest.strip_prefix("services.") {
        let (name, field) = split(rest)?;
        if field != "loadbalancer.server.port" {
            return Err(unsupported());
        }
        let port = port(value)?;
        draft.udp_services.entry(name.to_owned()).or_default().port = Some(port);
        Ok(())
    } else {
        Err(unsupported())
    }
}
