//! Explains a routing decision without sending a request (ADR-0024, "Explaining routing
//! decisions"): every route of a listener in evaluation order with why it does or does not
//! match, the winner, its middlewares with the pipeline phases each uses (ADR-0030), and the
//! backends its service would consider with why others are out.
//! Runs on the admin runtime against the live snapshot, never on the request path.

use std::net::IpAddr;
use std::time::Instant;

use http::HeaderMap;
use serde_json::{Value, json};

use crate::router::{Facts, normalize_host};
use crate::runtime::{RouteRuntime, Runtime};

/// The request to explain.
#[derive(Debug, Default)]
pub struct Request {
    /// `Host`, with or without port.
    pub host: String,
    /// Path as sent, query allowed.
    pub path: String,
    /// Method; `GET` when empty.
    pub method: String,
    /// Headers.
    pub headers: HeaderMap,
    /// Client address after the trusted-proxy rules.
    pub client_ip: Option<IpAddr>,
}

/// The decision for `request` on `listener`, or why it cannot be explained.
pub fn explain(runtime: &Runtime, listener: &str, request: &Request) -> Result<Value, String> {
    let Some(listener) = runtime.listeners.get(listener) else {
        let names: Vec<&String> = runtime.listeners.keys().collect();
        return Err(format!("no listener `{listener}`; listeners: {names:?}"));
    };
    let (path, query) = request.path.split_once('?').unwrap_or((&request.path, ""));
    let path = if path.is_empty() { "/" } else { path };
    let normalized =
        rdock_rules::path::normalize(path).map_err(|_| "the path is not valid".to_owned())?;
    let query: Vec<(String, String)> = url::form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect();
    let host = normalize_host(
        request
            .host
            .rsplit_once(':')
            .filter(|(h, port)| !h.ends_with(']') || port.is_empty())
            .map_or(&request.host, |(h, _)| h),
    );
    let method = if request.method.is_empty() {
        "GET".to_owned()
    } else {
        request.method.to_ascii_uppercase()
    };
    let client_ip = request.client_ip.unwrap_or(IpAddr::from([127, 0, 0, 1]));
    let facts = Facts {
        host: &host,
        path: &normalized.routing,
        method: &method,
        headers: &request.headers,
        query: &query,
        client_ip,
    };
    let mut winner = None;
    let routes: Vec<Value> = listener
        .routes
        .iter()
        .map(|route| {
            let reason = route.rule.explain(&facts);
            match (&reason, &winner) {
                (None, None) => {
                    winner = Some(route.clone());
                    json!({ "name": &*route.name, "priority": route.priority, "rule": route.expr, "result": "matched" })
                }
                (None, Some(first)) => json!({
                    "name": &*route.name, "priority": route.priority, "rule": route.expr, "result": "shadowed",
                    "reason": format!("it matches too, but `{}` comes first (higher priority)", first.name),
                }),
                (Some(reason), _) => json!({
                    "name": &*route.name, "priority": route.priority, "rule": route.expr, "result": "no match", "reason": reason,
                }),
            }
        })
        .collect();
    let now = Instant::now();
    let outcome = match &winner {
        Some(route) => route_outcome(route, now),
        None if listener
            .https_redirect
            .as_ref()
            .is_some_and(|r| r.hosts.contains(&host)) =>
        {
            json!({ "result": "https redirect", "reason": "no route on this plain-HTTP listener; the host has a route on an HTTPS listener" })
        }
        None => json!({ "result": "404", "reason": "no route matches" }),
    };
    Ok(json!({
        "listener": &*listener.name,
        "request": { "host": host, "path": normalized.routing, "method": method, "client_ip": client_ip },
        "routes": routes,
        "outcome": outcome,
    }))
}

/// Each middleware of the route with the phases it runs in, in list order. `request`,
/// `upstream_request` and `request_body` run in this order; `response`, `response_body` and
/// `log` in reverse.
fn phases(route: &RouteRuntime) -> Vec<Value> {
    route
        .middlewares
        .capabilities()
        .map(|(name, caps)| {
            let mut entry = json!({
                "middleware": name,
                "phases": caps.phases().names().collect::<Vec<_>>(),
            });
            if let Some(hold) = caps.body() {
                entry["hold_body"] = json!({
                    "max": hold.max,
                    "timeout_ms": u64::try_from(hold.timeout.as_millis()).unwrap_or(u64::MAX),
                    "replaces": hold.replaces,
                });
            }
            entry
        })
        .collect()
}

/// The outcome for the winning route: its service and the backends it would consider.
fn route_outcome(route: &RouteRuntime, now: Instant) -> Value {
    let Some(service) = &route.service else {
        return json!({
            "result": "route", "route": &*route.name,
            "reason": "the route's middlewares answer every request; it has no service",
            "middlewares": route.middlewares.names().collect::<Vec<_>>(),
            "phases": phases(route),
        });
    };
    let backends: Vec<Value> = service
        .members()
        .iter()
        .map(|m| {
            let exclusion = m.state.exclusion(now);
            // The weight while ramping, to two decimals.
            let ramp = m
                .state
                .ramp(service.health.slow_start.as_ref(), now)
                .map(|f| (f64::from(m.weight) * f * 100.0).round() / 100.0);
            let latency = service.selection.peak.and_then(|p| {
                m.state
                    .latency()
                    .peek(p.decay, now)
                    .map(|d| (d.as_secs_f64() * 1e6).round() / 1e3)
            });
            json!({
                "address": m.id,
                "weight": m.weight,
                "backup": m.backup,
                "priority": m.priority,
                "local": service.selection.zone.is_some().then_some(m.local),
                "latency_ms": latency,
                "considered": exclusion.is_none() && m.weight > 0,
                "reason": exclusion
                    .or_else(|| (m.weight == 0).then(|| "weight 0".to_owned()))
                    .or_else(|| m.backup.then(|| "backup: used only when no primary backend is available".to_owned())),
                "slow_start_weight": ramp,
                "in_flight": m.state.in_flight(),
            })
        })
        .collect();
    json!({
        "result": "route", "route": &*route.name, "service": &*service.name,
        "middlewares": route.middlewares.names().collect::<Vec<_>>(),
        "phases": phases(route),
        "backends": backends,
    })
}
