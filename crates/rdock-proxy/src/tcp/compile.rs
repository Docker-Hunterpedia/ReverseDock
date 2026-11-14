//! Compilation of `tcp_routes` and `tcp_services` onto the listeners they name.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use arc_swap::ArcSwapOption;
use rdock_balancer::{Balancer, RoundRobin};
use rdock_limits::ConcurrencyLimiter;
use rdock_model::config::{Config, ListenerProtocol};
use rdock_model::diagnostics::{Diagnostic, path_key};
use rdock_model::middleware::Middleware;
use rdock_model::route::TcpRoute;
use rdock_model::service::TcpService;
use rdock_rules::Expr;

use super::rule::TcpRule;
use super::{TcpFilter, TcpMode, TcpRouteRuntime, TcpServiceRuntime};
use crate::compile::{AutoTls, CompileEnv, compile_backends, key};
use crate::runtime::{HashOn, HealthRuntime, ListenerRuntime, ServiceRuntime, UpstreamTls};

/// Client addresses an `in_flight` limit of a TCP route tracks at once.
const IN_FLIGHT_KEYS: usize = 65_536;

/// Compiles every TCP route onto its listeners, in evaluation order: priority, then rule
/// length, then name. Terminating routes ask for certificates for their `HostSNI` names.
pub(crate) fn compile_tcp(
    config: &Config,
    env: &CompileEnv<'_>,
    listeners: &mut BTreeMap<String, ListenerRuntime>,
    auto_tls: &mut AutoTls<'_>,
    geoip: Option<&Arc<crate::geoip::GeoIp>>,
    out: &mut Vec<Diagnostic>,
) {
    let services: HashMap<&str, Arc<TcpServiceRuntime>> = config
        .tcp_services
        .iter()
        .map(|(name, service)| {
            (
                name.as_str(),
                Arc::new(compile_service(name, service, config, env)),
            )
        })
        .collect();
    let mut attached: BTreeMap<&str, Vec<Arc<TcpRouteRuntime>>> = BTreeMap::new();
    for (name, route) in &config.tcp_routes {
        let path = path_key("tcp_routes", name);
        let Some((expr, compiled)) = compile_route(name, route, config, &services, geoip, out)
        else {
            continue;
        };
        let mut wants_certificate = false;
        for listener_name in route.listeners.iter().flatten() {
            let Some(listener) = listeners.get(listener_name) else {
                continue;
            };
            if matches!(
                listener.protocol,
                ListenerProtocol::Tcp | ListenerProtocol::Https
            ) {
                wants_certificate |= compiled.mode == TcpMode::Terminate && listener.tls.is_some();
                attached
                    .entry(listener_name)
                    .or_default()
                    .push(compiled.clone());
            }
        }
        if wants_certificate {
            auto_tls.sni_route(&path, &expr, config, out);
        }
    }
    for (name, mut routes) in attached {
        routes.sort_by(|a, b| {
            b.priority
                .cmp(&a.priority)
                .then_with(|| b.length.cmp(&a.length))
                .then_with(|| a.name.cmp(&b.name))
        });
        if let Some(listener) = listeners.get_mut(name) {
            listener.tcp_routes = routes.into();
        }
    }
}

fn compile_service(
    name: &str,
    service: &TcpService,
    config: &Config,
    env: &CompileEnv<'_>,
) -> TcpServiceRuntime {
    let pool = ServiceRuntime {
        name: Arc::from(name),
        scheme: rdock_model::service::Scheme::default(),
        backends: compile_backends(&service.backends, env.dns),
        balancer: Balancer::RoundRobin(RoundRobin::default()),
        hash_on: HashOn::Nothing,
        sticky: None,
        // `:` cannot appear in names, so TCP and HTTP services never share backend state.
        pool: env.backends.pool(&format!("tcp:{name}")),
        live: Arc::default(),
        health: HealthRuntime {
            fail_open: true,
            ..HealthRuntime::default()
        },
        split: Vec::new(),
        split_balancer: RoundRobin::default(),
        respond: None,
        retries: None,
        max_requests: None,
        max_per_backend: None,
        members: ArcSwapOption::empty(),
        timeouts: rdock_model::service::Timeouts::default(),
        tls: UpstreamTls::default(),
        pass_host_header: false,
        allowed: crate::compile::label_guard(name, config, env),
        selection: crate::runtime::Selection {
            zone: crate::compile::preferred_zone(config, None),
            ..crate::runtime::Selection::default()
        },
    };
    TcpServiceRuntime {
        name: Arc::from(name),
        pool: Arc::new(pool),
        proxy_protocol: service.proxy_protocol,
        timeouts: service.timeouts,
    }
}

fn compile_route(
    name: &str,
    route: &TcpRoute,
    config: &Config,
    services: &HashMap<&str, Arc<TcpServiceRuntime>>,
    geoip: Option<&Arc<crate::geoip::GeoIp>>,
    out: &mut Vec<Diagnostic>,
) -> Option<(Expr, Arc<TcpRouteRuntime>)> {
    let path = path_key("tcp_routes", name);
    let compiled = rdock_rules::parse(&route.matcher)
        .map_err(|e| e.kind.to_string())
        .and_then(|expr| {
            let rule = TcpRule::compile_with(&expr, geoip).map_err(|e| e.to_string())?;
            Ok((expr, rule))
        });
    let (expr, rule) = match compiled {
        Ok(compiled) => compiled,
        Err(message) => {
            out.push(Diagnostic::error(format!("{path}.match"), message));
            return None;
        }
    };
    let Some(service) = services.get(key(&route.service)) else {
        out.push(Diagnostic::error(
            format!("{path}.service"),
            format!("TCP service `{}` does not exist", route.service),
        ));
        return None;
    };
    let filters = route
        .middlewares
        .iter()
        .map(|reference| filter(reference, config))
        .collect::<Result<Vec<_>, String>>();
    let filters = match filters {
        Ok(filters) => filters,
        Err(message) => {
            out.push(Diagnostic::error(format!("{path}.middlewares"), message));
            return None;
        }
    };
    let length = route.matcher.len();
    let runtime = TcpRouteRuntime {
        name: Arc::from(name),
        priority: if route.priority == 0 {
            i64::try_from(length).unwrap_or(i64::MAX)
        } else {
            route.priority
        },
        length,
        any_sni: expr.has_any_sni(),
        reads_hello: expr.reads_client_hello() || expr.uses_fingerprint(),
        reads_fingerprint: expr.uses_fingerprint(),
        rule,
        mode: match route.tls {
            None => TcpMode::Relay,
            Some(tls) if tls.passthrough => TcpMode::Passthrough,
            Some(_) => TcpMode::Terminate,
        },
        service: service.clone(),
        filters: filters.into(),
    };
    Some((expr, Arc::new(runtime)))
}

fn filter(reference: &str, config: &Config) -> Result<TcpFilter, String> {
    match config.middlewares.get(key(reference)) {
        Some(Middleware::IpAllow(list)) => Ok(TcpFilter::Allow(list.cidrs.clone())),
        Some(Middleware::IpDeny(list)) => Ok(TcpFilter::Deny(list.cidrs.clone())),
        Some(Middleware::InFlight(limit)) => Ok(TcpFilter::InFlight(ConcurrencyLimiter::new(
            limit.amount,
            limit.queue,
            limit.queue_timeout.as_std(),
            IN_FLIGHT_KEYS,
        ))),
        Some(_) => Err(format!(
            "middleware `{reference}` does not apply to TCP routes"
        )),
        None => Err(format!("middleware `{reference}` does not exist")),
    }
}
