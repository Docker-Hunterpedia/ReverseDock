//! Compilation of `udp_routes` and `udp_services` onto the `udp` listeners they name.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use arc_swap::ArcSwapOption;
use rdock_balancer::{Balancer, EjectPolicy, HashRing, ProbePolicy, RoundRobin};
use rdock_model::config::{Config, ListenerProtocol};
use rdock_model::diagnostics::{Diagnostic, path_key};
use rdock_model::middleware::Middleware;
use rdock_model::route::UdpRoute;
use rdock_model::service::{HealthMode, UdpLbPolicy, UdpService, WhenAllDown};

use super::{UdpFilter, UdpRouteRuntime, UdpServiceRuntime};
use crate::compile::{CompileEnv, compile_backends, key};
use crate::runtime::{ActiveCheck, HashOn, HealthRuntime, ListenerRuntime, ServiceRuntime};
use crate::tcp::rule::TcpRule;

/// Compiles every enabled UDP route onto its `udp` listeners, in evaluation order: priority,
/// then rule length, then name. Returns the backend pools, for active health checks.
pub(crate) fn compile_udp(
    config: &Config,
    env: &CompileEnv<'_>,
    listeners: &mut BTreeMap<String, ListenerRuntime>,
    geoip: Option<&Arc<crate::geoip::GeoIp>>,
    out: &mut Vec<Diagnostic>,
) -> BTreeMap<String, Arc<ServiceRuntime>> {
    let services: HashMap<&str, Arc<UdpServiceRuntime>> = config
        .udp_services
        .iter()
        .map(|(name, service)| {
            (
                name.as_str(),
                Arc::new(compile_service(name, service, config, env)),
            )
        })
        .collect();
    let mut attached: BTreeMap<&str, Vec<Arc<UdpRouteRuntime>>> = BTreeMap::new();
    for (name, route) in config.udp_routes.iter().filter(|(_, r)| r.enabled) {
        let Some(compiled) = compile_route(name, route, config, &services, geoip, out) else {
            continue;
        };
        for listener_name in route.listeners.iter().flatten() {
            if listeners
                .get(listener_name)
                .is_some_and(|l| l.protocol == ListenerProtocol::Udp)
            {
                attached
                    .entry(listener_name)
                    .or_default()
                    .push(compiled.clone());
            }
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
            listener.udp_routes = routes.into();
        }
    }
    services
        .into_iter()
        .map(|(name, service)| (name.to_owned(), service.pool.clone()))
        .collect()
}

fn compile_service(
    name: &str,
    service: &UdpService,
    config: &Config,
    env: &CompileEnv<'_>,
) -> UdpServiceRuntime {
    let (balancer, hash_on) = match service.load_balancer.policy {
        UdpLbPolicy::RoundRobin => (Balancer::RoundRobin(RoundRobin::default()), HashOn::Nothing),
        UdpLbPolicy::Random => (Balancer::Random, HashOn::Nothing),
        UdpLbPolicy::LeastSessions => (Balancer::LeastRequests, HashOn::Nothing),
        UdpLbPolicy::IpHash => (Balancer::Hash(Box::<HashRing>::default()), HashOn::ClientIp),
    };
    let health = &service.health;
    let active = health.tcp_check.map(|check| ActiveCheck {
        mode: HealthMode::Tcp,
        method: http::Method::GET,
        path: String::new(),
        hostname: None,
        headers: Vec::new(),
        expected_status: (200, 399),
        expected_body: None,
        grpc_service: String::new(),
        port: check.port,
        interval: check.interval.as_std(),
        timeout: check.timeout.as_std(),
        policy: ProbePolicy {
            healthy: check.healthy,
            unhealthy: check.unhealthy,
        },
    });
    let pool = ServiceRuntime {
        name: Arc::from(name),
        scheme: rdock_model::service::Scheme::default(),
        backends: compile_backends(&service.backends, env.dns),
        balancer,
        hash_on,
        sticky: None,
        // `:` cannot appear in names, so UDP, TCP and HTTP services never share backend state.
        pool: env.backends.pool(&format!("udp:{name}")),
        live: Arc::default(),
        health: HealthRuntime {
            active,
            passive: None,
            fail_open: health.when_all_down == WhenAllDown::FailOpen,
            slow_start: None,
        },
        split: Vec::new(),
        split_balancer: RoundRobin::default(),
        respond: None,
        retries: None,
        max_requests: None,
        max_per_backend: None,
        members: ArcSwapOption::empty(),
        timeouts: rdock_model::service::Timeouts::default(),
        tls: crate::runtime::UpstreamTls::default(),
        pass_host_header: false,
        allowed: crate::compile::label_guard(name, config, env),
        selection: crate::runtime::Selection {
            zone: crate::compile::preferred_zone(config, None),
            ..crate::runtime::Selection::default()
        },
    };
    let passive = health.passive;
    UdpServiceRuntime {
        name: Arc::from(name),
        pool: Arc::new(pool),
        idle: service.timeouts.idle.as_std(),
        responses: service.responses,
        requests: service.requests,
        passive: passive.enabled.then_some((
            EjectPolicy {
                failures: passive.failures,
                window: passive.window.as_std(),
                ejection: passive.ejection.as_std(),
                jitter: std::time::Duration::ZERO,
            },
            passive.max_ejection_percent,
        )),
    }
}

fn compile_route(
    name: &str,
    route: &UdpRoute,
    config: &Config,
    services: &HashMap<&str, Arc<UdpServiceRuntime>>,
    geoip: Option<&Arc<crate::geoip::GeoIp>>,
    out: &mut Vec<Diagnostic>,
) -> Option<Arc<UdpRouteRuntime>> {
    let path = path_key("udp_routes", name);
    let rule = match &route.matcher {
        None => None,
        Some(text) => {
            let compiled = rdock_rules::parse(text)
                .map_err(|e| e.kind.to_string())
                .and_then(|expr| {
                    let errors = expr.validate(rdock_rules::Context::Udp);
                    if let Some(err) = errors.first() {
                        return Err(err.to_string());
                    }
                    TcpRule::compile_with(&expr, geoip).map_err(|e| e.to_string())
                });
            match compiled {
                Ok(rule) => Some(rule),
                Err(message) => {
                    out.push(Diagnostic::error(format!("{path}.match"), message));
                    return None;
                }
            }
        }
    };
    let Some(service) = services.get(key(&route.service)) else {
        out.push(Diagnostic::error(
            format!("{path}.service"),
            format!("UDP service `{}` does not exist", route.service),
        ));
        return None;
    };
    let filters = route
        .middlewares
        .iter()
        .map(|reference| match config.middlewares.get(key(reference)) {
            Some(Middleware::IpAllow(list)) => Ok(UdpFilter::Allow(list.cidrs.clone())),
            Some(Middleware::IpDeny(list)) => Ok(UdpFilter::Deny(list.cidrs.clone())),
            Some(_) => Err(format!(
                "middleware `{reference}` does not apply to UDP routes"
            )),
            None => Err(format!("middleware `{reference}` does not exist")),
        })
        .collect::<Result<Vec<_>, String>>();
    let filters = match filters {
        Ok(filters) => filters,
        Err(message) => {
            out.push(Diagnostic::error(format!("{path}.middlewares"), message));
            return None;
        }
    };
    let length = route.matcher.as_ref().map_or(0, String::len);
    Some(Arc::new(UdpRouteRuntime {
        name: Arc::from(name),
        priority: if route.priority == 0 {
            i64::try_from(length).unwrap_or(i64::MAX)
        } else {
            route.priority
        },
        length,
        rule,
        service: service.clone(),
        filters: filters.into(),
    }))
}
