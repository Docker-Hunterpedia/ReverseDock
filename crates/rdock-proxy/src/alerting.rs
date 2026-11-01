//! Backend and service alerts (ADR-0024): raised when health changes, off the request path's
//! hot part (only on a state change), and never waiting.

use std::time::Instant;

use rdock_balancer::Availability;
use rdock_model::settings::AlertRule;
use rdock_observability::Metrics;
use rdock_observability::alerts::Alert;
use serde_json::json;

use crate::runtime::{Member, ServiceRuntime};

fn service_down(service: &ServiceRuntime) -> bool {
    let now = Instant::now();
    service
        .members()
        .iter()
        .all(|m| m.state.availability(now) == Availability::Down || m.state.is_drained())
}

pub(crate) fn backend_down(
    metrics: &Metrics,
    service: &ServiceRuntime,
    member: &Member,
    reason: &str,
) {
    let sink = &metrics.feeds.alerts;
    sink.raise(Alert::firing(
        AlertRule::Backends,
        format!("backend:{}/{}", service.name, member.id),
        format!("Backend {} of service {} is down: {reason}", member.id, service.name),
        json!({ "event": "backend_down", "service": &*service.name, "backend": member.id, "reason": reason }),
    ));
    if service_down(service) {
        sink.raise(Alert::firing(
            AlertRule::Backends,
            format!("service:{}", service.name),
            format!("Service {} has no healthy backend", service.name),
            json!({ "event": "service_down", "service": &*service.name }),
        ));
    }
}

pub(crate) fn backend_up(metrics: &Metrics, service: &ServiceRuntime, member: &Member) {
    let sink = &metrics.feeds.alerts;
    sink.raise(Alert::resolved(
        AlertRule::Backends,
        format!("backend:{}/{}", service.name, member.id),
        format!("Backend {} of service {} is back", member.id, service.name),
    ));
    sink.raise(Alert::resolved(
        AlertRule::Backends,
        format!("service:{}", service.name),
        format!("Service {} has a healthy backend again", service.name),
    ));
}
