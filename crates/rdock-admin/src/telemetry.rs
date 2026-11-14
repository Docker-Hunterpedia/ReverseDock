//! The admin side's own metrics (ADR-0024), appended to `/metrics`:
//! `rdock_admin_requests_total{endpoint,status_class}`, `rdock_admin_login_failures_total`, `rdock_admin_audit_write_failures_total`,
//! `rdock_admin_audit_refusals_total`,
//! `rdock_admin_sse_subscribers{stream}` and `rdock_admin_sse_dropped_events_total{stream}`.

use std::collections::BTreeMap;
use std::fmt::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use axum::extract::{MatchedPath, Request, State as Extract};
use axum::middleware::Next;
use axum::response::Response;

use crate::State;

/// Counters kept by the admin runtime; never touched by the request path.
#[derive(Default)]
pub(crate) struct Telemetry {
    requests: Mutex<BTreeMap<(String, &'static str), u64>>,
    login_failures: AtomicU64,
}

impl Telemetry {
    pub(crate) fn login_failed(&self) {
        self.login_failures.fetch_add(1, Ordering::Relaxed);
    }

    fn request(&self, endpoint: String, status: u16) {
        let class = rdock_observability::status_class(status);
        *self
            .requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry((endpoint, class))
            .or_default() += 1;
    }
}

/// Counts every admin request by its route pattern (never the raw path, which could hold
/// names) and status class.
pub(crate) async fn count(
    Extract(state): Extract<Arc<State>>,
    request: Request,
    next: Next,
) -> Response {
    let endpoint = request
        .extensions()
        .get::<MatchedPath>()
        .map_or_else(|| "other".to_owned(), |p| p.as_str().to_owned());
    let response = next.run(request).await;
    state
        .telemetry
        .request(endpoint, response.status().as_u16());
    response
}

/// The admin metrics: name, type, help text and label names. [`render`] writes their `# HELP`
/// and `# TYPE` lines from here, and [`metric_catalogue`] lists them for the compatibility
/// snapshot (ADR-0033).
const METRICS: [(&str, &str, &str, &[&str]); 6] = [
    (
        "rdock_admin_requests_total",
        "counter",
        "Admin API requests by endpoint and status class.",
        &["endpoint", "status_class"],
    ),
    (
        "rdock_admin_login_failures_total",
        "counter",
        "Failed admin logins.",
        &[],
    ),
    (
        "rdock_admin_audit_write_failures_total",
        "counter",
        "Audit records that could not be written.",
        &[],
    ),
    (
        "rdock_admin_audit_refusals_total",
        "counter",
        "Mutating admin calls refused because their audit record could not be written.",
        &[],
    ),
    (
        "rdock_admin_sse_subscribers",
        "gauge",
        "Open live streams.",
        &["stream"],
    ),
    (
        "rdock_admin_sse_dropped_events_total",
        "counter",
        "Live entries not delivered because a reader fell behind.",
        &["stream"],
    ),
];

/// The admin metrics appended to `/metrics`, as the compatibility snapshot lists metrics.
#[must_use]
pub fn metric_catalogue() -> Vec<rdock_observability::MetricInfo> {
    METRICS
        .iter()
        .map(|(name, kind, help, labels)| {
            rdock_observability::MetricInfo::new(name, kind, help, labels)
        })
        .collect()
}

/// Writes the `# HELP` and `# TYPE` lines of `METRICS[index]`.
fn header(out: &mut String, index: usize) {
    if let Some((name, kind, help, _)) = METRICS.get(index) {
        let _ = writeln!(out, "# HELP {name} {help}");
        let _ = writeln!(out, "# TYPE {name} {kind}");
    }
}

/// The Prometheus text of the admin metrics.
pub(crate) fn render(state: &State) -> String {
    let mut out = String::new();
    header(&mut out, 0);
    for ((endpoint, class), n) in state
        .telemetry
        .requests
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .iter()
    {
        let _ = writeln!(
            out,
            "rdock_admin_requests_total{{endpoint=\"{endpoint}\",status_class=\"{class}\"}} {n}"
        );
    }
    header(&mut out, 1);
    let _ = writeln!(
        out,
        "rdock_admin_login_failures_total {}",
        state.telemetry.login_failures.load(Ordering::Relaxed)
    );
    header(&mut out, 2);
    let _ = writeln!(
        out,
        "rdock_admin_audit_write_failures_total {}",
        state.audit.write_failures()
    );
    header(&mut out, 3);
    let _ = writeln!(
        out,
        "rdock_admin_audit_refusals_total {}",
        state.audit.refusals()
    );
    header(&mut out, 4);
    header(&mut out, 5);
    for (name, hub) in [("logs", &state.logs), ("events", &state.events)] {
        let _ = writeln!(
            out,
            "rdock_admin_sse_subscribers{{stream=\"{name}\"}} {}",
            hub.subscribers()
        );
        let _ = writeln!(
            out,
            "rdock_admin_sse_dropped_events_total{{stream=\"{name}\"}} {}",
            hub.dropped()
        );
    }
    out
}
