//! The admin side's own metrics (ADR-0024), appended to `/metrics`:
//! `rdock_admin_requests_total{endpoint,status_class}`, `rdock_admin_login_failures_total`,
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

/// The Prometheus text of the admin metrics.
pub(crate) fn render(state: &State) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "# HELP rdock_admin_requests_total Admin API requests by endpoint and status class."
    );
    let _ = writeln!(out, "# TYPE rdock_admin_requests_total counter");
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
    let _ = writeln!(
        out,
        "# HELP rdock_admin_login_failures_total Failed admin logins."
    );
    let _ = writeln!(out, "# TYPE rdock_admin_login_failures_total counter");
    let _ = writeln!(
        out,
        "rdock_admin_login_failures_total {}",
        state.telemetry.login_failures.load(Ordering::Relaxed)
    );
    let _ = writeln!(out, "# HELP rdock_admin_sse_subscribers Open live streams.");
    let _ = writeln!(out, "# TYPE rdock_admin_sse_subscribers gauge");
    let _ = writeln!(
        out,
        "# HELP rdock_admin_sse_dropped_events_total Live entries not delivered because a reader fell behind."
    );
    let _ = writeln!(out, "# TYPE rdock_admin_sse_dropped_events_total counter");
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
