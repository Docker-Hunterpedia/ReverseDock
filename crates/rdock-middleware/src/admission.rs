//! `admission`: an adaptive concurrency limit shared by the routes using the middleware
//! (H-LB-04, ADR-0031). Over the share of the limit that the route's `priority_class` may
//! fill, requests get `503` (`overloaded`) with `Retry-After`. The limit learns from the
//! latency until the response headers and from upstream errors (`502`, `503`, `504`).

use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use http::HeaderValue;
use pingora::http::{RequestHeader, ResponseHeader};
use rdock_limits::admission::{AdaptiveLimit, Algorithm, Class, Permit, Settings};
use rdock_model::middleware::{AdmissionConfig, AdmissionMode};
use rdock_model::route::PriorityClass;

use crate::phase::{Capabilities, Phases};
use crate::{Context, Flow, LogSummary, Middleware, ProblemKind, Reply};

/// The metrics of one middleware, looked up once.
#[derive(Debug, Clone)]
struct Gauges {
    limit: rdock_observability::IntGauge,
    in_flight: rdock_observability::IntGauge,
    shed: [rdock_observability::IntCounter; 3],
}

/// The `admission` middleware.
#[derive(Debug)]
pub(crate) struct Admission {
    name: String,
    limit: Arc<AdaptiveLimit>,
    retry_after: u64,
    gauges: Option<Gauges>,
}

/// An admitted request: its place, when it was admitted and when its response headers came.
/// Dropping it (with the request's context) frees the place.
#[derive(Debug)]
struct Ticket {
    permit: Option<Permit>,
    started: Instant,
    first_byte: Option<Instant>,
    in_flight: Option<rdock_observability::IntGauge>,
}

impl Drop for Ticket {
    fn drop(&mut self) {
        if let Some(permit) = self.permit.take() {
            let limit = permit.limit().clone();
            drop(permit);
            if let Some(gauge) = &self.in_flight {
                gauge.set(i64::from(limit.in_flight()));
            }
        }
    }
}

fn class(class: PriorityClass) -> Class {
    match class {
        PriorityClass::Critical => Class::Critical,
        PriorityClass::Normal => Class::Normal,
        PriorityClass::Sheddable => Class::Sheddable,
    }
}

fn index(class: PriorityClass) -> usize {
    match class {
        PriorityClass::Critical => 0,
        PriorityClass::Normal => 1,
        PriorityClass::Sheddable => 2,
    }
}

/// What the access log says about a shed request.
fn shed_reason(class: PriorityClass) -> &'static str {
    match class {
        PriorityClass::Critical => "shed:critical",
        PriorityClass::Normal => "shed:normal",
        PriorityClass::Sheddable => "shed:sheddable",
    }
}

/// The limiter settings for `config`, defaults filled in.
pub(crate) fn settings(config: &AdmissionConfig) -> Settings {
    let percent = |value: u32| f64::from(value) / 100.0;
    let algorithm = match config.mode {
        AdmissionMode::Aimd => Algorithm::Aimd {
            latency: config.latency.unwrap_or(AdmissionConfig::LATENCY).as_std(),
            backoff: percent(
                config
                    .backoff_percent
                    .unwrap_or(AdmissionConfig::BACKOFF_PERCENT),
            ),
        },
        AdmissionMode::Gradient => Algorithm::Gradient {
            tolerance: percent(
                config
                    .tolerance_percent
                    .unwrap_or(AdmissionConfig::TOLERANCE_PERCENT),
            ),
            smoothing: percent(
                config
                    .smoothing_percent
                    .unwrap_or(AdmissionConfig::SMOOTHING_PERCENT),
            ),
            queue: f64::from(config.queue.unwrap_or(AdmissionConfig::QUEUE)),
            window: config.window.unwrap_or(AdmissionConfig::WINDOW),
            probe: config.probe.unwrap_or(AdmissionConfig::PROBE),
        },
    };
    Settings {
        algorithm,
        min: config.min,
        max: config.max,
        initial: config.initial.unwrap_or(AdmissionConfig::INITIAL),
        normal_percent: config.shares.normal,
        sheddable_percent: config.shares.sheddable,
    }
}

impl Admission {
    pub(crate) fn new(
        name: &str,
        config: &AdmissionConfig,
        metrics: Option<&rdock_observability::Metrics>,
    ) -> Self {
        let limit = Arc::new(AdaptiveLimit::new(settings(config)));
        let gauges = metrics.map(|m| Gauges {
            limit: m.admission_limit.with_label_values(&[name]),
            in_flight: m.admission_in_flight.with_label_values(&[name]),
            shed: [
                PriorityClass::Critical,
                PriorityClass::Normal,
                PriorityClass::Sheddable,
            ]
            .map(|c| m.admission_shed.with_label_values(&[name, c.name()])),
        });
        if let Some(g) = &gauges {
            g.limit.set(i64::from(limit.limit()));
            g.in_flight.set(0);
        }
        Self {
            name: name.to_owned(),
            limit,
            retry_after: config.retry_after.as_std().as_secs().max(1),
            gauges,
        }
    }
}

#[async_trait]
impl Middleware for Admission {
    fn capabilities(&self) -> Capabilities {
        Capabilities::new(Phases::REQUEST | Phases::RESPONSE | Phases::LOG).with_state()
    }

    async fn request(&self, _req: &mut RequestHeader, cx: &mut Context) -> Flow {
        if let Some(permit) = self.limit.try_acquire(class(cx.priority_class)) {
            if let Some(g) = &self.gauges {
                g.in_flight.set(i64::from(self.limit.in_flight()));
            }
            cx.set_state(Ticket {
                permit: Some(permit),
                started: Instant::now(),
                first_byte: None,
                in_flight: self.gauges.as_ref().map(|g| g.in_flight.clone()),
            });
            return Flow::Next;
        }
        tracing::debug!(middleware = %self.name, class = cx.priority_class.name(), limit = self.limit.limit(), "load shed");
        if let Some(g) = &self.gauges {
            g.shed[index(cx.priority_class)].inc();
        }
        cx.admission = Some(shed_reason(cx.priority_class));
        Flow::Reply(Reply::problem(ProblemKind::Overloaded).header(
            http::header::RETRY_AFTER,
            HeaderValue::from(self.retry_after),
        ))
    }

    async fn response(&self, _resp: &mut ResponseHeader, cx: &mut Context) {
        if let Some(ticket) = cx.state_mut::<Ticket>() {
            ticket.first_byte.get_or_insert_with(Instant::now);
        }
    }

    fn log(&self, summary: &LogSummary, cx: &Context) {
        let Some(ticket) = cx.state::<Ticket>() else {
            return;
        };
        let Some(permit) = &ticket.permit else {
            return;
        };
        let end = ticket.first_byte.unwrap_or_else(Instant::now);
        // Upstream failures and timeouts are drops; nothing sent at all is one too.
        let dropped = matches!(summary.status, 0 | 502 | 503 | 504);
        let latency = end.saturating_duration_since(ticket.started);
        if let Some(limit) = self
            .limit
            .record(latency, permit.in_flight_at_start(), dropped)
            && let Some(g) = &self.gauges
        {
            g.limit.set(i64::from(limit));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{block_on, cx, reply_header, request};

    fn config(min: u32, max: u32) -> AdmissionConfig {
        serde_json::from_value(serde_json::json!({
            "mode": "aimd", "min": min, "max": max, "initial": min, "latency": "1s"
        }))
        .unwrap()
    }

    #[test]
    fn sheds_the_lowest_class_first_with_503_and_retry_after() {
        let mw = Admission::new("adm", &config(4, 4), None);
        let mut req = request("GET", "/", &[]);
        let mut held = Vec::new();
        // Sheddable may fill 75 % of 4 = 3.
        for _ in 0..3 {
            let mut c = cx();
            c.priority_class = PriorityClass::Sheddable;
            assert_eq!(block_on(mw.request(&mut req, &mut c)), Flow::Next);
            held.push(c);
        }
        let mut c = cx();
        c.priority_class = PriorityClass::Sheddable;
        let Flow::Reply(reply) = block_on(mw.request(&mut req, &mut c)) else {
            panic!("over the sheddable share")
        };
        assert_eq!(reply.status, 503);
        assert_eq!(reply.problem, Some(ProblemKind::Overloaded));
        assert_eq!(reply_header(&reply, "retry-after"), Some("1"));
        assert_eq!(c.admission, Some("shed:sheddable"));
        // A critical request still gets the last place.
        let mut c = cx();
        c.priority_class = PriorityClass::Critical;
        assert_eq!(block_on(mw.request(&mut req, &mut c)), Flow::Next);
        held.push(c);
        assert_eq!(mw.limit.in_flight(), 4);
        drop(held);
        assert_eq!(mw.limit.in_flight(), 0, "contexts free their places");
    }

    #[test]
    fn a_slow_or_failed_answer_lowers_the_limit() {
        let mw = Admission::new("adm", &config(2, 50), None);
        let mut req = request("GET", "/", &[]);
        let mut c = cx();
        block_on(mw.request(&mut req, &mut c));
        let summary = |status| LogSummary {
            status,
            bytes_in: 0,
            bytes_out: 0,
            duration: std::time::Duration::from_millis(1),
            upstream_duration: None,
            error: None,
        };
        mw.log(&summary(200), &c);
        assert_eq!(mw.limit.limit(), 3, "grew by one at full use");
        mw.log(&summary(504), &c);
        assert_eq!(mw.limit.limit(), 2, "backed off, not below min");
    }
}
