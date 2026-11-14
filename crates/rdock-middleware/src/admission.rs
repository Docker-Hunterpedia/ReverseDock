//! `admission`: an adaptive concurrency limit shared by the routes using the middleware
//! (H-LB-04, ADR-0031). Over the share of the limit that the route's `priority_class` may
//! fill, requests get `503` (`overloaded`) with `Retry-After`.
//!
//! The limit learns only from requests that reached a backend (Netflix's concurrency-limits
//! ignores cancelled requests, `onIgnore`; Envoy's filter cancels the sample of a stream
//! destroyed before its response completed): the latency until the backend's response
//! headers, with the backend's `502`, `503` and `504`, a failed or timed-out connect and an
//! upstream timeout as drops. A client that goes away, an answer of another middleware or of
//! rdock itself, and a cache hit are no sample, so nobody can push the limit down by
//! disconnecting or by asking for something rdock refuses.
//!
//! A request keeps its place until the response is complete (Envoy samples at
//! `encodeComplete`), so streaming responses count while they stream; an upgrade (`101`)
//! gives the place back when its response headers pass, because an upgraded connection is no
//! longer a request the backend is working on.

use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use http::HeaderValue;
use pingora::http::{RequestHeader, ResponseHeader};
use rdock_limits::admission::{AdaptiveLimit, Algorithm, Class, Permit, Settings};
use rdock_model::middleware::{AdmissionConfig, AdmissionMode};
use rdock_model::route::PriorityClass;

use crate::phase::{Capabilities, Phases};
use crate::{BackendOutcome, Context, Flow, LogSummary, Middleware, ProblemKind, Reply};

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
    /// The sample was taken (at the backend's response headers).
    sampled: bool,
    in_flight: Option<rdock_observability::IntGauge>,
}

impl Ticket {
    /// Gives the place back.
    fn release(&mut self) {
        if let Some(permit) = self.permit.take() {
            let limit = permit.limit().clone();
            drop(permit);
            if let Some(gauge) = &self.in_flight {
                gauge.set(i64::from(limit.in_flight()));
            }
        }
    }
}

impl Drop for Ticket {
    fn drop(&mut self) {
        self.release();
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
            interval: config
                .interval
                .unwrap_or(AdmissionConfig::INTERVAL)
                .as_std(),
            jitter: percent(
                config
                    .jitter_percent
                    .unwrap_or(AdmissionConfig::JITTER_PERCENT),
            ),
            probe: config.probe.unwrap_or(AdmissionConfig::PROBE),
            probe_timeout: config
                .probe_timeout
                .unwrap_or(AdmissionConfig::PROBE_TIMEOUT)
                .as_std(),
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
        let now = Instant::now();
        if let Some(permit) = self.limit.try_acquire(class(cx.priority_class), now) {
            if let Some(g) = &self.gauges {
                g.in_flight.set(i64::from(self.limit.in_flight()));
            }
            cx.set_state(Ticket {
                permit: Some(permit),
                started: now,
                sampled: false,
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
        // Only the backend's own response headers are a sample.
        let BackendOutcome::Responded(status) = cx.backend else {
            return;
        };
        let Some(ticket) = cx.state_mut::<Ticket>() else {
            return;
        };
        if ticket.sampled {
            return;
        }
        ticket.sampled = true;
        let now = Instant::now();
        if let Some(permit) = &ticket.permit {
            let dropped = matches!(status, 502..=504);
            self.sample(
                now.saturating_duration_since(ticket.started),
                permit.in_flight_at_start(),
                dropped,
                now,
            );
        }
        if status == 101 {
            ticket.release();
        }
    }

    fn log(&self, _summary: &LogSummary, cx: &Context) {
        let Some(ticket) = cx.state::<Ticket>() else {
            return;
        };
        // A backend that failed before answering is a drop; anything else that did not reach
        // a backend's response (a client that left, an answer of rdock's) is no sample.
        if !ticket.sampled
            && cx.backend == BackendOutcome::Failed
            && let Some(permit) = &ticket.permit
        {
            let now = Instant::now();
            self.sample(
                now.saturating_duration_since(ticket.started),
                permit.in_flight_at_start(),
                true,
                now,
            );
        }
    }
}

impl Admission {
    fn sample(&self, latency: std::time::Duration, in_flight: u32, dropped: bool, now: Instant) {
        if let Some(limit) = self.limit.record(latency, in_flight, dropped, now)
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

    fn summary(status: u16) -> LogSummary {
        LogSummary {
            status,
            bytes_in: 0,
            bytes_out: 0,
            duration: std::time::Duration::from_millis(1),
            upstream_duration: None,
            error: None,
        }
    }

    /// One request through the middleware's phases, the backend doing `backend`.
    fn exchange(mw: &Admission, backend: BackendOutcome, status: u16) {
        let mut req = request("GET", "/", &[]);
        let mut c = cx();
        assert_eq!(block_on(mw.request(&mut req, &mut c)), Flow::Next);
        c.backend = backend;
        if matches!(backend, BackendOutcome::Responded(_)) || status != 0 {
            let mut resp = ResponseHeader::build(status.max(100), None).unwrap();
            block_on(mw.response(&mut resp, &mut c));
        }
        mw.log(&summary(status), &c);
    }

    #[test]
    fn a_slow_or_failed_answer_lowers_the_limit() {
        let mw = Admission::new("adm", &config(2, 50), None);
        exchange(&mw, BackendOutcome::Responded(200), 200);
        assert_eq!(mw.limit.limit(), 3, "grew by one at full use");
        exchange(&mw, BackendOutcome::Responded(504), 504);
        assert_eq!(mw.limit.limit(), 2, "backed off, not below min");
        let mw = Admission::new("adm", &config(2, 50), None);
        exchange(&mw, BackendOutcome::Responded(200), 200);
        exchange(&mw, BackendOutcome::Failed, 502);
        assert_eq!(mw.limit.limit(), 2, "a failed connect is a drop");
    }

    #[test]
    fn aborts_and_rdock_answers_leave_the_limit_alone() {
        let mw = Admission::new("adm", &config(3, 50), None);
        let start = mw.limit.limit();
        for _ in 0..50 {
            // The client went away before any answer.
            exchange(&mw, BackendOutcome::None, 0);
            // A later middleware answered 503 (maintenance) or 401, or a cache hit: the
            // response phase runs, but no backend responded.
            exchange(&mw, BackendOutcome::None, 503);
            exchange(&mw, BackendOutcome::None, 401);
        }
        assert_eq!(mw.limit.limit(), start);
        assert_eq!(mw.limit.in_flight(), 0, "every place was given back");
    }

    #[test]
    fn an_upgrade_gives_its_place_back_at_101() {
        let mw = Admission::new("adm", &config(3, 3), None);
        let mut req = request("GET", "/", &[]);
        let mut sockets = Vec::new();
        for _ in 0..3 {
            let mut c = cx();
            assert_eq!(block_on(mw.request(&mut req, &mut c)), Flow::Next);
            c.backend = BackendOutcome::Responded(101);
            let mut resp = ResponseHeader::build(101, None).unwrap();
            block_on(mw.response(&mut resp, &mut c));
            // The upgraded connection stays open: its context lives on.
            sockets.push(c);
        }
        assert_eq!(mw.limit.in_flight(), 0);
        let mut c = cx();
        c.priority_class = PriorityClass::Sheddable;
        assert_eq!(
            block_on(mw.request(&mut req, &mut c)),
            Flow::Next,
            "idle WebSockets hold no place"
        );
        drop(sockets);
    }
}
