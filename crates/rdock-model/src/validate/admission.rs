//! `admission`, the adaptive concurrency limit, and its place in a route's chain (H-LB-04,
//! ADR-0031).

use super::{Validator, reference_key};
use crate::diagnostics::{Diagnostic, path_index};
use crate::middleware::{AdmissionConfig, AdmissionMode, Middleware};
use crate::route::Route;
use crate::values::RateLimitKey;

impl Validator<'_> {
    pub(super) fn check_admission(&mut self, path: &str, a: &AdmissionConfig) {
        self.check_not_zero(&format!("{path}.min"), a.min == 0);
        if a.max > AdmissionConfig::MAX_LIMIT {
            self.error(
                format!("{path}.max"),
                format!("at most {}", AdmissionConfig::MAX_LIMIT),
            );
        }
        if a.min > a.max {
            self.push(
                Diagnostic::error(
                    format!("{path}.min"),
                    format!("`min` ({}) is above `max` ({})", a.min, a.max),
                )
                .with_hint("the limit moves between `min` and `max`"),
            );
        }
        if let Some(initial) = a.initial
            && !(a.min..=a.max).contains(&initial)
        {
            self.error(
                format!("{path}.initial"),
                format!("use a value from `min` ({}) to `max` ({})", a.min, a.max),
            );
        }
        let shares = a.shares;
        if !(1..=100).contains(&shares.normal) {
            self.error(format!("{path}.shares.normal"), "use 1 to 100");
        }
        if !(1..=100).contains(&shares.sheddable) {
            self.error(format!("{path}.shares.sheddable"), "use 1 to 100");
        }
        if shares.sheddable > shares.normal {
            self.push(
                Diagnostic::error(
                    format!("{path}.shares.sheddable"),
                    "`sheddable` is above `normal`: sheddable routes would be shed after normal ones",
                )
                .with_hint("keep sheddable ≤ normal ≤ 100"),
            );
        }
        self.check_not_zero(&format!("{path}.retry_after"), a.retry_after.is_zero());
        // Settings of the other algorithm mean nothing: refuse them rather than ignore them.
        let (theirs, mine): (&[(&str, bool)], &str) = match a.mode {
            AdmissionMode::Aimd => (
                &[
                    ("tolerance_percent", a.tolerance_percent.is_some()),
                    ("smoothing_percent", a.smoothing_percent.is_some()),
                    ("queue", a.queue.is_some()),
                    ("window", a.window.is_some()),
                    ("probe", a.probe.is_some()),
                ],
                "aimd",
            ),
            AdmissionMode::Gradient => (
                &[
                    ("latency", a.latency.is_some()),
                    ("backoff_percent", a.backoff_percent.is_some()),
                ],
                "gradient",
            ),
        };
        for (field, set) in theirs {
            if *set {
                self.error(
                    format!("{path}.{field}"),
                    format!("`{field}` does not apply to `mode: {mine}`"),
                );
            }
        }
        if a.latency.is_some_and(crate::values::Duration::is_zero) {
            self.error(format!("{path}.latency"), "must be greater than zero");
        }
        if a.backoff_percent.is_some_and(|b| !(50..=99).contains(&b)) {
            self.error(format!("{path}.backoff_percent"), "use 50 to 99");
        }
        if a.tolerance_percent
            .is_some_and(|t| !(100..=1000).contains(&t))
        {
            self.error(format!("{path}.tolerance_percent"), "use 100 to 1000");
        }
        if a.smoothing_percent.is_some_and(|s| !(1..=100).contains(&s)) {
            self.error(format!("{path}.smoothing_percent"), "use 1 to 100");
        }
        if a.window.is_some_and(|w| !(10..=100_000).contains(&w)) {
            self.error(format!("{path}.window"), "use 10 to 100000");
        }
        if a.probe.is_some_and(|p| !(5..=1000).contains(&p)) {
            self.error(format!("{path}.probe"), "use 5 to 1000");
        }
    }

    /// One adaptive limit per route, and no route-wide `in_flight` beside it: two caps on
    /// the whole route would leave the adaptive one blind (the fixed cap refuses first, so
    /// the latency it learns from never rises) and the answer ambiguous (429 or 503).
    pub(super) fn check_route_admission(&mut self, path: &str, route: &Route) {
        let mut admission = None;
        let mut route_cap = None;
        for (i, reference) in route.middlewares.iter().enumerate() {
            match self.config.middlewares.get(reference_key(reference)) {
                Some(Middleware::Admission(_)) => {
                    if admission.is_some() {
                        self.error(
                            path_index(&format!("{path}.middlewares"), i),
                            "a second `admission` middleware on one route: use one",
                        );
                    }
                    admission = Some(i);
                }
                Some(Middleware::InFlight(f)) if f.key == RateLimitKey::Route => {
                    route_cap = Some(i);
                }
                _ => {}
            }
        }
        if let (Some(_), Some(i)) = (admission, route_cap) {
            self.push(
                Diagnostic::error(
                    path_index(&format!("{path}.middlewares"), i),
                    "`in_flight` with `key: route` and `admission` on one route are two caps on the same requests",
                )
                .with_hint(
                    "keep `admission` (its `max` is the fixed cap), or count `in_flight` per client (`key: client_ip`, `consumer`, …)",
                ),
            );
        }
        if admission.is_none() && !route.priority_class.is_normal() {
            self.warning(
                format!("{path}.priority_class"),
                "`priority_class` only matters to an `admission` middleware, and this route has none",
            );
        }
    }
}
