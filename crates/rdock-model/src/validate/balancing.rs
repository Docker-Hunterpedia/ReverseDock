//! Balancing settings of v0.9 (H-LB-01…03, H-HA-05, ADR-0031): Peak-EWMA, outlier detection,
//! slow start, priority tiers, zones and per-try timeouts.

use super::Validator;
use crate::diagnostics::{Diagnostic, path_index};
use crate::service::{
    Backend, Failover, LbPolicy, LocalityMode, OutlierDetection, RetryOn, Service, SlowStartConfig,
};

/// The highest backend priority tier.
pub(crate) const MAX_PRIORITY: u8 = 7;
/// Statistical detectors below this many hosts eject healthy backends (ADR-0031).
const MIN_OUTLIER_HOSTS: u32 = 3;

impl Validator<'_> {
    /// Tiers and zones of a backend list (HTTP, TCP and UDP services). `require_primary`: at
    /// least one backend must be in priority 0 (HTTP and UDP services have always required a
    /// primary; TCP services have not).
    pub(super) fn check_backend_tiers(
        &mut self,
        path: &str,
        backends: &[Backend],
        require_primary: bool,
    ) {
        let list = format!("{path}.backends");
        for (i, backend) in backends.iter().enumerate() {
            let p = path_index(&list, i);
            if let Some(priority) = backend.priority {
                if priority > MAX_PRIORITY {
                    self.error(
                        format!("{p}.priority"),
                        format!("priority is from 0 (first) to {MAX_PRIORITY}"),
                    );
                }
                if backend.backup {
                    self.push(
                        Diagnostic::error(
                            format!("{p}.backup"),
                            "set `backup` or `priority`, not both",
                        )
                        .with_hint("`backup: true` is the same as `priority: 1`"),
                    );
                }
            }
            if let Some(zone) = &backend.zone {
                self.check_zone(&format!("{p}.zone"), zone);
            }
            for (j, zone) in backend.for_zones.iter().enumerate() {
                self.check_zone(&path_index(&format!("{p}.for_zones"), j), zone);
            }
        }
        if require_primary && !backends.is_empty() && backends.iter().all(|b| b.tier() > 0) {
            let message = if backends.iter().all(|b| b.backup) {
                "every backend is a backup; at least one must be a primary"
            } else {
                "no backend is in priority 0; at least one must be a primary"
            };
            self.error(list, message);
        }
    }

    pub(super) fn check_zone(&mut self, path: &str, zone: &str) {
        if zone.is_empty()
            || zone.len() > 253
            || zone.chars().any(|c| c.is_whitespace() || c.is_control())
        {
            self.error(
                path,
                "a zone is a non-empty name without spaces, e.g. `eu-west-1a`",
            );
        }
    }

    /// Peak-EWMA, tiers, locality and hedging of an HTTP service.
    pub(super) fn check_service_balancing(&mut self, path: &str, service: &Service) {
        let lb = &service.load_balancer;
        let peak = lb.policy == LbPolicy::PeakEwma;
        if let Some(decay) = lb.decay {
            if !peak {
                self.warning(
                    format!("{path}.load_balancer.decay"),
                    "`decay` is only used by the peak_ewma policy",
                );
            } else if decay.is_zero() {
                self.error(format!("{path}.load_balancer.decay"), "must not be zero");
            }
        }
        if lb.measure.is_some() && !peak {
            self.warning(
                format!("{path}.load_balancer.measure"),
                "`measure` is only used by the peak_ewma policy",
            );
        }
        self.check_backend_tiers(path, &service.backends, true);
        if let Some(factor) = service.overprovisioning {
            if service.failover != Failover::Spill {
                self.warning(
                    format!("{path}.overprovisioning"),
                    "`overprovisioning` is only used with `failover: spill`",
                );
            }
            if factor.get() < 1.0 {
                self.push(
                    Diagnostic::error(format!("{path}.overprovisioning"), "must be at least 1")
                        .with_hint("below 1, a tier sends traffic to the next even when all its backends are up"),
                );
            }
        }
        if service.failover == Failover::Spill
            && !service.backends.is_empty()
            && service.backends.iter().all(|b| b.tier() == 0)
        {
            self.warning(
                format!("{path}.failover"),
                "`spill` has nothing to do: every backend is in priority 0",
            );
        }
        let prefer = service
            .locality
            .as_ref()
            .is_some_and(|l| l.mode == LocalityMode::Prefer);
        if prefer
            && service
                .backends
                .iter()
                .all(|b| b.zone.is_none() && b.for_zones.is_empty())
        {
            self.warning(
                format!("{path}.locality"),
                "no backend has a `zone`, so `prefer` uses every backend",
            );
        }
        if let Some(health) = &service.health {
            if let Some(slow) = &health.slow_start {
                self.check_slow_start(
                    &format!("{path}.health.slow_start"),
                    &slow.config(),
                    lb.policy,
                );
            }
            if let Some(outlier) = health.passive.as_ref().and_then(|p| p.outlier.as_ref()) {
                self.check_outlier(&format!("{path}.health.passive.outlier"), outlier);
            }
        }
        if let Some(retries) = &service.retries {
            self.check_per_try_timeout(&format!("{path}.retries"), service, retries);
        }
    }

    fn check_slow_start(&mut self, path: &str, slow: &SlowStartConfig, policy: LbPolicy) {
        if policy.is_hash() {
            self.push(
                Diagnostic::error(
                    path,
                    "slow start does not work with hash policies: every change of a weight moves keys between backends",
                )
                .with_hint("remove `slow_start`, or use a policy such as round_robin or least_requests"),
            );
        }
        self.check_not_zero(&format!("{path}.window"), slow.window.is_zero());
        if slow.aggression.thousandths() == 0 {
            self.error(format!("{path}.aggression"), "must be above 0");
        }
        if slow.min_weight_percent > 100 {
            self.error(
                format!("{path}.min_weight_percent"),
                "a percentage is at most 100",
            );
        }
        if slow.on.is_empty() {
            self.error(format!("{path}.on"), "list `recovery`, `join` or both");
        }
    }

    fn check_outlier(&mut self, path: &str, outlier: &OutlierDetection) {
        self.check_not_zero(&format!("{path}.interval"), outlier.interval.is_zero());
        let hosts = |v: &mut Self, p: String, n: u32| {
            if n < MIN_OUTLIER_HOSTS {
                v.push(
                    Diagnostic::error(
                        p,
                        format!("at least {MIN_OUTLIER_HOSTS}: with fewer hosts a statistical detector ejects healthy backends"),
                    )
                    .with_hint("Envoy's default, 5, is the safe choice"),
                );
            }
        };
        if let Some(sr) = &outlier.success_rate {
            let p = format!("{path}.success_rate");
            hosts(self, format!("{p}.minimum_hosts"), sr.minimum_hosts);
            self.check_not_zero(&format!("{p}.request_volume"), sr.request_volume == 0);
            if sr.stdev_factor.thousandths() == 0 {
                self.error(format!("{p}.stdev_factor"), "must be above 0");
            }
            if !sr.enabled {
                self.warning(p, "the detector is off; set `enabled: true` to use it");
            }
        }
        if let Some(fp) = &outlier.failure_percentage {
            let p = format!("{path}.failure_percentage");
            hosts(self, format!("{p}.minimum_hosts"), fp.minimum_hosts);
            self.check_not_zero(&format!("{p}.request_volume"), fp.request_volume == 0);
            if !(1..=100).contains(&fp.threshold) {
                self.error(format!("{p}.threshold"), "a percentage from 1 to 100");
            }
            if !fp.enabled {
                self.warning(p, "the detector is off; set `enabled: true` to use it");
            }
        }
    }

    fn check_per_try_timeout(
        &mut self,
        path: &str,
        service: &Service,
        retries: &crate::service::Retries,
    ) {
        let Some(per_try) = retries.per_try_timeout else {
            return;
        };
        let p = format!("{path}.per_try_timeout");
        if per_try.is_zero() {
            self.error(&p, "must not be zero");
            return;
        }
        if !retries.on.contains(&RetryOn::Timeout) {
            self.push(
                Diagnostic::error(&p, "an abandoned attempt is retried as a timeout, but `on` does not list `timeout`")
                    .with_hint("add `timeout` to `retries.on`"),
            );
        }
        if retries.attempts == 0 {
            self.warning(
                &p,
                "with `attempts: 0` nothing is retried, so this never applies",
            );
        }
        if per_try >= service.timeouts.read {
            self.warning(
                &p,
                "not shorter than `timeouts.read`, so it never ends an attempt earlier",
            );
        }
    }

    /// The top-level `locality`.
    pub(super) fn check_locality(&mut self) {
        if let Some(zone) = self
            .config
            .locality
            .as_ref()
            .and_then(|l| l.zone.as_deref())
        {
            self.check_zone("locality.zone", zone);
        }
    }
}
