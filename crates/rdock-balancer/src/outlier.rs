//! Statistical outlier detection (H-LB-02, ADR-0031), after Envoy's success-rate and
//! failure-percentage detectors: once per interval, the request counts of every backend are
//! compared with those of the others, and the outliers are handed to the ordinary ejection
//! (back-off, `max_ejection_percent`, half-open trial).

/// Success-rate detector: a backend whose success rate is below
/// `mean − stdev_factor × σ` of the backends with enough requests is an outlier.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SuccessRate {
    /// Multiplier of the standard deviation (Envoy's `success_rate_stdev_factor` / 1000).
    pub stdev_factor: f64,
    /// Backends with at least `request_volume` requests needed to evaluate at all.
    pub minimum_hosts: u32,
    /// Requests in the interval for a backend to be counted.
    pub request_volume: u32,
}

/// Failure-percentage detector: a backend whose failures are at least `threshold` percent of
/// its requests is an outlier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FailurePercentage {
    /// Failure share that ejects, in percent.
    pub threshold: u32,
    /// Backends with at least `request_volume` requests needed to evaluate at all.
    pub minimum_hosts: u32,
    /// Requests in the interval for a backend to be counted.
    pub request_volume: u32,
}

/// The detectors of one service.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Outlier {
    /// Success-rate detector, when enabled.
    pub success_rate: Option<SuccessRate>,
    /// Failure-percentage detector, when enabled.
    pub failure_percentage: Option<FailurePercentage>,
}

/// Which detector found an outlier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Detector {
    /// [`SuccessRate`].
    SuccessRate,
    /// [`FailurePercentage`].
    FailurePercentage,
}

impl Detector {
    /// Lower-case name, for metrics and logs.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SuccessRate => "success_rate",
            Self::FailurePercentage => "failure_percentage",
        }
    }
}

/// Mean and population standard deviation of `values` (Envoy divides by the number of hosts).
#[must_use]
pub fn mean_and_stdev(values: &[f64]) -> Option<(f64, f64)> {
    if values.is_empty() {
        return None;
    }
    #[allow(clippy::cast_precision_loss)]
    let n = values.len() as f64;
    let mean = values.iter().sum::<f64>() / n;
    let variance = values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / n;
    Some((mean, variance.sqrt()))
}

fn percent(part: u32, total: u32) -> f64 {
    f64::from(part) * 100.0 / f64::from(total)
}

/// The outliers among backends with `(requests, failures)` counts of one interval, by index.
/// A backend found by both detectors is reported once, for the success-rate detector.
#[must_use]
pub fn outliers(counts: &[(u32, u32)], detectors: &Outlier) -> Vec<(usize, Detector)> {
    let mut found: Vec<(usize, Detector)> = Vec::new();
    if let Some(sr) = detectors.success_rate {
        let eligible: Vec<(usize, f64)> = counts
            .iter()
            .enumerate()
            .filter(|(_, (total, _))| *total >= sr.request_volume.max(1))
            .map(|(i, (total, failed))| (i, percent(total - failed.min(total), *total)))
            .collect();
        if eligible.len() >= sr.minimum_hosts as usize {
            let rates: Vec<f64> = eligible.iter().map(|(_, r)| *r).collect();
            if let Some((mean, stdev)) = mean_and_stdev(&rates) {
                let threshold = mean - sr.stdev_factor * stdev;
                found.extend(
                    eligible
                        .iter()
                        .filter(|(_, rate)| *rate < threshold)
                        .map(|(i, _)| (*i, Detector::SuccessRate)),
                );
            }
        }
    }
    if let Some(fp) = detectors.failure_percentage {
        let eligible: Vec<(usize, f64)> = counts
            .iter()
            .enumerate()
            .filter(|(_, (total, _))| *total >= fp.request_volume.max(1))
            .map(|(i, (total, failed))| (i, percent(*failed.min(total), *total)))
            .collect();
        if eligible.len() >= fp.minimum_hosts as usize {
            for (i, failure) in eligible {
                if failure >= f64::from(fp.threshold) && !found.iter().any(|(j, _)| *j == i) {
                    found.push((i, Detector::FailurePercentage));
                }
            }
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    const SR: SuccessRate = SuccessRate {
        stdev_factor: 1.9,
        minimum_hosts: 5,
        request_volume: 100,
    };
    const FP: FailurePercentage = FailurePercentage {
        threshold: 85,
        minimum_hosts: 5,
        request_volume: 50,
    };

    fn only_sr() -> Outlier {
        Outlier {
            success_rate: Some(SR),
            failure_percentage: None,
        }
    }

    #[test]
    fn sigma_is_the_population_standard_deviation() {
        let (mean, stdev) = mean_and_stdev(&[100.0, 100.0, 100.0, 100.0, 60.0]).unwrap_or_default();
        assert!((mean - 92.0).abs() < 1e-9);
        // Deviations 8, 8, 8, 8, −32: (4 × 64 + 1024) / 5 = 256.
        assert!((stdev - 16.0).abs() < 1e-9);
        assert_eq!(mean_and_stdev(&[]), None);
    }

    #[test]
    fn a_backend_failing_40_percent_among_five_is_an_outlier() {
        // Threshold 92 − 1.9 × 16 = 61.6; 60 % is below it.
        let counts = [(100, 0), (100, 0), (100, 0), (100, 0), (100, 40)];
        assert_eq!(
            outliers(&counts, &only_sr()),
            vec![(4, Detector::SuccessRate)]
        );
        // At 30 % failures: mean 94, σ 12, threshold 71.2; 70 % is still an outlier.
        let counts = [(100, 0), (100, 0), (100, 0), (100, 0), (100, 30)];
        assert_eq!(outliers(&counts, &only_sr()).len(), 1);
        // Uniform noise is not.
        let counts = [(100, 2), (100, 1), (100, 3), (100, 2), (100, 4)];
        assert_eq!(outliers(&counts, &only_sr()), vec![]);
    }

    #[test]
    fn minimum_hosts_and_volume_gate_the_evaluation() {
        let four = [(100, 0), (100, 0), (100, 0), (100, 40)];
        assert_eq!(
            outliers(&four, &only_sr()),
            vec![],
            "four hosts are too few"
        );
        let quiet = [(100, 0), (100, 0), (100, 0), (100, 0), (99, 40)];
        assert_eq!(
            outliers(&quiet, &only_sr()),
            vec![],
            "the failing backend lacks volume, leaving four"
        );
        let mut six = vec![(100, 0); 5];
        six.push((10, 10));
        assert_eq!(
            outliers(&six, &only_sr()),
            vec![],
            "a low-volume backend is not judged"
        );
    }

    #[test]
    fn failure_percentage_ejects_at_its_threshold() {
        let both = Outlier {
            success_rate: None,
            failure_percentage: Some(FP),
        };
        let counts = [(50, 0), (50, 0), (50, 0), (50, 43), (50, 42)];
        // 43/50 = 86 % ≥ 85 %; 42/50 = 84 %.
        assert_eq!(
            outliers(&counts, &both),
            vec![(3, Detector::FailurePercentage)]
        );
        let counts = [(50, 0), (50, 0), (50, 0), (50, 50)];
        assert_eq!(outliers(&counts, &both).len(), 0, "four hosts");
        let all = Outlier {
            success_rate: Some(SR),
            failure_percentage: Some(FP),
        };
        let counts = [(100, 0), (100, 0), (100, 0), (100, 0), (100, 90)];
        assert_eq!(
            outliers(&counts, &all),
            vec![(4, Detector::SuccessRate)],
            "reported once"
        );
    }
}
