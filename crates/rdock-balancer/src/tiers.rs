//! Priority tiers with partial spill (H-LB-03, ADR-0031), after Envoy's priority levels: a
//! tier's health is its healthy share times the overprovisioning factor, capped at 100 %;
//! tier 0 takes that share of the traffic, the next tier takes its own health of what is left,
//! and so on. When the tiers' health adds up to less than 100 %, the shares are scaled up so
//! that they add up to 100 % again (Envoy's normalised total health).

/// Envoy's default overprovisioning factor: a tier keeps all traffic until fewer than about
/// 71.4 % of its backends are healthy.
pub const DEFAULT_OVERPROVISIONING: f64 = 1.4;

/// The share of traffic, in percent, each tier gets from `(healthy, total)` backend counts in
/// priority order. All zeros when no backend is healthy.
#[must_use]
pub fn tier_loads(tiers: &[(usize, usize)], overprovisioning: f64) -> Vec<f64> {
    #[allow(clippy::cast_precision_loss)]
    let health: Vec<f64> = tiers
        .iter()
        .map(|(healthy, total)| {
            if *total == 0 {
                0.0
            } else {
                (*healthy as f64 / *total as f64 * 100.0 * overprovisioning).min(100.0)
            }
        })
        .collect();
    let total: f64 = health.iter().sum();
    if total <= 0.0 {
        return vec![0.0; tiers.len()];
    }
    if total < 100.0 {
        return health.iter().map(|h| h * 100.0 / total).collect();
    }
    let mut left = 100.0;
    health
        .iter()
        .map(|h| {
            let share = h.min(left);
            left -= share;
            share
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round(loads: &[f64]) -> Vec<i64> {
        #[allow(clippy::cast_possible_truncation)]
        loads.iter().map(|l| l.round() as i64).collect()
    }

    #[test]
    fn envoys_documented_table() {
        // https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/upstream/load_balancing/priority
        // (P=0 healthy, P=1 healthy → traffic to P=0, P=1), checked 2026-11-13.
        let f = DEFAULT_OVERPROVISIONING;
        assert_eq!(round(&tier_loads(&[(100, 100), (100, 100)], f)), [100, 0]);
        assert_eq!(round(&tier_loads(&[(72, 100), (100, 100)], f)), [100, 0]);
        assert_eq!(round(&tier_loads(&[(71, 100), (100, 100)], f)), [99, 1]);
        assert_eq!(round(&tier_loads(&[(50, 100), (100, 100)], f)), [70, 30]);
        assert_eq!(round(&tier_loads(&[(25, 100), (100, 100)], f)), [35, 65]);
        assert_eq!(round(&tier_loads(&[(0, 100), (100, 100)], f)), [0, 100]);
    }

    #[test]
    fn degraded_tiers_are_normalised_and_empty_ones_get_nothing() {
        let f = DEFAULT_OVERPROVISIONING;
        // 20 % + 20 % → 28 + 28 = 56 < 100: shared equally after normalising.
        assert_eq!(round(&tier_loads(&[(1, 5), (1, 5)], f)), [50, 50]);
        assert_eq!(round(&tier_loads(&[(0, 3), (0, 2)], f)), [0, 0]);
        assert_eq!(round(&tier_loads(&[(0, 0), (2, 2)], f)), [0, 100]);
        // Three tiers: P0 at 50 % → 70, P1 at 10 % → 14, P2 takes the rest.
        assert_eq!(
            round(&tier_loads(&[(1, 2), (1, 10), (4, 4)], f)),
            [70, 14, 16]
        );
        assert_eq!(round(&tier_loads(&[(1, 2), (2, 2)], 1.0)), [50, 50]);
    }
}
