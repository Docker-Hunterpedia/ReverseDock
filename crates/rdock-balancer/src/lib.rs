#![doc = include_str!("../README.md")]

use std::sync::Mutex;

/// How a backend is picked among weighted candidates.
#[derive(Debug)]
pub enum Balancer {
    /// Smooth weighted round-robin (the NGINX algorithm): over a cycle every backend gets its
    /// share, and picks of a heavy backend are spread out instead of bunched together.
    RoundRobin(RoundRobin),
    /// Weighted random choice.
    Random,
}

impl Balancer {
    /// Picks the index of one of `weights`, or `None` when all weights are zero or the slice is
    /// empty.
    pub fn pick(&self, weights: &[u32]) -> Option<usize> {
        match self {
            Self::RoundRobin(rr) => rr.pick(weights),
            Self::Random => pick_random(weights, fastrand::u64(..)),
        }
    }
}

/// State of smooth weighted round-robin. The state resets when the candidate list changes
/// length, for example after a DNS refresh.
#[derive(Debug, Default)]
pub struct RoundRobin {
    current: Mutex<Vec<i64>>,
}

impl RoundRobin {
    fn pick(&self, weights: &[u32]) -> Option<usize> {
        let total: i64 = weights.iter().map(|w| i64::from(*w)).sum();
        if total == 0 {
            return None;
        }
        // A poisoned lock only means another thread panicked mid-pick; the counters are still
        // usable, so keep balancing.
        let mut current = self
            .current
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if current.len() != weights.len() {
            *current = vec![0; weights.len()];
        }
        let mut best: Option<usize> = None;
        for (i, weight) in weights.iter().enumerate() {
            current[i] += i64::from(*weight);
            if *weight > 0 && best.is_none_or(|b| current[i] > current[b]) {
                best = Some(i);
            }
        }
        let chosen = best?;
        current[chosen] -= total;
        Some(chosen)
    }
}

/// Weighted choice of an index using `random` as the source of randomness.
fn pick_random(weights: &[u32], random: u64) -> Option<usize> {
    let total: u64 = weights.iter().map(|w| u64::from(*w)).sum();
    if total == 0 {
        return None;
    }
    let mut point = random % total;
    for (i, weight) in weights.iter().enumerate() {
        let weight = u64::from(*weight);
        if point < weight {
            return Some(i);
        }
        point -= weight;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sequence(balancer: &Balancer, weights: &[u32], n: usize) -> Vec<usize> {
        (0..n).filter_map(|_| balancer.pick(weights)).collect()
    }

    #[test]
    fn round_robin_is_smooth_and_honours_weights() {
        let rr = Balancer::RoundRobin(RoundRobin::default());
        // NGINX's documented example: weights 5, 1, 1 give a a b a c a a.
        assert_eq!(sequence(&rr, &[5, 1, 1], 7), vec![0, 0, 1, 0, 2, 0, 0]);
        let even = Balancer::RoundRobin(RoundRobin::default());
        assert_eq!(sequence(&even, &[1, 1, 1], 6), vec![0, 1, 2, 0, 1, 2]);
    }

    #[test]
    fn zero_weights_are_skipped_and_empty_lists_pick_nothing() {
        let rr = Balancer::RoundRobin(RoundRobin::default());
        assert_eq!(sequence(&rr, &[0, 2, 0], 3), vec![1, 1, 1]);
        assert_eq!(rr.pick(&[]), None);
        assert_eq!(rr.pick(&[0, 0]), None);
        assert_eq!(Balancer::Random.pick(&[0]), None);
    }

    #[test]
    fn state_resets_when_the_list_changes() {
        let rr = Balancer::RoundRobin(RoundRobin::default());
        assert_eq!(sequence(&rr, &[1, 1], 1), vec![0]);
        assert_eq!(sequence(&rr, &[1, 1, 1], 3), vec![0, 1, 2]);
    }

    #[test]
    fn random_follows_the_weights() {
        assert_eq!(pick_random(&[3, 1], 0), Some(0));
        assert_eq!(pick_random(&[3, 1], 2), Some(0));
        assert_eq!(pick_random(&[3, 1], 3), Some(1));
        assert_eq!(pick_random(&[3, 1], 7), Some(1));
        let mut counts = [0u32; 2];
        for i in 0..4_000u64 {
            counts[pick_random(&[3, 1], i).unwrap_or(9)] += 1;
        }
        assert_eq!(counts, [3_000, 1_000]);
    }
}
