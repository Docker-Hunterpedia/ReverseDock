#![doc = include_str!("../README.md")]

use std::sync::Mutex;

mod hashring;
mod state;
mod sticky;

pub use hashring::HashRing;
pub use state::{BackendState, InFlight, Pool, Registry};
pub use sticky::{Match as StickyMatch, StickyKeys};

/// One backend the balancer may pick.
#[derive(Debug, Clone, Copy)]
pub struct Choice<'a> {
    /// Stable identity (the resolved address), used by hash policies.
    pub id: &'a str,
    /// Relative weight; zero is never picked.
    pub weight: u32,
    /// Requests currently sent to this backend.
    pub in_flight: u32,
}

/// How a backend is picked among weighted candidates.
#[derive(Debug)]
pub enum Balancer {
    /// Smooth weighted round-robin (the NGINX algorithm): over a cycle every backend gets its
    /// share, and picks of a heavy backend are spread out instead of bunched together.
    RoundRobin(RoundRobin),
    /// Weighted random choice.
    Random,
    /// The backend with the highest `weight / (in_flight + 1)`; ties are broken at random.
    LeastRequests,
    /// Two weighted random picks; the one with fewer in-flight requests (relative to its
    /// weight) wins.
    P2c,
    /// Consistent hashing of a request key; requests without a key use round-robin.
    Hash(Box<HashRing>),
}

impl Balancer {
    /// Picks the index of one of `choices`, or `None` when all weights are zero or the slice is
    /// empty. `key` is the hash input of [`Balancer::Hash`].
    pub fn pick(&self, choices: &[Choice<'_>], key: Option<&[u8]>) -> Option<usize> {
        match self {
            Self::RoundRobin(rr) => rr.pick(choices),
            Self::Random => pick_random(choices, fastrand::u64(..)),
            Self::LeastRequests => least_requests(choices, fastrand::usize(..=choices.len())),
            Self::P2c => p2c(choices, fastrand::u64(..), fastrand::u64(..)),
            Self::Hash(ring) => match key {
                Some(key) => ring.pick(choices, key),
                None => ring.fallback.pick(choices),
            },
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
    fn pick(&self, choices: &[Choice<'_>]) -> Option<usize> {
        let total: i64 = choices.iter().map(|c| i64::from(c.weight)).sum();
        if total == 0 {
            return None;
        }
        // A poisoned lock only means another thread panicked mid-pick; the counters are still
        // usable, so keep balancing.
        let mut current = self
            .current
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if current.len() != choices.len() {
            *current = vec![0; choices.len()];
        }
        let mut best: Option<usize> = None;
        for (i, choice) in choices.iter().enumerate() {
            current[i] += i64::from(choice.weight);
            if choice.weight > 0 && best.is_none_or(|b| current[i] > current[b]) {
                best = Some(i);
            }
        }
        let chosen = best?;
        current[chosen] -= total;
        Some(chosen)
    }
}

/// Whether `a` is less loaded than `b` relative to their weights:
/// `a.weight / (a.in_flight + 1) > b.weight / (b.in_flight + 1)`, without division.
fn less_loaded(a: &Choice<'_>, b: &Choice<'_>) -> bool {
    u64::from(a.weight) * (u64::from(b.in_flight) + 1)
        > u64::from(b.weight) * (u64::from(a.in_flight) + 1)
}

/// The least loaded choice, scanning from `start` so that ties do not always go to the first.
fn least_requests(choices: &[Choice<'_>], start: usize) -> Option<usize> {
    let n = choices.len();
    let mut best: Option<usize> = None;
    for offset in 0..n {
        let i = (start + offset) % n;
        if choices[i].weight > 0 && best.is_none_or(|b| less_loaded(&choices[i], &choices[b])) {
            best = Some(i);
        }
    }
    best
}

fn p2c(choices: &[Choice<'_>], first: u64, second: u64) -> Option<usize> {
    let a = pick_random(choices, first)?;
    let b = pick_random(choices, second)?;
    Some(if less_loaded(&choices[b], &choices[a]) {
        b
    } else {
        a
    })
}

/// Weighted choice of an index using `random` as the source of randomness.
fn pick_random(choices: &[Choice<'_>], random: u64) -> Option<usize> {
    let total: u64 = choices.iter().map(|c| u64::from(c.weight)).sum();
    if total == 0 {
        return None;
    }
    let mut point = random % total;
    for (i, choice) in choices.iter().enumerate() {
        let weight = u64::from(choice.weight);
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

    pub(crate) fn choices(weights: &[u32]) -> Vec<Choice<'static>> {
        const IDS: [&str; 8] = ["a", "b", "c", "d", "e", "f", "g", "h"];
        weights
            .iter()
            .enumerate()
            .map(|(i, w)| Choice {
                id: IDS[i],
                weight: *w,
                in_flight: 0,
            })
            .collect()
    }

    fn sequence(balancer: &Balancer, weights: &[u32], n: usize) -> Vec<usize> {
        let list = choices(weights);
        (0..n).filter_map(|_| balancer.pick(&list, None)).collect()
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
        for balancer in [
            rr,
            Balancer::Random,
            Balancer::LeastRequests,
            Balancer::P2c,
            Balancer::Hash(Box::default()),
        ] {
            assert_eq!(balancer.pick(&[], None), None);
            assert_eq!(balancer.pick(&choices(&[0, 0]), Some(b"k")), None);
            assert_eq!(balancer.pick(&choices(&[0, 0]), None), None);
        }
    }

    #[test]
    fn state_resets_when_the_list_changes() {
        let rr = Balancer::RoundRobin(RoundRobin::default());
        assert_eq!(sequence(&rr, &[1, 1], 1), vec![0]);
        assert_eq!(sequence(&rr, &[1, 1, 1], 3), vec![0, 1, 2]);
    }

    #[test]
    fn random_follows_the_weights() {
        let list = choices(&[3, 1]);
        assert_eq!(pick_random(&list, 0), Some(0));
        assert_eq!(pick_random(&list, 2), Some(0));
        assert_eq!(pick_random(&list, 3), Some(1));
        assert_eq!(pick_random(&list, 7), Some(1));
        let mut counts = [0u32; 2];
        for i in 0..4_000u64 {
            counts[pick_random(&list, i).unwrap_or(9)] += 1;
        }
        assert_eq!(counts, [3_000, 1_000]);
    }

    #[test]
    fn least_requests_prefers_idle_backends_relative_to_weight() {
        let mut list = choices(&[1, 1, 2]);
        list[0].in_flight = 3;
        list[1].in_flight = 0;
        list[2].in_flight = 1;
        // Scores: 1/4, 1/1, 2/2 → b and c tie; the scan start decides.
        assert_eq!(least_requests(&list, 0), Some(1));
        assert_eq!(least_requests(&list, 2), Some(2));
        list[1].in_flight = 1;
        assert_eq!(least_requests(&list, 0), Some(2), "2/2 beats 1/2");
        list[2].weight = 0;
        assert_eq!(
            least_requests(&list, 2),
            Some(1),
            "zero weight is never picked"
        );
    }

    #[test]
    fn p2c_keeps_the_less_loaded_of_two() {
        let mut list = choices(&[1, 1]);
        list[0].in_flight = 5;
        // Random values 0 and 1 select a and b.
        assert_eq!(p2c(&list, 0, 1), Some(1));
        assert_eq!(p2c(&list, 1, 0), Some(1));
        assert_eq!(p2c(&list, 0, 0), Some(0), "the same backend twice");
    }
}
