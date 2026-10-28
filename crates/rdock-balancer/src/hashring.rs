//! Consistent hashing in the style of ketama: every backend owns points on a ring of 64-bit
//! values, a request key goes to the first point at or after its hash. Adding or removing a
//! backend only moves the keys of the points it gains or loses.
//!
//! The hash is FNV-1a with a 64-bit finaliser, fixed by this file, so every instance and every
//! version maps a key to the same backend for the same list. `pingora-ketama` only takes socket
//! addresses; this ring takes any identity, Unix sockets included.

use std::sync::{Arc, Mutex, PoisonError};

use crate::{Choice, RoundRobin};

/// Points per unit of weight.
const POINTS_PER_WEIGHT: u32 = 160;
/// Weights above this count as this much, so one backend cannot blow up the ring.
const MAX_WEIGHT: u32 = 100;

/// A consistent-hash ring, rebuilt when the candidate list changes.
#[derive(Debug, Default)]
pub struct HashRing {
    ring: Mutex<Arc<Ring>>,
    /// Used for requests without a hash key.
    pub(crate) fallback: RoundRobin,
}

#[derive(Debug, Default)]
struct Ring {
    fingerprint: u64,
    /// Sorted by point; the second value indexes the choice list the ring was built from.
    points: Vec<(u64, usize)>,
}

impl HashRing {
    pub(crate) fn pick(&self, choices: &[Choice<'_>], key: &[u8]) -> Option<usize> {
        let ring = self.ring_for(choices);
        let hash = hash64(key);
        let at = ring.points.partition_point(|(point, _)| *point < hash);
        let (_, index) = ring.points.get(at).or_else(|| ring.points.first())?;
        Some(*index)
    }

    fn ring_for(&self, choices: &[Choice<'_>]) -> Arc<Ring> {
        let fingerprint = fingerprint(choices);
        let mut ring = self.ring.lock().unwrap_or_else(PoisonError::into_inner);
        if ring.fingerprint != fingerprint || ring.points.is_empty() {
            *ring = Arc::new(Ring::build(choices, fingerprint));
        }
        ring.clone()
    }
}

impl Ring {
    fn build(choices: &[Choice<'_>], fingerprint: u64) -> Self {
        let mut points = Vec::new();
        for (index, choice) in choices.iter().enumerate() {
            let count = choice.weight.min(MAX_WEIGHT) * POINTS_PER_WEIGHT;
            for n in 0..count {
                let mut input = Vec::with_capacity(choice.id.len() + 11);
                input.extend_from_slice(choice.id.as_bytes());
                input.push(b'-');
                input.extend_from_slice(n.to_string().as_bytes());
                points.push((hash64(&input), index));
            }
        }
        points.sort_unstable();
        Self {
            fingerprint,
            points,
        }
    }
}

fn fingerprint(choices: &[Choice<'_>]) -> u64 {
    let mut state = FNV_OFFSET;
    for choice in choices {
        state = fnv1a(state, choice.id.as_bytes());
        state = fnv1a(state, &choice.weight.to_le_bytes());
    }
    state
}

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;

fn fnv1a(mut state: u64, bytes: &[u8]) -> u64 {
    for byte in bytes {
        state ^= u64::from(*byte);
        state = state.wrapping_mul(0x0100_0000_01b3);
    }
    state
}

/// FNV-1a followed by the `SplitMix64` finaliser, which spreads FNV's weak low bits.
fn hash64(bytes: &[u8]) -> u64 {
    let mut z = fnv1a(FNV_OFFSET, bytes);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::choices;

    fn spread(ring: &HashRing, list: &[Choice<'_>], keys: u32) -> Vec<u32> {
        let mut counts = vec![0; list.len()];
        for k in 0..keys {
            let index = ring
                .pick(list, format!("client-{k}").as_bytes())
                .unwrap_or(99);
            counts[index] += 1;
        }
        counts
    }

    #[test]
    fn same_key_same_backend() {
        let ring = HashRing::default();
        let list = choices(&[1, 1, 1]);
        let first = ring.pick(&list, b"203.0.113.7");
        assert!(first.is_some());
        for _ in 0..10 {
            assert_eq!(ring.pick(&list, b"203.0.113.7"), first);
        }
        // A second ring (another instance) agrees.
        assert_eq!(HashRing::default().pick(&list, b"203.0.113.7"), first);
    }

    #[test]
    fn keys_spread_by_weight() {
        let ring = HashRing::default();
        let counts = spread(&ring, &choices(&[1, 1, 2]), 40_000);
        // Expected 10k, 10k, 20k; a ketama ring with 160 points per weight lands within about
        // 20 % of each share.
        assert!(counts[0].abs_diff(10_000) < 2_000, "{counts:?}");
        assert!(counts[1].abs_diff(10_000) < 2_000, "{counts:?}");
        assert!(counts[2].abs_diff(20_000) < 4_000, "{counts:?}");
    }

    #[test]
    fn removing_a_backend_only_moves_its_keys() {
        let ring = HashRing::default();
        let all = choices(&[1, 1, 1, 1]);
        let before: Vec<_> = (0..2_000)
            .map(|k| all[ring.pick(&all, format!("k{k}").as_bytes()).unwrap_or(0)].id)
            .collect();
        let without_c: Vec<_> = all.iter().copied().filter(|c| c.id != "c").collect();
        for (k, old) in before.iter().enumerate() {
            let new = without_c[ring
                .pick(&without_c, format!("k{k}").as_bytes())
                .unwrap_or(0)]
            .id;
            if *old != "c" {
                assert_eq!(new, *old, "key k{k} moved although its backend stayed");
            }
        }
    }

    #[test]
    fn huge_weights_are_capped() {
        let ring = HashRing::default();
        let list = choices(&[u32::MAX, 1]);
        assert!(ring.pick(&list, b"x").is_some());
        let built = ring.ring_for(&list);
        assert_eq!(
            built.points.len(),
            ((MAX_WEIGHT + 1) * POINTS_PER_WEIGHT) as usize
        );
    }
}
