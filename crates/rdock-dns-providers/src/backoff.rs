//! Retries with exponential backoff and full jitter, for API calls and DNS updates alike.

use std::time::Duration;

/// Attempts per call, the first one included.
pub(crate) const ATTEMPTS: u32 = 5;
/// The longest a call waits before its next attempt, whether the server asked for it or not;
/// a server asking for longer fails the call instead.
pub(crate) const LONGEST_WAIT: Duration = Duration::from_secs(30);
/// The ceiling of the first retry's random wait; it doubles with each retry.
const BASE: Duration = Duration::from_millis(500);

/// A random wait before retry number `retry` (1 for the first): uniform between zero and
/// `BASE · 2^(retry-1)`, at most [`LONGEST_WAIT`].
pub(crate) fn jittered(retry: u32) -> Duration {
    let ceiling = BASE
        .saturating_mul(1 << retry.saturating_sub(1).min(16))
        .min(LONGEST_WAIT);
    ceiling.mul_f64(fastrand::f64())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn waits_grow_and_stay_capped() {
        for _ in 0..100 {
            assert!(jittered(1) <= Duration::from_millis(500));
            assert!(jittered(3) <= Duration::from_secs(2));
            assert!(jittered(40) <= LONGEST_WAIT);
        }
    }
}
