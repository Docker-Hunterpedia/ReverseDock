//! Login rate limits (ADR-0024): 5 attempts per minute per client address and 10 per
//! 15 minutes per user name, as sliding windows. There is no lockout: a limited client waits
//! for `Retry-After` and tries again, so nobody can lock an admin out.

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::net::IpAddr;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

/// Keys tracked per window. Past it, expired keys are dropped; if none are, new keys are
/// refused (fail closed) rather than letting an attacker grow memory without bound.
const MAX_KEYS: usize = 50_000;

struct Window<K> {
    limit: usize,
    period: Duration,
    hits: HashMap<K, VecDeque<Instant>>,
}

impl<K: Hash + Eq + Clone> Window<K> {
    fn new(limit: usize, period: Duration) -> Self {
        Self {
            limit,
            period,
            hits: HashMap::new(),
        }
    }

    /// How long `key` must wait, or `None` when it may try now.
    fn wait(&mut self, key: &K, now: Instant) -> Option<Duration> {
        if let Some(hits) = self.hits.get_mut(key) {
            while hits
                .front()
                .is_some_and(|t| now.duration_since(*t) >= self.period)
            {
                hits.pop_front();
            }
            return (hits.len() >= self.limit).then(|| {
                hits.front().map_or(self.period, |t| {
                    self.period.saturating_sub(now.duration_since(*t))
                })
            });
        }
        if self.hits.len() >= MAX_KEYS {
            let period = self.period;
            self.hits
                .retain(|_, hits| hits.back().is_some_and(|t| now.duration_since(*t) < period));
            if self.hits.len() >= MAX_KEYS {
                return Some(self.period);
            }
        }
        None
    }

    fn record(&mut self, key: K, now: Instant) {
        self.hits.entry(key).or_default().push_back(now);
    }
}

/// The address a limit counts: the full IPv4 address, or the /64 of an IPv6 address, which
/// one client usually controls whole.
fn address_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => {
            let mut octets = v6.octets();
            octets[8..].fill(0);
            IpAddr::from(octets)
        }
        IpAddr::V4(_) => ip,
    }
}

struct Windows {
    by_address: Window<IpAddr>,
    by_name: Window<String>,
}

/// Both login windows, checked and recorded together.
pub struct LoginLimits {
    windows: Mutex<Windows>,
}

impl Default for LoginLimits {
    fn default() -> Self {
        Self::new(
            (5, Duration::from_secs(60)),
            (10, Duration::from_secs(15 * 60)),
        )
    }
}

impl LoginLimits {
    /// `(attempts, period)` per address and per user name.
    #[must_use]
    pub fn new(by_address: (usize, Duration), by_name: (usize, Duration)) -> Self {
        Self {
            windows: Mutex::new(Windows {
                by_address: Window::new(by_address.0, by_address.1),
                by_name: Window::new(by_name.0, by_name.1),
            }),
        }
    }

    /// Records an attempt from `address` (none on the Unix socket) for `name`, or returns how
    /// long to wait. A refused attempt is not recorded, so waiting is always enough.
    pub fn attempt(&self, address: Option<IpAddr>, name: &str) -> Result<(), Duration> {
        let now = Instant::now();
        let mut windows = self.windows.lock().unwrap_or_else(PoisonError::into_inner);
        let address = address.map(address_key);
        let name = name.to_ascii_lowercase();
        let wait_address = address.and_then(|a| windows.by_address.wait(&a, now));
        let wait = wait_address.max(windows.by_name.wait(&name, now));
        if let Some(wait) = wait {
            return Err(wait.max(Duration::from_secs(1)));
        }
        if let Some(address) = address {
            windows.by_address.record(address, now);
        }
        windows.by_name.record(name, now);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Option<IpAddr> {
        s.parse().ok()
    }

    #[test]
    fn addresses_and_names_are_limited_separately() {
        let limits = LoginLimits::default();
        for _ in 0..5 {
            limits.attempt(ip("192.0.2.1"), "root").unwrap();
        }
        let wait = limits.attempt(ip("192.0.2.1"), "other").unwrap_err();
        assert!(
            wait > Duration::from_secs(55) && wait <= Duration::from_secs(60),
            "{wait:?}"
        );

        for _ in 0..5 {
            limits.attempt(ip("192.0.2.2"), "ROOT").unwrap();
        }
        // Ten attempts on `root` from two addresses: the name is now limited everywhere.
        assert!(limits.attempt(ip("192.0.2.3"), "root").unwrap_err() > Duration::from_secs(800));
        limits.attempt(ip("192.0.2.3"), "someone").unwrap();
    }

    #[test]
    fn an_ipv6_slash_64_counts_as_one_client() {
        let limits = LoginLimits::default();
        for i in 1..=5 {
            limits
                .attempt(ip(&format!("2001:db8::{i}")), &format!("u{i}"))
                .unwrap();
        }
        assert!(limits.attempt(ip("2001:db8::ffff"), "u9").is_err());
        limits.attempt(ip("2001:db8:0:1::1"), "u9").unwrap();
    }

    #[test]
    fn attempts_age_out_and_refusals_are_not_counted() {
        let limits = LoginLimits::new(
            (2, Duration::from_millis(50)),
            (100, Duration::from_secs(60)),
        );
        limits.attempt(ip("192.0.2.1"), "a").unwrap();
        limits.attempt(ip("192.0.2.1"), "a").unwrap();
        for _ in 0..10 {
            assert!(limits.attempt(ip("192.0.2.1"), "a").is_err());
        }
        std::thread::sleep(Duration::from_millis(60));
        limits.attempt(ip("192.0.2.1"), "a").unwrap();
    }
}
