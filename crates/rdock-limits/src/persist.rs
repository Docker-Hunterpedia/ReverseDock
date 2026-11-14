//! How a background writer of counters and bans reports a disk it cannot write (ADR-0033): a
//! full disk degrades persistence, never request handling. Failures are counted for
//! `rdock_state_write_failures_total`, the first one and then one a minute per file are
//! logged, and the first write that succeeds again says so.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

/// Repeated failures for one file are logged at most this often.
const LOG_EVERY: Duration = Duration::from_secs(60);

/// Write failures of one kind of file (quota counters, ban lists).
#[derive(Debug, Default)]
pub struct Persistence {
    /// Failed writes since the start.
    failures: AtomicU64,
    /// Files whose last write failed, and when that was last logged.
    failing: Mutex<HashMap<String, Instant>>,
}

impl Persistence {
    /// Failed writes since the start.
    #[must_use]
    pub fn failures(&self) -> u64 {
        self.failures.load(Ordering::Relaxed)
    }

    /// Records the outcome of writing `name` (`what` names the kind in the log).
    pub fn outcome(&self, what: &str, name: &str, result: &std::io::Result<()>) {
        let mut failing = self.failing.lock().unwrap_or_else(PoisonError::into_inner);
        match result {
            Ok(()) => {
                if failing.remove(name).is_some() {
                    tracing::info!(%name, "the {what} are written again");
                }
            }
            Err(err) => {
                self.failures.fetch_add(1, Ordering::Relaxed);
                let now = Instant::now();
                let due = failing
                    .get(name)
                    .is_none_or(|logged| now.duration_since(*logged) >= LOG_EVERY);
                if due {
                    failing.insert(name.to_owned(), now);
                    tracing::warn!(%name, error = %err,
                        "cannot write the {what}; they stay in memory and are written when the disk takes writes again (logged once a minute)");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failures_are_counted_and_cleared_by_a_success() {
        let p = Persistence::default();
        let err = Err(std::io::Error::from_raw_os_error(28));
        p.outcome("quota counters", "q", &err);
        p.outcome("quota counters", "q", &err);
        assert_eq!(p.failures(), 2);
        assert!(p.failing.lock().unwrap().contains_key("q"));
        p.outcome("quota counters", "q", &Ok(()));
        assert!(p.failing.lock().unwrap().is_empty());
    }
}
