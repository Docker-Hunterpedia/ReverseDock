//! Live feeds for the admin API's streams (ADR-0024): access-log lines and events (reloads,
//! backend health, certificates). The data plane hands an entry over with a non-blocking send
//! on a bounded lock-free channel, and only while someone watches; when the admin side falls
//! behind, entries are dropped and counted, never waited for.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Mutex, PoisonError};

use serde_json::Value;

/// Entries in flight between the data plane and the admin side.
const QUEUE: usize = 4096;

/// The sending end, shared by every listener and task.
#[derive(Debug)]
pub struct Feed {
    sender: SyncSender<Value>,
    watchers: AtomicUsize,
    dropped: AtomicU64,
    receiver: Mutex<Option<Receiver<Value>>>,
}

impl Default for Feed {
    fn default() -> Self {
        let (sender, receiver) = sync_channel(QUEUE);
        Self {
            sender,
            watchers: AtomicUsize::new(0),
            dropped: AtomicU64::new(0),
            receiver: Mutex::new(Some(receiver)),
        }
    }
}

impl Feed {
    /// Whether anyone watches; callers skip building an entry when not.
    #[must_use]
    pub fn watched(&self) -> bool {
        self.watchers.load(Ordering::Relaxed) > 0
    }

    /// Hands an entry over without waiting. Dropped (and counted) when nobody watches or the
    /// queue is full.
    pub fn send(&self, entry: Value) {
        if !self.watched() {
            return;
        }
        if let Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) =
            self.sender.try_send(entry)
        {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Entries dropped because the admin side fell behind.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// The receiving end, for the admin side; `None` after the first call.
    pub fn take_receiver(&self) -> Option<Receiver<Value>> {
        self.receiver
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
    }

    /// Sets how many streams watch.
    pub fn set_watchers(&self, count: usize) {
        self.watchers.store(count, Ordering::Relaxed);
    }
}

/// The two feeds of a process.
#[derive(Debug, Clone, Default)]
pub struct Feeds {
    /// Access-log lines, redacted like the access log.
    pub logs: Arc<Feed>,
    /// Reloads, backend health changes, certificate events.
    pub events: Arc<Feed>,
    /// Where alerts are raised (`observability.alerts`).
    pub alerts: crate::alerts::AlertSink,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries_flow_only_while_watched_and_overflow_is_counted() {
        let feed = Feed::default();
        let receiver = feed.take_receiver().unwrap();
        feed.send(serde_json::json!({ "n": 0 }));
        assert!(
            receiver.try_recv().is_err(),
            "nobody watches: nothing is queued"
        );
        feed.set_watchers(1);
        feed.send(serde_json::json!({ "n": 1 }));
        assert_eq!(receiver.try_recv().unwrap()["n"], 1);
        for n in 0..QUEUE + 10 {
            feed.send(serde_json::json!({ "n": n }));
        }
        assert_eq!(feed.dropped(), 10);
        assert!(feed.take_receiver().is_none());
    }
}
