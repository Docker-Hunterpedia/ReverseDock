//! Alerts (ADR-0024, M-OBS-04, F-MGMT-04): certificates, backends and services down, error-rate
//! and latency thresholds, rejected configurations and admin security events go to Slack,
//! Discord, Slack-compatible chats, signed webhooks and e-mail. Producers call
//! [`AlertSink::raise`], which never blocks; a dispatcher task keeps what is firing, sends a
//! firing alert once and again at most every `min_interval`, sends `resolved` when it ends, and
//! delivers from a bounded queue with jittered retries. Never on the request path.

mod deliver;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use rdock_model::settings::{AlertRule, Alerts};
use serde::Serialize;
use serde_json::Value;
use tokio::sync::{mpsc, watch};

/// Alerts waiting for the dispatcher; more are dropped and counted.
const QUEUE: usize = 256;

/// Firing or over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    /// It started, or is still going.
    Firing,
    /// It is over.
    Resolved,
}

/// One alert.
#[derive(Debug, Clone, Serialize)]
pub struct Alert {
    /// What raised it.
    pub rule: AlertRule,
    /// Identifies the condition: the same key resolves what it fired.
    pub key: String,
    /// Firing or resolved.
    pub state: State,
    /// One line for people.
    pub summary: String,
    /// Details for machines.
    pub details: Value,
}

impl Alert {
    /// A firing alert.
    #[must_use]
    pub fn firing(
        rule: AlertRule,
        key: impl Into<String>,
        summary: impl Into<String>,
        details: Value,
    ) -> Self {
        Self {
            rule,
            key: key.into(),
            state: State::Firing,
            summary: summary.into(),
            details,
        }
    }

    /// The end of the condition `key`.
    #[must_use]
    pub fn resolved(rule: AlertRule, key: impl Into<String>, summary: impl Into<String>) -> Self {
        Self {
            rule,
            key: key.into(),
            state: State::Resolved,
            summary: summary.into(),
            details: Value::Null,
        }
    }
}

/// The producers' handle, cheap to clone and never blocking.
#[derive(Debug, Clone)]
pub struct AlertSink {
    sender: mpsc::Sender<Alert>,
    receiver: Arc<std::sync::Mutex<Option<mpsc::Receiver<Alert>>>>,
    dropped: Arc<AtomicU64>,
}

impl Default for AlertSink {
    fn default() -> Self {
        let (sender, receiver) = mpsc::channel(QUEUE);
        Self {
            sender,
            receiver: Arc::new(std::sync::Mutex::new(Some(receiver))),
            dropped: Arc::default(),
        }
    }
}

impl AlertSink {
    /// Queues an alert; when the dispatcher is behind it is dropped and counted.
    pub fn raise(&self, alert: Alert) {
        if self.sender.try_send(alert).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Alerts dropped because the queue was full.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Starts the dispatcher with the alert settings from `config`; call once.
    pub fn start(&self, config: watch::Receiver<Alerts>, sent: crate::Metrics) {
        if self
            .receiver
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_none()
        {
            return;
        }
        let receiver = self
            .receiver
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(receiver) = receiver {
            tokio::spawn(dispatch(receiver, config, sent));
        }
    }
}

struct Active {
    sent_at: Instant,
}

/// Whether `alert` should go out now, given what is firing; updates `active`.
fn decide(
    active: &mut HashMap<String, Active>,
    alert: &Alert,
    min_interval: Duration,
    now: Instant,
) -> bool {
    match alert.state {
        State::Firing => match active.get_mut(&alert.key) {
            Some(entry) if now.duration_since(entry.sent_at) < min_interval => false,
            Some(entry) => {
                entry.sent_at = now;
                true
            }
            None => {
                active.insert(alert.key.clone(), Active { sent_at: now });
                true
            }
        },
        State::Resolved => active.remove(&alert.key).is_some(),
    }
}

async fn dispatch(
    mut receiver: mpsc::Receiver<Alert>,
    config: watch::Receiver<Alerts>,
    metrics: crate::Metrics,
) {
    let mut active: HashMap<String, Active> = HashMap::new();
    let client = match deliver::Clients::new() {
        Ok(client) => client,
        Err(err) => {
            tracing::error!(error = %err, "cannot start alert delivery");
            return;
        }
    };
    while let Some(alert) = receiver.recv().await {
        let settings = config.borrow().clone();
        if settings.rules.disabled.contains(&alert.rule) {
            continue;
        }
        if !decide(
            &mut active,
            &alert,
            settings.min_interval.as_std(),
            Instant::now(),
        ) {
            continue;
        }
        match alert.state {
            State::Firing => {
                tracing::warn!(rule = ?alert.rule, key = %alert.key, "alert: {}", alert.summary);
            }
            State::Resolved => {
                tracing::info!(rule = ?alert.rule, key = %alert.key, "resolved: {}", alert.summary);
            }
        }
        for (name, channel) in deliver::channels(&settings) {
            if !deliver::wants(&channel, alert.rule) {
                continue;
            }
            let (client, alert, metrics) = (client.clone(), alert.clone(), metrics.clone());
            tokio::spawn(async move {
                let result = deliver::with_retries(&client, &name, &channel, &alert).await;
                let label = if result.is_ok() { "sent" } else { "failed" };
                metrics.alerts_sent.with_label_values(&[&name, label]).inc();
                if let Err(err) = result {
                    tracing::warn!(channel = %name, error = %err, "an alert could not be delivered");
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn backend(state: State) -> Alert {
        Alert {
            rule: AlertRule::Backends,
            key: "backend:app/10.0.0.1".into(),
            state,
            summary: String::new(),
            details: Value::Null,
        }
    }

    #[test]
    fn firing_is_sent_once_per_interval_and_resolved_once() {
        let mut active = HashMap::new();
        let start = Instant::now();
        let interval = Duration::from_secs(60);
        assert!(decide(
            &mut active,
            &backend(State::Firing),
            interval,
            start
        ));
        assert!(!decide(
            &mut active,
            &backend(State::Firing),
            interval,
            start + Duration::from_secs(30)
        ));
        assert!(
            decide(
                &mut active,
                &backend(State::Firing),
                interval,
                start + Duration::from_secs(61)
            ),
            "reminder"
        );
        assert!(decide(
            &mut active,
            &backend(State::Resolved),
            interval,
            start + Duration::from_secs(62)
        ));
        assert!(
            !decide(
                &mut active,
                &backend(State::Resolved),
                interval,
                start + Duration::from_secs(63)
            ),
            "nothing to resolve"
        );
    }

    #[test]
    fn a_full_queue_drops_and_counts() {
        let sink = AlertSink::default();
        for _ in 0..QUEUE + 3 {
            sink.raise(backend(State::Firing));
        }
        assert_eq!(sink.dropped(), 3);
    }
}
