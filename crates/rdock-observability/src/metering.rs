//! Usage metering (F-GW-05, ADR-0030): one event per finished request that has a consumer,
//! sent in batches to a webhook as `CloudEvents` 1.0 (`application/cloudevents-batch+json`)
//! and/or to an OTLP/HTTP logs endpoint (JSON encoding).
//!
//! The request path only puts the event in each sink's bounded queue with `try_send`: when the
//! queue is full the event is dropped and counted (`rdock_metering_dropped_total{reason=
//! "queue_full"}`), so a slow or hanging receiver never delays a request. Each sink's task
//! sends a batch when it holds `max_batch` events or its oldest event has waited
//! `flush_interval`, and retries a failed batch (network error, timeout, `429`, `5xx`) with
//! growing pauses, with the same event IDs: delivery is at least once, and receivers
//! deduplicate on `source` and `id` (`CloudEvents` 1.0.2 §3.1.2). A batch that still fails, or
//! is refused with another status, is dropped and counted as `undeliverable`. There is no
//! disk spool: events still queued are lost when the process ends abruptly.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use rdock_model::gateway::{Metering as Settings, MeteringOtlp, MeteringWebhook};
use serde_json::{Value, json};
use tokio::sync::mpsc;

use crate::alerts::deliver::{Clients, secret, sign};
use crate::metrics::Metrics;

/// Time allowed for one delivery attempt.
const TIMEOUT: Duration = Duration::from_secs(10);
/// Attempts per batch before it is dropped.
const ATTEMPTS: u32 = 6;
/// The pause after the first failed attempt; doubled after each, with jitter.
const FIRST_PAUSE: Duration = Duration::from_millis(500);
/// The longest pause between attempts.
const MAX_PAUSE: Duration = Duration::from_secs(30);

/// One finished request.
#[derive(Debug, Clone, PartialEq)]
pub struct MeterEvent {
    /// Unique and time-ordered (`UUIDv7`).
    pub id: String,
    /// When the request finished.
    pub time: SystemTime,
    /// The consumer, when one was set.
    pub consumer: Option<String>,
    /// The consumer's groups.
    pub groups: Vec<String>,
    /// The public ID of the API key used.
    pub key_id: Option<String>,
    /// The route.
    pub route: String,
    /// The service.
    pub service: String,
    /// The request method.
    pub method: String,
    /// The status sent.
    pub status: u16,
    /// Request body bytes read.
    pub bytes_in: u64,
    /// Response body bytes sent.
    pub bytes_out: u64,
    /// Total time in milliseconds.
    pub duration_ms: f64,
    /// What the HTTP cache did, on caching routes.
    pub cache_status: Option<String>,
}

impl MeterEvent {
    fn data(&self) -> Value {
        json!({
            "consumer": self.consumer,
            "groups": self.groups,
            "key_id": self.key_id,
            "route": self.route,
            "service": self.service,
            "method": self.method,
            "status": self.status,
            "bytes_in": self.bytes_in,
            "bytes_out": self.bytes_out,
            "duration_ms": self.duration_ms,
            "cache_status": self.cache_status,
        })
    }

    /// The event as a `CloudEvents` 1.0 structured JSON object.
    fn cloud_event(&self, kind: &str, source: &str) -> Value {
        let mut event = json!({
            "specversion": "1.0",
            "id": self.id,
            "source": source,
            "type": kind,
            "time": crate::rfc3339(self.time),
            "datacontenttype": "application/json",
            "data": self.data(),
        });
        if let Some(consumer) = &self.consumer {
            event["subject"] = json!(consumer);
        }
        event
    }

    /// The event as an OTLP log record (JSON encoding: 64-bit integers are strings).
    fn log_record(&self, kind: &str) -> Value {
        let nanos = self
            .time
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
            .to_string();
        let string = |k: &str, v: &str| json!({ "key": k, "value": { "stringValue": v } });
        let int = |k: &str, v: u64| json!({ "key": k, "value": { "intValue": v.to_string() } });
        let mut attributes = vec![
            string("event.id", &self.id),
            string("event.name", kind),
            string("rdock.route", &self.route),
            string("rdock.service", &self.service),
            string("http.request.method", &self.method),
            int("http.response.status_code", u64::from(self.status)),
            int("http.request.body.size", self.bytes_in),
            int("http.response.body.size", self.bytes_out),
            json!({ "key": "rdock.duration_ms", "value": { "doubleValue": self.duration_ms } }),
        ];
        if let Some(consumer) = &self.consumer {
            attributes.push(string("rdock.consumer", consumer));
        }
        if !self.groups.is_empty() {
            attributes.push(string("rdock.consumer.groups", &self.groups.join(",")));
        }
        if let Some(key) = &self.key_id {
            attributes.push(string("rdock.key_id", key));
        }
        if let Some(cache) = &self.cache_status {
            attributes.push(string("rdock.cache_status", cache));
        }
        json!({
            "timeUnixNano": nanos,
            "observedTimeUnixNano": nanos,
            "severityNumber": 9,
            "severityText": "INFO",
            "body": { "stringValue": kind },
            "attributes": attributes,
        })
    }
}

/// A sink's queue, as the request path sees it.
#[derive(Debug)]
struct Queue {
    name: &'static str,
    sender: mpsc::Sender<MeterEvent>,
}

/// The metering of one configuration: one queue and one task per sink. Dropping it lets the
/// tasks send what they hold and end.
#[derive(Debug)]
pub struct Meter {
    all_requests: bool,
    queues: Vec<Queue>,
    metrics: Metrics,
}

/// What a sink task needs.
struct Sink {
    name: &'static str,
    target: Target,
    max_batch: usize,
    flush: Duration,
}

enum Target {
    Webhook {
        url: String,
        kind: String,
        source: String,
        secret: Option<String>,
        token: Option<String>,
        allow_private: bool,
    },
    Otlp {
        url: String,
        token: Option<String>,
        allow_private: bool,
    },
}

/// `<base>/v1/logs`, unless the URL already ends with it.
fn logs_endpoint(url: &url::Url) -> String {
    let text = url.as_str().trim_end_matches('/');
    if text.ends_with("/v1/logs") {
        text.to_owned()
    } else {
        format!("{text}/v1/logs")
    }
}

/// `rdock/<host name>`.
fn default_source() -> String {
    let host = std::env::var("HOSTNAME")
        .ok()
        .filter(|h| !h.trim().is_empty())
        .or_else(|| {
            std::fs::read_to_string("/proc/sys/kernel/hostname")
                .ok()
                .map(|h| h.trim().to_owned())
                .filter(|h| !h.is_empty())
        })
        .unwrap_or_else(|| "unknown".to_owned());
    format!("rdock/{host}")
}

impl Meter {
    /// Starts the sinks of `settings`; must run inside a tokio runtime. Secret references
    /// are resolved now: a missing file or variable fails here, never per request.
    ///
    /// # Errors
    ///
    /// A secret reference cannot be resolved, or the HTTP client cannot start.
    pub fn start(settings: &Settings, metrics: Metrics) -> Result<Self, String> {
        let clients = Arc::new(Clients::new()?);
        let resolve = |reference: &Option<String>, what: &str| -> Result<Option<String>, String> {
            reference
                .as_deref()
                .map(|r| secret(r).map_err(|e| format!("observability.metering.{what}: {e}")))
                .transpose()
        };
        let mut sinks = Vec::new();
        if let Some(MeteringWebhook {
            url,
            r#type,
            source,
            secret: signing,
            token,
            allow_private_targets,
        }) = &settings.webhook
        {
            sinks.push(Sink {
                name: "webhook",
                target: Target::Webhook {
                    url: url.as_url().to_string(),
                    kind: r#type.clone(),
                    source: source.clone().unwrap_or_else(default_source),
                    secret: resolve(signing, "webhook.secret")?,
                    token: resolve(token, "webhook.token")?,
                    allow_private: *allow_private_targets,
                },
                max_batch: settings.max_batch as usize,
                flush: settings.flush_interval.as_std(),
            });
        }
        if let Some(MeteringOtlp {
            endpoint,
            token,
            allow_private_targets,
        }) = &settings.otlp
        {
            sinks.push(Sink {
                name: "otlp",
                target: Target::Otlp {
                    url: logs_endpoint(endpoint.as_url()),
                    token: resolve(token, "otlp.token")?,
                    allow_private: *allow_private_targets,
                },
                max_batch: settings.max_batch as usize,
                flush: settings.flush_interval.as_std(),
            });
        }
        let queue = (settings.queue as usize).max(1);
        let mut queues = Vec::new();
        let kind = settings.webhook.as_ref().map_or_else(
            || "dev.reversedock.request.v1".to_owned(),
            |w| w.r#type.clone(),
        );
        for sink in sinks {
            let (sender, receiver) = mpsc::channel(queue);
            queues.push(Queue {
                name: sink.name,
                sender,
            });
            tokio::spawn(run(
                sink,
                receiver,
                clients.clone(),
                metrics.clone(),
                kind.clone(),
            ));
        }
        Ok(Self {
            all_requests: settings.all_requests,
            queues,
            metrics,
        })
    }

    /// Whether a request without a consumer is metered too.
    #[must_use]
    pub fn all_requests(&self) -> bool {
        self.all_requests
    }

    /// Queues `event` for every sink without waiting; a full queue drops it and counts.
    pub fn record(&self, event: &MeterEvent) {
        for queue in &self.queues {
            if queue.sender.try_send(event.clone()).is_err() {
                self.metrics
                    .metering_dropped
                    .with_label_values(&[queue.name, "queue_full"])
                    .inc();
            }
        }
    }
}

/// Collects batches and delivers them until the [`Meter`] is gone and the queue is empty.
async fn run(
    sink: Sink,
    mut receiver: mpsc::Receiver<MeterEvent>,
    clients: Arc<Clients>,
    metrics: Metrics,
    kind: String,
) {
    let mut batch: Vec<MeterEvent> = Vec::with_capacity(sink.max_batch.min(1024));
    loop {
        // Wait for the first event of a batch, then for more until it is full or old enough.
        match receiver.recv().await {
            Some(event) => batch.push(event),
            None => return,
        }
        let deadline = tokio::time::Instant::now() + sink.flush;
        let mut closed = false;
        while batch.len() < sink.max_batch {
            match tokio::time::timeout_at(deadline, receiver.recv()).await {
                Ok(Some(event)) => batch.push(event),
                Ok(None) => {
                    closed = true;
                    break;
                }
                Err(_) => break,
            }
        }
        deliver(&sink, &clients, &metrics, &kind, &batch).await;
        batch.clear();
        if closed {
            return;
        }
    }
}

/// Whether an answer means "try again later".
fn retryable(status: http::StatusCode) -> bool {
    status == http::StatusCode::TOO_MANY_REQUESTS
        || status == http::StatusCode::REQUEST_TIMEOUT
        || status.is_server_error()
}

/// What one delivery sends: the URL, the body, the headers, whether the target may be
/// private, and the signing secret.
type Prepared<'a> = (
    &'a str,
    String,
    Vec<(&'static str, String)>,
    bool,
    Option<&'a str>,
);

fn prepare<'a>(sink: &'a Sink, kind: &str, batch: &[MeterEvent]) -> Prepared<'a> {
    match &sink.target {
        Target::Webhook {
            url,
            kind,
            source,
            secret,
            token,
            allow_private,
        } => {
            let events: Vec<Value> = batch.iter().map(|e| e.cloud_event(kind, source)).collect();
            let mut headers = vec![(
                "content-type",
                "application/cloudevents-batch+json".to_owned(),
            )];
            if let Some(token) = token {
                headers.push(("authorization", format!("Bearer {token}")));
            }
            (
                url,
                Value::Array(events).to_string(),
                headers,
                *allow_private,
                secret.as_deref(),
            )
        }
        Target::Otlp {
            url,
            token,
            allow_private,
        } => {
            let records: Vec<Value> = batch.iter().map(|e| e.log_record(kind)).collect();
            let body = json!({ "resourceLogs": [{
                "resource": { "attributes": [
                    { "key": "service.name", "value": { "stringValue": "rdock" } },
                    { "key": "service.version", "value": { "stringValue": env!("CARGO_PKG_VERSION") } },
                ] },
                "scopeLogs": [{ "scope": { "name": "rdock.metering" }, "logRecords": records }],
            }] });
            let mut headers = vec![("content-type", "application/json".to_owned())];
            if let Some(token) = token {
                headers.push(("authorization", format!("Bearer {token}")));
            }
            (url, body.to_string(), headers, *allow_private, None)
        }
    }
}

async fn deliver(
    sink: &Sink,
    clients: &Clients,
    metrics: &Metrics,
    kind: &str,
    batch: &[MeterEvent],
) {
    let (url, body, mut headers, allow_private, signing) = prepare(sink, kind, batch);
    // The delivery's ID is its first event's: a retried batch is recognisable.
    let message_id = format!("msg_{}", batch.first().map_or("", |e| e.id.as_str()));
    let count = batch.len() as u64;
    let mut pause = FIRST_PAUSE;
    let base = headers.len();
    for attempt in 1..=ATTEMPTS {
        headers.truncate(base);
        if let Some(secret) = signing {
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            match sign(secret, &message_id, timestamp, &body) {
                Ok(signature) => {
                    headers.push(("webhook-id", message_id.clone()));
                    headers.push(("webhook-timestamp", timestamp.to_string()));
                    headers.push(("webhook-signature", signature));
                }
                Err(err) => {
                    tracing::warn!(sink = sink.name, error = %err, "cannot sign metering events");
                    break;
                }
            }
        }
        let outcome = clients
            .post_raw(
                allow_private,
                url,
                &headers,
                Bytes::from(body.clone()),
                TIMEOUT,
            )
            .await;
        let again = match outcome {
            Ok(status) if status.is_success() => {
                metrics
                    .metering_events
                    .with_label_values(&[sink.name, "sent"])
                    .inc_by(count);
                return;
            }
            Ok(status) if retryable(status) => format!("answered {status}"),
            Ok(status) => {
                tracing::warn!(sink = sink.name, %status, events = count, "metering events refused; dropped");
                break;
            }
            Err(err) => err,
        };
        if attempt == ATTEMPTS {
            tracing::warn!(sink = sink.name, error = %again, events = count, "metering events undeliverable; dropped");
            break;
        }
        tracing::debug!(sink = sink.name, error = %again, attempt, "metering delivery failed; retrying");
        let jitter = Duration::from_millis(fastrand::u64(
            0..=pause.as_millis().try_into().unwrap_or(u64::MAX) / 4,
        ));
        tokio::time::sleep(pause + jitter).await;
        pause = (pause * 2).min(MAX_PAUSE);
    }
    metrics
        .metering_events
        .with_label_values(&[sink.name, "failed"])
        .inc_by(count);
    metrics
        .metering_dropped
        .with_label_values(&[sink.name, "undeliverable"])
        .inc_by(count);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event() -> MeterEvent {
        MeterEvent {
            id: "0190d4c4-8b6e-7a3c-9d2e-1f2a3b4c5d6e".into(),
            time: UNIX_EPOCH + Duration::from_secs(1_798_761_600),
            consumer: Some("acme".into()),
            groups: vec!["gold".into()],
            key_id: Some("AbCdEfGhIjK0".into()),
            route: "api".into(),
            service: "app".into(),
            method: "GET".into(),
            status: 200,
            bytes_in: 0,
            bytes_out: 512,
            duration_ms: 1.5,
            cache_status: None,
        }
    }

    #[test]
    fn events_are_cloud_events_and_otlp_records() {
        let ce = event().cloud_event("dev.reversedock.request.v1", "rdock/edge-1");
        assert_eq!(ce["specversion"], "1.0");
        assert_eq!(ce["id"], "0190d4c4-8b6e-7a3c-9d2e-1f2a3b4c5d6e");
        assert_eq!(ce["subject"], "acme");
        assert_eq!(ce["time"], "2027-01-01T00:00:00.000Z");
        assert_eq!(ce["data"]["bytes_out"], 512);
        let log = event().log_record("dev.reversedock.request.v1");
        assert_eq!(log["timeUnixNano"], "1798761600000000000");
        assert!(
            log["attributes"]
                .as_array()
                .unwrap()
                .iter()
                .any(|a| a["key"] == "rdock.consumer" && a["value"]["stringValue"] == "acme")
        );
        let url: url::Url = "http://collector:4318".parse().unwrap();
        assert_eq!(logs_endpoint(&url), "http://collector:4318/v1/logs");
        let full: url::Url = "http://collector:4318/v1/logs".parse().unwrap();
        assert_eq!(logs_endpoint(&full), "http://collector:4318/v1/logs");
    }

    #[tokio::test]
    async fn a_full_queue_drops_the_newest_and_counts() {
        let metrics = Metrics::new("test", "dev").unwrap();
        let settings: Settings = serde_json::from_value(json!({
            "webhook": { "url": "http://127.0.0.1:9/never", "allow_private_targets": true },
            "queue": 2, "max_batch": 1000, "flush_interval": "1h"
        }))
        .unwrap();
        let meter = Meter::start(&settings, metrics.clone()).unwrap();
        for _ in 0..10 {
            meter.record(&event());
        }
        // The task may have taken one event out of the queue already.
        let dropped = metrics
            .metering_dropped
            .with_label_values(&["webhook", "queue_full"])
            .get();
        assert!((7..=8).contains(&dropped), "{dropped}");
    }
}
