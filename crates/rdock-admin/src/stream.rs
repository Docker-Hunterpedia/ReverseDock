//! Live logs and events over server-sent events (ADR-0024). A hub per feed takes entries from
//! the data plane's bounded channel on a thread of its own, numbers them, keeps the last 10,000
//! for `Last-Event-ID`, and fans them out; each subscriber has a bounded queue and is told
//! `lagged` instead of slowing anyone down. Filters run on the server. Streams re-check their
//! caller every 60 seconds and end when the session or token is gone.

use std::collections::{HashMap, VecDeque};
use std::convert::Infallible;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use axum::extract::{Extension, State as Extract};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use rdock_observability::feed::Feed;
use serde::Deserialize;
use serde_json::Value;
use tokio::sync::broadcast;

use crate::auth::Peer;
use crate::caller::{Access, Caller, identify, need};
use crate::routes::error;
use crate::{State, Transport};

/// Entries kept for reconnecting clients.
const REPLAY: usize = 10_000;
/// Entries a subscriber may fall behind before it is told `lagged`.
const SUBSCRIBER_QUEUE: usize = 1024;
/// Streams one identity may hold at once.
const PER_IDENTITY: usize = 4;
/// How often a stream checks that its caller may still read it.
const RECHECK: Duration = Duration::from_secs(60);

/// One numbered entry.
pub(crate) struct Entry {
    id: u64,
    value: Value,
    text: String,
}

/// The fan-out of one feed.
pub(crate) struct Hub {
    name: &'static str,
    feed: Option<Arc<Feed>>,
    replay: Mutex<VecDeque<Arc<Entry>>>,
    next: AtomicU64,
    sender: broadcast::Sender<Arc<Entry>>,
    subscribers: AtomicUsize,
    lagged: AtomicU64,
}

impl Hub {
    /// A hub fed by `feed` (the data plane), or only by [`publish`](Self::publish).
    pub(crate) fn start(feed: Option<Arc<Feed>>, name: &'static str) -> Arc<Self> {
        let (sender, _) = broadcast::channel(SUBSCRIBER_QUEUE);
        let receiver = feed.as_ref().and_then(|f| f.take_receiver());
        let hub = Arc::new(Self {
            name,
            feed,
            replay: Mutex::new(VecDeque::with_capacity(REPLAY)),
            next: AtomicU64::new(1),
            sender,
            subscribers: AtomicUsize::new(0),
            lagged: AtomicU64::new(0),
        });
        if let Some(receiver) = receiver {
            let worker = Arc::downgrade(&hub);
            let spawned = std::thread::Builder::new()
                .name(format!("rdock-admin-{name}"))
                .spawn(move || {
                    while let Ok(value) = receiver.recv() {
                        let Some(hub) = worker.upgrade() else { return };
                        hub.publish(value);
                    }
                });
            if let Err(err) = spawned {
                tracing::error!(error = %err, feed = name, "cannot start a live feed");
            }
        }
        hub
    }

    /// Numbers an entry, keeps it for replay and sends it to every subscriber.
    pub(crate) fn publish(&self, value: Value) {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let entry = Arc::new(Entry {
            id,
            text: value.to_string(),
            value,
        });
        {
            let mut replay = self.replay.lock().unwrap_or_else(PoisonError::into_inner);
            if replay.len() == REPLAY {
                replay.pop_front();
            }
            replay.push_back(entry.clone());
        }
        let _ = self.sender.send(entry);
    }

    /// Entries after `id`, or `None` when `id` is older than the replay buffer.
    fn after(&self, id: u64) -> Option<Vec<Arc<Entry>>> {
        let replay = self.replay.lock().unwrap_or_else(PoisonError::into_inner);
        let oldest = replay
            .front()
            .map_or(self.next.load(Ordering::Relaxed), |e| e.id);
        if id + 1 < oldest {
            return None;
        }
        Some(replay.iter().filter(|e| e.id > id).cloned().collect())
    }

    fn watch(self: &Arc<Self>) -> Watching {
        let count = self.subscribers.fetch_add(1, Ordering::Relaxed) + 1;
        if let Some(feed) = &self.feed {
            feed.set_watchers(count);
        }
        Watching(self.clone())
    }

    /// Streams open now.
    pub(crate) fn subscribers(&self) -> usize {
        self.subscribers.load(Ordering::Relaxed)
    }

    /// Entries lost: dropped before the hub, or by subscribers that fell behind.
    pub(crate) fn dropped(&self) -> u64 {
        self.lagged.load(Ordering::Relaxed) + self.feed.as_ref().map_or(0, |f| f.dropped())
    }
}

/// One open stream; counted until dropped.
struct Watching(Arc<Hub>);

impl Drop for Watching {
    fn drop(&mut self) {
        let count = self.0.subscribers.fetch_sub(1, Ordering::Relaxed) - 1;
        if let Some(feed) = &self.0.feed {
            feed.set_watchers(count);
        }
    }
}

/// Streams per identity.
#[derive(Default)]
pub(crate) struct Quota {
    open: Mutex<HashMap<String, usize>>,
}

struct Slot(Arc<State>, String);

impl Drop for Slot {
    fn drop(&mut self) {
        let mut open = self
            .0
            .quota
            .open
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(n) = open.get_mut(&self.1) {
            *n -= 1;
            if *n == 0 {
                open.remove(&self.1);
            }
        }
    }
}

fn take_slot(state: &Arc<State>, identity: String) -> Option<Slot> {
    let mut open = state
        .quota
        .open
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let n = open.entry(identity.clone()).or_default();
    if *n >= PER_IDENTITY {
        return None;
    }
    *n += 1;
    Some(Slot(state.clone(), identity))
}

/// Server-side filters (`?route=…&service=…&status=5xx&client=10.0.&q=text&type=reload`).
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Filter {
    route: Option<String>,
    service: Option<String>,
    /// An exact status (`404`) or a class (`5xx`).
    status: Option<String>,
    /// Client address prefix.
    client: Option<String>,
    /// Text the entry must contain.
    q: Option<String>,
    /// Event type (`reload`, `backend`, `admin`).
    #[serde(rename = "type")]
    kind: Option<String>,
}

impl Filter {
    fn keeps(&self, entry: &Entry) -> bool {
        let field = |name: &str| {
            entry
                .value
                .get(name)
                .and_then(Value::as_str)
                .unwrap_or_default()
        };
        let same =
            |want: &Option<String>, name: &str| want.as_ref().is_none_or(|w| field(name) == w);
        let status = entry
            .value
            .get("status")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let status_ok = self
            .status
            .as_ref()
            .is_none_or(|want| match want.strip_suffix("xx") {
                Some(class) => class.parse::<u64>().is_ok_and(|c| status / 100 == c),
                None => want.parse::<u64>().is_ok_and(|s| s == status),
            });
        same(&self.route, "route")
            && same(&self.service, "service")
            && same(&self.kind, "type")
            && status_ok
            && self
                .client
                .as_ref()
                .is_none_or(|c| field("client_ip").starts_with(c.as_str()))
            && self
                .q
                .as_ref()
                .is_none_or(|q| entry.text.contains(q.as_str()))
    }
}

fn event(entry: &Entry) -> Event {
    Event::default().id(entry.id.to_string()).data(&entry.text)
}

/// Everything a stream needs between polls.
struct Stream {
    state: Arc<State>,
    receiver: broadcast::Receiver<Arc<Entry>>,
    pending: VecDeque<Event>,
    filter: Filter,
    checked: Instant,
    credentials: (Method, HeaderMap, Option<Transport>, Option<Peer>),
    watching: Watching,
    _slot: Slot,
}

impl Stream {
    /// The next event, or `None` to end the stream.
    async fn next(&mut self) -> Option<Event> {
        loop {
            if let Some(event) = self.pending.pop_front() {
                return Some(event);
            }
            let recheck_at = self.checked + RECHECK;
            tokio::select! {
                received = self.receiver.recv() => match received {
                    Ok(entry) if self.filter.keeps(&entry) => return Some(event(&entry)),
                    Ok(_) => {}
                    Err(broadcast::error::RecvError::Lagged(missed)) => {
                        self.watching.0.lagged.fetch_add(missed, Ordering::Relaxed);
                        return Some(Event::default().event("lagged").data(missed.to_string()));
                    }
                    Err(broadcast::error::RecvError::Closed) => return None,
                },
                () = tokio::time::sleep_until(recheck_at.into()) => {
                    let (method, headers, transport, peer) = &self.credentials;
                    let still = identify(&self.state, method, headers, *transport, *peer)
                        .is_ok_and(|caller| need(&caller, Access::Viewer).is_ok());
                    if !still {
                        return None;
                    }
                    self.checked = Instant::now();
                }
            }
        }
    }
}

fn last_event_id(headers: &HeaderMap) -> Option<u64> {
    headers
        .get("last-event-id")?
        .to_str()
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// Opens a stream on `hub` for `caller`.
fn open(
    state: &Arc<State>,
    hub: &Arc<Hub>,
    caller: &Caller,
    filter: Filter,
    request: (Method, HeaderMap, Option<Transport>, Option<Peer>),
) -> Response {
    if let Err(denied) = need(caller, Access::Viewer) {
        return denied.into_response();
    }
    let Some(slot) = take_slot(state, format!("{}:{}", caller.name(), hub.name)) else {
        return error(
            StatusCode::TOO_MANY_REQUESTS,
            "at most 4 streams per user or token",
        );
    };
    let receiver = hub.sender.subscribe();
    let mut pending = VecDeque::new();
    if let Some(id) = last_event_id(&request.1) {
        match hub.after(id) {
            Some(entries) => {
                pending.extend(entries.iter().filter(|e| filter.keeps(e)).map(|e| event(e)));
            }
            None => pending.push_back(
                Event::default()
                    .event("reset")
                    .data("too far behind; start again"),
            ),
        }
    }
    let stream = Stream {
        state: state.clone(),
        receiver,
        pending,
        filter,
        checked: Instant::now(),
        credentials: request,
        watching: hub.watch(),
        _slot: slot,
    };
    let events = futures_util::stream::unfold(stream, |mut stream| async move {
        stream
            .next()
            .await
            .map(|event| (Ok::<_, Infallible>(event), stream))
    });
    let mut response = Sse::new(events)
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
        .into_response();
    response
        .headers_mut()
        .insert("x-accel-buffering", HeaderValue::from_static("no"));
    response
}

/// `GET /api/v1/logs/stream`: access-log lines as they happen.
pub(crate) async fn logs(
    Extract(state): Extract<Arc<State>>,
    Extension(caller): Extension<Caller>,
    axum::extract::Query(filter): axum::extract::Query<Filter>,
    method: Method,
    headers: HeaderMap,
    transport: Option<Extension<Transport>>,
    peer: Option<Extension<Peer>>,
) -> Response {
    let hub = state.logs.clone();
    open(
        &state,
        &hub,
        &caller,
        filter,
        (method, headers, transport.map(|t| t.0), peer.map(|p| p.0)),
    )
}

/// `GET /api/v1/events/stream`: reloads, backend health, certificate and admin events.
pub(crate) async fn events(
    Extract(state): Extract<Arc<State>>,
    Extension(caller): Extension<Caller>,
    axum::extract::Query(filter): axum::extract::Query<Filter>,
    method: Method,
    headers: HeaderMap,
    transport: Option<Extension<Transport>>,
    peer: Option<Extension<Peer>>,
) -> Response {
    let hub = state.events.clone();
    open(
        &state,
        &hub,
        &caller,
        filter,
        (method, headers, transport.map(|t| t.0), peer.map(|p| p.0)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: u64, value: Value) -> Entry {
        Entry {
            id,
            text: value.to_string(),
            value,
        }
    }

    #[test]
    fn filters_match_fields_classes_and_text() {
        let line = entry(
            1,
            serde_json::json!({ "route": "app", "service": "app", "status": 503, "client_ip": "10.1.2.3", "path": "/cart" }),
        );
        let parse = |q: &str| -> Filter {
            serde_json::from_value(serde_json::from_str(q).unwrap()).unwrap()
        };
        assert!(Filter::default().keeps(&line));
        assert!(parse(r#"{"status":"5xx","route":"app"}"#).keeps(&line));
        assert!(!parse(r#"{"status":"4xx"}"#).keeps(&line));
        assert!(parse(r#"{"status":"503","client":"10.1."}"#).keeps(&line));
        assert!(parse(r#"{"q":"/cart"}"#).keeps(&line));
        assert!(!parse(r#"{"service":"other"}"#).keeps(&line));
    }

    #[test]
    fn replay_resumes_after_an_id_or_asks_for_a_reset() {
        let hub = Hub::start(None, "test");
        for n in 0..(REPLAY as u64 + 5) {
            hub.publish(serde_json::json!({ "n": n }));
        }
        assert!(hub.after(1).is_none(), "id 1 is gone from the buffer");
        let tail = hub.after(REPLAY as u64 + 3).unwrap();
        assert_eq!(tail.len(), 2);
        assert_eq!(tail[1].value["n"], REPLAY as u64 + 4);
    }
}
