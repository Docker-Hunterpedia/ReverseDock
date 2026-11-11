//! Leader election (ADR-0029): our own loop on a `coordination.k8s.io/v1` Lease, with
//! client-go's algorithm (`k8s.io/client-go/tools/leaderelection`).
//!
//! - A candidate reads the Lease. It takes it when the Lease is absent (create), when it has
//!   no holder, or when the record has not changed for `leaseDurationSeconds` **as measured on
//!   the candidate's own monotonic clock from the moment it last saw the record change**. The
//!   timestamps in the record are never compared with the local clock, so clock skew between
//!   pods does not matter.
//! - Every write is a compare-and-swap: create fails with 409 when someone else created it
//!   first, replace carries `resourceVersion` and fails with 409 when someone else wrote.
//! - The leader renews every retry period and stops leading at once when it has not renewed
//!   for the renew deadline, or when it sees another holder.
//! - On shutdown the leader writes an empty holder with a one-second duration
//!   (`ReleaseOnCancel`), so a successor takes over in one retry period.
//!
//! [`Observer::step`] is the whole decision as a pure function, tested without a cluster;
//! [`Elector`] does the I/O around it.

use std::time::{Duration, Instant};

use k8s_openapi::api::coordination::v1::{Lease, LeaseSpec};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::MicroTime;
use k8s_openapi::jiff::Timestamp;
use kube::api::{Api, ObjectMeta, PostParams};
use tokio::sync::watch;

/// client-go's timings. The defaults are client-go's and controller-runtime's (15 s, 10 s,
/// 2 s); tests shorten them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaseTimings {
    /// How long a record stays valid after it was last seen to change
    /// (`leaseDurationSeconds`, whole seconds).
    pub lease_duration: Duration,
    /// How long the leader keeps leading without a successful renewal.
    pub renew_deadline: Duration,
    /// How often candidates retry and the leader renews.
    pub retry_period: Duration,
}

impl Default for LeaseTimings {
    fn default() -> Self {
        Self {
            lease_duration: Duration::from_secs(15),
            renew_deadline: Duration::from_secs(10),
            retry_period: Duration::from_secs(2),
        }
    }
}

impl LeaseTimings {
    fn lease_seconds(&self) -> i32 {
        i32::try_from(self.lease_duration.as_secs().max(1)).unwrap_or(i32::MAX)
    }
}

/// The fields of a Lease that the algorithm reads and writes (client-go's
/// `LeaderElectionRecord`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LeaseRecord {
    /// `holderIdentity`; empty when nobody holds it.
    pub holder: String,
    /// `leaseDurationSeconds`.
    pub lease_duration_seconds: i32,
    /// `acquireTime`.
    pub acquire_time: Option<Timestamp>,
    /// `renewTime`.
    pub renew_time: Option<Timestamp>,
    /// `leaseTransitions`.
    pub transitions: i32,
}

impl LeaseRecord {
    /// The record of a Lease object.
    #[must_use]
    pub fn of(lease: &Lease) -> Self {
        let spec = lease.spec.clone().unwrap_or_default();
        Self {
            holder: spec.holder_identity.unwrap_or_default(),
            lease_duration_seconds: spec.lease_duration_seconds.unwrap_or(0),
            acquire_time: spec.acquire_time.map(|t| t.0),
            renew_time: spec.renew_time.map(|t| t.0),
            transitions: spec.lease_transitions.unwrap_or(0),
        }
    }

    fn write_to(&self, spec: &mut LeaseSpec) {
        spec.holder_identity = Some(self.holder.clone());
        spec.lease_duration_seconds = Some(self.lease_duration_seconds);
        spec.acquire_time = self.acquire_time.map(MicroTime);
        spec.renew_time = self.renew_time.map(MicroTime);
        spec.lease_transitions = Some(self.transitions);
    }
}

/// What the candidate or leader should do next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Someone else holds a valid Lease: stay (or become) a follower.
    Follow {
        /// The current holder.
        holder: String,
    },
    /// The Lease does not exist: create it with this record.
    Create(LeaseRecord),
    /// Take or renew the Lease: replace it with this record (guarded by `resourceVersion`).
    Update(LeaseRecord),
}

/// The local memory of the algorithm: the last record seen and when (on the monotonic
/// clock) it was first seen in that form.
#[derive(Debug, Clone, Default)]
pub struct Observer {
    observed: Option<LeaseRecord>,
    observed_at: Option<Instant>,
}

impl Observer {
    /// Decides the next step from the Lease as just read (`current`, `None` when absent),
    /// the monotonic `now`, the wall-clock `wall` (only written, never compared) and our
    /// identity.
    pub fn step(
        &mut self,
        current: Option<&LeaseRecord>,
        now: Instant,
        wall: Timestamp,
        identity: &str,
        timings: &LeaseTimings,
    ) -> Step {
        let Some(current) = current else {
            return Step::Create(LeaseRecord {
                holder: identity.to_owned(),
                lease_duration_seconds: timings.lease_seconds(),
                acquire_time: Some(wall),
                renew_time: Some(wall),
                transitions: 0,
            });
        };
        if self.observed.as_ref() != Some(current) {
            self.observed = Some(current.clone());
            self.observed_at = Some(now);
        }
        let valid_for =
            Duration::from_secs(u64::try_from(current.lease_duration_seconds).unwrap_or(0));
        let observed_at = self.observed_at.unwrap_or(now);
        if !current.holder.is_empty() && current.holder != identity && observed_at + valid_for > now
        {
            return Step::Follow {
                holder: current.holder.clone(),
            };
        }
        let ours = current.holder == identity;
        Step::Update(LeaseRecord {
            holder: identity.to_owned(),
            lease_duration_seconds: timings.lease_seconds(),
            acquire_time: if ours {
                current.acquire_time
            } else {
                Some(wall)
            },
            renew_time: Some(wall),
            transitions: if ours {
                current.transitions
            } else {
                current.transitions.saturating_add(1)
            },
        })
    }

    /// Records a successful create or update: we hold `record`, seen `now`.
    pub fn succeeded(&mut self, record: LeaseRecord, now: Instant) {
        self.observed = Some(record);
        self.observed_at = Some(now);
    }

    /// The record that releases the Lease (empty holder, one second), when we hold it.
    #[must_use]
    pub fn release(&self, identity: &str, wall: Timestamp) -> Option<LeaseRecord> {
        let observed = self.observed.as_ref()?;
        (observed.holder == identity).then(|| LeaseRecord {
            holder: String::new(),
            lease_duration_seconds: 1,
            acquire_time: Some(wall),
            renew_time: Some(wall),
            transitions: observed.transitions,
        })
    }
}

/// Why one attempt did not end with us holding the Lease.
#[derive(Debug)]
enum Attempt {
    Leading,
    Following(String),
    Conflict,
    Failed(String),
}

/// The I/O around [`Observer`]: one Lease, one identity.
pub struct Elector {
    api: Api<Lease>,
    name: String,
    identity: String,
    timings: LeaseTimings,
    observer: Observer,
    /// The Lease as last read or written, for the next replace.
    live: Option<Lease>,
}

impl Elector {
    /// An elector for Lease `name` in the namespace of `api`.
    #[must_use]
    pub fn new(api: Api<Lease>, name: &str, identity: &str, timings: LeaseTimings) -> Self {
        Self {
            api,
            name: name.to_owned(),
            identity: identity.to_owned(),
            timings,
            observer: Observer::default(),
            live: None,
        }
    }

    /// Spawns the election; the receiver says whether we lead. It turns `false` before the
    /// Lease is released on shutdown, and the task ends after the release.
    pub fn spawn(
        self,
        shutdown: watch::Receiver<bool>,
    ) -> (watch::Receiver<bool>, tokio::task::JoinHandle<()>) {
        let (tx, rx) = watch::channel(false);
        let task = tokio::spawn(self.run(tx, shutdown));
        (rx, task)
    }

    fn call_timeout(&self) -> Duration {
        self.timings.renew_deadline.min(Duration::from_secs(10))
    }

    async fn attempt(&mut self) -> Attempt {
        let timeout = self.call_timeout();
        let current = match tokio::time::timeout(timeout, self.api.get_opt(&self.name)).await {
            Ok(Ok(lease)) => lease,
            Ok(Err(err)) => return Attempt::Failed(err.to_string()),
            Err(_) => return Attempt::Failed("reading the Lease timed out".to_owned()),
        };
        let record = current.as_ref().map(LeaseRecord::of);
        let step = self.observer.step(
            record.as_ref(),
            Instant::now(),
            now_micros(),
            &self.identity,
            &self.timings,
        );
        let (record, result) = match step {
            Step::Follow { holder } => {
                self.live = current;
                return Attempt::Following(holder);
            }
            Step::Create(record) => {
                let mut spec = LeaseSpec::default();
                record.write_to(&mut spec);
                let lease = Lease {
                    metadata: ObjectMeta {
                        name: Some(self.name.clone()),
                        ..ObjectMeta::default()
                    },
                    spec: Some(spec),
                };
                let params = PostParams::default();
                let call = self.api.create(&params, &lease);
                (record, tokio::time::timeout(timeout, call).await)
            }
            Step::Update(record) => {
                let mut lease = current.unwrap_or_default();
                record.write_to(lease.spec.get_or_insert_default());
                let params = PostParams::default();
                let call = self.api.replace(&self.name, &params, &lease);
                (record, tokio::time::timeout(timeout, call).await)
            }
        };
        match result {
            Ok(Ok(lease)) => {
                self.observer.succeeded(record, Instant::now());
                self.live = Some(lease);
                Attempt::Leading
            }
            Ok(Err(kube::Error::Api(status))) if status.code == 409 => Attempt::Conflict,
            Ok(Err(err)) => Attempt::Failed(err.to_string()),
            Err(_) => Attempt::Failed("writing the Lease timed out".to_owned()),
        }
    }

    async fn release(&mut self) {
        let Some(record) = self.observer.release(&self.identity, now_micros()) else {
            return;
        };
        let Some(mut lease) = self.live.clone() else {
            return;
        };
        record.write_to(lease.spec.get_or_insert_default());
        let params = PostParams::default();
        let call = self.api.replace(&self.name, &params, &lease);
        match tokio::time::timeout(self.call_timeout(), call).await {
            Ok(Ok(_)) => tracing::info!(provider = crate::PROVIDER, lease = %self.name,
                "released the leader Lease"),
            Ok(Err(err)) => tracing::warn!(provider = crate::PROVIDER, lease = %self.name,
                error = %err, "cannot release the leader Lease; it expires on its own"),
            Err(_) => tracing::warn!(provider = crate::PROVIDER, lease = %self.name,
                "releasing the leader Lease timed out; it expires on its own"),
        }
    }

    async fn run(mut self, tx: watch::Sender<bool>, mut shutdown: watch::Receiver<bool>) {
        let mut last_failure: Option<String> = None;
        'candidate: loop {
            // Candidate: try every retry period, with client-go's jitter (factor 1.2).
            loop {
                let stop = *shutdown.borrow();
                if stop {
                    return;
                }
                match self.attempt().await {
                    Attempt::Leading => break,
                    Attempt::Following(holder) => {
                        last_failure = None;
                        tracing::debug!(provider = crate::PROVIDER, %holder, "another replica leads");
                    }
                    Attempt::Conflict => {}
                    Attempt::Failed(err) => {
                        if last_failure.as_deref() != Some(&err) {
                            tracing::warn!(provider = crate::PROVIDER, lease = %self.name,
                                error = %err, "cannot take part in leader election; retrying");
                            last_failure = Some(err);
                        }
                    }
                }
                let jitter = self.timings.retry_period.mul_f64(1.2 * fastrand::f64());
                tokio::select! {
                    () = tokio::time::sleep(self.timings.retry_period + jitter) => {}
                    () = super::store::stopped(&mut shutdown) => return,
                }
            }
            tracing::info!(provider = crate::PROVIDER, lease = %self.name, identity = %self.identity,
                "became the leader: this replica writes status and the per-Gateway Services");
            tx.send_replace(true);
            let mut renewed = Instant::now();
            loop {
                tokio::select! {
                    () = tokio::time::sleep(self.timings.retry_period) => {}
                    () = super::store::stopped(&mut shutdown) => {
                        tx.send_replace(false);
                        self.release().await;
                        return;
                    }
                }
                // client-go bounds the whole renewal by the renew deadline: the attempt (a
                // read and a replace) is cut off when the deadline since the last successful
                // renewal passes, and leadership ends right then, before any follower can
                // take the Lease over (it waits a full lease duration).
                let deadline = renew_deadline(renewed, &self.timings);
                let outcome = tokio::select! {
                    outcome = tokio::time::timeout_at(deadline.into(), self.attempt()) => {
                        outcome.unwrap_or_else(|_| Attempt::Failed("renewing the Lease timed out".to_owned()))
                    }
                    () = super::store::stopped(&mut shutdown) => {
                        tx.send_replace(false);
                        self.release().await;
                        return;
                    }
                };
                match outcome {
                    Attempt::Leading => renewed = Instant::now(),
                    Attempt::Following(holder) => {
                        tx.send_replace(false);
                        tracing::warn!(provider = crate::PROVIDER, lease = %self.name, %holder,
                            "lost the leader Lease to another replica");
                        continue 'candidate;
                    }
                    Attempt::Conflict | Attempt::Failed(_) => {}
                }
                if Instant::now() >= renew_deadline(renewed, &self.timings) {
                    tx.send_replace(false);
                    tracing::warn!(provider = crate::PROVIDER, lease = %self.name,
                        deadline = ?self.timings.renew_deadline,
                        "could not renew the leader Lease in time; stopped leading");
                    continue 'candidate;
                }
            }
        }
    }
}

/// The instant by which a leader that last renewed at `renewed` must renew again or stop
/// leading.
fn renew_deadline(renewed: Instant, timings: &LeaseTimings) -> Instant {
    renewed + timings.renew_deadline
}

/// Now, to the microsecond (a Lease's `MicroTime`).
fn now_micros() -> Timestamp {
    let now = Timestamp::now();
    Timestamp::from_microsecond(now.as_microsecond()).unwrap_or(now)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: &str = "rdock-0_aaaa";
    const OTHER: &str = "rdock-1_bbbb";

    fn timings() -> LeaseTimings {
        LeaseTimings::default()
    }

    fn wall(s: i64) -> Timestamp {
        Timestamp::from_second(1_800_000_000 + s).unwrap()
    }

    fn held_by(holder: &str, renewed: i64, transitions: i32) -> LeaseRecord {
        LeaseRecord {
            holder: holder.to_owned(),
            lease_duration_seconds: 15,
            acquire_time: Some(wall(0)),
            renew_time: Some(wall(renewed)),
            transitions,
        }
    }

    #[test]
    fn an_absent_lease_is_created() {
        let mut o = Observer::default();
        let step = o.step(None, Instant::now(), wall(5), ME, &timings());
        assert_eq!(
            step,
            Step::Create(LeaseRecord {
                holder: ME.to_owned(),
                lease_duration_seconds: 15,
                acquire_time: Some(wall(5)),
                renew_time: Some(wall(5)),
                transitions: 0,
            })
        );
    }

    #[test]
    fn the_holder_renews_keeping_acquire_time_and_transitions() {
        let mut o = Observer::default();
        let t0 = Instant::now();
        let current = held_by(ME, 0, 3);
        let Step::Update(next) = o.step(Some(&current), t0, wall(2), ME, &timings()) else {
            panic!("expected an update");
        };
        assert_eq!(next.holder, ME);
        assert_eq!(next.acquire_time, Some(wall(0)));
        assert_eq!(next.renew_time, Some(wall(2)));
        assert_eq!(next.transitions, 3);
    }

    #[test]
    fn no_takeover_before_expiry_and_takeover_after() {
        let mut o = Observer::default();
        let t0 = Instant::now();
        let current = held_by(OTHER, 0, 1);
        assert_eq!(
            o.step(Some(&current), t0, wall(0), ME, &timings()),
            Step::Follow {
                holder: OTHER.to_owned()
            }
        );
        // The same record 14.9 s later (by our clock): still valid.
        assert!(matches!(
            o.step(
                Some(&current),
                t0 + Duration::from_millis(14_900),
                wall(15),
                ME,
                &timings()
            ),
            Step::Follow { .. }
        ));
        // 15 s without a change: expired, taken over, transitions counted.
        let Step::Update(next) = o.step(
            Some(&current),
            t0 + Duration::from_secs(15),
            wall(15),
            ME,
            &timings(),
        ) else {
            panic!("expected a takeover");
        };
        assert_eq!(next.holder, ME);
        assert_eq!(next.transitions, 2);
        assert_eq!(next.acquire_time, Some(wall(15)));
    }

    #[test]
    fn a_renewal_by_the_holder_restarts_the_wait() {
        let mut o = Observer::default();
        let t0 = Instant::now();
        assert!(matches!(
            o.step(Some(&held_by(OTHER, 0, 1)), t0, wall(0), ME, &timings()),
            Step::Follow { .. }
        ));
        // The holder renewed at 10 s (we see a changed record at 10 s).
        let renewed = held_by(OTHER, 10, 1);
        assert!(matches!(
            o.step(
                Some(&renewed),
                t0 + Duration::from_secs(10),
                wall(10),
                ME,
                &timings()
            ),
            Step::Follow { .. }
        ));
        // 20 s after the start, but only 10 s after the change: still valid.
        assert!(matches!(
            o.step(
                Some(&renewed),
                t0 + Duration::from_secs(20),
                wall(20),
                ME,
                &timings()
            ),
            Step::Follow { .. }
        ));
        assert!(matches!(
            o.step(
                Some(&renewed),
                t0 + Duration::from_secs(25),
                wall(25),
                ME,
                &timings()
            ),
            Step::Update(_)
        ));
    }

    #[test]
    fn an_empty_holder_is_taken_at_once() {
        let mut o = Observer::default();
        let released = LeaseRecord {
            holder: String::new(),
            lease_duration_seconds: 1,
            transitions: 4,
            ..LeaseRecord::default()
        };
        let Step::Update(next) = o.step(Some(&released), Instant::now(), wall(0), ME, &timings())
        else {
            panic!("expected a takeover");
        };
        assert_eq!(next.transitions, 5);
    }

    #[test]
    fn clock_skew_does_not_matter() {
        // The holder's clock is an hour ahead or behind ours: only our observation counts.
        for skew in [-3600, 3600] {
            let mut o = Observer::default();
            let t0 = Instant::now();
            let current = held_by(OTHER, skew, 1);
            assert!(matches!(
                o.step(Some(&current), t0, wall(0), ME, &timings()),
                Step::Follow { .. }
            ));
            assert!(matches!(
                o.step(
                    Some(&current),
                    t0 + Duration::from_secs(14),
                    wall(14),
                    ME,
                    &timings()
                ),
                Step::Follow { .. }
            ));
            assert!(matches!(
                o.step(
                    Some(&current),
                    t0 + Duration::from_secs(15),
                    wall(15),
                    ME,
                    &timings()
                ),
                Step::Update(_)
            ));
        }
    }

    #[test]
    fn a_lost_race_leaves_us_following_the_winner() {
        // Both candidates saw an expired Lease and tried to replace it; the other one's
        // replace landed first, so ours got a 409. Reading again shows the winner's fresh
        // record, which is a change: we follow for a full lease duration.
        let mut o = Observer::default();
        let t0 = Instant::now();
        let stale = held_by("gone", 0, 1);
        o.step(Some(&stale), t0, wall(0), ME, &timings());
        assert!(matches!(
            o.step(
                Some(&stale),
                t0 + Duration::from_secs(16),
                wall(16),
                ME,
                &timings()
            ),
            Step::Update(_)
        ));
        // (409 here: `succeeded` is not called.)
        let winner = held_by(OTHER, 16, 2);
        let t1 = t0 + Duration::from_secs(16) + Duration::from_millis(100);
        assert_eq!(
            o.step(Some(&winner), t1, wall(16), ME, &timings()),
            Step::Follow {
                holder: OTHER.to_owned()
            }
        );
        assert!(o.release(ME, wall(17)).is_none(), "we never held it");
    }

    #[test]
    fn release_empties_the_holder_and_keeps_transitions() {
        let mut o = Observer::default();
        let t0 = Instant::now();
        let mine = held_by(ME, 0, 7);
        o.succeeded(mine, t0);
        let released = o.release(ME, wall(30)).unwrap();
        assert_eq!(released.holder, "");
        assert_eq!(released.lease_duration_seconds, 1);
        assert_eq!(released.transitions, 7);
        assert_eq!(released.renew_time, Some(wall(30)));
        assert!(o.release(OTHER, wall(30)).is_none());
    }

    /// A fake API server for one Lease: the first read answers 404, the create succeeds, and
    /// after that every read takes `slow_read` and every replace hangs (a slow API server).
    async fn slow_lease_server(slow_read: Duration) -> std::net::SocketAddr {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let lease = std::sync::Arc::new(std::sync::Mutex::new(None::<serde_json::Value>));
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                let lease = lease.clone();
                tokio::spawn(async move {
                    loop {
                        let mut buf = Vec::new();
                        let mut chunk = [0_u8; 4096];
                        let head_end = loop {
                            let Ok(n) = socket.read(&mut chunk).await else {
                                return;
                            };
                            if n == 0 {
                                return;
                            }
                            buf.extend_from_slice(&chunk[..n]);
                            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                                break i + 4;
                            }
                        };
                        let head = String::from_utf8_lossy(&buf[..head_end]).to_lowercase();
                        let length: usize = head
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length:"))
                            .and_then(|v| v.trim().parse().ok())
                            .unwrap_or(0);
                        while buf.len() < head_end + length {
                            let Ok(n) = socket.read(&mut chunk).await else {
                                return;
                            };
                            if n == 0 {
                                return;
                            }
                            buf.extend_from_slice(&chunk[..n]);
                        }
                        let body = buf[head_end..head_end + length].to_vec();
                        let (status, reply) = if head.starts_with("get ") {
                            let current = lease.lock().unwrap().clone();
                            if let Some(current) = current {
                                tokio::time::sleep(slow_read).await;
                                ("200 OK", current)
                            } else {
                                (
                                    "404 Not Found",
                                    serde_json::json!({
                                        "kind": "Status", "apiVersion": "v1", "status": "Failure",
                                        "reason": "NotFound", "code": 404, "message": "not found"
                                    }),
                                )
                            }
                        } else if head.starts_with("post ") {
                            let mut created: serde_json::Value =
                                serde_json::from_slice(&body).unwrap();
                            created["metadata"]["resourceVersion"] = "1".into();
                            created["metadata"]["namespace"] = "ns".into();
                            *lease.lock().unwrap() = Some(created.clone());
                            ("201 Created", created)
                        } else {
                            // A replace that never answers.
                            std::future::pending::<()>().await;
                            return;
                        };
                        let text = reply.to_string();
                        let response = format!(
                            "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{text}",
                            text.len()
                        );
                        if socket.write_all(response.as_bytes()).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn a_slow_api_server_ends_leadership_at_the_renew_deadline() {
        let addr = slow_lease_server(Duration::from_millis(900)).await;
        let url: http::Uri = format!("http://{addr}").parse().unwrap();
        let config = kube::Config::new(url);
        let client = kube::Client::try_from(config).unwrap();
        let timings = LeaseTimings {
            lease_duration: Duration::from_secs(3),
            renew_deadline: Duration::from_secs(1),
            retry_period: Duration::from_millis(200),
        };
        let elector = Elector::new(Api::namespaced(client, "ns"), "lease", ME, timings);
        let (_stop, shutdown) = watch::channel(false);
        let (mut leading, _task) = elector.spawn(shutdown);
        tokio::time::timeout(Duration::from_secs(5), leading.wait_for(|l| *l))
            .await
            .expect("becomes the leader")
            .unwrap();
        let since = Instant::now();
        tokio::time::timeout(Duration::from_secs(10), leading.wait_for(|l| !*l))
            .await
            .expect("stops leading")
            .unwrap();
        // The last successful renewal was the create, just before `since`. A read (0.9 s)
        // plus a replace bounded only by its own timeout (1 s) and the retry period would
        // keep leading for 2.1 s; the renew deadline is 1 s.
        let led = since.elapsed();
        assert!(
            led <= timings.renew_deadline + Duration::from_millis(250),
            "kept leading for {led:?} after the last renewal"
        );
    }
}
