//! `basic_auth`: HTTP Basic authentication against hashed passwords.
//!
//! bcrypt and argon2id are slow on purpose, and browsers send the credentials with every
//! request, so successful checks are remembered for a few minutes under a keyed hash of the
//! user name and password. Verification runs on the blocking thread pool so it never stalls the
//! proxy's workers, at most [`MAX_VERIFYING`] at a time across every `basic_auth` middleware
//! and [`PER_CLIENT`] at a time per client (an IPv4 address or an IPv6 /64), whose requests
//! wait for a turn up to [`VERIFY_WAIT`] and then get `429` (not counted as a failed login): a request that finds every slot busy
//! waits up to [`VERIFY_WAIT`], then gets `503` with `Retry-After`. A user name that does not exist is verified against a configured
//! hash and refused, so the answer takes as long as for a real user's wrong password. A hash whose cost is above the ceilings of [`rdock_model::password`] is
//! refused when the middleware is built, from `users` and from `users_file` alike.

use std::collections::{HashMap, VecDeque};
use std::hash::{BuildHasher, RandomState};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use http::HeaderValue;
use pingora::http::RequestHeader;
use rdock_model::middleware::BasicAuthConfig;

use crate::{BuildError, Context, Flow, Middleware, Reply, hashes, read_file};

const CACHE_TTL: Duration = Duration::from_secs(300);
const CACHE_ENTRIES: usize = 1024;

/// Most password verifications running at once, process-wide: the CPU count, at most four.
/// With argon2id at its ceiling (256 MiB) that bounds the memory they use to 1 GiB.
pub const MAX_VERIFYING: usize = 4;
/// How long a request waits for a verification slot before it gets `503`.
pub const VERIFY_WAIT: Duration = Duration::from_secs(1);

/// The verification slots shared by every `basic_auth` middleware.
fn slots() -> &'static Arc<tokio::sync::Semaphore> {
    static SLOTS: std::sync::OnceLock<Arc<tokio::sync::Semaphore>> = std::sync::OnceLock::new();
    SLOTS.get_or_init(|| {
        let cpus = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
        Arc::new(tokio::sync::Semaphore::new(cpus.clamp(1, MAX_VERIFYING)))
    })
}

/// The `basic_auth` middleware.
#[derive(Debug)]
pub(crate) struct BasicAuth {
    users: Arc<HashMap<String, String>>,
    challenge: HeaderValue,
    remove_header: bool,
    cache: Arc<Cache>,
    /// The verification slots: the process-wide ones (a test may give its own).
    slots: Arc<tokio::sync::Semaphore>,
    /// A configured hash, verified for names that are not users so that an unknown name
    /// costs what a known one does and timing does not tell them apart.
    decoy: Arc<str>,
    /// [`PER_CLIENT`] verifications at a time per client (an IPv4 address or an IPv6 /64):
    /// the process-wide turns (a test may give its own).
    verifying: Arc<Turns>,
}

/// Verifications one client (an IPv4 address or an IPv6 /64) may run at once. Two, not one:
/// several people behind one NAT logging in at the same moment are verified side by side
/// instead of queueing past [`VERIFY_WAIT`]. Not per (client, user): user names are the
/// caller's choice (unknown ones are verified against a decoy), so that would let one client
/// take every slot again. The bound: one client runs at most `PER_CLIENT` of the
/// `MAX_VERIFYING` slots, so it guesses at most two passwords per verification time (around
/// 0.3 s for the usual argon2id and bcrypt costs) and others keep the remaining slots.
pub const PER_CLIENT: usize = 2;

/// Per-client turns for verification, shared by every `basic_auth` middleware: a client runs
/// at most [`PER_CLIENT`] verifications at once, so one client cannot hold every slot.
#[derive(Debug, Default)]
struct Turns(Mutex<HashMap<String, TurnEntry>>);

/// A client's turns and how many requests have or wait for one; the entry goes when that
/// count does, whichever way a request ends (verified, timed out or cancelled).
#[derive(Debug)]
struct TurnEntry {
    semaphore: Arc<tokio::sync::Semaphore>,
    users: usize,
}

fn verifying() -> &'static Arc<Turns> {
    static VERIFYING: std::sync::OnceLock<Arc<Turns>> = std::sync::OnceLock::new();
    VERIFYING.get_or_init(Arc::default)
}

/// A request's registration with a client's turns, and its turn once it has one. Dropping it
/// gives the turn back and removes the entry when no other request has or waits for one.
struct Turn {
    turns: Arc<Turns>,
    key: String,
    permit: Option<tokio::sync::OwnedSemaphorePermit>,
}

impl Turn {
    /// Waits up to `wait` for one of `key`'s turns.
    async fn take(turns: &Arc<Turns>, key: String, wait: Duration) -> Option<Self> {
        let semaphore = {
            let mut map = turns.0.lock().unwrap_or_else(PoisonError::into_inner);
            let entry = map.entry(key.clone()).or_insert_with(|| TurnEntry {
                semaphore: Arc::new(tokio::sync::Semaphore::new(PER_CLIENT)),
                users: 0,
            });
            entry.users += 1;
            entry.semaphore.clone()
        };
        // Registered before waiting, so a timeout or a cancelled request unregisters too.
        let mut turn = Self {
            turns: turns.clone(),
            key,
            permit: None,
        };
        turn.permit = tokio::time::timeout(wait, semaphore.acquire_owned())
            .await
            .ok()?
            .ok();
        turn.permit.is_some().then_some(turn)
    }
}

impl Drop for Turn {
    fn drop(&mut self) {
        drop(self.permit.take());
        let mut map = self.turns.0.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(entry) = map.get_mut(&self.key) {
            entry.users = entry.users.saturating_sub(1);
            if entry.users == 0 {
                map.remove(&self.key);
            }
        }
    }
}

impl BasicAuth {
    pub(crate) fn new(config: &BasicAuthConfig) -> Result<Self, BuildError> {
        let mut users = HashMap::new();
        if let Some(path) = &config.users_file {
            let text = String::from_utf8_lossy(&read_file(path)?).into_owned();
            for line in text.lines().map(str::trim) {
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                if let Some((user, hash)) = line.split_once(':') {
                    users.insert(user.to_owned(), hash.to_owned());
                }
            }
        }
        // Inline users win over the file.
        for entry in &config.users {
            if let Some((user, hash)) = entry.split_once(':') {
                users.insert(user.to_owned(), hash.to_owned());
            }
        }
        if users.is_empty() {
            return Err(BuildError::Invalid("basic_auth has no users".to_owned()));
        }
        let mut names: Vec<&String> = users.keys().collect();
        names.sort();
        let decoy: Arc<str> = names
            .first()
            .and_then(|user| users.get(*user))
            .map_or_else(|| Arc::from(""), |hash| Arc::from(hash.as_str()));
        for user in names {
            if let Some(problem) = users
                .get(user)
                .and_then(|hash| rdock_model::password::cost_problem(hash))
            {
                return Err(BuildError::Invalid(format!(
                    "the password of `{user}`: {problem}"
                )));
            }
        }
        let realm = config.realm.as_deref().unwrap_or("rdock").replace('"', "'");
        let challenge = HeaderValue::from_str(&format!(
            "Basic realm=\"{realm}\", charset=\"UTF-8\""
        ))
        .map_err(|_| BuildError::Invalid("the realm is not a valid header value".to_owned()))?;
        Ok(Self {
            users: Arc::new(users),
            challenge,
            remove_header: config.remove_header,
            cache: Arc::new(Cache::default()),
            slots: slots().clone(),
            decoy,
            verifying: verifying().clone(),
        })
    }

    fn unauthorized(&self) -> Flow {
        Flow::Reply(Reply {
            status: 401,
            headers: vec![
                (http::header::WWW_AUTHENTICATE, self.challenge.clone()),
                (
                    http::header::CONTENT_TYPE,
                    HeaderValue::from_static("text/plain; charset=utf-8"),
                ),
            ],
            body: Some(Bytes::from_static(b"401 Unauthorized\n").into()),
            // The text is the `html` format's body; other formats render the problem.
            problem: Some(crate::ProblemKind::Unauthenticated),
            extensions: None,
        })
    }
}

/// Parses `Authorization: Basic …` into user and password.
fn credentials(req: &RequestHeader) -> Option<(String, String)> {
    let value = req
        .headers
        .get(http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let (scheme, encoded) = value.trim().split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let decoded = STANDARD.decode(encoded.trim()).ok()?;
    let text = String::from_utf8(decoded).ok()?;
    let (user, password) = text.split_once(':')?;
    Some((user.to_owned(), password.to_owned()))
}

#[async_trait]
impl Middleware for BasicAuth {
    async fn request(&self, req: &mut RequestHeader, cx: &mut Context) -> Flow {
        let Some((user, password)) = credentials(req) else {
            return self.unauthorized();
        };
        // An unknown name is checked against a configured hash and refused whatever the
        // result, so it takes as long as a wrong password for a real user.
        let (hash, known) = match self.users.get(&user) {
            Some(hash) => (hash.clone(), true),
            None => (self.decoy.to_string(), false),
        };
        let key = self.cache.key(&user, &password, &hash);
        let valid = if let Some(valid) = self.cache.get(key, Instant::now()) {
            valid
        } else {
            // At most `PER_CLIENT` verifications at a time per client: a client that floods
            // wrong passwords waits behind its own requests instead of taking every slot from
            // everyone else. Waiting too long is not a failed login: nothing was checked, so
            // it does not count towards an `auth_failure` ban.
            let Some(turn) = Turn::take(
                &self.verifying,
                crate::limits::client_ip_key(cx.client_ip),
                VERIFY_WAIT,
            )
            .await
            else {
                return Flow::Reply(
                    Reply::problem(crate::ProblemKind::RateLimited)
                        .header(http::header::RETRY_AFTER, HeaderValue::from_static("1")),
                );
            };
            // The request before it in the turn may have verified the same credentials.
            if let Some(valid) = self.cache.get(key, Instant::now()) {
                drop(turn);
                return self.finish(req, cx, user, valid);
            }
            let Ok(Ok(slot)) =
                tokio::time::timeout(VERIFY_WAIT, self.slots.clone().acquire_owned()).await
            else {
                tracing::warn!("every password verification slot is busy; answering 503");
                return Flow::Reply(
                    Reply::problem(crate::ProblemKind::Overloaded)
                        .header(http::header::RETRY_AFTER, HeaderValue::from_static("1")),
                );
            };
            let checked = tokio::task::spawn_blocking(move || {
                let _slot = slot;
                let _turn = turn;
                hashes::verify(&password, &hash)
            })
            .await
            .unwrap_or(false)
                && known;
            // Only successes are remembered: failures from a flood would push them out.
            if checked {
                self.cache.insert(key, Instant::now());
            }
            checked
        };
        self.finish(req, cx, user, valid)
    }
}

impl BasicAuth {
    fn finish(&self, req: &mut RequestHeader, cx: &mut Context, user: String, valid: bool) -> Flow {
        if !valid {
            cx.auth_failed = true;
            return self.unauthorized();
        }
        if self.remove_header {
            req.remove_header(&http::header::AUTHORIZATION);
        }
        cx.user = Some(user);
        Flow::Next
    }
}

/// Recently verified credentials: 128-bit keyed hashes with an expiry, bounded in size.
#[derive(Debug)]
struct Cache {
    hashers: (RandomState, RandomState),
    entries: Mutex<(HashMap<u128, Instant>, VecDeque<u128>)>,
}

impl Default for Cache {
    fn default() -> Self {
        Self {
            hashers: (RandomState::new(), RandomState::new()),
            entries: Mutex::new((HashMap::new(), VecDeque::new())),
        }
    }
}

impl Cache {
    fn key(&self, user: &str, password: &str, hash: &str) -> u128 {
        let input = (user, password, hash);
        (u128::from(self.hashers.0.hash_one(input)) << 64)
            | u128::from(self.hashers.1.hash_one(input))
    }

    /// `Some(true)` for credentials verified recently (only successes are remembered).
    fn get(&self, key: u128, now: Instant) -> Option<bool> {
        let guard = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        guard
            .0
            .get(&key)
            .is_some_and(|added| now.duration_since(*added) < CACHE_TTL)
            .then_some(true)
    }

    #[cfg(test)]
    fn contains(&self, key: u128, now: Instant) -> bool {
        self.get(key, now) == Some(true)
    }

    fn insert(&self, key: u128, now: Instant) {
        let mut guard = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let (map, order) = &mut *guard;
        if map.insert(key, now).is_none() {
            order.push_back(key);
        }
        while order.len() > CACHE_ENTRIES {
            if let Some(old) = order.pop_front() {
                map.remove(&old);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{block_on, cx, header, reply_header, request};

    fn basic(user: &str, password: &str) -> String {
        format!("Basic {}", STANDARD.encode(format!("{user}:{password}")))
    }

    fn auth(users: &[&str], remove: bool) -> BasicAuth {
        BasicAuth::new(&BasicAuthConfig {
            users: users.iter().map(|s| (*s).to_owned()).collect(),
            users_file: None,
            realm: Some("Office".into()),
            remove_header: remove,
        })
        .unwrap()
    }

    #[test]
    fn accepts_valid_credentials_and_remembers_them() {
        let hash = bcrypt::hash("s3cret", 4).unwrap();
        let mw = auth(&[&format!("alice:{hash}")], true);
        let header_value = basic("alice", "s3cret");
        let mut req = request("GET", "/", &[("authorization", &header_value)]);
        let mut c = cx();
        assert_eq!(block_on(mw.request(&mut req, &mut c)), Flow::Next);
        assert_eq!(c.user.as_deref(), Some("alice"));
        assert_eq!(header(&req.headers, "authorization"), None, "removed");
        assert!(
            mw.cache
                .contains(mw.cache.key("alice", "s3cret", &hash), Instant::now())
        );
    }

    #[test]
    fn rejects_missing_or_wrong_credentials_with_a_challenge() {
        let mw = auth(&["bob:$apr1$saltsalt$yAAkm4libquA.ZWLHbSBq/"], false);
        for value in [
            None,
            Some(basic("bob", "wrong")),
            Some(basic("eve", "password")),
            Some("Bearer x".into()),
        ] {
            let headers: Vec<(&'static str, &str)> = value
                .as_deref()
                .map(|v| vec![("authorization", v)])
                .unwrap_or_default();
            let mut req = request("GET", "/", &headers);
            let Flow::Reply(reply) = block_on(mw.request(&mut req, &mut cx())) else {
                panic!("expected 401 for {value:?}")
            };
            assert_eq!(reply.status, 401);
            assert_eq!(
                reply_header(&reply, "www-authenticate"),
                Some("Basic realm=\"Office\", charset=\"UTF-8\"")
            );
        }
        let ok = basic("bob", "password");
        let mut req = request("GET", "/", &[("authorization", &ok)]);
        assert_eq!(block_on(mw.request(&mut req, &mut cx())), Flow::Next);
        assert!(header(&req.headers, "authorization").is_some(), "kept");
    }

    #[test]
    fn hashes_above_the_cost_ceilings_are_refused_from_files_too() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("users");
        std::fs::write(
            &file,
            "ok:{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=\nslow:$2b$20$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234\n",
        )
        .unwrap();
        let Err(BuildError::Invalid(message)) = BasicAuth::new(&BasicAuthConfig {
            users_file: Some(file),
            ..BasicAuthConfig::default()
        }) else {
            panic!("a cost of 20 is refused")
        };
        assert!(
            message.contains("`slow`") && message.contains("limit is 14"),
            "{message}"
        );
        let Err(BuildError::Invalid(message)) = BasicAuth::new(&BasicAuthConfig {
            users: vec![
                "mem:$argon2id$v=19$m=4194304,t=1,p=1$c29tZXNhbHQxMjM0NTY3OA$AAAA".to_owned(),
            ],
            ..BasicAuthConfig::default()
        }) else {
            panic!("4 GiB is refused")
        };
        assert!(message.contains("262144"), "{message}");
    }

    #[test]
    fn verifications_are_capped_and_the_excess_gets_503() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            assert!((1..=MAX_VERIFYING).contains(&slots().available_permits()));
            // Two slots of its own, both held, as slow verifications would.
            let total = 2;
            let hash = bcrypt::hash("s3cret", 4).unwrap();
            let mut mw = auth(&[&format!("alice:{hash}")], false);
            mw.slots = Arc::new(tokio::sync::Semaphore::new(total));
            let held = mw.slots.clone().acquire_many_owned(2).await.unwrap();
            let value = basic("alice", "wrong");
            let mut req = request("GET", "/", &[("authorization", &value)]);
            let started = Instant::now();
            let Flow::Reply(reply) = mw.request(&mut req, &mut cx()).await else {
                panic!("no slot: 503")
            };
            assert_eq!(reply.status, 503);
            assert_eq!(reply_header(&reply, "retry-after"), Some("1"));
            assert!(started.elapsed() >= VERIFY_WAIT, "it waited briefly first");
            drop(held);
            // With a slot free, the same request is checked (and refused: wrong password).
            let Flow::Reply(reply) = mw.request(&mut req, &mut cx()).await else {
                panic!("401")
            };
            assert_eq!(reply.status, 401);
            assert_eq!(mw.slots.available_permits(), total, "slots come back");
        });
    }

    #[test]
    fn unknown_users_cost_a_verification_and_are_refused() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let hash = bcrypt::hash("s3cret", 4).unwrap();
            let mut mw = auth(&[&format!("alice:{hash}")], false);
            mw.slots = Arc::new(tokio::sync::Semaphore::new(1));
            mw.verifying = Arc::default();
            // With the only slot held, an unknown name waits for it like a known one: it is
            // verified, not answered at once.
            let held = mw.slots.clone().acquire_owned().await.unwrap();
            let value = basic("mallory", "s3cret");
            let mut req = request("GET", "/", &[("authorization", &value)]);
            let Flow::Reply(reply) = mw.request(&mut req, &mut cx()).await else {
                panic!("no slot: 503")
            };
            assert_eq!(
                reply.status, 503,
                "the unknown name took the verification path"
            );
            drop(held);
            // Alice's password under another name is still refused.
            let Flow::Reply(reply) = mw.request(&mut req, &mut cx()).await else {
                panic!("401")
            };
            assert_eq!(reply.status, 401);
        });
    }

    #[test]
    fn one_client_cannot_take_every_verification_slot() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let hash = bcrypt::hash("s3cret", 4).unwrap();
            let mut mw = auth(&[&format!("alice:{hash}")], false);
            mw.verifying = Arc::default();
            // Verifications of this client are running (any address of its /64), as many as
            // it may run at once.
            let mut flooding = cx();
            flooding.client_ip = "2001:db8:1:2::7".parse().unwrap();
            let mut busy = Vec::new();
            for _ in 0..PER_CLIENT {
                busy.push(
                    Turn::take(
                        &mw.verifying,
                        "2001:db8:1:2::/64".to_owned(),
                        Duration::ZERO,
                    )
                    .await
                    .unwrap(),
                );
            }
            let value = basic("alice", "s3cret");
            let mut req = request("GET", "/", &[("authorization", &value)]);
            let started = Instant::now();
            let Flow::Reply(reply) = mw.request(&mut req, &mut flooding).await else {
                panic!("429 while its own verifications run")
            };
            assert_eq!(reply.status, 429);
            assert!(
                !flooding.auth_failed,
                "waiting for a turn is not a failed login (no abuse-ban contribution)"
            );
            assert!(
                started.elapsed() >= VERIFY_WAIT,
                "it waited for its turn first"
            );
            // Another client is verified meanwhile.
            assert_eq!(mw.request(&mut req, &mut cx()).await, Flow::Next);
            drop(busy);
            let mut later = cx();
            later.client_ip = "2001:db8:1:2::8".parse().unwrap();
            mw.cache = Arc::new(Cache::default());
            assert_eq!(mw.request(&mut req, &mut later).await, Flow::Next);
            assert!(
                mw.verifying.0.lock().unwrap().is_empty(),
                "turns are given back"
            );
        });
    }

    #[test]
    fn turns_are_given_back_however_a_wait_ends() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let turns: Arc<Turns> = Arc::default();
            let key = || "203.0.113.7".to_owned();
            let take = |wait| Turn::take(&turns, key(), wait);
            // Two at once for one client; a third waits and times out.
            let first = take(Duration::ZERO).await.unwrap();
            let second = take(Duration::ZERO).await.unwrap();
            assert!(take(Duration::from_millis(10)).await.is_none());
            // The holders finish in either order: nothing is left.
            drop(first);
            drop(second);
            assert!(turns.0.lock().unwrap().is_empty());
            // A waiter that times out while the holder runs, then the holder finishes.
            let holder = take(Duration::ZERO).await.unwrap();
            let other = take(Duration::ZERO).await.unwrap();
            let waiter = tokio::spawn({
                let turns = turns.clone();
                async move {
                    Turn::take(&turns, key(), Duration::from_millis(20))
                        .await
                        .is_none()
                }
            });
            assert!(waiter.await.unwrap());
            drop(holder);
            drop(other);
            assert!(turns.0.lock().unwrap().is_empty());
            // A waiter whose request is cancelled.
            let a = take(Duration::ZERO).await.unwrap();
            let b = take(Duration::ZERO).await.unwrap();
            let cancelled = tokio::spawn({
                let turns = turns.clone();
                async move {
                    Turn::take(&turns, key(), Duration::from_secs(30))
                        .await
                        .is_some()
                }
            });
            // Poll until it waits (registered), up to a deadline.
            let deadline = Instant::now() + Duration::from_secs(10);
            while turns.0.lock().unwrap()[&key()].users < 3 {
                assert!(Instant::now() < deadline, "the waiter registers");
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            cancelled.abort();
            let _ = cancelled.await;
            drop(a);
            drop(b);
            assert!(turns.0.lock().unwrap().is_empty());
        });
    }

    #[test]
    fn reads_users_files() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("users");
        std::fs::write(
            &file,
            "# comment\n\n carol:{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g= \n",
        )
        .unwrap();
        let mw = BasicAuth::new(&BasicAuthConfig {
            users_file: Some(file),
            ..BasicAuthConfig::default()
        })
        .unwrap();
        let ok = basic("carol", "password");
        let mut req = request("GET", "/", &[("authorization", &ok)]);
        assert_eq!(block_on(mw.request(&mut req, &mut cx())), Flow::Next);
    }
}
