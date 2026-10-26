//! `basic_auth`: HTTP Basic authentication against hashed passwords.
//!
//! bcrypt and argon2id are slow on purpose, and browsers send the credentials with every
//! request, so successful checks are remembered for a few minutes under a keyed hash of the
//! user name and password. Verification runs on the blocking thread pool so it never stalls the
//! proxy's workers.

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

/// The `basic_auth` middleware.
#[derive(Debug)]
pub(crate) struct BasicAuth {
    users: Arc<HashMap<String, String>>,
    challenge: HeaderValue,
    remove_header: bool,
    cache: Arc<Cache>,
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
            body: Some(Bytes::from_static(b"401 Unauthorized\n")),
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
        let Some(hash) = self.users.get(&user).cloned() else {
            return self.unauthorized();
        };
        let key = self.cache.key(&user, &password, &hash);
        let valid = if self.cache.contains(key, Instant::now()) {
            true
        } else {
            let checked = tokio::task::spawn_blocking(move || hashes::verify(&password, &hash))
                .await
                .unwrap_or(false);
            if checked {
                self.cache.insert(key, Instant::now());
            }
            checked
        };
        if !valid {
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

    fn contains(&self, key: u128, now: Instant) -> bool {
        let guard = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        guard
            .0
            .get(&key)
            .is_some_and(|added| now.duration_since(*added) < CACHE_TTL)
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
