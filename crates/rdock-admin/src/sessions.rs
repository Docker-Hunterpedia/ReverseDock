//! Server-side dashboard sessions (ADR-0024). The browser holds a 256-bit random ID in the
//! `__Host-rdock_session` cookie; only its SHA-256 is kept, in memory, so a restart logs
//! everyone out. A new ID is issued at login and at every privilege change.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::digest::{SHA256, digest};
use ring::rand::{SecureRandom, SystemRandom};
use serde::Serialize;

use crate::users::Role;

/// The cookie's name. The `__Host-` prefix makes browsers require `Secure`, `Path=/` and no
/// `Domain`, so no other host or path can set or overwrite it.
pub const COOKIE: &str = "__Host-rdock_session";

/// Sessions per user; the oldest ends when a new one would exceed it.
const PER_USER: usize = 32;
/// Sessions in all; past it, logins are refused until some end.
const TOTAL: usize = 10_000;
/// How long a login may wait for its second factor or enrolment.
const PENDING: Duration = Duration::from_secs(10 * 60);
/// How recent a password check must be for sensitive changes (ASVS 7.5.1).
pub const REAUTH: Duration = Duration::from_secs(5 * 60);

/// How far a session has come.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    /// Password checked; the TOTP or a recovery code is next.
    Mfa,
    /// Password checked; the user must enrol TOTP before anything else.
    Enrol,
    /// Fully logged in.
    Full,
}

/// One session.
#[derive(Debug, Clone)]
pub struct Session {
    /// A public ID for listing and ending sessions; not a credential.
    pub id: String,
    /// The user's name.
    pub user: String,
    /// The user's role at login.
    pub role: Role,
    /// How far the login has come.
    pub stage: Stage,
    /// The synchronizer token unsafe requests must send in `X-CSRF-Token`.
    pub csrf: String,
    /// A TOTP secret shown for enrolment and not confirmed yet.
    pub pending_totp: Option<String>,
    /// When the password was last checked.
    pub authenticated: Instant,
    /// The client address at login.
    pub client: Option<IpAddr>,
    created: Instant,
    created_unix: u64,
    seen: Instant,
}

/// What `GET /api/v1/auth/sessions` shows of a session.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct Listed {
    id: String,
    user: String,
    created_at: u64,
    idle_seconds: u64,
    #[schema(value_type = Option<String>)]
    client: Option<IpAddr>,
    current: bool,
}

fn random_token() -> Option<String> {
    let mut bytes = [0u8; 32];
    SystemRandom::new().fill(&mut bytes).ok()?;
    Some(URL_SAFE_NO_PAD.encode(bytes))
}

fn key(cookie: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(digest(&SHA256, cookie.as_bytes()).as_ref());
    out
}

/// All sessions.
pub struct Sessions {
    idle: Duration,
    absolute: Duration,
    map: Mutex<HashMap<[u8; 32], Session>>,
}

impl Sessions {
    /// Sessions that end after `idle` without requests or `absolute` after login.
    #[must_use]
    pub fn new(idle: Duration, absolute: Duration) -> Self {
        Self {
            idle,
            absolute,
            map: Mutex::new(HashMap::new()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<[u8; 32], Session>> {
        self.map.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn alive(&self, session: &Session, now: Instant) -> bool {
        let absolute = if session.stage == Stage::Full {
            self.absolute
        } else {
            PENDING.min(self.absolute)
        };
        now.duration_since(session.seen) < self.idle
            && now.duration_since(session.created) < absolute
    }

    /// Starts a session and returns the cookie value with it; `None` when the random
    /// generator fails or the session table is full.
    pub fn create(
        &self,
        user: &str,
        role: Role,
        stage: Stage,
        client: Option<IpAddr>,
    ) -> Option<(String, Session)> {
        let now = Instant::now();
        let session = Session {
            id: random_token()?.chars().take(16).collect(),
            user: user.to_owned(),
            role,
            stage,
            csrf: random_token()?,
            pending_totp: None,
            authenticated: now,
            client,
            created: now,
            created_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
            seen: now,
        };
        let cookie = random_token()?;
        let mut map = self.lock();
        map.retain(|_, s| self.alive(s, now));
        let mut own: Vec<([u8; 32], Instant)> = map
            .iter()
            .filter(|(_, s)| s.user == user)
            .map(|(k, s)| (*k, s.created))
            .collect();
        if own.len() >= PER_USER {
            own.sort_by_key(|(_, created)| *created);
            for (k, _) in own.iter().take(own.len() + 1 - PER_USER) {
                map.remove(k);
            }
        }
        if map.len() >= TOTAL {
            return None;
        }
        map.insert(key(&cookie), session.clone());
        Some((cookie, session))
    }

    /// The live session for `cookie`, marking it as just used.
    pub fn get(&self, cookie: &str) -> Option<Session> {
        let now = Instant::now();
        let mut map = self.lock();
        let k = key(cookie);
        let session = map.get_mut(&k)?;
        if !self.alive(session, now) {
            map.remove(&k);
            return None;
        }
        session.seen = now;
        Some(session.clone())
    }

    /// Changes the session for `cookie` in place.
    pub fn modify(&self, cookie: &str, change: impl FnOnce(&mut Session)) -> Option<Session> {
        let mut map = self.lock();
        let session = map.get_mut(&key(cookie))?;
        change(session);
        Some(session.clone())
    }

    /// Moves the session for `cookie` to a new ID and CSRF token after `change` (a privilege
    /// change), keeping its login time, and returns the new cookie value.
    pub fn rotate(
        &self,
        cookie: &str,
        change: impl FnOnce(&mut Session),
    ) -> Option<(String, Session)> {
        let new_cookie = random_token()?;
        let csrf = random_token()?;
        let mut map = self.lock();
        let mut session = map.remove(&key(cookie))?;
        change(&mut session);
        session.csrf = csrf;
        session.seen = Instant::now();
        map.insert(key(&new_cookie), session.clone());
        Some((new_cookie, session))
    }

    /// Ends the session for `cookie`.
    pub fn remove(&self, cookie: &str) {
        self.lock().remove(&key(cookie));
    }

    /// Ends every session of `user` except the one for `keep`.
    pub fn end_user(&self, user: &str, keep: Option<&str>) {
        let keep = keep.map(key);
        self.lock()
            .retain(|k, s| s.user != user || Some(*k) == keep);
    }

    /// Ends the session with public ID `id` if `allowed` says the caller may.
    pub fn end_by_id(&self, id: &str, allowed: impl Fn(&Session) -> bool) -> bool {
        let mut map = self.lock();
        let found = map
            .iter()
            .find(|(_, s)| s.id == id && allowed(s))
            .map(|(k, _)| *k);
        found.is_some_and(|k| map.remove(&k).is_some())
    }

    /// Live sessions, of one user or of all, newest first; `current` marks the caller's.
    pub fn list(&self, user: Option<&str>, current: &str) -> Vec<Listed> {
        let now = Instant::now();
        let current = key(current);
        let map = self.lock();
        let mut listed: Vec<(Instant, Listed)> = map
            .iter()
            .filter(|(_, s)| self.alive(s, now) && user.is_none_or(|u| s.user == u))
            .map(|(k, s)| {
                (
                    s.created,
                    Listed {
                        id: s.id.clone(),
                        user: s.user.clone(),
                        created_at: s.created_unix,
                        idle_seconds: now.duration_since(s.seen).as_secs(),
                        client: s.client,
                        current: *k == current,
                    },
                )
            })
            .collect();
        listed.sort_by_key(|(created, _)| std::cmp::Reverse(*created));
        listed.into_iter().map(|(_, l)| l).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sessions() -> Sessions {
        Sessions::new(Duration::from_secs(60), Duration::from_secs(3600))
    }

    #[test]
    fn only_the_hash_of_the_cookie_is_kept() {
        let sessions = sessions();
        let (cookie, session) = sessions
            .create("root", Role::Admin, Stage::Full, None)
            .unwrap();
        assert_eq!(cookie.len(), 43, "256 bits in base64url");
        assert!(!sessions.lock().contains_key(cookie.as_bytes()));
        assert_eq!(sessions.get(&cookie).unwrap().id, session.id);
        assert!(sessions.get("forged").is_none());
    }

    #[test]
    fn rotation_issues_a_new_id_and_csrf_token() {
        let sessions = sessions();
        let (cookie, before) = sessions
            .create("root", Role::Admin, Stage::Mfa, None)
            .unwrap();
        let (rotated, after) = sessions.rotate(&cookie, |s| s.stage = Stage::Full).unwrap();
        assert!(
            sessions.get(&cookie).is_none(),
            "the old ID no longer works"
        );
        assert_eq!(sessions.get(&rotated).unwrap().stage, Stage::Full);
        assert_ne!(before.csrf, after.csrf);
        assert_eq!(before.id, after.id);
    }

    #[test]
    fn idle_and_absolute_timeouts_end_sessions() {
        let short = Sessions::new(Duration::from_millis(30), Duration::from_secs(3600));
        let (cookie, _) = short
            .create("root", Role::Admin, Stage::Full, None)
            .unwrap();
        std::thread::sleep(Duration::from_millis(60));
        assert!(short.get(&cookie).is_none());

        // Generous margins: the test must hold on a loaded CI machine.
        let absolute = Sessions::new(Duration::from_secs(60), Duration::from_millis(400));
        let (cookie, _) = absolute
            .create("root", Role::Admin, Stage::Full, None)
            .unwrap();
        assert!(
            absolute.get(&cookie).is_some(),
            "activity keeps the idle timer fresh"
        );
        std::thread::sleep(Duration::from_millis(500));
        assert!(absolute.get(&cookie).is_none(), "but not the absolute one");
    }

    #[test]
    fn users_keep_at_most_32_sessions_and_can_be_logged_out_everywhere() {
        let sessions = sessions();
        let (first, _) = sessions
            .create("root", Role::Admin, Stage::Full, None)
            .unwrap();
        let mut last = String::new();
        for _ in 0..PER_USER {
            last = sessions
                .create("root", Role::Admin, Stage::Full, None)
                .unwrap()
                .0;
        }
        assert!(sessions.get(&first).is_none(), "the oldest made room");
        assert_eq!(sessions.list(Some("root"), &last).len(), PER_USER);
        let (other, _) = sessions
            .create("ops", Role::Viewer, Stage::Full, None)
            .unwrap();
        sessions.end_user("root", Some(&last));
        assert_eq!(sessions.list(Some("root"), &last).len(), 1);
        assert!(sessions.get(&other).is_some());
    }
}
