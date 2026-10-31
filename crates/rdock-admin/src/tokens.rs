//! API tokens (ADR-0024): `rdk_pat_<id>_<secret><checksum>`. The 10-character ID is public
//! (lookup, audit, revocation), the 32-character Base62 secret carries 190 bits and is kept
//! only as its SHA-256, and the 6-character Base62 CRC32 lets ReverseDock and secret scanners
//! reject mistyped or made-up tokens without a lookup. Stored in
//! `$RDOCK_DATA_DIR/admin/tokens.json` (mode 0600).

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ipnet::IpNet;
use ring::digest::{SHA256, digest};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::caller::Access;

const PREFIX: &str = "rdk_pat_";
const BASE62: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const ID_LEN: usize = 10;
const SECRET_LEN: usize = 32;
const CHECK_LEN: usize = 6;
/// How often a token's last use is written to disk at most.
const PERSIST_USE_EVERY: Duration = Duration::from_secs(60);

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Uniform Base62 characters by rejection sampling, so no character is more likely.
fn random_base62(len: usize) -> Option<String> {
    let rng = SystemRandom::new();
    let mut out = String::with_capacity(len);
    let mut buffer = [0u8; 64];
    while out.len() < len {
        rng.fill(&mut buffer).ok()?;
        for &byte in &buffer {
            if byte < 248 && out.len() < len {
                out.push(char::from(BASE62[usize::from(byte % 62)]));
            }
        }
    }
    Some(out)
}

fn checksum(body: &str) -> String {
    let mut value = u64::from(crc32fast::hash(body.as_bytes()));
    let mut out = [b'0'; CHECK_LEN];
    for slot in out.iter_mut().rev() {
        *slot = BASE62[usize::try_from(value % 62).unwrap_or(0)];
        value /= 62;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The ID and secret of a well-formed token with a correct checksum.
fn parse(token: &str) -> Option<(&str, &str)> {
    let rest = token.strip_prefix(PREFIX)?;
    let (id, tail) = rest.split_once('_')?;
    if id.len() != ID_LEN || tail.len() != SECRET_LEN + CHECK_LEN || !tail.is_ascii() {
        return None;
    }
    let (secret, check) = tail.split_at(SECRET_LEN);
    let base62 = |s: &str| s.bytes().all(|b| b.is_ascii_alphanumeric());
    if !base62(id) || !base62(secret) {
        return None;
    }
    let body = &token[..token.len() - CHECK_LEN];
    (checksum(body) == check).then_some((id, secret))
}

fn hash(secret: &str) -> String {
    crate::hex(digest(&SHA256, secret.as_bytes()).as_ref())
}

/// One token as stored.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Token {
    /// Public ID.
    pub id: String,
    /// What the token is for, given by its creator.
    pub name: String,
    /// What it may do.
    pub role: Access,
    /// The user who created it (`cli` for the socket).
    pub created_by: String,
    /// Seconds since the Unix epoch.
    pub created_at: u64,
    /// Seconds since the Unix epoch; `None` never expires.
    pub expires_at: Option<u64>,
    /// Client networks it is accepted from; empty means any.
    #[serde(default)]
    pub allowed_from: Vec<IpNet>,
    /// SHA-256 of the secret, hex.
    secret_sha256: String,
    /// Last use, seconds since the Unix epoch.
    #[serde(default)]
    pub last_used_at: Option<u64>,
    /// Address of the last use.
    #[serde(default)]
    pub last_used_from: Option<IpAddr>,
}

/// What a new token needs.
pub struct NewToken {
    /// What the token is for.
    pub name: String,
    /// What it may do.
    pub role: Access,
    /// Who creates it.
    pub created_by: String,
    /// Lifetime; `None` never expires.
    pub lifetime: Option<Duration>,
    /// Client networks it is accepted from.
    pub allowed_from: Vec<IpNet>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TokensFile {
    version: u32,
    tokens: Vec<Token>,
}

struct Inner {
    list: Vec<Token>,
    persisted: HashMap<String, Instant>,
}

/// The token list and its file.
pub struct Tokens {
    path: PathBuf,
    inner: Mutex<Inner>,
}

impl Tokens {
    /// Reads `<dir>/tokens.json`; a missing file means no tokens.
    pub fn open(dir: &Path) -> io::Result<Self> {
        let path = dir.join("tokens.json");
        let list = match std::fs::read(&path) {
            Ok(bytes) => {
                let file: TokensFile = serde_json::from_slice(&bytes)
                    .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
                file.tokens
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(err) => return Err(err),
        };
        Ok(Self {
            path,
            inner: Mutex::new(Inner {
                list,
                persisted: HashMap::new(),
            }),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn save(&self, list: &[Token]) -> io::Result<()> {
        let file = TokensFile {
            version: 1,
            tokens: list.to_vec(),
        };
        let mut bytes = serde_json::to_vec_pretty(&file).map_err(io::Error::other)?;
        bytes.push(b'\n');
        rdock_config::state::write_atomic(&self.path, &bytes)
    }

    /// Creates a token and returns its full value (shown once) with the stored record.
    pub fn create(&self, new: NewToken) -> io::Result<(String, Token)> {
        let random = || random_base62(ID_LEN + SECRET_LEN);
        let chars = random().ok_or_else(|| io::Error::other("the random generator failed"))?;
        let (id, secret) = chars.split_at(ID_LEN);
        let body = format!("{PREFIX}{id}_{secret}");
        let value = format!("{body}{}", checksum(&body));
        let created_at = now();
        let token = Token {
            id: id.to_owned(),
            name: new.name,
            role: new.role,
            created_by: new.created_by,
            created_at,
            expires_at: new.lifetime.map(|l| created_at + l.as_secs()),
            allowed_from: new.allowed_from,
            secret_sha256: hash(secret),
            last_used_at: None,
            last_used_from: None,
        };
        let mut inner = self.lock();
        inner.list.push(token.clone());
        if let Err(err) = self.save(&inner.list) {
            inner.list.pop();
            return Err(err);
        }
        Ok((value, token))
    }

    /// The token record for a presented value, if it is valid, unexpired and allowed from
    /// `client`. Records the use; the file is updated at most once a minute per token.
    pub fn verify(&self, presented: &str, client: Option<IpAddr>) -> Option<Token> {
        let (id, secret) = parse(presented)?;
        let presented_hash = hash(secret);
        let mut inner = self.lock();
        let index = inner.list.iter().position(|t| t.id == id)?;
        let token = &mut inner.list[index];
        let matches = bool::from(
            presented_hash
                .as_bytes()
                .ct_eq(token.secret_sha256.as_bytes()),
        );
        let fresh = token.expires_at.is_none_or(|at| now() < at);
        let allowed = token.allowed_from.is_empty()
            || client.is_some_and(|ip| token.allowed_from.iter().any(|net| net.contains(&ip)));
        if !(matches && fresh && allowed) {
            return None;
        }
        token.last_used_at = Some(now());
        token.last_used_from = client;
        let found = token.clone();
        let due = inner
            .persisted
            .get(id)
            .is_none_or(|at| at.elapsed() >= PERSIST_USE_EVERY);
        if due {
            inner.persisted.insert(id.to_owned(), Instant::now());
            if let Err(err) = self.save(&inner.list) {
                tracing::warn!(error = %err, "cannot record the token's last use");
            }
        }
        Some(found)
    }

    /// All tokens, or those `created_by` one user.
    pub fn list(&self, created_by: Option<&str>) -> Vec<Token> {
        self.lock()
            .list
            .iter()
            .filter(|t| created_by.is_none_or(|u| t.created_by == u))
            .cloned()
            .collect()
    }

    /// Removes the token `id` if `allowed` says the caller may; returns whether it did.
    pub fn revoke(&self, id: &str, allowed: impl Fn(&Token) -> bool) -> io::Result<bool> {
        let mut inner = self.lock();
        let Some(index) = inner.list.iter().position(|t| t.id == id && allowed(t)) else {
            return Ok(false);
        };
        let removed = inner.list.remove(index);
        if let Err(err) = self.save(&inner.list) {
            inner.list.insert(index, removed);
            return Err(err);
        }
        Ok(true)
    }

    /// Removes every token a user created, when the user is deleted.
    pub fn revoke_user(&self, user: &str) -> io::Result<()> {
        let mut inner = self.lock();
        let before = inner.list.clone();
        inner.list.retain(|t| t.created_by != user);
        if inner.list.len() == before.len() {
            return Ok(());
        }
        if let Err(err) = self.save(&inner.list) {
            inner.list = before;
            return Err(err);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new(role: Access) -> NewToken {
        NewToken {
            name: "ci".into(),
            role,
            created_by: "root".into(),
            lifetime: Some(Duration::from_secs(3600)),
            allowed_from: Vec::new(),
        }
    }

    #[test]
    fn tokens_have_the_published_shape_and_a_checksum() {
        let dir = tempfile::tempdir().unwrap();
        let tokens = Tokens::open(dir.path()).unwrap();
        let (value, record) = tokens.create(new(Access::Viewer)).unwrap();
        assert_eq!(
            value.len(),
            PREFIX.len() + ID_LEN + 1 + SECRET_LEN + CHECK_LEN
        );
        assert!(value.starts_with(&format!("{PREFIX}{}_", record.id)));
        assert!(parse(&value).is_some());
        // One changed character fails the checksum.
        let mut typo = value.clone().into_bytes();
        let i = PREFIX.len() + ID_LEN + 5;
        typo[i] = if typo[i] == b'a' { b'b' } else { b'a' };
        assert!(parse(std::str::from_utf8(&typo).unwrap()).is_none());
        let text = std::fs::read_to_string(dir.path().join("tokens.json")).unwrap();
        assert!(
            !text.contains(&value[PREFIX.len() + ID_LEN + 1..value.len() - CHECK_LEN]),
            "the secret is not stored"
        );
    }

    #[test]
    fn verification_checks_secret_expiry_and_networks() {
        let dir = tempfile::tempdir().unwrap();
        let tokens = Tokens::open(dir.path()).unwrap();
        let (value, _) = tokens.create(new(Access::Operator)).unwrap();
        assert_eq!(tokens.verify(&value, None).unwrap().role, Access::Operator);
        assert!(tokens.verify("rdk_pat_nope", None).is_none());

        let (expired, _) = tokens
            .create(NewToken {
                lifetime: Some(Duration::ZERO),
                ..new(Access::Viewer)
            })
            .unwrap();
        assert!(tokens.verify(&expired, None).is_none());

        let (fenced, _) = tokens
            .create(NewToken {
                allowed_from: vec!["10.0.0.0/8".parse().unwrap()],
                ..new(Access::Metrics)
            })
            .unwrap();
        assert!(
            tokens
                .verify(&fenced, Some("10.1.2.3".parse().unwrap()))
                .is_some()
        );
        assert!(
            tokens
                .verify(&fenced, Some("192.0.2.1".parse().unwrap()))
                .is_none()
        );
        assert!(tokens.verify(&fenced, None).is_none());
    }

    #[test]
    fn revocation_is_immediate_and_survives_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let tokens = Tokens::open(dir.path()).unwrap();
        let (value, record) = tokens.create(new(Access::Admin)).unwrap();
        assert!(
            !tokens
                .revoke(&record.id, |t| t.created_by == "someone")
                .unwrap()
        );
        assert!(tokens.revoke(&record.id, |_| true).unwrap());
        assert!(tokens.verify(&value, None).is_none());
        let again = Tokens::open(dir.path()).unwrap();
        assert!(again.list(None).is_empty());
    }
}
