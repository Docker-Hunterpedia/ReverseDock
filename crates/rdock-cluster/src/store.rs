//! The `ClusterStore` trait: a small key-value store with compare-and-swap and leases with a
//! fencing token, shared by every member of a cluster (ADR-0031).
//!
//! Keys are `/`-separated segments of `[A-Za-z0-9._-]`, none empty, none `.` or `..`, none
//! starting with `.` (names beginning with a dot are the backends' own). Values are bytes.
//!
//! A **lease** names a piece of work (`cert/app.example.com`). One holder has it until it
//! expires or is released; each new holder gets a larger **token**. A write that carries a
//! lease (a *fenced* write) succeeds only while that lease is still the current one. Whether the
//! store can guarantee this is [`ClusterStore::fencing`]: the control plane's store checks every
//! fenced write under one lock and one clock; a shared directory checks it as well as files
//! allow, which is not a guarantee.

use std::fmt;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// A stored value and its version. Versions change on every write of new content and are
/// never `0` ([`Expect::Absent`] means "no value").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The value.
    pub value: Vec<u8>,
    /// The version to pass to [`Expect::Version`] for a compare-and-swap.
    pub version: u64,
}

/// The condition of a conditional write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "version")]
pub enum Expect {
    /// Write whatever is there.
    Any,
    /// Write only when there is no value.
    Absent,
    /// Write only when the value has this version.
    Version(u64),
}

/// A lease: who holds a piece of work, until when, and the fencing token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lease {
    /// What the lease is for, a key-shaped name.
    pub name: String,
    /// The holder's instance name.
    pub holder: String,
    /// Grows with every new holder of `name`; fenced writes carry it.
    pub token: u64,
    /// When the lease ends unless renewed, in milliseconds since the Unix epoch, by the clock
    /// of whoever judges it (the store's for the control plane, each instance's for a shared
    /// directory).
    pub expires_at_ms: u64,
}

/// How far a store enforces fencing tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Fencing {
    /// Every fenced write is checked atomically against the current lease, by one clock.
    Enforced,
    /// Checked when the write happens, not atomically, with each instance's clock deciding
    /// expiry: a holder paused between the check and the write can still write.
    BestEffort,
}

/// Why a store operation failed.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The condition of a conditional write did not hold.
    #[error("the value of `{key}` changed (version {current} now)")]
    Conflict {
        /// The key.
        key: String,
        /// The version now stored, `0` when there is none.
        current: u64,
    },
    /// The write carried a lease that is no longer the current one.
    #[error("the lease `{lease}` (token {token}) is no longer held")]
    Fenced {
        /// The lease's name.
        lease: String,
        /// The stale token.
        token: u64,
    },
    /// A lease to renew or release has passed to another holder or expired.
    #[error("the lease `{0}` was lost")]
    Lost(String),
    /// A key or lease name is not well-formed.
    #[error("`{0}` is not a valid store key")]
    InvalidKey(String),
    /// The store cannot be reached or refused the request.
    #[error("store unavailable: {0}")]
    Unavailable(String),
    /// The backend failed (a file could not be written, a document could not be read).
    #[error("store: {0}")]
    Backend(String),
}

impl From<std::io::Error> for StoreError {
    fn from(error: std::io::Error) -> Self {
        Self::Backend(error.to_string())
    }
}

/// A store shared by the members of a cluster.
#[async_trait]
pub trait ClusterStore: Send + Sync + fmt::Debug {
    /// The value of `key`, if any.
    async fn get(&self, key: &str) -> Result<Option<Entry>, StoreError>;

    /// Writes `value` to `key` when `expect` holds and, with `fence`, while that lease is the
    /// current one. Returns the new version.
    async fn put(
        &self,
        key: &str,
        value: Vec<u8>,
        expect: Expect,
        fence: Option<&Lease>,
    ) -> Result<u64, StoreError>;

    /// Removes `key` when `expect` holds and, with `fence`, while that lease is the current
    /// one. Removing a missing key with [`Expect::Any`] succeeds.
    async fn delete(
        &self,
        key: &str,
        expect: Expect,
        fence: Option<&Lease>,
    ) -> Result<(), StoreError>;

    /// The keys that start with `prefix` (a whole number of segments, or empty), sorted.
    async fn list(&self, prefix: &str) -> Result<Vec<String>, StoreError>;

    /// Takes the lease `name` for `holder` for `ttl`, unless someone else holds it (`None`).
    /// A holder that asks again while it holds the lease gets it renewed with the same token.
    async fn acquire(
        &self,
        name: &str,
        holder: &str,
        ttl: Duration,
    ) -> Result<Option<Lease>, StoreError>;

    /// Extends `lease` by `ttl` from now; [`StoreError::Lost`] when it is no longer held.
    async fn renew(&self, lease: &Lease, ttl: Duration) -> Result<Lease, StoreError>;

    /// Gives `lease` up; nothing happens when it is no longer held.
    async fn release(&self, lease: &Lease) -> Result<(), StoreError>;

    /// The current lease `name`, expired or not, if one was ever taken.
    async fn lease(&self, name: &str) -> Result<Option<Lease>, StoreError>;

    /// How far this store enforces fencing.
    fn fencing(&self) -> Fencing;
}

/// Checks that `key` is well-formed (see the module documentation). `prefix` allows the empty
/// key, which [`ClusterStore::list`] takes for "everything".
pub fn check_key(key: &str, prefix: bool) -> Result<(), StoreError> {
    if key.is_empty() {
        return if prefix {
            Ok(())
        } else {
            Err(StoreError::InvalidKey(key.to_owned()))
        };
    }
    let ok = key.len() <= 512
        && key.split('/').all(|segment| {
            !segment.is_empty()
                && !segment.starts_with('.')
                && segment
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
        });
    if ok {
        Ok(())
    } else {
        Err(StoreError::InvalidKey(key.to_owned()))
    }
}

/// A key segment for an arbitrary name (a host name, a wildcard, an IP address, a URL): `*`
/// becomes `_`, other characters outside `[A-Za-z0-9.-]` become `-`, a leading `.` becomes
/// `_`. The ACME storage uses the same rule for its directory names.
#[must_use]
pub fn segment(text: &str) -> String {
    let mut out: String = text
        .chars()
        .map(|c| match c {
            '*' => '_',
            c if c.is_ascii_alphanumeric() || c == '.' || c == '-' => c,
            _ => '-',
        })
        .collect();
    if out.is_empty() || out.starts_with('.') {
        out.insert(0, '_');
    }
    out
}

/// A version for `bytes` that does not depend on who wrote them: the first eight bytes of
/// their SHA-256, never `0`.
#[must_use]
pub fn content_version(bytes: &[u8]) -> u64 {
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
    let mut first = [0u8; 8];
    first.copy_from_slice(&digest.as_ref()[..8]);
    u64::from_be_bytes(first) | 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_checked() {
        for good in ["a", "certs/app.example.com/cert.pem", "leases/x_y-z"] {
            assert!(check_key(good, false).is_ok(), "{good}");
        }
        for bad in [
            "", "/a", "a/", "a//b", "a/../b", ".lease/x", "a/.b", "a b", "a/b*",
        ] {
            assert!(check_key(bad, false).is_err(), "{bad}");
        }
        assert!(check_key("", true).is_ok());
        assert_eq!(segment("*.example.com"), "_.example.com");
        assert_eq!(segment("2001:db8::1"), "2001-db8--1");
        assert_eq!(segment(".hidden"), "_.hidden");
        assert_ne!(content_version(b"a"), content_version(b"b"));
        assert_ne!(content_version(b""), 0);
    }
}
