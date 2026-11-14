//! Join tokens (`rdk_join_<id>_<secret><check>`, ADR-0031): single use, with an expiry. Only
//! the id and the SHA-256 of the secret are kept (`<data>/control/tokens.json`, mode 0600).

use std::path::PathBuf;

use rdock_credentials::{JOIN_TOKEN, Secret, hash_secret, hashes_match};
use serde::{Deserialize, Serialize};

use crate::{Error, unix_now};

fn refused() -> Error {
    Error::Refused("the join token is not valid (unknown, expired or already used)".to_owned())
}

/// A stored token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenRecord {
    /// The public id.
    pub id: String,
    /// SHA-256 of the secret, lower-case hex.
    pub secret_sha256: String,
    /// When it was created (Unix seconds).
    pub created_at: i64,
    /// When it stops working (Unix seconds).
    pub expires_at: i64,
    /// Who created it.
    #[serde(default)]
    pub created_by: Option<String>,
    /// The instance that used it, once used.
    #[serde(default)]
    pub used_by: Option<String>,
    /// SHA-256 of the public key it was used with: a retry with the same key while the token
    /// is valid is answered again, so a lost answer does not spend the token for good (review
    /// finding L2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub used_with_key: Option<String>,
}

/// What a join token allows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenUse {
    /// Unused and valid: enrol (the token's id).
    Fresh(String),
    /// Already used, for this key, and still valid: answer the instance it enrolled again.
    Retry {
        /// The token's id.
        id: String,
        /// The instance it enrolled.
        instance: String,
    },
}

/// The token file.
#[derive(Debug)]
pub struct Tokens {
    path: PathBuf,
    records: Vec<TokenRecord>,
}

impl Tokens {
    /// Loads `<dir>/tokens.json`.
    pub fn load(dir: &std::path::Path) -> Result<Self, Error> {
        let path = dir.join("tokens.json");
        let records = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| Error::State(format!("{}: {e}", path.display())))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(Error::State(format!("{}: {e}", path.display()))),
        };
        Ok(Self { path, records })
    }

    fn save(&self) -> Result<(), Error> {
        let json =
            serde_json::to_vec_pretty(&self.records).map_err(|e| Error::State(e.to_string()))?;
        rdock_cluster::dir::write_private(&self.path, &json)
            .map_err(|e| Error::State(format!("{}: {e}", self.path.display())))
    }

    /// Creates a token valid for `ttl`; the value is shown once and never stored.
    pub fn create(
        &mut self,
        ttl: std::time::Duration,
        created_by: Option<String>,
    ) -> Result<(Secret, TokenRecord), Error> {
        let generated = JOIN_TOKEN
            .generate()
            .ok_or_else(|| Error::State("the system random generator failed".to_owned()))?;
        let now = unix_now();
        let record = TokenRecord {
            id: generated.id.clone(),
            secret_sha256: generated.secret_sha256,
            created_at: now,
            expires_at: now.saturating_add(i64::try_from(ttl.as_secs()).unwrap_or(i64::MAX)),
            created_by,
            used_by: None,
            used_with_key: None,
        };
        // Forget tokens that expired more than a day ago.
        self.records.retain(|r| r.expires_at + 86_400 > now);
        self.records.push(record.clone());
        self.save()?;
        Ok((generated.value, record))
    }

    /// What `value` allows for a request with the public key `key` (its SHA-256): fails when
    /// it is malformed, unknown, expired, or used with another key.
    pub fn check(&self, value: &str, key: &str) -> Result<TokenUse, Error> {
        let (id, secret) = JOIN_TOKEN.parse(value.trim()).ok_or_else(refused)?;
        let record = self
            .records
            .iter()
            .find(|r| r.id == id)
            .ok_or_else(refused)?;
        if record.expires_at <= unix_now()
            || !hashes_match(&hash_secret(secret), &record.secret_sha256)
        {
            return Err(refused());
        }
        match (&record.used_by, &record.used_with_key) {
            (None, _) => Ok(TokenUse::Fresh(record.id.clone())),
            (Some(instance), Some(used)) if hashes_match(used, key) => Ok(TokenUse::Retry {
                id: record.id.clone(),
                instance: instance.clone(),
            }),
            _ => Err(refused()),
        }
    }

    /// Marks the token `id` used by `instance` with the public key `key` (its SHA-256).
    pub fn mark_used(&mut self, id: &str, instance: &str, key: &str) -> Result<(), Error> {
        let record = self
            .records
            .iter_mut()
            .find(|r| r.id == id)
            .ok_or_else(refused)?;
        record.used_by = Some(instance.to_owned());
        record.used_with_key = Some(key.to_owned());
        self.save()
    }

    /// Uses `value` for `instance` with the key `key`: fails when it is malformed, unknown,
    /// expired or used (also by the same key).
    pub fn consume(&mut self, value: &str, instance: &str, key: &str) -> Result<String, Error> {
        match self.check(value, key)? {
            TokenUse::Fresh(id) => {
                self.mark_used(&id, instance, key)?;
                Ok(id)
            }
            TokenUse::Retry { .. } => Err(refused()),
        }
    }

    /// Every token, newest first, without secrets.
    #[must_use]
    pub fn list(&self) -> Vec<TokenRecord> {
        let mut records = self.records.clone();
        records.reverse();
        records
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_single_use_and_expire() {
        let dir = tempfile::tempdir().unwrap();
        let mut tokens = Tokens::load(dir.path()).unwrap();
        let (value, record) = tokens
            .create(std::time::Duration::from_secs(3600), None)
            .unwrap();
        assert!(value.expose().starts_with("rdk_join_"));
        let stored = std::fs::read_to_string(dir.path().join("tokens.json")).unwrap();
        assert!(!stored.contains(value.expose()), "only the hash is stored");
        assert!(tokens.consume("rdk_join_nonsense", "a", "k1").is_err());
        assert_eq!(
            tokens.consume(value.expose(), "a", "k1").unwrap(),
            record.id
        );
        assert!(
            tokens.consume(value.expose(), "b", "k2").is_err(),
            "single use"
        );
        // The same key may ask again (its answer was lost); another key may not.
        assert_eq!(
            tokens.check(value.expose(), "k1").unwrap(),
            TokenUse::Retry {
                id: record.id.clone(),
                instance: "a".into()
            }
        );
        assert!(tokens.check(value.expose(), "k2").is_err());
        let (expired, _) = tokens.create(std::time::Duration::ZERO, None).unwrap();
        assert!(
            tokens.consume(expired.expose(), "c", "k3").is_err(),
            "expired"
        );
        let mut reloaded = Tokens::load(dir.path()).unwrap();
        assert!(
            reloaded.consume(value.expose(), "d", "k4").is_err(),
            "use survives a restart"
        );
        assert!(matches!(
            reloaded.check(value.expose(), "k1"),
            Ok(TokenUse::Retry { .. })
        ));
    }
}
