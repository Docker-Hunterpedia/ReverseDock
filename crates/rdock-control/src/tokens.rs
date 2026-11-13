//! Join tokens (`rdk_join_<id>_<secret><check>`, ADR-0031): single use, with an expiry. Only
//! the id and the SHA-256 of the secret are kept (`<data>/control/tokens.json`, mode 0600).

use std::path::PathBuf;

use rdock_credentials::{JOIN_TOKEN, Secret, hash_secret, hashes_match};
use serde::{Deserialize, Serialize};

use crate::{Error, unix_now};

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
        };
        // Forget tokens that expired more than a day ago.
        self.records.retain(|r| r.expires_at + 86_400 > now);
        self.records.push(record.clone());
        self.save()?;
        Ok((generated.value, record))
    }

    /// Uses `value` for `instance`: fails when it is malformed, unknown, expired or used.
    pub fn consume(&mut self, value: &str, instance: &str) -> Result<String, Error> {
        let refused = || {
            Error::Refused(
                "the join token is not valid (unknown, expired or already used)".to_owned(),
            )
        };
        let (id, secret) = JOIN_TOKEN.parse(value.trim()).ok_or_else(refused)?;
        let now = unix_now();
        let record = self
            .records
            .iter_mut()
            .find(|r| r.id == id)
            .ok_or_else(refused)?;
        if record.used_by.is_some()
            || record.expires_at <= now
            || !hashes_match(&hash_secret(secret), &record.secret_sha256)
        {
            return Err(refused());
        }
        record.used_by = Some(instance.to_owned());
        let id = record.id.clone();
        self.save()?;
        Ok(id)
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
        assert!(tokens.consume("rdk_join_nonsense", "a").is_err());
        assert_eq!(tokens.consume(value.expose(), "a").unwrap(), record.id);
        assert!(tokens.consume(value.expose(), "b").is_err(), "single use");
        let (expired, _) = tokens.create(std::time::Duration::ZERO, None).unwrap();
        assert!(tokens.consume(expired.expose(), "c").is_err(), "expired");
        let mut reloaded = Tokens::load(dir.path()).unwrap();
        assert!(
            reloaded.consume(value.expose(), "d").is_err(),
            "use survives a restart"
        );
    }
}
