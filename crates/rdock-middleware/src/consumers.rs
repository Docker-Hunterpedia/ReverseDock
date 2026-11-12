//! The consumers of a configuration and their API keys, compiled once per configuration into
//! a map from key ID to the consumer and the key's hash (ADR-0030, F-GW-01): a request's key
//! is found in O(1) and compared in constant time. Keys files are read here, on every reload.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::Arc;

use rdock_model::gateway::{Consumer as ConsumerConfig, parse_rfc3339};

use crate::{Consumer, Issue};

/// One stored key.
#[derive(Debug, Clone)]
pub struct StoredKey {
    /// Who the key belongs to.
    pub consumer: Consumer,
    /// SHA-256 of the key's secret, lower-case hex.
    pub hash: String,
    /// Unix seconds after which the key is refused.
    pub expires: Option<i64>,
}

/// Every consumer's keys, by key ID.
#[derive(Debug, Default)]
pub struct ConsumerIndex {
    keys: HashMap<String, StoredKey>,
    consumers: HashMap<String, Consumer>,
}

impl ConsumerIndex {
    /// Compiles `consumers`, reading their keys files. Problems carry a path under
    /// `consumers.<name>`; they never quote a line of a keys file, which could hold a key.
    ///
    /// # Errors
    ///
    /// Every problem found; the index is then not usable.
    pub fn build(consumers: &BTreeMap<String, ConsumerConfig>) -> Result<Self, Vec<Issue>> {
        let mut index = Self::default();
        let mut issues = Vec::new();
        for (name, config) in consumers {
            let consumer = Consumer {
                name: Arc::from(name.as_str()),
                groups: config
                    .groups()
                    .iter()
                    .map(|g| Arc::from(g.as_str()))
                    .collect(),
                issuer: None,
            };
            index.consumers.insert(name.clone(), consumer.clone());
            let base = rdock_model::path_key("consumers", name);
            let mut add = |id: &str, hash: &str, expires: Option<i64>, at: String| {
                let stored = StoredKey {
                    consumer: consumer.clone(),
                    hash: hash.to_owned(),
                    expires,
                };
                if index.keys.insert(id.to_owned(), stored).is_some() {
                    issues.push(Issue::new(at, format!("key `{id}` is listed twice")));
                }
            };
            for (i, key) in config.keys.iter().enumerate() {
                let expires = key.expires.as_deref().and_then(parse_rfc3339);
                add(&key.id, &key.hash, expires, format!("{base}.keys[{i}]"));
            }
            if let Some(file) = &config.keys_file {
                match read_keys_file(file) {
                    Ok(lines) => {
                        for (line, id, hash, expires) in lines {
                            add(&id, &hash, expires, format!("{base}.keys_file:{line}"));
                        }
                    }
                    Err(problems) => {
                        for message in problems {
                            issues.push(Issue::new(format!("{base}.keys_file"), message));
                        }
                    }
                }
            }
        }
        if issues.is_empty() {
            Ok(index)
        } else {
            Err(issues)
        }
    }

    /// The key with ID `id`.
    #[must_use]
    pub fn key(&self, id: &str) -> Option<&StoredKey> {
        self.keys.get(id)
    }

    /// The consumer named `name`.
    #[must_use]
    pub fn consumer(&self, name: &str) -> Option<&Consumer> {
        self.consumers.get(name)
    }

    /// Number of keys.
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether there are no keys.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

type KeyLine = (usize, String, String, Option<i64>);

/// The `id:sha256[:expires]` lines of a keys file, with their line numbers.
fn read_keys_file(path: &Path) -> Result<Vec<KeyLine>, Vec<String>> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| vec![format!("cannot read `{}`: {e}", path.display())])?;
    let mut out = Vec::new();
    let mut problems = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let number = i + 1;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with(rdock_credentials::API_KEY.prefix) {
            problems.push(format!(
                "line {number} looks like an API key itself; store `id:hash` (see `rdock keys hash`)"
            ));
            continue;
        }
        let mut parts = line.splitn(3, ':');
        let (Some(id), Some(hash)) = (parts.next(), parts.next()) else {
            problems.push(format!("line {number} is not `id:sha256[:expires]`"));
            continue;
        };
        if !rdock_credentials::API_KEY.is_id(id) {
            problems.push(format!(
                "line {number}: the ID is not 12 letters and digits"
            ));
            continue;
        }
        if !rdock_credentials::is_sha256_hex(hash) {
            problems.push(format!(
                "line {number}: the hash is not 64 lower-case hex digits"
            ));
            continue;
        }
        let expires = parts.next().map(parse_rfc3339);
        if expires == Some(None) {
            problems.push(format!("line {number}: the expiry is not an RFC 3339 time"));
            continue;
        }
        let expires = expires.flatten();
        out.push((number, id.to_owned(), hash.to_owned(), expires));
    }
    if problems.is_empty() {
        Ok(out)
    } else {
        Err(problems)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_from_the_configuration_and_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("keys.txt");
        let hash = "a".repeat(64);
        std::fs::write(
            &file,
            format!(
                "# partner keys\n\nAbCdEfGhIjK1:{hash}\nAbCdEfGhIjK2:{hash}:2027-01-01T00:00:00Z\n"
            ),
        )
        .unwrap();
        let yaml = format!(
            "acme:\n  groups: [gold]\n  keys: [{{ id: AbCdEfGhIjK0, hash: \"{hash}\" }}]\n  keys_file: \"{}\"\n",
            file.display()
        );
        let consumers: BTreeMap<String, ConsumerConfig> = serde_saphyr_free(&yaml);
        let index = ConsumerIndex::build(&consumers).unwrap();
        assert_eq!(index.len(), 3);
        let key = index.key("AbCdEfGhIjK2").unwrap();
        assert_eq!(&*key.consumer.name, "acme");
        assert_eq!(&*key.consumer.groups[0], "gold");
        assert_eq!(key.expires, Some(1_798_761_600));

        // A bad file names the line, never its content.
        let secret = rdock_credentials::API_KEY.generate().unwrap();
        std::fs::write(&file, format!("{}\nshort:{hash}\n", secret.value.expose())).unwrap();
        let issues = ConsumerIndex::build(&consumers).unwrap_err();
        let text = format!("{issues:?}");
        assert!(text.contains("line 1 looks like an API key"), "{text}");
        assert!(text.contains("line 2"), "{text}");
        assert!(!text.contains(secret.value.expose()));
    }

    fn serde_saphyr_free(yaml: &str) -> BTreeMap<String, ConsumerConfig> {
        let config = rdock_config::load_str(
            &format!("consumers:\n{}", indent(yaml)),
            rdock_config::Format::Yaml,
        )
        .unwrap()
        .config;
        config.consumers
    }

    fn indent(text: &str) -> String {
        text.lines().fold(String::new(), |mut out, l| {
            out.push_str("  ");
            out.push_str(l);
            out.push('\n');
            out
        })
    }
}
