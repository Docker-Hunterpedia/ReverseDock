//! Accounts, certificates and order journals in a cluster store (ADR-0020, ADR-0031). With no
//! cluster the store is the storage directory itself, with the layout of earlier versions:
//!
//! ```text
//! <root>/lock                                   (single instance: the process lock of ADR-0020)
//! <root>/accounts/<directory>/account.json
//! <root>/certs/<first name>/{cert.pem,key.pem,meta.json}
//! <root>/orders/<first name>.json               (the order in progress: URL and new key)
//! ```
//!
//! Values are written with mode 0600 into a temporary file and renamed, so a crash never leaves
//! half a certificate. `meta.json` is written last and names the SHA-256 of `cert.pem`, so a
//! reader that catches a certificate being replaced sees a mismatch and tries again later
//! instead of pairing a new chain with an old key.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use instant_acme::AccountCredentials;
use rdock_cluster::store::segment;
use rdock_cluster::{ClusterStore, Expect, Lease, StoreError};
use rdock_tls::LoadedCert;
use serde::{Deserialize, Serialize};

/// A lock older than this is left over from a process that died.
const STALE_LOCK: Duration = Duration::from_secs(30);

/// What is stored next to a certificate (`meta.json`). Everything after `profile` was added
/// in v0.9 (ADR-0031) so that every instance of a cluster takes the same renewal decision;
/// older files lack it and are completed when the certificate is next renewed.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CertMeta {
    /// Names on the certificate.
    pub names: Vec<String>,
    /// Directory URL of the issuing CA.
    pub directory: String,
    /// Profile asked for, if any.
    #[serde(default)]
    pub profile: Option<String>,
    /// The issuer's distinguished name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// The leaf's serial number, lower-case hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,
    /// Validity of the leaf (Unix seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<i64>,
    /// Expiry of the leaf (Unix seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<i64>,
    /// SHA-256 of `cert.pem` as stored, lower-case hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_sha256: Option<String>,
    /// The CA's suggested renewal window and the moment chosen in it (RFC 9773), shared so
    /// every instance renews at the same time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ari: Option<AriWindow>,
    /// Which instance issued the certificate, and when (Unix seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_by: Option<String>,
    /// When the certificate was stored (Unix seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<i64>,
    /// The last renewal failure, if the last attempt failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

/// The renewal window a CA suggested and the moment chosen in it (Unix seconds).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AriWindow {
    /// Start of the suggested window.
    pub start: i64,
    /// End of the suggested window.
    pub end: i64,
    /// The renewal time chosen inside it, once, by whichever instance read the window first.
    pub renew_at: i64,
}

/// An order in progress, so the instance that takes the lease next can finish it instead of
/// ordering again (ADR-0031). Holds the certificate's new private key: stored like `key.pem`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderJournal {
    /// The order's URL at the CA.
    pub url: String,
    /// The CA's directory URL.
    pub directory: String,
    /// Names ordered.
    pub names: Vec<String>,
    /// The private key the signing request is made with, PKCS#8 PEM.
    pub key_pem: String,
    /// Who created the order, and when (Unix seconds).
    pub created_by: String,
    /// When the order was created (Unix seconds).
    pub created_at: i64,
}

impl std::fmt::Debug for OrderJournal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OrderJournal")
            .field("url", &self.url)
            .field("names", &self.names)
            .field("created_by", &self.created_by)
            .finish_non_exhaustive()
    }
}

/// A stored certificate with its metadata and the metadata's version.
#[derive(Debug, Clone)]
pub struct StoredCert {
    /// The certificate and key, ready to serve.
    pub cert: LoadedCert,
    /// Its metadata.
    pub meta: CertMeta,
    /// The version of `meta.json`, for a compare-and-swap of the metadata.
    pub version: u64,
}

/// Why storage failed.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// The store refused or failed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// A stored document could not be read.
    #[error("{key}: {reason}")]
    Corrupt {
        /// The store key.
        key: String,
        /// What is wrong with it.
        reason: String,
    },
}

/// Accounts, certificates and journals in a store.
#[derive(Debug, Clone)]
pub struct Storage {
    store: Arc<dyn ClusterStore>,
    /// The directory of the single-instance store, for the process lock.
    root: Option<PathBuf>,
}

/// Holds the storage lock until dropped.
#[derive(Debug)]
pub struct StorageLock {
    path: PathBuf,
}

impl Drop for StorageLock {
    fn drop(&mut self) {
        // The lock file may already be gone if an operator removed it; nothing to do then.
        let _ = fs::remove_file(&self.path);
    }
}

impl StorageLock {
    /// Marks the lock as alive; call well within 30 seconds of the last refresh.
    pub fn refresh(&self) -> io::Result<()> {
        File::options()
            .write(true)
            .open(&self.path)?
            .set_modified(SystemTime::now())
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// SHA-256 of `bytes`, lower-case hex.
pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex(ring::digest::digest(&ring::digest::SHA256, bytes).as_ref())
}

fn corrupt(key: &str, reason: &dyn std::fmt::Display) -> StorageError {
    StorageError::Corrupt {
        key: key.to_owned(),
        reason: reason.to_string(),
    }
}

impl Storage {
    /// A single instance's storage directory (`acme.storage` or `$RDOCK_DATA_DIR/acme`).
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        Self {
            store: Arc::new(rdock_cluster::DirStore::shared(root.clone())),
            root: Some(root),
        }
    }

    /// A cluster's store.
    #[must_use]
    pub fn cluster(store: Arc<dyn ClusterStore>) -> Self {
        Self { store, root: None }
    }

    /// The store underneath.
    #[must_use]
    pub fn store(&self) -> &Arc<dyn ClusterStore> {
        &self.store
    }

    /// Takes the process lock of a single instance's directory (ADR-0020), which keeps a
    /// process of an earlier version that shares the directory from ordering at the same time.
    /// Returns `None` while another live process holds it. A cluster store has no such lock:
    /// its leases are per name (`Some` always).
    pub fn lock(&self) -> io::Result<Option<StorageLock>> {
        let Some(root) = &self.root else {
            return Ok(Some(StorageLock {
                path: PathBuf::new(),
            }));
        };
        create_dir(root)?;
        let path = root.join("lock");
        for _ in 0..2 {
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(mut file) => {
                    writeln!(file, "{}", std::process::id())?;
                    return Ok(Some(StorageLock { path }));
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    let age = fs::metadata(&path)?
                        .modified()?
                        .elapsed()
                        .unwrap_or_default();
                    if age < STALE_LOCK {
                        return Ok(None);
                    }
                    fs::remove_file(&path)?;
                }
                Err(e) => return Err(e),
            }
        }
        Ok(None)
    }

    /// Whether this is a single instance's directory (with the process lock).
    #[must_use]
    pub fn is_local(&self) -> bool {
        self.root.is_some()
    }

    /// The stored account for `directory`, if any, with its version.
    pub async fn load_account(
        &self,
        directory: &str,
    ) -> Result<Option<AccountCredentials>, StorageError> {
        let key = account_key(directory);
        match self.store.get(&key).await? {
            Some(entry) => serde_json::from_slice(&entry.value)
                .map(Some)
                .map_err(|e| corrupt(&key, &e)),
            None => Ok(None),
        }
    }

    /// Stores the account for `directory` unless one is stored already (`Conflict` then).
    pub async fn save_account(
        &self,
        directory: &str,
        account: &AccountCredentials,
    ) -> Result<(), StorageError> {
        let key = account_key(directory);
        let json = serde_json::to_vec_pretty(account).map_err(|e| corrupt(&key, &e))?;
        self.store.put(&key, json, Expect::Absent, None).await?;
        Ok(())
    }

    /// The stored certificate named after `first_name`, if present and complete.
    pub async fn load_cert(&self, first_name: &str) -> Result<Option<StoredCert>, StorageError> {
        let dir = cert_dir(first_name);
        let meta_key = format!("{dir}/meta.json");
        let Some(meta_entry) = self.store.get(&meta_key).await? else {
            return Ok(None);
        };
        let meta: CertMeta =
            serde_json::from_slice(&meta_entry.value).map_err(|e| corrupt(&meta_key, &e))?;
        let cert_key = format!("{dir}/cert.pem");
        let key_key = format!("{dir}/key.pem");
        let (Some(chain), Some(key)) = (
            self.store.get(&cert_key).await?,
            self.store.get(&key_key).await?,
        ) else {
            return Ok(None);
        };
        if let Some(expected) = &meta.chain_sha256
            && *expected != sha256_hex(&chain.value)
        {
            // Being replaced right now; the next look finds it complete.
            return Ok(None);
        }
        let cert = rdock_tls::certificate_from_pem(
            first_name,
            &chain.value,
            &key.value,
            Path::new(&cert_key),
        )
        .map_err(|e| corrupt(&cert_key, &e))?;
        Ok(Some(StoredCert {
            cert,
            meta,
            version: meta_entry.version,
        }))
    }

    /// The version of the stored metadata of `first_name` (`0` when there is none): a cheap
    /// check whether another instance stored a new certificate.
    pub async fn meta_version(&self, first_name: &str) -> Result<u64, StorageError> {
        let key = format!("{}/meta.json", cert_dir(first_name));
        Ok(self.store.get(&key).await?.map_or(0, |e| e.version))
    }

    /// Stores a certificate chain (PEM, leaf first), its key (PEM) and metadata, while `fence`
    /// is the current lease on the name. The metadata is written last, with compare-and-swap
    /// against `meta_version` (`0`: none stored), so a certificate is loaded only once all
    /// three are complete and two writers cannot both succeed.
    pub async fn save_cert(
        &self,
        first_name: &str,
        chain_pem: &str,
        key_pem: &str,
        meta: &CertMeta,
        meta_version: u64,
        fence: Option<&Lease>,
    ) -> Result<u64, StorageError> {
        let dir = cert_dir(first_name);
        let mut meta = meta.clone();
        meta.chain_sha256 = Some(sha256_hex(chain_pem.as_bytes()));
        self.store
            .put(
                &format!("{dir}/cert.pem"),
                chain_pem.as_bytes().to_vec(),
                Expect::Any,
                fence,
            )
            .await?;
        self.store
            .put(
                &format!("{dir}/key.pem"),
                key_pem.as_bytes().to_vec(),
                Expect::Any,
                fence,
            )
            .await?;
        let meta_key = format!("{dir}/meta.json");
        let json = serde_json::to_vec_pretty(&meta).map_err(|e| corrupt(&meta_key, &e))?;
        let expect = if meta_version == 0 {
            Expect::Absent
        } else {
            Expect::Version(meta_version)
        };
        Ok(self.store.put(&meta_key, json, expect, fence).await?)
    }

    /// Replaces the metadata of `first_name` when it still has `version`; returns the new
    /// version.
    pub async fn save_meta(
        &self,
        first_name: &str,
        meta: &CertMeta,
        version: u64,
    ) -> Result<u64, StorageError> {
        let key = format!("{}/meta.json", cert_dir(first_name));
        let json = serde_json::to_vec_pretty(meta).map_err(|e| corrupt(&key, &e))?;
        Ok(self
            .store
            .put(&key, json, Expect::Version(version), None)
            .await?)
    }

    /// The journal of the order in progress for `first_name`, if any.
    pub async fn load_order(&self, first_name: &str) -> Result<Option<OrderJournal>, StorageError> {
        let key = order_key(first_name);
        match self.store.get(&key).await? {
            Some(entry) => serde_json::from_slice(&entry.value)
                .map(Some)
                .map_err(|e| corrupt(&key, &e)),
            None => Ok(None),
        }
    }

    /// Records the order in progress, while `fence` holds.
    pub async fn save_order(
        &self,
        first_name: &str,
        journal: &OrderJournal,
        fence: Option<&Lease>,
    ) -> Result<(), StorageError> {
        let key = order_key(first_name);
        let json = serde_json::to_vec_pretty(journal).map_err(|e| corrupt(&key, &e))?;
        self.store.put(&key, json, Expect::Any, fence).await?;
        Ok(())
    }

    /// Forgets the order in progress, while `fence` holds.
    pub async fn delete_order(
        &self,
        first_name: &str,
        fence: Option<&Lease>,
    ) -> Result<(), StorageError> {
        self.store
            .delete(&order_key(first_name), Expect::Any, fence)
            .await?;
        Ok(())
    }
}

fn account_key(directory: &str) -> String {
    let name = directory
        .trim_start_matches("https://")
        .trim_end_matches('/');
    format!("accounts/{}/account.json", segment(name))
}

fn cert_dir(first_name: &str) -> String {
    format!("certs/{}", segment(first_name))
}

fn order_key(first_name: &str) -> String {
    format!("orders/{}.json", segment(first_name))
}

/// The lease that guards ordering the certificate named after `first_name`.
pub(crate) fn cert_lease(first_name: &str) -> String {
    format!("cert/{}", segment(first_name))
}

/// The lease that guards creating the account for `directory`.
pub(crate) fn account_lease(directory: &str) -> String {
    let name = directory
        .trim_start_matches("https://")
        .trim_end_matches('/');
    format!("account/{}", segment(name))
}

/// Creates `dir` and its parents, readable only by the owner.
pub(crate) fn create_dir(dir: &Path) -> io::Result<()> {
    rdock_cluster::dir::create_dir(dir)
}

/// Writes `bytes` to `path` readable only by the owner, replacing the file atomically.
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    write_atomic(path, bytes, 0o600)
}

/// Writes `bytes` to `path` readable by everyone (certificates, which are public), replacing
/// the file atomically.
pub(crate) fn write_public(path: &Path, bytes: &[u8]) -> io::Result<()> {
    write_atomic(path, bytes, 0o644)
}

#[cfg_attr(not(unix), allow(unused_variables))]
fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| io::Error::other("path has no parent directory"))?;
    create_dir(dir)?;
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, mode);
    let mut file = options.open(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_keys_safely() {
        assert_eq!(cert_dir("*.example.com"), "certs/_.example.com");
        assert_eq!(cert_dir("2001:db8::1"), "certs/2001-db8--1");
        assert_eq!(
            account_key("https://acme-v02.api.letsencrypt.org/directory"),
            "accounts/acme-v02.api.letsencrypt.org-directory/account.json"
        );
        assert_eq!(order_key("app.example.com"), "orders/app.example.com.json");
    }

    #[test]
    fn lock_is_exclusive_until_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new(dir.path());
        let lock = storage.lock().unwrap().unwrap();
        assert!(storage.lock().unwrap().is_none());
        lock.refresh().unwrap();
        drop(lock);
        assert!(storage.lock().unwrap().is_some());
    }

    #[cfg(unix)]
    #[test]
    fn writes_private_files() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a/b/key.pem");
        write_private(&path, b"secret").unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(fs::read(&path).unwrap(), b"secret");
    }

    #[tokio::test]
    async fn the_metadata_is_the_commit_point() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new(dir.path());
        let (chain, key) = crate::testing::self_signed("app.example.com");
        let meta = CertMeta {
            names: vec!["app.example.com".into()],
            directory: "https://ca.test/dir".into(),
            ..CertMeta::default()
        };
        let v1 = storage
            .save_cert("app.example.com", &chain, &key, &meta, 0, None)
            .await
            .unwrap();
        let stored = storage.load_cert("app.example.com").await.unwrap().unwrap();
        assert_eq!(stored.version, v1);
        assert_eq!(
            stored.meta.chain_sha256.as_deref(),
            Some(sha256_hex(chain.as_bytes()).as_str())
        );
        // A second writer that read no certificate loses.
        assert!(matches!(
            storage
                .save_cert("app.example.com", &chain, &key, &meta, 0, None)
                .await,
            Err(StorageError::Store(StoreError::Conflict { .. }))
        ));
        // A chain that does not match the metadata (a replacement in progress) is not loaded.
        let (other, _) = crate::testing::self_signed("app.example.com");
        storage
            .store()
            .put(
                "certs/app.example.com/cert.pem",
                other.into_bytes(),
                Expect::Any,
                None,
            )
            .await
            .unwrap();
        assert!(
            storage
                .load_cert("app.example.com")
                .await
                .unwrap()
                .is_none()
        );
        // Files of earlier versions (without `chain_sha256`) still load.
        let old = CertMeta {
            names: vec!["app.example.com".into()],
            directory: "https://ca.test/dir".into(),
            profile: None,
            ..CertMeta::default()
        };
        let path = dir.path().join("certs/app.example.com");
        fs::write(path.join("cert.pem"), &chain).unwrap();
        fs::write(path.join("meta.json"), serde_json::to_vec(&old).unwrap()).unwrap();
        assert!(
            storage
                .load_cert("app.example.com")
                .await
                .unwrap()
                .is_some()
        );
    }
}
