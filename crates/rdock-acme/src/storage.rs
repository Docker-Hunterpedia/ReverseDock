//! Accounts, certificates and order journals in a cluster store (ADR-0020, ADR-0031). With no
//! cluster the store is the storage directory itself, with the layout of earlier versions:
//!
//! ```text
//! <root>/lock                                   (single instance: the process lock of ADR-0020)
//! <root>/accounts/<directory>/account.json
//! <root>/certs/<first name>/{cert.pem,key.pem,meta.json}
//! <root>/certs/<first name>/next/{cert.pem,key.pem}   (while a new certificate is stored)
//! <root>/orders/<first name>.json               (the order in progress: URL and new key)
//! ```
//!
//! Values are written with mode 0600 into a temporary file and renamed, so a crash never leaves
//! half a file. A new certificate and key are written to `next/` first; `meta.json`, which names
//! the SHA-256 of the chain, is then written with compare-and-swap (the commit), and only after
//! that are `cert.pem` and `key.pem` replaced. A reader takes the pair that matches `meta.json`
//! (and whose key matches its chain), so it never pairs a new chain with an old key, and a save
//! that stops at any point leaves either the previous or the new certificate loading.

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

/// Free space an order needs before it is placed: the journal (about 2 KiB), the chain and key
/// twice (in `next/` and in place, about 8 KiB each with an RSA key), `meta.json` (about 1 KiB)
/// and the temporary file of each, rounded up to whole 4 KiB blocks, about 64 KiB, with a
/// sixteen-fold margin for the file system's own needs.
pub const CERT_ROOM: u64 = 1024 * 1024;

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

    /// Checks, before an order is placed, that the directory has room for what the order
    /// will store ([`CERT_ROOM`]): an order whose certificate cannot be stored would use up the
    /// CA's rate limits for nothing (ADR-0033). A cluster store is not on this file system
    /// and is not checked.
    ///
    /// # Errors
    ///
    /// Less room than [`CERT_ROOM`], or the free space cannot be read.
    pub fn check_room(&self) -> Result<(), rdock_config::disk::NoRoom> {
        match &self.root {
            Some(root) => rdock_config::disk::check_room(root, CERT_ROOM).map(|_| ()),
            None => Ok(()),
        }
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

    /// Stores the account for `directory` unless one is stored already (`Conflict` then),
    /// while `fence` (the lease `account/<directory>`) holds.
    pub async fn save_account(
        &self,
        directory: &str,
        account: &AccountCredentials,
        fence: Option<&Lease>,
    ) -> Result<(), StorageError> {
        let key = account_key(directory);
        let json = serde_json::to_vec_pretty(account).map_err(|e| corrupt(&key, &e))?;
        self.store.put(&key, json, Expect::Absent, fence).await?;
        Ok(())
    }

    /// The stored certificate named after `first_name`, if present and complete.
    pub async fn load_cert(&self, first_name: &str) -> Result<Option<StoredCert>, StorageError> {
        Ok(self.read_cert(first_name).await?.1)
    }

    /// The raw version of `meta.json` (`0` when there is none), whatever it describes, and the
    /// certificate it describes when one is stored complete. A `meta.json` that cannot be read
    /// or names a chain that is stored nowhere gives its version and no certificate, so the
    /// next save replaces it instead of failing its compare-and-swap (ADR-0031).
    ///
    /// The chain and key are looked for in `cert.pem`/`key.pem`, then in `next/`, where a save
    /// writes them before it commits the metadata: a save that stopped after the commit and
    /// before `cert.pem`/`key.pem` were replaced still loads, and one that stopped before the
    /// commit leaves the previous certificate loading.
    pub async fn read_cert(
        &self,
        first_name: &str,
    ) -> Result<(u64, Option<StoredCert>), StorageError> {
        let dir = cert_dir(first_name);
        let meta_key = format!("{dir}/meta.json");
        let Some(meta_entry) = self.store.get(&meta_key).await? else {
            return Ok((0, None));
        };
        let version = meta_entry.version;
        let meta: CertMeta = match serde_json::from_slice(&meta_entry.value) {
            Ok(meta) => meta,
            Err(e) => {
                tracing::warn!(key = %meta_key, error = %e, "ignoring unreadable certificate metadata; the next renewal replaces it");
                return Ok((version, None));
            }
        };
        let mut places = vec![dir.clone()];
        // Files of earlier versions name no chain: only `cert.pem` can be meant.
        if meta.chain_sha256.is_some() {
            places.push(format!("{dir}/next"));
        }
        for place in places {
            let (cert_key, key_key) = (format!("{place}/cert.pem"), format!("{place}/key.pem"));
            let (Some(chain), Some(key)) = (
                self.store.get(&cert_key).await?,
                self.store.get(&key_key).await?,
            ) else {
                continue;
            };
            if meta
                .chain_sha256
                .as_ref()
                .is_some_and(|expected| *expected != sha256_hex(&chain.value))
            {
                continue;
            }
            // A key that does not match the chain (a save stopped between the two) is skipped.
            if let Ok(cert) = rdock_tls::certificate_from_pem(
                first_name,
                &chain.value,
                &key.value,
                Path::new(&cert_key),
            ) {
                return Ok((
                    version,
                    Some(StoredCert {
                        cert,
                        meta,
                        version,
                    }),
                ));
            }
        }
        Ok((version, None))
    }

    /// The version of the stored metadata of `first_name` (`0` when there is none): a cheap
    /// check whether another instance stored a new certificate.
    pub async fn meta_version(&self, first_name: &str) -> Result<u64, StorageError> {
        let key = format!("{}/meta.json", cert_dir(first_name));
        Ok(self.store.get(&key).await?.map_or(0, |e| e.version))
    }

    /// Stores a certificate chain (PEM, leaf first), its key (PEM) and metadata, while `fence`
    /// is the current lease on the name. `meta_version` is the raw version of `meta.json` read
    /// under that lease ([`Storage::read_cert`]; `0`: none), whatever it describes.
    ///
    /// The chain and key are written to `next/` first, then the metadata is written with
    /// compare-and-swap against `meta_version`: that is the commit. Only then are `cert.pem`
    /// and `key.pem` replaced and `next/` removed. A save that fails before the commit leaves
    /// the previous certificate in place and loading; one that fails after it leaves the new
    /// one loading from `next/` ([`Storage::read_cert`]). Two writers cannot both commit.
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
        for (name, value) in [("cert.pem", chain_pem), ("key.pem", key_pem)] {
            self.store
                .put(
                    &format!("{dir}/next/{name}"),
                    value.as_bytes().to_vec(),
                    Expect::Any,
                    fence,
                )
                .await?;
        }
        let meta_key = format!("{dir}/meta.json");
        let json = serde_json::to_vec_pretty(&meta).map_err(|e| corrupt(&meta_key, &e))?;
        let expect = if meta_version == 0 {
            Expect::Absent
        } else {
            Expect::Version(meta_version)
        };
        let version = self.store.put(&meta_key, json, expect, fence).await?;
        // Committed. What follows only tidies up: the certificate loads from `next/` until it
        // is done, and the next save starts over.
        for (name, value) in [("key.pem", key_pem), ("cert.pem", chain_pem)] {
            if let Err(e) = self
                .store
                .put(
                    &format!("{dir}/{name}"),
                    value.as_bytes().to_vec(),
                    Expect::Any,
                    fence,
                )
                .await
            {
                tracing::warn!(certificate = %first_name, error = %e, "the certificate is stored; it is read from next/ until its files are moved into place");
                return Ok(version);
            }
        }
        for name in ["cert.pem", "key.pem"] {
            let _ = self
                .store
                .delete(&format!("{dir}/next/{name}"), Expect::Any, fence)
                .await;
        }
        Ok(version)
    }

    /// Replaces the metadata of `first_name` when it still has `version`, while `fence` (the
    /// certificate's lease) holds; returns the new version.
    pub async fn save_meta(
        &self,
        first_name: &str,
        meta: &CertMeta,
        version: u64,
        fence: Option<&Lease>,
    ) -> Result<u64, StorageError> {
        let key = format!("{}/meta.json", cert_dir(first_name));
        let json = serde_json::to_vec_pretty(meta).map_err(|e| corrupt(&key, &e))?;
        Ok(self
            .store
            .put(&key, json, Expect::Version(version), fence)
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
    let written = options.open(&tmp).and_then(|mut file| {
        file.write_all(bytes)?;
        file.sync_all()
    });
    if let Err(err) = written.and_then(|()| fs::rename(&tmp, path)) {
        // A full disk leaves no half-written temporary file behind.
        let _ = fs::remove_file(&tmp);
        return Err(err);
    }
    Ok(())
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
        // A second writer that read no certificate loses.
        assert!(matches!(
            storage
                .save_cert("app.example.com", &chain, &key, &meta, 0, None)
                .await,
            Err(StorageError::Store(StoreError::Conflict { .. }))
        ));
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

    fn meta(names: &[&str]) -> CertMeta {
        CertMeta {
            names: names.iter().map(|n| (*n).to_owned()).collect(),
            directory: "https://ca.test/dir".into(),
            ..CertMeta::default()
        }
    }

    fn leaf(stored: &StoredCert) -> Vec<u8> {
        stored.cert.key.cert[0].as_ref().to_vec()
    }

    fn der(chain: &str) -> Vec<u8> {
        use rustls_pki_types::pem::PemObject;
        rustls_pki_types::CertificateDer::from_pem_slice(chain.as_bytes())
            .unwrap()
            .as_ref()
            .to_vec()
    }

    /// A store that refuses writes to keys ending in `fail_on` (a holder that lost its lease
    /// or crashed at that point).
    #[derive(Debug)]
    struct Failing {
        inner: rdock_cluster::MemoryStore,
        fail_on: std::sync::Mutex<Option<String>>,
    }

    #[async_trait::async_trait]
    impl ClusterStore for Failing {
        async fn get(&self, key: &str) -> Result<Option<rdock_cluster::Entry>, StoreError> {
            self.inner.get(key).await
        }
        async fn put(
            &self,
            key: &str,
            value: Vec<u8>,
            expect: Expect,
            fence: Option<&Lease>,
        ) -> Result<u64, StoreError> {
            let fail = self.fail_on.lock().unwrap().clone();
            if fail.is_some_and(|f| key.ends_with(&f)) {
                return Err(StoreError::Fenced {
                    lease: "cert/x".into(),
                    token: 1,
                });
            }
            self.inner.put(key, value, expect, fence).await
        }
        async fn delete(
            &self,
            key: &str,
            expect: Expect,
            fence: Option<&Lease>,
        ) -> Result<(), StoreError> {
            self.inner.delete(key, expect, fence).await
        }
        async fn list(&self, prefix: &str) -> Result<Vec<String>, StoreError> {
            self.inner.list(prefix).await
        }
        async fn acquire(
            &self,
            name: &str,
            holder: &str,
            ttl: Duration,
        ) -> Result<Option<Lease>, StoreError> {
            self.inner.acquire(name, holder, ttl).await
        }
        async fn renew(&self, lease: &Lease, ttl: Duration) -> Result<Lease, StoreError> {
            self.inner.renew(lease, ttl).await
        }
        async fn release(&self, lease: &Lease) -> Result<(), StoreError> {
            self.inner.release(lease).await
        }
        async fn lease(&self, name: &str) -> Result<Option<Lease>, StoreError> {
            self.inner.lease(name).await
        }
        fn fencing(&self) -> rdock_cluster::Fencing {
            rdock_cluster::Fencing::Enforced
        }
    }

    /// Review finding H1: a `meta.json` that describes other names (the name list changed
    /// with the same first name, or two requests shared a first name), or a chain that is
    /// stored nowhere (a holder stopped midway with the layout of the first v0.9 code), never
    /// blocks the next save.
    #[tokio::test]
    async fn a_stale_or_mismatching_meta_never_blocks_a_save() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new(dir.path());
        let (chain, key) = crate::testing::self_signed("a.example");
        storage
            .save_cert("a.example", &chain, &key, &meta(&["a.example"]), 0, None)
            .await
            .unwrap();
        // The name list grows; the first name stays.
        let (raw, stored) = storage.read_cert("a.example").await.unwrap();
        assert_eq!(stored.unwrap().meta.names, ["a.example"]);
        let (chain2, key2) = crate::testing::self_signed("a.example");
        let both = meta(&["a.example", "b.example"]);
        storage
            .save_cert("a.example", &chain2, &key2, &both, raw, None)
            .await
            .unwrap();
        let stored = storage.load_cert("a.example").await.unwrap().unwrap();
        assert_eq!(stored.meta.names, ["a.example", "b.example"]);
        assert_eq!(leaf(&stored), der(&chain2));
        // The stuck state of the first v0.9 code: `cert.pem` and `key.pem` replaced, the old
        // `meta.json` left. Nothing loads, and the next save succeeds against the raw version.
        let (chain3, key3) = crate::testing::self_signed("a.example");
        let path = dir.path().join("certs/a.example");
        fs::write(path.join("cert.pem"), &chain3).unwrap();
        fs::write(path.join("key.pem"), &key3).unwrap();
        let (raw, stored) = storage.read_cert("a.example").await.unwrap();
        assert!(stored.is_none());
        assert_ne!(raw, 0);
        storage
            .save_cert("a.example", &chain3, &key3, &both, raw, None)
            .await
            .unwrap();
        assert_eq!(
            leaf(&storage.load_cert("a.example").await.unwrap().unwrap()),
            der(&chain3)
        );
        // An unreadable `meta.json` does not block either.
        fs::write(path.join("meta.json"), b"{ not json").unwrap();
        let (raw, stored) = storage.read_cert("a.example").await.unwrap();
        assert!(stored.is_none());
        storage
            .save_cert("a.example", &chain, &key, &both, raw, None)
            .await
            .unwrap();
        assert!(storage.load_cert("a.example").await.unwrap().is_some());
        // Nothing of the save is left in `next/`.
        assert!(!path.join("next").join("cert.pem").exists());
    }

    /// A save that stops at any point leaves either the previous or the new certificate
    /// loading, never a new chain with an old key, and the next save goes through.
    #[tokio::test]
    async fn a_save_that_stops_midway_leaves_a_certificate_that_loads() {
        let store = Arc::new(Failing {
            inner: rdock_cluster::MemoryStore::new(),
            fail_on: std::sync::Mutex::new(None),
        });
        let storage = Storage::cluster(store.clone());
        let (old_chain, old_key) = crate::testing::self_signed("a.example");
        let v1 = storage
            .save_cert(
                "a.example",
                &old_chain,
                &old_key,
                &meta(&["a.example"]),
                0,
                None,
            )
            .await
            .unwrap();
        let (new_chain, new_key) = crate::testing::self_signed("a.example");
        // Stopped before the commit (at the key in `next/`, or at the metadata): the previous
        // certificate still loads.
        for point in ["next/key.pem", "meta.json"] {
            *store.fail_on.lock().unwrap() = Some(point.to_owned());
            assert!(
                storage
                    .save_cert(
                        "a.example",
                        &new_chain,
                        &new_key,
                        &meta(&["a.example"]),
                        v1,
                        None
                    )
                    .await
                    .is_err()
            );
            let stored = storage.load_cert("a.example").await.unwrap().unwrap();
            assert_eq!(leaf(&stored), der(&old_chain), "stopped at {point}");
            assert_eq!(stored.version, v1);
        }
        // Stopped after the commit, with `key.pem` replaced and `cert.pem` not: the new
        // certificate loads from `next/` (its key matches; the old chain is not paired with it).
        *store.fail_on.lock().unwrap() = Some("a.example/cert.pem".to_owned());
        let v2 = storage
            .save_cert(
                "a.example",
                &new_chain,
                &new_key,
                &meta(&["a.example"]),
                v1,
                None,
            )
            .await
            .unwrap();
        let stored = storage.load_cert("a.example").await.unwrap().unwrap();
        assert_eq!(leaf(&stored), der(&new_chain));
        assert_eq!(stored.version, v2);
        // And the next save goes through against that version.
        *store.fail_on.lock().unwrap() = None;
        let (third, third_key) = crate::testing::self_signed("a.example");
        storage
            .save_cert(
                "a.example",
                &third,
                &third_key,
                &meta(&["a.example"]),
                v2,
                None,
            )
            .await
            .unwrap();
        assert_eq!(
            leaf(&storage.load_cert("a.example").await.unwrap().unwrap()),
            der(&third)
        );
        assert!(
            store
                .inner
                .get("certs/a.example/next/cert.pem")
                .await
                .unwrap()
                .is_none()
        );
    }

    /// A data directory written by 0.8 (no `chain_sha256`, no `next/`) loads, and its
    /// certificate is replaced at the next renewal.
    #[tokio::test]
    async fn a_pre_0_9_directory_loads_and_renews() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("certs/app.example.com");
        fs::create_dir_all(&path).unwrap();
        let (chain, key) = crate::testing::self_signed("app.example.com");
        fs::write(path.join("cert.pem"), &chain).unwrap();
        fs::write(path.join("key.pem"), &key).unwrap();
        // Exactly the fields 0.8 wrote.
        fs::write(
            path.join("meta.json"),
            br#"{ "names": ["app.example.com"], "directory": "https://ca.test/dir", "profile": null }"#,
        )
        .unwrap();
        let storage = Storage::new(dir.path());
        let (raw, stored) = storage.read_cert("app.example.com").await.unwrap();
        let stored = stored.unwrap();
        assert_eq!(stored.meta.names, ["app.example.com"]);
        assert_eq!(stored.meta.chain_sha256, None);
        assert_eq!(leaf(&stored), der(&chain));
        let (renewed, renewed_key) = crate::testing::self_signed("app.example.com");
        storage
            .save_cert(
                "app.example.com",
                &renewed,
                &renewed_key,
                &meta(&["app.example.com"]),
                raw,
                None,
            )
            .await
            .unwrap();
        let stored = storage.load_cert("app.example.com").await.unwrap().unwrap();
        assert_eq!(leaf(&stored), der(&renewed));
        // The layout stays the one 0.8 reads.
        assert_eq!(fs::read_to_string(path.join("cert.pem")).unwrap(), renewed);
        assert_eq!(
            fs::read_to_string(path.join("key.pem")).unwrap(),
            renewed_key
        );
        assert!(!path.join("next").exists());
    }
}
