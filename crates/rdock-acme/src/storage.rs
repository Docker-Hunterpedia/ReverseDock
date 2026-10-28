//! Accounts and certificates on disk (ADR-0020):
//!
//! ```text
//! <root>/lock
//! <root>/accounts/<directory>/account.json
//! <root>/certs/<first name>/{cert.pem,key.pem,meta.json}
//! ```
//!
//! Files are written with mode 0600 into a temporary file and renamed, so a crash never leaves
//! half a certificate.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use instant_acme::AccountCredentials;
use rdock_tls::LoadedCert;
use serde::{Deserialize, Serialize};

/// A lock older than this is left over from a process that died.
const STALE_LOCK: Duration = Duration::from_secs(30);

/// What is stored next to a certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertMeta {
    /// Names on the certificate.
    pub names: Vec<String>,
    /// Directory URL of the issuing CA.
    pub directory: String,
    /// Profile asked for, if any.
    #[serde(default)]
    pub profile: Option<String>,
}

/// The storage directory.
#[derive(Debug, Clone)]
pub struct Storage {
    root: PathBuf,
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

impl Storage {
    /// Storage under `root`.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Takes the lock that keeps two processes sharing this directory from ordering the same
    /// certificates. Returns `None` while another live process holds it.
    pub fn lock(&self) -> io::Result<Option<StorageLock>> {
        create_dir(&self.root)?;
        let path = self.root.join("lock");
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

    /// The stored account for `directory`, if any.
    pub fn load_account(&self, directory: &str) -> io::Result<Option<AccountCredentials>> {
        match fs::read(self.account_path(directory)) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(io::Error::other),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Stores the account for `directory`.
    pub fn save_account(&self, directory: &str, account: &AccountCredentials) -> io::Result<()> {
        let json = serde_json::to_vec_pretty(account).map_err(io::Error::other)?;
        write_private(&self.account_path(directory), &json)
    }

    /// The stored certificate named after `first_name`, if present and readable.
    pub fn load_cert(&self, first_name: &str) -> io::Result<Option<(LoadedCert, CertMeta)>> {
        let dir = self.cert_dir(first_name);
        let meta = match fs::read(dir.join("meta.json")) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(io::Error::other)?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let cert = rdock_tls::load_certificate(
            first_name,
            &dir.join("cert.pem"),
            &dir.join("key.pem"),
            None,
        )
        .map_err(io::Error::other)?;
        Ok(Some((cert, meta)))
    }

    /// Stores a certificate chain (PEM, leaf first), its key (PEM) and metadata. The metadata is
    /// written last, so a certificate is only loaded once all three files are complete.
    pub fn save_cert(
        &self,
        first_name: &str,
        chain_pem: &str,
        key_pem: &str,
        meta: &CertMeta,
    ) -> io::Result<()> {
        let dir = self.cert_dir(first_name);
        write_private(&dir.join("cert.pem"), chain_pem.as_bytes())?;
        write_private(&dir.join("key.pem"), key_pem.as_bytes())?;
        let json = serde_json::to_vec_pretty(meta).map_err(io::Error::other)?;
        write_private(&dir.join("meta.json"), &json)
    }

    fn account_path(&self, directory: &str) -> PathBuf {
        let name = directory
            .trim_start_matches("https://")
            .trim_end_matches('/');
        self.root
            .join("accounts")
            .join(file_name(name))
            .join("account.json")
    }

    fn cert_dir(&self, first_name: &str) -> PathBuf {
        self.root.join("certs").join(file_name(first_name))
    }
}

/// A file name for a host name, IP address or URL: `*` becomes `_`, other characters outside
/// `[A-Za-z0-9.-]` become `-`.
fn file_name(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '*' => '_',
            c if c.is_ascii_alphanumeric() || c == '.' || c == '-' => c,
            _ => '-',
        })
        .collect()
}

fn create_dir(dir: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(dir)
}

/// Writes `bytes` to `path` readable only by the owner, replacing the file atomically.
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
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
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_files_safely() {
        assert_eq!(file_name("*.example.com"), "_.example.com");
        assert_eq!(file_name("2001:db8::1"), "2001-db8--1");
        assert_eq!(
            file_name("acme-v02.api.letsencrypt.org/directory"),
            "acme-v02.api.letsencrypt.org-directory"
        );
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
}
