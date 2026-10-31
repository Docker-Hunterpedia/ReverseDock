//! The single-use bootstrap token that creates the first admin (ADR-0024, ASVS 6.4.1). While
//! no admin exists, every start writes a new token to `$RDOCK_DATA_DIR/admin/bootstrap-token`
//! (mode 0600) and logs the file's path, never the value. It expires after 24 hours and is
//! deleted once the first admin is created.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use ring::digest::{SHA256, digest};
use ring::rand::{SecureRandom, SystemRandom};
use subtle::ConstantTimeEq;

const LIFETIME: Duration = Duration::from_secs(24 * 60 * 60);
const PREFIX: &str = "rdk_boot_";

struct Active {
    verifier: [u8; 32],
    expires: Instant,
}

/// The bootstrap token, if one is active. Only its SHA-256 is kept in memory.
pub struct Bootstrap {
    path: PathBuf,
    active: Mutex<Option<Active>>,
}

impl Bootstrap {
    fn path(dir: &Path) -> PathBuf {
        dir.join("bootstrap-token")
    }

    /// Writes a new token (160 random bits) to `<dir>/bootstrap-token`.
    pub fn issue(dir: &Path) -> io::Result<Self> {
        let mut secret = [0u8; 20];
        SystemRandom::new()
            .fill(&mut secret)
            .map_err(|_| io::Error::other("the system random generator failed"))?;
        let token = format!("{PREFIX}{}", hex(&secret));
        let path = Self::path(dir);
        rdock_config::state::write_atomic(&path, format!("{token}\n").as_bytes())?;
        Ok(Self {
            path,
            active: Mutex::new(Some(Active {
                verifier: verifier(&token),
                expires: Instant::now() + LIFETIME,
            })),
        })
    }

    /// No token: an admin exists. A token file left from an earlier start is removed.
    pub fn inactive(dir: &Path) -> io::Result<Self> {
        let path = Self::path(dir);
        remove(&path)?;
        Ok(Self {
            path,
            active: Mutex::new(None),
        })
    }

    /// Where the token is written.
    #[must_use]
    pub fn file(&self) -> &Path {
        &self.path
    }

    /// Whether `presented` is the active, unexpired token.
    pub fn accepts(&self, presented: &str) -> bool {
        let active = self.active.lock().unwrap_or_else(PoisonError::into_inner);
        active.as_ref().is_some_and(|a| {
            Instant::now() < a.expires
                && presented.starts_with(PREFIX)
                && bool::from(verifier(presented).ct_eq(&a.verifier))
        })
    }

    /// Ends the token after the first admin was created, and deletes its file.
    pub fn consume(&self) -> io::Result<()> {
        self.active
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        remove(&self.path)
    }
}

fn verifier(token: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(digest(&SHA256, token.as_bytes()).as_ref());
    out
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

fn remove(path: &Path) -> io::Result<()> {
    match std::fs::remove_file(path) {
        Err(err) if err.kind() != io::ErrorKind::NotFound => Err(err),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_token_is_private_single_use_and_checked_in_full() {
        let dir = tempfile::tempdir().unwrap();
        let bootstrap = Bootstrap::issue(dir.path()).unwrap();
        let token = std::fs::read_to_string(bootstrap.file()).unwrap();
        let token = token.trim();
        assert_eq!(token.len(), PREFIX.len() + 40);
        let mode = std::os::unix::fs::PermissionsExt::mode(
            &std::fs::metadata(bootstrap.file()).unwrap().permissions(),
        );
        assert_eq!(mode & 0o777, 0o600);

        assert!(bootstrap.accepts(token));
        assert!(!bootstrap.accepts(&token[..token.len() - 1]));
        assert!(!bootstrap.accepts(""));
        bootstrap.consume().unwrap();
        assert!(!bootstrap.accepts(token));
        assert!(!bootstrap.file().exists());
    }

    #[test]
    fn an_expired_token_is_refused_and_a_stale_file_removed() {
        let dir = tempfile::tempdir().unwrap();
        let bootstrap = Bootstrap::issue(dir.path()).unwrap();
        let token = std::fs::read_to_string(bootstrap.file()).unwrap();
        if let Some(active) = bootstrap.active.lock().unwrap().as_mut() {
            active.expires = Instant::now();
        }
        assert!(!bootstrap.accepts(token.trim()));

        let inactive = Bootstrap::inactive(dir.path()).unwrap();
        assert!(!inactive.file().exists());
        assert!(!inactive.accepts(token.trim()));
    }
}
