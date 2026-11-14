//! A store in a directory.
//!
//! **Shared** (several instances mount the directory: NFS, EFS, a Docker volume): best effort.
//! Each operation on a key holds a lock file `.locks/<key>` created with `O_EXCL` for its few
//! milliseconds (removed by others after 10 s, when its holder died). Leases are files
//! `.leases/<name>` holding the holder, the token and the expiry written by the holder's clock
//! and judged by the reader's clock, so instances whose clocks disagree by more than the margin
//! between a lease's renewal and its expiry can both believe they hold it. A fenced write checks
//! the lease file before it writes, which does not stop a writer paused between the check and
//! the write. Caddy's certmagic documents the same limits for its file storage.
//!
//! **Exclusive** (one process owns the directory: the control plane's store and a single
//! instance's ACME storage): every operation also takes one in-process lock and every lease is
//! judged by that process's clock, so fencing is enforced.
//!
//! Values are files at `<root>/<key>`, written into a temporary file with mode 0600 and renamed,
//! so a reader never sees half a value. The layout of the ACME storage (`accounts/…`,
//! `certs/<name>/{cert.pem,key.pem,meta.json}`) is unchanged by this backend. Versions are
//! derived from the content ([`content_version`]).

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use async_trait::async_trait;

use crate::clock::{Clock, SystemClock, deadline};
use crate::store::{
    ClusterStore, Entry, Expect, Fencing, Lease, StoreError, check_key, content_version,
};

/// A key lock older than this was left by a process that died mid-operation.
const STALE_KEY_LOCK: Duration = Duration::from_secs(10);
/// How long an operation waits for a key lock.
const KEY_LOCK_WAIT: Duration = Duration::from_secs(10);

/// A store in a directory.
#[derive(Debug, Clone)]
pub struct DirStore {
    root: PathBuf,
    clock: Arc<dyn Clock>,
    /// Set when one process owns the directory.
    exclusive: Option<Arc<tokio::sync::Mutex<()>>>,
}

impl DirStore {
    /// A store in a directory several instances share (best effort, see the module
    /// documentation).
    #[must_use]
    pub fn shared(root: impl Into<PathBuf>) -> Self {
        Self::shared_with_clock(root, Arc::new(SystemClock))
    }

    /// A shared store judging leases by `clock` (tests give instances skewed clocks).
    #[must_use]
    pub fn shared_with_clock(root: impl Into<PathBuf>, clock: Arc<dyn Clock>) -> Self {
        Self {
            root: root.into(),
            clock,
            exclusive: None,
        }
    }

    /// A store in a directory only this process uses (fencing enforced).
    #[must_use]
    pub fn exclusive(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            clock: Arc::new(SystemClock),
            exclusive: Some(Arc::new(tokio::sync::Mutex::new(()))),
        }
    }

    /// The directory.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Runs `op` on a blocking thread, under the in-process lock when exclusive.
    async fn run<T: Send + 'static>(
        &self,
        op: impl FnOnce(&Paths) -> Result<T, StoreError> + Send + 'static,
    ) -> Result<T, StoreError> {
        let _guard = match &self.exclusive {
            Some(lock) => Some(lock.clone().lock_owned().await),
            None => None,
        };
        self.read_only(op).await
    }

    /// Runs `op` on a blocking thread without the in-process lock: for reads, which see
    /// either the old or the new file of a value (values are replaced by rename), so a long
    /// listing never holds up writes (review finding M3).
    async fn read_only<T: Send + 'static>(
        &self,
        op: impl FnOnce(&Paths) -> Result<T, StoreError> + Send + 'static,
    ) -> Result<T, StoreError> {
        let paths = Paths {
            root: self.root.clone(),
            clock: self.clock.clone(),
        };
        tokio::task::spawn_blocking(move || op(&paths))
            .await
            .map_err(|e| StoreError::Backend(format!("store task failed: {e}")))?
    }
}

/// What a blocking operation needs.
struct Paths {
    root: PathBuf,
    clock: Arc<dyn Clock>,
}

impl Paths {
    fn value(&self, key: &str) -> PathBuf {
        self.root.join(key)
    }

    fn lease(&self, name: &str) -> PathBuf {
        self.root.join(".leases").join(name)
    }

    /// Holds the lock file of `key` (a value key, or `.leases/<name>`) until dropped.
    fn lock(&self, key: &str) -> Result<KeyLock, StoreError> {
        let locks = self.root.join(".locks");
        let path = locks.join(key);
        let started = Instant::now();
        loop {
            if let Some(parent) = path.parent() {
                create_dir_racing(parent)?;
            }
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(_) => {
                    return Ok(KeyLock { path, stop: locks });
                }
                // Another operation removed the emptied directory meanwhile: make it again.
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    let stale = fs::metadata(&path)
                        .and_then(|m| m.modified())
                        .ok()
                        .and_then(|m| SystemTime::now().duration_since(m).ok())
                        .is_some_and(|age| age > STALE_KEY_LOCK);
                    if stale {
                        let _ = fs::remove_file(&path);
                        continue;
                    }
                    if started.elapsed() > KEY_LOCK_WAIT {
                        return Err(StoreError::Unavailable(format!(
                            "the lock file {} stays taken",
                            path.display()
                        )));
                    }
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    fn read(&self, key: &str) -> Result<Option<Entry>, StoreError> {
        match fs::read(self.value(key)) {
            Ok(value) => {
                let version = content_version(&value);
                Ok(Some(Entry { value, version }))
            }
            Err(e)
                if e.kind() == io::ErrorKind::NotFound
                    || e.kind() == io::ErrorKind::IsADirectory
                    || e.kind() == io::ErrorKind::NotADirectory =>
            {
                Ok(None)
            }
            Err(e) => Err(e.into()),
        }
    }

    fn read_lease(&self, name: &str) -> Result<Option<Lease>, StoreError> {
        match fs::read(self.lease(name)) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|e| StoreError::Backend(format!("lease `{name}`: {e}"))),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn write_lease(&self, lease: &Lease) -> Result<(), StoreError> {
        let json = serde_json::to_vec(lease).map_err(|e| StoreError::Backend(e.to_string()))?;
        write_private(&self.lease(&lease.name), &json)?;
        Ok(())
    }

    fn check_fence(&self, fence: Option<&Lease>) -> Result<(), StoreError> {
        let Some(fence) = fence else { return Ok(()) };
        let now = self.clock.now_ms();
        match self.read_lease(&fence.name)? {
            Some(current)
                if current.token == fence.token
                    && current.holder == fence.holder
                    && current.expires_at_ms > now =>
            {
                Ok(())
            }
            _ => Err(StoreError::Fenced {
                lease: fence.name.clone(),
                token: fence.token,
            }),
        }
    }

    fn check_expect(&self, key: &str, expect: Expect) -> Result<(), StoreError> {
        let current = self.read(key)?.map_or(0, |e| e.version);
        let ok = match expect {
            Expect::Any => true,
            Expect::Absent => current == 0,
            Expect::Version(v) => current == v,
        };
        if ok {
            Ok(())
        } else {
            Err(StoreError::Conflict {
                key: key.to_owned(),
                current,
            })
        }
    }
}

/// Removes its lock file, and the directories that leaves empty, when dropped.
struct KeyLock {
    path: PathBuf,
    stop: PathBuf,
}

impl Drop for KeyLock {
    fn drop(&mut self) {
        if fs::remove_file(&self.path).is_ok()
            && let Some(parent) = self.path.parent()
        {
            remove_empty_dirs(parent, &self.stop);
        }
    }
}

/// Removes `dir` and its parents while they are empty, up to (not including) `stop`. A
/// directory another writer has just filled again stays (review finding M3: without this, one
/// directory per limit window or challenge was left behind for ever).
fn remove_empty_dirs(dir: &Path, stop: &Path) {
    let mut current = dir;
    while current != stop && current.starts_with(stop) {
        if fs::remove_dir(current).is_err() {
            return;
        }
        match current.parent() {
            Some(parent) => current = parent,
            None => return,
        }
    }
}

#[async_trait]
impl ClusterStore for DirStore {
    async fn get(&self, key: &str) -> Result<Option<Entry>, StoreError> {
        check_key(key, false)?;
        let key = key.to_owned();
        self.read_only(move |p| p.read(&key)).await
    }

    async fn put(
        &self,
        key: &str,
        value: Vec<u8>,
        expect: Expect,
        fence: Option<&Lease>,
    ) -> Result<u64, StoreError> {
        check_key(key, false)?;
        let (key, fence) = (key.to_owned(), fence.cloned());
        self.run(move |p| {
            let _lock = p.lock(&key)?;
            p.check_fence(fence.as_ref())?;
            p.check_expect(&key, expect)?;
            write_private(&p.value(&key), &value)?;
            Ok(content_version(&value))
        })
        .await
    }

    async fn delete(
        &self,
        key: &str,
        expect: Expect,
        fence: Option<&Lease>,
    ) -> Result<(), StoreError> {
        check_key(key, false)?;
        let (key, fence) = (key.to_owned(), fence.cloned());
        self.run(move |p| {
            let _lock = p.lock(&key)?;
            p.check_fence(fence.as_ref())?;
            p.check_expect(&key, expect)?;
            let path = p.value(&key);
            match fs::remove_file(&path) {
                Ok(()) => {
                    if let Some(parent) = path.parent() {
                        remove_empty_dirs(parent, &p.root);
                    }
                    Ok(())
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(e.into()),
            }
        })
        .await
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>, StoreError> {
        check_key(prefix, true)?;
        let prefix = prefix.to_owned();
        self.read_only(move |p| {
            let mut keys = Vec::new();
            let start = if prefix.is_empty() {
                p.root.clone()
            } else {
                p.value(&prefix)
            };
            walk(&start, &prefix, &mut keys)?;
            keys.sort();
            Ok(keys)
        })
        .await
    }

    async fn acquire(
        &self,
        name: &str,
        holder: &str,
        ttl: Duration,
    ) -> Result<Option<Lease>, StoreError> {
        check_key(name, false)?;
        let (name, holder) = (name.to_owned(), holder.to_owned());
        self.run(move |p| {
            let _lock = p.lock(&format!(".leases/{name}"))?;
            let now = p.clock.now_ms();
            let token = match p.read_lease(&name)? {
                Some(current) if current.expires_at_ms > now && current.holder != holder => {
                    return Ok(None);
                }
                Some(current) if current.expires_at_ms > now => current.token,
                Some(current) => current.token + 1,
                None => 1,
            };
            let lease = Lease {
                name,
                holder,
                token,
                expires_at_ms: deadline(now, ttl),
            };
            p.write_lease(&lease)?;
            Ok(Some(lease))
        })
        .await
    }

    async fn renew(&self, lease: &Lease, ttl: Duration) -> Result<Lease, StoreError> {
        let lease = lease.clone();
        self.run(move |p| {
            let _lock = p.lock(&format!(".leases/{}", lease.name))?;
            let now = p.clock.now_ms();
            match p.read_lease(&lease.name)? {
                Some(current)
                    if current.token == lease.token
                        && current.holder == lease.holder
                        && current.expires_at_ms > now =>
                {
                    let renewed = Lease {
                        expires_at_ms: deadline(now, ttl),
                        ..current
                    };
                    p.write_lease(&renewed)?;
                    Ok(renewed)
                }
                _ => Err(StoreError::Lost(lease.name.clone())),
            }
        })
        .await
    }

    async fn release(&self, lease: &Lease) -> Result<(), StoreError> {
        let lease = lease.clone();
        self.run(move |p| {
            let _lock = p.lock(&format!(".leases/{}", lease.name))?;
            if let Some(current) = p.read_lease(&lease.name)?
                && current.token == lease.token
                && current.holder == lease.holder
            {
                // Kept, expired, so the next holder's token is larger.
                p.write_lease(&Lease {
                    expires_at_ms: 0,
                    ..current
                })?;
            }
            Ok(())
        })
        .await
    }

    async fn lease(&self, name: &str) -> Result<Option<Lease>, StoreError> {
        check_key(name, false)?;
        let name = name.to_owned();
        self.read_only(move |p| p.read_lease(&name)).await
    }

    fn fencing(&self) -> Fencing {
        if self.exclusive.is_some() {
            Fencing::Enforced
        } else {
            Fencing::BestEffort
        }
    }
}

/// Collects the keys of the files below `dir` (whose key is `prefix`), skipping names that
/// start with `.` and anything that is not a valid key.
fn walk(dir: &Path, prefix: &str, out: &mut Vec<String>) -> Result<(), StoreError> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e)
            if e.kind() == io::ErrorKind::NotFound || e.kind() == io::ErrorKind::NotADirectory =>
        {
            if !prefix.is_empty() && dir.is_file() {
                out.push(prefix.to_owned());
            }
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };
    for entry in entries {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if name.starts_with('.') || check_key(&name, false).is_err() {
            continue;
        }
        let key = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        let kind = entry.file_type()?;
        if kind.is_dir() {
            walk(&entry.path(), &key, out)?;
        } else if kind.is_file() {
            out.push(key);
        }
    }
    Ok(())
}

/// [`create_dir`] while other operations may remove emptied directories at the same time
/// ([`remove_empty_dirs`]): a step that loses that race is tried again.
fn create_dir_racing(dir: &Path) -> io::Result<()> {
    let mut attempts = 0;
    loop {
        attempts += 1;
        match create_dir(dir) {
            Err(e)
                if attempts < 20
                    && matches!(
                        e.kind(),
                        io::ErrorKind::NotFound | io::ErrorKind::AlreadyExists
                    ) => {}
            other => return other,
        }
    }
}

/// Creates `dir` and its parents, readable only by the owner.
pub fn create_dir(dir: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(dir)
}

/// Writes `bytes` to `path` readable only by the owner: a temporary file beside it (its name
/// starts with `.`, so listings skip it), synced, then renamed over `path`.
pub fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| io::Error::other("path has no parent directory"))?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| io::Error::other("path has no file name"))?;
    let tmp = dir.join(format!(".{name}.{}.tmp", std::process::id()));
    let mut attempts = 0;
    loop {
        attempts += 1;
        let result = (|| {
            create_dir_racing(dir)?;
            let mut options = OpenOptions::new();
            options.write(true).create(true).truncate(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
            let mut file = options.open(&tmp)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&tmp, path)
        })();
        match result {
            // A delete elsewhere removed the directory once it was empty: make it again.
            Err(e) if e.kind() == io::ErrorKind::NotFound && attempts < 5 => {}
            Err(e) => {
                // A full disk leaves no half-written temporary file behind (ADR-0033).
                let _ = fs::remove_file(&tmp);
                return Err(e);
            }
            Ok(()) => return Ok(()),
        }
    }
}
