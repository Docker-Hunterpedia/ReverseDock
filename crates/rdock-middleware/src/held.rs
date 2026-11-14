//! Held request bodies (ADR-0030, "Pipeline and body phase"): the one shared holder that
//! collects a body for the `request_body` phase. Up to [`MEMORY_LIMIT`] it stays in memory;
//! beyond that it goes to a spool file under `<data dir>/spool/`, opened through cap-std,
//! created `0600` and unlinked at once, so the kernel frees it when the request ends (or the
//! process dies). [`Spool::open`] empties the directory at start.

use std::io;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, OpenOptions};
use tokio::io::AsyncWriteExt;

use crate::phase::BodyHold;

/// Bytes of a held body kept in memory; the rest goes to a spool file. The same size as
/// Pingora's request replay buffer (`BODY_BUF_LIMIT`).
pub const MEMORY_LIMIT: usize = 64 * 1024;

/// A body that cannot be spooled (the disk is full) is held in memory up to this size; a
/// longer one is refused (`500`, as any spool failure) rather than risk the process's memory.
pub const SPOOL_FALLBACK: u64 = 1024 * 1024;

/// The spool directory for held bodies.
#[derive(Debug)]
pub struct Spool {
    dir: Dir,
    next: AtomicU64,
    holders: AtomicU64,
}

impl Spool {
    /// Opens (creating it `0700` if needed) the spool directory at `path` and removes whatever
    /// an earlier run left in it.
    ///
    /// # Errors
    ///
    /// The directory cannot be created, opened or cleaned.
    pub fn open(path: &Path) -> io::Result<Self> {
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        builder.create(path)?;
        let spool = Self {
            dir: Dir::open_ambient_dir(path, ambient_authority())?,
            next: AtomicU64::new(0),
            holders: AtomicU64::new(0),
        };
        let removed = spool.clean()?;
        if removed > 0 {
            tracing::info!(removed, path = %path.display(), "removed leftover spool files");
        }
        Ok(spool)
    }

    /// Holders started with this spool so far, whether or not they spooled (for tests and
    /// metrics: a route that holds nothing never starts one).
    #[must_use]
    pub fn holders_started(&self) -> u64 {
        self.holders.load(Ordering::Relaxed)
    }

    /// Removes every entry of the directory; returns how many.
    fn clean(&self) -> io::Result<usize> {
        let mut removed = 0;
        for entry in self.dir.entries()? {
            let entry = entry?;
            let name = entry.file_name();
            if entry.file_type()?.is_dir() {
                self.dir.remove_dir_all(&name)?;
            } else {
                self.dir.remove_file(&name)?;
            }
            removed += 1;
        }
        Ok(removed)
    }

    /// A new, empty spool file: created `0600` with a unique name and unlinked at once.
    fn create(&self) -> io::Result<std::fs::File> {
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        cap_std::fs::OpenOptionsExt::mode(&mut options, 0o600);
        loop {
            let name = format!(
                "body-{}-{}",
                std::process::id(),
                self.next.fetch_add(1, Ordering::Relaxed)
            );
            match self.dir.open_with(&name, &options) {
                Ok(file) => {
                    self.dir.remove_file(&name)?;
                    return Ok(file.into_std());
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            }
        }
    }
}

/// Why a body could not be held.
#[derive(Debug, thiserror::Error)]
pub enum HoldError {
    /// The body is longer than the limit.
    #[error("request body too large to hold")]
    TooLarge,
    /// The body did not arrive within the hold's timeout.
    #[error("request body did not arrive in time")]
    TimedOut,
    /// The spool file failed.
    #[error("spooling the request body failed: {0}")]
    Io(#[from] io::Error),
}

/// Collects a request body chunk by chunk.
#[derive(Debug)]
pub struct BodyHolder {
    limit: u64,
    timeout: Duration,
    deadline: Option<Instant>,
    spool: Option<Arc<Spool>>,
    memory: BytesMut,
    file: Option<tokio::fs::File>,
    len: u64,
}

impl BodyHolder {
    /// A holder for `hold`, never holding more than `limit` bytes (the smaller of the hold's
    /// `max` and the route's `max_body`). Without a spool everything stays in memory.
    #[must_use]
    pub fn new(hold: BodyHold, limit: u64, spool: Option<Arc<Spool>>) -> Self {
        if let Some(spool) = &spool {
            spool.holders.fetch_add(1, Ordering::Relaxed);
        }
        Self {
            limit: limit.min(hold.max),
            timeout: hold.timeout,
            deadline: None,
            spool,
            memory: BytesMut::new(),
            file: None,
            len: 0,
        }
    }

    /// The most bytes this holder accepts.
    #[must_use]
    pub fn limit(&self) -> u64 {
        self.limit
    }

    /// Bytes held so far.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Whether nothing is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Whether the body went to a spool file.
    #[must_use]
    pub fn is_spooled(&self) -> bool {
        self.file.is_some()
    }

    /// Time left until the timeout; `None` before the first chunk.
    #[must_use]
    pub fn remaining(&self) -> Option<Duration> {
        self.deadline
            .map(|d| d.saturating_duration_since(Instant::now()))
    }

    /// Adds a chunk.
    ///
    /// # Errors
    ///
    /// The body grew beyond the limit, the timeout passed, or the spool file failed.
    pub async fn push(&mut self, chunk: &[u8]) -> Result<(), HoldError> {
        let now = Instant::now();
        let deadline = *self.deadline.get_or_insert(now + self.timeout);
        if now > deadline {
            return Err(HoldError::TimedOut);
        }
        if chunk.is_empty() {
            return Ok(());
        }
        self.len += chunk.len() as u64;
        if self.len > self.limit {
            return Err(HoldError::TooLarge);
        }
        if let Some(file) = self.file.as_mut() {
            if let Err(e) = file.write_all(chunk).await {
                // The disk refused the spool file (full): keep the body in memory instead,
                // up to `SPOOL_FALLBACK` (ADR-0033).
                self.back_to_memory(e, chunk.len()).await?;
                self.memory.extend_from_slice(chunk);
            }
            return Ok(());
        }
        let in_memory = self.memory.len() + chunk.len() <= MEMORY_LIMIT;
        match self.spool.clone().filter(|_| !in_memory) {
            Some(spool) => {
                let started = async {
                    let mut file = tokio::fs::File::from_std(spool.create()?);
                    file.write_all(&self.memory).await?;
                    file.write_all(chunk).await?;
                    Ok::<_, io::Error>(file)
                }
                .await;
                match started {
                    Ok(file) => {
                        self.memory = BytesMut::new();
                        self.file = Some(file);
                    }
                    Err(e) => {
                        self.memory_instead(e)?;
                        self.memory.extend_from_slice(chunk);
                    }
                }
            }
            None => self.memory.extend_from_slice(chunk),
        }
        Ok(())
    }

    /// Gives the spool up for this body after a write error: the body stays in memory while
    /// it is at most [`SPOOL_FALLBACK`] long, else the error stands.
    fn memory_instead(&mut self, e: io::Error) -> Result<(), HoldError> {
        if self.len > SPOOL_FALLBACK {
            return Err(HoldError::Io(e));
        }
        tracing::debug!(error = %e, "cannot spool a request body; holding it in memory");
        self.spool = None;
        Ok(())
    }

    /// [`Self::memory_instead`] for a body already partly in a spool file: what the file
    /// holds (all but the last `pending` bytes of `len`) is read back into memory.
    async fn back_to_memory(&mut self, e: io::Error, pending: usize) -> Result<(), HoldError> {
        use tokio::io::{AsyncReadExt, AsyncSeekExt};
        self.memory_instead(e)?;
        let Some(mut file) = self.file.take() else {
            return Ok(());
        };
        let written = usize::try_from(self.len).unwrap_or(usize::MAX) - pending;
        let mut held = vec![0; written];
        file.seek(std::io::SeekFrom::Start(0)).await?;
        file.read_exact(&mut held).await?;
        self.memory = BytesMut::from(&held[..]);
        Ok(())
    }

    /// Forgets what was held, for a retry that replays the body from its start.
    pub fn reset(&mut self) {
        self.memory.clear();
        self.file = None;
        self.len = 0;
    }

    /// The complete body.
    ///
    /// # Errors
    ///
    /// The spool file failed.
    pub async fn finish(self) -> Result<HeldBody, HoldError> {
        let len = self.len;
        Ok(match self.file {
            Some(mut file) => {
                file.flush().await?;
                HeldBody {
                    len,
                    data: Data::File(Arc::new(file.into_std().await)),
                    cached: tokio::sync::OnceCell::new(),
                }
            }
            None => HeldBody::from_bytes(self.memory.freeze()),
        })
    }
}

#[derive(Debug)]
enum Data {
    Memory(Bytes),
    File(Arc<std::fs::File>),
}

/// A complete request body held by the proxy, given to `request_body` middlewares.
#[derive(Debug)]
pub struct HeldBody {
    len: u64,
    data: Data,
    cached: tokio::sync::OnceCell<Bytes>,
}

impl HeldBody {
    /// A body in memory (also for tests and for replacements).
    #[must_use]
    pub fn from_bytes(bytes: Bytes) -> Self {
        Self {
            len: bytes.len() as u64,
            data: Data::Memory(bytes),
            cached: tokio::sync::OnceCell::new(),
        }
    }

    /// Length in bytes.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Whether the body is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Whether the body is in a spool file (it was longer than [`MEMORY_LIMIT`]).
    #[must_use]
    pub fn is_spooled(&self) -> bool {
        matches!(self.data, Data::File(_))
    }

    /// The whole body in memory. A spooled body is read once and kept for later calls; it is
    /// at most the hold's limit.
    ///
    /// # Errors
    ///
    /// Reading the spool file failed.
    pub async fn bytes(&self) -> io::Result<Bytes> {
        let file = match &self.data {
            Data::Memory(bytes) => return Ok(bytes.clone()),
            Data::File(file) => file.clone(),
        };
        let len = usize::try_from(self.len)
            .map_err(|_| io::Error::new(io::ErrorKind::OutOfMemory, "body too large"))?;
        self.cached
            .get_or_try_init(|| async move {
                tokio::task::spawn_blocking(move || read_all(&file, len))
                    .await
                    .map_err(io::Error::other)?
            })
            .await
            .cloned()
    }
}

#[cfg(unix)]
fn read_all(file: &std::fs::File, len: usize) -> io::Result<Bytes> {
    use std::os::unix::fs::FileExt;
    let mut buf = vec![0; len];
    file.read_exact_at(&mut buf, 0)?;
    Ok(Bytes::from(buf))
}

#[cfg(not(unix))]
fn read_all(file: &std::fs::File, len: usize) -> io::Result<Bytes> {
    use std::io::{Read, Seek};
    let mut file = file.try_clone()?;
    file.seek(io::SeekFrom::Start(0))?;
    let mut buf = Vec::with_capacity(len);
    file.take(len as u64).read_to_end(&mut buf)?;
    Ok(Bytes::from(buf))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::test_support::block_on;

    fn bytes(n: usize) -> Vec<u8> {
        (0..n).map(|i| u8::try_from(i % 251).unwrap()).collect()
    }

    #[test]
    fn small_bodies_stay_in_memory() {
        let dir = tempfile::tempdir().unwrap();
        let spool = Arc::new(Spool::open(dir.path()).unwrap());
        block_on(async {
            let mut holder = BodyHolder::new(BodyHold::new(1 << 20), u64::MAX, Some(spool));
            holder.push(&bytes(MEMORY_LIMIT)).await.unwrap();
            assert!(!holder.is_spooled(), "exactly 64 KiB stays in memory");
            let body = holder.finish().await.unwrap();
            assert!(!body.is_spooled());
            assert_eq!(&body.bytes().await.unwrap()[..], &bytes(MEMORY_LIMIT)[..]);
        });
    }

    #[test]
    fn large_bodies_go_to_an_unlinked_private_spool_file() {
        let dir = tempfile::tempdir().unwrap();
        let spool = Arc::new(Spool::open(dir.path()).unwrap());
        let data = bytes(300_000);
        block_on(async {
            let mut holder = BodyHolder::new(BodyHold::new(1 << 20), u64::MAX, Some(spool));
            for chunk in data.chunks(7_000) {
                holder.push(chunk).await.unwrap();
            }
            assert!(holder.is_spooled());
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let file = holder.file.as_ref().unwrap();
                let mode = file.metadata().await.unwrap().permissions().mode();
                assert_eq!(mode & 0o777, 0o600);
            }
            assert_eq!(
                std::fs::read_dir(dir.path()).unwrap().count(),
                0,
                "the spool file has no name: it goes away with the request"
            );
            let body = holder.finish().await.unwrap();
            assert!(body.is_spooled());
            assert_eq!(body.len(), 300_000);
            assert_eq!(body.bytes().await.unwrap(), Bytes::from(data.clone()));
            assert_eq!(body.bytes().await.unwrap().len(), 300_000, "read again");
        });
    }

    #[test]
    fn opening_the_spool_removes_leftovers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spool");
        std::fs::create_dir_all(path.join("nested")).unwrap();
        std::fs::write(path.join("body-1-0"), b"old").unwrap();
        std::fs::write(path.join("nested/x"), b"old").unwrap();
        Spool::open(&path).unwrap();
        assert_eq!(std::fs::read_dir(&path).unwrap().count(), 0);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let fresh = dir.path().join("fresh");
            Spool::open(&fresh).unwrap();
            let mode = std::fs::metadata(&fresh).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700);
        }
    }

    #[test]
    fn limits_and_timeouts() {
        block_on(async {
            let mut holder = BodyHolder::new(BodyHold::new(10), 5, None);
            assert_eq!(holder.limit(), 5, "the route's max_body is smaller");
            holder.push(b"12345").await.unwrap();
            assert!(matches!(holder.push(b"6").await, Err(HoldError::TooLarge)));

            let hold = BodyHold::new(10).timeout(Duration::from_millis(20));
            let mut holder = BodyHolder::new(hold, u64::MAX, None);
            assert_eq!(holder.remaining(), None, "the clock starts with the body");
            holder.push(b"1").await.unwrap();
            tokio::time::sleep(Duration::from_millis(40)).await;
            assert!(matches!(holder.push(b"2").await, Err(HoldError::TimedOut)));
        });
    }

    #[test]
    fn without_a_spool_everything_stays_in_memory_and_reset_forgets() {
        block_on(async {
            let mut holder = BodyHolder::new(BodyHold::new(1 << 20), u64::MAX, None);
            holder.push(&bytes(100_000)).await.unwrap();
            assert!(!holder.is_spooled());
            holder.reset();
            assert!(holder.is_empty());
            holder.push(b"again").await.unwrap();
            let body = holder.finish().await.unwrap();
            assert_eq!(&body.bytes().await.unwrap()[..], b"again");
        });
    }
}
