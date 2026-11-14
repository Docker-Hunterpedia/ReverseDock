//! The disk store (ADR-0030): one file per object under two hashed directory levels below the
//! store root (`ab/cd/<32 hex digits>`), written under a temporary name in the same directory
//! and renamed when complete, so a partial object is never visible. A start-up walk rebuilds
//! the index, removes temporary files, drops damaged files and enforces the limits.
//!
//! The root is opened once with cap-std and every path is relative to it, so no key can name
//! a file outside it. Blocking file I/O runs on Tokio's blocking pool. Nothing is synced to
//! disk: after a power loss recent objects may be missing or damaged, and the start-up walk
//! drops what does not check out.

pub(crate) mod format;

use std::any::Any;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::SystemTime;

use async_trait::async_trait;
use bytes::Bytes;
use cap_std::ambient_authority;
use cap_std::fs::{Dir, OpenOptions};
use pingora::cache::storage::{HandleHit, HandleMiss, MissFinishType, MissHandler};
use pingora::cache::trace::SpanHandle;
use pingora::cache::{CacheKey, CacheMeta, HitHandler, Storage};

use self::format::{Header, PREFIX_LEN, Prefix, encode_head};
use super::index::{Evicted, Index};
use super::{Id, ObjectInfo, READ_CHUNK, Selector, Store, boxed, clamp_range, internal_error};

/// Body bytes buffered before a write to the temporary file.
const WRITE_BUFFER: usize = 256 * 1024;

/// What the start-up walk found.
#[derive(Debug, Default)]
pub(crate) struct Walk {
    pub objects: usize,
    pub bytes: u64,
    pub corrupt: u64,
    pub partial: u64,
    pub evicted: Vec<Evicted>,
}

#[derive(Debug)]
pub(crate) struct Disk {
    root: Dir,
    path: PathBuf,
    index: Mutex<Index<()>>,
    max_size: u64,
    max_objects: u64,
    seq: AtomicU64,
}

fn hex(id: &Id) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(32);
    for b in id {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn parse_hex(name: &str) -> Option<Id> {
    if name.len() != 32
        || !name
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return None;
    }
    let mut id = [0u8; 16];
    for (i, byte) in id.iter_mut().enumerate() {
        *byte = u8::from_str_radix(name.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(id)
}

/// `ab/cd` for an object.
fn dir_of(id: &Id) -> PathBuf {
    let h = hex(id);
    Path::new(&h[0..2]).join(&h[2..4])
}

/// `ab/cd/<hex>` for an object.
fn file_of(id: &Id) -> PathBuf {
    dir_of(id).join(hex(id))
}

fn is_hex_dir(name: &str) -> bool {
    name.len() == 2
        && name
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn join_error(e: &tokio::task::JoinError) -> io::Error {
    io::Error::other(format!("cache disk task failed: {e}"))
}

impl Disk {
    /// Opens (creating it with mode 0700 if needed) and walks the store at `path`.
    pub(crate) fn open(path: &Path, max_size: u64, max_objects: u64) -> io::Result<(Self, Walk)> {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
        let root = Dir::open_ambient_dir(path, ambient_authority())?;
        let disk = Self {
            root,
            path: path.to_owned(),
            index: Mutex::default(),
            max_size,
            max_objects,
            seq: AtomicU64::new(0),
        };
        let walk = disk.walk()?;
        Ok((disk, walk))
    }

    fn index(&self) -> MutexGuard<'_, Index<()>> {
        self.index.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn size(&self) -> (usize, u64) {
        let index = self.index();
        (index.len(), index.bytes())
    }

    pub(crate) fn max_size(&self) -> u64 {
        self.max_size
    }

    pub(crate) fn max_objects(&self) -> u64 {
        self.max_objects
    }

    /// Removes a file, ignoring one that is already gone.
    fn unlink(&self, rel: &Path) {
        if let Err(e) = self.root.remove_file(rel)
            && e.kind() != io::ErrorKind::NotFound
        {
            tracing::warn!(error = %e, path = %self.path.join(rel).display(), "cannot remove a cache file");
        }
    }

    /// Reads and checks the head of an object file: the prefix, the header block, the
    /// expected id and the file length.
    fn read_head(
        &self,
        rel: &Path,
        id: &Id,
    ) -> io::Result<Option<(std::fs::File, Prefix, Header)>> {
        let file = match self.root.open(rel) {
            Ok(f) => f.into_std(),
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let len = file.metadata()?.len();
        let mut prefix = [0u8; PREFIX_LEN];
        let bad = |e: format::FormatError| io::Error::new(io::ErrorKind::InvalidData, e);
        file.read_exact_at(&mut prefix, 0)
            .map_err(|_| bad(format::FormatError::Truncated))?;
        let prefix = Prefix::decode(&prefix).map_err(bad)?;
        if prefix.file_len() != len {
            return Err(bad(format::FormatError::Length));
        }
        let mut block = vec![0u8; prefix.header_len as usize];
        file.read_exact_at(&mut block, PREFIX_LEN as u64)
            .map_err(|_| bad(format::FormatError::Truncated))?;
        let header = Header::decode(&block, prefix.header_crc).map_err(bad)?;
        if header.id != *id {
            return Err(bad(format::FormatError::Length));
        }
        Ok(Some((file, prefix, header)))
    }

    /// The start-up walk.
    fn walk(&self) -> io::Result<Walk> {
        let mut walk = Walk::default();
        let mut found: Vec<(SystemTime, Id, u64, String, Vec<String>)> = Vec::new();
        for first in self.root.entries()? {
            let first = first?;
            let a = first.file_name().to_string_lossy().into_owned();
            if !is_hex_dir(&a) || !first.file_type()?.is_dir() {
                continue;
            }
            for second in self.root.read_dir(&a)? {
                let second = second?;
                let b = second.file_name().to_string_lossy().into_owned();
                if !is_hex_dir(&b) || !second.file_type()?.is_dir() {
                    continue;
                }
                let dir = Path::new(&a).join(&b);
                for entry in self.root.read_dir(&dir)? {
                    let entry = entry?;
                    let name = entry.file_name().to_string_lossy().into_owned();
                    let rel = dir.join(&name);
                    if Path::new(&name).extension().is_some_and(|e| e == "tmp") {
                        self.unlink(&rel);
                        walk.partial += 1;
                        continue;
                    }
                    let Some(id) = parse_hex(&name).filter(|id| dir_of(id) == dir) else {
                        continue;
                    };
                    let checked = self.read_head(&rel, &id).and_then(|head| {
                        let (file, prefix, header) =
                            head.ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
                        CacheMeta::deserialize(&header.internal, &header.meta_head).map_err(
                            |e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()),
                        )?;
                        let modified = file
                            .metadata()?
                            .modified()
                            .unwrap_or(SystemTime::UNIX_EPOCH);
                        Ok((modified, prefix.file_len(), header.url, header.tags))
                    });
                    match checked {
                        Ok((modified, len, url, tags)) => {
                            found.push((modified, id, len, url, tags));
                        }
                        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                        Err(_) => {
                            self.unlink(&rel);
                            walk.corrupt += 1;
                        }
                    }
                }
            }
        }
        // Oldest first, so the least recently written objects go first when over a limit.
        found.sort_by_key(|(modified, ..)| *modified);
        let mut index = self.index();
        for (_, id, len, url, tags) in found {
            let tags: Arc<[Box<str>]> = tags.iter().map(|t| Box::from(t.as_str())).collect();
            index.insert(id, len, Arc::from(url.as_str()), tags, ());
        }
        for (id, _, reason) in index.evict(self.max_size, self.max_objects) {
            self.unlink(&file_of(&id));
            walk.evicted.push(reason);
        }
        walk.objects = index.len();
        walk.bytes = index.bytes();
        Ok(walk)
    }

    pub(crate) async fn lookup(
        &'static self,
        id: &Id,
    ) -> pingora::Result<Option<(CacheMeta, HitHandler)>> {
        if self.index().get(id).is_none() {
            return Ok(None);
        }
        let id = *id;
        let read = tokio::task::spawn_blocking(move || self.read_head(&file_of(&id), &id))
            .await
            .map_err(|e| internal_error(e.to_string()))?;
        let Ok(Some((file, prefix, header))) = read else {
            // Gone or damaged under us: forget it.
            self.forget(id).await;
            return Ok(None);
        };
        let meta = CacheMeta::deserialize(&header.internal, &header.meta_head)?;
        let len = usize::try_from(prefix.body_len).map_err(|_| internal_error("body too large"))?;
        let hit = DiskHit {
            file: Arc::new(file),
            offset: prefix.body_offset(),
            pos: 0,
            end: len,
            len,
        };
        Ok(Some((meta, boxed(hit))))
    }

    async fn forget(&'static self, id: Id) {
        let _ = tokio::task::spawn_blocking(move || {
            let mut index = self.index();
            if index.remove(&id).is_some() {
                self.unlink(&file_of(&id));
            }
        })
        .await;
    }

    pub(crate) async fn miss_handler(
        &'static self,
        store: &'static Store,
        id: Id,
        variance: Option<Id>,
        info: ObjectInfo,
        internal: Vec<u8>,
        meta_head: Vec<u8>,
    ) -> pingora::Result<MissHandler> {
        let header = Header {
            id,
            variance,
            url: info.url.to_string(),
            tags: info.tags.iter().map(ToString::to_string).collect(),
            internal,
            meta_head,
        };
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let temp = dir_of(&id).join(format!("{}.{seq}.tmp", hex(&id)));
        let head = encode_head(&header, 0);
        let head_len = head.len() as u64;
        let path = temp.clone();
        let created = tokio::task::spawn_blocking(move || -> io::Result<std::fs::File> {
            self.root.create_dir_all(dir_of(&id))?;
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            let mut file = self.root.open_with(&path, &options)?.into_std();
            if let Err(e) = file.write_all(&head) {
                self.unlink(&path);
                return Err(e);
            }
            Ok(file)
        })
        .await
        .map_err(|e| internal_error(e.to_string()))?;
        // A disk that refuses the file (full) never fails the response: the body is passed
        // through and not stored (ADR-0033).
        let (created, failed) = match created {
            Ok(file) => (Some(Arc::new(file)), None),
            Err(e) => {
                let error = format!("creating a cache file: {e}");
                store.note_write_error(&error);
                (None, Some(error))
            }
        };
        let (fill, cancelled) = self.index().begin_fill(info.url.clone(), info.tags.clone());
        Ok(Box::new(DiskMiss {
            disk: self,
            store,
            id,
            temp,
            failed,
            file: created,
            buf: Vec::new(),
            head_len,
            body_len: 0,
            header,
            fill,
            cancelled,
            done: false,
        }))
    }

    pub(crate) async fn remove(&'static self, id: Id) -> io::Result<bool> {
        tokio::task::spawn_blocking(move || {
            let mut index = self.index();
            let removed = index.remove(&id).is_some();
            if removed {
                self.unlink(&file_of(&id));
            }
            removed
        })
        .await
        .map_err(|e| join_error(&e))
    }

    pub(crate) async fn purge(&'static self, selector: Selector) -> io::Result<u64> {
        tokio::task::spawn_blocking(move || {
            let mut index = self.index();
            index.cancel_fills(&selector);
            let mut removed = 0;
            for id in index.select(&selector) {
                if index.remove(&id).is_some() {
                    self.unlink(&file_of(&id));
                    removed += 1;
                }
            }
            removed
        })
        .await
        .map_err(|e| join_error(&e))
    }

    /// Rewrites an object's head after a revalidation: a new file with the new metadata and
    /// the old body, renamed over the old one.
    pub(crate) async fn update_meta(
        &'static self,
        id: Id,
        internal: Vec<u8>,
        meta_head: Vec<u8>,
        info: Option<ObjectInfo>,
    ) -> pingora::Result<bool> {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        tokio::task::spawn_blocking(move || -> io::Result<bool> {
            let rel = file_of(&id);
            let Some((mut old, prefix, mut header)) = self.read_head(&rel, &id)? else {
                return Ok(false);
            };
            header.internal = internal;
            header.meta_head = meta_head;
            if let Some(info) = &info {
                header.url = info.url.to_string();
                header.tags = info.tags.iter().map(ToString::to_string).collect();
            }
            let head = encode_head(&header, prefix.body_len);
            let temp = dir_of(&id).join(format!("{}.{seq}.tmp", hex(&id)));
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            let mut new = self.root.open_with(&temp, &options)?.into_std();
            let copied = (|| -> io::Result<u64> {
                new.write_all(&head)?;
                old.seek(SeekFrom::Start(prefix.body_offset()))?;
                io::copy(&mut (&mut old).take(prefix.body_len), &mut new)
            })();
            if copied.as_ref().ok() != Some(&prefix.body_len) {
                self.unlink(&temp);
                return copied.map(|_| false);
            }
            let mut index = self.index();
            if index.peek(&id).is_none() {
                // Purged meanwhile: do not bring it back.
                self.unlink(&temp);
                return Ok(false);
            }
            self.root.rename(&temp, &self.root, &rel)?;
            index.resize(&id, head.len() as u64 + prefix.body_len);
            if let Some(info) = info
                && let Some(entry) = index.peek_mut(&id)
            {
                entry.url = info.url;
            }
            Ok(true)
        })
        .await
        .map_err(|e| internal_error(e.to_string()))?
        .map_err(|e| internal_error(format!("updating a cache file: {e}")))
    }
}

/// Reads an object's body from its file, at most [`READ_CHUNK`] bytes per call. The file
/// stays readable while open even if a purge removes it.
#[derive(Debug)]
struct DiskHit {
    file: Arc<std::fs::File>,
    offset: u64,
    pos: usize,
    end: usize,
    len: usize,
}

#[async_trait]
impl HandleHit for DiskHit {
    async fn read_body(&mut self) -> pingora::Result<Option<Bytes>> {
        if self.pos >= self.end {
            return Ok(None);
        }
        let n = (self.end - self.pos).min(READ_CHUNK);
        let file = self.file.clone();
        let at = self.offset + self.pos as u64;
        let chunk = tokio::task::spawn_blocking(move || -> io::Result<Vec<u8>> {
            let mut buf = vec![0u8; n];
            file.read_exact_at(&mut buf, at)?;
            Ok(buf)
        })
        .await
        .map_err(|e| internal_error(e.to_string()))?
        .map_err(|e| internal_error(format!("reading a cache file: {e}")))?;
        self.pos += n;
        Ok(Some(Bytes::from(chunk)))
    }

    async fn finish(
        self: Box<Self>,
        _storage: &'static (dyn Storage + Sync),
        _key: &CacheKey,
        _trace: &SpanHandle,
    ) -> pingora::Result<()> {
        Ok(())
    }

    fn can_seek(&self) -> bool {
        true
    }

    fn seek(&mut self, start: usize, end: Option<usize>) -> pingora::Result<()> {
        let (start, end) = clamp_range(self.len, start, end)?;
        self.pos = start;
        self.end = end;
        Ok(())
    }

    fn as_any(&self) -> &(dyn Any + Send + Sync) {
        self
    }

    fn as_any_mut(&mut self) -> &mut (dyn Any + Send + Sync) {
        self
    }
}

#[derive(Debug)]
struct DiskMiss {
    disk: &'static Disk,
    store: &'static Store,
    id: Id,
    temp: PathBuf,
    /// Why the object is not being stored (the disk refused a write): the rest of the body is
    /// discarded and [`HandleMiss::finish`] reports it, which Pingora takes as "not cached".
    failed: Option<String>,
    file: Option<Arc<std::fs::File>>,
    buf: Vec<u8>,
    head_len: u64,
    body_len: u64,
    header: Header,
    fill: u64,
    cancelled: Arc<AtomicBool>,
    done: bool,
}

impl DiskMiss {
    /// Writes the buffered body bytes to the temporary file. A write the disk refuses gives
    /// the object up instead of failing the response it belongs to.
    async fn flush(&mut self) -> pingora::Result<()> {
        if self.failed.is_some() {
            self.buf.clear();
            return Ok(());
        }
        if self.buf.is_empty() {
            return Ok(());
        }
        let Some(file) = self.file.clone() else {
            return Err(internal_error("cache file already closed"));
        };
        let buf = std::mem::take(&mut self.buf);
        let at = self.head_len + self.body_len;
        let len = buf.len() as u64;
        let written = tokio::task::spawn_blocking(move || -> io::Result<Vec<u8>> {
            file.write_all_at(&buf, at)?;
            Ok(buf)
        })
        .await
        .map_err(|e| internal_error(e.to_string()))?;
        let buf = match written {
            Ok(buf) => buf,
            Err(e) => {
                let error = format!("writing a cache file: {e}");
                self.store.note_write_error(&error);
                self.failed = Some(error);
                self.file = None;
                let (disk, temp) = (self.disk, self.temp.clone());
                let _ = tokio::task::spawn_blocking(move || disk.unlink(&temp)).await;
                return Ok(());
            }
        };
        self.body_len += len;
        // Keep the allocation for the next chunks.
        self.buf = buf;
        self.buf.clear();
        Ok(())
    }
}

#[async_trait]
impl HandleMiss for DiskMiss {
    async fn write_body(&mut self, data: Bytes, _eof: bool) -> pingora::Result<()> {
        self.buf.extend_from_slice(&data);
        if self.buf.len() >= WRITE_BUFFER {
            self.flush().await?;
        }
        Ok(())
    }

    async fn finish(mut self: Box<Self>) -> pingora::Result<MissFinishType> {
        self.flush().await?;
        if let Some(error) = self.failed.take() {
            // Dropping ends the fill and removes the temporary file.
            return Err(internal_error(format!("not stored: {error}")));
        }
        self.done = true;
        let handle = self.file.take();
        let disk = self.disk;
        let (id, fill, temp) = (self.id, self.fill, self.temp.clone());
        let cancelled = self.cancelled.clone();
        let block = self.header.encode();
        let prefix = Prefix {
            header_len: u32::try_from(block.len()).unwrap_or(u32::MAX),
            body_len: self.body_len,
            header_crc: crc32fast::hash(&block),
        };
        let size = prefix.file_len();
        let (url, tags) = (
            Arc::from(self.header.url.as_str()),
            self.header
                .tags
                .iter()
                .map(|t| Box::from(t.as_str()))
                .collect::<Arc<[Box<str>]>>(),
        );
        let outcome = tokio::task::spawn_blocking(
            move || -> io::Result<Option<(Vec<Evicted>, usize, u64)>> {
                let Some(handle) = handle else {
                    return Ok(None);
                };
                handle.write_all_at(&prefix.encode(), 0)?;
                drop(handle);
                let mut index = disk.index();
                index.end_fill(fill);
                if cancelled.load(Ordering::SeqCst) || size > disk.max_size {
                    disk.unlink(&temp);
                    return Ok(None);
                }
                disk.root.rename(&temp, &disk.root, file_of(&id))?;
                index.insert(id, size, url, tags, ());
                let mut evicted = Vec::new();
                for (victim, _, reason) in index.evict(disk.max_size, disk.max_objects) {
                    disk.unlink(&file_of(&victim));
                    evicted.push(reason);
                }
                Ok(Some((evicted, index.len(), index.bytes())))
            },
        )
        .await
        .map_err(|e| internal_error(e.to_string()))?;
        match outcome {
            Ok(Some((evicted, objects, bytes))) => {
                self.store.after_commit(&evicted, objects, bytes);
                Ok(MissFinishType::Created(
                    usize::try_from(self.body_len).unwrap_or(usize::MAX),
                ))
            }
            Ok(None) => Err(internal_error(
                "the object was purged while it was being stored, or is larger than the store",
            )),
            Err(e) => {
                self.disk.unlink(&self.temp);
                let error = format!("storing a cache file: {e}");
                self.store.note_write_error(&error);
                Err(internal_error(error))
            }
        }
    }
}

impl Drop for DiskMiss {
    fn drop(&mut self) {
        if self.done {
            return;
        }
        let (disk, fill, temp) = (self.disk, self.fill, self.temp.clone());
        let cleanup = move || {
            disk.index().end_fill(fill);
            disk.unlink(&temp);
        };
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn_blocking(cleanup);
            }
            Err(_) => cleanup(),
        }
    }
}

#[cfg(test)]
mod tests;
