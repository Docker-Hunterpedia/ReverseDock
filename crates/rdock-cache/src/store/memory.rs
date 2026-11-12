//! The memory store: objects as reference-counted chunks, one index under a mutex, least
//! recently used eviction by size.

use std::any::Any;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use async_trait::async_trait;
use bytes::Bytes;
use pingora::cache::storage::{HandleHit, HandleMiss, MissFinishType, MissHandler};
use pingora::cache::trace::SpanHandle;
use pingora::cache::{CacheKey, CacheMeta, HitHandler, Storage};

use super::index::Index;
use super::{Id, ObjectInfo, READ_CHUNK, Selector, Store, boxed, clamp_range, internal_error};

/// Bytes of bookkeeping counted per object besides its body and headers.
const OVERHEAD: u64 = 128;

#[derive(Debug)]
pub(crate) struct Object {
    internal: Vec<u8>,
    header: Vec<u8>,
    body: Arc<[Bytes]>,
    len: usize,
}

#[derive(Debug)]
pub(crate) struct Memory {
    index: Mutex<Index<Arc<Object>>>,
    max_size: u64,
}

impl Memory {
    pub(crate) fn new(max_size: u64) -> Self {
        Self {
            index: Mutex::default(),
            max_size,
        }
    }

    fn index(&self) -> MutexGuard<'_, Index<Arc<Object>>> {
        self.index.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn max_size(&self) -> u64 {
        self.max_size
    }

    pub(crate) fn size(&self) -> (usize, u64) {
        let index = self.index();
        (index.len(), index.bytes())
    }

    pub(crate) fn lookup(&self, id: &Id) -> pingora::Result<Option<(CacheMeta, HitHandler)>> {
        let Some(object) = self.index().get(id).map(|e| e.value.clone()) else {
            return Ok(None);
        };
        let meta = CacheMeta::deserialize(&object.internal, &object.header)?;
        let hit = MemoryHit {
            body: object.body.clone(),
            chunk: 0,
            offset: 0,
            remaining: object.len,
            len: object.len,
        };
        Ok(Some((meta, boxed(hit))))
    }

    pub(crate) fn miss_handler(
        &self,
        store: &'static Store,
        id: Id,
        info: ObjectInfo,
        internal: Vec<u8>,
        header: Vec<u8>,
    ) -> MissHandler {
        let (fill, cancelled) = self.index().begin_fill(info.url.clone(), info.tags.clone());
        Box::new(MemoryMiss {
            store,
            id,
            fill,
            cancelled,
            info,
            internal,
            header,
            chunks: Vec::new(),
            len: 0,
            done: false,
        })
    }

    pub(crate) fn remove(&self, id: &Id) -> bool {
        self.index().remove(id).is_some()
    }

    pub(crate) fn purge(&self, selector: &Selector) -> u64 {
        let mut index = self.index();
        index.cancel_fills(selector);
        let ids = index.select(selector);
        let mut removed = 0;
        for id in ids {
            if index.remove(&id).is_some() {
                removed += 1;
            }
        }
        removed
    }

    pub(crate) fn update_meta(
        &self,
        id: &Id,
        internal: Vec<u8>,
        header: Vec<u8>,
        info: Option<ObjectInfo>,
    ) -> bool {
        let mut index = self.index();
        let Some(entry) = index.peek(id) else {
            return false;
        };
        let old = entry.value.clone();
        let (url, tags) = match info {
            Some(info) => (info.url, info.tags),
            None => (entry.url.clone(), entry.tags.clone()),
        };
        let size = object_size(old.len, &internal, &header, &url);
        let object = Arc::new(Object {
            internal,
            header,
            body: old.body.clone(),
            len: old.len,
        });
        index.insert(*id, size, url, tags, object);
        true
    }
}

fn object_size(len: usize, internal: &[u8], header: &[u8], url: &str) -> u64 {
    (len + internal.len() + header.len() + url.len()) as u64 + OVERHEAD
}

/// Reads a stored body chunk by chunk, at most [`READ_CHUNK`] bytes at a time.
#[derive(Debug)]
struct MemoryHit {
    body: Arc<[Bytes]>,
    chunk: usize,
    offset: usize,
    remaining: usize,
    len: usize,
}

#[async_trait]
impl HandleHit for MemoryHit {
    async fn read_body(&mut self) -> pingora::Result<Option<Bytes>> {
        while self.remaining > 0 {
            let Some(chunk) = self.body.get(self.chunk) else {
                return Ok(None);
            };
            if self.offset >= chunk.len() {
                self.chunk += 1;
                self.offset = 0;
                continue;
            }
            let take = (chunk.len() - self.offset)
                .min(self.remaining)
                .min(READ_CHUNK);
            let out = chunk.slice(self.offset..self.offset + take);
            self.offset += take;
            self.remaining -= take;
            return Ok(Some(out));
        }
        Ok(None)
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
        let mut skip = start;
        self.chunk = 0;
        self.offset = 0;
        for (i, chunk) in self.body.iter().enumerate() {
            if skip < chunk.len() {
                self.chunk = i;
                self.offset = skip;
                break;
            }
            skip -= chunk.len();
            self.chunk = i + 1;
        }
        self.remaining = end - start;
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
struct MemoryMiss {
    store: &'static Store,
    id: Id,
    fill: u64,
    cancelled: Arc<AtomicBool>,
    info: ObjectInfo,
    internal: Vec<u8>,
    header: Vec<u8>,
    chunks: Vec<Bytes>,
    len: usize,
    done: bool,
}

impl MemoryMiss {
    fn memory(&self) -> Option<&'static Memory> {
        match &self.store.backend {
            super::Backend::Memory(m) => Some(m),
            super::Backend::Disk(_) => None,
        }
    }
}

#[async_trait]
impl HandleMiss for MemoryMiss {
    async fn write_body(&mut self, data: Bytes, _eof: bool) -> pingora::Result<()> {
        if !data.is_empty() {
            self.len += data.len();
            self.chunks.push(data);
        }
        Ok(())
    }

    async fn finish(mut self: Box<Self>) -> pingora::Result<MissFinishType> {
        self.done = true;
        let Some(memory) = self.memory() else {
            return Err(internal_error("memory miss handler on a disk store"));
        };
        let size = object_size(self.len, &self.internal, &self.header, &self.info.url);
        let mut index = memory.index();
        index.end_fill(self.fill);
        if self.cancelled.load(Ordering::SeqCst) {
            return Err(internal_error(
                "the object was purged while it was being stored",
            ));
        }
        if size > memory.max_size {
            return Err(internal_error("the object is larger than the store"));
        }
        let object = Arc::new(Object {
            internal: std::mem::take(&mut self.internal),
            header: std::mem::take(&mut self.header),
            body: std::mem::take(&mut self.chunks).into(),
            len: self.len,
        });
        index.insert(
            self.id,
            size,
            self.info.url.clone(),
            self.info.tags.clone(),
            object,
        );
        let evicted: Vec<_> = index
            .evict(memory.max_size, u64::MAX)
            .into_iter()
            .map(|(_, _, reason)| reason)
            .collect();
        let (objects, bytes) = (index.len(), index.bytes());
        drop(index);
        self.store.after_commit(&evicted, objects, bytes);
        Ok(MissFinishType::Created(self.len))
    }
}

impl Drop for MemoryMiss {
    fn drop(&mut self) {
        if !self.done
            && let Some(memory) = self.memory()
        {
            memory.index().end_fill(self.fill);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Selector;
    use pingora::cache::trace::Span;
    use pingora::http::ResponseHeader;
    use std::time::{Duration, SystemTime};

    fn store(max: u64) -> &'static Store {
        Box::leak(Box::new(Store::memory("mem", max, None)))
    }

    fn meta(url: &str, tags: &[String]) -> CacheMeta {
        let mut header = ResponseHeader::build(200, None).unwrap();
        header.insert_header("cache-control", "max-age=60").unwrap();
        let now = SystemTime::now();
        let mut meta = CacheMeta::new(now + Duration::from_secs(60), now, 0, 0, header);
        meta.extensions_mut().insert(ObjectInfo::new(url, tags));
        meta
    }

    async fn fill(
        store: &'static Store,
        key: &CacheKey,
        url: &str,
        chunks: &[&[u8]],
    ) -> pingora::Result<MissFinishType> {
        let span = Span::inactive().handle();
        let mut miss = store.get_miss_handler(key, &meta(url, &[]), &span).await?;
        for chunk in chunks {
            miss.write_body(Bytes::copy_from_slice(chunk), false)
                .await?;
        }
        miss.finish().await
    }

    async fn read_all(hit: &mut HitHandler) -> Vec<u8> {
        let mut out = Vec::new();
        while let Some(chunk) = hit.read_body().await.unwrap() {
            assert!(chunk.len() <= READ_CHUNK);
            out.extend_from_slice(&chunk);
        }
        out
    }

    #[tokio::test]
    async fn stores_reads_and_seeks_across_chunks() {
        let store = store(1 << 20);
        let key = CacheKey::new(b"k1".to_vec(), "r");
        fill(store, &key, "https://a.test/1", &[b"hello ", b"wor", b"ld"])
            .await
            .unwrap();
        let span = Span::inactive().handle();
        let (_, mut hit) = store.lookup(&key, &span).await.unwrap().unwrap();
        assert_eq!(read_all(&mut hit).await, b"hello world");
        let (_, mut hit) = store.lookup(&key, &span).await.unwrap().unwrap();
        hit.seek(4, Some(9)).unwrap();
        assert_eq!(read_all(&mut hit).await, b"o wor");
        hit.seek(10, None).unwrap();
        assert_eq!(read_all(&mut hit).await, b"d");
        assert!(hit.seek(11, None).is_err());
        assert_eq!(store.stats().objects, 1);
    }

    #[tokio::test]
    async fn evicts_least_recently_used_by_size() {
        let store = store(3 * (1000 + OVERHEAD + 200));
        let span = Span::inactive().handle();
        let body = vec![b'x'; 1000];
        let keys: Vec<CacheKey> = (0..4).map(|i| CacheKey::new(vec![i], "r")).collect();
        for (i, key) in keys.iter().take(3).enumerate() {
            fill(store, key, &format!("https://a.test/{i}"), &[&body])
                .await
                .unwrap();
        }
        // Touch the first object, then add a fourth: the second goes.
        assert!(store.lookup(&keys[0], &span).await.unwrap().is_some());
        fill(store, &keys[3], "https://a.test/3", &[&body])
            .await
            .unwrap();
        assert!(store.lookup(&keys[0], &span).await.unwrap().is_some());
        assert!(store.lookup(&keys[1], &span).await.unwrap().is_none());
        assert!(store.lookup(&keys[3], &span).await.unwrap().is_some());
        let stats = store.stats();
        assert_eq!((stats.objects, stats.evictions), (3, 1));
        // An object larger than the store is refused.
        let huge = vec![b'x'; 4000];
        assert!(
            fill(store, &CacheKey::new(b"huge".to_vec(), "r"), "u", &[&huge])
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn a_purge_wins_over_a_fill_that_commits_after_it() {
        let store = store(1 << 20);
        let span = Span::inactive().handle();
        let key = CacheKey::new(b"race".to_vec(), "r");
        let mut miss = store
            .get_miss_handler(&key, &meta("https://a.test/r", &[]), &span)
            .await
            .unwrap();
        miss.write_body(Bytes::from_static(b"old"), false)
            .await
            .unwrap();
        store
            .purge(Selector::Url("https://a.test/r".into()))
            .await
            .unwrap();
        assert!(miss.finish().await.is_err());
        assert!(store.lookup(&key, &span).await.unwrap().is_none());
        // A dropped fill (the request failed) leaves nothing behind.
        let miss = store
            .get_miss_handler(&key, &meta("https://a.test/r", &[]), &span)
            .await
            .unwrap();
        drop(miss);
        assert!(store.lookup(&key, &span).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn concurrent_fills_and_reads_stay_consistent() {
        let store = store(64 << 20);
        let mut tasks = Vec::new();
        for t in 0..16u8 {
            tasks.push(tokio::spawn(async move {
                let span = Span::inactive().handle();
                for i in 0..50u8 {
                    let key = CacheKey::new(vec![t, i % 10], "r");
                    let body = vec![t; 100 + usize::from(i)];
                    let _ = fill(
                        store,
                        &key,
                        &format!("https://a.test/{t}/{}", i % 10),
                        &[&body],
                    )
                    .await;
                    if let Some((_, mut hit)) = store.lookup(&key, &span).await.unwrap() {
                        let read = read_all(&mut hit).await;
                        assert!(read.iter().all(|b| *b == t));
                    }
                }
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
        let stats = store.stats();
        assert_eq!(stats.objects, 160);
        assert_eq!(store.purge(Selector::All).await.unwrap(), 160);
        assert_eq!(store.stats().objects, 0);
    }

    #[tokio::test]
    async fn update_meta_keeps_the_body() {
        let store = store(1 << 20);
        let span = Span::inactive().handle();
        let key = CacheKey::new(b"m".to_vec(), "r");
        fill(store, &key, "https://a.test/m", &[b"body"])
            .await
            .unwrap();
        let mut new_meta = meta("https://a.test/m", &[]);
        new_meta
            .response_header_mut()
            .insert_header("x-new", "1")
            .unwrap();
        assert!(store.update_meta(&key, &new_meta, &span).await.unwrap());
        let (found, mut hit) = store.lookup(&key, &span).await.unwrap().unwrap();
        assert_eq!(found.headers().get("x-new").unwrap(), "1");
        assert_eq!(read_all(&mut hit).await, b"body");
    }
}
