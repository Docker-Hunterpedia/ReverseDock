//! The in-memory index of a store: objects by key with their size, URL and tags, least
//! recently used order, a URL index and a bounded tag index, and the fills in progress (so a
//! purge can cancel a fill that would otherwise commit after it).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use super::{Id, Selector};

/// One stored object.
#[derive(Debug)]
pub(crate) struct Entry<V> {
    tick: u64,
    /// Bytes it takes (body, headers and bookkeeping).
    pub size: u64,
    /// Public URL it answers.
    pub url: Arc<str>,
    /// Its tags, lower case.
    pub tags: Arc<[Box<str>]>,
    /// Store-specific data.
    pub value: V,
}

/// A fill in progress.
#[derive(Debug)]
struct Fill {
    url: Arc<str>,
    tags: Arc<[Box<str>]>,
    cancelled: Arc<AtomicBool>,
}

/// Why an object was evicted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Evicted {
    /// Over the byte limit.
    Size,
    /// Over the object limit.
    Count,
}

impl Evicted {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Size => "size",
            Self::Count => "count",
        }
    }
}

#[derive(Debug)]
pub(crate) struct Index<V> {
    entries: HashMap<Id, Entry<V>>,
    lru: BTreeMap<u64, Id>,
    urls: HashMap<Arc<str>, HashSet<Id>>,
    tags: HashMap<Box<str>, HashSet<Id>>,
    fills: HashMap<u64, Fill>,
    next_tick: u64,
    next_fill: u64,
    bytes: u64,
}

impl<V> Default for Index<V> {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            lru: BTreeMap::new(),
            urls: HashMap::new(),
            tags: HashMap::new(),
            fills: HashMap::new(),
            next_tick: 0,
            next_fill: 0,
            bytes: 0,
        }
    }
}

impl<V> Index<V> {
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(crate) fn bytes(&self) -> u64 {
        self.bytes
    }

    fn tick(&mut self) -> u64 {
        self.next_tick += 1;
        self.next_tick
    }

    /// The object `id`, marked as used now.
    pub(crate) fn get(&mut self, id: &Id) -> Option<&Entry<V>> {
        let tick = self.tick();
        let entry = self.entries.get_mut(id)?;
        self.lru.remove(&entry.tick);
        entry.tick = tick;
        self.lru.insert(tick, *id);
        Some(entry)
    }

    /// The object `id`, without changing its place in the order.
    pub(crate) fn peek(&self, id: &Id) -> Option<&Entry<V>> {
        self.entries.get(id)
    }

    pub(crate) fn peek_mut(&mut self, id: &Id) -> Option<&mut Entry<V>> {
        self.entries.get_mut(id)
    }

    /// Adds or replaces `id`; returns the object it replaced.
    pub(crate) fn insert(
        &mut self,
        id: Id,
        size: u64,
        url: Arc<str>,
        tags: Arc<[Box<str>]>,
        value: V,
    ) -> Option<Entry<V>> {
        let replaced = self.remove(&id);
        let tick = self.tick();
        self.lru.insert(tick, id);
        self.urls.entry(url.clone()).or_default().insert(id);
        for tag in tags.iter() {
            self.tags.entry(tag.clone()).or_default().insert(id);
        }
        self.bytes += size;
        self.entries.insert(
            id,
            Entry {
                tick,
                size,
                url,
                tags,
                value,
            },
        );
        replaced
    }

    /// Changes the recorded size of `id`.
    pub(crate) fn resize(&mut self, id: &Id, size: u64) {
        if let Some(entry) = self.entries.get_mut(id) {
            self.bytes = self.bytes - entry.size + size;
            entry.size = size;
        }
    }

    pub(crate) fn remove(&mut self, id: &Id) -> Option<Entry<V>> {
        let entry = self.entries.remove(id)?;
        self.lru.remove(&entry.tick);
        if let Some(set) = self.urls.get_mut(&entry.url) {
            set.remove(id);
            if set.is_empty() {
                self.urls.remove(&entry.url);
            }
        }
        for tag in entry.tags.iter() {
            if let Some(set) = self.tags.get_mut(tag) {
                set.remove(id);
                if set.is_empty() {
                    self.tags.remove(tag);
                }
            }
        }
        self.bytes -= entry.size;
        Some(entry)
    }

    /// The objects a purge selects.
    pub(crate) fn select(&self, selector: &Selector) -> Vec<Id> {
        match selector {
            Selector::Url(url) => self
                .urls
                .get(url.as_str())
                .map(|set| set.iter().copied().collect())
                .unwrap_or_default(),
            Selector::Tag(tag) => self
                .tags
                .get(tag.as_str())
                .map(|set| set.iter().copied().collect())
                .unwrap_or_default(),
            Selector::Prefix(prefix) => self
                .entries
                .iter()
                .filter(|(_, e)| e.url.starts_with(prefix.as_str()))
                .map(|(id, _)| *id)
                .collect(),
            Selector::All => self.entries.keys().copied().collect(),
        }
    }

    /// Registers a fill; its flag turns true when a purge selects it before it commits.
    pub(crate) fn begin_fill(
        &mut self,
        url: Arc<str>,
        tags: Arc<[Box<str>]>,
    ) -> (u64, Arc<AtomicBool>) {
        self.next_fill += 1;
        let cancelled = Arc::new(AtomicBool::new(false));
        self.fills.insert(
            self.next_fill,
            Fill {
                url,
                tags,
                cancelled: cancelled.clone(),
            },
        );
        (self.next_fill, cancelled)
    }

    pub(crate) fn end_fill(&mut self, fill: u64) {
        self.fills.remove(&fill);
    }

    /// Cancels the fills in progress that `selector` covers; returns how many.
    pub(crate) fn cancel_fills(&mut self, selector: &Selector) -> usize {
        let mut cancelled = 0;
        for fill in self.fills.values() {
            let hit = match selector {
                Selector::Url(url) => &*fill.url == url.as_str(),
                Selector::Prefix(prefix) => fill.url.starts_with(prefix.as_str()),
                Selector::Tag(tag) => fill.tags.iter().any(|t| &**t == tag.as_str()),
                Selector::All => true,
            };
            if hit {
                fill.cancelled.store(true, Ordering::SeqCst);
                cancelled += 1;
            }
        }
        cancelled
    }

    /// Removes least recently used objects until at most `max_bytes` and `max_count` remain.
    pub(crate) fn evict(&mut self, max_bytes: u64, max_count: u64) -> Vec<(Id, Entry<V>, Evicted)> {
        let mut out = Vec::new();
        loop {
            let reason = if self.bytes > max_bytes {
                Evicted::Size
            } else if self.entries.len() as u64 > max_count {
                Evicted::Count
            } else {
                break;
            };
            let Some((_, id)) = self.lru.first_key_value().map(|(t, id)| (*t, *id)) else {
                break;
            };
            match self.remove(&id) {
                Some(entry) => out.push((id, entry, reason)),
                None => break,
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> Id {
        [n; 16]
    }

    fn tags(t: &[&str]) -> Arc<[Box<str>]> {
        t.iter().map(|s| Box::from(*s)).collect()
    }

    #[test]
    fn lru_order_follows_use_and_eviction_takes_the_oldest() {
        let mut index = Index::default();
        for n in 1..=3 {
            index.insert(id(n), 10, Arc::from(format!("u{n}")), tags(&[]), ());
        }
        assert!(index.get(&id(1)).is_some());
        let evicted = index.evict(20, 100);
        assert_eq!(evicted.len(), 1);
        assert_eq!(evicted[0].0, id(2));
        assert_eq!(evicted[0].2, Evicted::Size);
        let evicted = index.evict(1000, 1);
        assert_eq!(evicted.iter().map(|e| e.0).collect::<Vec<_>>(), [id(3)]);
        assert_eq!(evicted[0].2, Evicted::Count);
        assert_eq!((index.len(), index.bytes()), (1, 10));
    }

    #[test]
    fn selectors_find_by_url_prefix_tag_and_all() {
        let mut index = Index::default();
        index.insert(id(1), 1, Arc::from("https://a.test/x"), tags(&["t1"]), ());
        index.insert(id(2), 1, Arc::from("https://a.test/x"), tags(&["t2"]), ());
        index.insert(
            id(3),
            1,
            Arc::from("https://a.test/y/z"),
            tags(&["t1", "t3"]),
            (),
        );
        let sorted = |mut v: Vec<Id>| {
            v.sort_unstable();
            v
        };
        assert_eq!(
            sorted(index.select(&Selector::Url("https://a.test/x".into()))),
            [id(1), id(2)]
        );
        assert_eq!(
            sorted(index.select(&Selector::Prefix("https://a.test/y".into()))),
            [id(3)]
        );
        assert_eq!(
            sorted(index.select(&Selector::Tag("t1".into()))),
            [id(1), id(3)]
        );
        assert_eq!(index.select(&Selector::All).len(), 3);
        index.remove(&id(3));
        assert_eq!(index.select(&Selector::Tag("t3".into())), Vec::<Id>::new());
        assert!(!index.tags.contains_key("t3"), "empty tag sets are dropped");
    }

    #[test]
    fn replacing_an_object_keeps_the_totals_right() {
        let mut index = Index::default();
        index.insert(id(1), 10, Arc::from("u"), tags(&["a"]), ());
        let old = index.insert(id(1), 25, Arc::from("u"), tags(&["b"]), ());
        assert_eq!(old.map(|e| e.size), Some(10));
        assert_eq!((index.len(), index.bytes()), (1, 25));
        assert_eq!(index.select(&Selector::Tag("a".into())), Vec::<Id>::new());
        index.resize(&id(1), 5);
        assert_eq!(index.bytes(), 5);
    }

    #[test]
    fn purges_cancel_matching_fills_in_progress() {
        let mut index: Index<()> = Index::default();
        let (a, flag_a) = index.begin_fill(Arc::from("https://a.test/1"), tags(&["x"]));
        let (_, flag_b) = index.begin_fill(Arc::from("https://b.test/1"), tags(&[]));
        assert_eq!(index.cancel_fills(&Selector::Tag("x".into())), 1);
        assert!(flag_a.load(Ordering::SeqCst));
        assert!(!flag_b.load(Ordering::SeqCst));
        index.end_fill(a);
        assert_eq!(index.cancel_fills(&Selector::All), 1);
        assert!(flag_b.load(Ordering::SeqCst));
    }
}
