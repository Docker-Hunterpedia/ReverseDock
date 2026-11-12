//! Named, process-lifetime stores. pingora-cache needs `&'static` stores, so each is created
//! once per process and kept; a reload reuses it.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard, PoisonError};

use rdock_model::cache::CacheStore;

use crate::metrics::CacheMetrics;
use crate::store::Store;

/// Something a reload changed that the registry cannot apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finding {
    /// The definition changed; the store keeps its old settings until a restart.
    Changed(String),
    /// The definition is gone; the store keeps its objects until a restart.
    Removed(String),
    /// The store could not be created.
    Failed(String, String),
}

impl Finding {
    /// The store's name.
    #[must_use]
    pub fn store(&self) -> &str {
        match self {
            Self::Changed(name) | Self::Removed(name) | Self::Failed(name, _) => name,
        }
    }

    /// Whether the configuration cannot be applied.
    #[must_use]
    pub fn is_error(&self) -> bool {
        matches!(self, Self::Failed(..))
    }

    /// A message for the diagnostic.
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Self::Changed(_) => "changing a cache store takes effect after a restart; the running store keeps its settings and objects until then".to_owned(),
            Self::Removed(_) => "removing a cache store takes effect after a restart; it keeps its objects until then".to_owned(),
            Self::Failed(_, why) => format!("cannot open the cache store: {why}"),
        }
    }
}

/// The stores for one configuration.
#[derive(Debug, Default)]
pub struct Resolved {
    /// Stores by name.
    pub stores: HashMap<String, &'static Store>,
    /// What could not be applied.
    pub findings: Vec<Finding>,
}

#[derive(Debug)]
struct Entry {
    definition: CacheStore,
    store: &'static Store,
}

/// The process's stores by name.
#[derive(Debug, Default)]
pub struct Registry {
    stores: Mutex<BTreeMap<String, Entry>>,
    metrics: Option<CacheMetrics>,
    default_dir: Mutex<Option<PathBuf>>,
}

impl Registry {
    /// A registry whose stores report `metrics`.
    #[must_use]
    pub fn new(metrics: Option<CacheMetrics>) -> Self {
        Self {
            stores: Mutex::default(),
            metrics,
            default_dir: Mutex::default(),
        }
    }

    fn stores(&self) -> MutexGuard<'_, BTreeMap<String, Entry>> {
        self.stores.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Where disk stores without a `path` go: `<dir>/<name>` (`<data dir>/cache`).
    pub fn set_default_dir(&self, dir: PathBuf) {
        *self
            .default_dir
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(dir);
    }

    /// The stores `definitions` name: existing ones are reused (a changed definition is
    /// reported and the old store kept), new ones are created.
    pub fn resolve(&self, definitions: &BTreeMap<String, CacheStore>) -> Resolved {
        let mut out = Resolved::default();
        let mut stores = self.stores();
        for (name, definition) in definitions {
            if let Some(entry) = stores.get(name) {
                if &entry.definition != definition {
                    out.findings.push(Finding::Changed(name.clone()));
                }
                out.stores.insert(name.clone(), entry.store);
                continue;
            }
            match self.create(name, definition) {
                Ok(store) => {
                    let store: &'static Store = Box::leak(Box::new(store));
                    stores.insert(
                        name.clone(),
                        Entry {
                            definition: definition.clone(),
                            store,
                        },
                    );
                    out.stores.insert(name.clone(), store);
                }
                Err(why) => out.findings.push(Finding::Failed(name.clone(), why)),
            }
        }
        for name in stores.keys() {
            if !definitions.contains_key(name) {
                out.findings.push(Finding::Removed(name.clone()));
            }
        }
        out
    }

    fn create(&self, name: &str, definition: &CacheStore) -> Result<Store, String> {
        match definition {
            CacheStore::Memory(m) => Ok(Store::memory(
                name,
                m.max_size.as_u64(),
                self.metrics.clone(),
            )),
            CacheStore::Disk(d) => {
                let path = match &d.path {
                    Some(path) => path.clone(),
                    None => self
                        .default_dir
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .as_ref()
                        .map(|dir| dir.join(name))
                        .ok_or("set `path`: no data directory is known here")?,
                };
                Store::disk(
                    name,
                    &path,
                    d.max_size.as_u64(),
                    d.max_objects,
                    self.metrics.clone(),
                )
                .map_err(|e| format!("{}: {e}", path.display()))
            }
        }
    }

    /// The store named `name`, if one was created.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&'static Store> {
        self.stores().get(name).map(|e| e.store)
    }

    /// Every store, by name.
    #[must_use]
    pub fn all(&self) -> Vec<&'static Store> {
        self.stores().values().map(|e| e.store).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rdock_model::cache::{DiskStore, MemoryStore};
    use rdock_model::values::ByteSize;

    fn memory(mib: u64) -> CacheStore {
        CacheStore::Memory(MemoryStore {
            max_size: ByteSize::mib(mib),
        })
    }

    #[test]
    fn stores_are_created_once_and_reused_across_reloads() {
        let registry = Registry::new(None);
        let first = registry.resolve(&BTreeMap::from([("a".to_owned(), memory(1))]));
        assert_eq!(first.findings, []);
        let a = first.stores["a"];
        // Same definition, plus a new store: `a` is the same object.
        let second = registry.resolve(&BTreeMap::from([
            ("a".to_owned(), memory(1)),
            ("b".to_owned(), memory(2)),
        ]));
        assert_eq!(second.findings, []);
        assert!(std::ptr::eq(a, second.stores["a"]));
        assert_eq!(registry.all().len(), 2);
        // A changed definition keeps the old store and says so; so does a removed one.
        let third = registry.resolve(&BTreeMap::from([("a".to_owned(), memory(9))]));
        assert!(std::ptr::eq(a, third.stores["a"]));
        assert_eq!(
            third.findings,
            [Finding::Changed("a".into()), Finding::Removed("b".into())]
        );
        assert!(third.findings[0].message().contains("after a restart"));
        assert!(!third.findings.iter().any(Finding::is_error));
    }

    #[test]
    fn disk_stores_need_a_path_or_a_data_directory() {
        let registry = Registry::new(None);
        let disk = CacheStore::Disk(DiskStore::default());
        let resolved = registry.resolve(&BTreeMap::from([("d".to_owned(), disk.clone())]));
        assert!(resolved.findings[0].is_error());
        let tmp = tempfile::tempdir().unwrap();
        registry.set_default_dir(tmp.path().join("cache"));
        let resolved = registry.resolve(&BTreeMap::from([("d".to_owned(), disk)]));
        assert!(resolved.findings.is_empty(), "{:?}", resolved.findings);
        assert!(tmp.path().join("cache").join("d").is_dir());
    }
}
