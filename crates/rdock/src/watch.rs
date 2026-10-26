//! Reload on file changes: the configuration file and the files it refers to. Directories are
//! watched rather than files, so editors that replace files and Kubernetes `ConfigMap` updates
//! (a `..data` symlink swap) are seen; events are debounced.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use notify::event::ModifyKind;
use notify::{EventKind, RecursiveMode};
use notify_debouncer_full::{DebounceEventResult, Debouncer, RecommendedCache, new_debouncer};
use tokio::sync::mpsc;

const DEBOUNCE: Duration = Duration::from_millis(250);

/// Watches a set of files and signals `changes` when one of them changes.
pub(crate) struct FileWatcher {
    debouncer: Debouncer<notify::RecommendedWatcher, RecommendedCache>,
    files: Arc<Mutex<BTreeSet<PathBuf>>>,
    dirs: BTreeSet<PathBuf>,
}

/// The path as the operating system reports it in events: the directory canonicalised (on
/// macOS `/var` is a symlink to `/private/var`), the file name kept.
fn absolute(path: &Path) -> PathBuf {
    let path = std::path::absolute(path).unwrap_or_else(|_| path.to_owned());
    let canonical = path
        .parent()
        .zip(path.file_name())
        .and_then(|(dir, name)| std::fs::canonicalize(dir).ok().map(|d| d.join(name)));
    canonical.unwrap_or(path)
}

impl FileWatcher {
    pub(crate) fn start(changes: mpsc::Sender<()>) -> notify::Result<Self> {
        let files: Arc<Mutex<BTreeSet<PathBuf>>> = Arc::default();
        let watched = files.clone();
        let debouncer = new_debouncer(DEBOUNCE, None, move |result: DebounceEventResult| {
            let Ok(events) = result else { return };
            let files = watched.lock().unwrap_or_else(PoisonError::into_inner);
            // Reading a file (which every reload does) produces access and metadata events on
            // Linux; only content, name and existence changes matter.
            let content_events = events.iter().filter(|e| {
                matches!(
                    e.kind,
                    EventKind::Create(_)
                        | EventKind::Remove(_)
                        | EventKind::Modify(
                            ModifyKind::Data(_) | ModifyKind::Name(_) | ModifyKind::Any
                        )
                        | EventKind::Any
                )
            });
            let relevant = content_events.flat_map(|e| e.paths.iter()).any(|path| {
                files.contains(path)
                    || path
                        .file_name()
                        .is_some_and(|n| n.to_string_lossy().starts_with(".."))
            });
            if relevant {
                // A full queue already holds a pending reload.
                let _ = changes.try_send(());
            }
        })?;
        Ok(Self {
            debouncer,
            files,
            dirs: BTreeSet::new(),
        })
    }

    /// Watches exactly `files` from now on.
    pub(crate) fn set_files(&mut self, files: &BTreeSet<PathBuf>) {
        let files: BTreeSet<PathBuf> = files.iter().map(|f| absolute(f)).collect();
        let dirs: BTreeSet<PathBuf> = files
            .iter()
            .filter_map(|f| f.parent().map(Path::to_owned))
            .collect();
        for gone in self.dirs.difference(&dirs) {
            let _ = self.debouncer.unwatch(gone);
        }
        for new in dirs.difference(&self.dirs) {
            if let Err(err) = self.debouncer.watch(new, RecursiveMode::NonRecursive) {
                tracing::warn!(dir = %new.display(), error = %err, "cannot watch for changes");
            }
        }
        self.dirs = dirs;
        *self.files.lock().unwrap_or_else(PoisonError::into_inner) = files;
    }
}
