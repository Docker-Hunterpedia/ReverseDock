//! Applied configurations on disk: the last-known-good copy and a bounded history, both under
//! `$RDOCK_DATA_DIR/state`. Entries hold the document as written (references unresolved). The
//! last snapshot of each provider is kept next to them (`providers/<name>.json`).

use std::fs;
use std::hash::{Hash, Hasher};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::merge::Snapshot;

/// History entries kept by default.
pub const HISTORY_LIMIT: usize = 50;

/// One applied configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HistoryEntry {
    /// When it was applied, in milliseconds since the Unix epoch.
    pub applied_at_ms: u64,
    /// Generation number of the running process.
    pub generation: u64,
    /// What changed compared with the previous configuration.
    pub summary: String,
    /// The document as written.
    pub source: Value,
}

/// The `state` directory.
#[derive(Debug, Clone)]
pub struct StateDir {
    root: PathBuf,
}

impl StateDir {
    /// The state directory inside `data_dir`. Nothing is created until something is written.
    #[must_use]
    pub fn new(data_dir: &Path) -> Self {
        Self {
            root: data_dir.join("state"),
        }
    }

    fn lkg_path(&self) -> PathBuf {
        self.root.join("lkg.json")
    }

    fn history_dir(&self) -> PathBuf {
        self.root.join("history")
    }

    /// Stores `source` as the last-known-good configuration.
    pub fn save_lkg(&self, source: &Value) -> io::Result<()> {
        write_atomic(&self.lkg_path(), &serde_json::to_vec_pretty(source)?)
    }

    /// The last-known-good configuration, if one was stored.
    pub fn load_lkg(&self) -> io::Result<Option<Value>> {
        match fs::read(self.lkg_path()) {
            Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err),
        }
    }

    fn snapshot_path(&self, provider: &str) -> PathBuf {
        self.root.join("providers").join(format!("{provider}.json"))
    }

    /// Stores a provider's last applied snapshot, served at the next start until the provider
    /// reports again (ADR-0018).
    pub fn save_snapshot(&self, snapshot: &Snapshot) -> io::Result<()> {
        write_atomic(
            &self.snapshot_path(&snapshot.provider),
            &serde_json::to_vec_pretty(snapshot)?,
        )
    }

    /// The stored snapshot of `provider`, if any.
    pub fn load_snapshot(&self, provider: &str) -> io::Result<Option<Snapshot>> {
        match fs::read(self.snapshot_path(provider)) {
            Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err),
        }
    }

    /// Adds a history entry and removes the oldest ones beyond `keep`.
    pub fn record(&self, entry: &HistoryEntry, keep: usize) -> io::Result<PathBuf> {
        let dir = self.history_dir();
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        entry.source.to_string().hash(&mut hasher);
        let path = dir.join(format!(
            "{:013}-{:016x}.json",
            entry.applied_at_ms,
            hasher.finish()
        ));
        write_atomic(&path, &serde_json::to_vec_pretty(entry)?)?;
        let mut names: Vec<PathBuf> = fs::read_dir(&dir)?
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|e| e == "json"))
            .collect();
        names.sort();
        let excess = names.len().saturating_sub(keep);
        for old in &names[..excess] {
            fs::remove_file(old)?;
        }
        Ok(path)
    }

    /// History entries, oldest first.
    pub fn history(&self) -> io::Result<Vec<HistoryEntry>> {
        let mut paths: Vec<PathBuf> = match fs::read_dir(self.history_dir()) {
            Ok(dir) => dir.filter_map(Result::ok).map(|e| e.path()).collect(),
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(err) => return Err(err),
        };
        paths.retain(|p| p.extension().is_some_and(|e| e == "json"));
        paths.sort();
        paths
            .iter()
            .map(|p| Ok(serde_json::from_slice(&fs::read(p)?)?))
            .collect()
    }
}

/// Writes `bytes` to a temporary file next to `path`, syncs it and renames it into place, so
/// readers see either the old or the new file. Files are readable by the owner only.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?;
    fs::create_dir_all(dir)?;
    let file_name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;
    let tmp = dir.join(format!(".{}.tmp", file_name.to_string_lossy()));
    let mut options = fs::OpenOptions::new();
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

    fn entry(at: u64, n: u64) -> HistoryEntry {
        HistoryEntry {
            applied_at_ms: at,
            generation: n,
            summary: format!("generation {n}"),
            source: serde_json::json!({ "routes": { format!("r{n}"): {} } }),
        }
    }

    #[test]
    fn stores_and_loads_the_last_known_good_copy() {
        let dir = tempfile::tempdir().unwrap();
        let state = StateDir::new(dir.path());
        assert_eq!(state.load_lkg().unwrap(), None);
        let source = serde_json::json!({ "services": {} });
        state.save_lkg(&source).unwrap();
        assert_eq!(state.load_lkg().unwrap(), Some(source));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(dir.path().join("state/lkg.json"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn stores_and_loads_provider_snapshots() {
        let dir = tempfile::tempdir().unwrap();
        let state = StateDir::new(dir.path());
        assert_eq!(state.load_snapshot("docker").unwrap(), None);
        let snapshot = Snapshot {
            provider: "docker".to_owned(),
            fragment: crate::merge::Fragment::default(),
            diagnostics: vec![rdock_model::Diagnostic::warning("x", "y")],
        };
        state.save_snapshot(&snapshot).unwrap();
        assert_eq!(state.load_snapshot("docker").unwrap(), Some(snapshot));
    }

    #[test]
    fn keeps_a_bounded_history_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let state = StateDir::new(dir.path());
        for n in 1..=5 {
            state.record(&entry(1_000 + n, n), 3).unwrap();
        }
        let history = state.history().unwrap();
        let generations: Vec<u64> = history.iter().map(|e| e.generation).collect();
        assert_eq!(generations, vec![3, 4, 5]);
    }
}
