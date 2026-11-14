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
    /// The API provider's objects at the time (ADR-0024), restored by a rollback.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api: Option<Value>,
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
        let staged = self.stage_history(entry)?;
        let path = staged.path().to_owned();
        staged.commit()?;
        self.prune_history(keep)?;
        Ok(path)
    }

    /// Writes a history entry next to its place without adding it yet ([`stage`]).
    pub fn stage_history(&self, entry: &HistoryEntry) -> io::Result<Staged> {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        entry.source.to_string().hash(&mut hasher);
        entry.api.as_ref().map(Value::to_string).hash(&mut hasher);
        let path = self.history_dir().join(format!(
            "{:013}-{:016x}.json",
            entry.applied_at_ms,
            hasher.finish()
        ));
        stage(&path, &serde_json::to_vec_pretty(entry)?)
    }

    /// Writes a provider snapshot next to its place without replacing the stored one yet.
    pub fn stage_snapshot(&self, snapshot: &Snapshot) -> io::Result<Staged> {
        stage(
            &self.snapshot_path(&snapshot.provider),
            &serde_json::to_vec_pretty(snapshot)?,
        )
    }

    /// Removes the oldest history entries beyond `keep`.
    pub fn prune_history(&self, keep: usize) -> io::Result<()> {
        let dir = self.history_dir();
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
        Ok(())
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
/// readers see either the old or the new file. Files are readable by the owner only. A write
/// that fails (a full disk) removes its temporary file and leaves `path` as it was.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    stage(path, bytes)?.commit()
}

/// Writes `bytes` to the temporary file of `path` and syncs it, without replacing `path`:
/// [`Staged::commit`] renames it into place, dropping the [`Staged`] removes it. A
/// configuration change stages its stored copies first and commits them only after the data
/// plane took the change, so a change that cannot be stored is refused before it is applied
/// and one the data plane refuses leaves the stored copies untouched (ADR-0033).
///
/// # Errors
///
/// The directory cannot be created, or the temporary file cannot be written in full; nothing
/// is left behind then.
pub fn stage(path: &Path, bytes: &[u8]) -> io::Result<Staged> {
    let dir = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?;
    fs::create_dir_all(dir)?;
    let file_name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;
    let tmp = dir.join(format!(".{}.tmp", file_name.to_string_lossy()));
    let staged = Staged {
        tmp,
        path: path.to_owned(),
        done: false,
    };
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(&staged.tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(staged)
}

/// A file written next to its place and not yet renamed into it; removed when dropped
/// uncommitted.
#[derive(Debug)]
pub struct Staged {
    tmp: PathBuf,
    path: PathBuf,
    done: bool,
}

impl Staged {
    /// The file it will replace.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Renames the staged file into place and syncs the directory. A rename needs no new
    /// space, so this does not fail on a full disk.
    ///
    /// # Errors
    ///
    /// The rename failed; the staged file is removed and `path` is unchanged.
    pub fn commit(mut self) -> io::Result<()> {
        fs::rename(&self.tmp, &self.path)?;
        self.done = true;
        if let Some(dir) = self.path.parent()
            && let Ok(dir) = fs::File::open(dir)
        {
            // Durability of the rename; the data itself was synced before.
            let _ = dir.sync_all();
        }
        Ok(())
    }
}

impl Drop for Staged {
    fn drop(&mut self) {
        if !self.done {
            let _ = fs::remove_file(&self.tmp);
        }
    }
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
            api: None,
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
            revision: None,
        };
        state.save_snapshot(&snapshot).unwrap();
        assert_eq!(state.load_snapshot("docker").unwrap(), Some(snapshot));
    }

    #[test]
    fn a_staged_write_changes_nothing_until_committed() {
        let dir = tempfile::tempdir().unwrap();
        let state = StateDir::new(dir.path());
        state.save_lkg(&serde_json::json!({ "a": 1 })).unwrap();
        let staged = stage(&dir.path().join("state/lkg.json"), b"{\"a\": 2}").unwrap();
        assert_eq!(
            state.load_lkg().unwrap(),
            Some(serde_json::json!({ "a": 1 }))
        );
        drop(staged);
        assert_eq!(
            state.load_lkg().unwrap(),
            Some(serde_json::json!({ "a": 1 }))
        );
        let leftovers: Vec<_> = fs::read_dir(dir.path().join("state"))
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "a dropped stage leaves no file");
        stage(&dir.path().join("state/lkg.json"), b"{\"a\": 2}")
            .unwrap()
            .commit()
            .unwrap();
        assert_eq!(
            state.load_lkg().unwrap(),
            Some(serde_json::json!({ "a": 2 }))
        );
        let entry = entry(5, 5);
        let staged = state.stage_history(&entry).unwrap();
        assert!(
            state.history().unwrap().is_empty(),
            "not listed while staged"
        );
        staged.commit().unwrap();
        assert_eq!(state.history().unwrap(), vec![entry]);
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
