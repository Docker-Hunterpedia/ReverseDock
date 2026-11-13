//! Published bundles (`<data>/control/bundles/<revision>.json.zst`): the newest `history` are
//! kept. Revisions grow by one with every publication; a rollback is a new revision with an
//! earlier document.

use std::path::{Path, PathBuf};

use rdock_cluster::protocol::Bundle;

use crate::Error;

/// zstd level for stored and served bundles (the library's default).
const LEVEL: i32 = 3;

/// The bundle history.
#[derive(Debug)]
pub struct History {
    dir: PathBuf,
    keep: usize,
    /// Revisions on disk, ascending.
    revisions: Vec<u64>,
    /// The newest bundle, compressed, as served.
    latest: Option<(Bundle, Vec<u8>)>,
}

fn file_name(revision: u64) -> String {
    format!("{revision:012}.json.zst")
}

/// Compresses a bundle for storage and transfer.
pub fn compress(bundle: &Bundle) -> Result<Vec<u8>, Error> {
    let json = serde_json::to_vec(bundle).map_err(|e| Error::State(e.to_string()))?;
    zstd::encode_all(json.as_slice(), LEVEL).map_err(|e| Error::State(e.to_string()))
}

/// Decompresses a stored or received bundle, refusing more than 64 MiB of JSON.
pub fn decompress(bytes: &[u8]) -> Result<Bundle, Error> {
    use std::io::Read as _;
    let mut json = Vec::new();
    zstd::Decoder::new(bytes)
        .map_err(|e| Error::State(e.to_string()))?
        .take(64 << 20)
        .read_to_end(&mut json)
        .map_err(|e| Error::State(e.to_string()))?;
    serde_json::from_slice(&json).map_err(|e| Error::State(e.to_string()))
}

impl History {
    /// Loads the history in `dir`, keeping `keep` revisions.
    pub fn load(dir: &Path, keep: usize) -> Result<Self, Error> {
        let mut revisions = Vec::new();
        match std::fs::read_dir(dir) {
            Ok(entries) => {
                for entry in entries.flatten() {
                    if let Some(revision) = entry
                        .file_name()
                        .to_str()
                        .and_then(|n| n.strip_suffix(".json.zst"))
                        .and_then(|n| n.parse::<u64>().ok())
                    {
                        revisions.push(revision);
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(Error::State(format!("{}: {e}", dir.display()))),
        }
        revisions.sort_unstable();
        let mut history = Self {
            dir: dir.to_owned(),
            keep: keep.max(1),
            revisions,
            latest: None,
        };
        if let Some(&revision) = history.revisions.last() {
            let bytes = std::fs::read(history.dir.join(file_name(revision)))
                .map_err(|e| Error::State(e.to_string()))?;
            history.latest = Some((decompress(&bytes)?, bytes));
        }
        Ok(history)
    }

    /// The newest revision (`0` before the first publication).
    #[must_use]
    pub fn latest_revision(&self) -> u64 {
        self.latest.as_ref().map_or(0, |(b, _)| b.revision)
    }

    /// The newest bundle and its compressed form.
    #[must_use]
    pub fn latest(&self) -> Option<&(Bundle, Vec<u8>)> {
        self.latest.as_ref()
    }

    /// The bundle with `revision`, if it is still kept.
    pub fn get(&self, revision: u64) -> Result<Option<Bundle>, Error> {
        if !self.revisions.contains(&revision) {
            return Ok(None);
        }
        let bytes = std::fs::read(self.dir.join(file_name(revision)))
            .map_err(|e| Error::State(e.to_string()))?;
        decompress(&bytes).map(Some)
    }

    /// Every kept bundle, newest first.
    pub fn list(&self) -> Result<Vec<Bundle>, Error> {
        let mut out = Vec::new();
        for revision in self.revisions.iter().rev() {
            if let Some(bundle) = self.get(*revision)? {
                out.push(bundle);
            }
        }
        Ok(out)
    }

    /// Stores `bundle` (whose revision must be the next one) and forgets the oldest beyond
    /// `keep`.
    pub fn add(&mut self, bundle: Bundle) -> Result<(), Error> {
        if bundle.revision != self.latest_revision() + 1 {
            return Err(Error::State(format!(
                "revision {} does not follow {}",
                bundle.revision,
                self.latest_revision()
            )));
        }
        let bytes = compress(&bundle)?;
        rdock_cluster::dir::write_private(&self.dir.join(file_name(bundle.revision)), &bytes)
            .map_err(|e| Error::State(e.to_string()))?;
        self.revisions.push(bundle.revision);
        while self.revisions.len() > self.keep {
            let old = self.revisions.remove(0);
            let _ = std::fs::remove_file(self.dir.join(file_name(old)));
        }
        self.latest = Some((bundle, bytes));
        Ok(())
    }
}
