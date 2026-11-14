//! One process per data directory (ADR-0031): `<data dir>/rdock.lock`, and the spool of held
//! request bodies per process.
//!
//! The lock is an advisory exclusive lock (`flock` on Unix) on the file, taken before anything
//! is written to the data directory. It belongs to the open file description, not to the file's
//! content or the process: a crashed or killed process leaves no lock behind (the file and the
//! pid in it may remain; that is not a refusal), and a binary upgrade hands the open file to the
//! next process, so the lock is held without a gap. The pid in the file is only for the message
//! a second process prints.
//!
//! Commands that only read the data directory or talk to the running process over its socket
//! (`validate`, `version`, `status`, `reload`, `healthcheck`, `audit verify`, the admin CLI)
//! never take the lock. `trust` writes the local CA's files the same way `run` does and does not
//! take it either, as before.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// The lock file's name in the data directory.
pub(crate) const LOCK_FILE: &str = "rdock.lock";
/// The data directory's format marker.
pub(crate) const FORMAT_FILE: &str = "rdock.format";
/// The data directory's format this binary reads and writes. A process refuses a data
/// directory (or a handover manifest) with a newer format, so a downgrade across a format change
/// fails before anything is touched.
pub(crate) const DATA_FORMAT: u32 = 1;

/// Refuses a data directory with a newer format than [`DATA_FORMAT`]; records the format of a
/// directory that has none yet. Call with the lock held.
pub(crate) fn check_format(dir: &Path) -> Result<(), String> {
    let path = dir.join(FORMAT_FILE);
    match std::fs::read_to_string(&path) {
        Ok(text) => match text.trim().parse::<u32>() {
            Ok(found) if found > DATA_FORMAT => Err(format!(
                "the data directory {} has format {found}, newer than this binary understands ({DATA_FORMAT}); run the newer rdock, or give this one an empty --data-dir",
                dir.display()
            )),
            Ok(_) => Ok(()),
            Err(_) => Err(format!("{} is not a format number", path.display())),
        },
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            rdock_config::state::write_atomic(&path, format!("{DATA_FORMAT}\n").as_bytes())
                .map_err(|e| format!("cannot write {}: {e}", path.display()))
        }
        Err(err) => Err(format!("cannot read {}: {err}", path.display())),
    }
}

/// The data directory, held by this process.
#[derive(Debug)]
pub(crate) struct DataDirLock {
    file: File,
    path: PathBuf,
}

/// Why the data directory could not be taken.
#[derive(Debug, thiserror::Error)]
pub(crate) enum LockError {
    /// Another process holds the lock.
    #[error(
        "another rdock{} is running with the data directory {dir}\n  hint: stop it first, or give this one its own --data-dir (RDOCK_DATA_DIR); to replace the running binary without downtime use `rdock upgrade`",
        .pid.map(|p| format!(" (pid {p})")).unwrap_or_default()
    )]
    Held {
        /// The pid written by the holder, when readable.
        pid: Option<u32>,
        /// The data directory.
        dir: PathBuf,
    },
    /// The lock file cannot be opened or locked.
    #[error("cannot lock {path}: {source}")]
    Io {
        /// The lock file.
        path: PathBuf,
        /// What the operating system said.
        source: std::io::Error,
    },
}

impl DataDirLock {
    /// Takes the lock of `dir` (created if missing) and writes this process's pid into it.
    ///
    /// # Errors
    ///
    /// Another process holds it, or the file cannot be opened.
    pub(crate) fn acquire(dir: &Path) -> Result<Self, LockError> {
        let path = dir.join(LOCK_FILE);
        let io = |source| LockError::Io {
            path: path.clone(),
            source,
        };
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let mut file = options.open(&path).map_err(io)?;
        match file.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => {
                let mut text = String::new();
                let _ = file.read_to_string(&mut text);
                return Err(LockError::Held {
                    pid: text.trim().parse().ok(),
                    dir: dir.to_owned(),
                });
            }
            Err(std::fs::TryLockError::Error(err)) => return Err(io(err)),
        }
        let lock = Self {
            file,
            path: path.clone(),
        };
        // The pid is only for the message a second process prints: a full disk must not
        // keep rdock from starting on the data it already has (ADR-0033).
        if let Err(err) = lock.write_pid() {
            tracing::warn!(file = %path.display(), error = %err, "cannot write the pid into the lock file; the lock is held all the same");
        }
        Ok(lock)
    }

    /// The lock handed over by the previous process: the same open file, already locked.
    pub(crate) fn adopt(file: File, dir: &Path) -> Self {
        Self {
            file,
            path: dir.join(LOCK_FILE),
        }
    }

    /// Writes this process's pid into the file (after a handover, the new process's).
    pub(crate) fn write_pid(&self) -> std::io::Result<()> {
        let mut file = &self.file;
        file.set_len(0)?;
        file.seek(SeekFrom::Start(0))?;
        writeln!(file, "{}", std::process::id())?;
        file.flush()
    }

    /// The open lock file, to hand to the next process.
    pub(crate) fn file(&self) -> &File {
        &self.file
    }

    /// The lock file's path.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

/// The spool directory of this process: `<data dir>/spool/<pid>`.
pub(crate) fn spool_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("spool").join(std::process::id().to_string())
}

/// Removes everything in `<data dir>/spool` (directories of earlier processes, and files of
/// versions before v0.9 that spooled into the directory itself). Only called by a process that
/// took the lock fresh, so no live process owns any of it.
pub(crate) fn clean_spool(data_dir: &Path) {
    let spool = data_dir.join("spool");
    let Ok(entries) = std::fs::read_dir(&spool) else {
        return;
    };
    let mut removed = 0usize;
    for entry in entries.flatten() {
        let path = entry.path();
        let result = if entry.file_type().is_ok_and(|t| t.is_dir()) {
            std::fs::remove_dir_all(&path)
        } else {
            std::fs::remove_file(&path)
        };
        match result {
            Ok(()) => removed += 1,
            Err(err) => {
                tracing::warn!(path = %path.display(), error = %err, "cannot remove a leftover spool entry");
            }
        }
    }
    if removed > 0 {
        tracing::info!(removed, path = %spool.display(), "removed spool entries of earlier runs");
    }
}

/// Removes this process's spool directory at a clean exit.
pub(crate) fn remove_own_spool(data_dir: &Path) {
    let dir = spool_dir(data_dir);
    match std::fs::remove_dir_all(&dir) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            tracing::warn!(path = %dir.display(), error = %err, "cannot remove the spool directory");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_second_lock_is_refused_with_the_holders_pid_and_released_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        let first = DataDirLock::acquire(dir.path()).unwrap();
        let err = DataDirLock::acquire(dir.path()).unwrap_err();
        assert!(
            err.to_string()
                .contains(&format!("(pid {})", std::process::id())),
            "{err}"
        );
        drop(first);
        // The file and its pid stay; only the kernel's lock matters.
        assert!(dir.path().join(LOCK_FILE).exists());
        let again = DataDirLock::acquire(dir.path()).unwrap();
        assert_eq!(again.path(), dir.path().join(LOCK_FILE));
    }

    #[test]
    fn a_newer_data_format_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        check_format(dir.path()).unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.path().join(FORMAT_FILE))
                .unwrap()
                .trim(),
            DATA_FORMAT.to_string()
        );
        std::fs::write(
            dir.path().join(FORMAT_FILE),
            format!("{}\n", DATA_FORMAT + 1),
        )
        .unwrap();
        assert!(
            check_format(dir.path())
                .unwrap_err()
                .contains("newer than this binary")
        );
    }

    #[test]
    fn a_stale_pid_in_the_file_is_not_a_refusal() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(LOCK_FILE), "1\n").unwrap();
        let lock = DataDirLock::acquire(dir.path()).unwrap();
        let text = std::fs::read_to_string(lock.path()).unwrap();
        assert_eq!(text.trim(), std::process::id().to_string());
    }

    #[test]
    fn spools_are_per_process_and_cleaned_only_on_a_fresh_start() {
        let dir = tempfile::tempdir().unwrap();
        let other = dir.path().join("spool/999999");
        std::fs::create_dir_all(&other).unwrap();
        std::fs::write(other.join("body-999999-0"), "held").unwrap();
        // Another process's spool is untouched by opening ours.
        let ours = spool_dir(dir.path());
        rdock_middleware::Spool::open(&ours).unwrap();
        assert!(other.join("body-999999-0").exists());
        remove_own_spool(dir.path());
        assert!(!ours.exists());
        assert!(other.exists());
        // A fresh start (the lock taken without a live predecessor) removes leftovers.
        std::fs::write(dir.path().join("spool/legacy-file"), "").unwrap();
        clean_spool(dir.path());
        assert_eq!(
            std::fs::read_dir(dir.path().join("spool")).unwrap().count(),
            0
        );
    }
}
