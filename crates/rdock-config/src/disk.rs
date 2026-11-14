//! Free space in the data directory and what a full disk means for a write (ADR-0033, "the
//! disk-full rules"): how much room a directory has, a check before a write whose failure
//! would cost more than the write (an ACME order), space reserved ahead of an append (the audit
//! log), and which write errors mean "out of space".
//!
//! "Room" is the smaller of the space the file system offers an unprivileged writer
//! (`statvfs` `f_bavail`) and the process's file-size limit (`RLIMIT_FSIZE`), since either
//! stops a write: `ENOSPC` or `EDQUOT` for the first, `EFBIG` for the second.

use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

/// What the file system holding a directory offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Space {
    /// Bytes an unprivileged process may still write (`f_bavail × f_frsize`), capped by the
    /// process's file-size limit.
    pub available: u64,
    /// Size of the file system (`f_blocks × f_frsize`).
    pub total: u64,
}

impl Space {
    /// Free space as a share of the total, from 0 to 100.
    #[must_use]
    pub fn free_percent(&self) -> f64 {
        if self.total == 0 {
            return 100.0;
        }
        #[allow(clippy::cast_precision_loss)]
        let share = self.available as f64 / self.total as f64 * 100.0;
        share.clamp(0.0, 100.0)
    }
}

/// The space of the file system that holds `dir`, or of its nearest existing parent (a data
/// directory that is not created yet still has a file system).
///
/// # Errors
///
/// `statvfs` fails on every ancestor.
pub fn space(dir: &Path) -> io::Result<Space> {
    let mut at: PathBuf = dir.to_owned();
    let stat = loop {
        match rustix::fs::statvfs(&at) {
            Ok(stat) => break stat,
            Err(err) => {
                if !at.pop() {
                    return Err(err.into());
                }
            }
        }
    };
    let available = stat.f_bavail.saturating_mul(stat.f_frsize);
    let total = stat.f_blocks.saturating_mul(stat.f_frsize);
    Ok(Space {
        available: available.min(file_size_limit().unwrap_or(u64::MAX)),
        total,
    })
}

/// The process's file-size limit (`RLIMIT_FSIZE`) in bytes, when one is set.
#[must_use]
pub fn file_size_limit() -> Option<u64> {
    rustix::process::getrlimit(rustix::process::Resource::Fsize).current
}

/// Why a write was not started.
#[derive(Debug, thiserror::Error)]
pub enum NoRoom {
    /// Less room than the write needs.
    #[error(
        "{dir} has {available} bytes free, fewer than the {needed} bytes this write needs; free some space"
    )]
    Short {
        /// The directory.
        dir: String,
        /// What it has.
        available: u64,
        /// What the write needs.
        needed: u64,
    },
    /// The free space could not be read.
    #[error("cannot read the free space of {dir}: {source}")]
    Unknown {
        /// The directory.
        dir: String,
        /// Why.
        source: io::Error,
    },
}

/// Checks that the file system of `dir` has at least `needed` bytes of room.
///
/// # Errors
///
/// [`NoRoom::Short`] when it has less, [`NoRoom::Unknown`] when the space cannot be read.
pub fn check_room(dir: &Path, needed: u64) -> Result<Space, NoRoom> {
    let space = space(dir).map_err(|source| NoRoom::Unknown {
        dir: dir.display().to_string(),
        source,
    })?;
    if space.available < needed {
        return Err(NoRoom::Short {
            dir: dir.display().to_string(),
            available: space.available,
            needed,
        });
    }
    Ok(space)
}

/// Reserves `len` bytes of `file` from `offset` on without changing its size
/// (`fallocate(FALLOC_FL_KEEP_SIZE)`), so later appends into that range cannot fail for lack
/// of space. Returns `false` when the file system cannot reserve (`EOPNOTSUPP`): the caller
/// then relies on a free-space check ([`check_room`]).
///
/// # Errors
///
/// The reservation failed for another reason, typically `ENOSPC` or `EFBIG`.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn reserve(file: &File, offset: u64, len: u64) -> io::Result<bool> {
    match rustix::fs::fallocate(file, rustix::fs::FallocateFlags::KEEP_SIZE, offset, len) {
        Ok(()) => Ok(true),
        Err(err) if err == rustix::io::Errno::OPNOTSUPP || err == rustix::io::Errno::NOSYS => {
            Ok(false)
        }
        Err(err) => Err(err.into()),
    }
}

/// Other systems (macOS) have no `FALLOC_FL_KEEP_SIZE`: nothing is reserved, and the caller
/// relies on the free-space check, as on a file system that cannot reserve.
///
/// # Errors
///
/// Never on these systems.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn reserve(_file: &File, _offset: u64, _len: u64) -> io::Result<bool> {
    Ok(false)
}

/// Whether `err` means the disk (or the quota, or the file-size limit) is full: `ENOSPC`,
/// `EDQUOT` or `EFBIG`. Callers treat any write error the same way; this only picks the
/// wording and the metric label.
#[must_use]
pub fn is_out_of_space(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::StorageFull | io::ErrorKind::QuotaExceeded | io::ErrorKind::FileTooLarge
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_directory_reports_the_space_of_its_parent() {
        let dir = tempfile::tempdir().unwrap();
        let here = space(dir.path()).unwrap();
        let below = space(&dir.path().join("not/yet/created")).unwrap();
        assert_eq!(here.total, below.total);
        assert!(here.total > 0);
        assert!(here.free_percent() <= 100.0);
    }

    #[test]
    fn a_check_names_what_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        assert!(check_room(dir.path(), 1).is_ok());
        let err = check_room(dir.path(), u64::MAX).unwrap_err();
        assert!(err.to_string().contains("fewer than the"), "{err}");
    }

    #[test]
    fn reserving_keeps_the_size() {
        let dir = tempfile::tempdir().unwrap();
        let file = File::create(dir.path().join("f")).unwrap();
        let _reserved = reserve(&file, 0, 64 * 1024).unwrap();
        assert_eq!(file.metadata().unwrap().len(), 0);
    }

    #[test]
    fn out_of_space_errors_are_recognised() {
        for errno in [28, 122, 27] {
            assert!(
                is_out_of_space(&io::Error::from_raw_os_error(errno)),
                "{errno}"
            );
        }
        assert!(!is_out_of_space(&io::Error::from_raw_os_error(13)));
    }
}
