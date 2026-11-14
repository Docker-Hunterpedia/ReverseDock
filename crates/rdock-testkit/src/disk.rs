//! A full disk for the chaos suite (ADR-0033), two ways:
//!
//! - [`Tmpfs`]: a size-limited tmpfs mounted for one test (root, or passwordless `sudo` as on
//!   GitHub-hosted runners), filled with a ballast file until writes fail with **`ENOSPC`**,
//!   and freed by removing the ballast. This is the real thing; the `chaos` CI job uses it.
//! - [`limit_file_size`]: the running rdock's file-size limit (`RLIMIT_FSIZE`) set to zero
//!   with `prlimit`, so every write that extends a regular file fails with **`EFBIG`**. No
//!   privileges; the rootless variant in the required `rust` job. It does not lower the free
//!   space `statvfs` reports, but rdock counts the limit as no room (`rdock_config::disk`), so
//!   the free-space checks see it too. Writes that do not extend a file still succeed, as on a
//!   full tmpfs for blocks already allocated.
//!
//! [`mechanism`] picks one from `RDOCK_CHAOS_DISK` (`tmpfs` or `rlimit`, default `rlimit`).
//! No test fills a file system other than the tmpfs it mounted.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use tempfile::TempDir;

/// How a test makes the disk full.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mechanism {
    /// A dedicated tmpfs filled until `ENOSPC`.
    Tmpfs,
    /// `RLIMIT_FSIZE` = 0 on the rdock process: `EFBIG`.
    FileSizeLimit,
}

/// The mechanism `RDOCK_CHAOS_DISK` asks for (`tmpfs`, `rlimit`; default `rlimit`).
pub fn mechanism() -> Mechanism {
    match std::env::var("RDOCK_CHAOS_DISK").as_deref() {
        Ok("tmpfs") => Mechanism::Tmpfs,
        _ => Mechanism::FileSizeLimit,
    }
}

fn root() -> bool {
    rustix::process::geteuid().is_root()
}

fn privileged(args: &[&str]) -> std::io::Result<std::process::Output> {
    if root() {
        Command::new(args[0]).args(&args[1..]).output()
    } else {
        Command::new("sudo").arg("-n").args(args).output()
    }
}

/// A tmpfs mounted for one test, unmounted when dropped.
pub struct Tmpfs {
    _dir: TempDir,
    mount: PathBuf,
    ballast: PathBuf,
}

impl Tmpfs {
    /// Mounts a tmpfs of `size` bytes owned by this user. `Err` says why it cannot (no root
    /// and no passwordless `sudo`).
    pub fn mount(size: u64) -> Result<Self, String> {
        let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
        let mount = dir.path().join("fs");
        std::fs::create_dir(&mount).map_err(|e| e.to_string())?;
        let uid = rustix::process::getuid().as_raw();
        let gid = rustix::process::getgid().as_raw();
        let options = format!("size={size},mode=0700,uid={uid},gid={gid}");
        let out = privileged(&[
            "mount",
            "-t",
            "tmpfs",
            "-o",
            &options,
            "tmpfs",
            mount.to_str().ok_or("not UTF-8")?,
        ])
        .map_err(|e| format!("mount: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "cannot mount a tmpfs (root or passwordless sudo needed): {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        let ballast = mount.join(".ballast");
        Ok(Self {
            _dir: dir,
            mount,
            ballast,
        })
    }

    /// The mounted directory.
    pub fn path(&self) -> &Path {
        &self.mount
    }

    /// Fills the file system with the ballast file until a write fails with `ENOSPC`.
    pub fn fill(&self) {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.ballast)
            .unwrap();
        let chunk = vec![0u8; 4096];
        loop {
            match file.write(&chunk) {
                Ok(0) => break,
                Ok(_) => {}
                Err(e) => {
                    assert_eq!(e.raw_os_error(), Some(28), "filling stopped with {e}");
                    break;
                }
            }
        }
        let _ = file.sync_all();
    }

    /// Removes the ballast: the space is back.
    pub fn free(&self) {
        let _ = std::fs::remove_file(&self.ballast);
    }

    /// Bytes still free.
    pub fn available(&self) -> u64 {
        let stat = rustix::fs::statvfs(&self.mount).unwrap();
        stat.f_bavail * stat.f_frsize
    }
}

impl Drop for Tmpfs {
    fn drop(&mut self) {
        if let Some(path) = self.mount.to_str() {
            let _ = privileged(&["umount", "-l", path]);
        }
    }
}

/// Sets the file-size limit of process `pid`: `Some(0)` makes every write that extends a file
/// fail with `EFBIG` (rdock catches the SIGXFSZ that comes with it), `None` lifts it.
pub fn limit_file_size(pid: u32, limit: Option<u64>) {
    let pid = rustix::process::Pid::from_raw(i32::try_from(pid).unwrap()).unwrap();
    rustix::process::prlimit(
        Some(pid),
        rustix::process::Resource::Fsize,
        rustix::process::Rlimit {
            current: limit,
            maximum: None,
        },
    )
    .unwrap();
}
