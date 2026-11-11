//! Secret and ConfigMap files (ADR-0029): the referenced `kubernetes.io/tls` Secrets as
//! `<data dir>/kubernetes/secrets/<namespace>/<name>/{tls.crt,tls.key}` and the referenced
//! ConfigMaps' `ca.crt` as `<data dir>/kubernetes/configmaps/<namespace>/<name>/ca.crt`.
//!
//! Directories are 0700 and files 0600; a file is replaced atomically (a temporary file in
//! the same directory, then a rename) and only when its content changed; files no longer
//! referenced are removed with the directories they leave empty. Nothing outside those two
//! trees is touched. Every replica writes its own files.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::inventory::ObjectKey;
use crate::translate::{config_map_path, secret_paths};

/// The file contents wanted below the data directory, by path.
pub(crate) type Wanted = BTreeMap<PathBuf, Vec<u8>>;

/// The files for `secrets` and `config_maps` (only those whose bytes are known; a referenced
/// Secret that is missing or incomplete gets no files, and the translator already reports
/// it).
pub(crate) fn wanted<'a>(
    data_dir: &Path,
    secrets: impl IntoIterator<Item = (&'a ObjectKey, &'a [u8], &'a [u8])>,
    config_maps: impl IntoIterator<Item = (&'a ObjectKey, &'a [u8])>,
) -> Wanted {
    let mut files = Wanted::new();
    for ((namespace, name), crt, key) in secrets {
        if !safe(namespace) || !safe(name) {
            continue;
        }
        let (crt_path, key_path) = secret_paths(data_dir, namespace, name);
        files.insert(crt_path, crt.to_vec());
        files.insert(key_path, key.to_vec());
    }
    for ((namespace, name), ca) in config_maps {
        if !safe(namespace) || !safe(name) {
            continue;
        }
        files.insert(config_map_path(data_dir, namespace, name), ca.to_vec());
    }
    files
}

/// Kubernetes object names are DNS subdomains; anything else never becomes a path.
fn safe(part: &str) -> bool {
    !part.is_empty() && !part.starts_with('.') && !part.contains(['/', '\\', '\0'])
}

/// The trees this module owns below `data_dir`.
fn roots(data_dir: &Path) -> [PathBuf; 2] {
    let base = data_dir.join("kubernetes");
    [base.join("secrets"), base.join("configmaps")]
}

/// Brings the files below `data_dir` in line with `wanted`. Returns whether any file was
/// written or removed.
pub(crate) fn materialise(data_dir: &Path, wanted: &Wanted) -> io::Result<bool> {
    let mut changed = false;
    for (path, content) in wanted {
        if write_if_changed(path, content)? {
            changed = true;
        }
    }
    let keep: BTreeSet<&Path> = wanted.keys().map(PathBuf::as_path).collect();
    for root in roots(data_dir) {
        if root.is_dir() && prune(&root, &keep, true)? {
            changed = true;
        }
    }
    Ok(changed)
}

fn create_dir(dir: &Path) -> io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir)?.permissions().mode() & 0o777;
        if mode != 0o700 {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    Ok(())
}

/// Replaces `path` with `content` unless it already holds exactly that (with mode 0600).
fn write_if_changed(path: &Path, content: &[u8]) -> io::Result<bool> {
    if let Ok(existing) = std::fs::read(path)
        && existing == content
        && mode_ok(path)
    {
        return Ok(false);
    }
    let dir = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "a file needs a directory"))?;
    create_dir(dir)?;
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let temp = dir.join(format!(".{file_name}.tmp-{:016x}", fastrand::u64(..)));
    let result = (|| {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let mut file = options.open(&temp)?;
        file.write_all(content)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result.map(|()| true)
}

#[cfg(unix)]
fn mode_ok(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).is_ok_and(|m| m.permissions().mode() & 0o777 == 0o600)
}

#[cfg(not(unix))]
fn mode_ok(_path: &Path) -> bool {
    true
}

/// Removes every file below `dir` that is not in `keep`, then the directories left empty
/// (except `dir` itself when `root`). Returns whether a file was removed.
fn prune(dir: &Path, keep: &BTreeSet<&Path>, root: bool) -> io::Result<bool> {
    let mut removed = false;
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let kind = entry.file_type()?;
        if kind.is_dir() {
            removed |= prune(&path, keep, false)?;
        } else if !keep.contains(path.as_path()) {
            std::fs::remove_file(&path)?;
            removed = true;
        }
    }
    if !root && std::fs::read_dir(dir)?.next().is_none() {
        std::fs::remove_dir(dir)?;
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(ns: &str, name: &str) -> ObjectKey {
        (ns.to_owned(), name.to_owned())
    }

    #[cfg(unix)]
    fn mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn files_are_written_private_replaced_atomically_and_cleaned_up() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path();
        let web = key("apps", "web");
        let ca = key("apps", "ca");
        let files = wanted(
            data,
            [(&web, b"CRT1".as_slice(), b"KEY1".as_slice())],
            [(&ca, b"CA1".as_slice())],
        );
        assert!(materialise(data, &files).unwrap());
        let (crt, key_file) = secret_paths(data, "apps", "web");
        assert_eq!(std::fs::read(&crt).unwrap(), b"CRT1");
        assert_eq!(std::fs::read(&key_file).unwrap(), b"KEY1");
        assert_eq!(
            std::fs::read(config_map_path(data, "apps", "ca")).unwrap(),
            b"CA1"
        );
        #[cfg(unix)]
        {
            assert_eq!(mode(&crt), 0o600);
            assert_eq!(mode(&key_file), 0o600);
            assert_eq!(mode(crt.parent().unwrap()), 0o700);
            assert_eq!(mode(&data.join("kubernetes")), 0o700);
        }

        // Unchanged: nothing is rewritten (the inode stays).
        #[cfg(unix)]
        let inode = {
            use std::os::unix::fs::MetadataExt;
            std::fs::metadata(&crt).unwrap().ino()
        };
        assert!(!materialise(data, &files).unwrap());
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(std::fs::metadata(&crt).unwrap().ino(), inode);
        }

        // Changed: replaced by a rename (new inode), no temporary file left behind.
        let files = wanted(
            data,
            [(&web, b"CRT2".as_slice(), b"KEY1".as_slice())],
            [(&ca, b"CA1".as_slice())],
        );
        assert!(materialise(data, &files).unwrap());
        assert_eq!(std::fs::read(&crt).unwrap(), b"CRT2");
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_ne!(std::fs::metadata(&crt).unwrap().ino(), inode);
        }
        let names: Vec<_> = std::fs::read_dir(crt.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names.len(), 2, "{names:?}");

        // A file with the wrong mode is rewritten.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(materialise(data, &files).unwrap());
            assert_eq!(mode(&key_file), 0o600);
        }

        // No longer referenced: files and empty directories go, other files stay.
        std::fs::write(data.join("kubernetes").join("keep-me"), b"x").unwrap();
        assert!(materialise(data, &Wanted::new()).unwrap());
        assert!(!crt.exists());
        assert!(!data.join("kubernetes/secrets/apps").exists());
        assert!(!data.join("kubernetes/configmaps/apps").exists());
        assert!(data.join("kubernetes/keep-me").exists());
        assert!(!materialise(data, &Wanted::new()).unwrap());
    }

    #[test]
    fn names_that_are_not_object_names_never_become_paths() {
        let dir = tempfile::tempdir().unwrap();
        let bad = key("..", "x");
        let files = wanted(dir.path(), [(&bad, b"a".as_slice(), b"b".as_slice())], []);
        assert!(files.is_empty());
    }
}
