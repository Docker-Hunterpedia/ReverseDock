//! The served directory, opened once, and the lookup of a request in it. Everything here
//! blocks and runs on the blocking pool.
//!
//! With `symlinks: none` and `within_root` the directory is a cap-std handle: every path is
//! resolved beneath it (`openat2` with `RESOLVE_BENEATH` on Linux 5.6+, component by component
//! elsewhere), so no request can leave it, whatever the path or the links in the tree say.
//! `none` also refuses any path with a symbolic link in it. `all` uses plain paths and follows
//! every link.

use std::fs::{File, Metadata};
use std::io;
use std::path::{Path, PathBuf};

use cap_std::ambient_authority;
use cap_std::fs::Dir;
use rdock_model::middleware::{CompressAlgorithm, SymlinkPolicy};

use super::path::SafePath;
use crate::BuildError;

/// The served directory.
#[derive(Debug)]
pub(crate) enum Root {
    /// A directory handle nothing can be resolved out of.
    Sandboxed {
        dir: Dir,
        /// Follow links that stay inside (`within_root`); otherwise refuse every link.
        follow_links: bool,
    },
    /// `symlinks: all`: plain paths under the directory.
    Ambient(PathBuf),
}

/// What a lookup needs besides the request path.
#[derive(Debug)]
pub(crate) struct Lookup {
    pub(crate) path: SafePath,
    /// Codings the client accepts that have sidecars, best first.
    pub(crate) codings: Vec<CompressAlgorithm>,
    /// File (relative to the root) answered when nothing else is found.
    pub(crate) fallback: Option<String>,
}

/// Directory settings of a lookup.
#[derive(Debug)]
pub(crate) struct Directories {
    pub(crate) index: Vec<String>,
    pub(crate) redirect: bool,
}

/// An open file chosen for a request.
#[derive(Debug)]
pub(crate) struct Found {
    pub(crate) file: File,
    pub(crate) metadata: Metadata,
    /// Path of the file as built, relative to the root (a sidecar's name without its suffix).
    pub(crate) served: String,
    /// The sidecar's coding, when one is sent.
    pub(crate) coding: Option<CompressAlgorithm>,
}

/// The outcome of a lookup.
#[derive(Debug)]
pub(crate) enum Resolution {
    /// Boxed: `Metadata` is large on Linux.
    File(Box<Found>),
    /// A directory with an index, named without its trailing slash.
    AddSlash,
    Missing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    File,
    Dir,
    Other,
}

/// Where a request path leads before sidecars and fallback.
enum Located {
    File(String),
    Index(String),
    Nothing,
}

/// The file name suffix of a sidecar.
fn sidecar_suffix(coding: CompressAlgorithm) -> &'static str {
    match coding {
        CompressAlgorithm::Zstd => ".zst",
        CompressAlgorithm::Br => ".br",
        CompressAlgorithm::Gzip => ".gz",
    }
}

fn not_found(why: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, why)
}

impl Root {
    /// Opens `path`, which must be a directory.
    pub(crate) fn open(path: &Path, symlinks: SymlinkPolicy) -> Result<Self, BuildError> {
        let file_error = |source| BuildError::File {
            path: path.to_owned(),
            source,
        };
        if !std::fs::metadata(path).map_err(file_error)?.is_dir() {
            return Err(BuildError::Invalid(format!(
                "`{}` is not a directory",
                path.display()
            )));
        }
        Ok(match symlinks {
            SymlinkPolicy::All => Self::Ambient(path.to_owned()),
            SymlinkPolicy::None | SymlinkPolicy::WithinRoot => Self::Sandboxed {
                dir: Dir::open_ambient_dir(path, ambient_authority()).map_err(file_error)?,
                follow_links: symlinks == SymlinkPolicy::WithinRoot,
            },
        })
    }

    /// Finds the file for a request: the file itself, a directory's index, or the fallback,
    /// with the best sidecar the client accepts.
    pub(crate) fn resolve(&self, lookup: &Lookup, directories: &Directories) -> Resolution {
        let path = &lookup.path;
        let plain = match self.locate(path, &directories.index) {
            Located::Index(_) if !path.trailing_slash && directories.redirect => {
                return Resolution::AddSlash;
            }
            Located::File(relative) | Located::Index(relative) => relative,
            Located::Nothing => match &lookup.fallback {
                Some(fallback) => fallback.clone(),
                None => return Resolution::Missing,
            },
        };
        self.open_with_sidecar(plain, &lookup.codings)
    }

    fn locate(&self, path: &SafePath, index: &[String]) -> Located {
        match self.kind(&path.relative) {
            Ok(Kind::File) if !path.trailing_slash => Located::File(path.relative.clone()),
            Ok(Kind::Dir) => index
                .iter()
                .map(|name| path.child(name))
                .find(|relative| matches!(self.kind(relative), Ok(Kind::File)))
                .map_or(Located::Nothing, Located::Index),
            _ => Located::Nothing,
        }
    }

    fn open_with_sidecar(&self, plain: String, codings: &[CompressAlgorithm]) -> Resolution {
        let Ok((file, metadata)) = self.open_file(&plain) else {
            return Resolution::Missing;
        };
        for coding in codings {
            let sidecar = format!("{plain}{}", sidecar_suffix(*coding));
            if let Ok((file, metadata)) = self.open_file(&sidecar) {
                return Resolution::File(Box::new(Found {
                    file,
                    metadata,
                    served: plain,
                    coding: Some(*coding),
                }));
            }
        }
        Resolution::File(Box::new(Found {
            file,
            metadata,
            served: plain,
            coding: None,
        }))
    }

    /// What `relative` is, following the links the policy allows.
    fn kind(&self, relative: &str) -> io::Result<Kind> {
        let (is_file, is_dir) = match self {
            Self::Sandboxed { dir, follow_links } => {
                if !follow_links {
                    refuse_links(dir, relative)?;
                }
                let metadata = dir.metadata(or_dot(relative))?;
                (metadata.is_file(), metadata.is_dir())
            }
            Self::Ambient(root) => {
                let metadata = std::fs::metadata(root.join(relative))?;
                (metadata.is_file(), metadata.is_dir())
            }
        };
        Ok(match (is_file, is_dir) {
            (true, _) => Kind::File,
            (_, true) => Kind::Dir,
            _ => Kind::Other,
        })
    }

    /// Opens a regular file. Anything else (a directory, a FIFO that would block, a device)
    /// counts as missing.
    fn open_file(&self, relative: &str) -> io::Result<(File, Metadata)> {
        if self.kind(relative)? != Kind::File {
            return Err(not_found("not a regular file"));
        }
        let file = match self {
            Self::Sandboxed { dir, .. } => dir.open(relative)?.into_std(),
            Self::Ambient(root) => File::open(root.join(relative))?,
        };
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(not_found("not a regular file"));
        }
        Ok((file, metadata))
    }
}

/// `relative`, or `.` for the root itself.
fn or_dot(relative: &str) -> &str {
    if relative.is_empty() { "." } else { relative }
}

/// Fails when any component of `relative` is a symbolic link. Resolution stays beneath the
/// handle anyway, so a link swapped in after this check still cannot lead out of the root.
fn refuse_links(dir: &Dir, relative: &str) -> io::Result<()> {
    let ends = relative
        .match_indices('/')
        .map(|(i, _)| i)
        .chain((!relative.is_empty()).then_some(relative.len()));
    for end in ends {
        if dir.symlink_metadata(&relative[..end])?.is_symlink() {
            return Err(not_found("symbolic link"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use rdock_model::middleware::HiddenFiles;

    use super::*;

    struct Tree {
        _outside: tempfile::TempDir,
        root: tempfile::TempDir,
    }

    /// `root/` with files, a directory with an index, links in and out, and a file outside.
    fn tree() -> Tree {
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret.txt"), "secret").unwrap();
        let root = tempfile::tempdir().unwrap();
        let r = root.path();
        std::fs::write(r.join("index.html"), "home").unwrap();
        std::fs::write(r.join("app.js"), "plain").unwrap();
        std::fs::write(r.join("app.js.br"), "brotli").unwrap();
        std::fs::write(r.join("app.js.gz"), "gzip").unwrap();
        std::fs::create_dir(r.join("dir")).unwrap();
        std::fs::write(r.join("dir/index.html"), "dir home").unwrap();
        std::fs::create_dir(r.join("empty")).unwrap();
        symlink("app.js", r.join("inside-link.js")).unwrap();
        symlink("dir", r.join("dir-link")).unwrap();
        symlink(
            outside.path().join("secret.txt"),
            r.join("outside-link.txt"),
        )
        .unwrap();
        symlink("../", r.join("dir/up")).unwrap();
        Tree {
            _outside: outside,
            root,
        }
    }

    fn lookup(raw: &str, codings: &[CompressAlgorithm], fallback: Option<&str>) -> Lookup {
        Lookup {
            path: SafePath::parse(raw, HiddenFiles::Refuse).unwrap(),
            codings: codings.to_vec(),
            fallback: fallback.map(str::to_owned),
        }
    }

    fn dirs() -> Directories {
        Directories {
            index: vec!["index.html".to_owned()],
            redirect: true,
        }
    }

    /// `(served, coding, content)` of a found file, or `"missing"` / `"add slash"`.
    fn outcome(root: &Root, lookup: &Lookup) -> String {
        match root.resolve(lookup, &dirs()) {
            Resolution::File(mut found) => {
                let mut content = String::new();
                std::io::Read::read_to_string(&mut found.file, &mut content).unwrap();
                format!("{} {:?} {content}", found.served, found.coding)
            }
            Resolution::AddSlash => "add slash".to_owned(),
            Resolution::Missing => "missing".to_owned(),
        }
    }

    #[test]
    fn files_indexes_sidecars_and_fallback() {
        let tree = tree();
        let root = Root::open(tree.root.path(), SymlinkPolicy::None).unwrap();
        let br = [CompressAlgorithm::Zstd, CompressAlgorithm::Br];
        assert_eq!(
            outcome(&root, &lookup("/app.js", &[], None)),
            "app.js None plain"
        );
        assert_eq!(
            outcome(&root, &lookup("/app.js", &br, None)),
            "app.js Some(Br) brotli",
            "zstd has no sidecar, Brotli is next"
        );
        assert_eq!(
            outcome(&root, &lookup("/", &[], None)),
            "index.html None home"
        );
        assert_eq!(outcome(&root, &lookup("/dir", &[], None)), "add slash");
        assert_eq!(
            outcome(&root, &lookup("/dir/", &[], None)),
            "dir/index.html None dir home"
        );
        assert_eq!(outcome(&root, &lookup("/empty/", &[], None)), "missing");
        assert_eq!(outcome(&root, &lookup("/app.js/", &[], None)), "missing");
        assert_eq!(outcome(&root, &lookup("/nope", &[], None)), "missing");
        assert_eq!(
            outcome(&root, &lookup("/about", &[], Some("index.html"))),
            "index.html None home"
        );
    }

    #[test]
    fn symlink_policies() {
        let tree = tree();
        let none = Root::open(tree.root.path(), SymlinkPolicy::None).unwrap();
        let within = Root::open(tree.root.path(), SymlinkPolicy::WithinRoot).unwrap();
        let all = Root::open(tree.root.path(), SymlinkPolicy::All).unwrap();
        let get = |root: &Root, raw: &str| outcome(root, &lookup(raw, &[], None));
        for raw in [
            "/inside-link.js",
            "/dir-link/index.html",
            "/outside-link.txt",
            "/dir/up/app.js",
        ] {
            assert_eq!(get(&none, raw), "missing", "none: {raw}");
        }
        assert_eq!(get(&within, "/inside-link.js"), "inside-link.js None plain");
        assert_eq!(
            get(&within, "/dir-link/index.html"),
            "dir-link/index.html None dir home"
        );
        assert_eq!(get(&within, "/dir/up/app.js"), "dir/up/app.js None plain");
        assert_eq!(
            get(&within, "/outside-link.txt"),
            "missing",
            "absolute link out"
        );
        assert_eq!(
            get(&all, "/outside-link.txt"),
            "outside-link.txt None secret"
        );
    }

    #[test]
    fn the_root_must_be_a_directory() {
        let tree = tree();
        let file = tree.root.path().join("app.js");
        let err = Root::open(&file, SymlinkPolicy::None).unwrap_err();
        assert!(err.to_string().ends_with("is not a directory"), "{err}");
        let err = Root::open(&tree.root.path().join("gone"), SymlinkPolicy::None).unwrap_err();
        assert!(err.to_string().starts_with("cannot read"), "{err}");
    }

    #[test]
    fn a_renamed_root_keeps_working_through_its_handle() {
        let tree = tree();
        let root = Root::open(tree.root.path(), SymlinkPolicy::None).unwrap();
        let moved = tree.root.path().with_extension("moved");
        std::fs::rename(tree.root.path(), &moved).unwrap();
        assert_eq!(
            outcome(&root, &lookup("/app.js", &[], None)),
            "app.js None plain"
        );
        std::fs::rename(&moved, tree.root.path()).unwrap();
    }
}
