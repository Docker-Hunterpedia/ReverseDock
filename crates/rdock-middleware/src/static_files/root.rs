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
use rdock_model::middleware::{CompressAlgorithm, HiddenFiles, SymlinkPolicy};

use super::listing::{self, Entry, EntryKind, Listing};
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
    /// List a directory that has no index file (F-WEB-02).
    pub(crate) listing: bool,
    /// Whether dot-files are listed: never what a request would be refused.
    pub(crate) hidden: HiddenFiles,
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
    /// A directory with an index (or, when listing, any directory), named without its
    /// trailing slash.
    AddSlash,
    /// A directory without an index file, to be listed; sorted.
    Listing(Listing),
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
    /// A directory without an index file, and listing is on.
    Directory,
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

    /// Finds the file for a request: the file itself, a directory's index, the directory's
    /// listing, or the fallback, with the best sidecar the client accepts. A directory that
    /// exists is never answered with the fallback: it has its index, its listing or is a 404.
    pub(crate) fn resolve(&self, lookup: &Lookup, directories: &Directories) -> Resolution {
        let path = &lookup.path;
        let plain = match self.locate(path, directories) {
            Located::Index(_) | Located::Directory
                if !path.trailing_slash && directories.redirect =>
            {
                return Resolution::AddSlash;
            }
            Located::Directory => return self.list(path, directories),
            Located::File(relative) | Located::Index(relative) => relative,
            Located::Nothing => match &lookup.fallback {
                Some(fallback) => fallback.clone(),
                None => return Resolution::Missing,
            },
        };
        self.open_with_sidecar(plain, &lookup.codings)
    }

    fn locate(&self, path: &SafePath, directories: &Directories) -> Located {
        match self.kind(&path.relative) {
            Ok(Kind::File) if !path.trailing_slash => Located::File(path.relative.clone()),
            Ok(Kind::Dir) => directories
                .index
                .iter()
                .map(|name| path.child(name))
                .find(|relative| matches!(self.kind(relative), Ok(Kind::File)))
                .map_or(
                    if directories.listing {
                        Located::Directory
                    } else {
                        Located::Nothing
                    },
                    Located::Index,
                ),
            _ => Located::Nothing,
        }
    }

    /// The listing of the directory `path` names. A directory that cannot be read counts as
    /// missing, like a file that cannot be opened.
    fn list(&self, path: &SafePath, directories: &Directories) -> Resolution {
        let limits = (listing::MAX_ENTRIES, listing::MAX_SCANNED);
        match self.read_entries(&path.relative, directories.hidden, limits) {
            Ok((entries, truncated)) => {
                let mut listing = Listing {
                    relative: path.relative.clone(),
                    trailing_slash: path.trailing_slash,
                    entries,
                    truncated,
                };
                listing.sort();
                Resolution::Listing(listing)
            }
            Err(e) => {
                tracing::warn!(error = %e, "static directory listing failed");
                Resolution::Missing
            }
        }
    }

    /// The entries of `relative` that a request for them would be answered, at most `limit` of
    /// them from the first `scan_limit` directory entries (in file system order, so a cut-off
    /// listing shows an arbitrary part of the directory), and whether more exist. Hidden names follow `hidden`; a name is skipped when it cannot be
    /// requested (a backslash, or bytes that are not UTF-8) or would not be served (a link the
    /// `symlinks` policy refuses, a FIFO, a device, a link that leads nowhere or out of the
    /// root). Metadata comes through the directory handle: a link is resolved beneath the root
    /// exactly as serving it would, never by a path built from the request.
    fn read_entries(
        &self,
        relative: &str,
        hidden: HiddenFiles,
        (limit, scan_limit): (usize, usize),
    ) -> io::Result<(Vec<Entry>, bool)> {
        let mut entries = Vec::new();
        let mut scanned = 0_usize;
        let mut truncated = false;
        // Takes a directory entry's name, whether it is a link, and its metadata without and with
        // following links; `false` stops the walk.
        let mut visit = |name: std::ffi::OsString,
                         is_link: bool,
                         plain: &dyn Fn() -> io::Result<Stat>,
                         followed: &dyn Fn() -> io::Result<Stat>|
         -> bool {
            scanned += 1;
            if scanned > scan_limit {
                truncated = true;
                return false;
            }
            let Some(name) = name.to_str() else {
                return true;
            };
            if name.contains(['\\', '\0'])
                || (hidden == HiddenFiles::Refuse && name.starts_with('.'))
            {
                return true;
            }
            let metadata = if is_link {
                if !self.follows_links() {
                    return true;
                }
                followed()
            } else {
                plain()
            };
            let Ok(metadata) = metadata else {
                return true;
            };
            let kind = if metadata.is_file {
                EntryKind::File
            } else if metadata.is_dir {
                EntryKind::Dir
            } else {
                return true;
            };
            if entries.len() == limit {
                truncated = true;
                return false;
            }
            entries.push(Entry {
                name: name.to_owned(),
                kind,
                size: (kind == EntryKind::File).then_some(metadata.len),
                modified: metadata.modified.and_then(listing::rfc3339),
                symlink: is_link,
            });
            true
        };
        match self {
            Self::Sandboxed { dir, .. } => {
                if !self.follows_links() {
                    refuse_links(dir, relative)?;
                }
                let sub = dir.open_dir(or_dot(relative))?;
                for entry in sub.entries()? {
                    let entry = entry?;
                    let child = if relative.is_empty() {
                        entry.file_name()
                    } else {
                        let mut path = std::ffi::OsString::from(relative);
                        path.push("/");
                        path.push(entry.file_name());
                        path
                    };
                    let is_link = entry.file_type()?.is_symlink();
                    let go_on = visit(
                        entry.file_name(),
                        is_link,
                        &|| entry.metadata().map(|m| Stat::from_cap(&m)),
                        &|| dir.metadata(&child).map(|m| Stat::from_cap(&m)),
                    );
                    if !go_on {
                        break;
                    }
                }
            }
            Self::Ambient(root) => {
                let directory = root.join(relative);
                for entry in std::fs::read_dir(&directory)? {
                    let entry = entry?;
                    let is_link = entry.file_type()?.is_symlink();
                    let go_on = visit(
                        entry.file_name(),
                        is_link,
                        &|| entry.metadata().map(|m| Stat::from_std(&m)),
                        &|| std::fs::metadata(entry.path()).map(|m| Stat::from_std(&m)),
                    );
                    if !go_on {
                        break;
                    }
                }
            }
        }
        Ok((entries, truncated))
    }

    /// Whether symbolic links are followed at all.
    fn follows_links(&self) -> bool {
        match self {
            Self::Sandboxed { follow_links, .. } => *follow_links,
            Self::Ambient(_) => true,
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

/// What a listing needs of a name's metadata, whichever handle it came through.
struct Stat {
    is_file: bool,
    is_dir: bool,
    len: u64,
    modified: Option<std::time::SystemTime>,
}

impl Stat {
    fn from_cap(metadata: &cap_std::fs::Metadata) -> Self {
        Self {
            is_file: metadata.is_file(),
            is_dir: metadata.is_dir(),
            len: metadata.len(),
            modified: metadata
                .modified()
                .ok()
                .map(cap_std::time::SystemTime::into_std),
        }
    }

    fn from_std(metadata: &Metadata) -> Self {
        Self {
            is_file: metadata.is_file(),
            is_dir: metadata.is_dir(),
            len: metadata.len(),
            modified: metadata.modified().ok(),
        }
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
        outside: tempfile::TempDir,
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
        Tree { outside, root }
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
            listing: false,
            hidden: HiddenFiles::Refuse,
        }
    }

    fn listing_dirs(hidden: HiddenFiles) -> Directories {
        Directories {
            listing: true,
            hidden,
            ..dirs()
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
            Resolution::Listing(_) => "listing".to_owned(),
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

    /// `list/` holds every kind of name a listing must decide on.
    fn listing_tree() -> Tree {
        use std::os::unix::ffi::OsStrExt;
        let tree = tree();
        let list = tree.root.path().join("list");
        std::fs::create_dir(&list).unwrap();
        std::fs::write(list.join("plain.txt"), "12345").unwrap();
        std::fs::create_dir(list.join("sub")).unwrap();
        std::fs::write(list.join(".hidden"), "h").unwrap();
        std::fs::create_dir(list.join(".hdir")).unwrap();
        symlink("../app.js", list.join("in-link")).unwrap();
        symlink("../dir", list.join("dir-link")).unwrap();
        symlink(
            tree.outside.path().join("secret.txt"),
            list.join("out-link"),
        )
        .unwrap();
        symlink(
            "../../../../../../../../../../etc/passwd",
            list.join("rel-out"),
        )
        .unwrap();
        symlink("nope", list.join("dangling")).unwrap();
        std::os::unix::net::UnixListener::bind(list.join("socket")).unwrap();
        std::fs::write(list.join(std::ffi::OsStr::from_bytes(b"bad-\xff.txt")), "x").unwrap();
        std::fs::write(list.join("back\\slash"), "x").unwrap();
        tree
    }

    /// `name:kind` of what `/list/` shows, `*` marking a followed link.
    fn listed(root: &Root, raw: &str, hidden: HiddenFiles) -> Vec<String> {
        let lookup = lookup(raw, &[], None);
        match root.resolve(&lookup, &listing_dirs(hidden)) {
            Resolution::Listing(l) => l
                .entries
                .iter()
                .map(|e| {
                    format!(
                        "{}:{:?}{}",
                        e.name,
                        e.kind,
                        if e.symlink { "*" } else { "" }
                    )
                })
                .collect(),
            Resolution::File(_) => vec!["file".to_owned()],
            Resolution::AddSlash => vec!["add slash".to_owned()],
            Resolution::Missing => vec!["missing".to_owned()],
        }
    }

    #[test]
    fn listings_follow_the_hidden_and_symlink_policies() {
        let tree = listing_tree();
        let path = tree.root.path();
        let none = Root::open(path, SymlinkPolicy::None).unwrap();
        let within = Root::open(path, SymlinkPolicy::WithinRoot).unwrap();
        let all = Root::open(path, SymlinkPolicy::All).unwrap();
        let plain = ["plain.txt:File", "sub:Dir"];
        // Unreadable names, FIFOs and sockets are never listed, whatever the policy.
        assert_eq!(listed(&none, "/list/", HiddenFiles::Refuse), plain);
        assert_eq!(
            listed(&none, "/list/", HiddenFiles::Allow),
            [".hdir:Dir", ".hidden:File", "plain.txt:File", "sub:Dir"]
        );
        assert_eq!(
            listed(&within, "/list/", HiddenFiles::Refuse),
            [
                "dir-link:Dir*",
                "in-link:File*",
                "plain.txt:File",
                "sub:Dir"
            ],
            "links that stay in the root, typed by their target; outside, dangling and \
             unrequestable names are not listed"
        );
        let everything = listed(&all, "/list/", HiddenFiles::Refuse);
        assert!(
            everything.contains(&"out-link:File*".to_owned()),
            "{everything:?}"
        );
        assert!(
            everything.contains(&"in-link:File*".to_owned()),
            "{everything:?}"
        );
        assert!(
            !everything.iter().any(|n| n.starts_with("dangling")),
            "{everything:?}"
        );
        assert!(
            !everything.iter().any(|n| n.starts_with("socket")),
            "{everything:?}"
        );
        assert!(
            !everything.iter().any(|n| n.starts_with("bad-")),
            "{everything:?}"
        );
        assert!(
            !everything.iter().any(|n| n.contains('\\')),
            "{everything:?}"
        );
        assert!(
            !everything.iter().any(|n| n.starts_with('.')),
            "{everything:?}"
        );
    }

    #[test]
    fn listed_names_are_the_ones_a_request_is_served() {
        // Whatever a policy lists, requesting it must not be refused; and the reverse for
        // what it hides.
        let tree = listing_tree();
        for policy in [
            SymlinkPolicy::None,
            SymlinkPolicy::WithinRoot,
            SymlinkPolicy::All,
        ] {
            let root = Root::open(tree.root.path(), policy).unwrap();
            for hidden in [HiddenFiles::Refuse, HiddenFiles::Allow] {
                for entry in listed(&root, "/list/", hidden) {
                    let (name, kind) = entry.split_once(':').unwrap();
                    let raw = format!("/list/{}", name.replace('.', "%2E"));
                    let Some(path) = SafePath::parse(&raw, hidden) else {
                        panic!("{policy:?}/{hidden:?}: {name} is listed but refused");
                    };
                    let served = match root.kind(&path.relative) {
                        Ok(Kind::File) => "File",
                        Ok(Kind::Dir) => "Dir",
                        _ => "nothing",
                    };
                    assert!(
                        kind.starts_with(served),
                        "{policy:?}/{hidden:?}: {entry} is {served}"
                    );
                }
            }
        }
    }

    #[test]
    fn listing_precedence_and_redirects() {
        let tree = listing_tree();
        let root = Root::open(tree.root.path(), SymlinkPolicy::None).unwrap();
        let with = |raw: &str, fallback: Option<&str>, d: &Directories| match root
            .resolve(&lookup(raw, &[], fallback), d)
        {
            Resolution::Listing(l) => format!("listing {}", l.url_path()),
            Resolution::File(f) => format!("file {}", f.served),
            Resolution::AddSlash => "add slash".to_owned(),
            Resolution::Missing => "missing".to_owned(),
        };
        let on = listing_dirs(HiddenFiles::Refuse);
        let off = dirs();
        // An index wins over listing; a directory without one lists when asked to.
        assert_eq!(with("/dir/", None, &on), "file dir/index.html");
        assert_eq!(with("/", None, &on), "file index.html");
        assert_eq!(with("/list/", None, &on), "listing /list/");
        assert_eq!(with("/list/", None, &off), "missing", "off: as before");
        assert_eq!(with("/empty/", None, &on), "listing /empty/");
        // The trailing-slash rule applies to listed directories too.
        assert_eq!(with("/list", None, &on), "add slash");
        assert_eq!(with("/list", None, &off), "missing");
        let no_redirect = Directories {
            redirect: false,
            ..listing_dirs(HiddenFiles::Refuse)
        };
        assert_eq!(with("/list", None, &no_redirect), "listing /list/");
        // The fallback is for paths that do not exist, never for a directory that does.
        assert_eq!(with("/list/", Some("index.html"), &on), "listing /list/");
        assert_eq!(
            with("/list", Some("index.html"), &no_redirect),
            "listing /list/"
        );
        assert_eq!(with("/list/", Some("index.html"), &off), "file index.html");
        assert_eq!(with("/nope", Some("index.html"), &on), "file index.html");
        assert_eq!(with("/nope/", None, &on), "missing");
        // Files are not directories.
        assert_eq!(with("/app.js/", None, &on), "missing");
        assert_eq!(with("/list/plain.txt", None, &on), "file list/plain.txt");
        // A link to a directory is refused under `none` and listed under `within_root`.
        assert_eq!(with("/dir-link/", None, &on), "missing");
        let within = Root::open(tree.root.path(), SymlinkPolicy::WithinRoot).unwrap();
        assert!(
            matches!(
                within.resolve(&lookup("/list/dir-link/", &[], None), &on),
                Resolution::File(_)
            ),
            "the linked directory has an index, which wins over listing"
        );
        assert!(matches!(
            within.resolve(&lookup("/dir-link/", &[], None), &on),
            Resolution::File(_)
        ));
    }

    /// Makes `n` empty files and `dots` hidden ones in a fresh directory.
    fn crowd(n: usize, dots: usize) -> Tree {
        let tree = tree();
        let crowd = tree.root.path().join("crowd");
        std::fs::create_dir(&crowd).unwrap();
        for i in 0..n {
            std::fs::File::create(crowd.join(format!("f{i:05}"))).unwrap();
        }
        for i in 0..dots {
            std::fs::File::create(crowd.join(format!(".d{i}"))).unwrap();
        }
        tree
    }

    #[test]
    fn a_listing_holds_at_most_ten_thousand_entries() {
        let tree = crowd(listing::MAX_ENTRIES + 1, 0);
        let root = Root::open(tree.root.path(), SymlinkPolicy::None).unwrap();
        let Resolution::Listing(l) = root.resolve(
            &lookup("/crowd/", &[], None),
            &listing_dirs(HiddenFiles::Refuse),
        ) else {
            panic!("listing");
        };
        assert_eq!(l.entries.len(), 10_000);
        assert!(l.truncated);
        assert!(
            l.entries.windows(2).all(|w| w[0].name < w[1].name),
            "sorted"
        );
        // Exactly at the limit is not cut off.
        std::fs::remove_file(tree.root.path().join("crowd/f00000")).unwrap();
        let Resolution::Listing(l) = root.resolve(
            &lookup("/crowd/", &[], None),
            &listing_dirs(HiddenFiles::Refuse),
        ) else {
            panic!("listing");
        };
        assert_eq!((l.entries.len(), l.truncated), (10_000, false));
    }

    #[test]
    fn reading_stops_after_the_scan_limit_too() {
        let tree = crowd(3, 20);
        let root = Root::open(tree.root.path(), SymlinkPolicy::None).unwrap();
        let (entries, truncated) = root
            .read_entries("crowd", HiddenFiles::Refuse, (100, 10))
            .unwrap();
        assert!(truncated, "20 hidden names exceed a scan limit of 10");
        assert!(entries.len() <= 3);
        let (entries, truncated) = root
            .read_entries("crowd", HiddenFiles::Refuse, (2, 100))
            .unwrap();
        assert_eq!((entries.len(), truncated), (2, true));
        let (entries, truncated) = root
            .read_entries("crowd", HiddenFiles::Refuse, (100, 100))
            .unwrap();
        assert_eq!((entries.len(), truncated), (3, false));
    }

    #[test]
    fn entries_carry_size_and_modification_time() {
        let tree = listing_tree();
        let root = Root::open(tree.root.path(), SymlinkPolicy::None).unwrap();
        let (entries, _) = root
            .read_entries("list", HiddenFiles::Refuse, (100, 100))
            .unwrap();
        let file = entries.iter().find(|e| e.name == "plain.txt").unwrap();
        assert_eq!(file.size, Some(5));
        let modified = file.modified.as_deref().unwrap();
        assert!(
            modified.ends_with('Z') && modified.len() == 20,
            "{modified}"
        );
        let dir = entries.iter().find(|e| e.name == "sub").unwrap();
        assert_eq!(dir.size, None);
        assert!(dir.modified.is_some());
    }
}
