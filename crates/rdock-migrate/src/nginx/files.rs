//! Reading the main file and the files its `include` directives name.
//!
//! `include file | mask;` "Includes another file, or files matching the specified mask, into
//! configuration" (<https://nginx.org/en/docs/ngx_core_module.html#include>, read 2026-11-14).
//! NGINX resolves a relative path against its configuration prefix, which in the standard layout
//! is the directory of `nginx.conf`; this tool resolves it against the directory of the main
//! file. Masks are matched as `glob(3)` does (`*`, `?`, `[…]`) and their files read in sorted
//! order. A dump of `nginx -T` (`# configuration file <path>:` before each file) is read without
//! touching the disk.
//!
//! Bounds: includes nest at most [`MAX_INCLUDE_DEPTH`] deep, at most [`MAX_FILES`] files are
//! read, and no file outside the main file's directory tree is read unless the caller allows it.
//! Files named by other directives (`auth_basic_user_file`, `ssl_certificate_key`, …) are never
//! read.

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

use super::parser::{self, Directive};

/// Deepest nesting of `include`.
pub const MAX_INCLUDE_DEPTH: usize = 8;
/// Most files read.
pub const MAX_FILES: usize = 256;

/// Where included files come from.
#[derive(Debug, Clone)]
pub enum Source {
    /// The disk: includes are resolved against `base` (the main file's directory); files outside
    /// `base` are read only with `allow_outside`.
    Disk {
        /// The main file's directory.
        base: PathBuf,
        /// Also read files outside `base`.
        allow_outside: bool,
    },
    /// The files of an `nginx -T` dump, by path.
    Dump(BTreeMap<PathBuf, String>),
    /// No includes are read (standard input without a dump).
    None,
}

/// The configuration with includes resolved.
#[derive(Debug, Default)]
pub struct Loaded {
    /// File names, by index.
    pub files: Vec<String>,
    /// The directives, with each `include` followed by what it read.
    pub tree: Vec<Directive>,
    /// What each `include` did, by (file, line, column): the files read, or why not.
    pub includes: BTreeMap<(usize, u32, u32), Result<Vec<String>, String>>,
}

/// Splits an `nginx -T` dump into its files; `None` when the text is not one.
pub fn split_dump(text: &str) -> Option<(PathBuf, BTreeMap<PathBuf, String>)> {
    const MARKER: &str = "# configuration file ";
    let mut files: BTreeMap<PathBuf, String> = BTreeMap::new();
    let mut first: Option<PathBuf> = None;
    let mut current: Option<PathBuf> = None;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix(MARKER)
            && let Some(path) = rest.strip_suffix(':')
        {
            let path = PathBuf::from(path);
            first.get_or_insert_with(|| path.clone());
            files.entry(path.clone()).or_default();
            current = Some(path);
            continue;
        }
        if let Some(path) = &current
            && let Some(content) = files.get_mut(path)
        {
            content.push_str(line);
            content.push('\n');
        }
    }
    first.map(|f| (f, files))
}

/// Reads `main` (already in memory) and resolves its includes.
pub fn load(
    main_name: &str,
    main: &str,
    main_path: &Path,
    source: &Source,
) -> Result<Loaded, String> {
    let mut loaded = Loaded {
        files: vec![main_name.to_owned()],
        ..Loaded::default()
    };
    let tree = parser::parse(main, 0).map_err(|e| format!("{main_name}: {e}"))?;
    let base = normalize(
        &main_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_default(),
    );
    loaded.tree = expand(tree, &base, source, &mut loaded, 0);
    Ok(loaded)
}

fn expand(
    tree: Vec<Directive>,
    base: &Path,
    source: &Source,
    loaded: &mut Loaded,
    depth: usize,
) -> Vec<Directive> {
    let mut out = Vec::with_capacity(tree.len());
    for mut d in tree {
        if let Some(block) = d.block.take() {
            d.block = Some(expand(block, base, source, loaded, depth));
            out.push(d);
            continue;
        }
        if d.name != "include" {
            out.push(d);
            continue;
        }
        let key = (d.file, d.line, d.column);
        let pattern = d.arg(0).to_owned();
        let result = if depth >= MAX_INCLUDE_DEPTH {
            Err(format!("includes nest deeper than {MAX_INCLUDE_DEPTH}"))
        } else if d.args.len() != 1 || pattern.contains('$') {
            Err("`include` takes one file name or mask without variables".to_owned())
        } else {
            resolve(&pattern, base, source)
                .map_err(|e| e.replace(&format!("{}/", base.display()), ""))
        };
        let mut included = Vec::new();
        let outcome = match result {
            Ok(paths) => {
                let mut names = Vec::new();
                let mut failure = None;
                for (path, text) in paths {
                    if loaded.files.len() >= MAX_FILES {
                        failure = Some(format!("more than {MAX_FILES} files"));
                        break;
                    }
                    let index = loaded.files.len();
                    // Named relative to the main file's directory when inside it.
                    let name = path
                        .strip_prefix(base)
                        .map_or_else(|_| path.display().to_string(), |p| p.display().to_string());
                    loaded.files.push(name.clone());
                    match parser::parse(&text, index) {
                        Ok(tree) => {
                            names.push(name);
                            included.extend(expand(tree, base, source, loaded, depth + 1));
                        }
                        Err(e) => {
                            failure = Some(format!("{name}: {e}"));
                            break;
                        }
                    }
                }
                match failure {
                    Some(why) => Err(why),
                    None => Ok(names),
                }
            }
            Err(why) => Err(why),
        };
        loaded.includes.insert(key, outcome);
        out.push(d);
        out.extend(included);
    }
    out
}

/// The files a pattern names, with their text.
fn resolve(pattern: &str, base: &Path, source: &Source) -> Result<Vec<(PathBuf, String)>, String> {
    let full = if Path::new(pattern).is_absolute() {
        PathBuf::from(pattern)
    } else {
        base.join(pattern)
    };
    let full = normalize(&full);
    let masked = pattern.contains(['*', '?', '[']);
    match source {
        Source::None => Err("included files are not read from standard input (pass the file, or a dump of `nginx -T`)".to_owned()),
        Source::Dump(files) => {
            let matches: Vec<(PathBuf, String)> = files
                .iter()
                .filter(|(path, _)| glob_path(&full, path))
                .map(|(p, t)| (p.clone(), t.clone()))
                .collect();
            if matches.is_empty() && !masked {
                return Err(format!("`{}` is not in the dump", full.display()));
            }
            Ok(matches)
        }
        Source::Disk { base: root, allow_outside } => {
            let root = std::fs::canonicalize(root).map_err(|e| format!("{}: {e}", root.display()))?;
            let mut candidates = Vec::new();
            expand_glob(&full, &mut candidates)?;
            if candidates.is_empty() && !masked {
                return Err(format!("`{pattern}` does not exist"));
            }
            candidates.sort();
            let mut out = Vec::new();
            for path in candidates {
                let real = std::fs::canonicalize(&path).map_err(|e| format!("{}: {e}", path.display()))?;
                if !allow_outside && !real.starts_with(&root) {
                    return Err(format!("`{pattern}` names a file outside the main file's directory (`--include-outside` reads it)"));
                }
                if real.is_dir() {
                    continue;
                }
                let meta = std::fs::metadata(&real).map_err(|e| format!("{}: {e}", path.display()))?;
                if usize::try_from(meta.len()).unwrap_or(usize::MAX) > parser::MAX_BYTES {
                    return Err(format!("`{}` is larger than {} bytes", path.display(), parser::MAX_BYTES));
                }
                let text = std::fs::read_to_string(&real).map_err(|e| format!("{}: {e}", path.display()))?;
                out.push((path, text));
            }
            Ok(out)
        }
    }
}

/// `a/./b/../c` → `a/c` without touching the disk.
fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Expands the wildcard components of `pattern` against the disk.
fn expand_glob(pattern: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    let mut prefixes = vec![PathBuf::new()];
    for component in pattern.components() {
        let text = component.as_os_str().to_string_lossy().into_owned();
        let mut next = Vec::new();
        for prefix in &prefixes {
            if text.contains(['*', '?', '[']) {
                let dir = if prefix.as_os_str().is_empty() {
                    PathBuf::from(".")
                } else {
                    prefix.clone()
                };
                let Ok(entries) = std::fs::read_dir(&dir) else {
                    continue;
                };
                let mut names: Vec<String> = entries
                    .filter_map(Result::ok)
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect();
                names.sort();
                for name in names {
                    if !name.starts_with('.') && glob_match(&text, &name) {
                        next.push(prefix.join(&name));
                    }
                }
            } else {
                next.push(prefix.join(component.as_os_str()));
            }
            if next.len() > MAX_FILES {
                return Err(format!("the mask matches more than {MAX_FILES} files"));
            }
        }
        prefixes = next;
    }
    out.extend(prefixes.into_iter().filter(|p| p.exists()));
    Ok(())
}

/// Whether `path` matches the mask `pattern`, component by component.
fn glob_path(pattern: &Path, path: &Path) -> bool {
    let p: Vec<String> = pattern
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    let n: Vec<String> = path
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    p.len() == n.len() && p.iter().zip(&n).all(|(p, n)| glob_match(p, n))
}

/// `glob(3)` matching of one name: `*`, `?`, `[abc]`, `[a-z]`, `[!x]`.
pub fn glob_match(pattern: &str, name: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let n: Vec<char> = name.chars().collect();
    // Iterative matching with one backtrack point for `*` (linear in practice).
    let (mut pi, mut ni) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while ni < n.len() {
        if pi < p.len() {
            match p[pi] {
                '*' => {
                    star = Some((pi, ni));
                    pi += 1;
                    continue;
                }
                '?' => {
                    pi += 1;
                    ni += 1;
                    continue;
                }
                '[' => {
                    if let Some((matched, len)) = class(&p[pi..], n[ni])
                        && matched
                    {
                        pi += len;
                        ni += 1;
                        continue;
                    }
                }
                c if c == n[ni] => {
                    pi += 1;
                    ni += 1;
                    continue;
                }
                _ => {}
            }
        }
        match star {
            Some((sp, sn)) => {
                pi = sp + 1;
                ni = sn + 1;
                star = Some((sp, sn + 1));
            }
            None => return false,
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// A `[…]` class at the start of `p`: whether `c` matches it, and the class's length.
fn class(p: &[char], c: char) -> Option<(bool, usize)> {
    let mut i = 1;
    let negate = matches!(p.get(1), Some('!' | '^'));
    if negate {
        i += 1;
    }
    let mut matched = false;
    let mut first = true;
    while i < p.len() {
        if p[i] == ']' && !first {
            return Some((matched != negate, i + 1));
        }
        first = false;
        if i + 2 < p.len() && p[i + 1] == '-' && p[i + 2] != ']' {
            if p[i] <= c && c <= p[i + 2] {
                matched = true;
            }
            i += 3;
        } else {
            if p[i] == c {
                matched = true;
            }
            i += 1;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn globs_match_like_glob3() {
        assert!(glob_match("*.conf", "site.conf"));
        assert!(!glob_match("*.conf", "site.conf.bak"));
        assert!(glob_match("site-?.conf", "site-a.conf"));
        assert!(glob_match("[a-c]*.conf", "b1.conf"));
        assert!(!glob_match("[!a-c]*.conf", "b1.conf"));
        assert!(glob_match("*", ""));
        assert!(glob_match("a*b*c", "aXXbYYc"));
        assert!(!glob_match("a*b*c", "aXXbYY"));
    }

    #[test]
    fn dumps_split_into_files() {
        let dump = "nginx: the configuration file /etc/nginx/nginx.conf syntax is ok\n# configuration file /etc/nginx/nginx.conf:\nhttp { include /etc/nginx/conf.d/*.conf; }\n\n# configuration file /etc/nginx/conf.d/a.conf:\nserver { listen 80; }\n";
        let (main, files) = split_dump(dump).unwrap();
        assert_eq!(main, PathBuf::from("/etc/nginx/nginx.conf"));
        assert_eq!(files.len(), 2);
        let loaded = load(
            "nginx.conf",
            &files[&main],
            &main,
            &Source::Dump(files.clone()),
        )
        .unwrap();
        assert_eq!(loaded.files.len(), 2);
        assert!(loaded.includes.values().all(Result::is_ok));
    }

    #[test]
    fn includes_stay_inside_the_tree_unless_allowed() {
        let outer = tempfile::tempdir().unwrap();
        let conf = outer.path().join("conf");
        std::fs::create_dir(&conf).unwrap();
        std::fs::write(outer.path().join("secret.conf"), "server { listen 81; }").unwrap();
        std::fs::write(conf.join("site.conf"), "server { listen 80; }").unwrap();
        let main = conf.join("nginx.conf");
        let text = "http { include site.conf; include ../secret.conf; include missing-*.conf; }";
        let source = Source::Disk {
            base: conf.clone(),
            allow_outside: false,
        };
        let loaded = load("nginx.conf", text, &main, &source).unwrap();
        let results: Vec<&Result<Vec<String>, String>> = loaded.includes.values().collect();
        assert!(results[0].is_ok());
        assert!(results[1].as_ref().unwrap_err().contains("outside"));
        assert_eq!(results[2], &Ok(Vec::new()));
        let allowed = Source::Disk {
            base: conf,
            allow_outside: true,
        };
        let loaded = load("nginx.conf", text, &main, &allowed).unwrap();
        assert!(loaded.includes.values().all(Result::is_ok));
    }

    #[test]
    fn include_cycles_stop_at_the_depth_limit() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("loop.conf"), "include loop.conf;").unwrap();
        let main = dir.path().join("nginx.conf");
        let source = Source::Disk {
            base: dir.path().to_path_buf(),
            allow_outside: false,
        };
        let loaded = load("nginx.conf", "include loop.conf;", &main, &source).unwrap();
        assert!(
            loaded
                .includes
                .values()
                .any(|r| r.as_ref().is_err_and(|e| e.contains("deeper")))
        );
        assert!(loaded.files.len() <= MAX_INCLUDE_DEPTH + 1);
    }
}
