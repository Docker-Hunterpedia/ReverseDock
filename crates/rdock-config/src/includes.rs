//! Extra configuration files (`providers.file.paths`): their routes, services, middlewares,
//! TCP objects and certificates are added to the main file before it is validated, so they can
//! refer to each other and to the main file's objects. The objects belong to the file provider,
//! like the main file's: a name defined twice is an error that names both files.
//!
//! A path is a file or a pattern whose last part may contain `*` and `?`
//! (`/etc/rdock/conf.d/*.yaml`); relative paths start at the main file's directory.

use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

use crate::{Format, LoadError, Loaded, System, load_value, parse};

/// Sections an extra file may hold.
pub const SECTIONS: [&str; 6] = [
    "routes",
    "services",
    "middlewares",
    "tcp_routes",
    "tcp_services",
    "certificates",
];

/// What the extra files were, for watching them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Included {
    /// Files read, in the order they were merged.
    pub files: Vec<PathBuf>,
    /// Patterns, as absolute paths, so new matching files can be noticed.
    pub patterns: Vec<PathBuf>,
}

/// Loads `path` and the extra files it names, then validates the whole.
pub fn load_file_with_includes(path: &Path) -> Result<(Loaded, Included), LoadError> {
    let text = read(path)?;
    let mut source = parse(&text, Format::from_path(path))?;
    if source.is_null() {
        source = Value::Object(Map::new());
    }
    let base = path.parent().unwrap_or_else(|| Path::new("."));
    let patterns: Vec<PathBuf> = paths(&source)?.into_iter().map(|p| base.join(p)).collect();
    let mut included = Included::default();
    let mut origins: Map<String, Value> = Map::new();
    for pattern in &patterns {
        let matched = expand(pattern)?;
        if is_pattern(pattern) {
            included.patterns.push(pattern.clone());
        } else if matched.is_empty() {
            return Err(LoadError::Io {
                path: pattern.clone(),
                source: std::io::Error::from(std::io::ErrorKind::NotFound),
            });
        }
        for file in matched {
            merge(&mut source, &file, &mut origins, path)?;
            included.files.push(file);
        }
    }
    Ok((load_value(source, &System)?, included))
}

fn read(path: &Path) -> Result<String, LoadError> {
    std::fs::read_to_string(path).map_err(|source| LoadError::Io {
        path: path.to_owned(),
        source,
    })
}

/// `providers.file.paths` as written, before the document is deserialised.
fn paths(source: &Value) -> Result<Vec<String>, LoadError> {
    match source.pointer("/providers/file/paths") {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| {
                item.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| invalid("providers.file.paths", "paths must be strings"))
            })
            .collect(),
        Some(_) => Err(invalid("providers.file.paths", "expected a list of paths")),
    }
}

fn invalid(path: impl Into<String>, message: impl Into<String>) -> LoadError {
    LoadError::Invalid {
        path: path.into(),
        message: message.into(),
    }
}

fn is_pattern(path: &Path) -> bool {
    path.file_name()
        .is_some_and(|n| n.to_string_lossy().contains(['*', '?']))
}

/// The files `pattern` names, sorted; a plain path names itself when it exists.
pub fn expand(pattern: &Path) -> Result<Vec<PathBuf>, LoadError> {
    let (Some(dir), Some(name)) = (pattern.parent(), pattern.file_name()) else {
        return Ok(Vec::new());
    };
    let name = name.to_string_lossy();
    if !is_pattern(pattern) {
        return Ok(if pattern.is_file() {
            vec![pattern.to_owned()]
        } else {
            Vec::new()
        });
    }
    if dir.to_string_lossy().contains(['*', '?']) {
        return Err(invalid(
            "providers.file.paths",
            format!(
                "`{}`: only the file name may contain `*` or `?`",
                pattern.display()
            ),
        ));
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(source) => {
            return Err(LoadError::Io {
                path: dir.to_owned(),
                source,
            });
        }
    };
    let mut files: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .filter(|p| {
            p.file_name()
                .is_some_and(|n| matches(&name, &n.to_string_lossy()))
        })
        .collect();
    files.sort();
    Ok(files)
}

/// `*` matches any run of characters, `?` one character; hidden files only match a pattern
/// that starts with `.`.
fn matches(pattern: &str, name: &str) -> bool {
    if name.starts_with('.') && !pattern.starts_with('.') {
        return false;
    }
    let p: Vec<char> = pattern.chars().collect();
    let n: Vec<char> = name.chars().collect();
    match_chars(&p, &n)
}

fn match_chars(p: &[char], n: &[char]) -> bool {
    match (p.first(), n.first()) {
        (None, None) => true,
        (Some('*'), _) => match_chars(&p[1..], n) || (!n.is_empty() && match_chars(p, &n[1..])),
        (Some('?'), Some(_)) => match_chars(&p[1..], &n[1..]),
        (Some(a), Some(b)) if a == b => match_chars(&p[1..], &n[1..]),
        _ => false,
    }
}

/// Adds the sections of `file` to `source`; `origins` remembers which file defined each name.
fn merge(
    source: &mut Value,
    file: &Path,
    origins: &mut Map<String, Value>,
    main: &Path,
) -> Result<(), LoadError> {
    let text = read(file)?;
    let shown = file.display().to_string();
    let extra = match parse(&text, Format::from_path(file)) {
        Ok(Value::Object(map)) => map,
        Ok(Value::Null) => return Ok(()),
        Ok(_) => return Err(invalid(shown, "expected a mapping of sections")),
        Err(LoadError::Syntax { message }) => {
            return Err(LoadError::Syntax {
                message: format!("{shown}: {message}"),
            });
        }
        Err(err) => return Err(err),
    };
    let Value::Object(root) = source else {
        return Err(invalid("(top level)", "expected a mapping"));
    };
    for (section, objects) in extra {
        if section == "$schema" || section.starts_with("x-") {
            continue;
        }
        if !SECTIONS.contains(&section.as_str()) {
            return Err(invalid(
                format!("{shown}: {section}"),
                format!(
                    "extra files may only hold {}; `{section}` belongs in the main file",
                    SECTIONS.join(", ")
                ),
            ));
        }
        let Value::Object(objects) = objects else {
            return Err(invalid(
                format!("{shown}: {section}"),
                "expected a mapping of names",
            ));
        };
        let target = root
            .entry(section.clone())
            .or_insert_with(|| Value::Object(Map::new()));
        let Value::Object(target) = target else {
            return Err(invalid(section, "expected a mapping of names"));
        };
        for (name, object) in objects {
            let key = format!("{section}.{name}");
            if target.contains_key(&name) {
                let first = origins
                    .get(&key)
                    .and_then(Value::as_str)
                    .map_or_else(|| main.display().to_string(), str::to_owned);
                return Err(invalid(key, format!("defined in both {first} and {shown}")));
            }
            origins.insert(key, Value::String(shown.clone()));
            target.insert(name, object);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAIN: &str = "listeners:\n  web: { address: \":8080\" }\ndefaults: { listeners: [web], tls: off }\nproviders:\n  file: { paths: [\"conf.d/*.yaml\", \"extra.yaml\"] }\nroutes:\n  site: { match: \"Host(`site.example.com`)\", service: site }\nservices:\n  site: { backends: [{ address: \"site:80\" }] }\n";

    fn setup(files: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("conf.d")).unwrap();
        for (name, text) in files {
            std::fs::write(dir.path().join(name), text).unwrap();
        }
        dir
    }

    #[test]
    fn extra_files_join_the_main_file_and_refer_to_it() {
        let dir = setup(&[
            ("rdock.yaml", MAIN),
            (
                "conf.d/a.yaml",
                "routes:\n  api: { match: \"Host(`api.example.com`)\", service: api, middlewares: [strip] }\nservices:\n  api: { backends: [{ address: \"api:80\" }] }\n",
            ),
            (
                "conf.d/b.yaml",
                "middlewares:\n  strip: { type: strip_prefix, prefixes: [/api] }\n",
            ),
            ("conf.d/.hidden.yaml", "routes: { broken: {} }\n"),
            ("conf.d/notes.txt", "not yaml"),
            (
                "extra.yaml",
                "routes:\n  blog: { match: \"Host(`blog.example.com`)\", service: site }\n",
            ),
        ]);
        let (loaded, included) = load_file_with_includes(&dir.path().join("rdock.yaml")).unwrap();
        assert!(!loaded.has_errors(), "{:?}", loaded.diagnostics);
        let routes: Vec<&String> = loaded.config.routes.keys().collect();
        assert_eq!(routes, ["api", "blog", "site"]);
        assert_eq!(included.files.len(), 3);
        assert_eq!(included.patterns, [dir.path().join("conf.d/*.yaml")]);
    }

    #[test]
    fn a_name_defined_twice_names_both_files() {
        let dir = setup(&[
            ("rdock.yaml", MAIN),
            (
                "conf.d/a.yaml",
                "routes:\n  site: { match: \"Host(`x.example.com`)\", service: site }\n",
            ),
            ("extra.yaml", ""),
        ]);
        let err = load_file_with_includes(&dir.path().join("rdock.yaml"))
            .unwrap_err()
            .to_string();
        assert!(err.starts_with("routes.site: defined in both"), "{err}");
        assert!(
            err.contains("rdock.yaml") && err.contains("a.yaml"),
            "{err}"
        );
    }

    #[test]
    fn only_object_sections_are_allowed() {
        let dir = setup(&[
            ("rdock.yaml", MAIN),
            ("extra.yaml", "listeners:\n  other: { address: \":9\" }\n"),
        ]);
        let err = load_file_with_includes(&dir.path().join("rdock.yaml"))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("`listeners` belongs in the main file"),
            "{err}"
        );
    }

    #[test]
    fn a_missing_plain_file_is_an_error_but_an_empty_pattern_is_not() {
        let dir = setup(&[("rdock.yaml", MAIN)]);
        let err = load_file_with_includes(&dir.path().join("rdock.yaml"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("extra.yaml"), "{err}");
        std::fs::write(dir.path().join("extra.yaml"), "").unwrap();
        assert!(load_file_with_includes(&dir.path().join("rdock.yaml")).is_ok());
    }

    #[test]
    fn patterns_match_names() {
        assert!(matches("*.yaml", "a.yaml"));
        assert!(matches("app-?.yml", "app-1.yml"));
        assert!(!matches("*.yaml", "a.yml"));
        assert!(!matches("*.yaml", ".a.yaml"));
        assert!(matches("*", "x"));
    }
}
