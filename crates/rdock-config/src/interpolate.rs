//! `${NAME}`, `${env:NAME}`, `${file:/path}` and `${vault:<mount>/<path>#<field>}` references
//! in string values.
//!
//! A reference is replaced by the value of an environment variable, by the contents of a file
//! (one trailing newline removed) or by a field of a Vault KV secret read earlier into
//! [`vault_store`]. `$${` writes a literal `${`. Replaced text is never expanded again, so a
//! secret cannot inject further references.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{PoisonError, RwLock};

/// Largest file a `${file:…}` reference may read.
pub const MAX_FILE_BYTES: u64 = 64 * 1024;

/// Where reference values come from.
pub trait Lookup {
    /// The value of an environment variable, or `None` when it is not set.
    fn env(&self, name: &str) -> Result<Option<String>, ReferenceError>;
    /// The contents of a file, at most [`MAX_FILE_BYTES`].
    fn file(&self, path: &Path) -> Result<String, ReferenceError>;
    /// The value of a Vault reference (`<mount>/<path>#<field>`), as read into
    /// [`vault_store`]. Lookups that do not read Vault refuse it.
    fn vault(&self, reference: &str) -> Result<String, ReferenceError> {
        Err(ReferenceError::VaultNotRead(reference.to_owned()))
    }
}

/// Values of `${vault:…}` references, read by the engine before a configuration is compiled
/// and on every refresh (W-OBS-02). In memory only; keyed by the reference body
/// (`<mount>/<path>#<field>`). Values are never formatted by this module.
pub mod vault_store {
    use super::{BTreeMap, PoisonError, RwLock};

    static VALUES: RwLock<BTreeMap<String, String>> = RwLock::new(BTreeMap::new());

    /// The value of `reference`, if it was read.
    #[must_use]
    pub fn get(reference: &str) -> Option<String> {
        VALUES
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(reference)
            .cloned()
    }

    /// Stores values; returns whether any stored value changed (a new reference counts).
    pub fn put(values: impl IntoIterator<Item = (String, String)>) -> bool {
        let mut store = VALUES.write().unwrap_or_else(PoisonError::into_inner);
        let mut changed = false;
        for (reference, value) in values {
            if store.get(&reference) != Some(&value) {
                store.insert(reference, value);
                changed = true;
            }
        }
        changed
    }

    /// The references read so far.
    #[must_use]
    pub fn references() -> Vec<String> {
        VALUES
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .keys()
            .cloned()
            .collect()
    }

    /// Keeps only `keep`, dropping values no configuration references any more.
    pub fn retain(keep: &std::collections::BTreeSet<String>) {
        VALUES
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|reference, _| keep.contains(reference));
    }
}

/// The process environment and file system.
#[derive(Debug, Clone, Copy, Default)]
pub struct System;

impl Lookup for System {
    fn env(&self, name: &str) -> Result<Option<String>, ReferenceError> {
        match std::env::var(name) {
            Ok(value) => Ok(Some(value)),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(std::env::VarError::NotUnicode(_)) => {
                Err(ReferenceError::NotUnicode(name.to_owned()))
            }
        }
    }

    fn file(&self, path: &Path) -> Result<String, ReferenceError> {
        let read_error = |source| ReferenceError::File {
            path: path.to_owned(),
            source,
        };
        let file = std::fs::File::open(path).map_err(read_error)?;
        let mut bytes = Vec::new();
        file.take(MAX_FILE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(read_error)?;
        if bytes.len() as u64 > MAX_FILE_BYTES {
            return Err(ReferenceError::FileTooLarge(path.to_owned()));
        }
        String::from_utf8(bytes).map_err(|_| ReferenceError::FileNotUnicode(path.to_owned()))
    }

    fn vault(&self, reference: &str) -> Result<String, ReferenceError> {
        vault_store::get(reference)
            .ok_or_else(|| ReferenceError::VaultNotRead(reference.to_owned()))
    }
}

/// Why a reference could not be resolved.
#[derive(Debug, thiserror::Error)]
pub enum ReferenceError {
    /// The variable is not set.
    #[error("environment variable `{0}` is not set")]
    EnvNotSet(String),
    /// The variable holds bytes that are not UTF-8.
    #[error("environment variable `{0}` is not valid UTF-8")]
    NotUnicode(String),
    /// The file could not be read.
    #[error("cannot read `{}`: {source}", path.display())]
    File {
        /// File that was read.
        path: PathBuf,
        /// Underlying error.
        #[source]
        source: std::io::Error,
    },
    /// The file is over [`MAX_FILE_BYTES`].
    #[error("`{}` is larger than 64 KiB", .0.display())]
    FileTooLarge(PathBuf),
    /// The file is not UTF-8 text.
    #[error("`{}` is not UTF-8 text", .0.display())]
    FileNotUnicode(PathBuf),
    /// `${file:…}` needs an absolute path.
    #[error("`{0}` is not an absolute path")]
    RelativePath(String),
    /// `${` without a closing `}`.
    #[error("`${{` is not closed; write `$${{` for a literal `${{`")]
    Unclosed,
    /// The name is empty or has characters other than letters, digits and `_`.
    #[error("invalid variable name `{0}`; use letters, digits and `_`")]
    InvalidName(String),
    /// A prefix other than `env:`, `file:` or `vault:`.
    #[error(
        "unknown reference `${{{0}:…}}`; use `${{env:NAME}}`, `${{file:/path}}` or `${{vault:<mount>/<path>#<field>}}`"
    )]
    UnknownKind(String),
    /// A malformed `${vault:…}` reference.
    #[error("{0}")]
    VaultSyntax(String),
    /// A `${vault:…}` reference whose value has not been read (no `secrets.vault`, or the
    /// read failed).
    #[error("`${{vault:{0}}}` has not been read from Vault; check `secrets.vault` and the logs")]
    VaultNotRead(String),
    /// A `${vault:…}` reference outside a secret field.
    #[error(
        "`${{vault:…}}` is accepted only in secret fields (tokens, passwords, keys), so its value never enters the loaded configuration"
    )]
    VaultNotAllowed,
}

/// Replaces every reference in `text`. Returns the input unchanged (borrowed) when it has none.
pub fn expand<'a>(text: &'a str, lookup: &dyn Lookup) -> Result<Cow<'a, str>, ReferenceError> {
    if !text.contains("${") {
        return Ok(Cow::Borrowed(text));
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("${") {
        if rest[..start].ends_with('$') {
            // `$${` is an escaped `${`.
            out.push_str(&rest[..start - 1]);
            out.push_str("${");
            rest = &rest[start + 2..];
            continue;
        }
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after.find('}').ok_or(ReferenceError::Unclosed)?;
        out.push_str(&resolve(&after[..end], lookup)?);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(Cow::Owned(out))
}

/// Resolves one reference body, the text between `${` and `}`.
fn resolve(body: &str, lookup: &dyn Lookup) -> Result<String, ReferenceError> {
    match body.split_once(':') {
        Some(("env", name)) => env(name, lookup),
        Some(("file", path)) => file(path, lookup),
        Some(("vault", reference)) => {
            rdock_model::secrets::VaultReference::parse(reference)
                .map_err(ReferenceError::VaultSyntax)?;
            lookup.vault(reference)
        }
        Some((kind, _)) => Err(ReferenceError::UnknownKind(kind.to_owned())),
        None => env(body, lookup),
    }
}

fn env(name: &str, lookup: &dyn Lookup) -> Result<String, ReferenceError> {
    let valid = name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    if !valid {
        return Err(ReferenceError::InvalidName(name.to_owned()));
    }
    lookup
        .env(name)?
        .ok_or_else(|| ReferenceError::EnvNotSet(name.to_owned()))
}

fn file(path: &str, lookup: &dyn Lookup) -> Result<String, ReferenceError> {
    if !Path::new(path).is_absolute() {
        return Err(ReferenceError::RelativePath(path.to_owned()));
    }
    let mut contents = lookup.file(Path::new(path))?;
    if contents.ends_with('\n') {
        contents.pop();
        if contents.ends_with('\r') {
            contents.pop();
        }
    }
    Ok(contents)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    struct Fake {
        env: HashMap<&'static str, &'static str>,
        files: HashMap<&'static str, &'static str>,
    }

    impl Lookup for Fake {
        fn env(&self, name: &str) -> Result<Option<String>, ReferenceError> {
            Ok(self.env.get(name).map(|v| (*v).to_owned()))
        }

        fn file(&self, path: &Path) -> Result<String, ReferenceError> {
            self.files
                .get(path.to_str().unwrap_or_default())
                .map(|v| (*v).to_owned())
                .ok_or_else(|| ReferenceError::File {
                    path: path.to_owned(),
                    source: std::io::ErrorKind::NotFound.into(),
                })
        }
    }

    fn fake() -> Fake {
        Fake {
            env: HashMap::from([("DOMAIN", "example.com"), ("NESTED", "${DOMAIN}")]),
            files: HashMap::from([
                ("/run/secrets/token", "s3cr3t\n"),
                ("/run/secrets/crlf", "v\r\n"),
            ]),
        }
    }

    fn ok(text: &str) -> String {
        expand(text, &fake()).unwrap().into_owned()
    }

    #[test]
    fn replaces_env_and_file_references() {
        assert_eq!(ok("app.${DOMAIN}"), "app.example.com");
        assert_eq!(ok("${env:DOMAIN}:443"), "example.com:443");
        assert_eq!(ok("${file:/run/secrets/token}"), "s3cr3t");
        assert_eq!(ok("${file:/run/secrets/crlf}"), "v");
        assert_eq!(
            ok("no references, $1 and $name stay"),
            "no references, $1 and $name stay"
        );
    }

    #[test]
    fn escapes_and_never_expands_twice() {
        assert_eq!(ok("$${DOMAIN}"), "${DOMAIN}");
        assert_eq!(ok("a$${b}${DOMAIN}"), "a${b}example.com");
        assert_eq!(ok("${NESTED}"), "${DOMAIN}");
        assert!(matches!(
            expand("plain", &fake()).unwrap(),
            Cow::Borrowed("plain")
        ));
    }

    #[test]
    fn explains_bad_references() {
        let err = |text: &str| expand(text, &fake()).unwrap_err().to_string();
        assert_eq!(
            err("${MISSING}"),
            "environment variable `MISSING` is not set"
        );
        assert!(err("${DOMAIN").contains("not closed"));
        assert!(err("${}").contains("invalid variable name"));
        assert!(err("${a-b}").contains("invalid variable name"));
        assert!(err("${file:relative/path}").contains("not an absolute path"));
        assert!(err("${file:/nope}").contains("cannot read `/nope`"));
        assert!(err("${other:x}").contains("unknown reference `${other:…}`"));
        assert!(err("${vault:x}").contains("needs `#<field>`"));
        assert!(err("${vault:kv/a#b}").contains("has not been read from Vault"));
    }

    #[test]
    fn vault_references_come_from_the_store() {
        assert!(vault_store::put([(
            "kv/app#token".to_owned(),
            "v1".to_owned()
        )]));
        assert!(!vault_store::put([(
            "kv/app#token".to_owned(),
            "v1".to_owned()
        )]));
        assert_eq!(
            expand("Bearer ${vault:kv/app#token}", &System).unwrap(),
            "Bearer v1"
        );
        assert!(vault_store::put([(
            "kv/app#token".to_owned(),
            "v2".to_owned()
        )]));
        assert_eq!(expand("${vault:kv/app#token}", &System).unwrap(), "v2");
        let err = expand("${vault:kv/app#other}", &System)
            .unwrap_err()
            .to_string();
        assert!(err.contains("kv/app#other") && !err.contains("v2"), "{err}");
        vault_store::retain(&std::collections::BTreeSet::new());
        assert_eq!(vault_store::references(), Vec::<String>::new());
    }

    #[test]
    fn system_lookup_caps_file_size() {
        let dir = tempfile::tempdir().unwrap();
        let big = dir.path().join("big");
        std::fs::write(&big, vec![b'a'; 64 * 1024 + 1]).unwrap();
        assert!(matches!(
            System.file(&big),
            Err(ReferenceError::FileTooLarge(_))
        ));
        let small = dir.path().join("small");
        std::fs::write(&small, "x\n").unwrap();
        assert_eq!(System.file(&small).unwrap(), "x\n");
    }
}
