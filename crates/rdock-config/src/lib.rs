#![doc = include_str!("../README.md")]

use std::path::{Path, PathBuf};

use rdock_model::interpolation::{FieldKind, field_kind};
use rdock_model::{Config, Diagnostic, closest_match, path_index, path_key};
use serde_json::Value;

pub mod interpolate;
pub mod state;

pub use interpolate::{Lookup, ReferenceError, System};

/// Source formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// YAML 1.2 (JSON is valid YAML too).
    Yaml,
    /// JSON.
    Json,
}

impl Format {
    /// `.json` files are JSON; everything else is read as YAML.
    #[must_use]
    pub fn from_path(path: &Path) -> Self {
        match path.extension().and_then(|e| e.to_str()) {
            Some(ext) if ext.eq_ignore_ascii_case("json") => Self::Json,
            _ => Self::Yaml,
        }
    }
}

/// A loaded configuration and everything found while loading and validating it.
#[derive(Debug, Clone)]
pub struct Loaded {
    /// The configuration, with references resolved (except in secret fields).
    pub config: Config,
    /// The document as written, before references were resolved. History and the
    /// last-known-good copy store this form, so resolved secrets never reach the disk.
    pub source: Value,
    /// Reference errors, unknown keys and validation findings, in that order.
    pub diagnostics: Vec<Diagnostic>,
}

impl Loaded {
    /// Whether any diagnostic is an error.
    #[must_use]
    pub fn has_errors(&self) -> bool {
        self.diagnostics.iter().any(Diagnostic::is_error)
    }
}

/// Why a configuration could not be loaded at all.
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    /// The file could not be read.
    #[error("cannot read {}: {source}", path.display())]
    Io {
        /// File that was read.
        path: PathBuf,
        /// Underlying error.
        #[source]
        source: std::io::Error,
    },
    /// The text is not valid YAML or JSON. The message includes the location.
    #[error("{message}")]
    Syntax {
        /// Parser message with line and column.
        message: String,
    },
    /// A value has the wrong type or format.
    #[error("{path}: {message}")]
    Invalid {
        /// Location, e.g. `services.app.backends[0].address`.
        path: String,
        /// What is wrong.
        message: String,
    },
}

/// Loads and validates a configuration file. The format follows the file extension.
pub fn load_file(path: &Path) -> Result<Loaded, LoadError> {
    let text = std::fs::read_to_string(path).map_err(|source| LoadError::Io {
        path: path.to_owned(),
        source,
    })?;
    load_str(&text, Format::from_path(path))
}

/// Loads and validates a configuration from text, resolving references from the process
/// environment and file system.
pub fn load_str(text: &str, format: Format) -> Result<Loaded, LoadError> {
    load_str_with(text, format, &System)
}

/// Like [`load_str`], with references resolved through `lookup`.
pub fn load_str_with(text: &str, format: Format, lookup: &dyn Lookup) -> Result<Loaded, LoadError> {
    let mut source = parse(text, format)?;
    if source.is_null() {
        source = Value::Object(serde_json::Map::new());
    }
    load_value(source, lookup)
}

/// Loads and validates an already parsed document, such as a stored last-known-good copy.
pub fn load_value(source: Value, lookup: &dyn Lookup) -> Result<Loaded, LoadError> {
    let mut input = source.clone();
    let mut references = References {
        lookup,
        resolved: Vec::new(),
        diagnostics: Vec::new(),
    };
    references.walk(&mut input, &mut Vec::new(), "");
    let config: Config = serde_path_to_error::deserialize(&input).map_err(|err| {
        let path = path_of(err.path());
        let message = if references.resolved.iter().any(|p| p == &path) {
            // The message would quote the resolved value, which may be a secret.
            "invalid value from a `${…}` reference (value not shown)".to_owned()
        } else {
            err.inner().to_string()
        };
        LoadError::Invalid { path, message }
    })?;
    let known = serde_json::to_value(&config).map_err(|err| LoadError::Invalid {
        path: "(top level)".to_owned(),
        message: err.to_string(),
    })?;
    let mut diagnostics = references.diagnostics;
    UnknownKeys {
        found: &mut diagnostics,
    }
    .compare(&input, &known, "");
    diagnostics.extend(config.validate());
    Ok(Loaded {
        config,
        source,
        diagnostics,
    })
}

fn parse(text: &str, format: Format) -> Result<Value, LoadError> {
    match format {
        Format::Json => serde_json::from_str(text).map_err(|err| LoadError::Syntax {
            message: format!("invalid JSON: {err}"),
        }),
        // YAML 1.2 booleans only: `yes`, `on` and `off` stay strings, so `tls: off` means "off".
        Format::Yaml => serde_saphyr::from_str_with_options(
            text,
            serde_saphyr::options! { strict_booleans: true },
        )
        .map_err(|err| LoadError::Syntax {
            message: format!("invalid YAML: {err}"),
        }),
    }
}

/// Formats a deserialisation path the same way validation diagnostics do.
fn path_of(path: &serde_path_to_error::Path) -> String {
    let mut out = String::new();
    for segment in path {
        out = match segment {
            serde_path_to_error::Segment::Seq { index } => path_index(&out, *index),
            serde_path_to_error::Segment::Map { key } => path_key(&out, key),
            serde_path_to_error::Segment::Enum { variant } => path_key(&out, variant),
            serde_path_to_error::Segment::Unknown => out,
        };
    }
    if out.is_empty() {
        "(top level)".to_owned()
    } else {
        out
    }
}

/// Resolves references in the string values of a document.
struct References<'a> {
    lookup: &'a dyn Lookup,
    /// Paths whose value came from a reference.
    resolved: Vec<String>,
    diagnostics: Vec<Diagnostic>,
}

impl References<'_> {
    fn walk(&mut self, value: &mut Value, keys: &mut Vec<String>, path: &str) {
        match value {
            Value::String(text) => {
                let segments: Vec<&str> = keys.iter().map(String::as_str).collect();
                if field_kind(&segments) != FieldKind::Interpolated {
                    return;
                }
                match interpolate::expand(text, self.lookup) {
                    Ok(std::borrow::Cow::Borrowed(_)) => {}
                    Ok(std::borrow::Cow::Owned(expanded)) => {
                        *text = expanded;
                        self.resolved.push(path.to_owned());
                    }
                    Err(err) => self
                        .diagnostics
                        .push(Diagnostic::error(path, err.to_string())),
                }
            }
            Value::Array(items) => {
                for (i, item) in items.iter_mut().enumerate() {
                    keys.push(i.to_string());
                    self.walk(item, keys, &path_index(path, i));
                    keys.pop();
                }
            }
            Value::Object(map) => {
                for (key, item) in map.iter_mut() {
                    keys.push(key.clone());
                    self.walk(item, keys, &path_key(path, key));
                    keys.pop();
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }
}

/// Reports keys of the input that the model did not use, by comparing the input with the model
/// serialised back to JSON: every field the model knows appears there. Keys starting with `x-`
/// are extension fields (for YAML anchors, as in Docker Compose) and are ignored.
struct UnknownKeys<'a> {
    found: &'a mut Vec<Diagnostic>,
}

impl UnknownKeys<'_> {
    fn compare(&mut self, input: &Value, known: &Value, path: &str) {
        match (input, known) {
            (Value::Object(input), Value::Object(known)) => {
                for (key, value) in input {
                    if key.starts_with("x-") {
                        continue;
                    }
                    let key_path = path_key(path, key);
                    match known.get(key) {
                        Some(known_value) => self.compare(value, known_value, &key_path),
                        None => self.report(key_path, key, known.keys().map(String::as_str)),
                    }
                }
            }
            (Value::Array(input), Value::Array(known)) => {
                for (i, (item, known_item)) in input.iter().zip(known).enumerate() {
                    self.compare(item, known_item, &path_index(path, i));
                }
            }
            _ => {}
        }
    }

    fn report<'a>(&mut self, path: String, key: &str, siblings: impl Iterator<Item = &'a str>) {
        let mut diagnostic = Diagnostic::error(path, format!("unknown key `{key}`"));
        diagnostic = match closest_match(key, siblings) {
            Some(near) => diagnostic.with_hint(format!("did you mean `{near}`?")),
            None => {
                diagnostic.with_hint("keys starting with `x-` are ignored, e.g. for YAML anchors")
            }
        };
        self.found.push(diagnostic);
    }
}
