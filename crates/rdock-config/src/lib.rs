#![doc = include_str!("../README.md")]

use std::path::{Path, PathBuf};

use rdock_model::{Config, Diagnostic, closest_match, path_index, path_key};
use serde_json::Value;

/// Options for loading a configuration.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LoadOptions {
    /// Report unknown keys as errors instead of warnings.
    pub strict: bool,
}

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
    /// The configuration.
    pub config: Config,
    /// Unknown keys and validation findings, in that order.
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
pub fn load_file(path: &Path, options: LoadOptions) -> Result<Loaded, LoadError> {
    let text = std::fs::read_to_string(path).map_err(|source| LoadError::Io {
        path: path.to_owned(),
        source,
    })?;
    load_str(&text, Format::from_path(path), options)
}

/// Loads and validates a configuration from text.
pub fn load_str(text: &str, format: Format, options: LoadOptions) -> Result<Loaded, LoadError> {
    let mut input = parse(text, format)?;
    if input.is_null() {
        input = Value::Object(serde_json::Map::new());
    }
    let config: Config =
        serde_path_to_error::deserialize(&input).map_err(|err| LoadError::Invalid {
            path: path_of(err.path()),
            message: err.inner().to_string(),
        })?;
    let known = serde_json::to_value(&config).map_err(|err| LoadError::Invalid {
        path: "(top level)".to_owned(),
        message: err.to_string(),
    })?;
    let mut finder = UnknownKeys {
        strict: options.strict,
        found: Vec::new(),
    };
    finder.compare(&input, &known, "");
    let mut diagnostics = finder.found;
    diagnostics.extend(config.validate());
    Ok(Loaded {
        config,
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

/// Finds keys of the input that the model did not use, by comparing the input with the model
/// serialised back to JSON: every field the model knows appears there.
struct UnknownKeys {
    strict: bool,
    found: Vec<Diagnostic>,
}

impl UnknownKeys {
    fn compare(&mut self, input: &Value, known: &Value, path: &str) {
        match (input, known) {
            (Value::Object(input), Value::Object(known)) => {
                for (key, value) in input {
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
        let mut diagnostic = if self.strict {
            Diagnostic::error(path, format!("unknown key `{key}`"))
        } else {
            Diagnostic::warning(path, format!("unknown key `{key}` is ignored"))
        };
        if let Some(near) = closest_match(key, siblings) {
            diagnostic = diagnostic.with_hint(format!("did you mean `{near}`?"));
        }
        self.found.push(diagnostic);
    }
}
