//! Building plugins from their configuration ([`Factory`], [`ConfigError`], [`typed`]) and the
//! explicit [`Registry`] an embedding binary hands to `rdock::run`.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use serde::de::DeserializeOwned;

use crate::Plugin;

/// One problem with a plugin's configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ConfigIssue {
    /// Where, relative to the plugin's `config` object: `""` for the object itself,
    /// `deny[2]`, `request.set.X-Team`. `rdock validate` prints it under
    /// `middlewares.<name>.config`.
    pub path: String,
    /// What is wrong.
    pub message: String,
    /// How to fix it, if the plugin knows.
    pub hint: Option<String>,
}

/// Why a factory refused a configuration: one or more [`ConfigIssue`]s, each with a path
/// inside the plugin's `config`. They become `rdock validate` diagnostics, and a configuration
/// with any of them is not loaded.
///
/// ```
/// use rdock_plugin_api::ConfigError;
///
/// let mut errors = ConfigError::empty();
/// errors.push(ConfigError::at("deny[1]", "`10.0.0.300/8` is not a network").with_hint("write `10.0.0.0/8`"));
/// errors.push(ConfigError::new("list at least one network"));
/// assert_eq!(errors.issues().len(), 2);
/// assert_eq!(errors.issues()[0].path, "deny[1]");
/// assert_eq!(errors.to_string(), "deny[1]: `10.0.0.300/8` is not a network; list at least one network");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ConfigError {
    issues: Vec<ConfigIssue>,
}

impl ConfigError {
    /// No issue yet; collect them with [`Self::push`] and return it with [`Self::into_result`].
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A problem with the configuration as a whole.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self::at("", message)
    }

    /// A problem at `path` inside the configuration.
    #[must_use]
    pub fn at(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            issues: vec![ConfigIssue {
                path: path.into(),
                message: message.into(),
                hint: None,
            }],
        }
    }

    /// Adds a hint to the last issue.
    #[must_use]
    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        if let Some(last) = self.issues.last_mut() {
            last.hint = Some(hint.into());
        }
        self
    }

    /// Adds the issues of `other`.
    pub fn push(&mut self, other: Self) {
        self.issues.extend(other.issues);
    }

    /// Whether there is no issue.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.issues.is_empty()
    }

    /// The issues, in the order they were found.
    #[must_use]
    pub fn issues(&self) -> &[ConfigIssue] {
        &self.issues
    }

    /// `Ok(value)` when no issue was collected, otherwise `Err(self)`.
    ///
    /// # Errors
    ///
    /// At least one issue was collected.
    pub fn into_result<T>(self, value: T) -> Result<T, Self> {
        if self.is_empty() {
            Ok(value)
        } else {
            Err(self)
        }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, issue) in self.issues.iter().enumerate() {
            if i > 0 {
                f.write_str("; ")?;
            }
            if issue.path.is_empty() {
                f.write_str(&issue.message)?;
            } else {
                write!(f, "{}: {}", issue.path, issue.message)?;
            }
        }
        Ok(())
    }
}

impl std::error::Error for ConfigError {}

/// Builds a plugin from its configuration (the `config` object of
/// `middlewares.<name>: { type: plugin, name: …, config: {…} }`).
///
/// It runs when a configuration is validated or loaded, never on the request path: a slow
/// factory (one that reads a file, compiles patterns) delays only the reload. Every closure
/// `Fn(&serde_json::Value) -> Result<Arc<dyn Plugin>, ConfigError>` is a factory; [`typed`]
/// builds one that deserializes the configuration into your own type first.
pub trait Factory: Send + Sync + 'static {
    /// Builds the plugin, or explains what is wrong with `config`.
    ///
    /// # Errors
    ///
    /// The configuration is invalid.
    fn build(&self, config: &serde_json::Value) -> Result<Arc<dyn Plugin>, ConfigError>;
}

impl<F> Factory for F
where
    F: Fn(&serde_json::Value) -> Result<Arc<dyn Plugin>, ConfigError> + Send + Sync + 'static,
{
    fn build(&self, config: &serde_json::Value) -> Result<Arc<dyn Plugin>, ConfigError> {
        self(config)
    }
}

/// A factory that deserializes the configuration into `C`, then calls `build`.
///
/// Deserialization errors carry the path of the offending field (`deny[1]`, `request.set`),
/// so `rdock validate` points at it. Mark your configuration type
/// `#[serde(deny_unknown_fields)]` to catch typos.
///
/// ```
/// use std::sync::Arc;
/// use rdock_plugin_api::{typed, Capabilities, ConfigError, Factory, Phases, Plugin, async_trait};
///
/// #[derive(serde::Deserialize)]
/// #[serde(deny_unknown_fields)]
/// struct Config { greeting: String }
///
/// struct Hello(String);
///
/// #[async_trait]
/// impl Plugin for Hello {
///     fn capabilities(&self) -> Capabilities { Capabilities::new(Phases::REQUEST) }
/// }
///
/// let factory = typed(|c: Config| {
///     if c.greeting.is_empty() {
///         return Err(ConfigError::at("greeting", "must not be empty"));
///     }
///     Ok(Hello(c.greeting))
/// });
/// assert!(factory.build(&serde_json::json!({ "greeting": "hi" })).is_ok());
/// let err = factory.build(&serde_json::json!({ "greting": "hi" })).err().unwrap();
/// assert_eq!(err.issues()[0].path, "greting");
/// let err = factory.build(&serde_json::json!({ "greeting": "" })).err().unwrap();
/// assert_eq!(err.to_string(), "greeting: must not be empty");
/// ```
pub fn typed<C, P, B>(build: B) -> impl Factory
where
    C: DeserializeOwned,
    P: Plugin,
    B: Fn(C) -> Result<P, ConfigError> + Send + Sync + 'static,
{
    move |config: &serde_json::Value| -> Result<Arc<dyn Plugin>, ConfigError> {
        let parsed: C = serde_path_to_error::deserialize(config).map_err(|e| {
            let path = e.path().to_string();
            let path = if path == "." { String::new() } else { path };
            ConfigError::at(path, e.into_inner().to_string())
        })?;
        Ok(Arc::new(build(parsed)?))
    }
}

/// Why a [`Registry`] cannot be used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RegistryError {
    /// Two factories were registered under one name.
    #[error("plugin `{0}` is registered twice")]
    Duplicate(String),
    /// A name is empty, longer than 64 characters, or uses characters other than lower-case
    /// ASCII letters, digits, `_` and `-`.
    #[error("`{0}` is not a valid plugin name: use 1 to 64 lower-case letters, digits, `_` or `-`")]
    InvalidName(String),
}

/// The plugins a binary contains: names mapped to factories, built explicitly by the
/// embedding binary and handed to `rdock::run`. Nothing is registered implicitly; what a
/// binary contains is what its `main` lists.
///
/// ```
/// use std::sync::Arc;
/// use rdock_plugin_api::{Capabilities, ConfigError, Phases, Plugin, Registry, async_trait};
///
/// struct Nothing;
/// #[async_trait]
/// impl Plugin for Nothing {
///     fn capabilities(&self) -> Capabilities { Capabilities::new(Phases::NONE) }
/// }
/// fn factory(_: &serde_json::Value) -> Result<Arc<dyn Plugin>, ConfigError> {
///     Ok(Arc::new(Nothing))
/// }
///
/// let registry = Registry::new().plugin("nothing", factory);
/// assert_eq!(registry.names().collect::<Vec<_>>(), ["nothing"]);
/// assert!(registry.check().is_ok());
/// assert!(Registry::new().plugin("Bad Name", factory).check().is_err());
/// ```
#[derive(Default, Clone)]
pub struct Registry {
    factories: BTreeMap<String, Arc<dyn Factory>>,
    errors: Vec<RegistryError>,
}

impl fmt::Debug for Registry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Registry")
            .field("plugins", &self.factories.keys().collect::<Vec<_>>())
            .field("errors", &self.errors)
            .finish()
    }
}

fn valid_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

impl Registry {
    /// An empty registry: the stock `rdock` binary.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers `factory` under `name`. An invalid or duplicate name is recorded and
    /// reported by [`Self::check`]; `rdock::run` refuses to start with it.
    #[must_use]
    pub fn plugin(mut self, name: &str, factory: impl Factory) -> Self {
        self.register(name, factory);
        self
    }

    /// Like [`Self::plugin`], on a mutable reference.
    pub fn register(&mut self, name: &str, factory: impl Factory) -> &mut Self {
        if !valid_name(name) {
            self.errors
                .push(RegistryError::InvalidName(name.to_owned()));
        } else if self.factories.contains_key(name) {
            self.errors.push(RegistryError::Duplicate(name.to_owned()));
        } else {
            self.factories.insert(name.to_owned(), Arc::new(factory));
        }
        self
    }

    /// Whether every registration succeeded.
    ///
    /// # Errors
    ///
    /// The first registration that failed.
    pub fn check(&self) -> Result<(), RegistryError> {
        match self.errors.first() {
            Some(error) => Err(error.clone()),
            None => Ok(()),
        }
    }

    /// The factory registered as `name`.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&dyn Factory> {
        self.factories.get(name).map(|f| &**f)
    }

    /// Registered names, sorted.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.factories.keys().map(String::as_str)
    }

    /// Number of registered plugins.
    #[must_use]
    pub fn len(&self) -> usize {
        self.factories.len()
    }

    /// Whether no plugin is registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.factories.is_empty()
    }
}
