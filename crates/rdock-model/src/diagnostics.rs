//! Diagnostics reported by validation and loading.

use std::fmt;

use serde::{Deserialize, Serialize};

/// How serious a diagnostic is.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// The configuration cannot be applied.
    Error,
    /// The configuration works but probably not as intended.
    Warning,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Error => "error",
            Self::Warning => "warning",
        })
    }
}

/// One finding about a configuration, located by a path such as `routes.app.service`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Diagnostic {
    /// Error or warning.
    pub severity: Severity,
    /// Location in the configuration, e.g. `services.app.backends[0].address`.
    pub path: String,
    /// What is wrong.
    pub message: String,
    /// How to fix it, when known. May span several lines.
    pub hint: Option<String>,
    /// A stable code for diagnostics that tools act on, e.g. `deprecated` or
    /// `experimental_not_enabled` (ADR-0033). Absent for the others.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    /// For a deprecation: the deprecated element as the registry names it, e.g.
    /// `observability.alerts.webhook` (also the `element` label of
    /// `rdock_deprecated_config_in_use`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub element: Option<String>,
    /// For a deprecation: the release that deprecated the element, e.g. `1.0`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,
    /// For a deprecation: the release that removes the element, e.g. `2.0`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removal: Option<String>,
    /// For a deprecation: what to use instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replacement: Option<String>,
}

impl Diagnostic {
    /// An error at `path`.
    pub fn error(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Error,
            path: path.into(),
            message: message.into(),
            hint: None,
            code: None,
            element: None,
            since: None,
            removal: None,
            replacement: None,
        }
    }

    /// A warning at `path`.
    pub fn warning(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Warning,
            path: path.into(),
            message: message.into(),
            hint: None,
            code: None,
            element: None,
            since: None,
            removal: None,
            replacement: None,
        }
    }

    /// Adds a stable code (see [`Diagnostic::code`]).
    #[must_use]
    pub fn with_code(mut self, code: impl Into<String>) -> Self {
        self.code = Some(code.into());
        self
    }

    /// Adds a hint.
    #[must_use]
    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    /// Whether this is an error.
    #[must_use]
    pub fn is_error(&self) -> bool {
        self.severity == Severity::Error
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}: {}", self.severity, self.path, self.message)
    }
}

/// Appends a map key to a path: `routes` + `app` → `routes.app`. Keys that are not plain
/// identifiers are quoted: `routes["my route"]`.
#[must_use]
pub fn path_key(base: &str, key: &str) -> String {
    let plain = !key.is_empty()
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '$');
    match (base.is_empty(), plain) {
        (true, true) => key.to_owned(),
        (false, true) => format!("{base}.{key}"),
        (_, false) => format!("{base}[{key:?}]"),
    }
}

/// Appends a list index to a path: `backends` + `0` → `backends[0]`.
#[must_use]
pub fn path_index(base: &str, index: usize) -> String {
    format!("{base}[{index}]")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_readable_paths() {
        assert_eq!(path_key("", "routes"), "routes");
        assert_eq!(path_key("routes", "app"), "routes.app");
        assert_eq!(path_key("routes", "my.route"), "routes[\"my.route\"]");
        assert_eq!(
            path_index("services.app.backends", 2),
            "services.app.backends[2]"
        );
    }
}
