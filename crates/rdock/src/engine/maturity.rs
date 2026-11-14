//! What the applied configuration uses below stable, and what it uses that is deprecated
//! (ADR-0033): one log line per feature or element at each load and reload, the metrics
//! `rdock_experimental_feature_in_use` and `rdock_deprecated_config_in_use`, and the lists the
//! status document carries for the admin API and the dashboard.

use std::collections::BTreeMap;

use rdock_model::maturity::{self, Level};
use rdock_model::{Config, Diagnostic};
use serde::Serialize;

/// A feature below stable in use.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct FeatureUse {
    pub(crate) feature: &'static str,
    pub(crate) level: Level,
    pub(crate) since: &'static str,
    pub(crate) summary: &'static str,
    pub(crate) paths: Vec<String>,
}

/// A deprecated element in use.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct DeprecationUse {
    pub(crate) element: String,
    pub(crate) since: String,
    pub(crate) removal: String,
    pub(crate) replacement: String,
    pub(crate) paths: Vec<String>,
}

/// Everything below stable or deprecated that the applied configuration uses.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub(crate) struct Signals {
    pub(crate) experimental: Vec<FeatureUse>,
    pub(crate) beta: Vec<FeatureUse>,
    pub(crate) deprecated: Vec<DeprecationUse>,
}

impl Signals {
    /// What `config` (providers merged) uses, and the deprecations among `diagnostics` (the
    /// file's and the providers').
    pub(crate) fn of(config: &Config, diagnostics: &[Diagnostic]) -> Self {
        let mut signals = Self::default();
        for use_ in maturity::in_use(config) {
            let entry = FeatureUse {
                feature: use_.feature.id,
                level: use_.feature.level,
                since: use_.feature.since,
                summary: use_.feature.summary,
                paths: use_.paths,
            };
            match use_.feature.level {
                Level::Experimental => signals.experimental.push(entry),
                Level::Beta => signals.beta.push(entry),
                Level::Stable => {}
            }
        }
        let mut by_element: BTreeMap<String, DeprecationUse> = BTreeMap::new();
        for d in diagnostics.iter().filter(|d| is_deprecation(d)) {
            let Some(element) = d.element.clone() else {
                continue;
            };
            by_element
                .entry(element.clone())
                .or_insert_with(|| DeprecationUse {
                    element,
                    since: d.since.clone().unwrap_or_default(),
                    removal: d.removal.clone().unwrap_or_default(),
                    replacement: d.replacement.clone().unwrap_or_default(),
                    paths: Vec::new(),
                })
                .paths
                .push(d.path.clone());
        }
        signals.deprecated = by_element.into_values().collect();
        signals
    }

    /// One WARN per experimental feature and deprecated element, one INFO per beta feature.
    pub(crate) fn log(&self) {
        for f in &self.experimental {
            tracing::warn!(
                feature = f.feature,
                paths = %f.paths.join(", "),
                "experimental feature in use: {}; it may change or be removed in any release and is not covered by the stability promise",
                f.summary
            );
        }
        for f in &self.beta {
            tracing::info!(
                feature = f.feature,
                paths = %f.paths.join(", "),
                "beta feature in use: {}; details may change in a minor release, with a migration note",
                f.summary
            );
        }
        for d in &self.deprecated {
            tracing::warn!(
                element = %d.element,
                since = %d.since,
                removal = %d.removal,
                paths = %d.paths.join(", "),
                "deprecated configuration in use: use {} (`rdock migrate config` rewrites what it can)",
                d.replacement
            );
        }
    }

    /// Sets the two gauges: every experimental feature to 0 or 1, and each deprecated element
    /// in use to 1 (elements no longer in use disappear).
    pub(crate) fn record(&self, metrics: &rdock_observability::Metrics) {
        for id in maturity::experimental_ids() {
            let used = self.experimental.iter().any(|f| f.feature == id);
            metrics
                .experimental_in_use
                .with_label_values(&[id])
                .set(i64::from(used));
        }
        metrics.deprecated_in_use.reset();
        for d in &self.deprecated {
            metrics
                .deprecated_in_use
                .with_label_values(&[d.element.as_str()])
                .set(1);
        }
    }
}

/// Whether a diagnostic is a deprecation warning (logged once per element, not per use).
pub(crate) fn is_deprecation(d: &Diagnostic) -> bool {
    d.code.as_deref() == Some("deprecated")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn groups_uses_by_feature_and_element() {
        let config: Config = serde_json::from_value(serde_json::json!({
            "experimental": ["wasm"],
            "caches": { "mem": { "type": "memory" } },
            "middlewares": { "w": { "type": "wasm", "path": "/w.wasm", "sha256": "0".repeat(64), "allow_unsigned": true } }
        }))
        .unwrap();
        let entry = &rdock_model::deprecation::REGISTRY[0];
        let diagnostics = vec![
            rdock_model::deprecation::diagnostic(entry, "observability.alerts.webhook".into()),
            Diagnostic::warning("x", "unrelated"),
        ];
        let signals = Signals::of(&config, &diagnostics);
        assert_eq!(signals.experimental.len(), 1);
        assert_eq!(signals.experimental[0].feature, "wasm");
        assert_eq!(signals.beta[0].feature, "http-cache");
        assert_eq!(signals.deprecated.len(), 1);
        assert_eq!(
            signals.deprecated[0].element,
            "observability.alerts.webhook"
        );
        assert_eq!(signals.deprecated[0].removal, "2.0");
        let metrics = rdock_observability::Metrics::new("test", "test").unwrap();
        signals.record(&metrics);
        let text = metrics.render();
        assert!(
            text.contains("rdock_experimental_feature_in_use{feature=\"wasm\"} 1"),
            "{text}"
        );
        assert!(
            text.contains("rdock_experimental_feature_in_use{feature=\"http3\"} 0"),
            "{text}"
        );
        assert!(
            text.contains(
                "rdock_deprecated_config_in_use{element=\"observability.alerts.webhook\"} 1"
            ),
            "{text}"
        );
        Signals::default().record(&metrics);
        assert!(!metrics.render().contains("rdock_deprecated_config_in_use{"));
    }
}
