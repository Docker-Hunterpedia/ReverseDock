//! Label selectors (`metav1.LabelSelector`): `matchLabels` and `matchExpressions` (`In`,
//! `NotIn`, `Exists`, `DoesNotExist`), all of which must hold. An empty selector selects everything; an
//! unknown operator selects nothing.

use std::collections::BTreeMap;

use crate::api::LabelSelector;

/// Whether `labels` satisfy `selector`.
#[must_use]
pub fn matches(selector: &LabelSelector, labels: &BTreeMap<String, String>) -> bool {
    let labels_ok = selector
        .match_labels
        .iter()
        .flatten()
        .all(|(key, value)| labels.get(key) == Some(value));
    let expressions_ok = selector.match_expressions.iter().flatten().all(|e| {
        let values = e.values.as_deref().unwrap_or_default();
        let value = labels.get(&e.key);
        match e.operator.as_str() {
            "In" => value.is_some_and(|v| values.contains(v)),
            "NotIn" => value.is_none_or(|v| !values.contains(v)),
            "Exists" => value.is_some(),
            "DoesNotExist" => value.is_none(),
            _ => false,
        }
    });
    labels_ok && expressions_ok
}

#[cfg(test)]
mod tests {
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelectorRequirement;

    use super::*;

    fn labels(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    fn expression(key: &str, operator: &str, values: &[&str]) -> LabelSelectorRequirement {
        LabelSelectorRequirement {
            key: key.to_owned(),
            operator: operator.to_owned(),
            values: Some(values.iter().map(|v| (*v).to_owned()).collect()),
        }
    }

    #[test]
    fn match_labels_and_expressions() {
        let ns = labels(&[("gateway-conformance", "backend"), ("team", "a")]);
        assert!(matches(&LabelSelector::default(), &ns));
        let by_label = LabelSelector {
            match_labels: Some(labels(&[("gateway-conformance", "backend")])),
            ..LabelSelector::default()
        };
        assert!(matches(&by_label, &ns));
        assert!(!matches(
            &by_label,
            &labels(&[("gateway-conformance", "infra")])
        ));
        let cases = [
            (expression("team", "In", &["a", "b"]), true),
            (expression("team", "In", &["b"]), false),
            (expression("team", "NotIn", &["b"]), true),
            (expression("missing", "NotIn", &["b"]), true),
            (expression("team", "Exists", &[]), true),
            (expression("missing", "Exists", &[]), false),
            (expression("missing", "DoesNotExist", &[]), true),
            (expression("team", "Bogus", &[]), false),
        ];
        for (requirement, expected) in cases {
            let selector = LabelSelector {
                match_expressions: Some(vec![requirement.clone()]),
                ..LabelSelector::default()
            };
            assert_eq!(matches(&selector, &ns), expected, "{requirement:?}");
        }
    }
}
