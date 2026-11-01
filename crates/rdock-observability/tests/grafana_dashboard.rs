//! The Grafana dashboard in `deploy/grafana/` (M-OBS-05) queries only metrics and labels that
//! rdock exports, and always through its data-source variable.
#![allow(clippy::unwrap_used)]

use std::collections::{BTreeMap, BTreeSet};

use prometheus::core::Collector;
use rdock_observability::Metrics;
use regex::Regex;
use serde_json::Value;

const DASHBOARD: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../deploy/grafana/dashboards/rdock.json"
);

/// Labels Prometheus adds to every scraped series.
const TARGET_LABELS: [&str; 2] = ["job", "instance"];

struct Exported {
    labels: BTreeSet<String>,
    histogram: bool,
}

fn exported() -> BTreeMap<String, Exported> {
    let m = Metrics::new("0.0.0", "test").unwrap();
    let histograms: Vec<Box<dyn Collector>> = vec![
        Box::new(m.duration.clone()),
        Box::new(m.upstream_duration.clone()),
    ];
    let others: Vec<Box<dyn Collector>> = vec![
        Box::new(m.alerts_sent.clone()),
        Box::new(m.requests.clone()),
        Box::new(m.upstream_errors.clone()),
        Box::new(m.connections.clone()),
        Box::new(m.connections_total.clone()),
        Box::new(m.tls_handshake_errors.clone()),
        Box::new(m.config_generation.clone()),
        Box::new(m.config_reloads.clone()),
        Box::new(m.cert_expiry.clone()),
        Box::new(m.cert_renewal_failures.clone()),
        Box::new(m.acme_orders.clone()),
        Box::new(m.backend_up.clone()),
        Box::new(m.backend_ejections.clone()),
        Box::new(m.retries.clone()),
        Box::new(m.retry_budget_exhausted.clone()),
        Box::new(m.backend_requests.clone()),
        Box::new(m.mirrors.clone()),
    ];
    let mut out = BTreeMap::new();
    for (collectors, histogram) in [(histograms, true), (others, false)] {
        for desc in collectors.iter().flat_map(|c| c.desc()) {
            let labels = desc.variable_labels.iter().cloned().collect();
            out.insert(desc.fq_name.clone(), Exported { labels, histogram });
        }
    }
    // Registered in `Metrics::new` but not a public field.
    let build_info = ["version", "commit"].map(str::to_owned).into();
    out.insert(
        "rdock_build_info".to_owned(),
        Exported {
            labels: build_info,
            histogram: false,
        },
    );
    out
}

fn dashboard() -> Value {
    serde_json::from_str(&std::fs::read_to_string(DASHBOARD).unwrap()).unwrap()
}

/// Every `PromQL` text: panel and annotation `expr`s and template variable queries.
fn queries(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                match (key.as_str(), child) {
                    ("expr" | "definition", Value::String(text)) => out.push(text.clone()),
                    _ => queries(child, out),
                }
            }
        }
        Value::Array(items) => items.iter().for_each(|item| queries(item, out)),
        _ => {}
    }
}

/// The exported metric a queried series name belongs to, and whether it is a histogram's
/// `_bucket` series.
fn resolve<'a>(
    name: &str,
    exported: &'a BTreeMap<String, Exported>,
) -> Option<(&'a Exported, bool)> {
    if let Some(metric) = exported.get(name) {
        return (!metric.histogram).then_some((metric, false));
    }
    ["_bucket", "_sum", "_count"].iter().find_map(|suffix| {
        let metric = exported.get(name.strip_suffix(suffix)?)?;
        metric.histogram.then_some((metric, *suffix == "_bucket"))
    })
}

#[test]
fn every_queried_metric_and_label_is_exported() {
    let exported = exported();
    let mut texts = Vec::new();
    queries(&dashboard(), &mut texts);
    assert!(texts.len() > 30, "found only {} queries", texts.len());

    let name = Regex::new(r"\brdock_[a-z_]+").unwrap();
    let selector = Regex::new(r"(rdock_[a-z_]+)\{([^}]*)\}").unwrap();
    let matcher = Regex::new(r"([a-z_]+)\s*(?:=~|!~|!=|=)").unwrap();
    let grouping = Regex::new(r"\b(?:by|without)\s*\(([^)]*)\)").unwrap();
    let label_values =
        Regex::new(r"label_values\((rdock_[a-z_]+)(?:\{[^}]*\})?,\s*([a-z_]+)\)").unwrap();

    let mut problems = Vec::new();
    for text in &texts {
        // Labels any metric of this query has; grouping may use any of them.
        let mut available: BTreeSet<String> = TARGET_LABELS.map(str::to_owned).into();
        for found in name.find_iter(text) {
            match resolve(found.as_str(), &exported) {
                Some((metric, bucket)) => {
                    available.extend(metric.labels.iter().cloned());
                    if bucket {
                        available.insert("le".to_owned());
                    }
                }
                None => problems.push(format!("{} is not exported: {text}", found.as_str())),
            }
        }
        for found in selector.captures_iter(text) {
            let Some((metric, bucket)) = resolve(&found[1], &exported) else {
                continue;
            };
            for label in matcher.captures_iter(&found[2]).map(|c| c[1].to_owned()) {
                let known = metric.labels.contains(&label)
                    || TARGET_LABELS.contains(&label.as_str())
                    || (bucket && label == "le");
                if !known {
                    problems.push(format!("{} has no label {label}: {text}", &found[1]));
                }
            }
        }
        for found in grouping.captures_iter(text) {
            for label in found[1].split(',').map(str::trim).filter(|l| !l.is_empty()) {
                if !available.contains(label) {
                    problems.push(format!("grouping by unknown label {label}: {text}"));
                }
            }
        }
        for found in label_values.captures_iter(text) {
            let known = exported
                .get(&found[1])
                .is_some_and(|m| m.labels.contains(&found[2]))
                || TARGET_LABELS.contains(&&found[2]);
            if !known {
                problems.push(format!("{} has no label {}: {text}", &found[1], &found[2]));
            }
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// Panels, targets and variables use `${datasource}`, so the dashboard works with any
/// Prometheus data source; the uid stays fixed so links and provisioning keep working.
#[test]
fn uses_the_data_source_variable_and_a_fixed_uid() {
    let dashboard = dashboard();
    assert_eq!(dashboard["uid"], "rdock-overview");
    let variables = dashboard["templating"]["list"].as_array().unwrap();
    assert!(
        variables
            .iter()
            .any(|v| v["type"] == "datasource" && v["name"] == "datasource")
    );

    let mut sources = Vec::new();
    collect_datasources(&dashboard, &mut sources);
    let fixed: Vec<_> = sources
        .iter()
        .filter(|ds| ds["type"] == "prometheus" && ds["uid"] != "${datasource}")
        .collect();
    assert!(fixed.is_empty(), "fixed data sources: {fixed:?}");
    assert!(sources.len() > 30);
}

fn collect_datasources<'a>(value: &'a Value, out: &mut Vec<&'a Value>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if key == "datasource" && child.is_object() {
                    out.push(child);
                } else {
                    collect_datasources(child, out);
                }
            }
        }
        Value::Array(items) => items.iter().for_each(|item| collect_datasources(item, out)),
        _ => {}
    }
}
