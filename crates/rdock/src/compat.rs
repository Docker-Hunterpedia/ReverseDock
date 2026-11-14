//! Compatibility snapshots (ADR-0033, step 3): the public surfaces that have no committed,
//! machine-readable definition of their own, generated from the code that defines them and
//! committed under `schema/compat/`. `just compat` regenerates them, a test fails when they are
//! stale, and `scripts/compat.py` compares them with the last release tag's copies.
//!
//! `rdock schema --compat <surface>` prints one (the flag is hidden: the snapshots are for the
//! repository, not for users). Every snapshot is pretty-printed JSON with sorted keys and no
//! timestamps or machine paths, so it is the same on every machine.

use clap::{Command, CommandFactory, ValueEnum};
use serde_json::{Map, Value, json};

use crate::Cli;

/// A surface `rdock schema --compat` prints.
#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum Surface {
    /// Every metric: name, type, unit, help, label names, histogram buckets, feature.
    Metrics,
    /// The command tree, the exit codes and the JSON outputs' schemas.
    Cli,
    /// The JSON access log's fields (a JSON Schema).
    AccessLog,
    /// The RFC 9457 problem types: type URI, status, feature.
    Problems,
    /// The documented `RDOCK_*` environment variables.
    Env,
    /// The deprecation registry.
    Deprecations,
}

/// The exit codes every command shares (`docs/10-stability.md`, CLI row). Their meaning is
/// stable; the CLI snapshot carries this table.
pub(crate) const EXIT_CODES: [(&str, &str); 3] = [
    ("0", "success"),
    (
        "1",
        "a failed check: invalid configuration, a broken audit chain, a proxy that is not ready",
    ),
    (
        "2",
        "an error: a usage error, an I/O error, an unreachable admin API",
    ),
];

/// Commands of features below stable in the maturity registry, by first word.
const COMMAND_FEATURES: [(&str, &str); 6] = [
    ("control", "cluster"),
    ("upgrade", "binary-upgrade"),
    ("cache", "http-cache"),
    ("consumers", "consumers"),
    ("keys", "consumers"),
    ("bans", "abuse"),
];

/// JSON outputs that print an admin API answer as it is: their fields are the API's, which the
/// OpenAPI check covers.
const API_OUTPUTS: [(&str, &str); 2] = [
    ("status --json", "GET /api/v1/status 200"),
    ("routes explain --json", "POST /api/v1/routes/explain 200"),
];

/// Documented `RDOCK_*` variables that are not a flag's `env` (those come from the command
/// tree): (name, what reads it, feature). A test in `tests/compat.rs` fails when the code reads
/// an `RDOCK_*` variable that is neither here, nor a flag's, nor internal by the stability
/// page's rules.
pub(crate) const PUBLIC_ENV: [(&str, &str, &str); 4] = [
    (
        "RDOCK_ADMIN_TOKEN",
        "the admin commands: the API token sent to the admin listener",
        "admin-api",
    ),
    (
        "RDOCK_ZONE",
        "this instance's zone for zone-aware balancing when `locality.zone` is not set",
        "balancing",
    ),
    (
        "RDOCK_POD_NAME",
        "the Kubernetes controller: this pod's name (downward API)",
        "gateway-api",
    ),
    (
        "RDOCK_POD_NAMESPACE",
        "the Kubernetes controller: this pod's namespace (downward API)",
        "gateway-api",
    ),
];

/// The snapshot of `surface`, as committed: pretty JSON with sorted keys and a final newline.
pub(crate) fn snapshot(surface: Surface) -> anyhow::Result<String> {
    let (name, body) = match surface {
        Surface::Metrics => ("metrics", metrics()?),
        Surface::Cli => ("cli", cli()),
        Surface::AccessLog => ("access-log", access_log()),
        Surface::Problems => ("problems", problems()),
        Surface::Env => ("env", env()),
        Surface::Deprecations => ("deprecations", deprecations()),
    };
    let mut document = Map::new();
    document.insert("surface".to_owned(), name.into());
    document.insert(
        "generated_by".to_owned(),
        format!("rdock schema --compat {name} (just compat)").into(),
    );
    document.insert(
        "stability".to_owned(),
        "docs/10-stability.md; compared with the last release tag by scripts/compat.py".into(),
    );
    if let Value::Object(body) = body {
        document.extend(body);
    }
    Ok(serde_json::to_string_pretty(&sorted(Value::Object(document)))? + "\n")
}

/// `value` with every object's keys in sorted order, whatever `serde_json`'s map keeps.
fn sorted(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<(String, Value)> = map.into_iter().collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            Value::Object(entries.into_iter().map(|(k, v)| (k, sorted(v))).collect())
        }
        Value::Array(items) => Value::Array(items.into_iter().map(sorted).collect()),
        other => other,
    }
}

/// The level of a maturity registry feature, `stable` when the id is unknown (a test keeps
/// every id known).
fn level(feature: &str) -> &'static str {
    rdock_model::maturity::feature(feature).map_or("stable", |f| f.level.as_str())
}

/// The unit a metric's name declares by Prometheus convention: its last word before `_total`.
fn unit(name: &str) -> &'static str {
    let base = name.strip_suffix("_total").unwrap_or(name);
    if base.ends_with("_seconds") {
        "seconds"
    } else if base.ends_with("_bytes") {
        "bytes"
    } else {
        ""
    }
}

fn metrics() -> anyhow::Result<Value> {
    let proxy = rdock_observability::Metrics::new("", "")?;
    let mut all: Vec<rdock_observability::MetricInfo> = proxy.catalogue().to_vec();
    all.extend(rdock_admin::metric_catalogue());
    let mut out = Map::new();
    for metric in all {
        let feature = rdock_observability::metric_feature(&metric.name).unwrap_or("observability");
        let mut labels = metric.labels.clone();
        labels.sort();
        let mut entry = json!({
            "type": metric.kind,
            "unit": unit(&metric.name),
            "help": metric.help,
            "labels": labels,
            "feature": feature,
            "maturity": level(feature),
        });
        if let Some(buckets) = &metric.buckets {
            entry["buckets"] = json!(buckets);
        }
        out.insert(metric.name.clone(), entry);
    }
    Ok(json!({ "metrics": out }))
}

/// The first word of a command path decides its feature.
fn command_feature(path: &str) -> Option<&'static str> {
    let first = path.split(' ').next().unwrap_or_default();
    COMMAND_FEATURES
        .iter()
        .find(|(word, _)| *word == first)
        .map(|(_, feature)| *feature)
}

fn cli() -> Value {
    let root = Cli::command();
    let mut commands = Map::new();
    walk(&root, "", &mut commands);
    let exit_codes: Map<String, Value> = EXIT_CODES
        .iter()
        .map(|(code, meaning)| ((*code).to_owned(), (*meaning).into()))
        .collect();
    let mut outputs = Map::new();
    outputs.insert(
        "validate --format json".to_owned(),
        schema_value(
            schemars::generate::SchemaSettings::draft2020_12()
                .for_serialize()
                .into_generator()
                .into_root_schema_for::<Vec<crate::validate::FileReport>>(),
        ),
    );
    outputs.insert(
        "version --json".to_owned(),
        schema_value(
            schemars::generate::SchemaSettings::draft2020_12()
                .for_serialize()
                .into_generator()
                .into_root_schema_for::<crate::VersionInfo>(),
        ),
    );
    for (output, operation) in API_OUTPUTS {
        outputs.insert(
            output.to_owned(),
            json!({ "x-rdock-openapi": operation, "description": "The admin API's answer as it is; its fields are checked with schema/openapi.json." }),
        );
    }
    json!({ "commands": commands, "exit_codes": exit_codes, "json_outputs": outputs })
}

/// A schema without its human-readable texts, which are not part of the promise.
fn schema_value(schema: schemars::Schema) -> Value {
    let mut value = schema.to_value();
    strip_texts(&mut value);
    value
}

fn strip_texts(value: &mut Value) {
    match value {
        Value::Object(map) => {
            map.remove("description");
            map.remove("title");
            map.values_mut().for_each(strip_texts);
        }
        Value::Array(items) => items.iter_mut().for_each(strip_texts),
        _ => {}
    }
}

/// Every visible command below `command`, keyed by its path (`control publish`).
fn walk(command: &Command, prefix: &str, out: &mut Map<String, Value>) {
    for sub in command.get_subcommands() {
        if sub.is_hide_set() {
            continue;
        }
        let path = if prefix.is_empty() {
            sub.get_name().to_owned()
        } else {
            format!("{prefix} {}", sub.get_name())
        };
        let feature = command_feature(&path);
        let mut entry = json!({
            "args": arguments(sub),
            "has_subcommands": sub.has_subcommands(),
        });
        if let Some(feature) = feature {
            entry["feature"] = feature.into();
            entry["maturity"] = level(feature).into();
        }
        out.insert(path.clone(), entry);
        walk(sub, &path, out);
    }
}

/// A command's visible arguments: flags by their long (or short) name, positionals as `#1`,
/// `#2`… by position.
fn arguments(command: &Command) -> Value {
    let mut out = Map::new();
    for arg in command.get_arguments() {
        let id = arg.get_id().as_str();
        if arg.is_hide_set() || id == "help" || id == "version" {
            continue;
        }
        let key = if arg.is_positional() {
            format!("#{}", arg.get_index().unwrap_or_default())
        } else if let Some(long) = arg.get_long() {
            format!("--{long}")
        } else if let Some(short) = arg.get_short() {
            format!("-{short}")
        } else {
            id.to_owned()
        };
        let takes_value = arg.get_action().takes_values();
        let value_names: Vec<String> = arg.get_value_names().map_or_else(
            || {
                if takes_value {
                    vec![id.to_uppercase()]
                } else {
                    Vec::new()
                }
            },
            |names| names.iter().map(ToString::to_string).collect(),
        );
        let defaults: Vec<String> = arg
            .get_default_values()
            .iter()
            .map(|v| v.to_string_lossy().into_owned())
            .collect();
        let possible: Vec<String> = arg
            .get_possible_values()
            .iter()
            .filter(|v| !v.is_hide_set())
            .map(|v| v.get_name().to_owned())
            .collect();
        let multiple = matches!(arg.get_action(), clap::ArgAction::Append)
            || arg.get_num_args().is_some_and(|n| n.max_values() > 1);
        let mut entry = json!({
            "takes_value": takes_value,
            "value_names": value_names,
            "defaults": defaults,
            "required": arg.is_required_set(),
            "multiple": multiple,
            "possible_values": possible,
        });
        if let Some(short) = arg.get_short() {
            entry["short"] = format!("-{short}").into();
        }
        if let Some(env) = arg.get_env() {
            entry["env"] = env.to_string_lossy().into_owned().into();
        }
        let aliases: Vec<String> = arg
            .get_visible_aliases()
            .unwrap_or_default()
            .iter()
            .map(|a| format!("--{a}"))
            .collect();
        if !aliases.is_empty() {
            entry["aliases"] = json!(aliases);
        }
        out.insert(key, entry);
    }
    Value::Object(out)
}

fn access_log() -> Value {
    let mut value = schemars::generate::SchemaSettings::draft2020_12()
        .for_serialize()
        .into_generator()
        .into_root_schema_for::<rdock_observability::AccessRecord>()
        .to_value();
    strip_texts(&mut value);
    if let Some(properties) = value["properties"].as_object_mut() {
        for field in properties.values_mut() {
            let Some(feature) = field["x-rdock-feature"].as_str().map(str::to_owned) else {
                continue;
            };
            let level = level(&feature);
            if level != "stable" {
                field["x-rdock-maturity"] = level.into();
            }
        }
    }
    json!({ "schema": value })
}

fn problems() -> Value {
    use rdock_middleware::problem::ProblemKind;
    let mut out = Map::new();
    for kind in ProblemKind::ALL {
        out.insert(
            kind.type_uri(),
            json!({
                "status": kind.status(),
                "feature": kind.feature(),
                "maturity": level(kind.feature()),
            }),
        );
    }
    json!({
        "problems": out,
        "untyped": "A status without a kind of its own is `about:blank` with the reason phrase as its title (RFC 9457 §4.2.1).",
    })
}

/// Every `RDOCK_*` variable a flag reads, with the flags, plus [`PUBLIC_ENV`].
fn env() -> Value {
    let mut flags: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    collect_env(&Cli::command(), "", &mut flags);
    let mut out = Map::new();
    for (name, mut users) in flags {
        users.sort();
        users.dedup();
        out.insert(
            name,
            json!({ "flags": users, "feature": "config-file", "maturity": "stable" }),
        );
    }
    for (name, read_by, feature) in PUBLIC_ENV {
        out.insert(
            name.to_owned(),
            json!({ "read_by": read_by, "feature": feature, "maturity": level(feature) }),
        );
    }
    json!({ "variables": out })
}

fn collect_env(
    command: &Command,
    prefix: &str,
    out: &mut std::collections::BTreeMap<String, Vec<String>>,
) {
    for arg in command.get_arguments() {
        if arg.is_hide_set() {
            continue;
        }
        if let (Some(env), Some(long)) = (arg.get_env(), arg.get_long()) {
            out.entry(env.to_string_lossy().into_owned())
                .or_default()
                .push(format!("{prefix} --{long}").trim().to_owned());
        }
    }
    for sub in command.get_subcommands() {
        if sub.is_hide_set() {
            continue;
        }
        let path = format!("{prefix} {}", sub.get_name());
        collect_env(sub, path.trim(), out);
    }
}

fn deprecations() -> Value {
    let entries: Vec<Value> = rdock_model::deprecation::REGISTRY
        .iter()
        .map(|d| {
            json!({
                "kind": d.kind,
                "element": d.element,
                "since": d.since,
                "removal": d.removal,
                "replacement": d.replacement,
            })
        })
        .collect();
    json!({ "deprecations": entries })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_feature_named_here_is_in_the_registry() {
        let named = COMMAND_FEATURES
            .iter()
            .map(|(_, f)| *f)
            .chain(PUBLIC_ENV.iter().map(|(_, _, f)| *f))
            .chain(rdock_observability::METRIC_FEATURES.iter().map(|(_, f)| *f))
            .chain(
                rdock_middleware::problem::ProblemKind::ALL
                    .iter()
                    .map(|k| k.feature()),
            );
        for feature in named {
            assert!(
                rdock_model::maturity::feature(feature).is_some(),
                "{feature} is not in the maturity registry"
            );
        }
    }

    #[test]
    fn every_command_feature_names_a_command() {
        let root = Cli::command();
        for (word, _) in COMMAND_FEATURES {
            assert!(
                root.get_subcommands().any(|c| c.get_name() == word),
                "no command {word}"
            );
        }
    }

    #[test]
    fn units_follow_the_name() {
        assert_eq!(unit("rdock_http_request_duration_seconds"), "seconds");
        assert_eq!(unit("rdock_tcp_bytes_total"), "bytes");
        assert_eq!(unit("rdock_http_requests_total"), "");
    }

    #[test]
    fn snapshots_are_sorted_and_end_with_a_newline() {
        for surface in [
            Surface::Metrics,
            Surface::Cli,
            Surface::AccessLog,
            Surface::Problems,
            Surface::Env,
            Surface::Deprecations,
        ] {
            let text = snapshot(surface).unwrap();
            assert!(text.ends_with("}\n"));
            let value: Value = serde_json::from_str(&text).unwrap();
            assert_eq!(
                serde_json::to_string_pretty(&sorted(value)).unwrap() + "\n",
                text
            );
        }
    }

    #[test]
    fn metrics_cover_the_proxy_and_the_admin_side() {
        let value: Value = serde_json::from_str(&snapshot(Surface::Metrics).unwrap()).unwrap();
        let metrics = value["metrics"].as_object().unwrap();
        assert_eq!(
            metrics["rdock_http_request_duration_seconds"]["type"],
            "histogram"
        );
        assert_eq!(
            metrics["rdock_http_request_duration_seconds"]["unit"],
            "seconds"
        );
        assert!(metrics["rdock_http_request_duration_seconds"]["buckets"].is_array());
        assert_eq!(metrics["rdock_admin_requests_total"]["type"], "counter");
        assert_eq!(
            metrics["rdock_http3_requests_total"]["maturity"],
            "experimental"
        );
        assert_eq!(metrics["rdock_cache_objects"]["maturity"], "beta");
        assert_eq!(metrics["rdock_http_requests_total"]["maturity"], "stable");
    }
}
