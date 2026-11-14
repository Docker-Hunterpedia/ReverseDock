use serde_json::json;

use super::*;

fn none(_: &Map<String, Value>) -> Vec<(String, Value)> {
    Vec::new()
}

static RENAME: Deprecation = Deprecation {
    kind: Kind::ConfigKey,
    element: "routes.*.rule",
    since: "1.1",
    removal: "2.0",
    deprecated_on: None,
    sunset: None,
    replacement: "`routes.<name>.match`",
    note: "test",
    rewrite: Rewrite::RenameKey("match"),
    read_by_model: false,
};

static NESTED_LIST: Deprecation = Deprecation {
    kind: Kind::ConfigKey,
    element: "services.*.backends.*.old_weight",
    since: "1.1",
    removal: "2.0",
    deprecated_on: None,
    sunset: None,
    replacement: "`weight`",
    note: "test",
    rewrite: Rewrite::RenameKey("weight"),
    read_by_model: false,
};

static VALUE: Deprecation = Deprecation {
    kind: Kind::ConfigValue,
    element: "services.*.load_balancer.policy=least_conn",
    since: "1.1",
    removal: "2.0",
    deprecated_on: None,
    sunset: None,
    replacement: "`least_requests`",
    note: "test",
    rewrite: Rewrite::ReplaceValue("least_requests"),
    read_by_model: true,
};

static MOVE_WITH_CAPTURE: Deprecation = Deprecation {
    kind: Kind::ConfigKey,
    element: "services.*.old_breaker",
    since: "1.1",
    removal: "2.0",
    deprecated_on: None,
    sunset: None,
    replacement: "`services.<name>.health.breaker`",
    note: "test",
    rewrite: Rewrite::Move {
        parent: "services.*.health",
        key: "breaker",
        drop: &["unused"],
        extra: none,
    },
    read_by_model: false,
};

static MANUAL: Deprecation = Deprecation {
    kind: Kind::ConfigKey,
    element: "security.legacy",
    since: "1.1",
    removal: "2.0",
    deprecated_on: None,
    sunset: None,
    replacement: "something that needs a decision",
    note: "test",
    rewrite: Rewrite::Manual,
    read_by_model: true,
};

#[test]
fn renames_keys_in_every_map_entry() {
    let mut doc = json!({ "routes": {
        "a": { "rule": "Host(`a`)", "service": "s" },
        "b": { "match": "Host(`b`)", "service": "s" },
        "c": { "rule": "Host(`c`)", "match": "Host(`c`)" }
    }});
    let done = rewrite_with(&mut doc, &[&RENAME], |_| true);
    assert_eq!(done.len(), 2);
    assert_eq!(display(&done[0].found.path), "routes.a.rule");
    assert_eq!(display(done[0].to.as_ref().unwrap()), "routes.a.match");
    assert_eq!(
        doc["routes"]["a"],
        json!({ "match": "Host(`a`)", "service": "s" })
    );
    // Both set: left alone, with the reason.
    assert!(done[1].to.is_none());
    assert!(
        done[1]
            .skipped
            .as_ref()
            .unwrap()
            .contains("`match` is set too")
    );
    assert_eq!(doc["routes"]["c"]["rule"], "Host(`c`)");
}

#[test]
fn walks_lists_and_nested_paths() {
    let mut doc = json!({ "services": { "s": { "backends": [
        { "address": "a:1", "old_weight": 2 },
        { "address": "b:1" },
        { "address": "c:1", "old_weight": 5 }
    ]}}});
    let found = scan_with(&doc, &[&NESTED_LIST]);
    let paths: Vec<String> = found.iter().map(|f| display(&f.path)).collect();
    assert_eq!(
        paths,
        [
            "services.s.backends[0].old_weight",
            "services.s.backends[2].old_weight"
        ]
    );
    rewrite_with(&mut doc, &[&NESTED_LIST], |_| true);
    assert_eq!(
        doc["services"]["s"]["backends"][2],
        json!({ "address": "c:1", "weight": 5 })
    );
}

#[test]
fn replaces_only_the_deprecated_value() {
    let mut doc = json!({ "services": {
        "a": { "load_balancer": { "policy": "least_conn" } },
        "b": { "load_balancer": { "policy": "random" } }
    }});
    let done = rewrite_with(&mut doc, &[&VALUE], |_| true);
    assert_eq!(done.len(), 1);
    assert_eq!(
        doc["services"]["a"]["load_balancer"]["policy"],
        "least_requests"
    );
    assert_eq!(doc["services"]["b"]["load_balancer"]["policy"], "random");
}

#[test]
fn moves_a_mapping_under_a_parent_named_by_the_capture() {
    let mut doc = json!({ "services": { "s": { "old_breaker": { "ratio": 0.5, "unused": 1 } } } });
    let done = rewrite_with(&mut doc, &[&MOVE_WITH_CAPTURE], |_| true);
    assert_eq!(
        display(done[0].to.as_ref().unwrap()),
        "services.s.health.breaker"
    );
    assert_eq!(
        doc,
        json!({ "services": { "s": { "health": { "breaker": { "ratio": 0.5 } } } } })
    );
}

#[test]
fn manual_entries_are_reported_and_left_alone() {
    let mut doc = json!({ "security": { "legacy": true } });
    let done = rewrite_with(&mut doc, &[&MANUAL], |_| true);
    assert!(done[0].to.is_none());
    assert!(done[0].skipped.as_ref().unwrap().contains("manual change"));
    assert_eq!(doc["security"]["legacy"], true);
}

#[test]
fn the_alerts_webhook_becomes_a_channel() {
    let entry = &REGISTRY[0];
    let mut doc = json!({ "observability": { "alerts": {
        "webhook": { "url": "https://alerts.example.com/rdock", "token": "${file:/run/secrets/t}", "timeout": "20s" },
        "channels": { "webhook": { "type": "slack", "url": "https://hooks.slack.com/x" } }
    }}});
    let done = rewrite_with(&mut doc, &[entry], |_| true);
    assert_eq!(
        display(done[0].to.as_ref().unwrap()),
        "observability.alerts.channels.webhook-2"
    );
    assert_eq!(
        doc["observability"]["alerts"],
        json!({ "channels": {
            "webhook": { "type": "slack", "url": "https://hooks.slack.com/x" },
            "webhook-2": { "type": "webhook", "url": "https://alerts.example.com/rdock", "token": "${file:/run/secrets/t}" }
        }})
    );
    // A loopback receiver keeps working: the channel allows private targets.
    let mut doc = json!({ "observability": { "alerts": { "webhook": { "url": "http://127.0.0.1:9000/hook" } } } });
    rewrite_with(&mut doc, &[entry], |_| true);
    assert_eq!(
        doc["observability"]["alerts"]["channels"]["webhook"],
        json!({ "type": "webhook", "url": "http://127.0.0.1:9000/hook", "allow_private_targets": true })
    );
    // The result is a valid configuration.
    let config: crate::Config = serde_json::from_value(doc).unwrap();
    assert!(config.validate().iter().all(|d| !d.is_error()));
}

#[test]
fn the_loader_rewrites_only_what_the_model_no_longer_reads() {
    let mut doc = json!({ "routes": { "a": { "rule": "Host(`a`)" } }, "observability": { "alerts": { "webhook": { "url": "https://a.example.com" } } } });
    let done = rewrite_with(&mut doc, &[&RENAME, &REGISTRY[0]], |e| !e.read_by_model);
    assert_eq!(done.len(), 1);
    assert!(doc["observability"]["alerts"]["webhook"].is_object());
    assert_eq!(doc["routes"]["a"]["match"], "Host(`a`)");
}

#[test]
fn diagnostics_carry_code_since_removal_and_replacement() {
    let doc = json!({ "routes": { "a": { "rule": "x" } } });
    let found = scan_with(&doc, &[&RENAME]);
    let d = found[0].diagnostic();
    assert!(!d.is_error());
    assert_eq!(d.path, "routes.a.rule");
    assert_eq!(d.code.as_deref(), Some("deprecated"));
    assert_eq!(d.since.as_deref(), Some("1.1"));
    assert_eq!(d.removal.as_deref(), Some("2.0"));
    assert_eq!(d.replacement.as_deref(), Some("`routes.<name>.match`"));
    assert!(d.hint.unwrap().contains("rdock migrate config"));
    let json = serde_json::to_value(diagnostic(&RENAME, "p".into())).unwrap();
    assert_eq!(json["code"], "deprecated");
    // Ordinary diagnostics keep their JSON shape.
    let plain = serde_json::to_value(Diagnostic::error("p", "m")).unwrap();
    assert_eq!(
        plain,
        json!({ "severity": "error", "path": "p", "message": "m", "hint": null })
    );
}

static LABEL: Deprecation = Deprecation {
    kind: Kind::Label,
    element: "rdock.old",
    since: "1.1",
    removal: "2.0",
    deprecated_on: None,
    sunset: None,
    replacement: "`rdock.new`",
    note: "test",
    rewrite: Rewrite::RenameKey("rdock.new"),
    read_by_model: false,
};

#[test]
fn labels_follow_the_configuration_paths() {
    let (new, entry) = rewrite_label_with("rdock.routes.api.rule", &[&RENAME]).unwrap();
    assert_eq!(new, "rdock.routes.api.match");
    assert_eq!(entry.element, "routes.*.rule");
    assert!(rewrite_label_with("rdock.routes.api.match", &[&RENAME]).is_none());
    assert!(rewrite_label_with("rdock.services.api.rule", &[&RENAME]).is_none());
    assert!(rewrite_label_with("traefik.http.routers.api.rule", &[&RENAME]).is_none());
    assert_eq!(
        rewrite_label_with("rdock.old", &[&LABEL]).unwrap().0,
        "rdock.new"
    );
}

#[test]
fn api_templates_match_one_segment_per_parameter() {
    assert!(template_matches(
        "/api/v1/consumers/{name}",
        "/api/v1/consumers/acme"
    ));
    assert!(!template_matches(
        "/api/v1/consumers/{name}",
        "/api/v1/consumers"
    ));
    assert!(!template_matches(
        "/api/v1/consumers/{name}",
        "/api/v1/consumers/a/keys"
    ));
    assert!(template_matches("/api/v1/listeners", "/api/v1/listeners/"));
}

#[test]
fn the_registry_is_well_formed() {
    for entry in REGISTRY.iter().chain(TEST_ENTRIES) {
        let major = |v: &str| v.split('.').next().and_then(|m| m.parse::<u32>().ok());
        assert!(
            major(entry.removal) > major(entry.since),
            "{}: removal only in a later major",
            entry.element
        );
        assert!(!entry.replacement.is_empty() && !entry.note.is_empty());
        if entry.kind == Kind::ApiOperation {
            assert!(entry.element.split_once(' ').is_some(), "{}", entry.element);
        }
        if !entry.read_by_model {
            assert!(entry.rewrite.is_automatic(), "{}", entry.element);
        }
    }
    // Test entries say so.
    assert!(
        TEST_ENTRIES
            .iter()
            .all(|e| e.note.starts_with("Test entry"))
    );
    assert_eq!(SCHEMA_MIGRATIONS.len(), 0, "no v2 exists yet");
}
