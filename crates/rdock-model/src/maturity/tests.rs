use std::collections::BTreeSet;

use serde_json::Value;

use super::*;

/// Fixtures are JSON: this crate has no YAML parser.
fn config(json: &str) -> Config {
    serde_json::from_str(json).expect("fixture parses")
}

fn schema() -> Value {
    crate::json_schema().to_value()
}

/// Every top-level section, middleware `type`, provider and cargo-feature-gated setting must
/// be listed under a feature. A new one fails here until it is given a level.
#[test]
fn every_section_middleware_type_provider_and_gated_setting_has_a_level() {
    let schema = schema();
    let mut required: Vec<String> = Vec::new();
    for key in schema["properties"].as_object().unwrap().keys() {
        required.push(key.clone());
    }
    let middleware = crate::locate(&schema, "middlewares.*").unwrap();
    let defs = schema.pointer(&middleware).unwrap();
    let target = defs["$ref"].as_str().unwrap().trim_start_matches('#');
    for variant in schema.pointer(target).unwrap()["oneOf"].as_array().unwrap() {
        let kind = variant["properties"]["type"]["const"].as_str().unwrap();
        required.push(format!("middlewares.*.type={kind}"));
    }
    let providers = crate::locate(&schema, "providers").unwrap();
    let providers = schema.pointer(&providers).unwrap();
    let target = providers["$ref"].as_str().unwrap().trim_start_matches('#');
    for key in schema.pointer(target).unwrap()["properties"]
        .as_object()
        .unwrap()
        .keys()
    {
        required.push(format!("providers.{key}"));
    }
    // Settings that need a cargo feature (`gate.rs`, `not_built`).
    required.push("listeners.*.http3".to_owned());
    required.push("middlewares.*.type=wasm".to_owned());
    let missing: Vec<&String> = required.iter().filter(|r| listed(r).is_none()).collect();
    assert!(
        missing.is_empty(),
        "not in the maturity registry (crates/rdock-model/src/maturity.rs): {missing:?}"
    );
}

#[test]
fn every_location_exists_in_the_schema_and_ids_are_unique() {
    let root = schemars::schema_for!(Config).to_value();
    let mut ids = BTreeSet::new();
    for feature in FEATURES {
        assert!(ids.insert(feature.id), "duplicate id {}", feature.id);
        assert!(feature.since.starts_with('v'), "{}", feature.id);
        for location in feature.locations {
            assert!(
                crate::locate(&root, location).is_some(),
                "{}: `{location}` is not in the schema",
                feature.id
            );
        }
        if feature.level != Level::Stable && !feature.locations.is_empty() {
            assert!(feature.detect.is_some(), "{} needs a detector", feature.id);
        }
        if feature.level == Level::Experimental {
            assert!(
                feature.cargo_feature.is_some() || feature.detect.is_some(),
                "{}",
                feature.id
            );
        }
    }
    // A location is listed once.
    let mut seen = BTreeSet::new();
    for feature in FEATURES {
        for location in feature.locations {
            assert!(seen.insert(*location), "`{location}` is listed twice");
        }
    }
}

#[test]
fn covering_falls_back_to_the_nearest_parent() {
    assert_eq!(covering("listeners.*.http3.enabled").unwrap().id, "http3");
    assert_eq!(covering("listeners.*.address").unwrap().id, "http-proxy");
    assert_eq!(covering("middlewares.*.type=wasm").unwrap().id, "wasm");
    assert_eq!(covering("caches.*.max_size").unwrap().id, "http-cache");
    assert!(covering("nothing").is_none());
}

#[test]
fn levels_at_1_0_follow_adr_0033() {
    let level = |id: &str| feature(id).unwrap().level;
    for id in ["wasm", "http3"] {
        assert_eq!(level(id), Level::Experimental, "{id}");
    }
    for id in [
        "http-cache",
        "native-plugins",
        "agents",
        "consumers",
        "oidc",
        "validation-and-transformation",
        "udp",
        "vault",
        "balancing",
        "binary-upgrade",
        "cluster",
        "cluster-limits",
        "admission-control",
        "tenants",
        "terraform-provider",
        "go-client",
        "migrate-caddy",
        "migrate-nginx",
        "migrate-report",
    ] {
        assert_eq!(level(id), Level::Beta, "{id}");
    }
    for id in [
        "http-proxy",
        "file-provider",
        "docker-provider",
        "automatic-https",
        "reliability",
        "admin-api",
        "users-and-audit",
        "dashboard",
        "swarm-provider",
        "tcp-routes",
        "static-files",
        "dns-01-providers",
        "gateway-api",
        "problem-types",
    ] {
        assert_eq!(level(id), Level::Stable, "{id}");
    }
}

const WASM: &str = r#"{
  "middlewares": { "filter": { "type": "wasm", "path": "/p/f.wasm", "sha256": "0000000000000000000000000000000000000000000000000000000000000000", "trusted_keys": ["k"] } }
}"#;

#[test]
fn an_experimental_feature_needs_the_opt_in() {
    let mut out = Vec::new();
    check_opt_in(&config(WASM), false, &mut out);
    assert_eq!(out.len(), 1, "{out:?}");
    assert!(out[0].is_error());
    assert_eq!(out[0].path, "middlewares.filter");
    assert_eq!(out[0].code.as_deref(), Some("experimental_not_enabled"));
    let hint = out[0].hint.as_deref().unwrap();
    assert!(hint.contains("experimental: [wasm]"), "{hint}");
    assert!(
        hint.contains("may change or be removed in any release"),
        "{hint}"
    );
    assert!(hint.contains("`wasm` cargo feature"), "{hint}");

    let mut with = config(WASM);
    with.experimental = vec!["wasm".to_owned()];
    let mut out = Vec::new();
    check_opt_in(&with, false, &mut out);
    assert_eq!(out, Vec::<Diagnostic>::new());
}

#[test]
fn http3_counts_only_when_enabled() {
    let off = config(
        r#"{ "listeners": { "web": { "address": ":443", "tls": {}, "http3": { "enabled": false } } } }"#,
    );
    assert!(in_use(&off).iter().all(|u| u.feature.id != "http3"));
    let on = config(
        r#"{ "listeners": { "web": { "address": ":443", "tls": {}, "http3": { "enabled": true } } } }"#,
    );
    let mut out = Vec::new();
    check_opt_in(&on, false, &mut out);
    assert_eq!(out.len(), 1, "{out:?}");
    assert_eq!(out[0].path, "listeners.web.http3.enabled");
}

#[test]
fn unknown_unused_and_graduated_names() {
    let mut c = config("{}");
    c.experimental = vec![
        "wsam".to_owned(),
        "http3".to_owned(),
        "http-cache".to_owned(),
    ];
    let mut out = Vec::new();
    check_opt_in(&c, false, &mut out);
    let by_path = |p: &str| out.iter().find(|d| d.path == p).unwrap();
    let unknown = by_path("experimental[0]");
    assert!(unknown.is_error());
    assert_eq!(unknown.hint.as_deref(), Some("did you mean `wasm`?"));
    let unused = by_path("experimental[1]");
    assert!(!unused.is_error());
    assert_eq!(unused.code.as_deref(), Some("experimental_unused"));
    let graduated = by_path("experimental[2]");
    assert!(!graduated.is_error());
    assert!(
        graduated.message.contains("is beta now"),
        "{}",
        graduated.message
    );
}

#[test]
fn beta_features_are_found_with_their_paths() {
    let c = config(
        r#"{
          "caches": { "mem": { "type": "memory" } },
          "middlewares": { "c": { "type": "cache", "store": "mem" }, "q": { "type": "rate_limit", "average": 1, "scope": "cluster" } },
          "services": { "s": { "backends": [{ "address": "127.0.0.1:1", "zone": "a" }], "load_balancer": { "policy": "peak_ewma" } } }
        }"#,
    );
    let used = in_use(&c);
    let ids: Vec<&str> = used.iter().map(|u| u.feature.id).collect();
    assert_eq!(ids, ["http-cache", "balancing", "cluster-limits"]);
    assert_eq!(used[0].paths, ["caches.mem", "middlewares.c"]);
    assert_eq!(
        used[1].paths,
        ["services.s.load_balancer", "services.s.backends[0]"]
    );
    assert_eq!(used[2].paths, ["middlewares.q.scope"]);
}
