use rdock_model::deprecation::{Kind, REGISTRY, TEST_ENTRIES};

use super::*;

fn real() -> Vec<&'static Deprecation> {
    REGISTRY.iter().collect()
}

fn with_tests() -> Vec<&'static Deprecation> {
    REGISTRY.iter().chain(TEST_ENTRIES).collect()
}

#[test]
fn nothing_deprecated_leaves_the_text_alone() {
    let text = "# a comment\nroutes:\n  app: { match: \"Host(`a`)\", service: app }   # trailing\n";
    let result = config_with(text, Format::Yaml, &real()).unwrap();
    assert!(!result.changed());
    assert_eq!(result.text, text);
    assert!(result.formatting_kept);
    assert_eq!(result.version, 1);
}

#[test]
fn the_webhook_moves_into_existing_channels_keeping_comments() {
    let text = "\
# Alerts for the team.
observability:
  alerts:
    # The old webhook, from v0.3.
    webhook:   # still works
      url: https://alerts.example.com/rdock
      # A secret reference.
      token: \"${file:/run/secrets/alert_token}\"
      timeout: 20s
    channels:
      team:
        type: slack
        url: \"${file:/run/secrets/slack}\"   # the team channel
    min_interval: 10m
routes: {}
";
    let result = config_with(text, Format::Yaml, &real()).unwrap();
    assert!(result.formatting_kept, "{}", result.text);
    assert_eq!(
        result.text,
        "\
# Alerts for the team.
observability:
  alerts:
    # The old webhook, from v0.3.
    channels:
      team:
        type: slack
        url: \"${file:/run/secrets/slack}\"   # the team channel
      webhook:   # still works
        type: webhook
        url: https://alerts.example.com/rdock
        # A secret reference.
        token: \"${file:/run/secrets/alert_token}\"
    min_interval: 10m
routes: {}
"
    );
    assert_eq!(result.done.len(), 1);
    assert_eq!(result.done[0].path, "observability.alerts.webhook");
    assert_eq!(
        result.done[0].to.as_deref(),
        Some("observability.alerts.channels.webhook")
    );
    assert_eq!(result.manual, Vec::<Change>::new());
}

#[test]
fn the_webhook_gets_a_new_channels_mapping_in_its_place() {
    let text = "\
observability:
  alerts:
    webhook:
      url: http://127.0.0.1:9000/hook
    min_interval: 10m
";
    let result = config_with(text, Format::Yaml, &real()).unwrap();
    assert!(result.formatting_kept, "{}", result.text);
    assert_eq!(
        result.text,
        "\
observability:
  alerts:
    channels:
      webhook:
        type: webhook
        allow_private_targets: true
        url: http://127.0.0.1:9000/hook
    min_interval: 10m
"
    );
}

#[test]
fn flow_style_is_written_out_again() {
    let text =
        "# lost\nobservability: { alerts: { webhook: { url: \"https://a.example.com/x\" } } }\n";
    let result = config_with(text, Format::Yaml, &real()).unwrap();
    assert!(!result.formatting_kept);
    let value = rdock_config::parse_document(&result.text, Format::Yaml).unwrap();
    assert_eq!(
        value,
        serde_json::json!({ "observability": { "alerts": { "channels": { "webhook": { "type": "webhook", "url": "https://a.example.com/x" } } } } })
    );
}

#[test]
fn json_stays_json() {
    let text =
        "{\"observability\": {\"alerts\": {\"webhook\": {\"url\": \"https://a.example.com/x\"}}}}";
    let result = config_with(text, Format::Json, &real()).unwrap();
    assert!(!result.formatting_kept);
    let value: Value = serde_json::from_str(&result.text).unwrap();
    assert_eq!(
        value["observability"]["alerts"]["channels"]["webhook"]["type"],
        "webhook"
    );
}

#[test]
fn renamed_keys_keep_quotes_and_flow_style() {
    let text = "\
routes:
  a: { rule: \"Host(`a`)\", service: s }   # flow
  b:
    'rule': \"Host(`b`)\"
    service: s
  c: { match: \"Host(`c`)\", service: s }
";
    let result = config_with(text, Format::Yaml, &with_tests()).unwrap();
    assert!(result.formatting_kept);
    assert_eq!(
        result.text,
        "\
routes:
  a: { match: \"Host(`a`)\", service: s }   # flow
  b:
    'match': \"Host(`b`)\"
    service: s
  c: { match: \"Host(`c`)\", service: s }
"
    );
    assert_eq!(result.done.len(), 2);
}

#[test]
fn renames_in_json_keep_the_layout() {
    let text = "{\n  \"routes\": {\n    \"a\": { \"rule\": \"Host(`a`)\" }\n  }\n}\n";
    let result = config_with(text, Format::Json, &with_tests()).unwrap();
    assert!(result.formatting_kept);
    assert_eq!(
        result.text,
        "{\n  \"routes\": {\n    \"a\": { \"match\": \"Host(`a`)\" }\n  }\n}\n"
    );
}

#[test]
fn conflicts_and_manual_changes_are_reported_not_applied() {
    let text = "routes:\n  a: { rule: x, match: y }\n";
    let result = config_with(text, Format::Yaml, &with_tests()).unwrap();
    assert!(!result.changed());
    assert_eq!(result.text, text);
    assert_eq!(result.manual.len(), 1);
    assert!(result.manual[0].detail.contains("`match` is set too"));
}

#[test]
fn version_one_is_explicit_and_others_are_refused() {
    let ok = config_with("version: 1\n", Format::Yaml, &real()).unwrap();
    assert_eq!(ok.version, 1);
    assert!(!ok.changed());
    let err = config_with("version: 2\n", Format::Yaml, &real()).unwrap_err();
    assert_eq!(
        err.to_string(),
        "`version: 2`: this release reads configuration schema version 1 only"
    );
    assert_eq!(
        config_with("- a\n", Format::Yaml, &real()).unwrap_err(),
        ConfigError::NotAMapping
    );
    assert!(matches!(
        config_with("a: [", Format::Yaml, &real()),
        Err(ConfigError::Syntax(_))
    ));
}

#[test]
fn every_rewrite_rule_in_the_registry_produces_a_valid_configuration() {
    for entry in REGISTRY.iter().filter(|e| e.kind == Kind::ConfigKey) {
        assert!(entry.rewrite.is_automatic(), "{}", entry.element);
    }
    let text = "observability:\n  alerts:\n    webhook: { url: \"https://a.example.com/x\", timeout: 3s }\n";
    let migrated = config_with(text, Format::Yaml, &real()).unwrap();
    let loaded = rdock_config::load_str(&migrated.text, Format::Yaml).unwrap();
    assert!(!loaded.has_errors(), "{:?}", loaded.diagnostics);
    assert!(
        loaded
            .diagnostics
            .iter()
            .all(|d| d.code.as_deref() != Some("deprecated")),
        "{:?}",
        loaded.diagnostics
    );
}

#[test]
fn the_diff_names_both_sides() {
    let d = diff("a: 1\n", "b: 1\n", "rdock.yaml");
    assert!(d.contains("--- rdock.yaml"), "{d}");
    assert!(d.contains("+++ rdock.yaml (migrated)"), "{d}");
    assert!(d.contains("-a: 1") && d.contains("+b: 1"), "{d}");
}
