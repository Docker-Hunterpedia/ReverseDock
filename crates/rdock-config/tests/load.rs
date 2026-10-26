//! Loading behaviour: unknown keys, type errors, syntax errors.

use rdock_config::{Format, LoadError, LoadOptions, load_str};
use rdock_model::Severity;

const STRICT: LoadOptions = LoadOptions { strict: true };

fn yaml(text: &str) -> Result<rdock_config::Loaded, LoadError> {
    load_str(text, Format::Yaml, LoadOptions::default())
}

#[test]
fn empty_documents_are_empty_configs() {
    let loaded = yaml("").unwrap();
    assert_eq!(loaded.diagnostics, Vec::new());
    assert_eq!(loaded.config.routes.len(), 0);
}

#[test]
fn unknown_keys_warn_with_suggestions_and_fail_in_strict_mode() {
    let text = r#"
routes:
  app:
    match: "Host(`a.example.com`)"
    service: app
    midlewares: [auth]
services:
  app:
    backends: [{ address: "app:3000", wieght: 2 }]
middlewares:
  auth: { type: basic_auth, users: ["a:$2y$05$abcdefghijklmnopqrstuv"], realmm: x }
servics: {}
"#;
    let loaded = yaml(text).unwrap();
    let found: Vec<(Severity, &str, Option<&str>)> = loaded
        .diagnostics
        .iter()
        .map(|d| (d.severity, d.path.as_str(), d.hint.as_deref()))
        .collect();
    assert!(found.contains(&(
        Severity::Warning,
        "routes.app.midlewares",
        Some("did you mean `middlewares`?")
    )));
    assert!(found.contains(&(
        Severity::Warning,
        "services.app.backends[0].wieght",
        Some("did you mean `weight`?")
    )));
    assert!(found.contains(&(
        Severity::Warning,
        "middlewares.auth.realmm",
        Some("did you mean `realm`?")
    )));
    assert!(found.contains(&(
        Severity::Warning,
        "servics",
        Some("did you mean `services`?")
    )));
    assert!(!loaded.has_errors());

    let strict = load_str(text, Format::Yaml, STRICT).unwrap();
    assert!(strict.has_errors());
    assert_eq!(
        strict.diagnostics.iter().filter(|d| d.is_error()).count(),
        4
    );
}

#[test]
fn type_errors_point_at_the_value() {
    let err = yaml(
        "services:\n  app:\n    backends:\n      - address: \"app:3000\"\n        weight: heavy\n",
    )
    .unwrap_err();
    let LoadError::Invalid { path, message } = err else {
        panic!("expected Invalid")
    };
    assert_eq!(path, "services.app.backends[0].weight");
    assert!(message.contains("invalid type"), "{message}");

    let err = yaml("listeners:\n  web: { address: \"80\" }\n").unwrap_err();
    assert!(
        err.to_string()
            .starts_with("listeners.web.address: invalid listen address `80`"),
        "{err}"
    );

    let err = yaml(
        "services:\n  app:\n    timeouts: { connect: 5 }\n    backends: [{ address: \"a:1\" }]\n",
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("services.app.timeouts.connect"),
        "{err}"
    );
}

#[test]
fn syntax_errors_and_duplicate_keys_are_reported() {
    let err = yaml("routes:\n  app: [unclosed\n").unwrap_err();
    assert!(matches!(err, LoadError::Syntax { .. }), "{err}");
    let err = yaml("routes: {}\nroutes: {}\n").unwrap_err();
    assert!(
        err.to_string().to_lowercase().contains("duplicate"),
        "{err}"
    );
    let err = load_str("{ \"routes\": ", Format::Json, LoadOptions::default()).unwrap_err();
    assert!(err.to_string().starts_with("invalid JSON"), "{err}");
}

#[test]
fn yaml_anchors_and_merge_keys_work() {
    let text = r#"
x-backend: &backend { address: "app:3000" }
services:
  app:
    backends: [*backend]
"#;
    let loaded = yaml(text).unwrap();
    assert_eq!(loaded.config.services["app"].backends.len(), 1);
    assert_eq!(
        loaded.diagnostics.len(),
        1,
        "x-backend is reported as unknown: {:?}",
        loaded.diagnostics
    );
    let merged = "defaults_tls: &tls { dns_provider: cf }\nroutes:\n  app:\n    match: \"Host(`a.example.com`)\"\n    service: app\n    tls: { <<: *tls, domains: [a.example.com] }\n";
    let loaded = yaml(merged).unwrap();
    let route = &loaded.config.routes["app"];
    assert!(
        matches!(&route.tls, Some(rdock_model::route::RouteTls::Options(o)) if o.dns_provider.as_deref() == Some("cf"))
    );
}

#[test]
fn yaml_1_1_booleans_are_not_guessed() {
    let err = yaml("defaults: { redirect_http_to_https: yes }\n").unwrap_err();
    assert!(
        err.to_string().contains("defaults.redirect_http_to_https"),
        "{err}"
    );
    let loaded = yaml("defaults: { tls: off }\nroutes:\n  r: { match: \"PathPrefix(`/`)\", service: s, tls: off }\nservices:\n  s: { backends: [{ address: \"s:1\" }] }\n").unwrap();
    assert_eq!(loaded.config.defaults.tls, rdock_model::route::TlsMode::Off);
    assert!(loaded.diagnostics.is_empty(), "{:?}", loaded.diagnostics);
}
