//! Loading behaviour: unknown keys, references, type errors, syntax errors.

use rdock_config::{Format, LoadError, load_str};
use rdock_model::Severity;

fn yaml(text: &str) -> Result<rdock_config::Loaded, LoadError> {
    load_str(text, Format::Yaml)
}

#[test]
fn empty_documents_are_empty_configs() {
    let loaded = yaml("").unwrap();
    assert_eq!(loaded.diagnostics, Vec::new());
    assert_eq!(loaded.config.routes.len(), 0);
}

#[test]
fn unknown_keys_are_errors_with_suggestions() {
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
    for (path, near) in [
        ("routes.app.midlewares", "middlewares"),
        ("services.app.backends[0].wieght", "weight"),
        ("middlewares.auth.realmm", "realm"),
        ("servics", "services"),
    ] {
        let hint = format!("did you mean `{near}`?");
        assert!(
            found.contains(&(Severity::Error, path, Some(hint.as_str()))),
            "{path}: {found:?}"
        );
    }
    assert_eq!(
        loaded.diagnostics.iter().filter(|d| d.is_error()).count(),
        4
    );
}

#[test]
fn references_are_resolved_except_in_secrets_and_replacements() {
    let dir = tempfile::tempdir().unwrap();
    let token = dir.path().join("token");
    std::fs::write(&token, "abc\n").unwrap();
    let text = format!(
        r#"
services:
  app:
    backends: [{{ address: "${{file:{token}}}:8080" }}]
middlewares:
  www: {{ type: redirect, regex: "^https://(.*)$", replacement: "https://www.${{1}}" }}
acme:
  email: ops@example.com
  dns_providers:
    cf: {{ type: cloudflare, api_token: "${{file:/run/secrets/cf_token}}" }}
"#,
        token = token.display()
    );
    let loaded = yaml(&text).unwrap();
    assert_eq!(
        loaded.config.services["app"].backends[0]
            .address
            .to_string(),
        "abc:8080"
    );
    let rdock_model::middleware::Middleware::Redirect(redirect) = &loaded.config.middlewares["www"]
    else {
        panic!("redirect")
    };
    assert_eq!(redirect.replacement.as_deref(), Some("https://www.${1}"));
    let acme = loaded.config.acme.as_ref().unwrap();
    let rdock_model::acme::DnsProvider::Cloudflare { api_token } = &acme.dns_providers["cf"];
    assert_eq!(api_token, "${file:/run/secrets/cf_token}");
    // The stored source keeps the reference, not the resolved value.
    assert!(loaded.source.to_string().contains("${file:"));
    assert!(!loaded.source.to_string().contains("abc:8080"));
}

#[test]
fn reference_errors_are_reported_and_values_stay_hidden() {
    let loaded = yaml("acme: { email: \"${RDOCK_TEST_SURELY_UNSET}\" }\n").unwrap();
    assert!(loaded.has_errors());
    assert!(
        loaded.diagnostics[0]
            .message
            .contains("`RDOCK_TEST_SURELY_UNSET` is not set"),
        "{:?}",
        loaded.diagnostics
    );
    let dir = tempfile::tempdir().unwrap();
    let secret = dir.path().join("weight");
    std::fs::write(&secret, "very-secret-value").unwrap();
    let err = yaml(&format!(
        "services:\n  app:\n    backends: [{{ address: \"${{file:{}}}\" }}]\n",
        secret.display()
    ))
    .unwrap_err();
    assert!(!err.to_string().contains("very-secret-value"), "{err}");
    assert!(err.to_string().contains("value not shown"), "{err}");
}

#[test]
fn extension_keys_are_ignored() {
    let loaded = yaml("x-common: &backend { address: \"app:3000\" }\nservices:\n  app:\n    backends: [*backend]\n    x-note: kept for humans\n").unwrap();
    assert_eq!(loaded.diagnostics, Vec::new());
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
    let err = load_str("{ \"routes\": ", Format::Json).unwrap_err();
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
        loaded.diagnostics,
        Vec::new(),
        "x- keys are extension fields"
    );
    let merged = "x-tls: &tls { dns_provider: cf }\nroutes:\n  app:\n    match: \"Host(`a.example.com`)\"\n    service: app\n    tls: { <<: *tls, domains: [a.example.com] }\n";
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
