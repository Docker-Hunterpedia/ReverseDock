use serde_json::{Value, json};

use crate::{Config, Diagnostic, Severity};

fn validate(value: Value) -> Vec<Diagnostic> {
    let config: Config = serde_json::from_value(value).unwrap();
    config.validate()
}

/// `(path, message)` of every error.
fn errors(value: Value) -> Vec<(String, String)> {
    validate(value)
        .into_iter()
        .filter(Diagnostic::is_error)
        .map(|d| (d.path, d.message))
        .collect()
}

fn warnings(value: Value) -> Vec<(String, String)> {
    validate(value)
        .into_iter()
        .filter(|d| d.severity == Severity::Warning)
        .map(|d| (d.path, d.message))
        .collect()
}

fn has(found: &[(String, String)], path: &str, fragment: &str) -> bool {
    found.iter().any(|(p, m)| p == path && m.contains(fragment))
}

fn app() -> Value {
    json!({
        "routes": { "app": { "match": "Host(`app.example.com`)", "service": "app" } },
        "services": { "app": { "backends": [{ "address": "app:3000" }] } }
    })
}

fn with(mut base: Value, patch: Value) -> Value {
    merge(&mut base, patch);
    base
}

fn merge(base: &mut Value, patch: Value) {
    match (base, patch) {
        (Value::Object(base), Value::Object(patch)) => {
            for (key, value) in patch {
                merge(base.entry(key).or_insert(Value::Null), value);
            }
        }
        (base, patch) => *base = patch,
    }
}

#[test]
fn a_small_config_is_valid() {
    assert_eq!(validate(app()), Vec::new());
}

#[test]
fn reports_missing_references_with_suggestions() {
    let found = validate(with(
        app(),
        json!({ "routes": { "app": { "service": "ap", "middlewares": ["nope@dockr"] } } }),
    ));
    let service = found
        .iter()
        .find(|d| d.path == "routes.app.service")
        .unwrap();
    assert_eq!(service.message, "service `ap` does not exist");
    assert_eq!(service.hint.as_deref(), Some("did you mean `app`?"));
    assert!(
        found.iter().any(|d| d.path == "routes.app.middlewares[0]"
            && d.message.contains("unknown provider `dockr`"))
    );
    let other_provider = with(
        app(),
        json!({ "routes": { "app": { "middlewares": ["auth@docker"] } } }),
    );
    assert_eq!(errors(other_provider), Vec::new());
}

#[test]
fn explains_invalid_rules() {
    let found = validate(with(
        app(),
        json!({ "routes": { "app": { "match": "Host(`a.com`) & Path(`/`)" } } }),
    ));
    let rule = found.iter().find(|d| d.path == "routes.app.match").unwrap();
    assert!(rule.message.contains("`&` must be doubled"));
    assert!(rule.hint.as_deref().unwrap().contains('^'));
    let empty = errors(with(app(), json!({ "routes": { "app": { "match": {} } } })));
    assert!(has(&empty, "routes.app.match", "empty"));
    let tcp_in_http = errors(with(
        app(),
        json!({ "routes": { "app": { "match": "HostSNI(`a.com`)" } } }),
    ));
    assert!(has(&tcp_in_http, "routes.app.match", "TCP matcher"));
}

#[test]
fn checks_listeners() {
    let config = with(
        app(),
        json!({
            "listeners": {
                "web": { "address": ":80", "tls": {}, "protocol": "http" },
                "other": { "address": "0.0.0.0:80" },
                "websecure": { "address": ":443", "tls": {} },
                "quic": { "address": ":443", "protocol": "udp" },
                "db": { "address": ":5432", "protocol": "tcp" }
            },
            "routes": { "app": { "listeners": ["websecure", "db", "missing"] } }
        }),
    );
    let found = errors(config);
    assert!(has(&found, "listeners.web.tls", "cannot terminate TLS"));
    assert!(has(
        &found,
        "listeners.other.address",
        "overlaps listener `web`"
    ));
    assert!(
        !found.iter().any(|(p, _)| p == "listeners.quic.address"),
        "UDP and TCP may share a port"
    );
    assert!(has(&found, "routes.app.listeners[1]", "is `tcp`"));
    assert!(has(&found, "routes.app.listeners[2]", "does not exist"));
}

#[test]
fn automatic_https_needs_hosts_and_dns_for_wildcards() {
    let no_host = with(
        app(),
        json!({ "routes": { "app": { "match": "PathPrefix(`/`)" } } }),
    );
    assert!(has(
        &warnings(no_host),
        "routes.app.tls",
        "needs a host name"
    ));
    let wildcard = with(
        app(),
        json!({ "routes": { "app": { "match": "Host(`*.example.com`)" } } }),
    );
    assert!(has(
        &errors(wildcard),
        "routes.app.tls",
        "needs a DNS-01 certificate"
    ));
    let with_dns = with(
        app(),
        json!({
            "acme": { "dns_providers": { "cf": { "type": "cloudflare", "api_token": "${file:/run/secrets/cf}" } } },
            "routes": { "app": { "match": "Host(`*.example.com`)", "tls": { "dns_provider": "cf" } } }
        }),
    );
    assert_eq!(validate(with_dns), Vec::new());
    let tls_off = with(
        app(),
        json!({ "routes": { "app": { "match": "PathPrefix(`/`)", "tls": "off" } } }),
    );
    assert_eq!(validate(tls_off), Vec::new());
}

#[test]
fn checks_services() {
    let config = json!({
        "services": {
            "empty": {},
            "both": { "backends": [{ "address": "a:1", "weight": 0 }], "split": [{ "service": "empty", "weight": 1 }] },
            "a": { "split": [{ "service": "b", "weight": 1 }] },
            "b": { "split": [{ "service": "a", "weight": 1 }] },
            "hash": { "backends": [{ "address": "a:1" }], "load_balancer": { "policy": "header_hash" } },
            "tls": { "backends": [{ "address": "a:1" }], "scheme": "https", "tls": { "verify": false, "cert_file": "/c.pem" } }
        }
    });
    let found = errors(config.clone());
    assert!(has(&found, "services.empty", "no backends"));
    assert!(has(&found, "services.both", "not both"));
    assert!(has(
        &found,
        "services.both.backends[0].weight",
        "at least 1"
    ));
    assert!(has(&found, "services.a.split", "cycle"));
    assert!(has(
        &found,
        "services.hash.load_balancer.hash_on",
        "needs `hash_on`"
    ));
    assert!(has(&found, "services.tls.tls", "cert_file"));
    assert!(has(
        &warnings(config),
        "services.tls.tls.verify",
        "not verified"
    ));
}

#[test]
fn checks_middlewares_without_echoing_secrets() {
    let config = json!({
        "middlewares": {
            "auth": { "type": "basic_auth", "users": ["admin:hunter2", "ok:$2y$05$abcdefghijklmnopqrstuv"] },
            "cors": { "type": "cors", "allowed_origins": ["*", "https://a.example.com/path"], "allow_credentials": true },
            "redirect": { "type": "redirect", "regex": "^http://(.*)" },
            "strip": { "type": "strip_prefix", "prefixes": ["api"] },
            "errors": { "type": "errors", "status": ["404", "600-700"], "file": "/e.html", "service": "x" },
            "limit": { "type": "rate_limit", "average": 0 }
        }
    });
    let found = validate(config);
    let auth = found
        .iter()
        .find(|d| d.path == "middlewares.auth.users[0]")
        .unwrap();
    assert!(auth.message.contains("`admin`") && !auth.message.contains("hunter2"));
    assert!(!found.iter().any(|d| d.path == "middlewares.auth.users[1]"));
    let found: Vec<(String, String)> = found.into_iter().map(|d| (d.path, d.message)).collect();
    assert!(has(
        &found,
        "middlewares.cors.allowed_origins[1]",
        "not an origin"
    ));
    assert!(has(&found, "middlewares.cors.allow_credentials", "`*`"));
    assert!(has(&found, "middlewares.redirect", "`replacement`"));
    assert!(has(
        &found,
        "middlewares.strip.prefixes[0]",
        "start with `/`"
    ));
    assert!(has(&found, "middlewares.errors.status[1]", "not a status"));
    assert!(has(
        &found,
        "middlewares.errors",
        "either `file` or `service`"
    ));
    assert!(has(
        &found,
        "middlewares.limit.average",
        "greater than zero"
    ));
}

#[test]
fn checks_tcp_routes() {
    let config = json!({
        "listeners": { "db": { "address": ":5432", "protocol": "tcp" }, "web": { "address": ":80" } },
        "tcp_routes": {
            "ok": { "match": "HostSNI(`*`)", "listeners": ["db"], "service": "db" },
            "bad": { "match": "Host(`a.com`)", "listeners": ["web"], "service": "nope" },
            "none": { "match": "HostSNI(`*`)", "service": "db" }
        },
        "tcp_services": { "db": { "backends": [{ "address": "10.0.0.20:5432" }] } }
    });
    let found = errors(config);
    assert!(!found.iter().any(|(p, _)| p.starts_with("tcp_routes.ok")));
    assert!(has(&found, "tcp_routes.bad.match", "HTTP matcher"));
    assert!(has(&found, "tcp_routes.bad.listeners[0]", "is `http`"));
    assert!(has(
        &found,
        "tcp_routes.bad.service",
        "TCP service `nope` does not exist"
    ));
    assert!(has(&found, "tcp_routes.none.listeners", "need `listeners`"));
}

#[test]
fn flags_risky_security_and_admin_settings() {
    let config = with(
        app(),
        json!({
            "security": { "client_ip_header": "cf-connecting-ip" },
            "admin": { "listener": "0.0.0.0:2080" },
            "acme": { "ca": "zerossl", "dns_providers": { "cf": { "type": "cloudflare", "api_token": "abc123" } } }
        }),
    );
    let found = validate(config);
    let as_pairs: Vec<(String, String)> = found
        .iter()
        .map(|d| (d.path.clone(), d.message.clone()))
        .collect();
    assert!(has(
        &as_pairs,
        "security.client_ip_header",
        "needs `cloudflare`"
    ));
    assert!(has(
        &as_pairs,
        "admin.listener",
        "reachable from the network"
    ));
    assert!(has(
        &as_pairs,
        "acme.dns_providers.cf.api_token",
        "secret is written"
    ));
    assert!(has(&as_pairs, "acme.eab", "external account binding"));
}

#[test]
fn checks_names_and_version() {
    let found = errors(json!({
        "version": 2,
        "services": { "bad@name": { "backends": [{ "address": "a:1" }] } }
    }));
    assert!(has(&found, "version", "unsupported"));
    assert!(has(&found, "services[\"bad@name\"]", "invalid name"));
}
