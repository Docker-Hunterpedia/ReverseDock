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
    let default_certificate = with(
        app(),
        json!({
            "routes": { "app": { "match": "PathPrefix(`/`)" } },
            "defaults": { "certificate": "site" },
            "certificates": { "site": { "cert_file": "/etc/rdock/site.pem", "key_file": "/etc/rdock/site.key" } }
        }),
    );
    assert!(!has(
        &warnings(default_certificate),
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
fn acme_can_be_turned_off_or_given_a_default_dns_provider() {
    assert_eq!(validate(with(app(), json!({ "acme": false }))), Vec::new());
    assert_eq!(validate(with(app(), json!({ "acme": true }))), Vec::new());
    let cf = json!({ "type": "cloudflare", "api_token": "${file:/run/secrets/cf}" });
    let wildcard_with_default = with(
        app(),
        json!({
            "acme": { "dns_provider": "cf", "dns_providers": { "cf": cf } },
            "routes": { "app": { "match": "Host(`*.example.com`)" } }
        }),
    );
    assert_eq!(validate(wildcard_with_default), Vec::new());
    let undefined = with(app(), json!({ "acme": { "dns_provider": "nope" } }));
    assert!(has(
        &errors(undefined),
        "acme.dns_provider",
        "`nope` is not defined"
    ));
    let acme_off = with(
        app(),
        json!({
            "acme": false,
            "routes": { "app": { "tls": { "dns_provider": "cf" } } }
        }),
    );
    assert!(has(
        &errors(acme_off),
        "routes.app.tls.dns_provider",
        "not defined"
    ));
}

#[test]
fn checks_exec_and_webhook_dns_providers() {
    let config = with(
        app(),
        json!({
            "acme": { "dns_providers": {
                "script": { "type": "exec", "command": "dns-hook.sh", "timeout": "0s" },
                "hook": { "type": "webhook", "url": "http://dns.example.com/acme", "token": "plain" },
                "local": { "type": "webhook", "url": "http://127.0.0.1:8080/acme" },
                "good": { "type": "exec", "command": "/usr/local/bin/dns-hook", "args": ["--zone", "example.com"] }
            } },
            "observability": { "alerts": { "webhook": { "url": "http://alerts.example.com/" } } }
        }),
    );
    let found = errors(config.clone());
    assert!(has(
        &found,
        "acme.dns_providers.script.command",
        "not an absolute path"
    ));
    assert!(has(
        &found,
        "acme.dns_providers.script.timeout",
        "longer than zero"
    ));
    assert!(has(&found, "acme.dns_providers.hook.url", "not encrypted"));
    assert!(has(
        &found,
        "observability.alerts.webhook.url",
        "not encrypted"
    ));
    assert!(
        !found
            .iter()
            .any(|(p, _)| p.starts_with("acme.dns_providers.local")
                || p.starts_with("acme.dns_providers.good"))
    );
    assert!(has(
        &warnings(config),
        "acme.dns_providers.hook.token",
        "a secret is written in the configuration file"
    ));
}

#[test]
fn checks_dns_resolvers_and_propagation_timeout() {
    let config = with(
        app(),
        json!({ "acme": { "dns_resolvers": ["1.1.1.1", "[2606:4700::1111]:53", "ns1.example.com"], "dns_propagation_timeout": "0s" } }),
    );
    let found = errors(config);
    assert!(has(&found, "acme.dns_resolvers[2]", "not an IP address"));
    assert!(
        !found
            .iter()
            .any(|(p, _)| p == "acme.dns_resolvers[0]" || p == "acme.dns_resolvers[1]")
    );
    assert!(has(
        &found,
        "acme.dns_propagation_timeout",
        "longer than zero"
    ));
}

#[test]
fn plain_routes_use_the_plain_listeners() {
    let config: Config = serde_json::from_value(with(
        app(),
        json!({
            "listeners": { "web": { "address": ":80" }, "websecure": { "address": ":443", "tls": {} } },
            "routes": {
                "plain": { "match": "Host(`p.example.com`)", "service": "app", "tls": "off" },
                "pinned": { "match": "Host(`q.example.com`)", "service": "app", "tls": "off", "listeners": ["websecure"] }
            }
        }),
    ))
    .unwrap();
    assert_eq!(config.route_listeners(&config.routes["plain"]), ["web"]);
    assert_eq!(
        config.route_listeners(&config.routes["pinned"]),
        ["websecure"]
    );
    assert_eq!(config.route_listeners(&config.routes["app"]), ["websecure"]);
}

#[test]
fn public_ip_addresses_need_shortlived_certificates() {
    let ip = with(
        app(),
        json!({ "routes": { "app": { "match": "Host(`203.0.113.7`)" } } }),
    );
    assert!(has(
        &warnings(ip.clone()),
        "routes.app.tls",
        "needs `acme.profile: shortlived`"
    ));
    let shortlived = with(ip.clone(), json!({ "acme": { "profile": "shortlived" } }));
    assert_eq!(validate(shortlived), Vec::new());
    let private = with(
        app(),
        json!({ "routes": { "app": { "match": "Host(`192.168.1.10`) || Host(`[::1]`)" } } }),
    );
    assert_eq!(validate(private), Vec::new());
    let dns = with(
        ip,
        json!({
            "acme": { "profile": "shortlived", "dns_provider": "cf", "dns_providers": {
                "cf": { "type": "cloudflare", "api_token": "${file:/run/secrets/cf}" }
            } }
        }),
    );
    assert!(has(
        &errors(dns),
        "routes.app.tls",
        "DNS-01 cannot validate"
    ));
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
        "needs trusted_proxies"
    ));
    assert!(has(
        &as_pairs,
        "admin.listener",
        "reachable from the network without TLS"
    ));
    assert!(has(&as_pairs, "admin.allowed_hosts", "list the host names"));
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

#[test]
fn a_network_admin_listener_needs_tls_and_known_hosts() {
    let tls = json!({ "cert_file": "/etc/rdock/admin.pem", "key_file": "/etc/rdock/admin.key" });
    let ok = with(
        app(),
        json!({ "admin": { "listener": "10.0.0.5:2080", "tls": tls } }),
    );
    let found = validate(ok);
    assert!(
        !found
            .iter()
            .any(|d| d.severity == Severity::Error && d.path.starts_with("admin")),
        "{found:?}"
    );

    let all = with(
        app(),
        json!({ "admin": { "listener": ":2080", "tls": tls, "allowed_hosts": ["admin.example.com"] } }),
    );
    assert!(
        !validate(all)
            .iter()
            .any(|d| d.severity == Severity::Error && d.path.starts_with("admin"))
    );

    let bad = with(
        app(),
        json!({ "admin": { "threads": 0, "allowed_hosts": ["a b"] } }),
    );
    let found: Vec<(String, String)> = validate(bad)
        .into_iter()
        .map(|d| (d.path, d.message))
        .collect();
    assert!(has(&found, "admin.threads", "between 1 and 16"));
    assert!(has(&found, "admin.allowed_hosts[0]", "not a host name"));
}
