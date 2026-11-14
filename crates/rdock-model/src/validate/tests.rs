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
fn api_dns_providers_need_secret_references_and_safe_urls() {
    let config = with(
        app(),
        json!({
            "acme": { "dns_providers": {
                "do": { "type": "digitalocean", "api_token": "dop_v1_plain", "zone": "" },
                "hz": { "type": "hetzner", "api_token": "${file:/run/secrets/hz}", "api_url": "http://api.example.com/" },
                "test": { "type": "hetzner", "api_token": "${env:HETZNER_API_TOKEN}", "api_url": "http://127.0.0.1:9000/" },
                "good": { "type": "digitalocean", "api_token": "${file:/run/secrets/do}", "zone": "example.com" }
            } }
        }),
    );
    let found = errors(config);
    assert!(has(
        &found,
        "acme.dns_providers.do.api_token",
        "a secret is written in the configuration file"
    ));
    assert!(has(&found, "acme.dns_providers.do.zone", "zone is empty"));
    assert!(has(
        &found,
        "acme.dns_providers.hz.api_url",
        "not encrypted"
    ));
    assert!(
        !found
            .iter()
            .any(|(p, _)| p.starts_with("acme.dns_providers.test")
                || p.starts_with("acme.dns_providers.good")),
        "{found:?}"
    );
}

#[test]
fn cloud_dns_providers_need_secret_references_and_one_azure_method() {
    let config = with(
        app(),
        json!({
            "acme": { "dns_providers": {
                "desec": { "type": "desec", "token": "plain-token", "zone": "" },
                "r53": { "type": "route53", "access_key_id": "AKIDEXAMPLE", "secret_access_key": "wJalrXUtnFEMI", "session_token": "${env:AWS_SESSION_TOKEN}", "region": "cn-north-1" },
                "gcp": { "type": "google_cloud_dns", "credentials_file": "", "project": "", "api_url": "http://dns.example.com/" },
                "az_none": { "type": "azure_dns", "subscription_id": "s", "resource_group": "rg", "zone": "example.com" },
                "az_two": { "type": "azure_dns", "tenant_id": "t", "client_id": "c", "client_secret": "${file:/run/secrets/az}", "managed_identity": true, "subscription_id": "s", "resource_group": "rg", "zone": "example.com" },
                "az_literal": { "type": "azure_dns", "client_secret": "s3cret", "subscription_id": "s", "resource_group": "", "zone": "example.com" },
                "good_desec": { "type": "desec", "token": "${env:DESEC_TOKEN}" },
                "good_r53": { "type": "route53", "access_key_id": "${env:AWS_ACCESS_KEY_ID}", "secret_access_key": "${env:AWS_SECRET_ACCESS_KEY}", "hosted_zone_id": "Z123", "region": "eu-west-1" },
                "good_gcp": { "type": "google_cloud_dns", "credentials_file": "/run/secrets/gcp.json", "zone": "example-com" },
                "good_az_cert": { "type": "azure_dns", "tenant_id": "t", "client_id": "c", "client_certificate": "${file:/run/secrets/az.pem}", "subscription_id": "s", "resource_group": "rg", "zone": "example.com", "environment": "usgovernment" },
                "good_az_mi": { "type": "azure_dns", "managed_identity": true, "subscription_id": "s", "resource_group": "rg", "zone": "example.com" }
            } }
        }),
    );
    let found = errors(config);
    for (path, message) in [
        (
            "acme.dns_providers.desec.token",
            "a secret is written in the configuration file",
        ),
        ("acme.dns_providers.desec.zone", "zone is empty"),
        (
            "acme.dns_providers.r53.secret_access_key",
            "a secret is written",
        ),
        (
            "acme.dns_providers.r53.region",
            "outside the standard AWS partition",
        ),
        (
            "acme.dns_providers.gcp.credentials_file",
            "credentials_file is empty",
        ),
        ("acme.dns_providers.gcp.project", "project is empty"),
        ("acme.dns_providers.gcp.api_url", "not encrypted"),
        ("acme.dns_providers.az_none", "set exactly one of"),
        ("acme.dns_providers.az_none.tenant_id", "required"),
        ("acme.dns_providers.az_two", "set exactly one of"),
        (
            "acme.dns_providers.az_literal.client_secret",
            "a secret is written",
        ),
        ("acme.dns_providers.az_literal.client_id", "required"),
        (
            "acme.dns_providers.az_literal.resource_group",
            "resource_group is empty",
        ),
    ] {
        assert!(has(&found, path, message), "{path}: {message} in {found:?}");
    }
    assert!(
        !found
            .iter()
            .any(|(p, _)| p.starts_with("acme.dns_providers.good")
                || p == "acme.dns_providers.r53.session_token"
                || p == "acme.dns_providers.r53.access_key_id"),
        "{found:?}"
    );
}

#[test]
fn rfc2136_refuses_md5_and_unsigned_updates_without_consent() {
    let provider = |extra: Value| {
        let mut base = json!({
            "type": "rfc2136",
            "nameserver": "192.0.2.53",
            "tsig_key_name": "rdock-acme",
            "tsig_secret": "${file:/run/secrets/tsig}"
        });
        merge(&mut base, extra);
        with(
            app(),
            json!({ "acme": { "dns_providers": { "ns": base } } }),
        )
    };
    assert_eq!(errors(provider(json!({}))), []);
    assert_eq!(warnings(provider(json!({}))), []);
    let md5 = errors(provider(json!({ "tsig_algorithm": "hmac-md5" })));
    assert!(has(
        &md5,
        "acme.dns_providers.ns.tsig_algorithm",
        "hmac-md5 must not be used"
    ));
    let sha1 = warnings(provider(json!({ "tsig_algorithm": "hmac-sha1" })));
    assert!(has(
        &sha1,
        "acme.dns_providers.ns.tsig_algorithm",
        "not recommended"
    ));
    let literal = errors(provider(json!({ "tsig_secret": "c2VjcmV0" })));
    assert!(has(
        &literal,
        "acme.dns_providers.ns.tsig_secret",
        "a secret is written"
    ));
    let bad = errors(provider(
        json!({ "nameserver": "ns1.example.com", "tsig_key_name": null }),
    ));
    assert!(has(
        &bad,
        "acme.dns_providers.ns.nameserver",
        "not an IP address"
    ));
    assert!(has(&bad, "acme.dns_providers.ns.tsig_key_name", "required"));

    let unsigned = |extra: Value| {
        let mut base = json!({ "type": "rfc2136", "nameserver": "[2001:db8::53]:5353", "insecure_unsigned": true });
        merge(&mut base, extra);
        with(
            app(),
            json!({ "acme": { "dns_providers": { "ns": base } } }),
        )
    };
    assert_eq!(errors(unsigned(json!({}))), []);
    assert!(has(
        &warnings(unsigned(json!({}))),
        "acme.dns_providers.ns.insecure_unsigned",
        "without TSIG"
    ));
    assert!(has(
        &errors(unsigned(json!({ "tsig_key_name": "k" }))),
        "acme.dns_providers.ns.insecure_unsigned",
        "a TSIG key is set"
    ));
    assert!(has(
        &errors(with(
            app(),
            json!({ "acme": { "dns_providers": { "ns": { "type": "rfc2136", "nameserver": "192.0.2.53" } } } })
        )),
        "acme.dns_providers.ns.tsig_secret",
        "required"
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
fn plain_routes_never_attach_to_provider_listeners_implicitly() {
    // A Gateway's internal listener (`name@kubernetes`) is reached only by naming it.
    let config: Config = serde_json::from_value(with(
        app(),
        json!({
            "listeners": {
                "web": { "address": ":80" },
                "websecure": { "address": ":443", "tls": {} },
                "gw-a@kubernetes": { "address": ":20000" },
                "gw-b@kubernetes": { "address": ":20001" }
            },
            "routes": {
                "plain": { "match": "PathPrefix(`/`)", "service": "app", "tls": "off" },
                "named": { "match": "PathPrefix(`/`)", "service": "app", "tls": "off", "listeners": ["gw-a@kubernetes"] }
            }
        }),
    ))
    .unwrap();
    assert_eq!(config.route_listeners(&config.routes["plain"]), ["web"]);
    assert_eq!(
        config.route_listeners(&config.routes["named"]),
        ["gw-a@kubernetes"]
    );
    // With only provider plain listeners, a plain route falls back to `defaults.listeners`.
    let only_provider: Config = serde_json::from_value(with(
        app(),
        json!({
            "listeners": {
                "websecure": { "address": ":443", "tls": {} },
                "gw-a@kubernetes": { "address": ":20000" }
            },
            "routes": { "plain": { "match": "PathPrefix(`/`)", "service": "app", "tls": "off" } }
        }),
    ))
    .unwrap();
    assert_eq!(
        only_provider.route_listeners(&only_provider.routes["plain"]),
        ["websecure"]
    );
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
fn a_tcp_only_config_needs_no_http_listener() {
    let config = json!({
        "listeners": { "db": { "address": ":5432", "protocol": "tcp" } },
        "tcp_routes": { "db": { "match": "HostSNI(`*`)", "listeners": ["db"], "service": "db" } },
        "tcp_services": { "db": { "backends": [{ "address": "10.0.0.20:5432" }] } }
    });
    assert_eq!(validate(config), Vec::new());
}

#[test]
fn checks_tcp_tls_middlewares_and_listener_kinds() {
    let config = json!({
        "listeners": {
            "db": { "address": ":5432", "protocol": "tcp", "starttls": "postgres" },
            "tls": { "address": ":6000", "protocol": "tcp", "tls": {} },
            "websecure": { "address": ":443", "tls": {}, "starttls": "postgres" }
        },
        "tcp_routes": {
            "terminate": { "match": "HostSNI(`db.example.com`)", "listeners": ["db", "tls"], "service": "db", "tls": {} },
            "mixed": { "match": "HostSNI(`*`)", "listeners": ["websecure"], "service": "db", "tls": { "passthrough": true } },
            "sni": { "match": "HostSNI(`db.example.com`)", "listeners": ["websecure"], "service": "db", "tls": { "passthrough": true } },
            "limits": { "match": "HostSNI(`*`)", "listeners": ["db"], "service": "db", "middlewares": ["allow", "conns", "per-route", "headers", "missing"] },
            "mysql": { "match": "HostSNI(`my.example.com`)", "listeners": ["tls"], "service": "mysql", "tls": { "passthrough": true } }
        },
        "tcp_services": {
            "db": { "backends": [{ "address": "10.0.0.20:5432" }], "timeouts": { "idle": "0s", "termination_delay": "0s" } },
            "mysql": { "backends": [{ "address": "10.0.0.30:3306" }] }
        },
        "middlewares": {
            "allow": { "type": "ip_allow", "cidrs": ["10.0.0.0/8"] },
            "conns": { "type": "in_flight", "amount": 10 },
            "per-route": { "type": "in_flight", "amount": 10, "key": "route" },
            "headers": { "type": "headers", "request": { "set": { "x": "y" } } }
        }
    });
    let found = errors(config.clone());
    assert!(has(
        &found,
        "listeners.websecure.starttls",
        "only `tcp` listeners"
    ));
    assert!(!found.iter().any(|(p, _)| p == "listeners.db.starttls"));
    assert!(has(
        &found,
        "tcp_routes.terminate.listeners[0]",
        "needs `tls` on listener `db`"
    ));
    assert!(
        !found
            .iter()
            .any(|(p, _)| p == "tcp_routes.terminate.listeners[1]")
    );
    assert!(has(
        &found,
        "tcp_routes.mixed.listeners[0]",
        "cannot share the https listener"
    ));
    assert!(!found.iter().any(|(p, _)| p.starts_with("tcp_routes.sni")));
    assert!(
        !found
            .iter()
            .any(|(p, _)| p == "tcp_routes.limits.middlewares[0]")
    );
    assert!(
        !found
            .iter()
            .any(|(p, _)| p == "tcp_routes.limits.middlewares[1]")
    );
    assert!(has(
        &found,
        "tcp_routes.limits.middlewares[2]",
        "per client IP"
    ));
    assert!(has(
        &found,
        "tcp_routes.limits.middlewares[3]",
        "does not apply to TCP routes"
    ));
    assert!(has(
        &found,
        "tcp_routes.limits.middlewares[4]",
        "does not exist"
    ));
    assert!(has(
        &found,
        "tcp_services.db.timeouts.idle",
        "greater than zero"
    ));
    assert!(
        !found
            .iter()
            .any(|(p, _)| p == "tcp_services.db.timeouts.termination_delay")
    );
    let warned = warnings(config);
    assert!(has(&warned, "tcp_routes.mysql.match", "MySQL (port 3306)"));
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

#[test]
fn admin_passwords_refuse_weak_settings() {
    let bad = with(
        app(),
        json!({ "admin": { "passwords": {
            "min_length": 6,
            "argon2": { "memory_kib": 4096, "iterations": 1, "parallelism": 0 },
            "blocklist_file": ""
        } } }),
    );
    let found: Vec<(String, String)> = validate(bad)
        .into_iter()
        .map(|d| (d.path, d.message))
        .collect();
    assert!(has(
        &found,
        "admin.passwords.min_length",
        "between 8 and 128"
    ));
    assert!(has(
        &found,
        "admin.passwords.argon2.memory_kib",
        "between 19456"
    ));
    assert!(has(
        &found,
        "admin.passwords.argon2.iterations",
        "between 2"
    ));
    assert!(has(
        &found,
        "admin.passwords.argon2.parallelism",
        "between 1"
    ));
    assert!(has(&found, "admin.passwords.blocklist_file", "empty"));

    let stronger = with(
        app(),
        json!({ "admin": { "passwords": { "min_length": 16, "argon2": { "memory_kib": 65536, "iterations": 3 } } } }),
    );
    assert!(
        !validate(stronger)
            .iter()
            .any(|d| d.severity == Severity::Error && d.path.starts_with("admin")),
    );
}

#[test]
fn admin_sessions_are_bounded() {
    let bad = with(
        app(),
        json!({ "admin": { "sessions": { "idle": "1m", "absolute": "1d" } } }),
    );
    let found: Vec<(String, String)> = validate(bad)
        .into_iter()
        .map(|d| (d.path, d.message))
        .collect();
    assert!(has(&found, "admin.sessions.idle", "between 5m and 12h"));
    assert!(has(&found, "admin.sessions.absolute", "between 5m and 12h"));

    let inverted = with(
        app(),
        json!({ "admin": { "sessions": { "idle": "2h", "absolute": "1h" }, "mfa": "required" } }),
    );
    let found: Vec<(String, String)> = validate(inverted)
        .into_iter()
        .map(|d| (d.path, d.message))
        .collect();
    assert!(has(&found, "admin.sessions.idle", "not be longer"));
}

#[test]
fn alert_channels_need_safe_urls_and_smtp_needs_tls() {
    let bad = with(
        app(),
        json!({ "observability": { "alerts": {
            "min_interval": "10s",
            "channels": {
                "plain": { "type": "slack", "url": "http://hooks.example.com/x" },
                "mail": { "type": "smtp", "host": "mail.example.com", "tls": "none", "from": "rdock@example.com", "to": ["ops@example.com"], "username": "u" },
                "signed": { "type": "webhook", "url": "https://hooks.example.com", "secret": "not-a-whsec" },
                "bad name": { "type": "discord", "url": "${env:DISCORD}" }
            },
            "rules": { "error_rate": { "percent": 0, "window": "1h" } }
        } } }),
    );
    let found: Vec<(String, String)> = validate(bad)
        .into_iter()
        .map(|d| (d.path, d.message))
        .collect();
    assert!(has(
        &found,
        "observability.alerts.min_interval",
        "between 1m"
    ));
    assert!(has(
        &found,
        "observability.alerts.channels.plain.url",
        "https://"
    ));
    assert!(has(
        &found,
        "observability.alerts.channels.mail.tls",
        "unencrypted"
    ));
    assert!(has(
        &found,
        "observability.alerts.channels.mail.password",
        "both"
    ));
    assert!(has(
        &found,
        "observability.alerts.channels.signed.secret",
        "whsec_"
    ));
    assert!(has(
        &found,
        "observability.alerts.channels.bad name",
        "channel names"
    ));
    assert!(has(
        &found,
        "observability.alerts.rules.error_rate.percent",
        "between 1 and 100"
    ));
    assert!(has(
        &found,
        "observability.alerts.rules.error_rate.window",
        "15m"
    ));
}

#[test]
fn swarm_polls_at_least_every_second_and_warns_about_acme_per_replica() {
    let fast = with(
        app(),
        json!({ "acme": false, "providers": { "swarm": { "poll_interval": "500ms" } } }),
    );
    assert!(has(
        &errors(fast),
        "providers.swarm.poll_interval",
        "at least 1s"
    ));
    let acme_off = with(
        app(),
        json!({ "acme": false, "providers": { "swarm": {} } }),
    );
    assert_eq!(errors(acme_off.clone()), Vec::new());
    assert!(!has(
        &warnings(acme_off),
        "providers.swarm",
        "automatic HTTPS"
    ));
    let acme_on = with(app(), json!({ "providers": { "swarm": {} } }));
    assert!(has(
        &warnings(acme_on),
        "providers.swarm",
        "every replica orders and stores its own certificates"
    ));
}

fn site(static_config: Value) -> Value {
    let mut middleware = json!({ "type": "static", "root": "/srv/site" });
    merge(&mut middleware, static_config);
    json!({
        "routes": { "site": { "match": "Host(`site.example.com`)", "middlewares": ["files"] } },
        "middlewares": { "files": middleware }
    })
}

#[test]
fn a_route_ending_with_a_terminal_middleware_needs_no_service() {
    assert_eq!(validate(site(json!({}))), Vec::new());
    let maintenance = json!({
        "routes": { "down": { "match": "Host(`a.example.com`)", "middlewares": ["down"] } },
        "middlewares": { "down": { "type": "maintenance" } }
    });
    assert_eq!(validate(maintenance), Vec::new());
}

#[test]
fn a_route_without_service_must_end_with_a_terminal_middleware() {
    let found = errors(json!({
        "routes": { "app": { "match": "Host(`app.example.com`)" } }
    }));
    assert!(
        has(&found, "routes.app.service", "the route needs a service"),
        "{found:?}"
    );
    let found = errors(site(json!({ "pass_through": true })));
    assert!(
        has(&found, "routes.site.service", "the route needs a service"),
        "{found:?}"
    );
    let diagnostics = validate(site(json!({ "pass_through": true })));
    assert!(
        diagnostics.iter().any(|d| d
            .hint
            .as_deref()
            .is_some_and(|h| h.contains("pass_through"))),
        "{diagnostics:?}"
    );
    let found = errors(json!({
        "routes": { "down": { "match": "Host(`a.example.com`)", "middlewares": ["down"] } },
        "middlewares": { "down": { "type": "maintenance", "allow": ["10.0.0.0/8"] } }
    }));
    assert!(
        has(&found, "routes.down.service", "the route needs a service"),
        "{found:?}"
    );
    // Another provider's middleware is checked when the configuration compiles.
    let other = json!({
        "routes": { "app": { "match": "Host(`app.example.com`)", "middlewares": ["files@docker"] } }
    });
    assert_eq!(errors(other), Vec::new());
}

#[test]
fn middlewares_after_a_terminal_one_are_reported() {
    let mut config = site(json!({}));
    merge(
        &mut config,
        json!({
            "routes": { "site": { "middlewares": ["files", "hdr"] } },
            "middlewares": { "hdr": { "type": "headers" } }
        }),
    );
    let found = warnings(config);
    assert!(
        has(
            &found,
            "routes.site.middlewares[1]",
            "answers every request"
        ),
        "{found:?}"
    );
}

#[test]
fn static_settings_are_checked() {
    let found = errors(site(json!({
        "index": ["a/b.html", ".."],
        "fallback": "index.html",
        "fallback_except": ["api"],
        "max_ranges": 17,
        "cache_control": { "default": "", "assets/": "public", "/x/": "bad\u{1}" },
        "types": { ".ts": "text/typescript", "md": "markdown" }
    })));
    for (path, fragment) in [
        ("middlewares.files.index[0]", "must be a file name"),
        ("middlewares.files.index[1]", "must be a file name"),
        ("middlewares.files.fallback", "must be the path of a file"),
        (
            "middlewares.files.fallback_except[0]",
            "must start with `/`",
        ),
        ("middlewares.files.max_ranges", "between 1 and 16"),
        (
            "middlewares.files.cache_control.default",
            "valid `Cache-Control`",
        ),
        (
            "middlewares.files.cache_control[\"assets/\"]",
            "path prefix starting with `/`",
        ),
        (
            "middlewares.files.cache_control[\"/x/\"]",
            "valid `Cache-Control`",
        ),
        ("middlewares.files.types[\".ts\"]", "without the dot"),
        ("middlewares.files.types.md", "not a media type"),
    ] {
        assert!(has(&found, path, fragment), "{path}: {found:?}");
    }
    assert!(has(
        &errors(site(json!({ "max_ranges": 0 }))),
        "middlewares.files.max_ranges",
        "between 1 and 16"
    ));
    assert!(has(
        &errors(site(json!({ "fallback": "/../etc/passwd" }))),
        "middlewares.files.fallback",
        "must be the path of a file"
    ));
}

#[test]
fn directory_listing_with_risky_options_warns() {
    assert_eq!(
        warnings(site(json!({ "listing": true }))),
        Vec::new(),
        "safe defaults list without a warning"
    );
    assert_eq!(
        warnings(site(json!({ "listing": true, "symlinks": "within_root" }))),
        Vec::new()
    );
    // The options alone are warned about elsewhere; the listing adds its own warning.
    let found = warnings(site(json!({ "listing": true, "hidden": "allow" })));
    assert!(
        has(&found, "middlewares.files.listing", "starting with `.`"),
        "{found:?}"
    );
    let found = warnings(site(json!({ "listing": true, "symlinks": "all" })));
    assert!(
        has(&found, "middlewares.files.listing", "lead out of `root`"),
        "{found:?}"
    );
    let found = warnings(site(json!({
        "listing": true, "hidden": "allow", "symlinks": "all"
    })));
    assert_eq!(
        found
            .iter()
            .filter(|(p, _)| p == "middlewares.files.listing")
            .count(),
        2,
        "{found:?}"
    );
    assert!(
        errors(site(
            json!({ "listing": true, "hidden": "allow", "symlinks": "all" })
        ))
        .is_empty(),
        "warnings, not errors"
    );
    assert!(
        !warnings(site(json!({ "hidden": "allow" })))
            .iter()
            .any(|(p, _)| p.ends_with(".listing")),
        "no listing, no listing warning"
    );
}

#[test]
fn risky_static_options_are_warnings() {
    let found = warnings(site(json!({
        "symlinks": "all",
        "hidden": "allow",
        "fallback_except": ["/api/"]
    })));
    assert!(
        has(&found, "middlewares.files.symlinks", "also out of `root`"),
        "{found:?}"
    );
    assert!(
        has(&found, "middlewares.files.hidden", "`.env`"),
        "{found:?}"
    );
    assert!(
        has(
            &found,
            "middlewares.files.fallback_except",
            "without `fallback`"
        ),
        "{found:?}"
    );
    assert_eq!(
        errors(site(json!({ "symlinks": "within_root", "max_ranges": 16 }))),
        Vec::new()
    );
}

#[test]
fn docker_static_roots_are_absolute() {
    let found = errors(with(
        app(),
        json!({ "providers": { "docker": { "static_roots": ["/srv/sites", "sites"] } } }),
    ));
    assert_eq!(
        found,
        vec![(
            "providers.docker.static_roots[1]".to_owned(),
            "`sites` must be an absolute path".to_owned()
        )]
    );
}

fn kubernetes(settings: Value) -> Value {
    let mut config = with(app(), json!({ "acme": false }));
    config["providers"]["kubernetes"] = settings;
    config
}

#[test]
fn kubernetes_defaults_are_valid() {
    // The pod selector has no default: the controller never reads its own pod.
    let selector =
        json!({ "gateway": { "pod_selector": { "app.kubernetes.io/name": "reversedock" } } });
    assert_eq!(validate(kubernetes(selector)), Vec::new());
    assert_eq!(
        validate(kubernetes(json!({ "gateway": { "enabled": false } }))),
        Vec::new()
    );
    let missing = errors(kubernetes(json!({})));
    assert!(has(
        &missing,
        "providers.kubernetes.gateway.pod_selector",
        "labels of the ReverseDock pods"
    ));
    let full = json!({
        "kubeconfig": "/etc/rdock/kubeconfig",
        "namespaces": ["apps", "infra"],
        "controller_name": "example.com/gateway",
        "gateway": {
            "service_type": "cluster_ip",
            "service_namespace": "rdock-system",
            "pod_selector": { "app.kubernetes.io/name": "reversedock" },
            "port_range": "30000-30010",
            "allow_external_name": true
        },
        "ingress": { "enabled": true, "class": "public", "publish_service": "rdock-system/reversedock" },
        "leader_election": { "enabled": false, "lease": "rdock" }
    });
    assert_eq!(validate(kubernetes(full)), Vec::new());
}

#[test]
fn a_node_port_gateway_service_is_a_warning() {
    // The Gateway address is the cluster IP, which is not reachable from outside the cluster.
    let found = validate(kubernetes(json!({
        "gateway": {
            "service_type": "node_port",
            "pod_selector": { "app.kubernetes.io/name": "reversedock" }
        }
    })));
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(!found[0].is_error());
    assert_eq!(found[0].path, "providers.kubernetes.gateway.service_type");
    assert!(found[0].message.contains("cluster IP"), "{found:?}");
    // Not while the Gateway API is off.
    let off = validate(kubernetes(json!({
        "gateway": { "enabled": false, "service_type": "node_port" }
    })));
    assert_eq!(off, Vec::new());
}

#[test]
fn kubernetes_settings_are_checked() {
    let found = errors(kubernetes(json!({
        "namespaces": ["Apps"],
        "controller_name": "gateway-controller",
        "gateway": { "port_range": "20000", "service_namespace": "-x" },
        "ingress": { "class": "Public", "publish_service": "reversedock" },
        "leader_election": { "lease": "my_lease" }
    })));
    for (path, fragment) in [
        ("providers.kubernetes.namespaces[0]", "namespace name"),
        (
            "providers.kubernetes.controller_name",
            "not a controller name",
        ),
        (
            "providers.kubernetes.gateway.port_range",
            "not a port range",
        ),
        (
            "providers.kubernetes.gateway.service_namespace",
            "namespace name",
        ),
        ("providers.kubernetes.ingress.class", "class name"),
        (
            "providers.kubernetes.ingress.publish_service",
            "`namespace/name`",
        ),
        ("providers.kubernetes.leader_election.lease", "Lease name"),
    ] {
        assert!(has(&found, path, fragment), "{path}: {found:?}");
    }
    let low = errors(kubernetes(json!({ "gateway": { "port_range": "80-90" } })));
    assert!(has(
        &low,
        "providers.kubernetes.gateway.port_range",
        "1024–65535"
    ));
    let reversed = errors(kubernetes(
        json!({ "gateway": { "port_range": "30000-20000" } }),
    ));
    assert!(has(
        &reversed,
        "providers.kubernetes.gateway.port_range",
        "starts after it ends"
    ));
    let too_high = errors(kubernetes(
        json!({ "gateway": { "port_range": "20000-70000" } }),
    ));
    assert!(has(
        &too_high,
        "providers.kubernetes.gateway.port_range",
        "not a port range"
    ));
    assert_eq!(
        errors(kubernetes(
            json!({ "gateway": { "port_range": "65535-65535", "pod_selector": { "app": "rdock" } } })
        )),
        Vec::new()
    );
}

#[test]
fn kubernetes_refuses_acme_unless_allowed() {
    // `acme` is on unless set to `false`.
    let implicit = with(app(), json!({ "providers": { "kubernetes": {} } }));
    let found = validate(implicit);
    let error = found
        .iter()
        .find(|d| d.path == "acme" && d.is_error())
        .unwrap();
    assert!(error.message.contains("providers.kubernetes"));
    assert!(error.hint.as_deref().unwrap().contains("cert-manager"));
    let allowed = with(
        app(),
        json!({ "providers": { "kubernetes": { "allow_acme": true, "gateway": { "pod_selector": { "app": "rdock" } } } } }),
    );
    assert_eq!(errors(allowed.clone()), Vec::new());
    assert!(has(
        &warnings(allowed),
        "providers.kubernetes",
        "replicas share no certificate storage"
    ));
    assert!(!has(
        &warnings(kubernetes(json!({}))),
        "providers.kubernetes",
        "certificate storage"
    ));
}

fn redirect(settings: Value) -> Vec<(String, String)> {
    let mut middleware = json!({ "type": "redirect" });
    merge(&mut middleware, settings);
    let found = validate(json!({ "middlewares": { "r": middleware } }));
    found.into_iter().map(|d| (d.path, d.message)).collect()
}

#[test]
fn redirects_combine_their_parts() {
    for ok in [
        json!({ "scheme": "https" }),
        json!({ "scheme": "https", "port": 8443, "permanent": true }),
        json!({ "hostname": "example.org", "status": 302 }),
        json!({ "port": 8080 }),
        json!({ "path": "/new", "status": 303 }),
        json!({ "prefix": { "from": "/a", "to": "/b" }, "scheme": "https", "status": 308 }),
        json!({ "prefix": { "from": "/a", "to": "" } }),
        json!({ "regex": "^http://(.*)$", "replacement": "https://$1", "status": 307 }),
    ] {
        assert_eq!(redirect(ok.clone()), Vec::new(), "{ok}");
    }
    let path = "middlewares.r";
    assert!(has(&redirect(json!({})), path, "set `scheme`, `hostname`"));
    assert!(has(
        &redirect(json!({ "hostname": "a.test", "regex": ".*", "replacement": "x" })),
        &format!("{path}.regex"),
        "cannot be combined"
    ));
    assert!(has(
        &redirect(json!({ "path": "/a", "prefix": { "from": "/b", "to": "/c" } })),
        path,
        "not both"
    ));
    assert!(has(
        &redirect(json!({ "path": "a" })),
        &format!("{path}.path"),
        "start with `/`"
    ));
    assert!(has(
        &redirect(json!({ "prefix": { "from": "a", "to": "b" } })),
        &format!("{path}.prefix.from"),
        "start with `/`"
    ));
    assert!(has(
        &redirect(json!({ "prefix": { "from": "/a", "to": "b" } })),
        &format!("{path}.prefix.to"),
        "start with `/`"
    ));
    assert!(has(
        &redirect(json!({ "hostname": "a.test", "status": 304 })),
        &format!("{path}.status"),
        "not a redirect status"
    ));
    assert!(has(
        &redirect(json!({ "hostname": "*.example.com" })),
        &format!("{path}.hostname"),
        "wildcard"
    ));
    assert!(has(
        &redirect(json!({ "hostname": "a.test", "status": 301, "permanent": true })),
        &format!("{path}.permanent"),
        "ignored"
    ));
}

#[test]
fn responding_services_take_no_backends() {
    let split = json!({
        "routes": { "app": { "match": "Host(`app.example.com`)", "service": "app" } },
        "services": {
            "app": { "split": [{ "service": "real", "weight": 9 }, { "service": "broken", "weight": 1 }] },
            "real": { "backends": [{ "address": "app:3000" }] },
            "broken": { "respond": { "status": 500 } }
        }
    });
    assert_eq!(validate(split), Vec::new());
    let both = errors(json!({
        "services": {
            "s": { "respond": { "status": 500 }, "backends": [{ "address": "app:3000" }] },
            "t": { "respond": { "status": 99 } }
        }
    }));
    assert!(has(&both, "services.s.respond", "no `backends` or `split`"));
    assert!(has(&both, "services.t.respond.status", "200 to 599"));
}

#[test]
fn listener_certificates_must_exist() {
    let config = json!({
        "acme": false,
        "listeners": {
            "web": { "address": ":80" },
            "a": { "address": ":8443", "tls": { "certificates": ["one"] } },
            "b": { "address": ":9443", "tls": { "certificates": ["two"] } }
        },
        "defaults": { "listeners": ["web"], "tls": "off" },
        "certificates": { "one": { "cert_file": "/a.crt", "key_file": "/a.key" } }
    });
    let found = errors(config);
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(has(
        &found,
        "listeners.b.tls.certificates[0]",
        "certificate `two` does not exist"
    ));
}

#[test]
fn hold_body_needs_a_bounded_positive_size_and_timeout() {
    let hold = |settings: Value| {
        let mut m = json!({ "type": "hold_body" });
        merge(&mut m, settings);
        errors(with(app(), json!({ "middlewares": { "hold": m } })))
    };
    assert_eq!(hold(json!({})), [], "defaults: 1MiB within 30s");
    assert_eq!(hold(json!({ "max": "64MiB", "timeout": "2m" })), []);
    assert!(has(
        &hold(json!({ "max": 0 })),
        "middlewares.hold.max",
        "greater than zero"
    ));
    assert!(has(
        &hold(json!({ "max": "65MiB" })),
        "middlewares.hold.max",
        "at most 64MiB"
    ));
    assert!(has(
        &hold(json!({ "timeout": "0s" })),
        "middlewares.hold.timeout",
        "greater than zero"
    ));
}

// -- HTTP cache (F-WEB-03) --------------------------------------------------------------------

#[allow(
    clippy::needless_pass_by_value,
    reason = "built inline by every caller"
)]
fn cached(middlewares: Value, chain: Value) -> Value {
    with(
        app(),
        json!({
            "caches": { "mem": { "type": "memory" } },
            "middlewares": middlewares,
            "routes": { "app": { "middlewares": chain } }
        }),
    )
}

#[test]
fn cache_targeted_fields_are_header_names_other_than_cache_control() {
    let found = errors(cached(
        json!({ "c": { "type": "cache", "store": "mem", "targeted": ["Cache-Control", "bad name", "CDN-Cache-Control", "cdn-cache-control"] } }),
        json!(["c"]),
    ));
    assert!(
        has(&found, "middlewares.c.targeted[0]", "not a targeted field"),
        "{found:?}"
    );
    assert!(
        has(
            &found,
            "middlewares.c.targeted[1]",
            "not a valid header name"
        ),
        "{found:?}"
    );
    assert!(
        has(&found, "middlewares.c.targeted[3]", "listed twice"),
        "{found:?}"
    );
    let ok = cached(
        json!({ "c": { "type": "cache", "store": "mem", "targeted": [] } }),
        json!(["c"]),
    );
    assert_eq!(errors(ok), Vec::<(String, String)>::new());
}

#[test]
fn cache_middlewares_need_a_defined_store_and_sane_settings() {
    let found = errors(cached(
        json!({ "c": { "type": "cache", "store": "nope", "statuses": [206, 200, 99], "default_ttl": { "404": "1m", "x": "1m" }, "lock": { "timeout": "0s" }, "key": { "headers": ["bad header"], "query": { "only": [] } } } }),
        json!(["c"]),
    ));
    assert!(
        has(
            &found,
            "middlewares.c.store",
            "cache store `nope` does not exist"
        ),
        "{found:?}"
    );
    assert!(
        has(&found, "middlewares.c.statuses[0]", "never stored as such"),
        "{found:?}"
    );
    assert!(
        has(
            &found,
            "middlewares.c.statuses[2]",
            "not a final status code"
        ),
        "{found:?}"
    );
    assert!(
        has(
            &found,
            "middlewares.c.default_ttl.404",
            "not one the route stores"
        ),
        "{found:?}"
    );
    assert!(
        has(&found, "middlewares.c.default_ttl.x", "not a status code"),
        "{found:?}"
    );
    assert!(
        has(&found, "middlewares.c.lock.timeout", "above zero"),
        "{found:?}"
    );
    assert!(
        has(
            &found,
            "middlewares.c.key.headers[0]",
            "not a valid header name"
        ),
        "{found:?}"
    );
    assert!(
        has(&found, "middlewares.c.key.query", "at least one parameter"),
        "{found:?}"
    );
    let ok = cached(
        json!({ "c": { "type": "cache", "store": "mem" } }),
        json!(["c"]),
    );
    assert_eq!(errors(ok), Vec::new());
}

#[test]
fn disk_stores_need_absolute_separate_directories() {
    let found = errors(with(
        app(),
        json!({ "caches": {
            "a": { "type": "disk", "path": "relative/dir" },
            "b": { "type": "disk", "path": "/var/cache/rdock" },
            "c": { "type": "disk", "path": "/var/cache/rdock/inner" },
            "d": { "type": "disk", "path": "/" },
            "e": { "type": "disk", "path": "/var/../etc", "max_objects": 0 },
            "f": { "type": "memory", "max_size": 0 }
        } }),
    ));
    assert!(has(&found, "caches.a.path", "absolute path"), "{found:?}");
    assert!(
        has(&found, "caches.c.path", "overlaps store `b`"),
        "{found:?}"
    );
    assert!(has(&found, "caches.d.path", "root directory"), "{found:?}");
    assert!(has(&found, "caches.e.path", "`..`"), "{found:?}");
    assert!(
        has(&found, "caches.e.max_objects", "greater than zero"),
        "{found:?}"
    );
    assert!(
        has(&found, "caches.f.max_size", "greater than zero"),
        "{found:?}"
    );
}

#[test]
fn an_authenticated_route_caches_only_with_an_explicit_statement() {
    const MESSAGE: &str = "`c` caches the responses of a route that authenticates with `auth`: one user's response could be served to another";
    let auth = json!({ "type": "basic_auth", "users": ["alice:$2y$05$abcdefghijklmnopqrstuuJ8iS0V0zP5Y9n7wS8pB5yFq6YxwH8ZC"] });
    let cache = |extra: Value| {
        let mut c = json!({ "type": "cache", "store": "mem" });
        merge(&mut c, extra);
        c
    };
    // Position does not matter: the cache is looked up after every request phase.
    for chain in [json!(["auth", "c"]), json!(["c", "auth"])] {
        let found = errors(cached(
            json!({ "auth": auth.clone(), "c": cache(json!({})) }),
            chain.clone(),
        ));
        let index = usize::from(chain[0] != "c");
        assert!(
            has(&found, &format!("routes.app.middlewares[{index}]"), MESSAGE),
            "{found:?}"
        );
    }
    let diagnostics = validate(cached(
        json!({ "auth": auth.clone(), "c": cache(json!({})) }),
        json!(["auth", "c"]),
    ));
    let hint = diagnostics
        .iter()
        .find(|d| d.message == MESSAGE)
        .and_then(|d| d.hint.clone())
        .unwrap();
    assert!(
        hint.contains("`shared_across_users: true`") && hint.contains("keyed on the user name"),
        "{hint}"
    );
    for extra in [
        json!({ "shared_across_users": true }),
        json!({ "key": { "consumer": true } }),
    ] {
        let found = errors(cached(
            json!({ "auth": auth.clone(), "c": cache(extra.clone()) }),
            json!(["auth", "c"]),
        ));
        assert_eq!(found, Vec::new(), "{extra}");
    }
    // forward_auth: rdock does not learn the identity; only a header it copies can key it.
    let fa = json!({ "type": "forward_auth", "address": "http://auth:9091/verify", "copy_headers": ["X-User"] });
    let found = errors(cached(
        json!({ "auth": fa.clone(), "c": cache(json!({ "key": { "consumer": true } })) }),
        json!(["auth", "c"]),
    ));
    assert!(
        has(&found, "routes.app.middlewares[1]", MESSAGE),
        "{found:?}"
    );
    let found = errors(cached(
        json!({ "auth": fa, "c": cache(json!({ "key": { "headers": ["x-user"] } })) }),
        json!(["auth", "c"]),
    ));
    assert_eq!(found, Vec::new());
    // jwt and client_cert authenticate too.
    let jwt = json!({ "type": "jwt", "jwks_url": "https://idp.example.com/jwks", "issuer": "https://idp.example.com", "audiences": ["app"] });
    let found = errors(cached(
        json!({ "auth": jwt, "c": cache(json!({})) }),
        json!(["auth", "c"]),
    ));
    assert!(
        has(&found, "routes.app.middlewares[1]", MESSAGE),
        "{found:?}"
    );
    // A second cache middleware is refused.
    let found = errors(cached(
        json!({ "c": cache(json!({})), "c2": cache(json!({})) }),
        json!(["c", "c2"]),
    ));
    assert!(
        has(
            &found,
            "routes.app.middlewares[1]",
            "second `cache` middleware"
        ),
        "{found:?}"
    );
}

#[test]
fn a_fully_mirrored_cached_route_is_warned_about() {
    let mut config = cached(
        json!({ "c": { "type": "cache", "store": "mem" } }),
        json!(["c"]),
    );
    merge(
        &mut config,
        json!({ "routes": { "app": { "mirror": { "service": "copy", "percent": 100 } } }, "services": { "copy": { "backends": [{ "address": "copy:1" }] } } }),
    );
    let found = warnings(config);
    assert!(
        has(&found, "routes.app.mirror.percent", "never used"),
        "{found:?}"
    );
}

#[test]
fn agents_and_plugins_are_checked() {
    let config = json!({ "middlewares": {
        "waf": {
            "type": "agent", "address": "https://waf.example.com",
            "max_body": "65MiB", "timeout": "0s",
            "request_headers": ["*", "bad name"],
            "response_headers": ["X-User", "Host", "X-Forwarded-For", "Content-Length"],
            "breaker": { "failures": 3, "window": "0s" },
            "tls": { "verify": false }
        },
        "plain": { "type": "agent", "address": "http://policy.internal:9000", "tls": {} },
        "local": { "type": "agent", "address": "http://127.0.0.1:9000", "max_body": 0, "response_headers": ["X-User"] },
        "plug": { "type": "plugin", "name": "Not Valid" },
        "ok": { "type": "plugin", "name": "header_rewrite", "config": { "anything": [1, 2] } }
    }});
    let errors = errors(config.clone());
    assert!(
        has(&errors, "middlewares.waf.max_body", "at most 64MiB"),
        "{errors:?}"
    );
    assert!(has(&errors, "middlewares.waf.timeout", ""), "{errors:?}");
    assert!(has(
        &errors,
        "middlewares.waf.request_headers[1]",
        "not a valid header name"
    ));
    assert!(
        !errors
            .iter()
            .any(|(p, _)| p == "middlewares.waf.request_headers[0]"),
        "`*` is allowed"
    );
    assert!(has(
        &errors,
        "middlewares.waf.response_headers[1]",
        "managed by rdock"
    ));
    assert!(has(
        &errors,
        "middlewares.waf.response_headers[2]",
        "managed by rdock"
    ));
    assert!(has(
        &errors,
        "middlewares.waf.response_headers[3]",
        "managed by rdock"
    ));
    assert!(
        !errors
            .iter()
            .any(|(p, _)| p == "middlewares.waf.response_headers[0]")
    );
    assert!(
        has(&errors, "middlewares.waf.breaker.window", ""),
        "{errors:?}"
    );
    assert!(has(
        &errors,
        "middlewares.plug.name",
        "is not a plugin name"
    ));
    assert!(
        !errors.iter().any(|(p, _)| p.starts_with("middlewares.ok")),
        "config is free-form"
    );
    let warnings = warnings(config);
    assert!(has(&warnings, "middlewares.waf.tls.verify", "not verified"));
    assert!(has(
        &warnings,
        "middlewares.waf.response_headers",
        "only to requests without a body"
    ));
    assert!(has(
        &warnings,
        "middlewares.plain.address",
        "plain `http://`"
    ));
    assert!(has(
        &warnings,
        "middlewares.plain.tls",
        "only to an `https://` address"
    ));
    assert!(
        !warnings
            .iter()
            .any(|(p, _)| p.starts_with("middlewares.local")),
        "{warnings:?}"
    );
}

#[test]
fn validate_middlewares_are_checked() {
    let check = |mw: Value| errors(with(app(), json!({ "middlewares": { "v": mw } })));
    let found = check(json!({ "type": "validate" }));
    assert!(
        has(&found, "middlewares.v", "nothing to check"),
        "{found:?}"
    );
    let found = check(json!({ "type": "validate", "openapi": "/api.yaml", "body": {} }));
    assert!(
        has(&found, "middlewares.v", "cannot be combined"),
        "{found:?}"
    );
    let found = check(json!({
        "type": "validate",
        "body": { "properties": { "a": { "$ref": "https://example.com/a.json" } } }
    }));
    assert!(
        has(
            &found,
            "middlewares.v.body.properties.a.$ref",
            "outside the schema"
        ),
        "{found:?}"
    );
    let found = check(json!({ "type": "validate", "query": "string" }));
    assert!(
        has(&found, "middlewares.v.query", "object or a boolean"),
        "{found:?}"
    );
    let found =
        check(json!({ "type": "validate", "body": {}, "max_body": "65MiB", "max_errors": 0 }));
    assert!(
        has(&found, "middlewares.v.max_body", "at most"),
        "{found:?}"
    );
    assert!(
        has(&found, "middlewares.v.max_errors", "use 1 to 100"),
        "{found:?}"
    );
    assert_eq!(
        check(json!({ "type": "validate", "body": { "$ref": "#/$defs/a", "$defs": { "a": {} } } })),
        Vec::<(String, String)>::new()
    );
}

#[test]
fn transform_middlewares_are_checked() {
    let check = |mw: Value| errors(with(app(), json!({ "middlewares": { "t": mw } })));
    let found = check(json!({
        "type": "transform",
        "request": { "body": { "patch": [{ "op": "add", "path": "nope", "value": 1 }] } },
        "response": { "body": { "patch": [{ "op": "move", "from": "/a", "path": "/a/b" }] } }
    }));
    assert!(
        has(
            &found,
            "middlewares.t.request.body.patch[0]",
            "must be empty or start with `/`"
        ),
        "{found:?}"
    );
    assert!(
        has(
            &found,
            "middlewares.t.response.body.patch[0]",
            "moved into itself"
        ),
        "{found:?}"
    );
    let found = warnings(with(
        app(),
        json!({ "middlewares": { "t": { "type": "transform" } } }),
    ));
    assert!(
        has(&found, "middlewares.t", "nothing to change"),
        "{found:?}"
    );
}

#[test]
fn vault_settings_are_checked() {
    let check = |vault: Value| errors(with(app(), json!({ "secrets": { "vault": vault } })));
    let found = check(
        json!({ "address": "http://vault.internal:8200", "auth": { "token": "${file:/t}" } }),
    );
    assert!(
        has(&found, "secrets.vault.address", "`https://`"),
        "{found:?}"
    );
    assert_eq!(
        check(json!({ "address": "http://127.0.0.1:8200", "auth": { "token": "${file:/t}" } })),
        Vec::<(String, String)>::new()
    );
    let insecure = json!({ "address": "http://vault.internal:8200", "insecure_http": true, "auth": { "token": "${file:/t}" } });
    assert_eq!(check(insecure.clone()), Vec::<(String, String)>::new());
    let found = warnings(with(app(), json!({ "secrets": { "vault": insecure } })));
    assert!(
        has(&found, "secrets.vault.insecure_http", "unencrypted"),
        "{found:?}"
    );
    let found = check(
        json!({ "address": "https://vault.internal:8200/v1", "auth": { "token": "s.literal" } }),
    );
    assert!(has(&found, "secrets.vault.address", "root"), "{found:?}");
    assert!(
        has(
            &found,
            "secrets.vault.auth.token",
            "written in the configuration"
        ),
        "{found:?}"
    );
    let found = check(json!({
        "address": "https://vault.internal:8200",
        "auth": { "kubernetes": { "role": "", "token_file": "relative" } },
        "refresh": "500ms"
    }));
    assert!(
        has(&found, "secrets.vault.auth.kubernetes.role", "empty"),
        "{found:?}"
    );
    assert!(
        has(
            &found,
            "secrets.vault.auth.kubernetes.token_file",
            "absolute"
        ),
        "{found:?}"
    );
    assert!(
        has(&found, "secrets.vault.refresh", "at least 1s"),
        "{found:?}"
    );
    assert!(
        has(&found, "secrets.vault.timeout", "shorter than `refresh`"),
        "{found:?}"
    );
}

#[test]
fn wasm_plugins_are_checked() {
    let pin = "a".repeat(64);
    let config = json!({ "experimental": ["wasm"], "middlewares": {
        "bad": {
            "type": "wasm", "path": "", "sha256": "abc",
            "fuel": 0, "timeout": "11s", "memory": "1KiB",
            "capabilities": ["log", "log"]
        },
        "unsigned": { "type": "wasm", "path": "/p.wasm", "sha256": pin, "allow_unsigned": true },
        "ok": {
            "type": "wasm", "path": "/p.wasm", "sha256": pin,
            "trusted_keys": ["RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3"],
            "capabilities": ["clock", "random"], "on_error": "allow", "config": { "x": 1 }
        }
    }});
    let errors = errors(config.clone());
    for (path, fragment) in [
        ("middlewares.bad.path", "required"),
        ("middlewares.bad.sha256", "64 hex digits"),
        ("middlewares.bad.trusted_keys", "signed by a trusted key"),
        ("middlewares.bad.fuel", ""),
        ("middlewares.bad.timeout", "at most 10s"),
        ("middlewares.bad.memory", "between 64KiB"),
    ] {
        assert!(has(&errors, path, fragment), "{path}: {errors:?}");
    }
    assert!(
        !errors
            .iter()
            .any(|(p, _)| p.starts_with("middlewares.ok") || p.starts_with("middlewares.unsigned")),
        "{errors:?}"
    );
    let warnings = warnings(config);
    assert!(has(
        &warnings,
        "middlewares.unsigned.allow_unsigned",
        "unsigned"
    ));
    assert!(has(
        &warnings,
        "middlewares.bad.capabilities[1]",
        "listed twice"
    ));
}

/// M1 of the v0.8 review: a provider object cannot make rdock read a file, a variable or a
/// Vault secret through a secret field; the API may name files and variables (documented for
/// the configuration API), not Vault; the file may name anything.
#[test]
fn provider_objects_hold_no_references_in_secret_fields() {
    let jwt = |secret: &str| {
        json!({ "type": "jwt", "issuer": "any", "audiences": ["any"], "algorithms": ["HS256"],
            "hmac_secret": secret })
    };
    let config: Config = serde_json::from_value(json!({
        "middlewares": {
            "a@docker": jwt("${file:/etc/shadow}"),
            "b@kubernetes": jwt("${env:HOME}"),
            "c@api": jwt("${vault:kv/prod#db}"),
            "d@api": jwt("${file:/run/secrets/jwt}"),
            "e": jwt("${vault:kv/prod#db}"),
            "f@docker": jwt("a-literal-secret-of-at-least-32-bytes!!"),
        },
        "services": {
            "s@swarm": { "backends": [{ "address": "10.0.0.1:80" }],
                "sticky": { "cookie": { "name": "s", "secret": "${file:/etc/shadow}" } } }
        }
    }))
    .unwrap();
    let found: Vec<(String, String)> = config
        .validate_merged()
        .into_iter()
        .filter(Diagnostic::is_error)
        .map(|d| (d.path, d.message))
        .collect();
    let refused = |path: &str| has(&found, path, "reference") || has(&found, path, "read only");
    assert!(
        refused("middlewares[\"a@docker\"].hmac_secret"),
        "{found:?}"
    );
    assert!(
        refused("middlewares[\"b@kubernetes\"].hmac_secret"),
        "{found:?}"
    );
    assert!(
        has(
            &found,
            "middlewares[\"c@api\"].hmac_secret",
            "read only for the configuration file"
        ),
        "{found:?}"
    );
    assert!(
        refused("services[\"s@swarm\"].sticky.cookie.secret"),
        "{found:?}"
    );
    for allowed in ["d@api", "e", "f@docker"] {
        assert!(
            !found
                .iter()
                .any(|(p, _)| p.contains(&format!("{allowed}\"]"))
                    || p == &format!("middlewares.{allowed}.hmac_secret")),
            "{allowed}: {found:?}"
        );
    }
}

#[test]
fn ticket_rotation_and_cache_size_are_bounded() {
    let config = with(
        app(),
        json!({ "listeners": {
            "a": { "address": ":443", "tls": { "tickets": { "rotate": "100h" }, "session_cache": { "size": 2_000_000 } } },
            "b": { "address": ":8443", "tls": { "tickets": { "enabled": false, "key_file": "/k" } } },
            "c": { "address": ":9443", "tls": { "tickets": { "rotate": "1h", "key_file": "/k" }, "session_cache": { "size": 0 } } }
        }}),
    );
    let found = errors(config.clone());
    assert!(has(
        &found,
        "listeners.a.tls.tickets.rotate",
        "between 1s and 84h"
    ));
    assert!(has(&found, "listeners.a.tls.session_cache.size", "at most"));
    assert!(!found.iter().any(|(p, _)| p.starts_with("listeners.c")));
    assert!(has(
        &warnings(config),
        "listeners.b.tls.tickets.key_file",
        "not read"
    ));
}

#[test]
fn http2_settings_follow_rfc_9113_and_floods_need_unlimited() {
    let config = with(
        app(),
        json!({ "listeners": {
            "a": { "address": ":443", "tls": {}, "http2": {
                "max_concurrent_streams": 1_000_000,
                "initial_stream_window": 2_147_483_648_u64,
                "max_frame_size": 1024,
                "max_local_error_reset_streams": 0
            } },
            "b": { "address": ":80", "http2": { "max_pending_accept_reset_streams": "unlimited", "max_frame_size": 16_777_215 } },
            "c": { "address": ":5432", "protocol": "tcp", "http2": {} }
        }}),
    );
    let found = errors(config.clone());
    assert!(has(
        &found,
        "listeners.a.http2.max_concurrent_streams",
        "write `unlimited`"
    ));
    assert!(has(
        &found,
        "listeners.a.http2.initial_stream_window",
        "between 1 and 2147483647"
    ));
    assert!(has(
        &found,
        "listeners.a.http2.max_frame_size",
        "between 16384 and 16777215"
    ));
    assert!(has(
        &found,
        "listeners.a.http2.max_local_error_reset_streams",
        "greater than zero"
    ));
    assert!(!found.iter().any(|(p, _)| p.starts_with("listeners.b")));
    assert!(has(&found, "listeners.c.http2", "`http` and `https`"));
    assert!(has(
        &warnings(config),
        "listeners.b.http2.max_pending_accept_reset_streams",
        "floods"
    ));
}

#[test]
fn upgrade_settings_are_checked() {
    let config = with(
        app(),
        json!({ "upgrade": {
            "binary": "rdock",
            "drain": "unlimited",
            "start_timeout": "1h",
            "trusted_keys": ["RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3", "nope"]
        }}),
    );
    let found = errors(config.clone());
    assert!(has(&found, "upgrade.binary", "absolute"));
    assert!(has(&found, "upgrade.start_timeout", "between 1s and 10m"));
    assert!(has(&found, "upgrade.trusted_keys[1]", "minisign"));
    assert!(!found.iter().any(|(p, _)| p == "upgrade.trusted_keys[0]"));
    assert!(has(&warnings(config), "upgrade.drain", "old binary"));
    let ok: Config = serde_json::from_value(json!({ "upgrade": { "drain": "5s" } })).unwrap();
    assert_eq!(
        ok.upgrade.unwrap().drain,
        crate::settings::DrainLimit::Within(crate::values::Duration::from_secs(5))
    );
}

// ---------------------------------------------------------------------------------------------
// Balancing (H-LB-01…03, H-HA-05, ADR-0031)

fn service(patch: Value) -> Value {
    let mut base = app();
    merge(&mut base, json!({ "services": { "app": Value::Null } }));
    if let Some(services) = base.get_mut("services") {
        services["app"] = patch;
    }
    base
}

#[test]
fn priorities_are_bounded_and_exclusive_with_backup() {
    let found = errors(service(json!({ "backends": [
        { "address": "a:1" },
        { "address": "b:1", "priority": 8 },
        { "address": "c:1", "priority": 2, "backup": true }
    ]})));
    assert!(
        has(
            &found,
            "services.app.backends[1].priority",
            "from 0 (first) to 7"
        ),
        "{found:?}"
    );
    assert!(
        has(&found, "services.app.backends[2].backup", "not both"),
        "{found:?}"
    );
    let found = errors(service(json!({ "backends": [
        { "address": "a:1", "priority": 1 }, { "address": "b:1", "backup": true }
    ]})));
    assert!(
        has(
            &found,
            "services.app.backends",
            "no backend is in priority 0"
        ),
        "{found:?}"
    );
    let ok = service(json!({ "backends": [
        { "address": "a:1", "priority": 0, "zone": "eu-1a" },
        { "address": "b:1", "priority": 7, "for_zones": ["eu-1b"] }
    ], "failover": "spill", "overprovisioning": 1.5 }));
    assert_eq!(errors(ok), Vec::new());
}

#[test]
fn spill_settings_and_zones_are_checked() {
    let found = errors(service(json!({
        "backends": [{ "address": "a:1", "zone": "" }, { "address": "b:1", "priority": 1 }],
        "failover": "spill", "overprovisioning": 0.5
    })));
    assert!(
        has(&found, "services.app.overprovisioning", "at least 1"),
        "{found:?}"
    );
    assert!(
        has(&found, "services.app.backends[0].zone", "non-empty"),
        "{found:?}"
    );
    let found = warnings(service(json!({
        "backends": [{ "address": "a:1" }], "overprovisioning": 1.4,
        "locality": { "mode": "prefer" }
    })));
    assert!(has(
        &found,
        "services.app.overprovisioning",
        "only used with `failover: spill`"
    ));
    assert!(has(
        &found,
        "services.app.locality",
        "no backend has a `zone`"
    ));
    let found = errors(with(
        app(),
        json!({ "locality": { "zone": "a b", "mode": "prefer" } }),
    ));
    assert!(has(&found, "locality.zone", "without spaces"), "{found:?}");
}

#[test]
fn peak_ewma_settings_belong_to_their_policy() {
    let found = warnings(service(json!({ "backends": [{ "address": "a:1" }],
        "load_balancer": { "decay": "5s", "measure": "last_byte" } })));
    assert!(has(
        &found,
        "services.app.load_balancer.decay",
        "only used by the peak_ewma"
    ));
    assert!(has(
        &found,
        "services.app.load_balancer.measure",
        "only used by the peak_ewma"
    ));
    let found = errors(service(json!({ "backends": [{ "address": "a:1" }],
        "load_balancer": { "policy": "peak_ewma", "decay": "0s" } })));
    assert!(has(
        &found,
        "services.app.load_balancer.decay",
        "must not be zero"
    ));
    let ok = service(json!({ "backends": [{ "address": "a:1" }],
        "load_balancer": { "policy": "peak_ewma", "decay": "10s", "measure": "first_byte" } }));
    assert_eq!(validate(ok), Vec::new());
}

#[test]
fn slow_start_has_two_forms_and_is_refused_with_hash_policies() {
    let short = service(json!({ "backends": [{ "address": "a:1" }],
        "health": { "slow_start": "30s" } }));
    assert_eq!(errors(short), Vec::new());
    let long = service(json!({ "backends": [{ "address": "a:1" }],
        "health": { "slow_start": { "window": "1m", "aggression": 2, "min_weight_percent": 5,
            "on": ["recovery", "join"] } } }));
    assert_eq!(errors(long), Vec::new());
    let found = errors(service(json!({ "backends": [{ "address": "a:1" }],
        "load_balancer": { "policy": "ip_hash" },
        "health": { "slow_start": { "window": "0s", "aggression": 0,
            "min_weight_percent": 101, "on": [] } } })));
    for (path, fragment) in [
        ("services.app.health.slow_start", "hash policies"),
        ("services.app.health.slow_start.window", "zero"),
        ("services.app.health.slow_start.aggression", "above 0"),
        (
            "services.app.health.slow_start.min_weight_percent",
            "at most 100",
        ),
        ("services.app.health.slow_start.on", "recovery"),
    ] {
        assert!(has(&found, path, fragment), "{path}: {found:?}");
    }
}

#[test]
fn outlier_detectors_need_three_hosts_and_say_when_they_are_off() {
    let found = errors(service(json!({ "backends": [{ "address": "a:1" }],
        "health": { "passive": { "outlier": {
            "interval": "0s",
            "success_rate": { "enabled": true, "minimum_hosts": 2, "request_volume": 0,
                "stdev_factor": 0 },
            "failure_percentage": { "enabled": true, "minimum_hosts": 1, "threshold": 101 }
        } } } })));
    for (path, fragment) in [
        ("services.app.health.passive.outlier.interval", "zero"),
        (
            "services.app.health.passive.outlier.success_rate.minimum_hosts",
            "at least 3",
        ),
        (
            "services.app.health.passive.outlier.success_rate.request_volume",
            "zero",
        ),
        (
            "services.app.health.passive.outlier.success_rate.stdev_factor",
            "above 0",
        ),
        (
            "services.app.health.passive.outlier.failure_percentage.minimum_hosts",
            "at least 3",
        ),
        (
            "services.app.health.passive.outlier.failure_percentage.threshold",
            "1 to 100",
        ),
    ] {
        assert!(has(&found, path, fragment), "{path}: {found:?}");
    }
    let found = warnings(service(json!({ "backends": [{ "address": "a:1" }],
        "health": { "passive": { "outlier": { "success_rate": {} } } } })));
    assert!(has(
        &found,
        "services.app.health.passive.outlier.success_rate",
        "the detector is off"
    ));
}

#[test]
fn per_try_timeout_needs_timeout_retries() {
    let found = errors(service(json!({ "backends": [{ "address": "a:1" }],
        "retries": { "per_try_timeout": "500ms" } })));
    assert!(has(
        &found,
        "services.app.retries.per_try_timeout",
        "does not list `timeout`"
    ));
    let found = warnings(service(json!({ "backends": [{ "address": "a:1" }],
        "timeouts": { "read": "1s" },
        "retries": { "per_try_timeout": "2s", "on": ["timeout"], "attempts": 0 } })));
    assert!(has(
        &found,
        "services.app.retries.per_try_timeout",
        "not shorter than"
    ));
    assert!(has(
        &found,
        "services.app.retries.per_try_timeout",
        "attempts: 0"
    ));
    let ok = service(json!({ "backends": [{ "address": "a:1" }],
        "retries": { "per_try_timeout": "500ms", "on": ["connect", "timeout"] } }));
    assert_eq!(validate(ok), Vec::new());
}

#[test]
fn fingerprint_rules_need_a_listener_that_computes_them() {
    let base = json!({
        "listeners": { "websecure": { "address": ":443", "tls": {} } },
        "routes": { "app": {
            "match": "Host(`a.test`) && ClientFingerprint(`t13d1516h2_8daaf6152771_e5627efa2ab1`)",
            "service": "app"
        } },
        "services": { "app": { "backends": [{ "address": "app:3000" }] } }
    });
    assert!(has(
        &errors(base.clone()),
        "routes.app.match",
        "computes fingerprints"
    ));
    let on = with(
        base.clone(),
        json!({ "listeners": { "websecure": { "tls": { "fingerprint": { "header": "X-JA4" } } } } }),
    );
    assert_eq!(errors(on), Vec::new());
    let bad = with(
        base,
        json!({ "listeners": { "websecure": { "tls": { "fingerprint": {
            "ja3_header": "X-JA3", "header": "bad header"
        } } } } }),
    );
    let found = errors(bad);
    assert!(has(
        &found,
        "listeners.websecure.tls.fingerprint.ja3_header",
        "ja3: true"
    ));
    assert!(has(
        &found,
        "listeners.websecure.tls.fingerprint.header",
        "not a valid header"
    ));
}

#[test]
fn geo_matchers_need_their_database() {
    let rule = |m: &str| {
        with(
            app(),
            json!({ "routes": { "app": { "match": format!("Host(`app.example.com`) && {m}") } } }),
        )
    };
    for m in [
        "ClientCountry(`DE`)",
        "ClientContinent(`EU`)",
        "ClientASN(`64496`)",
    ] {
        assert!(
            has(
                &errors(rule(m)),
                "routes.app.match",
                "needs a GeoIP database"
            ),
            "{m}"
        );
    }
    let with_asn = with(
        rule("ClientASN(`64496`)"),
        json!({ "geoip": { "asn_database": "/x/asn.mmdb" } }),
    );
    assert_eq!(errors(with_asn), Vec::new());
    let country_only_asn = with(
        rule("ClientCountry(`DE`)"),
        json!({ "geoip": { "asn_database": "/x/asn.mmdb" } }),
    );
    assert!(has(
        &errors(country_only_asn),
        "routes.app.match",
        "needs a GeoIP database"
    ));
    let tcp = json!({
        "tcp_routes": { "db": { "match": "HostSNI(`*`) && ClientCountry(`DE`)", "service": "db" } },
        "tcp_services": { "db": { "backends": [{ "address": "db:5432" }] } }
    });
    assert!(has(
        &errors(tcp),
        "tcp_routes.db.match",
        "needs a GeoIP database"
    ));
    assert!(has(
        &errors(with(
            app(),
            json!({ "geoip": { "database": "/x/c.mmdb", "max_age": "0s" } })
        )),
        "geoip.max_age",
        "more than zero"
    ));
}

#[test]
fn abuse_settings_are_checked() {
    let mw = |settings: Value| {
        let mut abuse = json!({ "type": "abuse" });
        merge(&mut abuse, settings);
        with(app(), json!({ "middlewares": { "guard": abuse } }))
    };
    assert_eq!(errors(mw(json!({}))), Vec::new());
    assert_eq!(
        errors(mw(
            json!({ "events": [401, "4xx", "auth_failure"], "key": "ja4", "action": "tarpit" })
        )),
        Vec::new()
    );
    let found = errors(mw(
        json!({ "events": [], "threshold": 0, "ban": "0s", "max_bans": 0 }),
    ));
    assert!(has(&found, "middlewares.guard.events", "at least one"));
    assert!(has(&found, "middlewares.guard.threshold", "at least 1"));
    assert!(has(&found, "middlewares.guard.ban", "at least 1s"));
    assert!(has(&found, "middlewares.guard.max_bans", "between"));
    let tarpit = errors(mw(
        json!({ "action": "tarpit", "tarpit": { "delay": "2m" } }),
    ));
    assert!(has(&tarpit, "middlewares.guard.tarpit.delay", "60s"));
    assert!(has(
        &warnings(mw(json!({ "key": "header:X-Session" }))),
        "middlewares.guard.key",
        "the client chooses"
    ));
    let config: Result<Config, _> = serde_json::from_value(mw(json!({ "events": [200] })));
    assert!(config.is_err(), "events are 4xx and 5xx statuses");
}

#[test]
fn spiffe_rules_are_checked() {
    let mw = |spiffe: Value| {
        with(
            app(),
            json!({ "middlewares": { "workloads": { "type": "client_cert", "spiffe": spiffe } } }),
        )
    };
    assert_eq!(
        errors(mw(json!({
            "trust_domains": ["prod.example.com"],
            "ids": ["spiffe://prod.example.com/ns/web/sa/api"],
            "id_prefixes": ["spiffe://prod.example.com/ns/jobs"]
        }))),
        Vec::new()
    );
    let found = errors(mw(json!({ "trust_domains": [] })));
    assert!(has(
        &found,
        "middlewares.workloads.spiffe.trust_domains",
        "at least one"
    ));
    let found = errors(mw(json!({
        "trust_domains": ["Prod.Example.com:443"],
        "ids": ["spiffe://other.example.com/x", "https://prod.example.com/x"]
    })));
    assert!(has(
        &found,
        "middlewares.workloads.spiffe.trust_domains",
        "not a trust domain"
    ));
    assert!(has(
        &found,
        "middlewares.workloads.spiffe.ids",
        "not in one of"
    ));
    assert!(has(
        &found,
        "middlewares.workloads.spiffe.ids",
        "not a SPIFFE ID"
    ));
    let pins = errors(with(
        app(),
        json!({ "middlewares": { "pinned": { "type": "client_cert", "sha256": ["abc"] } } }),
    ));
    assert!(has(&pins, "middlewares.pinned.sha256", "64 digits"));
}

#[test]
fn cluster_members_need_a_control_plane_or_a_directory() {
    let found = errors(json!({ "cluster": {} }));
    assert!(has(&found, "cluster", "needs `control`"));
    let found = errors(json!({ "cluster": { "store": { "type": "directory" } } }));
    assert!(has(&found, "cluster.store.path", "required"));
    let found = errors(json!({ "cluster": { "store": { "type": "control" } } }));
    assert!(has(&found, "cluster.store.type", "needs `cluster.control`"));
    let ok = validate(with(
        app(),
        json!({ "cluster": { "store": { "type": "directory", "path": "/shared/rdock" } } }),
    ));
    assert!(!ok.iter().any(Diagnostic::is_error), "{ok:?}");
    assert!(
        ok.iter()
            .any(|d| d.path == "cluster.store" && d.message.contains("best effort"))
    );
    assert!(
        ok.iter()
            .any(|d| d.path == "acme.challenges" && d.message.contains("cut off"))
    );
    let found = errors(
        json!({ "cluster": { "store": { "type": "directory", "path": "/s", "lease_ttl": "1s", "barrier_timeout": "5m" } } }),
    );
    assert!(has(
        &found,
        "cluster.store.lease_ttl",
        "between 10s and 10m"
    ));
    assert!(has(
        &found,
        "cluster.store.barrier_timeout",
        "between 1s and 2m"
    ));
}

#[test]
fn cluster_control_is_https_and_authenticated() {
    let found =
        errors(json!({ "cluster": { "control": { "url": "http://cp.example.com:7443" } } }));
    assert!(has(&found, "cluster.control.url", "`https://` only"));
    assert!(has(&found, "cluster.control", "`ca_file` or `ca_pin`"));
    let found = errors(json!({ "cluster": { "control": {
        "url": "https://cp.example.com:7443/x", "ca_pin": "sha256:abc", "identity_dir": "rel",
        "poll_timeout": "1s"
    } } }));
    assert!(has(&found, "cluster.control.url", "root"));
    assert!(has(&found, "cluster.control.ca_pin", "64 lower-case"));
    assert!(has(&found, "cluster.control.identity_dir", "absolute"));
    assert!(has(
        &found,
        "cluster.control.poll_timeout",
        "between 5s and 5m"
    ));
    let pin = format!("sha256:{}", "0f".repeat(32));
    let ok = validate(json!({ "cluster": { "control": {
        "url": "https://cp.example.com:7443", "ca_pin": pin, "join_token": "rdk_join_literal"
    } } }));
    assert!(!ok.iter().any(Diagnostic::is_error), "{ok:?}");
    assert!(
        ok.iter()
            .any(|d| d.path == "cluster.control.join_token" && d.message.contains("secret"))
    );
}

#[test]
fn control_plane_settings_are_bounded() {
    let found = errors(json!({ "control": {
        "names": ["bad name"], "identity_lifetime": "1m", "join_token_ttl": "1s",
        "history": 0, "offline_after": "2h"
    } }));
    assert!(has(&found, "control.names[0]", "DNS name"));
    assert!(has(
        &found,
        "control.identity_lifetime",
        "between 1h and 90d"
    ));
    assert!(has(&found, "control.join_token_ttl", "between 1m and 30d"));
    assert!(has(&found, "control.history", "between 1 and 1000"));
    assert!(has(&found, "control.offline_after", "between 10s and 1h"));
    let both = errors(
        json!({ "control": {}, "cluster": { "store": { "type": "directory", "path": "/s" } } }),
    );
    assert!(has(&both, "control", "not both"));
    let open = warnings(json!({ "control": { "listener": "0.0.0.0:7443" } }));
    assert!(has(&open, "control.names", "certificate"));
}

#[test]
fn kubernetes_members_of_a_control_plane_cluster_may_use_acme() {
    let pin = format!("sha256:{}", "0f".repeat(32));
    let shared = validate(with(
        app(),
        json!({
            "providers": { "kubernetes": { "gateway": { "pod_selector": { "app": "rdock" } } } },
            "cluster": { "control": { "url": "https://cp.example.com:7443", "ca_pin": pin } }
        }),
    ));
    assert!(
        !shared.iter().any(|d| d.path == "acme" && d.is_error()),
        "{shared:?}"
    );
    assert!(
        !shared
            .iter()
            .any(|d| d.message.contains("share no certificate storage"))
    );
    // A shared directory is not enough: still refused without `allow_acme`.
    let directory = errors(with(
        app(),
        json!({
            "providers": { "kubernetes": { "gateway": { "pod_selector": { "app": "rdock" } } } },
            "cluster": { "store": { "type": "directory", "path": "/shared" } }
        }),
    ));
    assert!(has(&directory, "acme", "providers.kubernetes"));
}

#[test]
fn group_keys_need_a_consumer_and_accept_overrides() {
    let config = with(
        app(),
        json!({
            "middlewares": {
                "per_group": { "type": "rate_limit", "key": "group", "average": 10,
                               "overrides": { "gold": { "average": 100 } } },
                "monthly": { "type": "quota", "key": "group", "limit": 1000, "window": "month" },
                "by_ip": { "type": "rate_limit", "average": 10, "overrides": { "gold": { "average": 1 } } }
            },
            "routes": { "app": { "middlewares": ["per_group", "monthly", "by_ip"] } }
        }),
    );
    let found = errors(config);
    assert!(
        has(&found, "routes.app.middlewares[0]", "counts per consumer"),
        "{found:?}"
    );
    assert!(
        has(&found, "routes.app.middlewares[1]", "counts per consumer"),
        "{found:?}"
    );
    assert!(
        has(&found, "middlewares.by_ip.overrides", "`key: group`"),
        "{found:?}"
    );
    assert!(
        !found
            .iter()
            .any(|(p, _)| p.starts_with("middlewares.per_group")),
        "{found:?}"
    );
    assert!(
        !found
            .iter()
            .any(|(p, _)| p.starts_with("middlewares.monthly")),
        "{found:?}"
    );
}

#[test]
fn admission_refuses_meaningless_settings() {
    let config = with(
        app(),
        json!({
            "middlewares": {
                "bad": { "type": "admission", "mode": "aimd", "min": 50, "max": 10,
                         "interval": "10s", "shares": { "normal": 50, "sheddable": 80 } },
                "grad": { "type": "admission", "mode": "gradient", "latency": "1s", "max": 200_000,
                          "interval": "2h", "jitter_percent": 101, "probe_timeout": "10ms" },
                "ok": { "type": "admission", "mode": "gradient" },
                "slots": { "type": "in_flight", "amount": 10, "key": "route" }
            },
            "routes": { "app": { "middlewares": ["ok", "slots"], "priority_class": "critical" } }
        }),
    );
    let found = errors(config.clone());
    assert!(
        has(&found, "middlewares.bad.min", "above `max`"),
        "{found:?}"
    );
    assert!(
        has(&found, "middlewares.bad.interval", "does not apply"),
        "{found:?}"
    );
    assert!(
        has(&found, "middlewares.grad.interval", "1s to 1h"),
        "{found:?}"
    );
    assert!(
        has(&found, "middlewares.grad.jitter_percent", "0 to 100"),
        "{found:?}"
    );
    assert!(
        has(&found, "middlewares.grad.probe_timeout", "100ms to 60s"),
        "{found:?}"
    );
    assert!(
        has(&found, "middlewares.bad.shares.sheddable", "above `normal`"),
        "{found:?}"
    );
    assert!(
        has(&found, "middlewares.grad.latency", "does not apply"),
        "{found:?}"
    );
    assert!(
        has(&found, "middlewares.grad.max", "at most 100000"),
        "{found:?}"
    );
    assert!(
        has(&found, "routes.app.middlewares[1]", "two caps"),
        "{found:?}"
    );
    assert!(
        !found.iter().any(|(p, _)| p.starts_with("middlewares.ok")),
        "{found:?}"
    );
    // A class without an admission middleware does nothing: a warning.
    let lone = with(
        app(),
        json!({ "routes": { "app": { "priority_class": "sheddable" } } }),
    );
    assert!(has(
        &warnings(lone),
        "routes.app.priority_class",
        "only matters"
    ));
}

fn merged_errors(value: Value) -> Vec<(String, String)> {
    let config: Config = serde_json::from_value(value).unwrap();
    config
        .validate_merged()
        .into_iter()
        .filter(Diagnostic::is_error)
        .map(|d| (d.path, d.message))
        .collect()
}

#[test]
#[allow(clippy::too_many_lines)]
fn tenant_objects_stay_inside_their_claims_and_prefix() {
    let backend = json!({ "backends": [{ "address": "10.0.0.1:80" }] });
    let public = json!({ "backends": [{ "address": "app.example.net:80" }] });
    let config = json!({
        "tenants": {
            "acme": { "hosts": ["acme.example.com", "*.acme.example.com"],
                      "shared": { "middlewares": ["compress"] } },
            "globex": { "hosts": ["globex.example.com"], "backend_networks": ["10.0.0.0/8"] }
        },
        "routes": {
            "acme-web@api": { "match": "Host(`shop.acme.example.com`) && PathPrefix(`/`)",
                              "service": "acme-svc@api", "middlewares": ["compress", "acme-hdr@api"] },
            "acme-out@api": { "match": "Host(`globex.example.com`)", "service": "acme-svc@api" },
            "acme-or@api": { "match": "Host(`acme.example.com`) || Host(`globex.example.com`)", "service": "acme-svc@api" },
            "acme-wide@api": { "match": "Host(`*.example.com`)", "service": "acme-svc@api" },
            "acme-any@api": { "match": "PathPrefix(`/`)", "service": "acme-svc@api" },
            "acme-steal@api": { "match": "Host(`acme.example.com`)", "service": "globex-svc@api" },
            "globex-web@api": { "match": "Host(`globex.example.com`)", "service": "globex-svc@api" },
            "file-route": { "match": "Host(`globex.example.com`)", "service": "file-svc" }
        },
        "services": {
            "acme-svc@api": public,
            "acme-loop@api": { "backends": [{ "address": "127.0.0.1:9900" }] },
            "acme-meta@api": { "backends": [{ "address": "169.254.169.254:80" }] },
            "acme-sock@api": { "backends": [{ "address": "unix:///run/admin.sock" }] },
            "acme-tls@api": { "backends": [{ "address": "app.example.net:443" }], "scheme": "https",
                              "tls": { "ca_file": "/etc/ssl/private/ca.pem" } },
            "globex-svc@api": backend.clone(),
            "file-svc": backend
        },
        "middlewares": {
            "compress": { "type": "compress" },
            "acme-hdr@api": { "type": "headers", "request": { "set": { "x-key": "${env:ADMIN_TOKEN}" } } },
            "acme-fa@api": { "type": "forward_auth", "address": "http://auth.internal:9000/check" },
            "acme-page@api": { "type": "errors", "status": ["500"], "file": "/etc/shadow" },
            "acme-rewrite@api": { "type": "rewrite", "regex": "^/(.*)", "replacement": "/${1}" }
        }
    });
    let found = merged_errors(config);
    let at = |path: &str, fragment: &str| has(&found, path, fragment);
    assert!(
        !found
            .iter()
            .any(|(p, _)| p.starts_with(&crate::diagnostics::path_key("routes", "acme-web@api"))),
        "{found:?}"
    );
    assert!(
        at(
            &format!(
                "{}.match",
                crate::diagnostics::path_key("routes", "acme-out@api")
            ),
            "not inside the host claims"
        ),
        "{found:?}"
    );
    assert!(
        at(
            &format!(
                "{}.match",
                crate::diagnostics::path_key("routes", "acme-or@api")
            ),
            "not inside"
        ),
        "{found:?}"
    );
    assert!(
        at(
            &format!(
                "{}.match",
                crate::diagnostics::path_key("routes", "acme-wide@api")
            ),
            "not inside"
        ),
        "{found:?}"
    );
    assert!(
        at(
            &format!(
                "{}.match",
                crate::diagnostics::path_key("routes", "acme-any@api")
            ),
            "not inside"
        ),
        "{found:?}"
    );
    assert!(
        at(
            &format!(
                "{}.service",
                crate::diagnostics::path_key("routes", "acme-steal@api")
            ),
            "outside tenant `acme`"
        ),
        "{found:?}"
    );
    assert!(
        at(
            &format!(
                "{}.backends[0].address",
                crate::diagnostics::path_key("services", "acme-loop@api")
            ),
            "loopback"
        ),
        "{found:?}"
    );
    assert!(
        at(
            &format!(
                "{}.backends[0].address",
                crate::diagnostics::path_key("services", "acme-meta@api")
            ),
            "cloud metadata"
        ),
        "{found:?}"
    );
    assert!(
        at(
            &format!(
                "{}.backends[0].address",
                crate::diagnostics::path_key("services", "acme-sock@api")
            ),
            "Unix socket"
        ),
        "{found:?}"
    );
    assert!(
        at(
            &format!(
                "{}.tls.ca_file",
                crate::diagnostics::path_key("services", "acme-tls@api")
            ),
            "reads a file"
        ),
        "{found:?}"
    );
    assert!(
        at(
            &format!(
                "{}.request.set.x-key",
                crate::diagnostics::path_key("middlewares", "acme-hdr@api")
            ),
            "`${…}` reference"
        ),
        "{found:?}"
    );
    assert!(
        at(
            &crate::diagnostics::path_key("middlewares", "acme-fa@api"),
            "`type: forward_auth`"
        ),
        "{found:?}"
    );
    assert!(
        at(
            &format!(
                "{}.file",
                crate::diagnostics::path_key("middlewares", "acme-page@api")
            ),
            "reads a file"
        ),
        "{found:?}"
    );
    assert!(
        !found
            .iter()
            .any(|(p, _)| p.starts_with(&crate::diagnostics::path_key(
                "middlewares",
                "acme-rewrite@api"
            ))),
        "{found:?}"
    );
    // The other tenant's and the file's objects are not checked against acme.
    assert!(
        !found
            .iter()
            .any(|(p, _)| p.starts_with(&crate::diagnostics::path_key("routes", "globex-web@api"))),
        "{found:?}"
    );
    assert!(
        !found
            .iter()
            .any(|(p, _)| p.starts_with(&crate::diagnostics::path_key("routes", "file-route"))),
        "{found:?}"
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn tenant_backends_reach_only_global_addresses_by_default() {
    let config = |networks: Value, addresses: &[&str]| {
        let services: serde_json::Map<String, Value> = addresses
            .iter()
            .enumerate()
            .map(|(i, a)| {
                (
                    format!("acme-s{i}@api"),
                    json!({ "backends": [{ "address": a }] }),
                )
            })
            .collect();
        json!({
            "tenants": { "acme": { "hosts": ["acme.example.com"], "backend_networks": networks } },
            "services": services,
        })
    };
    let refused = [
        "127.0.0.1:80",
        "127.0.0.2:80",
        "0.0.0.0:80",
        "10.0.0.1:80",
        "172.17.0.1:2375",
        "192.168.1.1:80",
        "100.64.0.1:80",
        "169.254.169.254:80",
        "169.254.170.2:80",
        "168.63.129.16:80",
        "224.0.0.1:80",
        "192.0.2.1:80",
        "[::1]:80",
        "[::]:80",
        "[::ffff:127.0.0.1]:80",
        "[::ffff:8.8.8.8]:80",
        "[fe80::1]:80",
        "[fd00:ec2::254]:80",
        "[fd12::1]:80",
        "[2001:db8::1]:80",
        "localhost:80",
        "localhost.localdomain:80",
        "ip6-localhost:80",
        "ip6-loopback:80",
        "a.localhost:80",
        "unix:///run/admin.sock",
    ];
    let found = merged_errors(config(json!([]), &refused));
    for (i, address) in refused.iter().enumerate() {
        let path = format!(
            "{}.backends[0].address",
            crate::diagnostics::path_key("services", &format!("acme-s{i}@api"))
        );
        assert!(
            has(&found, &path, "cannot send traffic"),
            "{address}: {found:?}"
        );
    }
    let accepted = [
        "8.8.8.8:53",
        "[2001:4860:4860::8888]:53",
        "app.example.net:80",
        "srv://_http._tcp.example.net",
    ];
    let found = merged_errors(config(json!([]), &accepted));
    assert!(found.is_empty(), "{found:?}");
    // With networks: exactly those, IP literals only.
    let listed = [
        "10.1.2.3:80",
        "[::ffff:10.1.2.3]:80",
        "8.8.8.8:80",
        "app.example.net:80",
        "169.254.169.254:80",
    ];
    let found = merged_errors(config(json!(["10.0.0.0/8", "0.0.0.0/0"]), &listed));
    let at = |i: usize| {
        format!(
            "{}.backends[0].address",
            crate::diagnostics::path_key("services", &format!("acme-s{i}@api"))
        )
    };
    assert!(!found.iter().any(|(p, _)| *p == at(0)), "{found:?}");
    assert!(has(&found, &at(1), "IPv4-mapped"), "{found:?}");
    assert!(
        !found.iter().any(|(p, _)| *p == at(2)),
        "inside 0.0.0.0/0: {found:?}"
    );
    assert!(has(&found, &at(3), "DNS name"), "{found:?}");
    assert!(has(&found, &at(4), "metadata"), "{found:?}");
    // Listing loopback or link-local is allowed, with a warning.
    let config: Config =
        serde_json::from_value(config(json!(["127.0.0.1", "169.254.0.0/16"]), &[])).unwrap();
    let warned: Vec<_> = config
        .validate_merged()
        .into_iter()
        .filter(|d| !d.is_error())
        .map(|d| (d.path, d.message))
        .collect();
    assert!(
        has(&warned, "tenants.acme.backend_networks[0]", "loopback"),
        "{warned:?}"
    );
    assert!(
        has(&warned, "tenants.acme.backend_networks[1]", "link-local"),
        "{warned:?}"
    );
}

#[test]
fn numeric_host_spellings_are_never_dns_names() {
    for address in [
        "127.1:80",
        "2130706433:80",
        "2852039166:80",
        "0:80",
        "0.0:80",
        "0x7f.0.0.1:80",
        "0x7f000001:80",
        "0177.0.0.1:80",
        "127.0.0.1.:80",
        "[fe80::1%eth0]:80",
        "[::ffff:127.0.0.1%1]:80",
    ] {
        assert!(
            address.parse::<crate::values::BackendAddress>().is_err(),
            "{address}"
        );
    }
    let message = "127.1:80"
        .parse::<crate::values::BackendAddress>()
        .unwrap_err()
        .to_string();
    assert!(message.contains("non-canonical IP address"), "{message}");
    assert!("app-1:80".parse::<crate::values::BackendAddress>().is_ok());
}

#[test]
fn tenant_limits_cap_bodies_objects_and_certificate_names() {
    let route =
        |host: &str| json!({ "match": format!("Host(`{host}`)"), "service": "acme-svc@api" });
    let mut routes = serde_json::Map::new();
    for i in 0..4 {
        routes.insert(
            format!("acme-r{i}@api"),
            route(&format!("r{i}.acme.example.com")),
        );
    }
    routes.insert(
        "acme-big@api".into(),
        json!({ "match": "Host(`big.acme.example.com`)", "service": "acme-svc@api", "max_body": "2MiB" }),
    );
    routes.insert(
        "acme-crit@api".into(),
        json!({ "match": "Host(`c.acme.example.com`)", "service": "acme-svc@api",
                "priority_class": "critical", "middlewares": ["shared-adm"] }),
    );
    routes.insert(
        "acme-crit-own@api".into(),
        json!({ "match": "Host(`d.acme.example.com`)", "service": "acme-svc@api",
                "priority_class": "critical", "middlewares": ["acme-adm@api"] }),
    );
    let found = merged_errors(json!({
        "defaults": { "tls": "auto" },
        "tenants": { "acme": {
            "hosts": ["*.acme.example.com"],
            "shared": { "middlewares": ["shared-adm"] },
            "limits": { "max_body": "1MiB", "max_routes": 6, "max_tls_names": 3 }
        } },
        "routes": routes,
        "services": { "acme-svc@api": { "backends": [{ "address": "app.example.net:80" }] } },
        "middlewares": {
            "shared-adm": { "type": "admission", "mode": "aimd" },
            "acme-adm@api": { "type": "admission", "mode": "aimd" },
            "acme-hold@api": { "type": "hold_body", "max": "4MiB" }
        }
    }));
    let key = |section: &str, name: &str| crate::diagnostics::path_key(section, name);
    assert!(
        has(
            &found,
            &format!("{}.max_body", key("routes", "acme-big@api")),
            "body limit"
        ),
        "{found:?}"
    );
    assert!(
        has(
            &found,
            &format!("{}.max", key("middlewares", "acme-hold@api")),
            "body limit"
        ),
        "{found:?}"
    );
    // Seven routes, six allowed: the last by name is refused.
    assert!(
        has(&found, &key("routes", "acme-r3@api"), "at most 6 routes"),
        "{found:?}"
    );
    assert!(
        found
            .iter()
            .filter(|(_, m)| m.contains("at most 6 routes"))
            .count()
            == 1,
        "{found:?}"
    );
    // Three certificate names: the fourth name is refused.
    assert!(
        found
            .iter()
            .any(|(_, m)| m.contains("at most 3 host names")),
        "{found:?}"
    );
    assert!(
        has(
            &found,
            &format!("{}.priority_class", key("routes", "acme-crit@api")),
            "cannot mark routes `critical`"
        ),
        "{found:?}"
    );
    assert!(
        !found
            .iter()
            .any(|(p, _)| p.starts_with(&key("routes", "acme-crit-own@api"))
                && p.ends_with("priority_class")),
        "{found:?}"
    );
}

#[test]
fn tenant_diagnostics_do_not_list_other_objects() {
    let found = merged_errors(json!({
        "tenants": { "acme": { "hosts": ["acme.example.com"] } },
        "routes": {
            "acme-a@api": { "match": "Host(`acme.example.com`)", "service": "secret-backend" },
            "acme-b@api": { "match": "Host(`acme.example.com`) && Path(`/b`)", "service": "nothing-here" },
            "acme-c@api": { "match": "Host(`acme.example.com`) && Path(`/c`)", "service": "acme-missing@api" }
        },
        "services": {
            "secret-backend": { "backends": [{ "address": "10.0.0.1:80" }] }
        }
    }));
    let key = |name: &str| format!("{}.service", crate::diagnostics::path_key("routes", name));
    // Existing and missing objects outside the tenant answer the same.
    let a: Vec<_> = found
        .iter()
        .filter(|(p, _)| *p == key("acme-a@api"))
        .map(|(_, m)| m.replace("secret-backend", "X"))
        .collect();
    let b: Vec<_> = found
        .iter()
        .filter(|(p, _)| *p == key("acme-b@api"))
        .map(|(_, m)| m.replace("nothing-here", "X"))
        .collect();
    assert_eq!(a, b, "{found:?}");
    assert!(
        has(&found, &key("acme-c@api"), "does not exist"),
        "{found:?}"
    );
    let config: Config = serde_json::from_value(json!({
        "tenants": { "acme": { "hosts": ["acme.example.com"] } },
        "routes": { "acme-c@api": { "match": "Host(`acme.example.com`)", "service": "acme-missing@api" } },
        "services": { "secret-backend": { "backends": [{ "address": "10.0.0.1:80" }] } }
    }))
    .unwrap();
    for d in config.validate_merged() {
        assert!(!format!("{d:?}").contains("secret-backend"), "{d:?}");
    }
}

#[test]
fn tenant_prefixes_and_claims_may_not_overlap() {
    let found = errors(json!({
        "tenants": {
            "a": { "hosts": ["*.example.com"] },
            "ab": { "prefix": "a-b", "hosts": ["shop.example.com"] },
            "c": { "hosts": ["*.com", "bücher.example"] }
        }
    }));
    assert!(has(&found, "tenants.ab.prefix", "overlap"), "{found:?}");
    assert!(
        has(&found, "tenants.ab.hosts", "overlaps `*.example.com`"),
        "{found:?}"
    );
    assert!(
        has(&found, "tenants.c.hosts[0]", "top-level domain"),
        "{found:?}"
    );
    assert!(has(&found, "tenants.c.hosts[1]", "A-label"), "{found:?}");
}

#[test]
fn http3_values_are_bounded_and_need_an_https_listener() {
    let config = with(
        app(),
        json!({ "listeners": {
            "a": { "address": ":443", "tls": {}, "http3": {
                "enabled": true,
                "advertise_max_age": "0s",
                "advertise_port": 0,
                "max_idle": "1h",
                "max_concurrent_streams": 0,
                "max_header_size": "2MiB",
                "max_connections": 10,
                "max_connections_per_client": 11,
                "congestion": "bbr"
            } },
            "b": { "address": ":80", "http3": { "enabled": true } },
            "c": { "address": ":8443", "tls": {}, "http3": { "max_header_size": "512B", "max_connections": 0 } }
        }}),
    );
    let found = errors(config.clone());
    for (path, fragment) in [
        ("listeners.a.http3.advertise_max_age", "between 1s and 30d"),
        ("listeners.a.http3.advertise_port", "1-65535"),
        ("listeners.a.http3.max_idle", "between 1s and 10m"),
        (
            "listeners.a.http3.max_concurrent_streams",
            "between 1 and 10000",
        ),
        (
            "listeners.a.http3.max_header_size",
            "between 1024 and 786432",
        ),
        (
            "listeners.a.http3.max_connections_per_client",
            "`max_connections`",
        ),
        ("listeners.b.http3", "`https` listeners only"),
        (
            "listeners.c.http3.max_header_size",
            "between 1024 and 786432",
        ),
        ("listeners.c.http3.max_connections", "between 1 and 1000000"),
    ] {
        assert!(has(&found, path, fragment), "{path}: {found:?}");
    }
    assert!(has(
        &warnings(config),
        "listeners.a.http3.congestion",
        "experimental"
    ));
}

#[test]
fn http3_windows_are_bounded_and_their_memory_is_warned_about() {
    let config = with(
        app(),
        json!({ "listeners": {
            "a": { "address": ":443", "tls": {}, "http3": {
                "client_ipv6_prefix": 16,
                "stream_receive_window": "2MiB",
                "receive_window": "1MiB",
                "send_window": "128MiB",
                "max_header_size": "768KiB"
            } },
            "b": { "address": ":8443", "tls": {}, "http3": {
                "stream_receive_window": "4KiB",
                "receive_window": "16KiB",
                "max_header_size": "32KiB"
            } },
            "c": { "address": ":9443", "tls": {}, "http3": {
                "max_connections": 100_000,
                "receive_window": "8MiB",
                "max_connections_per_client": 100
            } }
        }}),
    );
    let found = errors(config.clone());
    for (path, fragment) in [
        ("listeners.a.http3.client_ipv6_prefix", "between 32 and 128"),
        (
            "listeners.a.http3.stream_receive_window",
            "at most `receive_window`",
        ),
        ("listeners.a.http3.send_window", "between 64KiB and 64MiB"),
        ("listeners.b.http3.stream_receive_window", "16KiB and 16MiB"),
        ("listeners.b.http3.receive_window", "64KiB and 64MiB"),
        (
            "listeners.b.http3.max_header_size",
            "at most `receive_window`",
        ),
    ] {
        assert!(has(&found, path, fragment), "{path}: {found:?}");
    }
    assert!(
        !found.iter().any(|(p, _)| p.starts_with("listeners.c")),
        "{found:?}"
    );
    // 100,000 × (2 × 8 MiB + 1 MiB) is 1.7 TB: a warning, not an error.
    assert!(has(
        &warnings(config),
        "listeners.c.http3.max_connections",
        "1700000 MiB"
    ));
    // The defaults stay below the warning: 1000 × (2 × 1 MiB + 1 MiB) = 3000 MiB.
    let defaults = crate::config::ListenerHttp3::default();
    assert_eq!(defaults.worst_case_memory(), 3000 << 20);
    assert!(defaults.worst_case_memory() <= crate::config::ListenerHttp3::MEMORY_WARNING);
}

#[test]
fn the_header_size_ceiling_stays_below_the_header_map_panic() {
    // h3 0.0.8 calls `HeaderMap::with_capacity(fields)` and counts at least 32 bytes per field;
    // http 1.5 panics when the capacity plus a third rounds up past 2^15.
    let ceiling = crate::config::ListenerHttp3::MAX_HEADER_SIZE_CEILING.as_u64();
    let fields = usize::try_from(ceiling / 32).unwrap();
    assert_eq!(fields, 24_576);
    let raw = fields + fields / 3;
    assert!(raw.next_power_of_two() <= 1 << 15);
    let one_more = fields + 1;
    assert!((one_more + one_more / 3).next_power_of_two() > 1 << 15);
}

#[test]
fn http3_owns_the_udp_port_of_its_address() {
    let config = with(
        app(),
        json!({ "listeners": {
            "web": { "address": ":443", "tls": {}, "http3": { "enabled": true } },
            "dns": { "address": ":443", "protocol": "udp" }
        }}),
    );
    assert!(has(
        &errors(config),
        "listeners.web.http3.enabled",
        "the `udp` listener `dns`"
    ));
    // Off, the `udp` listener keeps the port (as before v0.9).
    let off = with(
        app(),
        json!({ "listeners": {
            "web": { "address": ":443", "tls": {}, "http3": { "enabled": false } },
            "dns": { "address": ":443", "protocol": "udp" }
        }}),
    );
    assert!(!errors(off).iter().any(|(p, _)| p.contains("http3")));
    // The defaults are valid.
    let defaults = with(
        app(),
        json!({ "experimental": ["http3"], "listeners": { "websecure": { "address": ":443", "tls": {}, "http3": { "enabled": true } }, "web": { "address": ":80" } } }),
    );
    assert_eq!(errors(defaults.clone()), Vec::<(String, String)>::new());
    assert_eq!(warnings(defaults), Vec::<(String, String)>::new());
}

#[test]
fn basic_auth_hashes_have_a_bounded_cost() {
    let salt = "c29tZXNhbHQxMjM0NTY3OA$AAAA";
    let config = with(
        app(),
        json!({
            "middlewares": {
                "auth": { "type": "basic_auth", "users": [
                    format!("ok:$argon2id$v=19$m=19456,t=2,p=1${salt}"),
                    format!("mem:$argon2id$v=19$m=4194304,t=1,p=1${salt}"),
                    "slow:$2b$20$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234"
                ] }
            }
        }),
    );
    let found = errors(config);
    assert!(
        !found.iter().any(|(p, _)| p == "middlewares.auth.users[0]"),
        "{found:?}"
    );
    assert!(
        has(&found, "middlewares.auth.users[1]", "the limit is 262144"),
        "{found:?}"
    );
    assert!(
        has(&found, "middlewares.auth.users[2]", "the limit is 14"),
        "{found:?}"
    );
}

#[test]
fn consumer_bans_need_the_consumer_first_and_fingerprint_bans_warn() {
    let config = with(
        app(),
        json!({
            "consumers": { "ann": { "keys": [] } },
            "middlewares": {
                "ban": { "type": "abuse", "key": "consumer", "events": ["404"] },
                "keys": { "type": "api_key" },
                "ja4ban": { "type": "abuse", "key": "ja4", "events": ["auth_failure"], "action": "deny" },
                "ja4limit": { "type": "rate_limit", "key": "ja4", "average": 10 }
            },
            "routes": {
                "app": { "middlewares": ["ban", "keys"] },
                "after": { "match": "Host(`after.example.com`)", "service": "app", "middlewares": ["keys", "ban"] }
            }
        }),
    );
    let found = errors(config.clone());
    assert!(
        has(
            &found,
            "routes.app.middlewares[0]",
            "no middleware before it sets one"
        ),
        "{found:?}"
    );
    assert!(
        !found.iter().any(|(p, _)| p.starts_with("routes.after")),
        "{found:?}"
    );
    let warned = warnings(config);
    assert!(
        has(
            &warned,
            "middlewares.ja4ban.key",
            "every client with the same TLS stack"
        ),
        "{warned:?}"
    );
    assert!(
        has(
            &warned,
            "middlewares.ja4limit.key",
            "every client with the same TLS stack"
        ),
        "{warned:?}"
    );
}
