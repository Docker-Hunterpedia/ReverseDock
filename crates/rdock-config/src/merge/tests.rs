use std::collections::BTreeSet;

use super::*;
use crate::{Format, load_str};

const FILE: &str = "
listeners:
  web: { address: \":8080\" }
defaults: { listeners: [web], tls: off }
routes:
  site: { match: \"Host(`site.example.com`)\", service: site }
services:
  site: { backends: [{ address: \"site:80\" }] }
middlewares:
  secure: { type: headers, response: { set: { X-Frame-Options: DENY } } }
";

fn base(yaml: &str) -> Config {
    let loaded = load_str(yaml, Format::Yaml).unwrap();
    assert!(!loaded.has_errors(), "{:?}", loaded.diagnostics);
    loaded.config
}

fn docker(yaml: &str) -> Snapshot {
    let fragment: Fragment = serde_saphyr::from_str(yaml).unwrap();
    Snapshot {
        provider: "docker".to_owned(),
        fragment,
        diagnostics: Vec::new(),
        revision: None,
    }
}

const APP: &str = "
routes:
  app: { match: \"Host(`app.example.com`)\", service: app, middlewares: [secure, limit] }
services:
  app: { backends: [{ address: \"10.0.0.5:3000\" }] }
middlewares:
  limit: { type: rate_limit, average: 10 }
";

#[test]
fn provider_objects_get_qualified_keys_and_same_provider_references() {
    let merged = assemble(&base(FILE), &[&docker(APP)], &BTreeSet::new());
    assert_eq!(merged.errors, Vec::new());
    assert_eq!(merged.skipped, Vec::new());
    let route = &merged.config.routes["app@docker"];
    assert_eq!(route.service.as_deref(), Some("app@docker"));
    // `secure` exists only in the file; `limit` is the container's own.
    assert_eq!(route.middlewares, ["secure", "limit@docker"]);
    assert!(merged.config.services.contains_key("app@docker"));
    assert!(merged.config.routes.contains_key("site"));
}

#[test]
fn a_bad_object_is_left_out_with_what_needs_it() {
    let snapshot = docker(
        "
routes:
  app: { match: \"Host(`app.example.com`)\", service: app }
  broken: { match: \"Host(`b.example.com`)\", service: missing }
services:
  app: { backends: [{ address: \"10.0.0.5:3000\" }] }
",
    );
    let merged = assemble(&base(FILE), &[&snapshot], &BTreeSet::new());
    assert_eq!(merged.errors, Vec::new());
    assert!(merged.config.routes.contains_key("app@docker"));
    assert!(!merged.config.routes.contains_key("broken@docker"));
    assert_eq!(merged.skipped.len(), 1);
    assert_eq!(merged.skipped[0].path, "routes[\"broken@docker\"]");
    assert!(
        merged.skipped[0]
            .message
            .starts_with("left out: service `missing` does not exist")
    );
}

#[test]
fn excluded_objects_take_their_dependents_with_them() {
    let excluded = BTreeSet::from([(Section::Services, "app@docker".to_owned())]);
    let merged = assemble(&base(FILE), &[&docker(APP)], &excluded);
    assert_eq!(merged.errors, Vec::new());
    assert!(!merged.config.routes.contains_key("app@docker"));
    assert_eq!(merged.skipped.len(), 1, "{:?}", merged.skipped);
}

#[test]
fn a_file_route_that_needs_a_missing_provider_object_is_left_out() {
    let file = FILE.replace(
        "routes:\n",
        "routes:\n  other: { match: \"Host(`o.example.com`)\", service: \"app@docker\" }\n",
    );
    let merged = assemble(&base(&file), &[], &BTreeSet::new());
    assert_eq!(merged.errors, Vec::new());
    assert!(!merged.config.routes.contains_key("other"));
    assert!(merged.config.routes.contains_key("site"));
}

#[test]
fn owners_are_found_in_both_path_forms() {
    assert_eq!(
        owner("routes.app.tls"),
        Some((Section::Routes, "app".to_owned()))
    );
    assert_eq!(
        owner("services[\"api@docker\"].backends[0].address"),
        Some((Section::Services, "api@docker".to_owned()))
    );
    assert_eq!(
        owner("middlewares.limit"),
        Some((Section::Middlewares, "limit".to_owned()))
    );
    assert_eq!(
        owner("tcp_routes.db.match"),
        Some((Section::TcpRoutes, "db".to_owned()))
    );
    assert_eq!(
        owner("tcp_services[\"pg@docker\"].backends"),
        Some((Section::TcpServices, "pg@docker".to_owned()))
    );
    assert_eq!(owner("defaults.certificate"), None);
}

#[test]
fn provider_tcp_routes_are_qualified_and_left_out_when_invalid() {
    let file = FILE.replace(
        "  web: { address: \":8080\" }\n",
        "  web: { address: \":8080\" }\n  db: { address: \":5432\", protocol: tcp }\n",
    );
    let snapshot = docker(
        "
tcp_routes:
  pg: { match: \"HostSNI(`*`)\", listeners: [db], service: pg, middlewares: [allow] }
  broken: { match: \"Host(`x.example.com`)\", listeners: [db], service: pg }
tcp_services:
  pg: { backends: [{ address: \"10.0.0.7:5432\" }] }
middlewares:
  allow: { type: ip_allow, cidrs: [10.0.0.0/8] }
",
    );
    let merged = assemble(&base(&file), &[&snapshot], &BTreeSet::new());
    assert_eq!(merged.errors, Vec::new());
    let route = &merged.config.tcp_routes["pg@docker"];
    assert_eq!(route.service, "pg@docker");
    assert_eq!(route.middlewares, ["allow@docker"]);
    assert!(merged.config.tcp_services.contains_key("pg@docker"));
    assert!(!merged.config.tcp_routes.contains_key("broken@docker"));
    assert!(
        merged
            .skipped
            .iter()
            .any(|d| d.path == "tcp_routes[\"broken@docker\"]"),
        "{:?}",
        merged.skipped
    );
}

#[test]
fn provider_udp_routes_are_qualified_and_left_out_when_invalid() {
    let file = FILE.replace(
        "  web: { address: \":8080\" }\n",
        "  web: { address: \":8080\" }\n  dns: { address: \":5353\", protocol: udp }\n",
    );
    let snapshot = docker(
        "
udp_routes:
  dns: { listeners: [dns], service: dns, middlewares: [allow] }
  second: { listeners: [dns], service: dns }
  broken: { match: \"Host(`x.example.com`)\", listeners: [dns], service: dns }
udp_services:
  dns: { backends: [{ address: \"10.0.0.53:53\" }] }
middlewares:
  allow: { type: ip_allow, cidrs: [10.0.0.0/8] }
",
    );
    let merged = assemble(&base(&file), &[&snapshot], &BTreeSet::new());
    assert_eq!(merged.errors, Vec::new());
    let route = &merged.config.udp_routes["dns@docker"];
    assert_eq!(route.service, "dns@docker");
    assert_eq!(route.middlewares, ["allow@docker"]);
    assert!(merged.config.udp_services.contains_key("dns@docker"));
    // A second route without `match` on the listener, and an HTTP rule, are left out.
    for name in ["broken@docker", "second@docker"] {
        assert!(!merged.config.udp_routes.contains_key(name), "{name}");
        assert!(
            merged
                .skipped
                .iter()
                .any(|d| d.path == format!("udp_routes[\"{name}\"]")),
            "{:?}",
            merged.skipped
        );
    }
    assert_eq!(
        owner("udp_services[\"dns@docker\"].backends"),
        Some((Section::UdpServices, "dns@docker".to_owned()))
    );
}

fn kubernetes(yaml: &str) -> Snapshot {
    let fragment: Fragment = serde_saphyr::from_str(yaml).unwrap();
    Snapshot {
        provider: "kubernetes".to_owned(),
        fragment,
        diagnostics: Vec::new(),
        revision: None,
    }
}

/// A Gateway's internal listener with its own certificate and a route on it.
const GATEWAY: &str = "
listeners:
  gw-443: { address: \":20001\", tls: { certificates: [gw-cert] } }
  gw-80: { address: \":20000\" }
certificates:
  gw-cert: { cert_file: /data/kubernetes/secrets/ns/gw/tls.crt, key_file: /data/kubernetes/secrets/ns/gw/tls.key }
routes:
  app: { match: \"Host(`app.example.com`)\", service: app, listeners: [gw-443, web], tls: { certificate: gw-cert } }
  plain: { match: \"Host(`app.example.com`)\", service: app, listeners: [gw-80], tls: \"off\" }
services:
  app: { backends: [{ address: \"10.0.0.5:3000\" }] }
";

#[test]
fn kubernetes_listeners_and_certificates_are_merged_and_referenced_by_bare_name() {
    let merged = assemble(&base(FILE), &[&kubernetes(GATEWAY)], &BTreeSet::new());
    assert_eq!(merged.errors, Vec::new());
    assert_eq!(merged.skipped, Vec::new());
    let config = &merged.config;
    let listener = &config.listeners["gw-443@kubernetes"];
    assert_eq!(
        listener.tls.as_ref().unwrap().certificates,
        ["gw-cert@kubernetes"]
    );
    assert!(
        config.listeners.contains_key("web"),
        "the file's listener stays"
    );
    assert!(config.certificates.contains_key("gw-cert@kubernetes"));
    let route = &config.routes["app@kubernetes"];
    // Its own listener is qualified; `web` exists only in the file.
    assert_eq!(
        route.listeners.as_deref(),
        Some(&["gw-443@kubernetes".to_owned(), "web".to_owned()][..])
    );
    let Some(rdock_model::route::RouteTls::Options(tls)) = &route.tls else {
        panic!("route tls options")
    };
    assert_eq!(tls.certificate.as_deref(), Some("gw-cert@kubernetes"));
    assert_eq!(
        config.routes["plain@kubernetes"].listeners.as_deref(),
        Some(&["gw-80@kubernetes".to_owned()][..])
    );
}

#[test]
fn implicit_listeners_survive_provider_listeners() {
    let file = "
routes:
  site: { match: \"Host(`site.example.com`)\", service: site }
services:
  site: { backends: [{ address: \"site:80\" }] }
";
    let merged = assemble(&base(file), &[&kubernetes(GATEWAY)], &BTreeSet::new());
    assert_eq!(merged.errors, Vec::new());
    let names: Vec<&str> = merged.config.listeners.keys().map(String::as_str).collect();
    assert_eq!(
        names,
        ["gw-443@kubernetes", "gw-80@kubernetes", "web", "websecure"]
    );
}

#[test]
fn only_allowed_providers_contribute_listeners_and_certificates() {
    let mut snapshot = kubernetes(GATEWAY);
    snapshot.provider = "docker".to_owned();
    let merged = assemble(&base(FILE), &[&snapshot], &BTreeSet::new());
    assert_eq!(merged.errors, Vec::new());
    assert!(!merged.config.listeners.keys().any(|k| k.contains('@')));
    assert!(merged.config.certificates.is_empty());
    for path in [
        "listeners[\"gw-443@docker\"]",
        "listeners[\"gw-80@docker\"]",
        "certificates[\"gw-cert@docker\"]",
    ] {
        assert!(
            merged
                .skipped
                .iter()
                .any(|d| d.path == path && d.message.contains("cannot contribute")),
            "{path}: {:?}",
            merged.skipped
        );
    }
    // The routes that needed them are left out; nothing else is.
    assert!(!merged.config.routes.contains_key("app@docker"));
    assert!(!merged.config.routes.contains_key("plain@docker"));
    assert!(merged.config.services.contains_key("app@docker"));
    assert!(merged.config.routes.contains_key("site"));
}

#[test]
fn a_provider_listener_on_a_file_address_is_left_out() {
    let snapshot = kubernetes(
        "
listeners:
  clash: { address: \"0.0.0.0:8080\" }
  fine: { address: \":20000\" }
routes:
  a: { match: \"Host(`a.example.com`)\", service: app, listeners: [clash], tls: \"off\" }
  b: { match: \"Host(`b.example.com`)\", service: app, listeners: [fine], tls: \"off\" }
services:
  app: { backends: [{ address: \"10.0.0.5:3000\" }] }
",
    );
    let merged = assemble(&base(FILE), &[&snapshot], &BTreeSet::new());
    assert_eq!(merged.errors, Vec::new());
    assert!(!merged.config.listeners.contains_key("clash@kubernetes"));
    assert!(merged.config.listeners.contains_key("fine@kubernetes"));
    assert!(merged.skipped.iter().any(|d| {
        d.path == "listeners[\"clash@kubernetes\"]"
            && d.message
                .contains("already bound by the file's listener `web`")
    }));
    // `clash` was not this provider's, so the route names a listener that does not exist.
    assert!(!merged.config.routes.contains_key("a@kubernetes"));
    assert!(merged.config.routes.contains_key("b@kubernetes"));
}

#[test]
fn invalid_provider_listeners_and_certificates_are_left_out_one_by_one() {
    let snapshot = kubernetes(
        "
listeners:
  good: { address: \":20001\", tls: { certificates: [good] } }
  bad: { address: \":20002\", tls: { certificates: [bad] } }
  twin: { address: \":20001\" }
certificates:
  good: { cert_file: /a.crt, key_file: /a.key }
  bad: { cert_file: \"\", key_file: /b.key }
",
    );
    let merged = assemble(&base(FILE), &[&snapshot], &BTreeSet::new());
    assert_eq!(merged.errors, Vec::new());
    let config = &merged.config;
    assert!(config.certificates.contains_key("good@kubernetes"));
    assert!(!config.certificates.contains_key("bad@kubernetes"));
    assert!(
        !config.listeners.contains_key("bad@kubernetes"),
        "it needs the certificate that was left out"
    );
    // Two provider listeners on one address: one of them goes.
    assert_eq!(
        usize::from(config.listeners.contains_key("good@kubernetes"))
            + usize::from(config.listeners.contains_key("twin@kubernetes")),
        1
    );
    assert!(config.listeners.contains_key("web"));
}

#[test]
fn owners_of_listeners_and_certificates() {
    assert_eq!(
        owner("listeners[\"gw@kubernetes\"].tls.certificates[0]"),
        Some((Section::Listeners, "gw@kubernetes".to_owned()))
    );
    assert_eq!(
        owner("certificates[\"c@kubernetes\"].cert_file"),
        Some((Section::Certificates, "c@kubernetes".to_owned()))
    );
}
