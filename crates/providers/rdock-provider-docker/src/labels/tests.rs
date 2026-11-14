use std::net::{IpAddr, Ipv4Addr};

use rdock_model::middleware::Middleware;
use rdock_model::route::{RouteTls, TlsMode};

use super::*;

fn container(name: &str, ip: u8, ports: &[u16], labels: &[(&str, &str)]) -> Container {
    Container {
        name: name.to_owned(),
        labels: labels
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect(),
        networks: BTreeMap::from([(
            "web".to_owned(),
            Some(IpAddr::V4(Ipv4Addr::new(172, 18, 0, ip))),
        )]),
        host_network: false,
        exposed_ports: ports.iter().copied().collect(),
        health: Health::None,
        stopping: false,
        dns_name: None,
    }
}

fn run(containers: &[Container]) -> Translation {
    translate(containers, &DockerProvider::default())
}

fn backends(t: &Translation, service: &str) -> Vec<String> {
    t.fragment.services[service]
        .backends
        .iter()
        .map(|b| b.address.to_string())
        .collect()
}

fn messages(t: &Translation) -> Vec<String> {
    t.diagnostics
        .iter()
        .map(|d| format!("{}: {}", d.path, d.message))
        .collect()
}

#[test]
fn shorthand_makes_one_route_and_one_service() {
    let t = run(&[container(
        "shop-web-1",
        5,
        &[3000],
        &[
            ("rdock.enable", "true"),
            ("rdock.host", "shop.example.com, www.shop.example.com"),
            ("rdock.path", "/api"),
            ("rdock.tls", "off"),
            ("rdock.middlewares", "secure@file, limit"),
            ("com.docker.compose.service", "web"),
            ("com.docker.compose.project", "shop"),
        ],
    )]);
    assert_eq!(messages(&t), Vec::<String>::new());
    let route = &t.fragment.routes["web-shop"];
    assert_eq!(
        route.matcher,
        rdock_model::route::MatchSpec::Rule(
            "(Host(`shop.example.com`) || Host(`www.shop.example.com`)) && PathPrefix(`/api`)"
                .to_owned()
        )
    );
    assert_eq!(route.service.as_deref(), Some("web-shop"));
    assert_eq!(route.middlewares, ["secure@file", "limit"]);
    assert_eq!(route.tls, Some(RouteTls::Mode(TlsMode::Off)));
    assert_eq!(backends(&t, "web-shop"), ["172.18.0.5:3000"]);
}

#[test]
fn containers_are_opt_in() {
    let labels = [("rdock.host", "a.example.com")];
    assert!(
        run(&[container("a", 2, &[80], &labels)])
            .fragment
            .routes
            .is_empty()
    );
    let settings = DockerProvider {
        expose_by_default: true,
        ..DockerProvider::default()
    };
    let exposed = translate(&[container("a", 2, &[80], &labels)], &settings);
    assert_eq!(exposed.fragment.routes.len(), 1);
    let off = [("rdock.enable", "false"), ("rdock.host", "a.example.com")];
    assert!(
        translate(&[container("a", 2, &[80], &off)], &settings)
            .fragment
            .routes
            .is_empty()
    );
}

#[test]
fn replicas_share_one_service() {
    let labels = [
        ("rdock.enable", "true"),
        ("rdock.host", "app.example.com"),
        ("com.docker.compose.service", "app"),
        ("com.docker.compose.project", "demo"),
    ];
    let t = run(&[
        container("demo-app-1", 2, &[8080], &labels),
        container("demo-app-2", 3, &[8080], &labels),
    ]);
    assert_eq!(t.fragment.routes.len(), 1);
    assert_eq!(
        backends(&t, "app-demo"),
        ["172.18.0.2:8080", "172.18.0.3:8080"]
    );
}

#[test]
fn unhealthy_replicas_leave_the_pool_unless_none_is_healthy() {
    let labels = [
        ("rdock.enable", "true"),
        ("rdock.host", "app.example.com"),
        ("com.docker.compose.service", "app"),
        ("com.docker.compose.project", "demo"),
    ];
    let mut sick = container("demo-app-2", 3, &[80], &labels);
    sick.health = Health::Unhealthy;
    let t = run(&[container("demo-app-1", 2, &[80], &labels), sick.clone()]);
    assert_eq!(backends(&t, "app-demo"), ["172.18.0.2:80"]);
    let t = run(&[sick]);
    assert_eq!(backends(&t, "app-demo"), ["172.18.0.3:80"]);
    assert!(
        messages(&t)[0].contains("no container of service `app-demo` is healthy"),
        "{:?}",
        messages(&t)
    );
}

#[test]
fn ports_come_from_the_label_or_the_only_exposed_port() {
    let labels = [("rdock.enable", "true"), ("rdock.host", "a.example.com")];
    let t = run(&[container("a", 2, &[80, 443, 9000], &labels)]);
    assert!(t.fragment.services.is_empty());
    assert!(
        messages(&t)[0].contains("exposes 3 ports (80, 443, 9000)"),
        "{:?}",
        messages(&t)
    );
    let labels = [
        ("rdock.enable", "true"),
        ("rdock.host", "a.example.com"),
        ("rdock.port", "9000"),
    ];
    assert_eq!(
        backends(&run(&[container("a", 2, &[80, 443, 9000], &labels)]), "a"),
        ["172.18.0.2:9000"]
    );
}

#[test]
fn the_network_is_chosen_by_label_setting_or_uniqueness() {
    let mut c = container(
        "a",
        2,
        &[80],
        &[("rdock.enable", "true"), ("rdock.host", "a.example.com")],
    );
    c.networks.insert(
        "db".to_owned(),
        Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9))),
    );
    let t = run(std::slice::from_ref(&c));
    assert!(t.fragment.services.is_empty());
    assert!(messages(&t)[0].contains("several networks (db, web)"));
    c.labels
        .insert("traefik.docker.network".to_owned(), "db".to_owned());
    assert_eq!(backends(&run(&[c]), "a"), ["10.0.0.9:80"]);
}

#[test]
fn full_form_objects_decode_into_the_model() {
    let t = run(&[container(
        "api",
        7,
        &[4000, 9100],
        &[
            ("rdock.enable", "true"),
            (
                "rdock.routes.api.match",
                "Host(`api.example.com`) && PathPrefix(`/v1`)",
            ),
            ("rdock.routes.api.priority", "10"),
            ("rdock.routes.api.middlewares", "robots"),
            ("rdock.services.api.port", "4000"),
            ("rdock.services.api.scheme", "h2c"),
            ("rdock.services.api.health.active.path", "/healthz"),
            ("rdock.middlewares.robots.type", "headers"),
            ("rdock.middlewares.robots.response.set.X-Robots-Tag", "none"),
        ],
    )]);
    assert_eq!(messages(&t), Vec::<String>::new());
    let route = &t.fragment.routes["api"];
    assert_eq!(
        (route.priority, route.service.as_deref()),
        (10, Some("api"))
    );
    let service = &t.fragment.services["api"];
    assert_eq!(service.scheme, rdock_model::service::Scheme::H2c);
    assert_eq!(
        service
            .health
            .as_ref()
            .and_then(|h| h.active.as_ref())
            .map(|a| a.path.as_str()),
        Some("/healthz")
    );
    let Middleware::Headers(headers) = &t.fragment.middlewares["robots"] else {
        panic!("not headers")
    };
    assert_eq!(headers.response.set["x-robots-tag"], "none");
}

#[test]
fn static_listing_is_a_label_like_any_other_setting() {
    let t = run(&[container(
        "files",
        9,
        &[],
        &[
            ("rdock.enable", "true"),
            ("rdock.routes.files.match", "Host(`files.example.com`)"),
            ("rdock.routes.files.middlewares", "browse"),
            ("rdock.middlewares.browse.type", "static"),
            ("rdock.middlewares.browse.root", "/srv/www/files"),
            ("rdock.middlewares.browse.listing", "true"),
            ("rdock.middlewares.browse.hidden", "refuse"),
        ],
    )]);
    assert_eq!(messages(&t), Vec::<String>::new());
    let Middleware::Static(files) = &t.fragment.middlewares["browse"] else {
        panic!("not static")
    };
    assert!(files.listing);
    assert_eq!(files.root, std::path::PathBuf::from("/srv/www/files"));
    // Off unless the label says so.
    let t = run(&[container(
        "plain",
        10,
        &[],
        &[
            ("rdock.enable", "true"),
            ("rdock.routes.plain.match", "Host(`plain.example.com`)"),
            ("rdock.routes.plain.middlewares", "files"),
            ("rdock.middlewares.files.type", "static"),
            ("rdock.middlewares.files.root", "/srv/www/plain"),
        ],
    )]);
    let Middleware::Static(files) = &t.fragment.middlewares["files"] else {
        panic!("not static")
    };
    assert!(!files.listing);
}

#[test]
fn traefik_labels_map_to_the_same_model() {
    let t = run(&[container(
        "whoami",
        4,
        &[80],
        &[
            ("traefik.enable", "true"),
            ("traefik.http.routers.who.rule", "Host(`who.example.com`)"),
            ("traefik.http.routers.who.entrypoints", "websecure"),
            ("traefik.http.routers.who.tls.certresolver", "le"),
            ("traefik.http.routers.who.middlewares", "strip,auth@file"),
            (
                "traefik.http.middlewares.strip.stripprefix.prefixes",
                "/who,/w",
            ),
            ("traefik.http.services.who.loadbalancer.server.port", "80"),
            (
                "traefik.http.services.who.loadbalancer.passhostheader",
                "false",
            ),
        ],
    )]);
    assert_eq!(messages(&t), Vec::<String>::new());
    let route = &t.fragment.routes["who"];
    assert_eq!(
        route.listeners.as_deref(),
        Some(&["websecure".to_owned()][..])
    );
    assert_eq!(route.middlewares, ["strip", "auth@file"]);
    assert!(matches!(route.tls, Some(RouteTls::Options(ref o)) if o.auto));
    assert!(!t.fragment.services["who"].pass_host_header);
    assert!(
        matches!(&t.fragment.middlewares["strip"], Middleware::StripPrefix(s) if s.prefixes == ["/who", "/w"])
    );
}

#[test]
fn a_router_without_a_service_uses_the_containers_only_service() {
    let t = run(&[container(
        "web",
        4,
        &[8080],
        &[
            ("traefik.enable", "true"),
            ("traefik.http.routers.web.rule", "Host(`web.example.com`)"),
        ],
    )]);
    assert_eq!(t.fragment.routes["web"].service.as_deref(), Some("web"));
    assert_eq!(backends(&t, "web"), ["172.18.0.4:8080"]);
}

#[test]
fn unsupported_and_unsafe_labels_are_warnings() {
    let t = run(&[container(
        "x",
        4,
        &[80],
        &[
            ("traefik.enable", "true"),
            ("traefik.http.routers.x.rule", "Host(`x.example.com`)"),
            ("traefik.http.middlewares.p.plugin.demo.key", "v"),
            (
                "traefik.http.middlewares.auth.basicauth.usersfile",
                "/etc/passwd",
            ),
            ("traefik.udp.routers.dns.rule", "HostSNI(`*`)"),
            ("rdock.routes.x.tls", "${file:/run/secrets/x}"),
        ],
    )]);
    let found = messages(&t);
    assert_eq!(found.len(), 4, "{found:?}");
    assert!(
        found
            .iter()
            .any(|m| m.contains("p.plugin.demo.key") && m.contains("plugins do not run here"))
    );
    assert!(
        found
            .iter()
            .any(|m| m.contains("usersfile") && m.contains("must not name files"))
    );
    assert!(
        found
            .iter()
            .any(|m| m.contains("udp.routers.dns.rule") && m.contains("not in the supported"))
    );
    assert!(
        found
            .iter()
            .any(|m| m.contains("references are not allowed in labels"))
    );
    assert_eq!(t.fragment.routes.len(), 1);
}

#[test]
fn conflicting_declarations_drop_both() {
    let a = container(
        "a",
        2,
        &[80],
        &[
            ("rdock.enable", "true"),
            ("rdock.routes.same.match", "Host(`a.example.com`)"),
            ("rdock.routes.same.service", "a"),
        ],
    );
    let b = container(
        "b",
        3,
        &[80],
        &[
            ("rdock.enable", "true"),
            ("rdock.routes.same.match", "Host(`b.example.com`)"),
            ("rdock.routes.same.service", "a"),
        ],
    );
    let t = run(&[a, b]);
    assert!(!t.fragment.routes.contains_key("same"));
    assert!(
        messages(&t)
            .iter()
            .any(|m| m.contains("declared differently"))
    );
}

#[test]
fn translated_objects_pass_the_merged_validation() {
    let t = run(&[container(
        "whoami",
        4,
        &[80],
        &[
            ("traefik.enable", "true"),
            ("traefik.http.routers.who.rule", "Host(`who.example.com`)"),
            ("traefik.http.routers.who.tls", "false"),
            (
                "traefik.http.routers.who.middlewares",
                "strip,limit,secure-headers",
            ),
            (
                "traefik.http.middlewares.strip.stripprefix.prefixes",
                "/who",
            ),
            ("traefik.http.middlewares.limit.ratelimit.average", "20"),
            ("traefik.http.middlewares.limit.ratelimit.period", "1"),
            (
                "traefik.http.middlewares.secure-headers.headers.framedeny",
                "true",
            ),
            (
                "traefik.http.middlewares.secure-headers.headers.stsseconds",
                "31536000",
            ),
            (
                "traefik.http.middlewares.secure-headers.headers.customresponseheaders.X-Powered-By",
                "",
            ),
        ],
    )]);
    assert_eq!(messages(&t), Vec::<String>::new());
    let base: rdock_model::Config = serde_json::from_value(serde_json::json!({
        "listeners": { "web": { "address": ":8080" } },
        "defaults": { "listeners": ["web"], "tls": "off" }
    }))
    .unwrap();
    let snapshot = rdock_config::merge::Snapshot {
        provider: "docker".to_owned(),
        fragment: t.fragment,
        diagnostics: t.diagnostics,
        revision: None,
    };
    let merged =
        rdock_config::merge::assemble(&base, &[&snapshot], &std::collections::BTreeSet::new());
    assert_eq!(merged.errors, Vec::new());
    assert_eq!(merged.skipped, Vec::new());
    assert_eq!(
        merged.config.routes["who@docker"].middlewares,
        ["strip@docker", "limit@docker", "secure-headers@docker"]
    );
}

#[test]
fn a_stopping_replica_leaves_the_pool_at_once() {
    let labels = [
        ("rdock.enable", "true"),
        ("rdock.host", "app.example.com"),
        ("com.docker.compose.service", "app"),
        ("com.docker.compose.project", "demo"),
    ];
    let mut leaving = container("demo-app-2", 3, &[80], &labels);
    leaving.stopping = true;
    let t = run(&[container("demo-app-1", 2, &[80], &labels), leaving]);
    assert_eq!(backends(&t, "app-demo"), ["172.18.0.2:80"]);
}

#[test]
fn native_tcp_labels_build_tcp_routes_that_pass_the_merged_validation() {
    let t = run(&[container(
        "db",
        9,
        &[5432],
        &[
            ("rdock.enable", "true"),
            ("rdock.tcp_routes.pg.match", "HostSNI(`db.example.com`)"),
            ("rdock.tcp_routes.pg.listeners", "postgres"),
            ("rdock.tcp_routes.pg.tls.passthrough", "true"),
            ("rdock.tcp_routes.pg.middlewares", "office"),
            ("rdock.tcp_services.pg.proxy_protocol", "v2"),
            ("rdock.tcp_services.pg.timeouts.idle", "1h"),
            ("rdock.middlewares.office.type", "ip_allow"),
            ("rdock.middlewares.office.cidrs", "[10.0.0.0/8]"),
        ],
    )]);
    assert_eq!(messages(&t), Vec::<String>::new());
    let route = &t.fragment.tcp_routes["pg"];
    assert_eq!(route.service, "pg");
    assert_eq!(route.tls.map(|t| t.passthrough), Some(true));
    let service = &t.fragment.tcp_services["pg"];
    assert_eq!(service.backends[0].address.to_string(), "172.18.0.9:5432");
    assert_eq!(
        service.proxy_protocol,
        Some(rdock_model::service::ProxyProtocolVersion::V2)
    );
    let base: rdock_model::Config = serde_json::from_value(serde_json::json!({
        "listeners": { "postgres": { "address": ":5432", "protocol": "tcp" } }
    }))
    .unwrap();
    let snapshot = rdock_config::merge::Snapshot {
        provider: "docker".to_owned(),
        fragment: t.fragment,
        diagnostics: t.diagnostics,
        revision: None,
    };
    let merged =
        rdock_config::merge::assemble(&base, &[&snapshot], &std::collections::BTreeSet::new());
    assert_eq!(merged.errors, Vec::new());
    assert_eq!(merged.skipped, Vec::new());
    assert_eq!(
        merged.config.tcp_routes["pg@docker"].middlewares,
        ["office@docker"]
    );
}

/// A deprecated label is reported with the registry's facts, and a renamed one is read under
/// its new name (ADR-0033). The registry's test entries rename `routes.<name>.rule` to
/// `match`; no other test here uses that label, so turning them on for this process is safe.
#[test]
fn deprecated_labels_are_reported_and_renamed_ones_still_work() {
    rdock_model::deprecation::enable_test_entries();
    let t = run(&[container(
        "api-1",
        9,
        &[8080],
        &[
            ("rdock.enable", "true"),
            ("rdock.routes.api.rule", "Host(`api.example.com`)"),
            ("rdock.routes.api.service", "api"),
            ("rdock.services.api.port", "8080"),
        ],
    )]);
    let route = &t.fragment.routes["api"];
    assert_eq!(
        serde_json::to_value(&route.matcher).unwrap(),
        serde_json::json!("Host(`api.example.com`)")
    );
    let deprecated: Vec<_> = t
        .diagnostics
        .iter()
        .filter(|d| d.code.as_deref() == Some("deprecated"))
        .collect();
    assert_eq!(deprecated.len(), 1, "{:?}", t.diagnostics);
    assert!(
        deprecated[0].path.ends_with("rdock.routes.api.rule\"]"),
        "{}",
        deprecated[0].path
    );
    assert_eq!(deprecated[0].removal.as_deref(), Some("2.0"));
}

#[test]
fn labels_cannot_reach_the_proxys_own_machine_unless_allowed() {
    let refused = [
        "http://unix:///var/lib/rdock/admin.sock",
        "http://127.0.0.1:2080",
        "http://localhost:2080",
        "http://[::1]:2080",
        "http://169.254.169.254",
        "http://2130706433:80",
        "http://0.0.0.0:80",
    ];
    for url in refused {
        let c = container(
            "evil",
            2,
            &[80],
            &[
                ("traefik.enable", "true"),
                ("traefik.http.routers.r.rule", "Host(`evil.test`)"),
                ("traefik.http.services.s.loadbalancer.server.url", url),
            ],
        );
        let t = run(std::slice::from_ref(&c));
        assert!(!t.fragment.services.contains_key("s"), "{url}: {t:?}");
        let found = messages(&t);
        assert!(
            found
                .iter()
                .any(|m| m.contains("allow_local_backends") || m.contains("not `host:port`")),
            "{url}: {found:?}"
        );
    }
    // The setting allows loopback, never a socket.
    let allow = DockerProvider {
        allow_local_backends: true,
        ..DockerProvider::default()
    };
    let local = container(
        "dev",
        3,
        &[80],
        &[
            ("traefik.enable", "true"),
            ("traefik.http.routers.r.rule", "Host(`dev.test`)"),
            (
                "traefik.http.services.s.loadbalancer.server.url",
                "http://127.0.0.1:8080",
            ),
        ],
    );
    let t = translate(std::slice::from_ref(&local), &allow);
    assert_eq!(backends(&t, "s"), vec!["127.0.0.1:8080"]);
    let socket = container(
        "dev",
        3,
        &[80],
        &[
            ("traefik.enable", "true"),
            ("traefik.http.routers.r.rule", "Host(`dev.test`)"),
            (
                "traefik.http.services.s.loadbalancer.server.url",
                "http://unix:///run/x.sock",
            ),
        ],
    );
    assert!(
        !translate(&[socket], &allow)
            .fragment
            .services
            .contains_key("s")
    );
    // Middleware URLs too.
    let auth = container(
        "evil",
        2,
        &[80],
        &[
            ("traefik.enable", "true"),
            ("traefik.http.routers.r.rule", "Host(`evil.test`)"),
            ("traefik.http.routers.r.middlewares", "fa"),
            (
                "traefik.http.middlewares.fa.forwardauth.address",
                "http://127.0.0.1:2080/api/v1/status",
            ),
        ],
    );
    let t = run(&[auth]);
    assert!(!t.fragment.middlewares.contains_key("fa"), "{t:?}");
    // A container's own address stays as it was.
    let fine = container(
        "app",
        4,
        &[80],
        &[
            ("traefik.enable", "true"),
            ("traefik.http.routers.r.rule", "Host(`app.test`)"),
            (
                "traefik.http.middlewares.fa.forwardauth.address",
                "http://auth.internal:9000/check",
            ),
            ("traefik.http.routers.r.middlewares", "fa"),
        ],
    );
    let t = run(&[fine]);
    assert!(t.fragment.middlewares.contains_key("fa"), "{t:?}");
}

#[test]
fn middleware_urls_from_labels_are_judged_by_the_host_the_url_parser_sees() {
    let refused = [
        // `\` is `/` in special URLs, so the host is 127.0.0.1, not x.test.
        "http://127.0.0.1\\@x.test/",
        // Percent-encoded and fullwidth digits decode to 127.0.0.1.
        "http://127.0.0.%31/",
        "http://\u{ff11}\u{ff12}\u{ff17}.\u{ff10}.\u{ff10}.\u{ff11}/",
        "http://0x7f.1/",
        "http://[::ffff:127.0.0.1]/",
        "http://[fe80::1]/",
        "http://100.100.100.200/",
        "http://LOCALHOST./",
    ];
    for url in refused {
        let c = container(
            "evil",
            2,
            &[80],
            &[
                ("traefik.enable", "true"),
                ("traefik.http.routers.r.rule", "Host(`evil.test`)"),
                ("traefik.http.routers.r.middlewares", "fa"),
                ("traefik.http.middlewares.fa.forwardauth.address", url),
            ],
        );
        let t = run(&[c]);
        assert!(!t.fragment.middlewares.contains_key("fa"), "{url}: {t:?}");
        assert!(
            messages(&t)
                .iter()
                .any(|m| m.contains("allow_local_backends")),
            "{url}: {:?}",
            messages(&t)
        );
    }
    // Values that are never fetched may name the machine (a development identity provider).
    let c = container(
        "dev",
        3,
        &[80],
        &[
            ("rdock.enable", "true"),
            ("rdock.routes.app.match", "Host(`app.test`)"),
            ("rdock.routes.app.service", "app"),
            ("rdock.routes.app.middlewares", "j"),
            ("rdock.services.app.port", "80"),
            ("rdock.middlewares.j.type", "jwt"),
            (
                "rdock.middlewares.j.issuer",
                "http://localhost:8080/realms/dev",
            ),
            ("rdock.middlewares.j.audiences", "[app]"),
            ("rdock.middlewares.j.jwks_url", "https://idp.example/certs"),
        ],
    );
    let t = run(&[c]);
    assert!(
        t.fragment.middlewares.contains_key("j"),
        "{:?}",
        messages(&t)
    );
    // A fetched key URL on the machine is not.
    let c = container(
        "dev",
        3,
        &[80],
        &[
            ("rdock.enable", "true"),
            ("rdock.routes.app.match", "Host(`app.test`)"),
            ("rdock.routes.app.service", "app"),
            ("rdock.services.app.port", "80"),
            ("rdock.middlewares.j.type", "jwt"),
            ("rdock.middlewares.j.issuer", "any"),
            ("rdock.middlewares.j.audiences", "[app]"),
            (
                "rdock.middlewares.j.jwks_url",
                "http://127.0.0.%31:8080/certs",
            ),
        ],
    );
    let t = run(&[c]);
    assert!(!t.fragment.middlewares.contains_key("j"), "{t:?}");
    // A module file on the proxy's machine is never named from labels.
    let c = container(
        "evil",
        2,
        &[80],
        &[
            ("rdock.enable", "true"),
            ("rdock.routes.app.match", "Host(`app.test`)"),
            ("rdock.routes.app.service", "app"),
            ("rdock.services.app.port", "80"),
            ("rdock.middlewares.w.type", "wasm"),
            ("rdock.middlewares.w.path", "/var/lib/rdock/x.wasm"),
        ],
    );
    let t = run(&[c]);
    assert!(!t.fragment.middlewares.contains_key("w"), "{t:?}");
    assert!(
        messages(&t).iter().any(|m| m.contains("`type: wasm`")),
        "{:?}",
        messages(&t)
    );
}

#[test]
fn labels_cannot_name_files_on_the_proxys_host() {
    let c = container(
        "app",
        5,
        &[80],
        &[
            ("rdock.enable", "true"),
            ("rdock.routes.app.match", "Host(`app.test`)"),
            ("rdock.routes.app.service", "app"),
            ("rdock.services.app.port", "80"),
            ("rdock.services.app.tls.key_file", "/etc/rdock/key.pem"),
            ("rdock.middlewares.v.type", "validate"),
            ("rdock.middlewares.v.openapi", "/etc/passwd"),
            ("rdock.middlewares.j.jwks_file", "/etc/passwd"),
        ],
    );
    let t = run(&[c]);
    let found = messages(&t);
    for field in ["key_file", "openapi", "jwks_file"] {
        assert!(
            found
                .iter()
                .any(|m| m.contains(&format!("`{field}` cannot be set from labels"))),
            "{field}: {found:?}"
        );
    }
    if let Some(service) = t.fragment.services.get("app") {
        assert!(
            service
                .tls
                .as_ref()
                .is_none_or(|tls| tls.key_file.is_none())
        );
    }
}
