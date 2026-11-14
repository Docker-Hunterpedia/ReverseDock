//! A tenant's service never gets a member for an address its tenant may not reach, however the
//! address came: a DNS answer, an SRV target, a later re-resolution (H-SEC-07, ADR-0031 review
//! fixes). A service from Docker or Swarm labels never gets one on the proxy's own machine or
//! a link-local address that a name resolved to (ADR-0033 review 10 fixes).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::SocketAddr;
use std::sync::Arc;

use rdock_proxy::forwarded::CloudflareRanges;
use rdock_proxy::upstream::{Dns, SrvTarget};
use rdock_proxy::{CompileEnv, Mode, compile};

const CONFIG: &str = r#"
listeners:
  web: { address: ":8080" }
defaults: { listeners: [web], tls: off }
tenants:
  acme: { hosts: [acme.example.com] }
  lab: { hosts: [lab.example.com], backend_networks: ["10.0.0.0/8"] }
routes:
  admin: { match: "PathPrefix(`/`)", service: internal }
services:
  internal:
    backends: [{ address: "app.internal.test:8080" }]
"#;

fn api_service(name: &str, address: &str) -> rdock_config::merge::Snapshot {
    provider_service("api", name, address)
}

fn provider_service(provider: &str, name: &str, address: &str) -> rdock_config::merge::Snapshot {
    let fragment: rdock_config::merge::Fragment = serde_json::from_value(serde_json::json!({
        "services": { name: { "backends": [{ "address": address }] } }
    }))
    .unwrap();
    rdock_config::merge::Snapshot {
        provider: provider.into(),
        fragment,
        diagnostics: Vec::new(),
        revision: None,
    }
}

fn members_of(service: &rdock_proxy::runtime::ServiceRuntime) -> Vec<String> {
    service.members().iter().map(|m| m.id.clone()).collect()
}

#[test]
fn resolved_addresses_outside_the_tenants_policy_are_never_members() {
    let file = rdock_config::load_str(CONFIG, rdock_config::Format::Yaml)
        .unwrap()
        .config;
    let snapshots = [
        api_service("acme-web", "rebind.attacker.test:80"),
        api_service("acme-srv", "srv://_http._tcp.attacker.test"),
        api_service("lab-db", "10.0.0.5:5432"),
    ];
    let refs: Vec<&rdock_config::merge::Snapshot> = snapshots.iter().collect();
    let merged = rdock_config::merge::assemble(&file, &refs, &std::collections::BTreeSet::new());
    assert!(
        merged.skipped.is_empty() && merged.errors.is_empty(),
        "{merged:?}"
    );
    let config = merged.config;
    let dns = Dns::default();
    let backends = rdock_balancer::Registry::default();
    let cloudflare = CloudflareRanges::default();
    let compiled = compile(
        &config,
        &CompileEnv {
            mode: Mode::Validate,
            generation: 1,
            dns: &dns,
            client: Arc::new(rdock_middleware::HttpClient::default()),
            previous: None,
            cloudflare: &cloudflare,
            backends: &backends,
            sticky_key: b"test",
            live: &rdock_observability::live::Live::default(),
            caches: None,
            plugins: &rdock_plugin_api::Registry::new(),
            metrics: None,
            quotas: None,
            abuse: None,
            shared_limits: None,
        },
    );
    let runtime = compiled
        .runtime
        .unwrap_or_else(|| panic!("{:?}", compiled.diagnostics));
    let web = runtime.services.get("acme-web@api").unwrap();
    let cell = dns.cell("rebind.attacker.test", 80);
    let addrs = |list: &[&str]| -> Arc<Vec<SocketAddr>> {
        Arc::new(list.iter().map(|a| a.parse().unwrap()).collect())
    };
    // A name that resolves to loopback and the metadata service: nothing to connect to.
    cell.store(addrs(&["127.0.0.1:80", "169.254.169.254:80", "[::1]:80"]));
    assert_eq!(members_of(web), Vec::<String>::new());
    // It re-resolves to a public address: that one is used, the private one is not.
    cell.store(addrs(&["10.0.0.7:80", "8.8.8.8:80"]));
    assert_eq!(members_of(web), ["8.8.8.8:80"]);
    // And rebinds to loopback again.
    cell.store(addrs(&["127.0.0.1:80"]));
    assert_eq!(members_of(web), Vec::<String>::new());

    // SRV targets are checked the same way.
    let srv = runtime.services.get("acme-srv@api").unwrap();
    let target = |ip: &str| SrvTarget {
        priority: 10,
        weight: 1,
        host: "t.attacker.test".into(),
        addr: format!("{ip}:80").parse().unwrap(),
    };
    dns.srv_cell("_http._tcp.attacker.test")
        .store(Arc::new(vec![target("169.254.169.254"), target("1.1.1.1")]));
    assert_eq!(members_of(srv), ["1.1.1.1:80"]);

    // With `backend_networks`, exactly those networks.
    let lab = runtime.services.get("lab-db@api").unwrap();
    assert_eq!(members_of(lab), ["10.0.0.5:5432"]);

    // A service outside every tenant is not checked.
    let internal = runtime.services.get("internal").unwrap();
    dns.cell("app.internal.test", 8080)
        .store(addrs(&["127.0.0.1:8080"]));
    assert_eq!(members_of(internal), ["127.0.0.1:8080"]);
}

/// L1 of the tenants review: a tenant's route shadowed by an administrator's catch-all is told
/// that another route comes first, without that route's or the listener's name.
#[test]
fn a_shadowed_tenant_route_is_not_told_whose_route_wins() {
    let file = rdock_config::load_str(
        r#"
listeners:
  edge-secret: { address: ":8080" }
defaults: { listeners: [edge-secret], tls: off }
tenants:
  acme: { hosts: [acme.example.com] }
routes:
  admin-catchall: { match: "PathPrefix(`/`)", service: internal, priority: 1000 }
services:
  internal:
    backends: [{ address: "app.internal.test:8080" }]
"#,
        rdock_config::Format::Yaml,
    )
    .unwrap()
    .config;
    let fragment: rdock_config::merge::Fragment = serde_json::from_value(serde_json::json!({
        "routes": { "acme-web": { "match": "Host(`acme.example.com`)", "service": "acme-svc", "priority": 1 } },
        "services": { "acme-svc": { "backends": [{ "address": "app.example.net:80" }] } }
    }))
    .unwrap();
    let snapshot = rdock_config::merge::Snapshot {
        provider: "api".into(),
        fragment,
        diagnostics: Vec::new(),
        revision: None,
    };
    let merged =
        rdock_config::merge::assemble(&file, &[&snapshot], &std::collections::BTreeSet::new());
    let dns = Dns::default();
    let backends = rdock_balancer::Registry::default();
    let cloudflare = CloudflareRanges::default();
    let compiled = compile(
        &merged.config,
        &CompileEnv {
            mode: Mode::Validate,
            generation: 1,
            dns: &dns,
            client: Arc::new(rdock_middleware::HttpClient::default()),
            previous: None,
            cloudflare: &cloudflare,
            backends: &backends,
            sticky_key: b"test",
            live: &rdock_observability::live::Live::default(),
            caches: None,
            plugins: &rdock_plugin_api::Registry::new(),
            metrics: None,
            quotas: None,
            abuse: None,
            shared_limits: None,
        },
    );
    let shadowed: Vec<_> = compiled
        .diagnostics
        .iter()
        .filter(|d| d.path.contains("acme-web@api"))
        .collect();
    assert!(
        shadowed
            .iter()
            .any(|d| d.message.contains("another route comes first")),
        "{:?}",
        compiled.diagnostics
    );
    for d in shadowed {
        assert!(
            !d.message.contains("admin-catchall") && !d.message.contains("edge-secret"),
            "{d:?}"
        );
    }
}

fn compile_with(config: &rdock_model::config::Config, dns: &Dns) -> rdock_proxy::runtime::Runtime {
    let backends = rdock_balancer::Registry::default();
    let cloudflare = CloudflareRanges::default();
    let compiled = compile(
        config,
        &CompileEnv {
            mode: Mode::Validate,
            generation: 1,
            dns,
            client: Arc::new(rdock_middleware::HttpClient::default()),
            previous: None,
            cloudflare: &cloudflare,
            backends: &backends,
            sticky_key: b"test",
            live: &rdock_observability::live::Live::default(),
            caches: None,
            plugins: &rdock_plugin_api::Registry::new(),
            metrics: None,
            quotas: None,
            abuse: None,
            shared_limits: None,
        },
    );
    compiled
        .runtime
        .ok_or_else(|| format!("{:?}", compiled.diagnostics))
        .unwrap()
}

#[test]
fn label_services_never_reach_the_machine_through_a_name() {
    let base = r#"
listeners:
  web: { address: ":8080" }
defaults: { listeners: [web], tls: off }
"#;
    let snapshots = [
        provider_service("docker", "rebind", "127.0.0.1.nip.io:80"),
        // A host-network container's backend is `host_address`, 127.0.0.1 by default.
        provider_service("docker", "host-net", "127.0.0.1:8080"),
        provider_service("docker", "app", "172.18.0.5:80"),
        provider_service("swarm", "meta", "metadata.google.internal:80"),
    ];
    let refs: Vec<&rdock_config::merge::Snapshot> = snapshots.iter().collect();
    let addrs = |list: &[&str]| -> Arc<Vec<SocketAddr>> {
        Arc::new(list.iter().map(|a| a.parse().unwrap()).collect())
    };
    for (allow, extra) in [
        (false, ""),
        (
            true,
            "providers:\n  docker: { allow_local_backends: true }\n  swarm: { allow_local_backends: true }\n",
        ),
    ] {
        let file = rdock_config::load_str(&format!("{base}{extra}"), rdock_config::Format::Yaml)
            .unwrap()
            .config;
        let merged =
            rdock_config::merge::assemble(&file, &refs, &std::collections::BTreeSet::new());
        assert!(merged.errors.is_empty(), "{merged:?}");
        let dns = Dns::default();
        let runtime = compile_with(&merged.config, &dns);
        let rebind = runtime.services.get("rebind@docker").unwrap();
        dns.cell("127.0.0.1.nip.io", 80)
            .store(addrs(&["127.0.0.1:80", "[::1]:80", "0.0.0.0:80"]));
        if allow {
            assert_eq!(members_of(rebind).len(), 3, "allow_local_backends opts out");
        } else {
            assert_eq!(members_of(rebind), Vec::<String>::new());
        }
        // Private networks, where containers are, stay reachable.
        dns.cell("127.0.0.1.nip.io", 80)
            .store(addrs(&["127.0.0.1:80", "10.0.3.4:80"]));
        assert!(members_of(rebind).contains(&"10.0.3.4:80".to_owned()));
        let meta = runtime.services.get("meta@swarm").unwrap();
        dns.cell("metadata.google.internal", 80)
            .store(addrs(&["169.254.169.254:80"]));
        assert_eq!(members_of(meta).is_empty(), !allow);
        // Literals are the provider's own: a container address and `host_address`.
        assert_eq!(
            members_of(runtime.services.get("host-net@docker").unwrap()),
            ["127.0.0.1:8080"]
        );
        assert_eq!(
            members_of(runtime.services.get("app@docker").unwrap()),
            ["172.18.0.5:80"]
        );
    }
}
