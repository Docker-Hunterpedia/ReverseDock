//! SRV backends become members by priority and weight (M-LB-10, RFC 2782).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use rdock_proxy::forwarded::CloudflareRanges;
use rdock_proxy::upstream::{Dns, SrvTarget};
use rdock_proxy::{CompileEnv, Mode, compile};

#[test]
fn srv_targets_become_members_and_higher_priorities_backups() {
    let yaml = r#"
listeners:
  web: { address: ":8080" }
defaults: { listeners: [web], tls: off }
routes:
  app: { match: "PathPrefix(`/`)", service: app }
services:
  app:
    backends: [{ address: "srv://_http._tcp.api.example.com", weight: 2 }]
"#;
    let config = rdock_config::load_str(yaml, rdock_config::Format::Yaml)
        .unwrap()
        .config;
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
        },
    );
    let runtime = compiled.runtime.expect("compiles");
    let service = runtime.services.get("app").unwrap();
    assert!(
        service.members().is_empty(),
        "nothing until the SRV name resolves"
    );
    let target = |priority, weight, ip: &str| SrvTarget {
        priority,
        weight,
        host: format!("{ip}.host"),
        addr: format!("{ip}:9000").parse().unwrap(),
    };
    dns.srv_cell("_http._tcp.api.example.com")
        .store(Arc::new(vec![
            target(10, 3, "10.0.0.1"),
            target(10, 0, "10.0.0.2"),
            target(20, 5, "10.0.0.3"),
        ]));
    let members = service.members();
    let summary: Vec<(String, u32, bool)> = members
        .iter()
        .map(|m| (m.id.clone(), m.weight, m.backup))
        .collect();
    assert_eq!(
        summary,
        vec![
            ("10.0.0.1:9000".into(), 6, false),
            ("10.0.0.2:9000".into(), 2, false),
            ("10.0.0.3:9000".into(), 10, true),
        ],
        "weight = backend weight × SRV weight (0 counts as 1); priority 20 is a backup"
    );
}
