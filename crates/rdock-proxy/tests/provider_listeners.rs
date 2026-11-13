//! Listeners and certificates contributed by the Kubernetes provider (ADR-0029): each
//! listener presents its own certificates, two listeners can present different certificates
//! for the same host name, and provider listeners take no part in the automatic
//! HTTP-to-HTTPS redirect.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rdock_config::merge::{Fragment, Snapshot, assemble};
use rdock_proxy::forwarded::CloudflareRanges;
use rdock_proxy::upstream::Dns;
use rdock_proxy::{CompileEnv, DataPlane, Mode, Runtime, compile};
use rdock_testkit::certs::{Issued, TestCa};
use rdock_testkit::{client, free_port};
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;

struct Setup {
    runtime: Runtime,
    first: Issued,
    second: Issued,
    shared: Issued,
    ports: [u16; 4],
    ca: TestCa,
    _dir: tempfile::TempDir,
}

/// A file configuration with `web` and `websecure`, merged with a Kubernetes fragment that
/// has two HTTPS listeners (one certificate each, both for `app.test`) and a plain one.
fn setup() -> Setup {
    let ca = TestCa::new();
    let dir = tempfile::tempdir().unwrap();
    let shared = ca.issue(dir.path(), "shared", &["app.test"]);
    let first = ca.issue(dir.path(), "first", &["app.test", "only-first.test"]);
    let second = ca.issue(dir.path(), "second", &["app.test"]);
    let ports = [free_port(), free_port(), free_port(), free_port()];
    let [web, websecure, gw_a, gw_b] = ports;
    let file = format!(
        r#"
acme: false
listeners:
  web: {{ address: "127.0.0.1:{web}" }}
  websecure: {{ address: "127.0.0.1:{websecure}", tls: {{}} }}
certificates:
  shared: {{ cert_file: "{}", key_file: "{}" }}
routes:
  site: {{ match: "Host(`app.test`)", service: app }}
services:
  app: {{ backends: [{{ address: "127.0.0.1:9" }}] }}
"#,
        shared.cert.display(),
        shared.key.display(),
    );
    let base = rdock_config::load_str(&file, rdock_config::Format::Yaml).unwrap();
    assert!(!base.has_errors(), "{:?}", base.diagnostics);
    let fragment: Fragment = serde_json::from_value(serde_json::json!({
        "listeners": {
            "gw-a": { "address": format!("127.0.0.1:{gw_a}"), "tls": { "certificates": ["first"] } },
            "gw-b": { "address": format!("127.0.0.1:{gw_b}"), "tls": { "certificates": ["second"] } },
            "gw-http": { "address": format!("127.0.0.1:{}", free_port()) }
        },
        "certificates": {
            "first": { "cert_file": first.cert, "key_file": first.key },
            "second": { "cert_file": second.cert, "key_file": second.key }
        },
        "routes": {
            // `tls: auto` (the default) with ACME off: the listeners' own certificates serve.
            "app": { "match": "Host(`app.test`)", "service": "app", "listeners": ["gw-a", "gw-b"] },
            "plain": { "match": "Host(`app.test`)", "service": "app", "listeners": ["gw-http"], "tls": "off" }
        },
        "services": { "app": { "backends": [{ "address": "127.0.0.1:9" }] } }
    }))
    .unwrap();
    let snapshot = Snapshot {
        provider: "kubernetes".to_owned(),
        fragment,
        diagnostics: Vec::new(),
        revision: None,
    };
    let merged = assemble(&base.config, &[&snapshot], &BTreeSet::new());
    assert_eq!(merged.errors, Vec::new());
    assert_eq!(merged.skipped, Vec::new());
    let compiled = compile(
        &merged.config,
        &CompileEnv {
            mode: Mode::Run,
            generation: 1,
            dns: &Dns::default(),
            client: Arc::new(rdock_middleware::HttpClient::default()),
            previous: None,
            cloudflare: &CloudflareRanges::default(),
            backends: &rdock_balancer::Registry::default(),
            sticky_key: b"test",
            live: &rdock_observability::live::Live::default(),
            caches: None,
            plugins: &rdock_plugin_api::Registry::new(),
            metrics: None,
            quotas: None,
        },
    );
    let errors: Vec<_> = compiled
        .diagnostics
        .iter()
        .filter(|d| d.is_error())
        .collect();
    assert!(errors.is_empty(), "{errors:?}");
    Setup {
        runtime: compiled.runtime.unwrap(),
        first,
        second,
        shared,
        ports,
        ca,
        _dir: dir,
    }
}

fn der(issued: &Issued) -> CertificateDer<'static> {
    CertificateDer::from_pem_slice(issued.cert_pem.as_bytes()).unwrap()
}

#[test]
fn each_listener_indexes_its_own_certificates() {
    let s = setup();
    let scoped = &s.runtime.listener_certificates;
    assert_eq!(
        scoped.keys().map(String::as_str).collect::<BTreeSet<_>>(),
        BTreeSet::from(["gw-a@kubernetes", "gw-b@kubernetes"])
    );
    let leaf = |key: Arc<rustls::sign::CertifiedKey>| key.cert[0].clone();
    let a = &scoped["gw-a@kubernetes"];
    let b = &scoped["gw-b@kubernetes"];
    assert_eq!(leaf(a.lookup(Some("app.test")).unwrap()), der(&s.first));
    assert_eq!(leaf(b.lookup(Some("app.test")).unwrap()), der(&s.second));
    // The shared index holds only the file's certificate.
    let shared = &s.runtime.certificates;
    assert_eq!(
        leaf(shared.lookup(Some("app.test")).unwrap()),
        der(&s.shared)
    );
    assert!(!shared.covers("only-first.test"));
}

#[test]
fn provider_listeners_take_no_part_in_the_https_redirect() {
    let s = setup();
    let listeners = &s.runtime.listeners;
    let web = listeners["web"].https_redirect.as_ref().unwrap();
    // `gw-a@kubernetes` sorts before `websecure`, but the redirect targets the file's listener.
    assert_eq!(web.port, s.ports[1]);
    assert!(listeners["gw-http@kubernetes"].https_redirect.is_none());
}

#[tokio::test]
async fn two_listeners_present_different_certificates_for_one_host() {
    let s = setup();
    let metrics = rdock_observability::Metrics::new("test", "test").unwrap();
    let plane = DataPlane::new(metrics, Runtime::empty());
    plane
        .apply(s.runtime, Duration::from_millis(10))
        .await
        .unwrap();
    let config = s.ca.client_config(&[b"http/1.1"]);
    let served = |port: u16| {
        let config = config.clone();
        async move {
            let addr = SocketAddr::from(([127, 0, 0, 1], port));
            let stream = client::tls_connect(addr, "app.test", config).await.unwrap();
            stream.get_ref().1.peer_certificates().unwrap()[0].clone()
        }
    };
    let [_, websecure, gw_a, gw_b] = s.ports;
    assert_eq!(served(gw_a).await, der(&s.first));
    assert_eq!(served(gw_b).await, der(&s.second));
    assert_eq!(served(websecure).await, der(&s.shared));
}
