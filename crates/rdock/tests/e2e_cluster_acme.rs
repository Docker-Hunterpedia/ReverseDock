//! Automatic certificates against the testkit's fake ACME CA, without Docker (ADR-0020,
//! ADR-0031): a single instance (the behaviour of every earlier version: HTTP-01, TLS-ALPN-01,
//! reuse after a restart), and proof 2 with three `rdock run` processes sharing a directory
//! store: exactly one order per name counted at the CA, one renewal, answers present on every
//! instance before validation (the fake CA asks every instance), and a lease holder killed in
//! the middle of an order whose successor finishes the journalled order.
//!
//! The same proof against Pebble and the control plane's store is in `e2e_cluster.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rdock_testkit::backend::Backend;
use rdock_testkit::client::{self, get};
use rdock_testkit::fake_acme::FakeAcme;
use rdock_testkit::free_port;
use rdock_testkit::rdock::Rdock;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;

const RDOCK: &str = env!("CARGO_BIN_EXE_rdock");
const NAMES: [&str; 2] = ["a.example.com", "b.example.com"];

fn trust(pem: &str) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(pem.as_bytes()) {
        roots.add(cert.unwrap()).unwrap();
    }
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}

/// The leaf served for `host` after a verified handshake, if any.
async fn served(
    addr: SocketAddr,
    host: &str,
    config: &Arc<rustls::ClientConfig>,
) -> Option<Vec<u8>> {
    let stream = client::tls_connect(addr, host, config.clone()).await.ok()?;
    let leaf = stream.get_ref().1.peer_certificates()?.first()?.clone();
    Some(leaf.as_ref().to_vec())
}

struct Ports {
    http: u16,
    https: u16,
}

impl Ports {
    fn new() -> Self {
        Self {
            http: free_port(),
            https: free_port(),
        }
    }

    fn https(&self) -> SocketAddr {
        format!("127.0.0.1:{}", self.https).parse().unwrap()
    }

    fn http(&self) -> SocketAddr {
        format!("127.0.0.1:{}", self.http).parse().unwrap()
    }
}

fn config(
    fake: &FakeAcme,
    root: &Path,
    ports: &Ports,
    challenges: &str,
    backend: SocketAddr,
    cluster: &str,
) -> String {
    let routes: String = NAMES
        .iter()
        .enumerate()
        .fold(String::new(), |mut out, (i, n)| {
            use std::fmt::Write as _;
            let _ = writeln!(out, "  r{i}: {{ match: \"Host(`{n}`)\", service: app }}");
            out
        });
    format!(
        r#"listeners:
  web: {{ address: "127.0.0.1:{http}" }}
  websecure: {{ address: "127.0.0.1:{https}", tls: {{}} }}
acme:
  ca: "{directory}"
  ca_root: "{root}"
  challenges: [{challenges}]
routes:
{routes}services:
  app: {{ backends: [{{ address: "{backend}" }}] }}
{cluster}"#,
        http = ports.http,
        https = ports.https,
        directory = fake.directory(),
        root = root.display(),
    )
}

/// Waits until every instance serves one and the same verified certificate for each name,
/// other than `before` when given.
async fn converged(
    instances: &[(&Rdock, SocketAddr)],
    trust: &Arc<rustls::ClientConfig>,
    before: Option<&BTreeMap<String, Vec<u8>>>,
    within: Duration,
) -> BTreeMap<String, Vec<u8>> {
    let deadline = Instant::now() + within;
    loop {
        let mut agreed = BTreeMap::new();
        for name in NAMES {
            let mut leaves = Vec::new();
            for (_, addr) in instances {
                leaves.push(served(*addr, name, trust).await);
            }
            if let Some(Some(first)) = leaves.first()
                && leaves.iter().all(|l| l.as_ref() == Some(first))
                && before.is_none_or(|b| b.get(name) != Some(first))
            {
                agreed.insert(name.to_owned(), first.clone());
            }
        }
        if agreed.len() == NAMES.len() {
            return agreed;
        }
        assert!(
            Instant::now() < deadline,
            "instances did not converge on one certificate per name\n{}",
            instances
                .iter()
                .map(|(r, _)| r.log())
                .collect::<Vec<_>>()
                .join("\n----\n")
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

fn counts(n: usize) -> BTreeMap<String, usize> {
    NAMES.iter().map(|name| ((*name).to_owned(), n)).collect()
}

#[tokio::test]
async fn a_single_instance_issues_serves_and_reuses_after_restart() {
    let backend = Backend::start("app").await;
    let ports = Ports::new();
    let fake = FakeAcme::start(vec![ports.http()], vec![ports.https()]).await;
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root.pem");
    std::fs::write(&root, fake.root_pem()).unwrap();
    let mut rdock = Rdock::start(
        RDOCK,
        &config(
            &fake,
            &root,
            &ports,
            "http-01, tls-alpn-01",
            backend.addr,
            "",
        ),
    );
    let trust = trust(fake.issuing_pem());
    let first = converged(
        &[(&rdock, ports.https())],
        &trust,
        None,
        Duration::from_secs(60),
    )
    .await;
    assert_eq!(fake.orders_created(), counts(1), "{:?}", fake.failures());
    let reply = client::tls(ports.https(), NAMES[0], trust.clone(), get(NAMES[0], "/")).await;
    assert_eq!(reply.status, 200, "{}", rdock.log());
    let stored = rdock.data_dir().join("acme/certs").join(NAMES[0]);
    for file in ["cert.pem", "key.pem", "meta.json"] {
        assert!(stored.join(file).exists(), "missing {file}");
    }
    let meta: serde_json::Value =
        serde_json::from_slice(&std::fs::read(stored.join("meta.json")).unwrap()).unwrap();
    assert!(
        meta["serial"].is_string() && meta["not_after"].is_i64(),
        "{meta}"
    );
    assert!(meta["chain_sha256"].is_string(), "{meta}");
    rdock.restart().unwrap();
    let again = converged(
        &[(&rdock, ports.https())],
        &trust,
        None,
        Duration::from_secs(30),
    )
    .await;
    assert_eq!(
        again, first,
        "the stored certificates are served after a restart"
    );
    assert_eq!(fake.orders_created(), counts(1));
}

#[tokio::test]
async fn a_single_instance_answers_tls_alpn01() {
    let backend = Backend::start("app").await;
    let ports = Ports::new();
    let fake = FakeAcme::start(vec![ports.http()], vec![ports.https()]).await;
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root.pem");
    std::fs::write(&root, fake.root_pem()).unwrap();
    let rdock = Rdock::start(
        RDOCK,
        &config(&fake, &root, &ports, "tls-alpn-01", backend.addr, ""),
    );
    let trust = trust(fake.issuing_pem());
    converged(
        &[(&rdock, ports.https())],
        &trust,
        None,
        Duration::from_secs(60),
    )
    .await;
    assert_eq!(fake.orders_created(), counts(1), "{:?}", fake.failures());
}

/// Three instances that share a directory store.
struct Trio {
    instances: Vec<Rdock>,
    ports: Vec<Ports>,
    fake: FakeAcme,
    store: tempfile::TempDir,
    _dir: tempfile::TempDir,
    _backend: Backend,
}

impl Trio {
    async fn start(challenges: &str, validation_delay: Option<Duration>) -> Self {
        let backend = Backend::start("app").await;
        let ports: Vec<Ports> = (0..3).map(|_| Ports::new()).collect();
        let fake = FakeAcme::start(
            ports.iter().map(Ports::http).collect(),
            ports.iter().map(Ports::https).collect(),
        )
        .await;
        if let Some(delay) = validation_delay {
            fake.set_validation_delay(delay);
        }
        let dir = tempfile::tempdir().unwrap();
        let store = tempfile::tempdir().unwrap();
        let root = dir.path().join("root.pem");
        std::fs::write(&root, fake.root_pem()).unwrap();
        let mut instances = Vec::new();
        for (i, p) in ports.iter().enumerate() {
            let cluster = format!(
                "cluster:\n  instance: edge-{i}\n  store: {{ type: directory, path: \"{}\", lease_ttl: 10s, barrier_timeout: 10s }}\n",
                store.path().display()
            );
            instances.push(Rdock::start(
                RDOCK,
                &config(&fake, &root, p, challenges, backend.addr, &cluster),
            ));
        }
        Self {
            instances,
            ports,
            fake,
            store,
            _dir: dir,
            _backend: backend,
        }
    }

    fn views(&self, alive: &[usize]) -> Vec<(&Rdock, SocketAddr)> {
        alive
            .iter()
            .map(|i| (&self.instances[*i], self.ports[*i].https()))
            .collect()
    }
}

#[tokio::test]
async fn three_instances_on_a_shared_directory_order_once_per_name_and_renew_once() {
    let trio = Trio::start("http-01", None).await;
    // Short-lived certificates, so the renewal (a third of the lifetime before expiry) comes
    // within the test: the first orders run under the default lifetime, so set it before.
    trio.fake.set_lifetime(Duration::from_secs(45));
    let trust = trust(trio.fake.issuing_pem());
    let views = trio.views(&[0, 1, 2]);
    let first = converged(&views, &trust, None, Duration::from_secs(90)).await;
    assert_eq!(
        trio.fake.orders_created(),
        counts(1),
        "{:?}",
        trio.fake.failures()
    );
    assert_eq!(trio.fake.issued(), counts(1));
    let renewed = converged(&views, &trust, Some(&first), Duration::from_secs(90)).await;
    assert_ne!(renewed, first);
    assert_eq!(
        trio.fake.orders_created(),
        counts(2),
        "{:?}",
        trio.fake.failures()
    );
    assert!(
        trio.fake.failures().is_empty(),
        "{:?}",
        trio.fake.failures()
    );
}

#[tokio::test]
async fn three_instances_replicate_tls_alpn01_answers() {
    let trio = Trio::start("tls-alpn-01", None).await;
    let trust = trust(trio.fake.issuing_pem());
    converged(
        &trio.views(&[0, 1, 2]),
        &trust,
        None,
        Duration::from_secs(90),
    )
    .await;
    assert_eq!(
        trio.fake.orders_created(),
        counts(1),
        "{:?}",
        trio.fake.failures()
    );
    assert!(
        trio.fake.failures().is_empty(),
        "{:?}",
        trio.fake.failures()
    );
}

#[tokio::test]
async fn the_lease_holder_killed_mid_order_leaves_one_order() {
    let mut trio = Trio::start("http-01", Some(Duration::from_secs(6))).await;
    let lease_file = trio.store.path().join(".leases/cert").join(NAMES[0]);
    let journal = trio
        .store
        .path()
        .join("orders")
        .join(format!("{}.json", NAMES[0]));
    let deadline = Instant::now() + Duration::from_secs(60);
    let holder = loop {
        if journal.exists()
            && let Ok(bytes) = std::fs::read(&lease_file)
            && let Ok(lease) = serde_json::from_slice::<serde_json::Value>(&bytes)
        {
            break lease["holder"].as_str().unwrap().to_owned();
        }
        assert!(Instant::now() < deadline, "no order was journalled");
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    let victim: usize = holder.trim_start_matches("edge-").parse().unwrap();
    trio.instances[victim].kill();
    let alive: Vec<usize> = (0..3).filter(|i| *i != victim).collect();
    trio.fake.set_targets(
        alive.iter().map(|i| trio.ports[*i].http()).collect(),
        alive.iter().map(|i| trio.ports[*i].https()).collect(),
    );
    let trust = trust(trio.fake.issuing_pem());
    converged(&trio.views(&alive), &trust, None, Duration::from_secs(90)).await;
    // The journal rule: the next holder resumes the journalled order; only an order the CA
    // reports invalid or unknown is replaced. So: one order per name, even here.
    assert_eq!(
        trio.fake.orders_created(),
        counts(1),
        "{:?}",
        trio.fake.failures()
    );
    assert_eq!(trio.fake.issued(), counts(1));
    assert!(!journal.exists());
    let log = alive
        .iter()
        .map(|i| trio.instances[*i].log())
        .collect::<String>();
    assert!(log.contains("resuming the journalled order"), "{log}");
}
