//! Proof 2 in one process, without Docker (ADR-0031): three certificate managers that need the
//! same names at the same moment share one cluster store and one ACME CA (the testkit's fake,
//! which counts orders and validates HTTP-01 against *every* instance). Asserted at the CA:
//! exactly one order per name, one renewal per name, and with the lease holder killed in the
//! middle of an order the successor finishes the journalled order instead of ordering again.
//!
//! Run for the shared-directory store (best effort) and the memory store (fencing enforced, as
//! on the control plane's store).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rdock_acme::{ClusterAcme, Manager, Plan, Services};
use rdock_cluster::{ClusterStore, DirStore, MemoryStore};
use rdock_model::acme::{Acme, CaRef, Challenge};
use rdock_testkit::fake_acme::FakeAcme;
use rdock_tls::{CertIndex, CertRequest, SniResolver};

const NAMES: [&str; 2] = ["a.example.com", "b.example.com"];

#[derive(Debug)]
struct NoDns;

impl rdock_acme::dns::DnsProviders for NoDns {
    fn build(
        &self,
        _: &rdock_model::acme::DnsProvider,
    ) -> Result<Arc<dyn rdock_acme::dns::DnsSolver>, rdock_acme::dns::DnsError> {
        Err(rdock_acme::dns::DnsError("no DNS in this test".into()))
    }
}

/// One instance: its own runtime (so it can be killed like a process), resolver and
/// challenge listener.
struct Instance {
    name: String,
    runtime: Option<tokio::runtime::Runtime>,
    resolver: Arc<SniResolver>,
    http: SocketAddr,
    manager: Option<Manager>,
}

impl Instance {
    fn start(name: &str, store: Arc<dyn ClusterStore>, data: &std::path::Path) -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let resolver = Arc::new(SniResolver::new(CertIndex::build(&[], None)));
        let challenges = resolver.challenges();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let http = listener.local_addr().unwrap();
        let served = challenges.clone();
        runtime.spawn(async move {
            let listener = tokio::net::TcpListener::from_std(listener).unwrap();
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    continue;
                };
                let served = served.clone();
                tokio::spawn(async move {
                    let service =
                        service_fn(move |request: http::Request<hyper::body::Incoming>| {
                            let answer = served.http01_answer(request.uri().path());
                            async move {
                                let response = match answer {
                                    Some(answer) => http::Response::new(Full::new(Bytes::from(
                                        answer.to_string(),
                                    ))),
                                    None => http::Response::builder()
                                        .status(404)
                                        .body(Full::new(Bytes::new()))
                                        .unwrap(),
                                };
                                Ok::<_, std::convert::Infallible>(response)
                            }
                        });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(tcp), service)
                        .await;
                });
            }
        });
        let metrics = rdock_observability::Metrics::new("test", "test").unwrap();
        let services = Services {
            default_storage: data.join(name),
            resolver: resolver.clone(),
            challenges,
            metrics: metrics.clone(),
            dns: Arc::new(NoDns),
            cluster: Some(ClusterAcme {
                store,
                instance: name.to_owned(),
                lease_ttl: Duration::from_secs(3),
                barrier_timeout: Duration::from_secs(5),
                metrics: Some(metrics),
            }),
        };
        let manager = {
            let _context = runtime.enter();
            Manager::spawn(services)
        };
        Self {
            name: name.to_owned(),
            runtime: Some(runtime),
            resolver,
            http,
            manager: Some(manager),
        }
    }

    fn plan(&self, plan: &Plan) {
        if let Some(manager) = &self.manager {
            manager.update(plan.clone());
        }
    }

    /// Ends the instance abruptly: every task stops where it is, no lease is released.
    fn kill(&mut self) {
        self.manager = None;
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }

    fn serving(&self, name: &str) -> Option<Vec<u8>> {
        self.resolver
            .lookup(Some(name))
            .and_then(|k| k.cert.first().map(|c| c.as_ref().to_vec()))
    }
}

impl Drop for Instance {
    fn drop(&mut self) {
        self.kill();
    }
}

fn plan(fake: &FakeAcme, root: &std::path::Path) -> Plan {
    Plan {
        acme: Acme {
            ca: CaRef::Directory(fake.directory().parse().unwrap()),
            ca_root: Some(root.to_owned()),
            challenges: vec![Challenge::Http01],
            ..Acme::default()
        },
        requests: NAMES
            .iter()
            .map(|n| CertRequest {
                names: vec![(*n).to_owned()],
                dns_provider: None,
            })
            .collect(),
        http01: true,
        tls_alpn01: false,
    }
}

/// Waits until every live instance serves one and the same certificate for each name, other
/// than `before` (when given); returns it per name.
async fn converged(
    instances: &[&Instance],
    before: Option<&BTreeMap<String, Vec<u8>>>,
    within: Duration,
) -> BTreeMap<String, Vec<u8>> {
    let deadline = Instant::now() + within;
    loop {
        let mut agreed = BTreeMap::new();
        for name in NAMES {
            let served: Vec<Option<Vec<u8>>> = instances.iter().map(|i| i.serving(name)).collect();
            if let Some(Some(first)) = served.first()
                && served.iter().all(|s| s.as_ref() == Some(first))
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
            "instances did not converge: {:?}",
            instances
                .iter()
                .map(|i| (i.name.clone(), NAMES.map(|n| i.serving(n).is_some())))
                .collect::<Vec<_>>()
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

fn counts(n: usize) -> BTreeMap<String, usize> {
    NAMES.iter().map(|name| ((*name).to_owned(), n)).collect()
}

async fn one_order_per_name_and_one_renewal(store: impl Fn() -> Arc<dyn ClusterStore>) {
    let dir = tempfile::tempdir().unwrap();
    let mut instances: Vec<Instance> = ["edge-1", "edge-2", "edge-3"]
        .iter()
        .map(|n| Instance::start(n, store(), dir.path()))
        .collect();
    let fake = FakeAcme::start(instances.iter().map(|i| i.http).collect(), Vec::new()).await;
    // Short-lived certificates: renewal (a third of the lifetime before expiry) comes within
    // the test.
    fake.set_lifetime(Duration::from_secs(45));
    let root = dir.path().join("root.pem");
    std::fs::write(&root, fake.root_pem()).unwrap();
    let plan = plan(&fake, &root);
    for instance in &instances {
        instance.plan(&plan);
    }
    let views: Vec<&Instance> = instances.iter().collect();
    let first = converged(&views, None, Duration::from_secs(60)).await;
    assert_eq!(fake.orders_created(), counts(1), "{:?}", fake.failures());
    assert_eq!(fake.issued(), counts(1));
    // Renewal 30 s after issuance: once more per name, by one instance.
    let renewed = converged(&views, Some(&first), Duration::from_secs(60)).await;
    assert_ne!(renewed, first);
    assert_eq!(fake.orders_created(), counts(2), "{:?}", fake.failures());
    assert_eq!(fake.issued(), counts(2));
    assert!(fake.failures().is_empty(), "{:?}", fake.failures());
    for instance in &mut instances {
        instance.kill();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_shared_directory_issues_once_per_name() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_owned();
    one_order_per_name_and_one_renewal(move || Arc::new(DirStore::shared(path.clone()))).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_fenced_store_issues_once_per_name() {
    let store = MemoryStore::new();
    one_order_per_name_and_one_renewal(move || Arc::new(store.clone())).await;
}

/// The lease holder dies after it created and journalled the order; the next holder resumes
/// that order: still one order per name at the CA.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_successor_finishes_the_journalled_order() {
    let dir = tempfile::tempdir().unwrap();
    let store: Arc<dyn ClusterStore> = Arc::new(DirStore::shared(dir.path().join("store")));
    let mut instances: Vec<Instance> = ["edge-1", "edge-2", "edge-3"]
        .iter()
        .map(|n| Instance::start(n, store.clone(), dir.path()))
        .collect();
    let fake = FakeAcme::start(instances.iter().map(|i| i.http).collect(), Vec::new()).await;
    // Validation waits long enough to kill the instance that ordered.
    fake.set_validation_delay(Duration::from_secs(4));
    let root = dir.path().join("root.pem");
    std::fs::write(&root, fake.root_pem()).unwrap();
    let plan = plan(&fake, &root);
    for instance in &instances {
        instance.plan(&plan);
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    let holder = loop {
        if fake.orders_created().len() == NAMES.len()
            && let Some(lease) = store.lease("cert/a.example.com").await.unwrap()
            && store
                .get("orders/a.example.com.json")
                .await
                .unwrap()
                .is_some()
        {
            break lease.holder;
        }
        assert!(Instant::now() < deadline, "no order was created");
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    let victim = instances.iter().position(|i| i.name == holder).unwrap();
    instances[victim].kill();
    let survivors: Vec<SocketAddr> = instances
        .iter()
        .filter(|i| i.runtime.is_some())
        .map(|i| i.http)
        .collect();
    fake.set_targets(survivors, Vec::new());
    let views: Vec<&Instance> = instances.iter().filter(|i| i.runtime.is_some()).collect();
    converged(&views, None, Duration::from_secs(60)).await;
    // The journal rule: a successor resumes the journalled order; a new order is created only
    // when the CA reports the journalled one invalid or unknown. Here it was neither.
    assert_eq!(fake.orders_created(), counts(1), "{:?}", fake.failures());
    assert_eq!(fake.issued(), counts(1));
    assert!(
        store
            .get("orders/a.example.com.json")
            .await
            .unwrap()
            .is_none()
    );
}
