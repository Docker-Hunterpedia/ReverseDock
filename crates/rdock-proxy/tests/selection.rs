//! Backend selection with priority tiers, spill, locality, slow start and Peak-EWMA (ADR-0031),
//! on compiled configurations.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rdock_proxy::forwarded::CloudflareRanges;
use rdock_proxy::runtime::{Runtime, ServiceRuntime};
use rdock_proxy::upstream::{Dns, RequestKey, select};
use rdock_proxy::{CompileEnv, Mode, compile};

fn runtime(yaml: &str, registry: &rdock_balancer::Registry) -> Runtime {
    let config = rdock_config::load_str(yaml, rdock_config::Format::Yaml)
        .unwrap()
        .config;
    let errors: Vec<_> = config
        .validate()
        .into_iter()
        .filter(rdock_model::Diagnostic::is_error)
        .collect();
    assert!(errors.is_empty(), "{errors:?}");
    compile(
        &config,
        &CompileEnv {
            mode: Mode::Run,
            generation: 1,
            dns: &Dns::default(),
            client: Arc::new(rdock_middleware::HttpClient::default()),
            previous: None,
            cloudflare: &CloudflareRanges::default(),
            backends: registry,
            sticky_key: b"test",
            live: &rdock_observability::live::Live::default(),
            caches: None,
            plugins: &rdock_plugin_api::Registry::new(),
            metrics: None,
            quotas: None,
            abuse: None,
        },
    )
    .runtime
    .expect("compiles")
}

fn config(backends: &str, extra: &str) -> String {
    format!(
        r#"
listeners:
  web: {{ address: ":8080" }}
defaults: {{ listeners: [web], tls: off }}
routes:
  app: {{ match: "PathPrefix(`/`)", service: app }}
services:
  app:
    backends: [{backends}]
{extra}
"#
    )
}

fn app(runtime: &Runtime) -> Arc<ServiceRuntime> {
    runtime.services.get("app").unwrap().clone()
}

/// Picks per backend address over `n` selections.
fn picks(service: &ServiceRuntime, n: usize) -> HashMap<String, usize> {
    let mut counts = HashMap::new();
    for _ in 0..n {
        let selected = select(service, RequestKey::default()).expect("a backend");
        *counts.entry(selected.member.id.clone()).or_insert(0) += 1;
    }
    counts
}

fn state(service: &ServiceRuntime, id: &str) -> Arc<rdock_balancer::BackendState> {
    service
        .members()
        .iter()
        .find(|m| m.id == id)
        .unwrap()
        .state
        .clone()
}

const A: &str = "10.0.0.1:80";
const B: &str = "10.0.0.2:80";
const C: &str = "10.0.0.3:80";
const D: &str = "10.0.0.4:80";
const E: &str = "10.0.0.5:80";
const F: &str = "10.0.0.6:80";

#[test]
fn strict_tiers_fail_over_in_order_and_hand_back() {
    let registry = rdock_balancer::Registry::default();
    let rt = runtime(
        &config(
            &format!(
                r#"{{ address: "{A}" }}, {{ address: "{B}", priority: 1 }}, {{ address: "{C}", priority: 2 }}, {{ address: "{D}", backup: true }}"#
            ),
            "",
        ),
        &registry,
    );
    let service = app(&rt);
    assert_eq!(
        picks(&service, 50).keys().collect::<Vec<_>>(),
        [&A.to_owned()]
    );
    state(&service, A).set_drained(true);
    let tier1 = picks(&service, 100);
    assert_eq!(tier1.len(), 2, "B and the backup D share tier 1: {tier1:?}");
    assert!(tier1.contains_key(B) && tier1.contains_key(D));
    state(&service, B).set_drained(true);
    state(&service, D).pause(Instant::now() + Duration::from_secs(60));
    assert_eq!(
        picks(&service, 20).keys().collect::<Vec<_>>(),
        [&C.to_owned()]
    );
    state(&service, A).set_drained(false);
    assert_eq!(
        picks(&service, 20).keys().collect::<Vec<_>>(),
        [&A.to_owned()],
        "tier 0 takes everything back"
    );
}

#[test]
fn spill_shares_traffic_by_envoys_formula() {
    let registry = rdock_balancer::Registry::default();
    let rt = runtime(
        &config(
            &format!(
                r#"{{ address: "{A}" }}, {{ address: "{B}" }}, {{ address: "{C}" }}, {{ address: "{D}" }}, {{ address: "{E}", priority: 1 }}, {{ address: "{F}", priority: 1 }}"#
            ),
            "    failover: spill",
        ),
        &registry,
    );
    let service = app(&rt);
    let healthy = picks(&service, 2_000);
    assert!(
        !healthy.contains_key(E) && !healthy.contains_key(F),
        "{healthy:?}"
    );
    // Half of tier 0 is out: 50 % × 1.4 = 70 % stays, 30 % spills.
    let later = Instant::now() + Duration::from_secs(3_600);
    state(&service, A).pause(later);
    state(&service, B).pause(later);
    let n = 20_000;
    let counts = picks(&service, n);
    let tier1 = counts.get(E).unwrap_or(&0) + counts.get(F).unwrap_or(&0);
    #[allow(clippy::cast_precision_loss)]
    let share = tier1 as f64 / n as f64;
    assert!(
        (share - 0.30).abs() < 0.02,
        "tier 1 share {share}: {counts:?}"
    );
    assert!(!counts.contains_key(A) && !counts.contains_key(B));
}

#[test]
fn locality_prefers_the_own_zone_and_falls_back() {
    let registry = rdock_balancer::Registry::default();
    let backends = format!(
        r#"{{ address: "{A}", zone: z1 }}, {{ address: "{B}", zone: z2 }}, {{ address: "{C}", zone: z2 }}"#
    );
    let rt = runtime(
        &format!(
            "{}locality: {{ zone: z1, mode: prefer }}\n",
            config(&backends, "")
        ),
        &registry,
    );
    let service = app(&rt);
    assert_eq!(
        picks(&service, 30).keys().collect::<Vec<_>>(),
        [&A.to_owned()]
    );
    state(&service, A).pause(Instant::now() + Duration::from_secs(60));
    let others = picks(&service, 60);
    assert_eq!(others.len(), 2, "zone z1 is down: every zone: {others:?}");
    // A service can turn the preference off.
    let registry = rdock_balancer::Registry::default();
    let rt = runtime(
        &format!(
            "{}locality: {{ zone: z1, mode: prefer }}\n",
            config(&backends, "    locality: { mode: off }")
        ),
        &registry,
    );
    assert_eq!(picks(&app(&rt), 60).len(), 3);
}

#[test]
fn topology_hints_decide_which_backends_are_local() {
    let registry = rdock_balancer::Registry::default();
    // Kubernetes may assign an endpoint in z2 to proxies in z1 (`hints.forZones`).
    let backends = format!(
        r#"{{ address: "{A}", zone: z1, for_zones: [z2] }}, {{ address: "{B}", zone: z2, for_zones: [z1] }}"#
    );
    let rt = runtime(
        &format!(
            "{}locality: {{ zone: z1, mode: prefer }}\n",
            config(&backends, "")
        ),
        &registry,
    );
    assert_eq!(
        picks(&app(&rt), 30).keys().collect::<Vec<_>>(),
        [&B.to_owned()]
    );
}

#[test]
fn retries_leave_the_zone_when_its_backends_were_tried() {
    let registry = rdock_balancer::Registry::default();
    let backends = format!(r#"{{ address: "{A}", zone: z1 }}, {{ address: "{B}", zone: z2 }}"#);
    let rt = runtime(
        &format!(
            "{}locality: {{ zone: z1, mode: prefer }}\n",
            config(&backends, "")
        ),
        &registry,
    );
    let tried = vec![A.to_owned()];
    let key = RequestKey {
        tried: &tried,
        ..RequestKey::default()
    };
    assert_eq!(select(&app(&rt), key).unwrap().member.id, B);
}

#[test]
fn a_joining_backend_ramps_up_only_into_a_settled_pool() {
    let registry = rdock_balancer::Registry::default();
    let slow = "    health: { slow_start: { window: 10m, on: [recovery, join] } }";
    let first = runtime(
        &config(
            &format!(r#"{{ address: "{A}" }}, {{ address: "{B}" }}"#),
            slow,
        ),
        &registry,
    );
    let service = app(&first);
    let counts = picks(&service, 2_000);
    assert_eq!(
        counts.get(A),
        Some(&1_000),
        "a new pool starts at full weight"
    );
    // A reload adds C while the first generation is alive: C joins at 10 % of its weight.
    let second = runtime(
        &config(
            &format!(r#"{{ address: "{A}" }}, {{ address: "{B}" }}, {{ address: "{C}" }}"#),
            slow,
        ),
        &registry,
    );
    let counts = picks(&app(&second), 2_100);
    let c = *counts.get(C).unwrap_or(&0);
    assert!((90..=110).contains(&c), "C ramps from 10 %: {counts:?}");
    drop(first);
}

#[test]
fn sticky_sessions_win_over_peak_ewma() {
    let registry = rdock_balancer::Registry::default();
    let rt = runtime(
        &config(
            &format!(r#"{{ address: "{A}" }}, {{ address: "{B}" }}"#),
            "    load_balancer: { policy: peak_ewma }\n    sticky: { cookie: { name: srv } }",
        ),
        &registry,
    );
    let service = app(&rt);
    let now = Instant::now();
    let decay = Duration::from_secs(10);
    state(&service, A)
        .latency()
        .observe(Duration::from_millis(500), decay, now);
    state(&service, B)
        .latency()
        .observe(Duration::from_millis(1), decay, now);
    let counts = picks(&service, 50);
    assert_eq!(
        counts.get(B),
        Some(&50),
        "the fast backend wins: {counts:?}"
    );
    let token = service
        .members()
        .iter()
        .find(|m| m.id == A)
        .unwrap()
        .sticky
        .clone()
        .unwrap();
    let mut request = pingora::http::RequestHeader::build("GET", b"/", None).unwrap();
    request
        .insert_header("cookie", format!("srv={token}"))
        .unwrap();
    let key = RequestKey {
        request: Some(&request),
        ..RequestKey::default()
    };
    for _ in 0..10 {
        assert_eq!(
            select(&service, key).unwrap().member.id,
            A,
            "the cookie wins"
        );
    }
}

#[test]
fn peak_ewma_respects_weights_and_avoids_unhealthy_backends() {
    let registry = rdock_balancer::Registry::default();
    let rt = runtime(
        &config(
            &format!(
                r#"{{ address: "{A}", weight: 4 }}, {{ address: "{B}" }}, {{ address: "{C}" }}"#
            ),
            "    load_balancer: { policy: peak_ewma, decay: 10s }",
        ),
        &registry,
    );
    let service = app(&rt);
    let now = Instant::now();
    let decay = Duration::from_secs(10);
    for id in [A, B, C] {
        state(&service, id)
            .latency()
            .observe(Duration::from_millis(10), decay, now);
    }
    let counts = picks(&service, 300);
    // Equal latency and load: A's cost is a quarter of the others', so it wins every
    // comparison it is drawn into (two of three pairs).
    let a = *counts.get(A).unwrap_or(&0);
    assert!(a > 150, "{counts:?}");
    state(&service, A).pause(now + Duration::from_secs(60));
    let counts = picks(&service, 50);
    assert!(
        !counts.contains_key(A),
        "health filters before the pick: {counts:?}"
    );
}
