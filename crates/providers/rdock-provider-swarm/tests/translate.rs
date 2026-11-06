//! Swarm services and tasks into routes, from Engine API responses recorded on a single-node
//! swarm (Docker 29.9.2, 2026-11-06). No daemon needed.
//!
//! `fixtures/scale-down` holds six services: `rdfx_web` (2 replicas on `rdfx_front` and
//! `rdfx_back`, `rdock.network=rdfx_front`), `rdfx_agent` (global, Traefik labels with
//! `traefik.swarm.network`), `rdfx_dns` (`dnsrr` with `rdock.swarm.lbswarm=true`), `rdfx_edge`
//! (a published port and no network but `ingress`), `rdfx_job` (a replicated job) and
//! `rdfx_slow` (scaled from 2 to 1 while replica 2 still runs, `DesiredState: remove`).
//! `fixtures/rolling-update/tasks.json` is the same swarm during a `stop-first` update of
//! `rdfx_slow`: its only task has `DesiredState: shutdown` and still runs.

#![allow(clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::path::Path;

use rdock_model::providers::{SwarmEndpointMode, SwarmProvider};
use rdock_provider_docker::labels::Translation;
use rdock_provider_swarm::convert::{Inventory, translate};

fn read<T: serde::de::DeserializeOwned>(case: &str, file: &str) -> T {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(case)
        .join(file);
    serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap()
}

fn scale_down() -> Inventory {
    Inventory {
        services: read("scale-down", "services.json"),
        tasks: read("scale-down", "tasks.json"),
        networks: read("scale-down", "networks.json"),
    }
}

fn rolling_update() -> Inventory {
    Inventory {
        tasks: read("rolling-update", "tasks.json"),
        ..scale_down()
    }
}

/// Changes the labels of `service`.
fn relabel(inventory: &mut Inventory, service: &str, set: &[(&str, &str)], remove: &[&str]) {
    let spec = inventory
        .services
        .iter_mut()
        .filter_map(|s| s.spec.as_mut())
        .find(|s| s.name.as_deref() == Some(service))
        .unwrap();
    let labels = spec.labels.get_or_insert_with(Default::default);
    for key in remove {
        labels.remove(*key);
    }
    for (key, value) in set {
        labels.insert((*key).to_owned(), (*value).to_owned());
    }
}

fn run(inventory: &Inventory) -> Translation {
    translate(inventory, &SwarmProvider::default(), None)
}

fn backends(t: &Translation, service: &str) -> Vec<String> {
    let Some(service) = t.fragment.services.get(service) else {
        return Vec::new();
    };
    service
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

fn has_message(t: &Translation, needle: &str) -> bool {
    messages(t).iter().any(|m| m.contains(needle))
}

#[test]
fn replicas_become_one_pool_on_the_labelled_network() {
    let t = run(&scale_down());
    assert_eq!(backends(&t, "rdfx_web"), ["10.0.1.3:80", "10.0.1.4:80"]);
    let route = serde_json::to_value(&t.fragment.routes["rdfx_web"]).unwrap();
    assert_eq!(route["service"], "rdfx_web");
    assert_eq!(route["match"], "Host(`web.example.test`)");
}

#[test]
fn global_services_use_traefik_swarm_labels() {
    let t = run(&scale_down());
    assert_eq!(backends(&t, "agent"), ["10.0.1.7:80"]);
    assert!(t.fragment.routes.contains_key("agent"));
    assert!(
        !has_message(&t, "traefik.swarm"),
        "Swarm labels are not reported as unsupported: {:?}",
        messages(&t)
    );
}

#[test]
fn a_task_swarm_is_stopping_leaves_the_pool() {
    let t = run(&scale_down());
    assert_eq!(backends(&t, "rdfx_slow"), ["10.0.1.10:8080"]);
}

#[test]
fn a_service_whose_only_task_is_stopping_keeps_it_until_it_exits() {
    let t = run(&rolling_update());
    assert_eq!(backends(&t, "rdfx_slow"), ["10.0.1.10:8080"]);
    assert!(
        has_message(
            &t,
            "no container of service `rdfx_slow` is healthy (rdfx_slow.1)"
        ),
        "{:?}",
        messages(&t)
    );
}

#[test]
fn services_that_cannot_be_routed_say_why() {
    let t = run(&scale_down());
    for (service, message) in [
        ("rdfx_edge", "only on the `ingress` network"),
        ("rdfx_dns", "uses `dnsrr` and has no virtual IP"),
        ("rdfx_job", "job-mode services run to completion"),
    ] {
        assert!(!t.fragment.services.contains_key(service), "{service}");
        let expected = format!("swarm.{service}: ");
        assert!(
            messages(&t)
                .iter()
                .any(|m| m.starts_with(&expected) && m.contains(message)),
            "{service}: {:?}",
            messages(&t)
        );
    }
}

#[test]
fn services_that_are_not_exposed_get_no_swarm_warnings() {
    let mut inventory = scale_down();
    for service in ["rdfx_edge", "rdfx_dns", "rdfx_job"] {
        relabel(&mut inventory, service, &[], &["rdock.enable"]);
    }
    let t = run(&inventory);
    for message in ["ingress", "dnsrr", "job-mode"] {
        assert!(!has_message(&t, message), "{:?}", messages(&t));
    }
}

#[test]
fn vip_mode_routes_to_the_virtual_ip() {
    let provider = SwarmProvider {
        endpoint_mode: SwarmEndpointMode::Vip,
        ..SwarmProvider::default()
    };
    let t = translate(&scale_down(), &provider, None);
    assert_eq!(backends(&t, "rdfx_web"), ["10.0.1.2:80"]);
    assert_eq!(backends(&t, "rdfx_slow"), ["10.0.1.9:8080"]);
    assert_eq!(backends(&t, "agent"), ["10.0.1.6:80"]);
    assert!(has_message(&t, "only on the `ingress` network"));
}

#[test]
fn lbswarm_labels_choose_the_mode_per_service() {
    let provider = SwarmProvider {
        endpoint_mode: SwarmEndpointMode::Vip,
        ..SwarmProvider::default()
    };
    let mut inventory = scale_down();
    relabel(
        &mut inventory,
        "rdfx_web",
        &[("rdock.swarm.lbswarm", "false")],
        &[],
    );
    relabel(
        &mut inventory,
        "rdfx_agent",
        &[("traefik.swarm.lbswarm", "false")],
        &[],
    );
    let t = translate(&inventory, &provider, None);
    assert_eq!(backends(&t, "rdfx_web"), ["10.0.1.3:80", "10.0.1.4:80"]);
    assert_eq!(backends(&t, "agent"), ["10.0.1.7:80"]);
    let mut inventory = scale_down();
    relabel(
        &mut inventory,
        "rdfx_web",
        &[("traefik.swarm.lbswarm", "true")],
        &[],
    );
    assert_eq!(backends(&run(&inventory), "rdfx_web"), ["10.0.1.2:80"]);
}

#[test]
fn vip_services_drop_health_checks_and_sticky_sessions() {
    let mut inventory = scale_down();
    relabel(
        &mut inventory,
        "rdfx_web",
        &[
            ("rdock.swarm.lbswarm", "true"),
            ("rdock.services.rdfx_web.health.active.path", "/health"),
            ("rdock.services.rdfx_web.sticky.cookie.name", "rd"),
        ],
        &[],
    );
    let t = run(&inventory);
    let service = &t.fragment.services["rdfx_web"];
    assert_eq!(service.sticky, None);
    assert!(service.health.as_ref().is_none_or(|h| h.active.is_none()));
    assert!(has_message(
        &t,
        "sticky sessions do nothing behind a Swarm virtual IP"
    ));
    assert!(has_message(
        &t,
        "active health checks cannot see tasks behind a Swarm virtual IP"
    ));
}

#[test]
fn deprecated_traefik_docker_labels_still_work_with_a_warning() {
    let mut inventory = scale_down();
    relabel(
        &mut inventory,
        "rdfx_agent",
        &[("traefik.docker.network", "rdfx_front")],
        &["traefik.swarm.network"],
    );
    let t = run(&inventory);
    assert_eq!(backends(&t, "agent"), ["10.0.1.7:80"]);
    assert!(
        has_message(&t, "deprecated on Swarm: use `traefik.swarm.network`"),
        "{:?}",
        messages(&t)
    );
}

#[test]
fn both_traefik_spellings_together_keep_the_swarm_one() {
    let mut inventory = scale_down();
    relabel(&mut inventory, "rdfx_web", &[], &["rdock.network"]);
    relabel(
        &mut inventory,
        "rdfx_web",
        &[
            ("traefik.swarm.network", "rdfx_front"),
            ("traefik.docker.network", "rdfx_back"),
        ],
        &[],
    );
    let t = run(&inventory);
    assert_eq!(backends(&t, "rdfx_web"), ["10.0.1.3:80", "10.0.1.4:80"]);
    assert!(
        has_message(
            &t,
            "both `traefik.docker.*` and `traefik.swarm.*` labels are set; the label is ignored"
        ),
        "{:?}",
        messages(&t)
    );
}

#[test]
fn a_task_on_several_networks_uses_the_one_shared_with_the_proxy() {
    let mut inventory = scale_down();
    relabel(&mut inventory, "rdfx_web", &[], &["rdock.network"]);
    let provider = SwarmProvider::default();

    let t = translate(&inventory, &provider, None);
    assert_eq!(backends(&t, "rdfx_web"), Vec::<String>::new());
    assert!(
        has_message(
            &t,
            "the task is on several networks (rdfx_back, rdfx_front); choose one"
        ),
        "{:?}",
        messages(&t)
    );

    let front = BTreeSet::from(["rdfx_front".to_owned(), "bridge".to_owned()]);
    let t = translate(&inventory, &provider, Some(&front));
    assert_eq!(backends(&t, "rdfx_web"), ["10.0.1.3:80", "10.0.1.4:80"]);

    let both = BTreeSet::from(["rdfx_front".to_owned(), "rdfx_back".to_owned()]);
    let t = translate(&inventory, &provider, Some(&both));
    assert!(has_message(
        &t,
        "shares several networks with ReverseDock's container"
    ));

    let other = BTreeSet::from(["elsewhere".to_owned()]);
    let t = translate(&inventory, &provider, Some(&other));
    assert!(has_message(
        &t,
        "the task shares no network with ReverseDock's container (it is on: rdfx_back, rdfx_front)"
    ));
    assert!(t.diagnostics.iter().any(|d| d.hint.as_deref()
        == Some("set `rdock.network` on the service or `providers.swarm.network`")));

    let back = SwarmProvider {
        network: Some("rdfx_back".to_owned()),
        ..SwarmProvider::default()
    };
    let t = translate(&inventory, &back, Some(&front));
    assert_eq!(backends(&t, "rdfx_web"), ["10.0.2.3:80", "10.0.2.4:80"]);
}

#[test]
fn a_missing_port_label_says_swarm_reports_no_ports() {
    let mut inventory = scale_down();
    relabel(&mut inventory, "rdfx_web", &[], &["rdock.port"]);
    let t = run(&inventory);
    assert!(!t.fragment.services.contains_key("rdfx_web"));
    assert!(
        has_message(
            &t,
            "service `rdfx_web`: Swarm reports no ports for its tasks, so the port must be set"
        ),
        "{:?}",
        messages(&t)
    );
}

#[test]
fn diagnostics_point_at_the_swarm_task() {
    let mut inventory = scale_down();
    relabel(&mut inventory, "rdfx_web", &[("rdock.bogus", "1")], &[]);
    let t = run(&inventory);
    assert!(
        messages(&t).iter().any(|m| m.starts_with("swarm")
            && m.contains("rdfx_web.1")
            && m.contains("rdock.bogus")),
        "{:?}",
        messages(&t)
    );
}
