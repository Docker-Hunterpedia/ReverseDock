//! The upstream `UDPRoute` conformance tests (Gateway API v1.7.0, profile `GATEWAY-UDP`),
//! transcribed against the translator as in `gateway_conformance.rs`: every test gated on
//! the `UDPRoute` feature (`conformance/tests/udproute-*.go`) is here, with the status it
//! asserts and, where it sends datagrams, the backend a datagram reaches through the
//! assembled and compiled fragment. The Rust test name carries the upstream `ShortName`.
//!
//! The suite's client is a UDP echo, not DNS (`conformance/utils/udp`); the weighted test opens
//! a new socket per probe, so per-session balancing meets it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::unnecessary_wraps
)]

mod gateway_support;

use std::collections::{BTreeMap, BTreeSet};

use gateway_support::{
    APP, Cluster, INFRA, Router, assert_accepted, assert_condition, assert_resolved, gateway,
    listener, parent,
};
use rdock_provider_kubernetes::translate::RouteKind::Udp;

fn router(tests: &[&str]) -> (Cluster, Router) {
    let mut cluster = Cluster::upstream(tests);
    let router = Router::new(&mut cluster);
    (cluster, router)
}

fn deployments(names: &[&str]) -> Option<BTreeSet<String>> {
    Some(names.iter().map(|n| (*n).to_owned()).collect())
}

fn listener_port(cluster: &Cluster, gw: (&str, &str), name: &str) -> u16 {
    cluster.inventory.gateways[&(gw.0.to_owned(), gw.1.to_owned())]
        .spec
        .listeners
        .iter()
        .find(|l| l.name == name)
        .unwrap()
        .port
}

/// What `GatewayAndUDPRoutesMustBeAccepted` waits for, plus the listener's `UDPRoute` kind.
fn assert_udp_accepted(r: &Router, route: (&str, &str), gw: (&str, &str)) {
    assert_accepted(&r.translation, Udp, route, gw);
    let g = gateway(&r.translation, gw.0, gw.1);
    for l in &g.listeners {
        let kinds: Vec<&str> = l.supported_kinds.iter().map(|k| k.kind.as_str()).collect();
        assert_eq!(kinds, ["UDPRoute"], "{}", l.name);
    }
}

#[test]
fn udp_route() {
    // UDPRoute: a datagram to the Gateway reaches `udp-echo`.
    let (cluster, r) = router(&["udproute-simple"]);
    let gw = (INFRA, "udp-gateway");
    assert_udp_accepted(&r, (INFRA, "udp-route"), gw);
    let port = listener_port(&cluster, gw, "udp");
    assert!(
        r.udp_target(gw, port).is_some(),
        "the Service maps UDP {port}"
    );
    assert_eq!(r.datagram(gw, port), deployments(&["udp-echo"]));
    // The UDP listener has its own internal port; no TCP listener exists for it.
    assert!(!r.has_listener(gw, port));
}

#[test]
fn udp_route_invalid_backend_ref_nonexistent() {
    // UDPRouteInvalidBackendRefNonexistent.
    let (cluster, r) = router(&["udproute-invalid-backendref-nonexistent"]);
    let gw = (INFRA, "udp-gateway-invalid-backend");
    let route = (INFRA, "udp-route-invalid-backend-ref-nonexistent");
    assert_resolved(&r.translation, Udp, route, gw, false, "BackendNotFound");
    // No usable backend: no UDP route, the datagrams are dropped.
    let port = listener_port(&cluster, gw, "udp");
    assert_eq!(r.datagram(gw, port), None);
}

#[test]
fn udp_route_invalid_cross_namespace_backend_ref() {
    // UDPRouteInvalidCrossNamespaceBackendRef.
    let (cluster, r) = router(&["udproute-invalid-cross-namespace-backend-ref"]);
    let gw = (INFRA, "udp-gateway-invalid-cross-namespace-backend-ref");
    let route = (INFRA, "udp-route-invalid-cross-namespace-backend-ref");
    assert_udp_accepted(&r, route, gw);
    assert_resolved(&r.translation, Udp, route, gw, false, "RefNotPermitted");
    let port = listener_port(&cluster, gw, "udp");
    assert_eq!(r.datagram(gw, port), None);
}

#[test]
fn udp_route_reference_grant() {
    // UDPRouteReferenceGrant: allowed while the grant exists, refused once it is deleted.
    let (mut cluster, r) = router(&["udproute-reference-grant"]);
    let gw = (INFRA, "udp-gateway-reference-grant");
    let route = (INFRA, "udp-route-reference-grant");
    assert_udp_accepted(&r, route, gw);
    assert_resolved(&r.translation, Udp, route, gw, true, "ResolvedRefs");
    let port = listener_port(&cluster, gw, "udp");
    assert_eq!(
        r.datagram(gw, port),
        deployments(&["udp-echo-reference-grant"])
    );
    cluster
        .inventory
        .reference_grants
        .remove(&(APP.to_owned(), "udp-reference-grant".to_owned()));
    let r = Router::new(&mut cluster);
    assert_resolved(&r.translation, Udp, route, gw, false, "RefNotPermitted");
    assert_eq!(r.datagram(gw, port), None);
}

#[test]
fn udp_route_multiple_routes_attachment() {
    // UDPRouteMultipleRoutesAttachment: both are accepted and attached, the older one gets
    // every datagram.
    let mut cluster = Cluster::upstream(&["udproute-multiple-routes-attachment"]);
    let gw = (INFRA, "udp-multi-route-attach-gateway");
    cluster.apply_yaml(
        "apiVersion: gateway.networking.k8s.io/v1\nkind: UDPRoute\nmetadata: {name: udproute-attach-newer, namespace: gateway-conformance-infra}\nspec:\n  parentRefs: [{name: udp-multi-route-attach-gateway, sectionName: udp}]\n  rules: [{backendRefs: [{name: udp-attach-backend-2, port: 8080}]}]\n",
    );
    let r = Router::new(&mut cluster);
    let t = &r.translation;
    for route in ["udproute-attach-older", "udproute-attach-newer"] {
        let p = parent(t, Udp, (INFRA, route), gw);
        assert_condition(&p.conditions, "Accepted", true, "Accepted");
    }
    let g = gateway(t, gw.0, gw.1);
    let l = listener(g, "udp");
    assert_eq!(l.attached_routes, 2);
    assert_eq!(
        l.supported_kinds
            .iter()
            .map(|k| (k.group.as_deref(), k.kind.as_str()))
            .collect::<Vec<_>>(),
        [(Some("gateway.networking.k8s.io"), "UDPRoute")]
    );
    assert_condition(&l.conditions, "Accepted", true, "Accepted");
    let port = listener_port(&cluster, gw, "udp");
    assert_eq!(r.datagram(gw, port), deployments(&["udp-attach-backend-1"]));
    assert_eq!(t.fragment.udp_routes.len(), 1, "one route per listener");
}

#[test]
fn udp_route_not_allowed_by_listeners() {
    // UDPRouteNotAllowedByListeners (runs when TLSRoute is supported, which it is): a UDPRoute
    // on a TLS-only Gateway is not accepted and not attached.
    let (_, r) = router(&["udproute-not-allowed-by-listeners"]);
    let gw = (INFRA, "udproute-tls-only-gateway");
    let p = parent(
        &r.translation,
        Udp,
        (INFRA, "udproute-not-allowed-by-listeners"),
        gw,
    );
    assert_condition(&p.conditions, "Accepted", false, "NotAllowedByListeners");
    let g = gateway(&r.translation, gw.0, gw.1);
    assert!(g.listeners.iter().all(|l| l.attached_routes == 0));
    assert!(r.translation.fragment.udp_routes.is_empty());
}

#[test]
fn udp_route_parent_ref_attach_all_listeners() {
    // UDPRouteParentRefAttachAllListeners: no port, no sectionName → every UDP listener.
    let (cluster, r) = router(&["udproute-parentref-attach-all-listeners"]);
    let gw = (INFRA, "udp-attach-all-listeners-gateway");
    let p = parent(&r.translation, Udp, (INFRA, "udp-route-attach-all"), gw);
    assert_condition(&p.conditions, "Accepted", true, "Accepted");
    let g = gateway(&r.translation, gw.0, gw.1);
    for name in ["udp-1", "udp-2", "udp-3"] {
        let l = listener(g, name);
        assert_eq!(l.attached_routes, 1, "{name}");
        assert_eq!(l.supported_kinds[0].kind, "UDPRoute");
        assert_condition(&l.conditions, "Accepted", true, "");
        assert_condition(&l.conditions, "ResolvedRefs", true, "");
        let port = listener_port(&cluster, gw, name);
        assert_eq!(
            r.datagram(gw, port),
            deployments(&["udp-echo-attach-all"]),
            "{name}"
        );
    }
}

#[test]
fn udp_route_parent_ref_port_and_section_name() {
    // UDPRouteParentRefPortAndSectionName.
    let (cluster, r) = router(&["udproute-parentref-port-and-section-name"]);
    let gw = (INFRA, "udp-multi-listener-gateway");
    for (route, listener_name, backend) in [
        ("udp-route-by-port", "by-port", "udp-echo-by-port"),
        ("udp-route-by-section", "by-section", "udp-echo-by-section"),
        (
            "udp-route-by-section-and-port",
            "by-section-and-port",
            "udp-echo-by-section-and-port",
        ),
    ] {
        let p = parent(&r.translation, Udp, (INFRA, route), gw);
        assert_condition(&p.conditions, "Accepted", true, "Accepted");
        let port = listener_port(&cluster, gw, listener_name);
        assert_eq!(r.datagram(gw, port), deployments(&[backend]), "{route}");
    }
}

#[test]
fn udp_route_weighted_routing() {
    // UDPRouteWeightedRouting: 70/30/0; the weight-0 backend gets nothing.
    let (cluster, r) = router(&["udproute-weighted-routing"]);
    let gw = (INFRA, "udp-weighted-gateway");
    assert_udp_accepted(&r, (INFRA, "udp-weighted-route"), gw);
    let port = listener_port(&cluster, gw, "udp");
    let service = r.udp_service(gw, port).unwrap();
    let mut share = BTreeMap::<String, u32>::new();
    for b in &service.backends {
        let ip = b.address.to_string();
        let ip = ip.rsplit_once(':').unwrap().0.to_owned();
        *share.entry(cluster.pods[&ip].1.clone()).or_default() += b.weight;
    }
    let total: u32 = share.values().sum();
    assert_eq!(share.get("udp-backend-v3"), None, "{share:?}");
    let v1 = f64::from(share["udp-backend-v1"]) / f64::from(total);
    assert!((v1 - 0.7).abs() < 0.01, "{share:?}");
    assert_eq!(
        r.datagram(gw, port),
        deployments(&["udp-backend-v1", "udp-backend-v2"])
    );
}

#[test]
fn tcp_and_udp_listeners_share_a_port_with_two_internal_ports() {
    // Not an upstream test: the DNS case, TCP and UDP on 53 of one Gateway.
    let mut cluster = Cluster::upstream(&["udproute-simple"]);
    cluster.apply_yaml(
        "apiVersion: gateway.networking.k8s.io/v1\nkind: Gateway\nmetadata: {name: dns, namespace: gateway-conformance-infra}\nspec:\n  gatewayClassName: gateway-conformance\n  listeners:\n  - {name: dns-udp, port: 53, protocol: UDP, allowedRoutes: {namespaces: {from: Same}}}\n  - {name: dns-tcp, port: 53, protocol: TCP, allowedRoutes: {namespaces: {from: Same}}}\n---\napiVersion: gateway.networking.k8s.io/v1\nkind: UDPRoute\nmetadata: {name: dns-udp, namespace: gateway-conformance-infra}\nspec:\n  parentRefs: [{name: dns, sectionName: dns-udp}]\n  rules: [{backendRefs: [{name: udp-echo, port: 8080}]}]\n",
    );
    let r = Router::new(&mut cluster);
    let gw = (INFRA, "dns");
    let g = gateway(&r.translation, gw.0, gw.1);
    for name in ["dns-udp", "dns-tcp"] {
        assert_condition(&listener(g, name).conditions, "Accepted", true, "Accepted");
        assert_condition(
            &listener(g, name).conditions,
            "Conflicted",
            false,
            "NoConflicts",
        );
    }
    let desired = r
        .translation
        .services
        .iter()
        .find(|s| s.gateway == (INFRA.to_owned(), "dns".to_owned()))
        .unwrap();
    assert_eq!(
        (desired.ports.clone(), desired.udp_ports.clone()),
        (vec![53], vec![53])
    );
    let service = &cluster.inventory.gateway_services[&(INFRA.to_owned(), "dns".to_owned())];
    assert_ne!(service.ports[&53], service.udp_ports[&53]);
    assert!(r.has_listener(gw, 53));
    assert_eq!(r.datagram(gw, 53), deployments(&["udp-echo"]));
}

/// Behind a Service every datagram arrives from the load balancer's or the node's address, so
/// a Gateway's UDP listener must not cap sessions per client address (the upstream weighted
/// routing test opens one socket per probe and stalled at the default of 64).
#[test]
fn gateway_udp_listeners_do_not_cap_sessions_per_client_address() {
    let mut cluster = Cluster::upstream(&["udproute-simple"]);
    let r = Router::new(&mut cluster);
    let udp: Vec<_> = r
        .translation
        .fragment
        .listeners
        .values()
        .filter(|l| l.protocol == Some(rdock_model::config::ListenerProtocol::Udp))
        .collect();
    assert!(!udp.is_empty(), "the fixture has a UDP listener");
    for listener in udp {
        let sessions = listener.sessions.as_ref().expect("sessions are set");
        assert_eq!(
            sessions.max_per_client,
            rdock_model::config::SessionLimit::Unlimited
        );
        assert_ne!(sessions.max, rdock_model::config::SessionLimit::Unlimited);
    }
}
