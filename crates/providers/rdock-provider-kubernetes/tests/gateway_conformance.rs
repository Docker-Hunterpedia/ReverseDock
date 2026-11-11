//! The upstream Gateway API conformance tests (v1.7.0), transcribed against the translator.
//!
//! Each test loads the suite's base manifests and the test's own manifest from
//! `tests/fixtures/upstream` into a simulated cluster (`gateway_support`), translates, and
//! asserts what the upstream Go test (`conformance/tests/<name>.go`) asserts: conditions,
//! reasons, `attachedRoutes` and `supportedKinds` in the desired status, and for traffic,
//! which backend (or status) a request reaches through the compiled fragment. Every
//! translation is also assembled onto a base configuration and compiled, with nothing left
//! out and no error. The Rust test name carries the upstream test's `ShortName`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::type_complexity
)]

mod gateway_support;

use gateway_support::{
    APP, Cluster, INFRA, Outcome, Request, Router, WEB, assert_accepted, assert_condition,
    assert_gateway_ready, assert_listener, assert_resolved, backends, gateway, get, listener,
    parent, parents,
};
use rdock_provider_kubernetes::translate::RouteKind::{self, Grpc, Http, Tcp, Tls, Udp};

const SAME: (&str, &str) = (INFRA, "same-namespace");

fn router(tests: &[&str]) -> Router {
    Router::new(&mut Cluster::upstream(tests))
}

fn expect(r: &Router, gw: (&str, &str), port: u16, request: &Request<'_>, outcome: &Outcome) {
    let routed = r.route(gw, port, request);
    assert_eq!(
        &routed.outcome, outcome,
        "{request:?} on {gw:?}:{port} → {:?}",
        routed.route
    );
}

fn host<'a>(host: &'a str, path: &'a str) -> Request<'a> {
    Request {
        host,
        path,
        method: "GET",
        headers: &[],
    }
}

fn with_headers<'a>(path: &'a str, headers: &'a [(&'a str, &'a str)]) -> Request<'a> {
    Request {
        host: "",
        path,
        method: "GET",
        headers,
    }
}

fn v1() -> Outcome {
    backends(&["infra-backend-v1"])
}
fn v2() -> Outcome {
    backends(&["infra-backend-v2"])
}
fn v3() -> Outcome {
    backends(&["infra-backend-v3"])
}

// ---------------------------------------------------------------------------------------
// Base manifests and GatewayClass.

#[test]
fn base_gateways_are_accepted_and_programmed() {
    let r = router(&[]);
    let t = &r.translation;
    for name in [
        "same-namespace",
        "same-namespace-with-https-listener",
        "all-namespaces",
        "backend-namespaces",
    ] {
        assert_gateway_ready(t, (INFRA, name));
    }
    let class = &t.status.gateway_classes["gateway-conformance"];
    assert_condition(&class.conditions, "Accepted", true, "Accepted");
    assert_condition(
        &class.conditions,
        "SupportedVersion",
        true,
        "SupportedVersion",
    );
    let names: Vec<&str> = class
        .supported_features
        .iter()
        .map(|f| f.name.as_str())
        .collect();
    assert_eq!(names, rdock_provider_kubernetes::features::SUPPORTED);
    // One Service per Gateway with the listener ports, labelled.
    let service = t
        .services
        .iter()
        .find(|s| {
            s.gateway
                == (
                    INFRA.to_owned(),
                    "same-namespace-with-https-listener".to_owned(),
                )
        })
        .unwrap();
    assert_eq!(service.ports, vec![443]);
    assert_eq!(
        service.labels["gateway.networking.k8s.io/gateway-name"],
        "same-namespace-with-https-listener"
    );
    assert_eq!(service.labels["reversedock.dev/gateway-namespace"], INFRA);
    assert_eq!(
        service.name,
        rdock_provider_kubernetes::translate::gateway_service_name(
            INFRA,
            "same-namespace-with-https-listener"
        )
    );
    assert!(
        service
            .name
            .starts_with(&format!("{INFRA}-same-namespace-with-https-"))
    );
    // The HTTPS listener's Secret is written as files and named as a certificate.
    assert!(t.secrets.contains(&(
        INFRA.to_owned(),
        "tls-validity-checks-certificate".to_owned()
    )));
    assert_eq!(t.fragment.certificates.len(), 1);
}

#[test]
fn gateway_class_observed_generation_bump() {
    // GatewayClassObservedGenerationBump.
    let mut cluster = Cluster::upstream(&["gatewayclass-observed-generation-bump"]);
    let t = cluster.translate();
    let class = &t.status.gateway_classes["gatewayclass-observed-generation-bump"];
    assert_condition(&class.conditions, "Accepted", true, "");
    let gc = cluster
        .inventory
        .gateway_classes
        .get_mut("gatewayclass-observed-generation-bump")
        .unwrap();
    gc.spec.description = Some("new".into());
    gc.metadata.generation = Some(2);
    let t = cluster.translate();
    let class = &t.status.gateway_classes["gatewayclass-observed-generation-bump"];
    assert!(
        class
            .conditions
            .iter()
            .all(|c| c.observed_generation == Some(2))
    );
}

#[test]
fn classes_of_other_controllers_are_not_touched() {
    let mut cluster = Cluster::upstream(&[]);
    cluster.apply_yaml(
        "apiVersion: gateway.networking.k8s.io/v1\nkind: GatewayClass\nmetadata: {name: other}\nspec: {controllerName: example.com/other}\n---\napiVersion: gateway.networking.k8s.io/v1\nkind: Gateway\nmetadata: {name: foreign, namespace: gateway-conformance-infra}\nspec:\n  gatewayClassName: other\n  listeners: [{name: http, port: 80, protocol: HTTP}]\n---\napiVersion: gateway.networking.k8s.io/v1\nkind: HTTPRoute\nmetadata: {name: to-foreign, namespace: gateway-conformance-infra}\nspec:\n  parentRefs: [{name: foreign}, {name: same-namespace}]\n  rules: [{backendRefs: [{name: infra-backend-v1, port: 8080}]}]\n",
    );
    let t = cluster.translate();
    assert!(!t.status.gateway_classes.contains_key("other"));
    assert!(
        !t.status
            .gateways
            .contains_key(&(INFRA.to_owned(), "foreign".to_owned()))
    );
    // Only the parentRef to our Gateway gets an entry from us.
    let p = parents(&t, Http, INFRA, "to-foreign");
    assert_eq!(p.len(), 1);
    assert_eq!(p[0].parent_ref.name, "same-namespace");
}

// ---------------------------------------------------------------------------------------
// Gateway tests (core).

#[test]
fn gateway_listener_unsupported_protocol() {
    // GatewayListenerUnsupportedProtocol.
    let mut cluster = Cluster::upstream(&["gateway-invalid-listeners-unsupported-protocol"]);
    let t = cluster.translate();
    let gw = gateway(&t, INFRA, "gateway-only-unsupported-protocols");
    assert_condition(&gw.conditions, "Accepted", false, "ListenersNotValid");
    assert_listener(gw, "invalid", &[], 0);
    assert_condition(
        &listener(gw, "invalid").conditions,
        "Accepted",
        false,
        "UnsupportedProtocol",
    );
    let gw = gateway(&t, INFRA, "gateway-supported-and-unsupported-protocols");
    assert_condition(&gw.conditions, "Accepted", true, "ListenersNotValid");
    // Not annotated as skipped for readiness: it must also be programmed.
    assert_condition(&gw.conditions, "Programmed", true, "");
    assert_listener(gw, "http", &["HTTPRoute"], 0);
    assert_condition(
        &listener(gw, "http").conditions,
        "Accepted",
        true,
        "Accepted",
    );
    assert_listener(gw, "invalid", &[], 0);
    assert_condition(
        &listener(gw, "invalid").conditions,
        "Accepted",
        false,
        "UnsupportedProtocol",
    );
}

#[test]
fn gateway_invalid_route_kind() {
    // GatewayInvalidRouteKind.
    let mut cluster = Cluster::upstream(&["gateway-invalid-route-kind"]);
    let t = cluster.translate();
    let gw = gateway(&t, INFRA, "gateway-only-invalid-route-kind");
    assert_listener(gw, "http", &[], 0);
    assert_condition(
        &listener(gw, "http").conditions,
        "ResolvedRefs",
        false,
        "InvalidRouteKinds",
    );
    let gw = gateway(&t, INFRA, "gateway-supported-and-invalid-route-kind");
    assert_listener(gw, "http", &["HTTPRoute"], 0);
    assert_eq!(listener(gw, "http").supported_kinds.len(), 1);
    assert_condition(
        &listener(gw, "http").conditions,
        "ResolvedRefs",
        false,
        "InvalidRouteKinds",
    );
}

#[test]
fn gateway_invalid_tls_configuration() {
    // GatewayInvalidTLSConfiguration.
    let mut cluster = Cluster::upstream(&["gateway-invalid-tls-configuration"]);
    let t = cluster.translate();
    for name in [
        "gateway-certificate-nonexistent-secret",
        "gateway-certificate-unsupported-group",
        "gateway-certificate-unsupported-kind",
        "gateway-certificate-malformed-secret",
    ] {
        let gw = gateway(&t, INFRA, name);
        assert_listener(gw, "https", &["HTTPRoute"], 0);
        assert_condition(
            &listener(gw, "https").conditions,
            "ResolvedRefs",
            false,
            "InvalidCertificateRef",
        );
        assert_condition(&listener(gw, "https").conditions, "Programmed", false, "");
    }
    // No listener, no certificate and no Secret file for an invalid listener.
    assert!(t.secrets.iter().all(|(_, n)| n != "malformed-certificate"));
}

#[test]
fn gateway_modify_listeners() {
    // GatewayModifyListeners: add a listener, then remove one.
    let mut cluster = Cluster::upstream(&["gateway-modify-listeners"]);
    let t = cluster.translate();
    let gw = gateway(&t, INFRA, "gateway-add-listener");
    assert_listener(gw, "https", &["HTTPRoute"], 1);
    let key = (INFRA.to_owned(), "gateway-add-listener".to_owned());
    let g = cluster.inventory.gateways.get_mut(&key).unwrap();
    g.spec.listeners.push(
        serde_json::from_value(serde_json::json!({
            "name": "http", "port": 80, "protocol": "HTTP", "hostname": "data.test.com",
            "allowedRoutes": {"namespaces": {"from": "All"}}
        }))
        .unwrap(),
    );
    g.metadata.generation = Some(2);
    // The first translation asks for port 80; until the Service maps it, nothing listens.
    let pending = rdock_provider_kubernetes::translate(&cluster.inventory, &cluster.settings);
    let gw = &pending.status.gateways[&key];
    assert_condition_gen(
        &listener(gw, "http").conditions,
        "Programmed",
        false,
        "Pending",
        2,
    );
    assert_condition_gen(&gw.conditions, "Programmed", false, "Pending", 2);
    assert!(
        pending
            .services
            .iter()
            .any(|s| s.gateway == key && s.ports == vec![80, 443])
    );
    let t = cluster.translate();
    let gw = &t.status.gateways[&key];
    for name in ["https", "http"] {
        let l = listener(gw, name);
        assert_eq!(l.attached_routes, 1, "{name}");
        assert_condition_gen(&l.conditions, "Accepted", true, "", 2);
        assert_condition_gen(&l.conditions, "ResolvedRefs", true, "", 2);
        assert_condition_gen(&l.conditions, "Programmed", true, "", 2);
    }
    let r = Router::compile(&cluster, t);
    assert!(r.has_listener((INFRA, "gateway-add-listener"), 80));
    expect(
        &r,
        (INFRA, "gateway-add-listener"),
        80,
        &host("data.test.com", "/"),
        &v1(),
    );

    let key = (INFRA.to_owned(), "gateway-remove-listener".to_owned());
    let g = cluster.inventory.gateways.get_mut(&key).unwrap();
    g.spec.listeners.retain(|l| l.name == "http");
    g.metadata.generation = Some(2);
    let t = cluster.translate();
    let gw = &t.status.gateways[&key];
    assert_eq!(gw.listeners.len(), 1);
    assert_eq!(listener(gw, "http").attached_routes, 1);
    let r = Router::compile(&cluster, t);
    assert!(!r.has_listener((INFRA, "gateway-remove-listener"), 443));
    assert!(r.has_listener((INFRA, "gateway-remove-listener"), 80));
}

fn assert_condition_gen(
    conditions: &[rdock_provider_kubernetes::translate::DesiredCondition],
    kind: &str,
    status: bool,
    reason: &str,
    generation: i64,
) {
    let c = conditions.iter().find(|c| c.kind == kind).unwrap();
    assert_eq!(c.status, status, "{c:?}");
    if !reason.is_empty() {
        assert_eq!(c.reason, reason, "{c:?}");
    }
    assert_eq!(c.observed_generation, Some(generation), "{c:?}");
}

#[test]
fn gateway_name_maximum_length() {
    // GatewayNameMaximumLength: a 253-character name is reconciled.
    let r = router(&["gateway-name-maximum-length"]);
    let t = &r.translation;
    let (key, gw) = t
        .status
        .gateways
        .iter()
        .find(|(k, _)| k.1.len() == 253)
        .unwrap();
    assert!(
        gw.conditions
            .iter()
            .all(|c| c.observed_generation == Some(1))
    );
    let service = t.services.iter().find(|s| &s.gateway == key).unwrap();
    assert!(service.name.len() <= 63);
    assert!(service.labels.values().all(|v| v.len() <= 63));
}

#[test]
fn gateway_observed_generation_bump() {
    // GatewayObservedGenerationBump.
    let mut cluster = Cluster::upstream(&["gateway-observed-generation-bump"]);
    let key = (
        INFRA.to_owned(),
        "gateway-observed-generation-bump".to_owned(),
    );
    let t = cluster.translate();
    assert!(
        t.status.gateways[&key]
            .conditions
            .iter()
            .all(|c| c.observed_generation == Some(1))
    );
    let g = cluster.inventory.gateways.get_mut(&key).unwrap();
    g.spec.listeners.push(
        serde_json::from_value(serde_json::json!({
            "name": "alternate", "port": 80, "protocol": "HTTP", "hostname": "foo.com",
            "allowedRoutes": {"namespaces": {"from": "All"}}
        }))
        .unwrap(),
    );
    g.metadata.generation = Some(2);
    let t = cluster.translate();
    let gw = &t.status.gateways[&key];
    assert_condition_gen(&gw.conditions, "Accepted", true, "", 2);
    assert_condition_gen(&gw.conditions, "Programmed", true, "", 2);
    for l in &gw.listeners {
        assert!(
            l.conditions
                .iter()
                .all(|c| c.observed_generation == Some(2))
        );
    }
}

#[test]
fn gateway_secret_invalid_reference_grant() {
    // GatewaySecretInvalidReferenceGrant.
    let mut cluster = Cluster::upstream(&["gateway-secret-invalid-reference-grant"]);
    let t = cluster.translate();
    let gw = gateway(&t, INFRA, "gateway-secret-invalid-reference-grant");
    assert_listener(gw, "https", &["HTTPRoute"], 0);
    assert_condition(
        &listener(gw, "https").conditions,
        "ResolvedRefs",
        false,
        "RefNotPermitted",
    );
    // Not annotated as skipped for readiness: the Gateway itself is ready.
    assert_condition(&gw.conditions, "Accepted", true, "");
    assert_condition(&gw.conditions, "Programmed", true, "");
}

#[test]
fn gateway_secret_missing_reference_grant() {
    // GatewaySecretMissingReferenceGrant.
    let mut cluster = Cluster::upstream(&["gateway-secret-missing-reference-grant"]);
    let t = cluster.translate();
    let gw = gateway(&t, INFRA, "gateway-secret-missing-reference-grant");
    for name in ["https", "https-nonexistent-secret"] {
        assert_listener(gw, name, &["HTTPRoute"], 0);
        assert_condition(
            &listener(gw, name).conditions,
            "ResolvedRefs",
            false,
            "RefNotPermitted",
        );
    }
    assert_condition(&gw.conditions, "Programmed", true, "");
}

#[test]
fn gateway_secret_reference_grant_all_in_namespace() {
    // GatewaySecretReferenceGrantAllInNamespace.
    let r = router(&["gateway-secret-reference-grant-all-in-namespace"]);
    let gw = gateway(
        &r.translation,
        INFRA,
        "gateway-secret-reference-grant-all-in-namespace",
    );
    assert_listener(gw, "https", &["HTTPRoute"], 0);
    let l = listener(gw, "https");
    assert_condition(&l.conditions, "Programmed", true, "Programmed");
    assert_condition(&l.conditions, "ResolvedRefs", true, "");
    assert!(
        r.translation
            .secrets
            .contains(&(WEB.to_owned(), "certificate".to_owned()))
    );
}

#[test]
fn gateway_secret_reference_grant_specific() {
    // GatewaySecretReferenceGrantSpecific.
    let r = router(&["gateway-secret-reference-grant-specific"]);
    let gw = gateway(
        &r.translation,
        INFRA,
        "gateway-secret-reference-grant-specific",
    );
    assert_listener(gw, "https", &["HTTPRoute"], 0);
    let l = listener(gw, "https");
    assert_condition(&l.conditions, "Programmed", true, "Programmed");
    assert_condition(&l.conditions, "ResolvedRefs", true, "");
}

#[test]
fn gateway_with_attached_routes() {
    // GatewayWithAttachedRoutes.
    let r = router(&["gateway-with-attached-routes"]);
    let t = &r.translation;
    let gw = gateway(t, INFRA, "gateway-with-one-attached-route");
    assert_listener(gw, "http", &["HTTPRoute"], 1);
    assert_condition(&listener(gw, "http").conditions, "Accepted", true, "");
    assert_condition(&listener(gw, "http").conditions, "ResolvedRefs", true, "");
    let gw = gateway(t, INFRA, "gateway-with-two-attached-routes");
    assert_listener(gw, "http", &["HTTPRoute"], 2);
    let p = parent(
        t,
        Http,
        (INFRA, "http-route-not-accepted"),
        (INFRA, "gateway-with-two-attached-routes"),
    );
    assert_condition(
        &p.conditions,
        "Accepted",
        false,
        "NoMatchingListenerHostname",
    );
    // attachedRoutes is set even when the listener's references do not resolve.
    let gw = gateway(
        t,
        INFRA,
        "unresolved-gateway-with-one-attached-unresolved-route",
    );
    assert_listener(gw, "tls", &["HTTPRoute"], 1);
    assert_condition(&listener(gw, "tls").conditions, "Programmed", false, "");
    assert_condition(&listener(gw, "tls").conditions, "ResolvedRefs", false, "");
    assert_resolved(
        t,
        Http,
        (INFRA, "http-route-4"),
        (
            INFRA,
            "unresolved-gateway-with-one-attached-unresolved-route",
        ),
        false,
        "",
    );
}

#[test]
fn gateway_with_attached_routes_with_port_8080() {
    // GatewayWithAttachedRoutesWithPort8080.
    let r = router(&["gateway-with-attached-routes-with-port-8080"]);
    let gw = gateway(
        &r.translation,
        INFRA,
        "gateway-with-two-listeners-and-one-attached-route",
    );
    assert_listener(gw, "http-unattached", &["HTTPRoute"], 0);
    assert_listener(gw, "http", &["HTTPRoute"], 1);
    for name in ["http", "http-unattached"] {
        assert_condition(&listener(gw, name).conditions, "Accepted", true, "");
        assert_condition(&listener(gw, name).conditions, "ResolvedRefs", true, "");
    }
    let gw_key = (INFRA, "gateway-with-two-listeners-and-one-attached-route");
    expect(&r, gw_key, 80, &get("/"), &v1());
    expect(&r, gw_key, 8080, &get("/"), &Outcome::NotFound);
}

// ---------------------------------------------------------------------------------------
// HTTPRoute tests (core).

#[test]
fn httproute_simple_same_namespace() {
    // HTTPRouteSimpleSameNamespace.
    let r = router(&["httproute-simple-same-namespace"]);
    let route = (INFRA, "gateway-conformance-infra-test");
    assert_accepted(&r.translation, Http, route, SAME);
    assert_resolved(&r.translation, Http, route, SAME, true, "ResolvedRefs");
    expect(&r, SAME, 80, &get("/"), &v1());
}

#[test]
fn httproute_cross_namespace() {
    // HTTPRouteCrossNamespace.
    let r = router(&["httproute-cross-namespace"]);
    let gw = (INFRA, "backend-namespaces");
    assert_accepted(&r.translation, Http, (WEB, "cross-namespace"), gw);
    assert_resolved(&r.translation, Http, (WEB, "cross-namespace"), gw, true, "");
    expect(&r, gw, 80, &get("/"), &backends(&["web-backend"]));
}

#[test]
fn httproute_disallowed_kind() {
    // HTTPRouteDisallowedKind.
    let r = router(&["httproute-disallowed-kind"]);
    let t = &r.translation;
    let gw = (INFRA, "tlsroutes-only");
    let route = (INFRA, "disallowed-kind");
    assert_resolved(t, Http, route, gw, true, "");
    let p = parents(t, Http, INFRA, "disallowed-kind");
    assert_eq!(p.len(), 1);
    assert_condition(&p[0].conditions, "Accepted", false, "NotAllowedByListeners");
    assert_listener(gateway(t, INFRA, "tlsroutes-only"), "tls", &["TLSRoute"], 0);
}

#[test]
fn httproute_exact_path_matching() {
    // HTTPRouteExactPathMatching.
    let r = router(&["httproute-exact-path-matching"]);
    assert_accepted(&r.translation, Http, (INFRA, "exact-matching"), SAME);
    for (path, outcome) in [
        ("/one", v1()),
        ("/two", v2()),
        ("/", Outcome::NotFound),
        ("/one/example", Outcome::NotFound),
        ("/two/", Outcome::NotFound),
        ("/Two", Outcome::NotFound),
    ] {
        expect(&r, SAME, 80, &get(path), &outcome);
    }
}

#[test]
fn httproute_header_matching() {
    // HTTPRouteHeaderMatching.
    let r = router(&["httproute-header-matching"]);
    assert_accepted(&r.translation, Http, (INFRA, "header-matching"), SAME);
    let cases: &[(&[(&str, &str)], Outcome)] = &[
        (&[("Version", "one")], v1()),
        (&[("Version", "two")], v2()),
        (&[("Version", "two"), ("Color", "orange")], v1()),
        (&[("Version", "two"), ("Color", "blue")], v2()),
        (&[("Color", "orange")], Outcome::NotFound),
        (&[("Some-Other-Header", "one")], Outcome::NotFound),
        (&[("Color", "blue")], v1()),
        (&[("Color", "green")], v1()),
        (&[("Color", "red")], v2()),
        (&[("Color", "yellow")], v2()),
        (&[("Color", "purple")], Outcome::NotFound),
    ];
    for (headers, outcome) in cases {
        expect(&r, SAME, 80, &with_headers("/", headers), outcome);
    }
}

#[test]
fn httproute_hostname_intersection() {
    // HTTPRouteHostnameIntersection.
    let r = router(&["httproute-hostname-intersection"]);
    let t = &r.translation;
    let gw = (INFRA, "httproute-hostname-intersection");
    for route in [
        "specific-host-matches-listener-specific-host",
        "specific-host-matches-listener-wildcard-host",
        "wildcard-host-matches-listener-specific-host",
        "wildcard-host-matches-listener-wildcard-host",
    ] {
        assert_accepted(t, Http, (INFRA, route), gw);
        assert_resolved(t, Http, (INFRA, route), gw, true, "");
    }
    let cases = [
        ("very.specific.com", "/s1", v1()),
        ("very.specific.com:1234", "/s1", v1()),
        ("non.matching.com", "/s1", Outcome::NotFound),
        ("foo.nonmatchingwildcard.io", "/s1", Outcome::NotFound),
        ("foo.wildcard.io", "/s1", Outcome::NotFound),
        (
            "very.specific.com",
            "/non-matching-prefix",
            Outcome::NotFound,
        ),
        ("foo.wildcard.io", "/s2", v2()),
        ("bar.wildcard.io", "/s2", v2()),
        ("foo.bar.wildcard.io", "/s2", v2()),
        ("non.matching.com", "/s2", Outcome::NotFound),
        ("wildcard.io", "/s2", Outcome::NotFound),
        ("very.specific.com", "/s2", Outcome::NotFound),
        ("foo.wildcard.io", "/non-matching-prefix", Outcome::NotFound),
        ("very.specific.com", "/s3", v3()),
        ("non.matching.com", "/s3", Outcome::NotFound),
        ("foo.specific.com", "/s3", Outcome::NotFound),
        ("foo.wildcard.io", "/s3", Outcome::NotFound),
        (
            "very.specific.com",
            "/non-matching-prefix",
            Outcome::NotFound,
        ),
        ("foo.anotherwildcard.io", "/s4", v1()),
        ("bar.anotherwildcard.io", "/s4", v1()),
        ("foo.bar.anotherwildcard.io", "/s4", v1()),
        ("anotherwildcard.io", "/s4", Outcome::NotFound),
        ("foo.wildcard.io", "/s4", Outcome::NotFound),
        ("very.specific.com", "/s4", Outcome::NotFound),
        (
            "foo.anotherwildcard.io",
            "/non-matching-prefix",
            Outcome::NotFound,
        ),
        // Routes that do not intersect.
        ("specific.but.wrong.com", "/s5", Outcome::NotFound),
        ("wildcard.io", "/s5", Outcome::NotFound),
    ];
    for (h, path, outcome) in cases {
        expect(&r, gw, 80, &host(h, path), &outcome);
    }
    let p = parent(t, Http, (INFRA, "no-intersecting-hosts"), gw);
    assert_condition(
        &p.conditions,
        "Accepted",
        false,
        "NoMatchingListenerHostname",
    );
    let g = gateway(t, INFRA, "httproute-hostname-intersection");
    assert_listener(g, "listener-1", &["HTTPRoute"], 2);
    assert_listener(g, "listener-2", &["HTTPRoute"], 1);
    assert_listener(g, "listener-3", &["HTTPRoute"], 1);
    // A listener without a host name.
    let all = (INFRA, "httproute-hostname-intersection-all");
    assert_accepted(t, Http, (INFRA, "httproute-hostname-intersection-all"), all);
    for (h, outcome) in [
        ("first.com", v2()),
        ("sub.first.com", v2()),
        ("second.com", v2()),
        ("sub.second.com", v2()),
        ("third.com", Outcome::NotFound),
        ("sub.third.com", Outcome::NotFound),
    ] {
        expect(&r, all, 80, &host(h, "/"), &outcome);
    }
}

#[test]
fn httproute_https_listener() {
    // HTTPRouteHTTPSListener.
    let r = router(&["httproute-https-listener"]);
    let t = &r.translation;
    let gw = (INFRA, "same-namespace-with-https-listener");
    for route in ["httproute-https-test", "httproute-https-test-no-hostname"] {
        assert_accepted(t, Http, (INFRA, route), gw);
        assert_resolved(t, Http, (INFRA, route), gw, true, "");
    }
    expect(&r, gw, 443, &host("example.org", "/"), &v1());
    expect(
        &r,
        gw,
        443,
        &host("unknown-example.org", "/"),
        &Outcome::NotFound,
    );
    expect(&r, gw, 443, &host("second-example.org", "/"), &v2());
}

#[test]
fn httproute_invalid_backend_ref_unknown_kind() {
    // HTTPRouteInvalidBackendRefUnknownKind.
    let r = router(&["httproute-invalid-backendref-unknown-kind"]);
    let route = (INFRA, "invalid-backend-ref-unknown-kind");
    assert_accepted(&r.translation, Http, route, SAME);
    assert_resolved(&r.translation, Http, route, SAME, false, "InvalidKind");
    expect(&r, SAME, 80, &get("/v2"), &Outcome::Status(500));
}

#[test]
fn httproute_invalid_cross_namespace_backend_ref() {
    // HTTPRouteInvalidCrossNamespaceBackendRef.
    let r = router(&["httproute-invalid-cross-namespace-backend-ref"]);
    let route = (INFRA, "invalid-cross-namespace-backend-ref");
    assert_accepted(&r.translation, Http, route, SAME);
    assert_resolved(&r.translation, Http, route, SAME, false, "RefNotPermitted");
    expect(&r, SAME, 80, &get("/"), &Outcome::Status(500));
}

#[test]
fn httproute_invalid_cross_namespace_parent_ref() {
    // HTTPRouteInvalidCrossNamespaceParentRef.
    let r = router(&["httproute-invalid-cross-namespace-parent-ref"]);
    let t = &r.translation;
    let route = (WEB, "invalid-cross-namespace-parent-ref");
    assert_resolved(t, Http, route, SAME, true, "");
    let p = parents(t, Http, WEB, "invalid-cross-namespace-parent-ref");
    assert_eq!(p.len(), 1);
    assert_condition(&p[0].conditions, "Accepted", false, "NotAllowedByListeners");
    assert_eq!(
        listener(gateway(t, INFRA, "same-namespace"), "http").attached_routes,
        0
    );
}

#[test]
fn httproute_invalid_nonexistent_backend_ref() {
    // HTTPRouteInvalidNonExistentBackendRef.
    let r = router(&["httproute-invalid-nonexistent-backendref"]);
    let route = (INFRA, "invalid-nonexistent-backend-ref");
    assert_accepted(&r.translation, Http, route, SAME);
    assert_resolved(&r.translation, Http, route, SAME, false, "BackendNotFound");
    expect(&r, SAME, 80, &get("/"), &Outcome::Status(500));
}

#[test]
fn httproute_invalid_parent_ref_not_matching_section_name() {
    // HTTPRouteInvalidParentRefNotMatchingSectionName.
    let r = router(&["httproute-invalid-parentref-not-matching-section-name"]);
    let t = &r.translation;
    let p = parents(
        t,
        Http,
        INFRA,
        "httproute-listener-not-matching-section-name",
    );
    assert_eq!(p.len(), 1);
    assert_condition(&p[0].conditions, "Accepted", false, "NoMatchingParent");
    assert_eq!(
        listener(gateway(t, INFRA, "same-namespace"), "http").attached_routes,
        0
    );
}

#[test]
fn httproute_invalid_reference_grant() {
    // HTTPRouteInvalidReferenceGrant.
    let r = router(&["httproute-invalid-reference-grant"]);
    let route = (INFRA, "reference-grant");
    assert_accepted(&r.translation, Http, route, SAME);
    assert_resolved(&r.translation, Http, route, SAME, false, "RefNotPermitted");
    expect(&r, SAME, 80, &get("/"), &Outcome::Status(500));
}

#[test]
fn httproute_listener_hostname_matching() {
    // HTTPRouteListenerHostnameMatching.
    let r = router(&["httproute-listener-hostname-matching"]);
    let gw = (INFRA, "httproute-listener-hostname-matching");
    for route in ["backend-v1", "backend-v2", "backend-v3"] {
        assert_accepted(&r.translation, Http, (INFRA, route), gw);
    }
    for (h, outcome) in [
        ("bar.com", v1()),
        ("foo.bar.com", v2()),
        ("baz.bar.com", v3()),
        ("boo.bar.com", v3()),
        ("multiple.prefixes.bar.com", v3()),
        ("multiple.prefixes.foo.com", v3()),
        ("foo.com", Outcome::NotFound),
        ("no.matching.host", Outcome::NotFound),
    ] {
        expect(&r, gw, 80, &host(h, "/"), &outcome);
    }
}

#[test]
fn httproute_matching_across_routes() {
    // HTTPRouteMatchingAcrossRoutes.
    let r = router(&["httproute-matching-across-routes"]);
    for route in ["matching-part1", "matching-part2"] {
        assert_accepted(&r.translation, Http, (INFRA, route), SAME);
    }
    let one: &[(&str, &str)] = &[("Version", "one")];
    let two: &[(&str, &str)] = &[("Version", "two")];
    let none: &[(&str, &str)] = &[];
    for (h, path, headers, outcome) in [
        ("example.com", "/", none, v1()),
        ("example.com", "/example", none, v1()),
        ("example.net", "/example", none, v1()),
        ("example.com", "/example", one, v1()),
        ("example.com", "/v2", none, v2()),
        ("example.net", "/v2", none, v1()),
        ("example.com", "/v2/example", none, v2()),
        ("example.com", "/", two, v2()),
    ] {
        let request = Request {
            host: h,
            path,
            method: "GET",
            headers,
        };
        expect(&r, SAME, 80, &request, &outcome);
    }
}

#[test]
fn httproute_matching() {
    // HTTPRouteMatching.
    let r = router(&["httproute-matching"]);
    assert_accepted(&r.translation, Http, (INFRA, "matching"), SAME);
    let none: &[(&str, &str)] = &[];
    for (path, headers, outcome) in [
        ("/", none, v1()),
        ("/example", none, v1()),
        ("/", &[("Version", "one")][..], v1()),
        ("/v2", none, v2()),
        ("/v2/example", none, v2()),
        ("/", &[("Version", "two")][..], v2()),
        ("/v2/", none, v2()),
        ("/v2example", none, v1()),
        ("/foo/v2/example", none, v1()),
    ] {
        expect(&r, SAME, 80, &with_headers(path, headers), &outcome);
    }
}

#[test]
fn httproute_multiple_gateways() {
    // HTTPRouteMultipleGateways.
    let r = router(&["httproute-multiple-gateways"]);
    let t = &r.translation;
    let all = (INFRA, "all-namespaces");
    for (gw, route) in [
        (SAME, "multiple-gateways-shared-route"),
        (SAME, "same-namespace-dedicated-route"),
        (all, "multiple-gateways-shared-route"),
        (all, "all-namespaces-dedicated-route"),
    ] {
        assert_accepted(t, Http, (INFRA, route), gw);
    }
    expect(&r, SAME, 80, &get("/shared"), &v1());
    expect(&r, SAME, 80, &get("/"), &v2());
    expect(&r, all, 80, &get("/shared"), &v1());
    expect(&r, all, 80, &get("/"), &v3());
}

#[test]
fn httproute_observed_generation_bump() {
    // HTTPRouteObservedGenerationBump.
    let mut cluster = Cluster::upstream(&["httproute-observed-generation-bump"]);
    let route = (INFRA, "observed-generation-bump");
    let t = cluster.translate();
    assert_accepted(&t, Http, route, SAME);
    let key = (INFRA.to_owned(), "observed-generation-bump".to_owned());
    let r = cluster.inventory.http_routes.get_mut(&key).unwrap();
    r.spec.rules[0].backend_refs[0].backend.reference.name = "infra-backend-v2".into();
    r.metadata.generation = Some(2);
    let t = cluster.translate();
    let p = parent(&t, Http, route, SAME);
    assert_condition_gen(&p.conditions, "Accepted", true, "", 2);
    assert_condition_gen(&p.conditions, "ResolvedRefs", true, "", 2);
    let r = Router::compile(&cluster, t);
    expect(&r, SAME, 80, &get("/"), &v2());
}

#[test]
fn httproute_partially_invalid_via_invalid_reference_grant() {
    // HTTPRoutePartiallyInvalidViaInvalidReferenceGrant.
    let r = router(&["httproute-partially-invalid-via-invalid-reference-grant"]);
    let route = (INFRA, "invalid-reference-grant");
    assert_accepted(&r.translation, Http, route, SAME);
    assert_resolved(&r.translation, Http, route, SAME, false, "RefNotPermitted");
    expect(&r, SAME, 80, &get("/v2"), &Outcome::Status(500));
    expect(&r, SAME, 80, &get("/"), &backends(&["app-backend-v1"]));
}

#[test]
fn httproute_path_match_order() {
    // HTTPRoutePathMatchOrder.
    let r = router(&["httproute-path-match-order"]);
    assert_accepted(&r.translation, Http, (INFRA, "path-matching-order"), SAME);
    for (path, outcome) in [
        ("/match/exact/one", v3()),
        ("/match/exact", v2()),
        ("/match", v1()),
        ("/match/prefix/one/any", v2()),
        ("/match/prefix/any", v1()),
        ("/match/any", v3()),
    ] {
        expect(&r, SAME, 80, &get(path), &outcome);
    }
}

#[test]
fn httproute_preserve_foreign_status() {
    // HTTPRoutePreserveForeignStatus (provisional): the translator writes an entry for our
    // Gateway only, none for `unmanaged-gateway`; the runtime merges it with the stored
    // entries of other controllers.
    let r = router(&["httproute-preserve-foreign-status"]);
    let p = parents(&r.translation, Http, INFRA, "preserve-foreign-status");
    assert_eq!(p.len(), 1);
    assert_eq!(p[0].parent_ref.name, "same-namespace");
    assert_accepted(
        &r.translation,
        Http,
        (INFRA, "preserve-foreign-status"),
        SAME,
    );
}

#[test]
fn httproute_redirect_host_and_status() {
    // HTTPRouteRedirectHostAndStatus.
    let r = router(&["httproute-redirect-host-and-status"]);
    assert_accepted(
        &r.translation,
        Http,
        (INFRA, "redirect-host-and-status"),
        SAME,
    );
    assert_resolved(
        &r.translation,
        Http,
        (INFRA, "redirect-host-and-status"),
        SAME,
        true,
        "",
    );
    for (path, status) in [("/hostname-redirect", 302), ("/host-and-status", 301)] {
        let routed = r.route(SAME, 80, &get(path));
        let redirect = routed.redirect().unwrap();
        assert_eq!(redirect.status, Some(status));
        assert_eq!(redirect.hostname.as_deref(), Some("example.org"));
        // No scheme and no port: the listener's port.
        assert_eq!(redirect.port, Some(80));
        // Executed: what the client receives.
        assert_eq!(
            r.execute(SAME, 80, &get(path)),
            Some((status, Some(format!("http://example.org{path}")))),
            "{path}"
        );
    }
}

#[test]
fn httproute_reference_grant() {
    // HTTPRouteReferenceGrant: allowed, then 500 once the grant is deleted.
    let mut cluster = Cluster::upstream(&["httproute-reference-grant"]);
    let r = Router::new(&mut cluster);
    let route = (INFRA, "reference-grant");
    assert_accepted(&r.translation, Http, route, SAME);
    assert_resolved(&r.translation, Http, route, SAME, true, "");
    expect(&r, SAME, 80, &get("/"), &backends(&["web-backend"]));
    cluster
        .inventory
        .reference_grants
        .remove(&(WEB.to_owned(), "reference-grant".to_owned()));
    let r = Router::new(&mut cluster);
    expect(&r, SAME, 80, &get("/"), &Outcome::Status(500));
    assert_resolved(&r.translation, Http, route, SAME, false, "RefNotPermitted");
}

#[test]
fn httproute_rule_order() {
    // HTTPRouteRuleOrder.
    let r = router(&["httproute-rule-order"]);
    let t = &r.translation;
    assert_accepted(t, Http, (INFRA, "rule-order"), SAME);
    assert_accepted(t, Http, (INFRA, "rule-order-invalid-backend"), SAME);
    assert_resolved(t, Http, (INFRA, "rule-order"), SAME, true, "");
    assert_resolved(
        t,
        Http,
        (INFRA, "rule-order-invalid-backend"),
        SAME,
        false,
        "BackendNotFound",
    );
    let headers: &[(&str, &str)] = &[("x-color", "blue"), ("x-version", "one")];
    expect(&r, SAME, 80, &with_headers("/rule-order", headers), &v1());
    expect(
        &r,
        SAME,
        80,
        &get("/rule-order-invalid-backend"),
        &Outcome::Status(500),
    );
}

#[test]
fn httproute_service_types() {
    // HTTPRouteServiceTypes: manual EndpointSlices (IPv4 and IPv6), headless Services.
    let r = router(&["httproute-service-types"]);
    assert_accepted(&r.translation, Http, (INFRA, "service-types"), SAME);
    assert_resolved(
        &r.translation,
        Http,
        (INFRA, "service-types"),
        SAME,
        true,
        "",
    );
    for path in [
        "/manual-endpointslices",
        "/headless-manual-endpointslices",
        "/headless",
    ] {
        expect(&r, SAME, 80, &get(path), &v1());
    }
    // Both address families of the manual slices are in the pool.
    let routed = r.route(SAME, 80, &get("/manual-endpointslices"));
    let service = &r.translation.fragment.services[routed.route.unwrap().service.as_ref().unwrap()];
    assert!(
        service
            .backends
            .iter()
            .any(|b| b.address.to_string().starts_with('['))
    );
    assert!(
        service
            .backends
            .iter()
            .any(|b| b.address.to_string().starts_with("10."))
    );
}

#[test]
fn httproute_no_backend_refs() {
    // HTTPRouteNoBackendRefs.
    let r = router(&["httproute-omitted-backendrefs"]);
    let route = (INFRA, "omitted-backendrefs");
    assert_accepted(&r.translation, Http, route, SAME);
    assert_resolved(&r.translation, Http, route, SAME, true, "");
    expect(&r, SAME, 80, &get("/forward"), &v1());
    expect(
        &r,
        SAME,
        80,
        &get("/omitted-no-forward"),
        &Outcome::Status(500),
    );
    expect(
        &r,
        SAME,
        80,
        &get("/empty-no-forward"),
        &Outcome::Status(500),
    );
}

#[test]
fn httproute_weight() {
    // HTTPRouteWeight: 70/30/0.
    let r = router(&["httproute-weight"]);
    let route = (INFRA, "weighted-backends");
    assert_accepted(&r.translation, Http, route, SAME);
    assert_resolved(&r.translation, Http, route, SAME, true, "");
    let routed = r.route(SAME, 80, &get("/"));
    assert_eq!(routed.split, vec![(v1(), 70), (v2(), 30)]);
}

// ---------------------------------------------------------------------------------------
// GRPCRoute tests (core).

#[test]
fn grpc_exact_method_matching() {
    // GRPCExactMethodMatching.
    let r = router(&["grpcroute-exact-method-matching"]);
    assert_accepted(&r.translation, Grpc, (INFRA, "exact-matching"), SAME);
    let svc = "/gateway_api_conformance.echo_basic.grpcecho.GrpcEcho";
    let post = |path: &'static str| Request {
        host: "",
        path,
        method: "POST",
        headers: &[("content-type", "application/grpc")],
    };
    expect(
        &r,
        SAME,
        80,
        &post(leak(format!("{svc}/Echo"))),
        &backends(&["grpc-infra-backend-v1"]),
    );
    expect(
        &r,
        SAME,
        80,
        &post(leak(format!("{svc}/EchoTwo"))),
        &backends(&["grpc-infra-backend-v2"]),
    );
    // Unimplemented: gRPC maps the 404 to it.
    expect(
        &r,
        SAME,
        80,
        &post(leak(format!("{svc}/EchoThree"))),
        &Outcome::NotFound,
    );
    // GRPCRoute backends speak h2c.
    let routed = r.route(SAME, 80, &post(leak(format!("{svc}/Echo"))));
    let service = &r.translation.fragment.services[routed.route.unwrap().service.as_ref().unwrap()];
    assert_eq!(service.scheme, rdock_model::service::Scheme::H2c);
}

fn leak(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

#[test]
fn grpc_route_header_matching() {
    // GRPCRouteHeaderMatching.
    let r = router(&["grpcroute-header-matching"]);
    assert_accepted(&r.translation, Grpc, (INFRA, "grpc-header-matching"), SAME);
    let g1 = backends(&["grpc-infra-backend-v1"]);
    let g2 = backends(&["grpc-infra-backend-v2"]);
    let cases: &[(&[(&str, &str)], Outcome)] = &[
        (&[("Version", "one")], g1.clone()),
        (&[("Version", "two")], g2.clone()),
        (&[("Version", "two"), ("Color", "orange")], g1.clone()),
        (&[("Version", "two"), ("Color", "blue")], g2.clone()),
        (&[("Color", "orange")], Outcome::NotFound),
        (&[("Some-Other-Header", "one")], Outcome::NotFound),
        (&[("Color", "blue")], g1.clone()),
        (&[("Color", "green")], g1.clone()),
        (&[("Color", "red")], g2.clone()),
        (&[("Color", "yellow")], g2),
        (&[("Color", "purple")], Outcome::NotFound),
    ];
    for (headers, outcome) in cases {
        let request = Request {
            host: "",
            path: "/gateway_api_conformance.echo_basic.grpcecho.GrpcEcho/Echo",
            method: "POST",
            headers,
        };
        expect(&r, SAME, 80, &request, outcome);
    }
}

#[test]
fn grpc_route_listener_hostname_matching() {
    // GRPCRouteListenerHostnameMatching.
    let r = router(&["grpcroute-listener-hostname-matching"]);
    let gw = (INFRA, "grpcroute-listener-hostname-matching");
    for route in ["backend-v1", "backend-v2", "backend-v3"] {
        assert_accepted(&r.translation, Grpc, (INFRA, route), gw);
    }
    let echo = "/gateway_api_conformance.echo_basic.grpcecho.GrpcEcho/Echo";
    for (authority, outcome) in [
        ("bar.com", backends(&["grpc-infra-backend-v1"])),
        ("foo.bar.com", backends(&["grpc-infra-backend-v2"])),
        ("baz.bar.com", backends(&["grpc-infra-backend-v3"])),
        ("boo.bar.com", backends(&["grpc-infra-backend-v3"])),
        (
            "multiple.prefixes.bar.com",
            backends(&["grpc-infra-backend-v3"]),
        ),
        (
            "multiple.prefixes.foo.com",
            backends(&["grpc-infra-backend-v3"]),
        ),
        ("foo.com", Outcome::NotFound),
        ("no.matching.host", Outcome::NotFound),
    ] {
        expect(&r, gw, 80, &host(authority, echo), &outcome);
    }
}

#[test]
fn grpc_route_multiple_gateways() {
    // GRPCRouteMultipleGateways.
    let r = router(&["grpcroute-multiple-gateways"]);
    let all = (INFRA, "all-namespaces");
    for (gw, route) in [
        (SAME, "multiple-gateways-shared-route"),
        (SAME, "same-namespace-dedicated-route"),
        (all, "multiple-gateways-shared-route"),
        (all, "all-namespaces-dedicated-route"),
    ] {
        assert_accepted(&r.translation, Grpc, (INFRA, route), gw);
    }
    let svc = "/gateway_api_conformance.echo_basic.grpcecho.GrpcEcho";
    let echo = leak(format!("{svc}/Echo"));
    let two = leak(format!("{svc}/EchoTwo"));
    expect(
        &r,
        SAME,
        80,
        &get(echo),
        &backends(&["grpc-infra-backend-v1"]),
    );
    expect(
        &r,
        SAME,
        80,
        &get(two),
        &backends(&["grpc-infra-backend-v2"]),
    );
    expect(
        &r,
        all,
        80,
        &get(echo),
        &backends(&["grpc-infra-backend-v1"]),
    );
    expect(
        &r,
        all,
        80,
        &get(two),
        &backends(&["grpc-infra-backend-v3"]),
    );
}

#[test]
fn grpc_route_weight() {
    // GRPCRouteWeight.
    let r = router(&["grpcroute-weight"]);
    let routed = r.route(
        SAME,
        80,
        &get("/gateway_api_conformance.echo_basic.grpcecho.GrpcEcho/Echo"),
    );
    assert_eq!(
        routed.split,
        vec![
            (backends(&["grpc-infra-backend-v1"]), 70),
            (backends(&["grpc-infra-backend-v2"]), 30)
        ]
    );
}

// ---------------------------------------------------------------------------------------
// TLSRoute tests (core).

const ABC: Option<&str> = Some("abc.example.com");

#[test]
fn tls_route_simple_same_namespace() {
    // TLSRouteSimpleSameNamespace.
    let r = router(&["tlsroute-simple-same-namespace"]);
    let gw = (INFRA, "gateway-tlsroute");
    assert_accepted(
        &r.translation,
        Tls,
        (INFRA, "gateway-conformance-infra-test"),
        gw,
    );
    assert_eq!(
        r.connect(gw, 443, ABC),
        Some(["tcp-backend".to_owned()].into())
    );
    assert_eq!(r.connect(gw, 443, Some("other.org")), None);
    let route = r.translation.fragment.tcp_routes.values().next().unwrap();
    assert!(route.tls.unwrap().passthrough);
}

#[test]
fn tls_route_hostname_intersection() {
    // TLSRouteHostnameIntersection.
    let r = router(&["tlsroute-hostname-intersection"]);
    let t = &r.translation;
    let tls1 = Some(["tls-backend".to_owned()].into());
    let tls2 = Some(["tls-backend-2".to_owned()].into());
    let x1 = (INFRA, "gw-tlsroute-exact-hostname-x-1");
    assert_accepted(
        t,
        Tls,
        (INFRA, "tlsroute-more-specific-wc-hostname-x-1"),
        x1,
    );
    assert_eq!(r.connect(x1, 443, ABC), tls1);
    assert_eq!(r.connect(x1, 443, Some("non.matching.com")), None);
    for (gw, routes) in [
        (
            "gw-tlsroute-more-specific-wc-hostname-x-2",
            [
                "tlsroute-exact-hostname-x-2",
                "tlsroute-less-specific-wc-hostname-x-2",
            ],
        ),
        (
            "gw-tlsroute-less-specific-wc-hostname-x-3",
            [
                "tlsroute-exact-hostname-x-3",
                "tlsroute-more-specific-wc-hostname-x-3",
            ],
        ),
        (
            "gw-tlsroute-empty-hostname-x-4",
            [
                "tlsroute-exact-hostname-x-4",
                "tlsroute-less-specific-wc-hostname-x-4",
            ],
        ),
    ] {
        let gw = (INFRA, gw);
        for route in routes {
            assert_accepted(t, Tls, (INFRA, route), gw);
            assert_resolved(t, Tls, (INFRA, route), gw, true, "");
        }
        assert_eq!(r.connect(gw, 443, ABC), tls1, "{gw:?}");
        assert_eq!(
            r.connect(gw, 443, Some("other.example.com")),
            tls2,
            "{gw:?}"
        );
        assert_eq!(r.connect(gw, 443, Some("non.matching.org")), None, "{gw:?}");
    }
}

#[test]
fn tls_route_invalid_backend_ref_nonexistent() {
    // TLSRouteInvalidBackendRefNonexistent.
    let r = router(&["tlsroute-invalid-backendref-nonexistent"]);
    let gw = (INFRA, "gateway-tlsroute-invalid-backend-ref-nonexistent");
    let route = (INFRA, "invalid-backend-ref-nonexistent");
    assert_accepted(&r.translation, Tls, route, gw);
    assert_resolved(&r.translation, Tls, route, gw, false, "BackendNotFound");
    assert_eq!(r.connect(gw, 443, Some("example.com")), None);
}

#[test]
fn tls_route_invalid_backend_ref_unknown_kind() {
    // TLSRouteInvalidBackendRefUnknownKind.
    let r = router(&["tlsroute-invalid-backendref-unknown-kind"]);
    let gw = (INFRA, "gateway-tlsroute-invalid-backend-ref-unknown-kind");
    let route = (INFRA, "invalid-backend-ref-unknown-kind");
    assert_accepted(&r.translation, Tls, route, gw);
    assert_resolved(&r.translation, Tls, route, gw, false, "InvalidKind");
    assert_eq!(r.connect(gw, 443, Some("example.com")), None);
}

#[test]
fn tls_route_invalid_no_matching_listener_hostname() {
    // TLSRouteInvalidNoMatchingListenerHostname.
    let r = router(&["tlsroute-invalid-no-matching-listener-hostname"]);
    let t = &r.translation;
    for (route, gw) in [
        ("tlsroute-hostname-mismatch-1", "gateway-tls-exact-hostname"),
        (
            "tlsroute-hostname-mismatch-2",
            "gateway-tls-wildcard-hostname",
        ),
    ] {
        let p = parents(t, Tls, INFRA, route);
        assert_eq!(p.len(), 1);
        assert_condition(
            &p[0].conditions,
            "Accepted",
            false,
            "NoMatchingListenerHostname",
        );
        assert_eq!(listener(gateway(t, INFRA, gw), "tls").attached_routes, 0);
    }
}

#[test]
fn tls_route_invalid_no_matching_listener() {
    // TLSRouteInvalidNoMatchingListener.
    let r = router(&["tlsroute-invalid-no-matching-listener"]);
    let t = &r.translation;
    for (route, reason) in [
        (
            "tlsroute-not-allowed-protocol-http",
            "NotAllowedByListeners",
        ),
        (
            "tlsroute-not-allowed-protocol-https",
            "NotAllowedByListeners",
        ),
        ("tlsroute-no-matching-section-name", "NoMatchingParent"),
    ] {
        let p = parents(t, Tls, INFRA, route);
        assert_eq!(p.len(), 1, "{route}");
        assert_condition(&p[0].conditions, "Accepted", false, reason);
    }
    for gw in ["gateway-tlsroute-http-only", "gateway-tlsroute-https-only"] {
        let g = gateway(t, INFRA, gw);
        assert_eq!(g.listeners.len(), 1);
        assert_eq!(g.listeners[0].attached_routes, 0);
    }
}

#[test]
fn tls_route_invalid_reference_grant() {
    // TLSRouteInvalidReferenceGrant.
    let r = router(&["tlsroute-invalid-reference-grant"]);
    let gw = (INFRA, "gateway-tlsroute-referencegrant");
    let route = (INFRA, "gateway-conformance-infra-test");
    assert_accepted(&r.translation, Tls, route, gw);
    assert_resolved(&r.translation, Tls, route, gw, false, "RefNotPermitted");
}

#[test]
fn tls_route_listener_passthrough_supported_kinds() {
    // TLSRouteListenerPassthroughSupportedKinds.
    let r = router(&["tlsroute-listener-passthrough-supported-kinds"]);
    let gw = gateway(
        &r.translation,
        INFRA,
        "gateway-tlsroute-passthrough-supported-kind",
    );
    assert_listener(gw, "tls-passthrough", &["TLSRoute"], 0);
    assert_eq!(listener(gw, "tls-passthrough").supported_kinds.len(), 1);
    assert_condition(
        &listener(gw, "tls-passthrough").conditions,
        "ResolvedRefs",
        false,
        "InvalidRouteKinds",
    );
}

#[test]
fn tls_route_listener_terminate_not_supported() {
    // TLSRouteListenerTerminateNotSupported.
    let r = router(&["tlsroute-listener-terminate-not-supported"]);
    let gw = gateway(
        &r.translation,
        INFRA,
        "gateway-tlsroute-terminate-unsupported",
    );
    assert_listener(gw, "tls-terminate", &[], 0);
    assert_condition(
        &listener(gw, "tls-terminate").conditions,
        "Accepted",
        false,
        "UnsupportedValue",
    );
}

// ---------------------------------------------------------------------------------------
// UDPRoute: not supported until v0.8.

#[test]
fn udp_routes_are_not_accepted() {
    let r = router(&["udproute-simple"]);
    let t = &r.translation;
    for (route, entries) in &t.status.routes {
        if route.kind == Udp {
            for p in entries {
                let accepted = p.conditions.iter().find(|c| c.kind == "Accepted").unwrap();
                assert!(!accepted.status, "{p:?}");
            }
        }
    }
    for gw in t.status.gateways.values() {
        for l in &gw.listeners {
            if l.conditions
                .iter()
                .any(|c| c.reason == "UnsupportedProtocol")
            {
                assert_eq!(l.supported_kinds.len(), 0);
            }
        }
    }
}

#[allow(dead_code)]
fn unused(_: RouteKind, _: &str) -> (RouteKind, &str) {
    (Tcp, APP)
}

// ---------------------------------------------------------------------------------------
// TCPRoute tests (core of GATEWAY-TCP).

fn tcp(names: &[&str]) -> Option<std::collections::BTreeSet<String>> {
    let set: std::collections::BTreeSet<String> = names.iter().map(|n| (*n).to_owned()).collect();
    (!set.is_empty()).then_some(set)
}

#[test]
fn tcp_route_invalid_backend_ref_nonexistent() {
    // TCPRouteInvalidBackendRefNonexistent.
    let r = router(&["tcproute-invalid-backendref-nonexistent"]);
    let gw = (INFRA, "tcp-gateway-invalid-backend");
    let route = (INFRA, "tcp-route-invalid-backend-ref-nonexistent");
    assert_resolved(&r.translation, Tcp, route, gw, false, "BackendNotFound");
}

#[test]
fn tcp_route_invalid_cross_namespace_backend_ref() {
    // TCPRouteInvalidCrossNamespaceBackendRef.
    let r = router(&["tcproute-invalid-cross-namespace-backend-ref"]);
    let gw = (INFRA, "tcp-invalid-cross-namespace-backend-ref-gateway");
    let route = (INFRA, "tcp-invalid-cross-namespace-backend-ref");
    assert_accepted(&r.translation, Tcp, route, gw);
    assert_resolved(&r.translation, Tcp, route, gw, false, "RefNotPermitted");
}

#[test]
fn tcp_route_invalid_non_tcp_listener() {
    // TCPRouteInvalidNonTCPListener.
    let r = router(&["tcproute-invalid-non-tcp-listener"]);
    let gw = (INFRA, "tcp-mixed-protocol-gateway");
    let p = parent(&r.translation, Tcp, (INFRA, "tcp-route"), gw);
    assert_condition(&p.conditions, "Accepted", false, "NotAllowedByListeners");
    let g = gateway(&r.translation, gw.0, gw.1);
    assert!(g.listeners.iter().all(|l| l.attached_routes == 0));
}

#[test]
fn tcp_route_multiple_routes_attachment() {
    // TCPRouteMultipleRoutesAttachment: both attach, the older one gets the traffic.
    let mut cluster = Cluster::upstream(&["tcproute-multiple-routes-attachment"]);
    let gw = (INFRA, "tcp-multi-route-attach-gateway");
    cluster.apply_yaml(
        "apiVersion: gateway.networking.k8s.io/v1\nkind: TCPRoute\nmetadata: {name: tcproute-attach-newer, namespace: gateway-conformance-infra}\nspec:\n  parentRefs: [{name: tcp-multi-route-attach-gateway, sectionName: tcp}]\n  rules: [{backendRefs: [{name: tcp-attach-backend-2, port: 3000}]}]\n",
    );
    let r = Router::new(&mut cluster);
    let t = &r.translation;
    for route in ["tcproute-attach-older", "tcproute-attach-newer"] {
        let p = parent(t, Tcp, (INFRA, route), gw);
        assert_condition(&p.conditions, "Accepted", true, "Accepted");
    }
    let g = gateway(t, gw.0, gw.1);
    assert_eq!(listener(g, "tcp").attached_routes, 2);
    assert_condition(&listener(g, "tcp").conditions, "Accepted", true, "Accepted");
    let port = cluster_port(&cluster, gw, "tcp");
    assert_eq!(r.connect(gw, port, None), tcp(&["tcp-attach-backend-1"]));
}

fn cluster_port(cluster: &Cluster, gw: (&str, &str), listener: &str) -> u16 {
    cluster.inventory.gateways[&(gw.0.to_owned(), gw.1.to_owned())]
        .spec
        .listeners
        .iter()
        .find(|l| l.name == listener)
        .unwrap()
        .port
}

#[test]
fn tcp_route_parent_ref_attach_all() {
    // TCPRouteParentRefAttachAll.
    let mut cluster = Cluster::upstream(&["tcproute-parentref-attach-all"]);
    let r = Router::new(&mut cluster);
    let gw = (INFRA, "tcp-attach-all-gateway");
    let p = parent(&r.translation, Tcp, (INFRA, "tcp-route-attach-all"), gw);
    assert_condition(&p.conditions, "Accepted", true, "Accepted");
    let route =
        &cluster.inventory.tcp_routes[&(INFRA.to_owned(), "tcp-route-attach-all".to_owned())];
    let backend = route.spec.rules[0].backend_refs[0].reference.name.clone();
    for name in ["one", "two", "three", "four"] {
        let port = cluster_port(&cluster, gw, name);
        assert_eq!(r.connect(gw, port, None), tcp(&[&backend]), "{name}");
    }
}

#[test]
fn tcp_route_parent_ref_port_and_section_name() {
    // TCPRouteParentRefPortAndSectionName.
    let mut cluster = Cluster::upstream(&["tcproute-parentref-port-and-section-name"]);
    let r = Router::new(&mut cluster);
    let gw = (INFRA, "tcp-multi-listener-gateway");
    for (route, listener_name, backend) in [
        ("tcp-route-by-port", "one", "tcp-echo-one"),
        ("tcp-route-by-section", "two", "tcp-echo-two"),
        ("tcp-route-by-section-and-port", "three", "tcp-echo-three"),
    ] {
        let p = parent(&r.translation, Tcp, (INFRA, route), gw);
        assert_condition(&p.conditions, "Accepted", true, "Accepted");
        let port = cluster_port(&cluster, gw, listener_name);
        assert_eq!(r.connect(gw, port, None), tcp(&[backend]), "{route}");
    }
}

#[test]
fn tcp_route_reference_grant() {
    // TCPRouteReferenceGrant: allowed, then refused once the grant is deleted.
    let mut cluster = Cluster::upstream(&["tcproute-reference-grant"]);
    let r = Router::new(&mut cluster);
    let gw = (INFRA, "tcp-reference-grant-gateway");
    let route = (INFRA, "tcp-reference-grant");
    assert_accepted(&r.translation, Tcp, route, gw);
    let port = cluster_port(&cluster, gw, "tcp");
    assert_eq!(
        r.connect(gw, port, None),
        tcp(&["tcp-reference-grant-backend"])
    );
    cluster
        .inventory
        .reference_grants
        .remove(&(WEB.to_owned(), "tcp-reference-grant".to_owned()));
    let r = Router::new(&mut cluster);
    assert_resolved(&r.translation, Tcp, route, gw, false, "RefNotPermitted");
    assert_eq!(r.connect(gw, port, None), None);
}

#[test]
fn tcp_route_weighted_routing() {
    // TCPRouteWeightedRouting: 70/30/0 over two Services of two endpoints each.
    let mut cluster = Cluster::upstream(&["tcproute-weighted-routing"]);
    let r = Router::new(&mut cluster);
    let gw = (INFRA, "tcp-weighted-gateway");
    assert_accepted(&r.translation, Tcp, (INFRA, "tcp-weighted-route"), gw);
    let service = r.translation.fragment.tcp_services.values().next().unwrap();
    let mut share = std::collections::BTreeMap::<String, u32>::new();
    for b in &service.backends {
        let ip = b.address.to_string();
        let ip = ip.rsplit_once(':').unwrap().0.to_owned();
        *share.entry(cluster.pods[&ip].1.clone()).or_default() += b.weight;
    }
    let total: u32 = share.values().sum();
    assert_eq!(share.get("tcp-backend-v3"), None);
    let v1 = f64::from(share["tcp-backend-v1"]) / f64::from(total);
    assert!((v1 - 0.7).abs() < 0.01, "{share:?}");
}

#[test]
fn httproute_request_header_modifier() {
    // HTTPRouteRequestHeaderModifier (core).
    use rdock_model::middleware::Middleware;
    let r = router(&["httproute-request-header-modifier"]);
    let route = (INFRA, "request-header-modifier");
    assert_accepted(&r.translation, Http, route, SAME);
    assert_resolved(&r.translation, Http, route, SAME, true, "");
    let rules = |path: &str| {
        let routed = r.route(SAME, 80, &get(path));
        assert_eq!(routed.outcome, v1(), "{path}");
        match &routed.middlewares[..] {
            [Middleware::Headers(h)] => h.request.clone(),
            other => panic!("{other:?}"),
        }
    };
    assert_eq!(rules("/set").set["X-Header-Set"], "set-overwrites-values");
    assert_eq!(rules("/add").add["X-Header-Add"], "add-appends-values");
    assert_eq!(rules("/remove").remove, vec!["X-Header-Remove".to_owned()]);
    let multiple = rules("/multiple");
    assert_eq!(multiple.set.len(), 2);
    assert_eq!(multiple.add.len(), 3);
    assert_eq!(multiple.remove.len(), 2);
    let case = rules("/case-insensitivity");
    assert_eq!(case.set["X-Header-Set"], "header-set");
}

#[test]
fn every_upstream_manifest_translates_to_a_fragment_that_compiles() {
    // Every test manifest of the suite, with the base manifests: the fragment assembles with
    // nothing left out and compiles without errors, every parentRef of ours has `Accepted`
    // and `ResolvedRefs`, and every condition carries the generation.
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/upstream");
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| {
            std::path::Path::new(n)
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("yaml"))
                && n != "base-manifests.yaml"
        })
        .map(|n| n.trim_end_matches(".yaml").to_owned())
        .collect();
    names.sort();
    assert!(names.len() > 140, "{}", names.len());
    for name in &names {
        let r = router(&[name]);
        let t = &r.translation;
        for (route, entries) in &t.status.routes {
            for entry in entries {
                for kind in ["Accepted", "ResolvedRefs"] {
                    assert!(
                        entry.conditions.iter().any(|c| c.kind == kind),
                        "{name}: {route:?} has no {kind}"
                    );
                }
            }
        }
        let all = t
            .status
            .gateways
            .values()
            .flat_map(|g| {
                g.conditions
                    .iter()
                    .chain(g.listeners.iter().flat_map(|l| &l.conditions))
            })
            .chain(
                t.status
                    .routes
                    .values()
                    .flatten()
                    .flat_map(|p| &p.conditions),
            );
        for c in all {
            assert_eq!(c.observed_generation, Some(1), "{name}: {c:?}");
        }
    }
}

// ---------------------------------------------------------------------------------------
// Not claimed: BackendTLSPolicy (applied, CI pending). ListenerSet: gateway_listenerset.rs.

#[test]
fn backend_tls_policy_sets_https_with_the_policy_hostname_and_ca() {
    // From BackendTLSPolicy (`backendtlspolicy.go`), translation only.
    let r = router(&["backendtlspolicy"]);
    let t = &r.translation;
    assert_accepted(t, Http, (INFRA, "backendtlspolicy"), SAME);
    let request = Request {
        host: "abc.example.com",
        path: "/backendtlspolicy",
        method: "GET",
        headers: &[],
    };
    let routed = r.route(SAME, 80, &request);
    assert_eq!(routed.outcome, backends(&["tls-backend"]));
    let service = &t.fragment.services[routed.route.unwrap().service.as_ref().unwrap()];
    assert_eq!(service.scheme, rdock_model::service::Scheme::Https);
    let tls = service.tls.as_ref().unwrap();
    assert!(tls.verify);
    assert_eq!(tls.server_name.as_deref(), Some("abc.example.com"));
    assert!(tls.ca_file.as_ref().unwrap().ends_with(
        "kubernetes/configmaps/gateway-conformance-infra/tls-checks-ca-certificate/ca.crt"
    ));
    assert!(
        t.config_maps
            .contains(&(INFRA.to_owned(), "tls-checks-ca-certificate".to_owned()))
    );
    let ancestors =
        &t.status.backend_tls_policies[&(INFRA.to_owned(), "normative-test".to_owned())];
    let gateways: Vec<&str> = ancestors
        .iter()
        .map(|a| a.ancestor_ref.name.as_str())
        .collect();
    assert_eq!(
        gateways,
        ["same-namespace", "same-namespace-with-https-listener"]
    );
    assert_condition(&ancestors[0].conditions, "Accepted", true, "Accepted");
    assert_condition(
        &ancestors[0].conditions,
        "ResolvedRefs",
        true,
        "ResolvedRefs",
    );
}

#[test]
fn backend_tls_policy_with_an_invalid_ca_fails_the_backend() {
    // From BackendTLSPolicyInvalidCACertificateRef, translation only.
    let r = router(&["backendtlspolicy-invalid-ca-certificate-ref"]);
    let t = &r.translation;
    for policy in [
        "nonexistent-ca-certificate-ref",
        "malformed-ca-certificate-ref",
    ] {
        let Some(ancestors) = t
            .status
            .backend_tls_policies
            .get(&(INFRA.to_owned(), policy.to_owned()))
        else {
            continue;
        };
        assert_condition(
            &ancestors[0].conditions,
            "Accepted",
            false,
            "NoValidCACertificate",
        );
        assert_condition(
            &ancestors[0].conditions,
            "ResolvedRefs",
            false,
            "InvalidCACertificateRef",
        );
    }
    assert!(!t.status.backend_tls_policies.is_empty());
    // Requests to the backend fail instead of going out unverified.
    let route = t
        .fragment
        .routes
        .values()
        .find(|r| r.matcher_text().contains("nonexistent-ca"))
        .unwrap();
    assert_eq!(
        t.fragment.services[route.service.as_ref().unwrap()]
            .respond
            .as_ref()
            .map(|r| r.status),
        Some(500)
    );
}

trait MatcherText {
    fn matcher_text(&self) -> String;
}

impl MatcherText for rdock_model::route::Route {
    fn matcher_text(&self) -> String {
        match &self.matcher {
            rdock_model::route::MatchSpec::Rule(rule) => rule.clone(),
            rdock_model::route::MatchSpec::Structured(s) => format!("{s:?}"),
        }
    }
}
