//! Regression tests for defects found by review of the v0.7 provider: each test reproduces
//! one finding through the translator and the real data plane (see `gateway_conformance.rs`
//! for the method).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]

mod gateway_support;

use gateway_support::{Cluster, INFRA, Outcome, Request, Router, backends};
use rdock_provider_kubernetes::translate::RouteKind::Http;

const SAME: (&str, &str) = (INFRA, "same-namespace");

fn host<'a>(host: &'a str, path: &'a str) -> Request<'a> {
    Request {
        host,
        path,
        method: "GET",
        headers: &[],
    }
}

/// An Ingress (with a `defaultBackend` catch-all) never answers on a Gateway's port: a
/// Gateway listener serves only the routes attached to it, and 404 for anything else.
#[test]
fn ingress_routes_do_not_leak_onto_gateway_listeners() {
    let mut cluster = Cluster::upstream(&[]);
    cluster.settings.provider.ingress.enabled = true;
    cluster.apply_yaml(&format!(
        r"
apiVersion: networking.k8s.io/v1
kind: IngressClass
metadata: {{name: rdock}}
spec: {{controller: {controller}}}
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata: {{name: catch-all, namespace: {INFRA}}}
spec:
  ingressClassName: rdock
  defaultBackend:
    service: {{name: infra-backend-v2, port: {{number: 8080}}}}
  rules:
  - host: ingress.example
    http:
      paths:
      - {{path: /, pathType: Prefix, backend: {{service: {{name: infra-backend-v3, port: {{number: 8080}}}}}}}}
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: {{name: gw-only, namespace: {INFRA}}}
spec:
  parentRefs: [{{name: same-namespace}}]
  hostnames: [gw.example]
  rules:
  - backendRefs: [{{name: infra-backend-v1, port: 8080}}]
",
        controller = rdock_provider_kubernetes::translate::INGRESS_CONTROLLER,
    ));
    let r = Router::new(&mut cluster);
    assert_eq!(
        r.route(SAME, 80, &host("gw.example", "/")).outcome,
        backends(&["infra-backend-v1"])
    );
    assert_eq!(
        r.route(SAME, 80, &host("unmatched.example", "/")).outcome,
        Outcome::NotFound,
        "the Ingress defaultBackend answered on the Gateway's listener"
    );
    assert_eq!(
        r.route(SAME, 80, &host("ingress.example", "/")).outcome,
        Outcome::NotFound,
        "the Ingress host is reachable through the Gateway's listener"
    );
}

/// Gateways `a/b-c` and `a-b/c` read the same once joined with `-`: each still gets its own
/// Service, and a Gateway name over 63 characters is programmed like any other.
#[test]
fn per_gateway_services_are_distinct_and_long_names_are_programmed() {
    let mut cluster = Cluster::upstream(&[]);
    let long = "g".repeat(253);
    let gateway = |ns: &str, name: &str, port: u16| {
        format!(
            "apiVersion: gateway.networking.k8s.io/v1\nkind: Gateway\nmetadata: {{name: {name}, namespace: {ns}}}\nspec:\n  gatewayClassName: {}\n  listeners: [{{name: http, port: {port}, protocol: HTTP, allowedRoutes: {{namespaces: {{from: All}}}}}}]\n",
            gateway_support::CLASS
        )
    };
    cluster.apply_yaml(&gateway("a", "b-c", 80));
    cluster.apply_yaml(&gateway("a-b", "c", 8080));
    cluster.apply_yaml(&gateway(INFRA, &long, 80));
    let t = cluster.translate();
    let name_of = |ns: &str, name: &str| {
        t.services
            .iter()
            .find(|s| s.gateway == (ns.to_owned(), name.to_owned()))
            .unwrap_or_else(|| panic!("no Service for {ns}/{name}"))
            .name
            .clone()
    };
    let first = name_of("a", "b-c");
    let second = name_of("a-b", "c");
    assert_ne!(first, second, "two Gateways share one Service");
    let names: std::collections::BTreeSet<_> = t.services.iter().map(|s| &s.name).collect();
    assert_eq!(names.len(), t.services.len(), "duplicate Service names");
    for s in &t.services {
        assert!(s.name.len() <= 63, "{}", s.name);
        assert!(
            s.labels.values().all(|v| v.len() <= 63),
            "label value over 63 characters on {}",
            s.name
        );
    }
    // Each keeps its own ports; the long-named Gateway is programmed.
    let r = Router::compile(&cluster, t);
    assert!(r.has_listener(("a", "b-c"), 80));
    assert!(!r.has_listener(("a", "b-c"), 8080));
    assert!(r.has_listener(("a-b", "c"), 8080));
    assert!(r.has_listener((INFRA, &long), 80));
    gateway_support::assert_gateway_ready(&r.translation, (INFRA, &long));
}

/// `allowedRoutes.namespaces.from: Selector` without a selector admits no route (Go's
/// `LabelSelectorAsSelector(nil)` selects nothing; the field is required with `Selector`),
/// with a diagnostic; an explicitly empty selector (`selector: {}`) selects every namespace,
/// as an empty `metav1.LabelSelector` does.
#[test]
fn a_selector_listener_without_a_selector_admits_no_route() {
    for (selector, admitted) in [("", false), (", selector: {}", true)] {
        let mut cluster = Cluster::upstream(&[]);
        cluster.apply_yaml(&format!(
            r"
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata: {{name: selector-gw, namespace: {INFRA}}}
spec:
  gatewayClassName: {class}
  listeners:
  - name: http
    port: 80
    protocol: HTTP
    allowedRoutes: {{namespaces: {{from: Selector{selector}}}}}
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: {{name: elsewhere, namespace: {APP}}}
spec:
  parentRefs: [{{name: selector-gw, namespace: {INFRA}}}]
  rules:
  - backendRefs: [{{name: app-backend-v1, port: 8080}}]
",
            class = gateway_support::CLASS,
            APP = gateway_support::APP,
        ));
        let t = cluster.translate();
        let p = gateway_support::parent(
            &t,
            Http,
            (gateway_support::APP, "elsewhere"),
            (INFRA, "selector-gw"),
        );
        if admitted {
            gateway_support::assert_condition(&p.conditions, "Accepted", true, "Accepted");
        } else {
            gateway_support::assert_condition(
                &p.conditions,
                "Accepted",
                false,
                "NotAllowedByListeners",
            );
            assert!(
                t.diagnostics.iter().any(|d| d.message.contains("selector")),
                "no diagnostic: {:#?}",
                t.diagnostics
            );
        }
    }
}

/// A `RequestRedirect` whose scheme is the request's own still redirects (the specification
/// has no "already on that scheme" exception), with or without a port.
#[test]
fn a_same_scheme_request_redirect_redirects() {
    let mut cluster = Cluster::upstream(&["httproute-redirect-port-and-scheme"]);
    cluster.apply_yaml(&format!(
        r"
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: {{name: same-scheme, namespace: {INFRA}}}
spec:
  parentRefs: [{{name: same-namespace-with-https-listener}}]
  hostnames: [same.example]
  rules:
  - matches: [{{path: {{type: PathPrefix, value: /port}}}}]
    filters: [{{type: RequestRedirect, requestRedirect: {{scheme: https, port: 8443}}}}]
  - matches: [{{path: {{type: PathPrefix, value: /plain}}}}]
    filters: [{{type: RequestRedirect, requestRedirect: {{scheme: https}}}}]
"
    ));
    let r = Router::new(&mut cluster);
    let https = (INFRA, "same-namespace-with-https-listener");
    assert_eq!(
        r.execute(https, 443, &host("same.example", "/port/a")),
        Some((302, Some("https://same.example:8443/port/a".to_owned())))
    );
    assert_eq!(
        r.execute(https, 443, &host("same.example", "/plain")),
        Some((302, Some("https://same.example/plain".to_owned())))
    );
}

/// EndpointSlice addresses on loopback, link-local or unspecified are never proxied to (a
/// tenant writing EndpointSlices for its own Service could otherwise reach rdock's admin
/// listener on loopback or the node's metadata service); one diagnostic names them.
#[test]
fn loopback_and_link_local_endpoints_are_never_backends() {
    let mut cluster = Cluster::upstream(&[]);
    cluster.apply_yaml(&format!(
        r#"
apiVersion: v1
kind: Service
metadata: {{name: sneaky, namespace: {INFRA}}}
spec: {{ports: [{{port: 8080}}]}}
---
apiVersion: discovery.k8s.io/v1
kind: EndpointSlice
metadata:
  name: sneaky-1
  namespace: {INFRA}
  labels: {{kubernetes.io/service-name: sneaky}}
addressType: IPv4
ports: [{{port: 2080}}]
endpoints:
- addresses: ["127.0.0.1"]
- addresses: ["169.254.169.254"]
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: {{name: sneaky, namespace: {INFRA}}}
spec:
  parentRefs: [{{name: same-namespace}}]
  hostnames: [sneaky.example]
  rules:
  - backendRefs: [{{name: sneaky, port: 8080}}]
"#
    ));
    let r = Router::new(&mut cluster);
    // No usable endpoint is left: the Service answers 503 instead of dialling them.
    assert_eq!(
        r.route(SAME, 80, &host("sneaky.example", "/")).outcome,
        Outcome::Status(503)
    );
    let warnings: Vec<_> = r
        .translation
        .diagnostics
        .iter()
        .filter(|d| d.message.contains("127.0.0.1"))
        .collect();
    assert_eq!(warnings.len(), 1, "{:#?}", r.translation.diagnostics);
    assert!(warnings[0].message.contains("169.254.169.254"));
}
