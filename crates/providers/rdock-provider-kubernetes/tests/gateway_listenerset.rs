//! ListenerSet (feature `ListenerSet`, Gateway API v1.7.0): the upstream conformance tests
//! gated on it, transcribed against the translator (see `gateway_conformance.rs` for the
//! method), and tests of the rules they leave open: `allowedListeners` namespaces,
//! precedence, certificate grants, Service ports, removal and names.
//!
//! The Rust test name carries the upstream test's `ShortName`; status assertions are the Go
//! test's (`ListenerSetMustHaveCondition`, `ListenerSetListenersMustHaveConditions`,
//! `ListenerSetStatusMustHaveListeners`, `GatewayMustHaveAttachedListeners`,
//! `RoutesAndParentMustBeAccepted`, `HTTPRouteMustHaveCondition`), and traffic expectations
//! run through the assembled and compiled fragment.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::assert_is_empty
)]

mod gateway_support;

use std::fmt::Write as _;

use gateway_support::{
    Cluster, INFRA, Outcome, Request, Router, WEB, assert_accepted, assert_condition,
    assert_gateway_ready, backends, gateway, listener,
};
use rdock_provider_kubernetes::translate::RouteKind::{Http, Tcp};
use rdock_provider_kubernetes::translate::{
    DesiredListener, DesiredListenerSet, DesiredRouteParent, RouteKind, Translation,
};

fn router(tests: &[&str]) -> Router {
    Router::new(&mut Cluster::upstream(tests))
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
fn not_found() -> Outcome {
    Outcome::NotFound
}

fn host<'a>(host: &'a str, path: &'a str) -> Request<'a> {
    Request {
        host,
        path,
        method: "GET",
        headers: &[],
    }
}

fn expect(r: &Router, gw: (&str, &str), port: u16, request: &Request<'_>, outcome: &Outcome) {
    let routed = r.route(gw, port, request);
    assert_eq!(
        &routed.outcome, outcome,
        "{request:?} on {gw:?}:{port} → {:?}",
        routed.route
    );
}

/// The desired status of ListenerSet `ns/name`.
fn set<'a>(t: &'a Translation, ns: &str, name: &str) -> &'a DesiredListenerSet {
    t.status
        .listener_sets
        .get(&(ns.to_owned(), name.to_owned()))
        .unwrap_or_else(|| panic!("no status for ListenerSet {ns}/{name}"))
}

/// A listener entry of a ListenerSet status.
fn entry<'a>(set: &'a DesiredListenerSet, name: &str) -> &'a DesiredListener {
    set.listeners
        .iter()
        .find(|l| l.name == name)
        .unwrap_or_else(|| panic!("no listener {name} in {set:#?}"))
}

/// `ListenerSetMustHaveCondition` for `Accepted` and `Programmed`.
fn assert_set(set: &DesiredListenerSet, accepted: (bool, &str), programmed: (bool, &str)) {
    assert_condition(&set.conditions, "Accepted", accepted.0, accepted.1);
    assert_condition(&set.conditions, "Programmed", programmed.0, programmed.1);
}

/// `generateAcceptedListenerConditions`: `ResolvedRefs`, `Accepted` and `Programmed` true.
fn assert_entry_ready(l: &DesiredListener) {
    assert_condition(&l.conditions, "ResolvedRefs", true, "");
    assert_condition(&l.conditions, "Accepted", true, "");
    assert_condition(&l.conditions, "Programmed", true, "");
}

/// A listener that lost a conflict: `Accepted`/`Programmed` false and `Conflicted` true, all
/// with `reason`.
fn assert_entry_conflicted(l: &DesiredListener, reason: &str) {
    assert_condition(&l.conditions, "Accepted", false, reason);
    assert_condition(&l.conditions, "Programmed", false, reason);
    assert_condition(&l.conditions, "Conflicted", true, reason);
}

/// `ListenerSetStatusMustHaveListeners`: exactly these listeners, each supporting HTTPRoute,
/// with these `attachedRoutes` and accepted conditions.
fn assert_set_listeners(set: &DesiredListenerSet, expected: &[(&str, i32)]) {
    assert_eq!(set.listeners.len(), expected.len(), "{set:#?}");
    for (name, attached) in expected {
        let l = entry(set, name);
        assert!(
            l.supported_kinds.iter().any(|k| k.kind == "HTTPRoute"
                && k.group.as_deref() == Some("gateway.networking.k8s.io")),
            "{name}: {:?}",
            l.supported_kinds
        );
        assert_eq!(l.attached_routes, *attached, "{name}: attachedRoutes");
        assert_entry_ready(l);
    }
}

/// `GatewayMustHaveAttachedListeners` (an unset count reads as 0, `ptr.Deref(…, 0)`).
fn attached_sets(t: &Translation, gw: &str) -> i32 {
    let g = gateway(t, INFRA, gw);
    for c in &g.conditions {
        assert_eq!(c.observed_generation, Some(1));
    }
    g.attached_listener_sets.unwrap_or(0)
}

/// Our `status.parents` entry of route `route` for parent `kind` `parent`.
fn parent_of<'a>(
    t: &'a Translation,
    kind: RouteKind,
    route: (&str, &str),
    parent_kind: &str,
    parent: (&str, &str),
) -> &'a DesiredRouteParent {
    t.status
        .routes
        .iter()
        .find(|(r, _)| r.kind == kind && r.namespace == route.0 && r.name == route.1)
        .and_then(|(_, entries)| {
            entries.iter().find(|p| {
                p.parent_ref.kind.as_deref().unwrap_or("Gateway") == parent_kind
                    && p.parent_ref.name == parent.1
                    && p.parent_ref.namespace.as_deref().unwrap_or(route.0) == parent.0
            })
        })
        .unwrap_or_else(|| panic!("no {parent_kind} {parent:?} parent for {route:?}"))
}

/// `RoutesAndParentMustBeAccepted` for a ListenerSet: each route accepted by it, and every
/// listener of the ListenerSet accepted, programmed and resolved.
fn assert_routes_and_set_accepted(t: &Translation, set_key: (&str, &str), routes: &[(&str, &str)]) {
    for route in routes {
        let p = parent_of(t, Http, *route, "ListenerSet", set_key);
        assert_condition(&p.conditions, "Accepted", true, "Accepted");
    }
    let s = set(t, set_key.0, set_key.1);
    assert!(!s.listeners.is_empty());
    for l in &s.listeners {
        assert_entry_ready(l);
    }
}

// ---------------------------------------------------------------------------------------
// The upstream conformance tests gated on `ListenerSet`.

#[test]
fn listener_set_default_not_allowed() {
    // ListenerSetDefaultNotAllowed.
    let r = router(&["listenerset-default-not-allowed"]);
    let t = &r.translation;
    let gw = "gateway-default-does-not-allow-listenerset";
    assert_condition(&gateway(t, INFRA, gw).conditions, "Accepted", true, "");
    assert_eq!(attached_sets(t, gw), 0);
    let s = set(t, INFRA, "listenerset-default-not-allowed");
    assert_set(s, (false, "NotAllowed"), (false, "NotAllowed"));
    // Nothing of it reaches the data plane.
    expect(
        &r,
        (INFRA, gw),
        80,
        &host("listenerset-default-not-allowed-listener.com", "/"),
        &not_found(),
    );
}

#[test]
fn listener_set_allowed_namespace_none() {
    // ListenerSetAllowedNamespaceNone.
    let r = router(&["listenerset-allowed-namespace-none"]);
    let t = &r.translation;
    let gw = "gateway-does-not-allow-listenerset";
    assert_condition(&gateway(t, INFRA, gw).conditions, "Accepted", true, "");
    assert_eq!(attached_sets(t, gw), 0);
    let s = set(t, INFRA, "listenerset-not-allowed");
    assert_set(s, (false, "NotAllowed"), (false, "NotAllowed"));
}

#[test]
fn listener_set_allowed_namespace_same() {
    // ListenerSetAllowedNamespaceSame.
    let r = router(&["listenerset-allowed-namespace-same"]);
    let t = &r.translation;
    let gw = "gateway-allows-listenerset-in-same-namespace";
    assert_condition(&gateway(t, INFRA, gw).conditions, "Accepted", true, "");
    assert_eq!(attached_sets(t, gw), 1);
    let s = set(t, INFRA, "listenerset-in-same-namespace");
    assert_set(s, (true, "Accepted"), (true, "Programmed"));
    assert_entry_ready(entry(s, "listenerset-in-same-namespace-listener"));
    let other = set(
        t,
        "gateway-api-listenerset-not-allowed-ns",
        "listenerset-in-different-namespace",
    );
    assert_set(other, (false, "NotAllowed"), (false, "NotAllowed"));
}

#[test]
fn listener_set_allowed_namespace_selector() {
    // ListenerSetAllowedNamespaceSelector.
    let r = router(&["listenerset-allowed-namespace-selector"]);
    let t = &r.translation;
    let gw = "gateway-allows-listenerset-in-selected-namespace";
    assert_condition(&gateway(t, INFRA, gw).conditions, "Accepted", true, "");
    assert_eq!(attached_sets(t, gw), 1);
    let s = set(
        t,
        "gateway-api-listenerset-selector-allowed-ns",
        "listenerset-in-selected-namespace",
    );
    assert_set(s, (true, "Accepted"), (true, "Programmed"));
    assert_entry_ready(entry(s, "listenerset-in-selected-namespace-listener"));
    let other = set(
        t,
        "gateway-api-listenerset-selector-not-allowed-ns",
        "listenerset-not-in-selected-namespace",
    );
    assert_set(other, (false, "NotAllowed"), (false, "NotAllowed"));
}

#[test]
fn listener_set_http_routing() {
    // ListenerSetHTTPRouting.
    let r = router(&["listenerset-http-routing"]);
    let t = &r.translation;
    let gw = (INFRA, "gateway-with-listener-sets-http-routing");
    for route in [
        "attaches-to-all-listeners",
        "gateway-route",
        "gateway-section-route",
    ] {
        assert_accepted(t, Http, (INFRA, route), gw);
    }
    assert_eq!(attached_sets(t, gw.1), 2);
    // The Gateway's listeners count only the routes attached through the Gateway.
    let g = gateway(t, gw.0, gw.1);
    assert_eq!(g.listeners.len(), 2);
    assert_eq!(listener(g, "gateway-listener-1").attached_routes, 3);
    assert_eq!(listener(g, "gateway-listener-2").attached_routes, 2);

    let ls1 = (INFRA, "listener-set-http-routing-1");
    assert_routes_and_set_accepted(
        t,
        ls1,
        &[
            (INFRA, "attaches-to-all-listeners"),
            (INFRA, "listener-set-http-routing-1-route"),
            (INFRA, "listener-set-http-routing-1-section-route"),
        ],
    );
    assert_set_listeners(
        set(t, ls1.0, ls1.1),
        &[
            ("listener-set-http-routing-1-listener-1", 3),
            ("listener-set-http-routing-1-listener-2", 2),
        ],
    );
    let ls2 = (INFRA, "listener-set-http-routing-2");
    assert_routes_and_set_accepted(
        t,
        ls2,
        &[
            (INFRA, "attaches-to-all-listeners"),
            (INFRA, "listener-set-http-routing-2-route"),
        ],
    );
    assert_set_listeners(
        set(t, ls2.0, ls2.1),
        &[
            ("listener-set-http-routing-2-listener-1", 2),
            ("listener-set-http-routing-2-listener-2", 2),
        ],
    );

    let gw_hosts = ["gateway-listener-1.com", "gateway-listener-2.com"];
    let ls1_hosts = [
        "listener-set-http-routing-1-listener-1.com",
        "listener-set-http-routing-1-listener-2.com",
    ];
    let ls2_hosts = [
        "listener-set-http-routing-2-listener-1.com",
        "listener-set-http-routing-2-listener-2.com",
    ];
    let all: Vec<&str> = gw_hosts
        .iter()
        .chain(&ls1_hosts)
        .chain(&ls2_hosts)
        .copied()
        .collect();
    let mut cases: Vec<(&str, &str, Outcome)> = Vec::new();
    for h in &all {
        // The route attached to every resource answers on every host.
        cases.push((h, "/route", v1()));
        // gateway-route only on the Gateway's listeners.
        let on_gw = gw_hosts.contains(h);
        cases.push((h, "/gateway-route", if on_gw { v2() } else { not_found() }));
        // gateway-section-route only on gateway-listener-1.
        let first = *h == "gateway-listener-1.com";
        cases.push((
            h,
            "/gateway-section-route",
            if first { v3() } else { not_found() },
        ));
        // listener-set-http-routing-1-route only on the first ListenerSet's listeners.
        let on_ls1 = ls1_hosts.contains(h);
        cases.push((
            h,
            "/listener-set-http-routing-1-route",
            if on_ls1 { v2() } else { not_found() },
        ));
        // …-1-section-route only on listener-set-http-routing-1-listener-1.
        let ls1_first = *h == "listener-set-http-routing-1-listener-1.com";
        cases.push((
            h,
            "/listener-set-http-routing-1-section-route",
            if ls1_first { v3() } else { not_found() },
        ));
        // listener-set-http-routing-2-route only on the second ListenerSet's listeners.
        let on_ls2 = ls2_hosts.contains(h);
        cases.push((
            h,
            "/listener-set-http-routing-2-route",
            if on_ls2 { v2() } else { not_found() },
        ));
    }
    assert_eq!(cases.len(), 36);
    for (h, path, outcome) in &cases {
        expect(&r, gw, 80, &host(h, path), outcome);
    }
    // All of it on the one internal listener of port 80.
    let ports: Vec<u16> = t
        .services
        .iter()
        .find(|s| s.gateway == (gw.0.to_owned(), gw.1.to_owned()))
        .unwrap()
        .ports
        .clone();
    assert_eq!(ports, [80]);
}

#[test]
fn listener_set_reference_grant() {
    // ListenerSetReferenceGrant.
    let r = router(&["listenerset-reference-grant"]);
    let t = &r.translation;
    let gw = "gateway-with-listener-sets-test-reference-grant";
    assert_condition(&gateway(t, INFRA, gw).conditions, "Accepted", true, "");
    let with = set(t, INFRA, "listenerset-with-reference-grant");
    assert_set(with, (true, ""), (true, ""));
    assert_condition(
        &entry(with, "listenerset-with-reference-grant-listener").conditions,
        "ResolvedRefs",
        true,
        "",
    );
    let without = set(
        t,
        "gateway-api-listener-sets-test-reference-grant-ns",
        "listenerset-without-reference-grant",
    );
    assert_set(
        without,
        (false, "ListenersNotValid"),
        (false, "ListenersNotValid"),
    );
    assert_condition(
        &entry(without, "listenerset-without-reference-grant-listener").conditions,
        "ResolvedRefs",
        false,
        "RefNotPermitted",
    );
    // The Gateway's grant (from kind Gateway) is not inherited; the ListenerSet's grant (from
    // kind ListenerSet in its namespace) makes the certificate usable on port 443.
    assert!(
        t.secrets
            .contains(&(WEB.to_owned(), "certificate".to_owned()))
    );
    assert!(r.has_listener((INFRA, gw), 443));
}

#[test]
fn listener_set_protocol_conflict() {
    // ListenerSetProtocolConflict.
    let r = router(&["listenerset-protocol-conflict"]);
    let t = &r.translation;
    let gw_name = "gateway-with-listenerset-protocol-conflict";
    let g = gateway(t, INFRA, gw_name);
    assert_condition(&g.conditions, "Accepted", true, "");
    assert_entry_ready(listener(g, "gateway-listener"));
    assert_entry_ready(listener(g, "protocol-conflict-with-gateway-listener"));
    assert_eq!(attached_sets(t, gw_name), 2);
    let reason = "ProtocolConflict";

    let s = set(
        t,
        INFRA,
        "listenerset-with-protocol-conflict-with-gateway-1",
    );
    assert_set(s, (true, ""), (true, "Programmed"));
    assert_entry_ready(entry(s, "listener-set-1-listener"));
    assert_entry_conflicted(entry(s, "protocol-conflict-with-gateway-listener"), reason);
    assert_entry_ready(entry(s, "protocol-conflict-with-listener-set-listener"));

    let s = set(
        t,
        INFRA,
        "listenerset-with-protocol-conflict-with-gateway-2",
    );
    assert_set(
        s,
        (false, "ListenersNotValid"),
        (false, "ListenersNotValid"),
    );
    assert_entry_conflicted(entry(s, "protocol-conflict-with-gateway-listener"), reason);

    let s = set(
        t,
        INFRA,
        "listenerset-with-protocol-conflict-with-listener-set-1",
    );
    assert_set(s, (true, ""), (true, "Programmed"));
    assert_entry_ready(entry(s, "listener-set-2-listener"));
    assert_entry_conflicted(
        entry(s, "protocol-conflict-with-listener-set-listener"),
        reason,
    );

    let s = set(
        t,
        INFRA,
        "listenerset-with-protocol-conflict-with-listener-set-2",
    );
    assert_set(
        s,
        (false, "ListenersNotValid"),
        (false, "ListenersNotValid"),
    );
    assert_entry_conflicted(
        entry(s, "protocol-conflict-with-listener-set-listener"),
        reason,
    );
    // Port 80 stays an HTTP listener.
    let fragment_listener = &t.fragment.listeners[r
        .listener((INFRA, gw_name), 80)
        .trim_end_matches("@kubernetes")];
    assert_eq!(
        fragment_listener.protocol,
        Some(rdock_model::config::ListenerProtocol::Http)
    );
}

#[test]
fn listener_set_hostname_conflict() {
    // ListenerSetHostnameConflict.
    let r = router(&["listenerset-hostname-conflict"]);
    let t = &r.translation;
    let gw_name = "gateway-with-listenerset-hostname-conflict";
    let g = gateway(t, INFRA, gw_name);
    assert_condition(&g.conditions, "Accepted", true, "");
    assert_entry_ready(listener(g, "gateway-listener"));
    assert_entry_ready(listener(g, "hostname-conflict-with-gateway-listener"));
    assert_eq!(attached_sets(t, gw_name), 2);
    let reason = "HostnameConflict";

    let s = set(
        t,
        INFRA,
        "listenerset-with-hostname-conflict-with-gateway-1",
    );
    assert_set(s, (true, ""), (true, "Programmed"));
    assert_entry_ready(entry(s, "listener-set-1-listener"));
    assert_entry_conflicted(entry(s, "hostname-conflict-with-gateway-listener"), reason);
    assert_entry_ready(entry(s, "hostname-conflict-with-listener-set-listener"));

    let s = set(
        t,
        INFRA,
        "listenerset-with-hostname-conflict-with-gateway-2",
    );
    assert_set(
        s,
        (false, "ListenersNotValid"),
        (false, "ListenersNotValid"),
    );
    assert_entry_conflicted(entry(s, "hostname-conflict-with-gateway-listener"), reason);

    let s = set(
        t,
        INFRA,
        "listenerset-with-hostname-conflict-with-listener-set-1",
    );
    assert_set(s, (true, ""), (true, "Programmed"));
    assert_entry_ready(entry(s, "listener-set-2-listener"));
    assert_entry_conflicted(
        entry(s, "hostname-conflict-with-listener-set-listener"),
        reason,
    );

    let s = set(
        t,
        INFRA,
        "listenerset-with-hostname-conflict-with-listener-set-2",
    );
    assert_set(
        s,
        (false, "ListenersNotValid"),
        (false, "ListenersNotValid"),
    );
    assert_entry_conflicted(
        entry(s, "hostname-conflict-with-listener-set-listener"),
        reason,
    );
}

#[test]
fn listener_set_allowed_routes_namespaces() {
    // ListenerSetAllowedRoutesNamespaces.
    let r = router(&["listenerset-allowed-routes-namespaces"]);
    let t = &r.translation;
    let gw = (INFRA, "gateway-with-listener-sets-test-allowed-routes");
    assert!(!gateway(t, gw.0, gw.1).addresses.is_empty());
    assert_condition(&gateway(t, gw.0, gw.1).conditions, "Accepted", true, "");
    assert_eq!(attached_sets(t, gw.1), 2);

    // Same-namespace ListenerSet.
    let ls = (INFRA, "listenerset-test-allowed-routes-namespaces");
    assert_routes_and_set_accepted(
        t,
        ls,
        &[
            (INFRA, "route-in-same-namespace"),
            (
                "gateway-api-routes-allowed-ns",
                "route-in-selected-namespace",
            ),
            (
                "gateway-api-routes-not-allowed-ns",
                "route-not-in-selected-namespace",
            ),
        ],
    );
    assert_set_listeners(
        set(t, ls.0, ls.1),
        &[
            ("listener-set-listener-allowed-routes-all", 3),
            ("listener-set-listener-allowed-routes-same", 1),
            ("listener-set-listener-allowed-routes-selector", 1),
        ],
    );
    let all = "listener-set-listener-allowed-routes-all.com";
    let same = "listener-set-listener-allowed-routes-same.com";
    let selector = "listener-set-listener-allowed-routes-selector.com";
    let cases = [
        (all, "/route-in-same-namespace", v1()),
        (all, "/route-in-selected-namespace", v2()),
        (all, "/route-not-in-selected-namespace", v3()),
        (same, "/route-in-same-namespace", v1()),
        (same, "/route-in-selected-namespace", not_found()),
        (same, "/route-not-in-selected-namespace", not_found()),
        (selector, "/route-in-same-namespace", not_found()),
        (selector, "/route-in-selected-namespace", v2()),
        (selector, "/route-not-in-selected-namespace", not_found()),
    ];
    for (h, path, outcome) in &cases {
        expect(&r, gw, 80, &host(h, path), outcome);
    }

    // Cross-namespace ListenerSet: `Same` is the ListenerSet's namespace.
    let ls_ns = "gateway-api-ls-cross-ns";
    let ls = (ls_ns, "listenerset-test-allowed-routes-cross-ns");
    assert_routes_and_set_accepted(t, ls, &[(ls_ns, "route-in-listenerset-namespace")]);
    let p = parent_of(
        t,
        Http,
        (INFRA, "route-in-gateway-namespace"),
        "ListenerSet",
        ls,
    );
    assert_condition(&p.conditions, "Accepted", false, "NotAllowedByListeners");
    assert_set_listeners(
        set(t, ls.0, ls.1),
        &[("listener-set-listener-allowed-routes-cross-ns-same", 1)],
    );
    let cross = "listener-set-listener-allowed-routes-cross-ns-same.com";
    expect(
        &r,
        gw,
        80,
        &host(cross, "/route-in-listenerset-namespace"),
        &v1(),
    );
    expect(
        &r,
        gw,
        80,
        &host(cross, "/route-in-gateway-namespace"),
        &not_found(),
    );
}

#[test]
fn listener_set_allowed_routes_supported_kinds() {
    // ListenerSetAllowedRoutesSupportedKinds.
    let r = router(&["listenerset-allowed-routes-supported-kinds"]);
    let t = &r.translation;
    let gw = "gateway-with-listener-sets-test-supported-route-kinds";
    assert_condition(&gateway(t, INFRA, gw).conditions, "Accepted", true, "");
    let s = set(t, INFRA, "listenerset-test-allowed-routes-supported-kinds");
    for c in &s.conditions {
        assert_eq!(c.observed_generation, Some(1));
    }
    assert_condition(
        &entry(s, "listener-set-listener-allowed-routes-tls-only").conditions,
        "ResolvedRefs",
        false,
        "InvalidRouteKinds",
    );
}

#[test]
fn listener_set_gateway_parent_section_name_not_found() {
    // ListenerSetGatewayParentSectionNameNotFound.
    let r = router(&["listenerset-gateway-parent-section-name-not-found"]);
    let t = &r.translation;
    let gw = (INFRA, "gateway-section-name");
    assert!(!gateway(t, gw.0, gw.1).addresses.is_empty());
    assert_condition(&gateway(t, gw.0, gw.1).conditions, "Accepted", true, "");
    assert_eq!(attached_sets(t, gw.1), 1);
    assert_routes_and_set_accepted(
        t,
        (INFRA, "listenerset-section-name"),
        &[(INFRA, "route-via-listenerset")],
    );
    let p = parent_of(t, Http, (INFRA, "route-via-gateway"), "Gateway", gw);
    assert_condition(&p.conditions, "Accepted", false, "NoMatchingParent");
    expect(
        &r,
        gw,
        80,
        &host("ls-section-name.com", "/goodsection"),
        &v1(),
    );
    expect(
        &r,
        gw,
        80,
        &host("gw-section.com", "/badsection"),
        &not_found(),
    );
}

#[test]
fn listener_set_dual_parent_ref_independence() {
    // ListenerSetDualParentRefIndependence.
    let r = router(&["listenerset-dual-parentref-independence"]);
    let t = &r.translation;
    let gw = (INFRA, "gateway-dual-parentref");
    let ls = (INFRA, "ls-dual-parentref");
    assert!(!gateway(t, gw.0, gw.1).addresses.is_empty());
    assert_condition(&gateway(t, gw.0, gw.1).conditions, "Accepted", true, "");
    assert_eq!(attached_sets(t, gw.1), 1);
    assert_set_listeners(set(t, ls.0, ls.1), &[("ls-dual-parentref-listener", 2)]);

    // Both parentRefs are Accepted.
    let both = (INFRA, "route-dual-parentref-both");
    let p = parent_of(t, Http, both, "Gateway", gw);
    assert_condition(&p.conditions, "Accepted", true, "");
    let p = parent_of(t, Http, both, "ListenerSet", ls);
    assert_condition(&p.conditions, "Accepted", true, "");
    expect(&r, gw, 80, &host("gw-dual.com", "/dualboth"), &v1());
    expect(&r, gw, 80, &host("ls-dual.com", "/dualboth"), &v1());

    // One of two parentRefs is Accepted.
    let one = (INFRA, "route-dual-parentref-one");
    let p = parent_of(t, Http, one, "Gateway", gw);
    assert_condition(&p.conditions, "Accepted", false, "NoMatchingParent");
    let p = parent_of(t, Http, one, "ListenerSet", ls);
    assert_condition(&p.conditions, "Accepted", true, "");
    assert_routes_and_set_accepted(t, ls, &[one]);
    expect(&r, gw, 80, &host("ls-dual.com", "/dualone"), &v2());
    expect(&r, gw, 80, &host("gw-dual.com", "/dualone"), &not_found());
}

#[test]
fn listener_set_route_status_scoped_to_parent_ref() {
    // ListenerSetRouteStatusScopedToParentRef.
    let r = router(&["listenerset-route-status-scoped-to-parentref"]);
    let t = &r.translation;
    let gw = (INFRA, "gateway-parentref");
    let ls = (INFRA, "listenerset-parentref");
    assert_condition(&gateway(t, gw.0, gw.1).conditions, "Accepted", true, "");
    assert_eq!(attached_sets(t, gw.1), 1);
    assert_set_listeners(set(t, ls.0, ls.1), &[("listenerset-parentref-listener", 1)]);
    // Gateway-only parentRef: one entry, for the Gateway.
    let gw_only = gateway_support::parents(t, Http, INFRA, "route-parentref-gwonly");
    assert_eq!(gw_only.len(), 1, "{gw_only:#?}");
    assert_eq!(
        gw_only[0].parent_ref.kind.as_deref().unwrap_or("Gateway"),
        "Gateway"
    );
    assert_eq!(gw_only[0].parent_ref.name, gw.1);
    assert_condition(&gw_only[0].conditions, "Accepted", true, "");
    // ListenerSet-only parentRef: one entry, for the ListenerSet.
    let ls_only = gateway_support::parents(t, Http, INFRA, "route-parentref-lsonly");
    assert_eq!(ls_only.len(), 1, "{ls_only:#?}");
    assert_eq!(ls_only[0].parent_ref.kind.as_deref(), Some("ListenerSet"));
    assert_eq!(
        ls_only[0].parent_ref.group.as_deref(),
        Some("gateway.networking.k8s.io")
    );
    assert_eq!(ls_only[0].parent_ref.namespace.as_deref(), Some(INFRA));
    assert_eq!(ls_only[0].parent_ref.name, ls.1);
    assert_routes_and_set_accepted(t, ls, &[(INFRA, "route-parentref-lsonly")]);
    // And the Gateway listener does not count the ListenerSet's route.
    assert_eq!(
        listener(gateway(t, gw.0, gw.1), "gw-parentref-listener").attached_routes,
        1
    );
    expect(&r, gw, 80, &host("gw-parentref.com", "/gwonly"), &v1());
    expect(
        &r,
        gw,
        80,
        &host("listenerset-parentref.com", "/lsonly"),
        &v2(),
    );
    expect(
        &r,
        gw,
        80,
        &host("gw-parentref.com", "/lsonly"),
        &not_found(),
    );
}

// ---------------------------------------------------------------------------------------
// Rules the upstream tests leave open.

/// A cluster with the base manifests and `yaml`.
fn cluster(yaml: &str) -> Cluster {
    let mut c = Cluster::upstream(&[]);
    c.apply_yaml(yaml);
    c
}

/// A Gateway in the infra namespace with one HTTP listener on port 80 and `allowed` as its
/// `allowedListeners` (YAML, or empty for none).
fn gateway_yaml(name: &str, allowed: &str) -> String {
    format!(
        r#"
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata: {{name: {name}, namespace: {INFRA}}}
spec:
  gatewayClassName: "{{GATEWAY_CLASS_NAME}}"
  listeners:
  - name: http
    port: 80
    protocol: HTTP
    hostname: gw.example
    allowedRoutes: {{namespaces: {{from: All}}}}
{allowed}
"#
    )
}

/// A ListenerSet `ns/name` for Gateway `gw` with one HTTP listener on `port` for `hostname`.
fn set_yaml(ns: &str, name: &str, gw: &str, listener: &str, port: u16, hostname: &str) -> String {
    format!(
        r"
---
apiVersion: gateway.networking.k8s.io/v1
kind: ListenerSet
metadata: {{name: {name}, namespace: {ns}}}
spec:
  parentRef: {{name: {gw}, namespace: {INFRA}}}
  listeners:
  - name: {listener}
    port: {port}
    protocol: HTTP
    hostname: {hostname}
    allowedRoutes: {{namespaces: {{from: All}}}}
"
    )
}

fn namespace_yaml(name: &str, labels: &str) -> String {
    format!(
        "\n---\napiVersion: v1\nkind: Namespace\nmetadata: {{name: {name}, labels: {{{labels}}}}}\n"
    )
}

#[test]
fn allowed_listeners_namespace_rules() {
    // None (explicit and the default), Same, All, Selector with labels, an empty selector
    // (every namespace) and a missing selector (no namespace, as for `allowedRoutes`).
    let cases: &[(&str, &[bool; 2])] = &[
        ("", &[false, false]),
        (
            "  allowedListeners: {namespaces: {from: None}}",
            &[false, false],
        ),
        ("  allowedListeners: {}", &[false, false]),
        (
            "  allowedListeners: {namespaces: {from: Same}}",
            &[true, false],
        ),
        (
            "  allowedListeners: {namespaces: {from: All}}",
            &[true, true],
        ),
        (
            "  allowedListeners: {namespaces: {from: Selector, selector: {matchLabels: {team: a}}}}",
            &[false, true],
        ),
        (
            "  allowedListeners: {namespaces: {from: Selector, selector: {}}}",
            &[true, true],
        ),
        (
            "  allowedListeners: {namespaces: {from: Selector}}",
            &[false, false],
        ),
        (
            "  allowedListeners: {namespaces: {from: Sideways}}",
            &[false, false],
        ),
    ];
    for (allowed, expected) in cases {
        let mut yaml = gateway_yaml("gw", allowed);
        yaml.push_str(&namespace_yaml("team-a", "team: a"));
        yaml.push_str(&set_yaml(INFRA, "same", "gw", "l", 80, "same.example"));
        yaml.push_str(&set_yaml("team-a", "other", "gw", "l", 80, "other.example"));
        let r = Router::new(&mut cluster(&yaml));
        let t = &r.translation;
        for (i, (ns, name, h)) in [
            (INFRA, "same", "same.example"),
            ("team-a", "other", "other.example"),
        ]
        .iter()
        .enumerate()
        {
            let s = set(t, ns, name);
            if expected[i] {
                assert_set(s, (true, "Accepted"), (true, "Programmed"));
                assert!(r.route((INFRA, "gw"), 80, &host(h, "/")).route.is_none());
            } else {
                assert_set(s, (false, "NotAllowed"), (false, "NotAllowed"));
                assert!(s.listeners.is_empty(), "{allowed}: {s:#?}");
            }
        }
        let count = expected.iter().filter(|e| **e).count();
        let g = gateway(t, INFRA, "gw");
        let allows_some =
            allowed.contains("Same") || allowed.contains("All") || allowed.contains("selector:");
        assert_eq!(
            g.attached_listener_sets,
            allows_some.then(|| i32::try_from(count).unwrap()),
            "{allowed}"
        );
        // The Gateway's status lists its own listener only.
        assert_eq!(g.listeners.len(), 1);
    }
}

#[test]
fn a_set_whose_parent_is_missing_or_not_ours_gets_no_status() {
    let mut yaml = gateway_yaml("gw", "  allowedListeners: {namespaces: {from: All}}");
    yaml.push_str(
        r"
---
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata: {name: someone-else}
spec: {controllerName: example.com/other}
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata: {name: theirs, namespace: gateway-conformance-infra}
spec:
  gatewayClassName: someone-else
  allowedListeners: {namespaces: {from: All}}
  listeners: [{name: http, port: 80, protocol: HTTP}]
",
    );
    yaml.push_str(&set_yaml(
        INFRA,
        "to-theirs",
        "theirs",
        "l",
        80,
        "a.example",
    ));
    yaml.push_str(&set_yaml(
        INFRA,
        "to-nothing",
        "missing",
        "l",
        80,
        "b.example",
    ));
    yaml.push_str(
        r"
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: {name: to-theirs, namespace: gateway-conformance-infra}
spec:
  parentRefs: [{kind: ListenerSet, name: to-theirs}]
  rules: [{backendRefs: [{name: infra-backend-v1, port: 8080}]}]
",
    );
    let r = Router::new(&mut cluster(&yaml));
    let t = &r.translation;
    assert!(
        t.status.listener_sets.is_empty(),
        "{:#?}",
        t.status.listener_sets
    );
    assert!(gateway_support::parents(t, Http, INFRA, "to-theirs").is_empty());
}

#[test]
fn a_set_of_a_gateway_that_is_not_accepted_is_parent_not_accepted() {
    let mut yaml = gateway_yaml(
        "gw",
        "  allowedListeners: {namespaces: {from: All}}\n  addresses: [{type: IPAddress, value: 192.0.2.99}]",
    );
    yaml.push_str(&set_yaml(INFRA, "s", "gw", "l", 80, "s.example"));
    yaml.push_str(
        r"
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: {name: r, namespace: gateway-conformance-infra}
spec:
  parentRefs: [{kind: ListenerSet, group: gateway.networking.k8s.io, name: s}]
  rules: [{backendRefs: [{name: infra-backend-v1, port: 8080}]}]
",
    );
    let t = cluster(&yaml).translate();
    assert_condition(
        &gateway(&t, INFRA, "gw").conditions,
        "Accepted",
        false,
        "UnsupportedAddress",
    );
    let s = set(&t, INFRA, "s");
    assert_set(
        s,
        (false, "ParentNotAccepted"),
        (false, "ParentNotAccepted"),
    );
    assert_eq!(gateway(&t, INFRA, "gw").attached_listener_sets, Some(0));
    let p = parent_of(&t, Http, (INFRA, "r"), "ListenerSet", (INFRA, "s"));
    assert_condition(&p.conditions, "Accepted", false, "NotAllowedByListeners");
}

#[test]
fn precedence_is_creation_time_then_namespace_and_name() {
    // `b-older` is older than `a-newer`: it wins the host name although its name sorts
    // later. `c-tie` and `d-tie` have the same creation time: the name decides.
    let mut yaml = gateway_yaml("gw", "  allowedListeners: {namespaces: {from: All}}");
    let stamped = |name: &str, created: &str, hostname: &str| {
        set_yaml(INFRA, name, "gw", "l", 80, hostname).replace(
            &format!("metadata: {{name: {name}, namespace: {INFRA}}}"),
            &format!(
                "metadata: {{name: {name}, namespace: {INFRA}, creationTimestamp: \"{created}\"}}"
            ),
        )
    };
    yaml.push_str(&stamped("a-newer", "2025-06-02T00:00:00Z", "x.example"));
    yaml.push_str(&stamped("b-older", "2025-06-01T00:00:00Z", "x.example"));
    yaml.push_str(&stamped("d-tie", "2025-06-03T00:00:00Z", "y.example"));
    yaml.push_str(&stamped("c-tie", "2025-06-03T00:00:00Z", "y.example"));
    let t = cluster(&yaml).translate();
    assert_set(set(&t, INFRA, "b-older"), (true, "Accepted"), (true, ""));
    let newer = set(&t, INFRA, "a-newer");
    assert_set(
        newer,
        (false, "ListenersNotValid"),
        (false, "ListenersNotValid"),
    );
    assert_entry_conflicted(entry(newer, "l"), "HostnameConflict");
    assert_set(set(&t, INFRA, "c-tie"), (true, "Accepted"), (true, ""));
    assert_entry_conflicted(entry(set(&t, INFRA, "d-tie"), "l"), "HostnameConflict");
    assert_eq!(gateway(&t, INFRA, "gw").attached_listener_sets, Some(2));
}

#[test]
fn conflicts_against_the_gateway_and_within_a_set() {
    // The Gateway's listener wins over a ListenerSet's with the same host name; within one
    // ListenerSet the first listener of a port wins (TCP first, then HTTP on that port);
    // a valid listener elsewhere keeps the set accepted with `ListenersNotValid`.
    let mut yaml = gateway_yaml("gw", "  allowedListeners: {namespaces: {from: Same}}");
    yaml.push_str(
        r"
---
apiVersion: gateway.networking.k8s.io/v1
kind: ListenerSet
metadata: {name: s, namespace: gateway-conformance-infra}
spec:
  parentRef: {name: gw}
  listeners:
  - {name: dup, port: 80, protocol: HTTP, hostname: gw.example}
  - {name: tcp, port: 9000, protocol: TCP}
  - {name: http-after-tcp, port: 9000, protocol: HTTP}
  - {name: ok, port: 80, protocol: HTTP, hostname: ok.example}
",
    );
    let t = cluster(&yaml).translate();
    assert_entry_ready(listener(gateway(&t, INFRA, "gw"), "http"));
    let s = set(&t, INFRA, "s");
    assert_set(s, (true, "ListenersNotValid"), (true, "Programmed"));
    assert_entry_conflicted(entry(s, "dup"), "HostnameConflict");
    assert_entry_ready(entry(s, "tcp"));
    assert_entry_conflicted(entry(s, "http-after-tcp"), "ProtocolConflict");
    assert_entry_ready(entry(s, "ok"));
    let service = t.services.iter().find(|s| s.gateway.1 == "gw").unwrap();
    assert_eq!(service.ports, [80, 9000]);
}

/// A Gateway with an HTTPS listener on 443 (certificate in the infra namespace) that allows
/// ListenerSets from every namespace, and a namespace `team-a`.
const HTTPS_GATEWAY: &str = r#"
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata: {name: gw, namespace: gateway-conformance-infra}
spec:
  gatewayClassName: "{GATEWAY_CLASS_NAME}"
  allowedListeners: {namespaces: {from: All}}
  listeners:
  - name: https
    port: 443
    protocol: HTTPS
    hostname: gw.example
    tls: {certificateRefs: [{name: tls-checks-certificate}]}
---
apiVersion: v1
kind: Namespace
metadata: {name: team-a}
"#;

fn https_set(ns: &str, name: &str, port: u16, hostname: &str, cert: &str) -> String {
    format!(
        r"
---
apiVersion: gateway.networking.k8s.io/v1
kind: ListenerSet
metadata: {{name: {name}, namespace: {ns}}}
spec:
  parentRef: {{name: gw, namespace: {INFRA}}}
  listeners:
  - name: https
    port: {port}
    protocol: HTTPS
    hostname: {hostname}
    tls: {{certificateRefs: [{cert}]}}
"
    )
}

#[test]
fn certificates_are_relative_to_the_set_and_need_a_grant_from_listener_set() {
    let mut yaml = HTTPS_GATEWAY.to_owned();
    // Its own namespace: no grant needed (the Secret is one the suite creates in infra).
    yaml.push_str(&https_set(
        INFRA,
        "own",
        443,
        "own.example",
        "{name: tls-checks-certificate}",
    ));
    // Another namespace with a grant from kind ListenerSet in team-a.
    yaml.push_str(&https_set(
        "team-a",
        "granted",
        8443,
        "granted.example",
        "{name: certificate, namespace: gateway-conformance-web-backend}",
    ));
    // A grant from kind Gateway does not cover a ListenerSet.
    yaml.push_str(&https_set(
        INFRA,
        "gateway-grant-only",
        443,
        "gwgrant.example",
        "{name: certificate, namespace: gateway-conformance-web-backend}",
    ));
    // Unset namespace: the ListenerSet's own (team-a), where the Secret does not exist.
    yaml.push_str(&https_set(
        "team-a",
        "missing",
        443,
        "missing.example",
        "{name: tls-checks-certificate}",
    ));
    yaml.push_str(
        r#"
---
apiVersion: gateway.networking.k8s.io/v1
kind: ReferenceGrant
metadata: {name: from-team-a-sets, namespace: gateway-conformance-web-backend}
spec:
  from: [{group: gateway.networking.k8s.io, kind: ListenerSet, namespace: team-a}]
  to: [{group: "", kind: Secret}]
---
apiVersion: gateway.networking.k8s.io/v1
kind: ReferenceGrant
metadata: {name: from-infra-gateways, namespace: gateway-conformance-web-backend}
spec:
  from: [{group: gateway.networking.k8s.io, kind: Gateway, namespace: gateway-conformance-infra}]
  to: [{group: "", kind: Secret}]
"#,
    );
    let r = Router::new(&mut cluster(&yaml));
    let t = &r.translation;
    assert_entry_ready(entry(set(t, INFRA, "own"), "https"));
    assert_entry_ready(entry(set(t, "team-a", "granted"), "https"));
    let gateway_only = set(t, INFRA, "gateway-grant-only");
    assert_set(
        gateway_only,
        (false, "ListenersNotValid"),
        (false, "ListenersNotValid"),
    );
    assert_condition(
        &entry(gateway_only, "https").conditions,
        "ResolvedRefs",
        false,
        "RefNotPermitted",
    );
    assert_condition(
        &entry(set(t, "team-a", "missing"), "https").conditions,
        "ResolvedRefs",
        false,
        "InvalidCertificateRef",
    );
    // Port 443 serves the Gateway's and the ListenerSet's certificates on one listener; the
    // ListenerSet in team-a got a port of its own.
    let gw = (INFRA, "gw");
    let https = &t.fragment.listeners[r.listener(gw, 443).trim_end_matches("@kubernetes")];
    assert_eq!(https.tls.as_ref().unwrap().certificates.len(), 1);
    let granted = &t.fragment.listeners[r.listener(gw, 8443).trim_end_matches("@kubernetes")];
    assert_eq!(granted.tls.as_ref().unwrap().certificates.len(), 1);
    assert!(
        t.secrets
            .contains(&(WEB.to_owned(), "certificate".to_owned()))
    );
    assert!(
        t.secrets
            .contains(&(INFRA.to_owned(), "tls-checks-certificate".to_owned()))
    );
    let service = t.services.iter().find(|s| s.gateway.1 == "gw").unwrap();
    assert_eq!(service.ports, [443, 8443]);
}

/// A Gateway on port 80 that allows ListenerSets from its namespace, a ListenerSet with a
/// listener on 80 and one on 8080, and routes attached to each section.
const PORTS: &str = r#"
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata: {name: gw, namespace: gateway-conformance-infra}
spec:
  gatewayClassName: "{GATEWAY_CLASS_NAME}"
  allowedListeners: {namespaces: {from: Same}}
  listeners:
  - {name: web, port: 80, protocol: HTTP, hostname: gw.example}
---
apiVersion: gateway.networking.k8s.io/v1
kind: ListenerSet
metadata: {name: extra, namespace: gateway-conformance-infra}
spec:
  parentRef: {name: gw}
  listeners:
  - {name: web, port: 80, protocol: HTTP, hostname: set.example}
  - {name: alt, port: 8080, protocol: HTTP}
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: {name: on-web, namespace: gateway-conformance-infra}
spec:
  parentRefs: [{kind: ListenerSet, name: extra, sectionName: web}]
  rules: [{backendRefs: [{name: infra-backend-v1, port: 8080}]}]
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: {name: on-alt, namespace: gateway-conformance-infra}
spec:
  parentRefs: [{kind: ListenerSet, name: extra, port: 8080}]
  rules: [{backendRefs: [{name: infra-backend-v2, port: 8080}]}]
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: {name: on-gateway-web, namespace: gateway-conformance-infra}
spec:
  parentRefs: [{name: gw, sectionName: web}]
  rules: [{backendRefs: [{name: infra-backend-v3, port: 8080}]}]
"#;

#[test]
fn set_ports_join_the_gateway_service_and_share_its_internal_listeners() {
    let mut c = cluster(PORTS);
    let r = Router::new(&mut c);
    let t = &r.translation;
    let gw = (INFRA, "gw");
    assert_gateway_ready(t, gw);
    let service = t.services.iter().find(|s| s.gateway.1 == "gw").unwrap();
    assert_eq!(service.ports, [80, 8080]);
    // One internal listener per port: the ListenerSet's `web` shares port 80's.
    let names = own_listeners(t);
    assert_eq!(names.len(), 2, "{names:?}");
    assert!(r.has_listener(gw, 80) && r.has_listener(gw, 8080));
    // `web` is the name of a Gateway listener and of a ListenerSet listener: each parentRef
    // reaches its own.
    expect(&r, gw, 80, &host("set.example", "/"), &v1());
    expect(&r, gw, 80, &host("gw.example", "/"), &v3());
    expect(&r, gw, 8080, &host("anything.example", "/"), &v2());
    let s = set(t, INFRA, "extra");
    assert_set_listeners(s, &[("web", 1), ("alt", 1)]);
    assert_eq!(listener(gateway(t, gw.0, gw.1), "web").attached_routes, 1);
    assert_eq!(gateway(t, gw.0, gw.1).attached_listener_sets, Some(1));
}

#[test]
fn a_new_port_is_pending_until_the_service_maps_it() {
    let c = cluster(PORTS);
    let first = rdock_provider_kubernetes::translate(&c.inventory, &c.settings);
    let s = set(&first, INFRA, "extra");
    assert_set(s, (true, "Accepted"), (false, "ParentNotProgrammed"));
    assert_condition(&entry(s, "alt").conditions, "Programmed", false, "Pending");
}

#[test]
fn removing_or_disallowing_a_set_removes_its_listeners_routes_and_ports() {
    // Deleted.
    let mut c = cluster(PORTS);
    let before = c.translate();
    assert_eq!(
        before
            .services
            .iter()
            .find(|s| s.gateway.1 == "gw")
            .unwrap()
            .ports,
        [80, 8080]
    );
    c.inventory
        .listener_sets
        .remove(&(INFRA.to_owned(), "extra".to_owned()));
    let r = Router::new(&mut c);
    let t = &r.translation;
    assert!(t.status.listener_sets.is_empty());
    let gw = (INFRA, "gw");
    assert_eq!(
        t.services
            .iter()
            .find(|s| s.gateway.1 == "gw")
            .unwrap()
            .ports,
        [80]
    );
    assert!(!r.has_listener(gw, 8080));
    expect(&r, gw, 80, &host("set.example", "/"), &not_found());
    expect(&r, gw, 80, &host("gw.example", "/"), &v3());
    // A route to a ListenerSet that no longer exists has no parent of ours.
    assert!(gateway_support::parents(t, Http, INFRA, "on-alt").is_empty());
    assert_eq!(gateway(t, gw.0, gw.1).attached_listener_sets, Some(0));

    // No longer allowed.
    let mut c = cluster(&PORTS.replace("{namespaces: {from: Same}}", "{namespaces: {from: None}}"));
    let r = Router::new(&mut c);
    let t = &r.translation;
    assert_set(
        set(t, INFRA, "extra"),
        (false, "NotAllowed"),
        (false, "NotAllowed"),
    );
    assert_eq!(
        t.services
            .iter()
            .find(|s| s.gateway.1 == "gw")
            .unwrap()
            .ports,
        [80]
    );
    assert!(!r.has_listener(gw, 8080));
    expect(&r, gw, 80, &host("set.example", "/"), &not_found());
    let p = parent_of(t, Http, (INFRA, "on-alt"), "ListenerSet", (INFRA, "extra"));
    assert_condition(&p.conditions, "Accepted", false, "NotAllowedByListeners");
    assert_eq!(gateway(t, gw.0, gw.1).attached_listener_sets, None);
}

#[test]
fn two_sets_with_the_same_listener_name_get_distinct_objects() {
    // Two ListenerSets, each with a listener `l` (on port 80 with different host names, and
    // on 9000 and 9001 for TCP); their routes and services do not collide.
    let mut yaml = gateway_yaml("gw", "  allowedListeners: {namespaces: {from: Same}}");
    for (name, h, port, backend) in [
        ("one", "one.example", 9000, "infra-backend-v1"),
        ("two", "two.example", 9001, "infra-backend-v2"),
    ] {
        write!(
            yaml,
            r"
---
apiVersion: gateway.networking.k8s.io/v1
kind: ListenerSet
metadata: {{name: {name}, namespace: {INFRA}}}
spec:
  parentRef: {{name: gw}}
  listeners:
  - {{name: l, port: 80, protocol: HTTP, hostname: {h}}}
  - {{name: t, port: {port}, protocol: TCP}}
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: {{name: {name}, namespace: {INFRA}}}
spec:
  parentRefs: [{{kind: ListenerSet, name: {name}, sectionName: l}}]
  rules: [{{backendRefs: [{{name: {backend}, port: 8080}}]}}]
---
apiVersion: gateway.networking.k8s.io/v1
kind: TCPRoute
metadata: {{name: {name}, namespace: {INFRA}}}
spec:
  parentRefs: [{{kind: ListenerSet, name: {name}, sectionName: t}}]
  rules: [{{backendRefs: [{{name: {backend}, port: 8080}}]}}]
"
        )
        .unwrap();
    }
    let r = Router::new(&mut cluster(&yaml));
    let t = &r.translation;
    let gw = (INFRA, "gw");
    expect(&r, gw, 80, &host("one.example", "/"), &v1());
    expect(&r, gw, 80, &host("two.example", "/"), &v2());
    assert_eq!(
        r.connect(gw, 9000, None),
        Some(["infra-backend-v1".to_owned()].into())
    );
    assert_eq!(
        r.connect(gw, 9001, None),
        Some(["infra-backend-v2".to_owned()].into())
    );
    for name in ["one", "two"] {
        let p = parent_of(t, Tcp, (INFRA, name), "ListenerSet", (INFRA, name));
        assert_condition(&p.conditions, "Accepted", true, "Accepted");
        assert_set_listeners_kinds(set(t, INFRA, name));
    }
    assert_eq!(own_listeners(t).len(), 3);
}

fn assert_set_listeners_kinds(s: &DesiredListenerSet) {
    assert_eq!(entry(s, "l").attached_routes, 1);
    assert_eq!(entry(s, "t").attached_routes, 1);
    assert_eq!(entry(s, "t").supported_kinds[0].kind, "TCPRoute");
}

/// The internal listeners of Gateway `gateway-conformance-infra/gw` (the base manifests
/// bring Gateways of their own).
fn own_listeners(t: &Translation) -> Vec<&String> {
    t.fragment
        .listeners
        .keys()
        .filter(|n| n.starts_with("gw-gateway-conformance-infra-gw-"))
        .collect()
}
