//! Upstream conformance tests (v1.7.0) of the Extended features in
//! [`rdock_provider_kubernetes::features::SUPPORTED`], transcribed against the translator
//! (see `gateway_conformance.rs` for the method). Each test names the feature and the
//! upstream test it transcribes; a feature is claimed only with its test here.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::type_complexity
)]

mod gateway_support;

use gateway_support::{
    Cluster, INFRA, Outcome, Request, Router, assert_accepted, assert_resolved, backends, get,
};
use rdock_model::middleware::{Middleware, RedirectScheme};
use rdock_model::service::Scheme;
use rdock_provider_kubernetes::translate::RouteKind::{Grpc, Http};

const SAME: (&str, &str) = (INFRA, "same-namespace");

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

fn request<'a>(method: &'a str, path: &'a str, headers: &'a [(&'a str, &'a str)]) -> Request<'a> {
    Request {
        host: "",
        path,
        method,
        headers,
    }
}

fn expect(r: &Router, gw: (&str, &str), port: u16, req: &Request<'_>, outcome: &Outcome) {
    let routed = r.route(gw, port, req);
    assert_eq!(&routed.outcome, outcome, "{req:?} → {:?}", routed.route);
}

fn every_supported_feature_has_a_test() -> &'static [&'static str] {
    rdock_provider_kubernetes::features::SUPPORTED
}

#[test]
fn the_claimed_features_are_exactly_the_tested_ones() {
    // Core features (tests in gateway_conformance.rs) and the Extended ones below.
    let tested = [
        "GRPCRoute",
        "GRPCRouteNamedRouteRule",
        "Gateway",
        "GatewayPort8080",
        "HTTPRoute",
        "HTTPRoute303RedirectStatusCode",
        "HTTPRoute307RedirectStatusCode",
        "HTTPRoute308RedirectStatusCode",
        "HTTPRouteBackendProtocolH2C",
        "HTTPRouteBackendProtocolWebSocket",
        "HTTPRouteHostRewrite",
        "HTTPRouteMethodMatching",
        "HTTPRouteNamedRouteRule",
        "HTTPRouteParentRefPort",
        "HTTPRoutePathRedirect",
        "HTTPRoutePathRewrite",
        "HTTPRoutePortRedirect",
        "HTTPRouteQueryParamMatching",
        "HTTPRouteRequestMirror",
        "HTTPRouteResponseHeaderModification",
        "HTTPRouteSchemeRedirect",
        "ReferenceGrant",
        "TCPRoute",
        "TLSRoute",
    ];
    assert_eq!(every_supported_feature_has_a_test(), tested);
}

#[test]
fn httproute_query_param_matching() {
    // HTTPRouteQueryParamMatching.
    let r = router(&["httproute-query-param-matching"]);
    assert_accepted(&r.translation, Http, (INFRA, "query-param-matching"), SAME);
    let none: &[(&str, &str)] = &[];
    let cases: &[(&str, &[(&str, &str)], Outcome)] = &[
        ("/?animal=whale", none, v1()),
        ("/?animal=dolphin", none, v2()),
        ("/?animal=dolphin&color=blue", none, v3()),
        ("/?ANIMAL=Whale", none, v3()),
        ("/?animal=whale&otherparam=irrelevant", none, v1()),
        ("/?animal=dolphin&color=yellow", none, v2()),
        ("/?color=blue", none, Outcome::NotFound),
        ("/?animal=dog", none, Outcome::NotFound),
        ("/?animal=whaledolphin", none, Outcome::NotFound),
        ("/", none, Outcome::NotFound),
        ("/path1?animal=whale", none, v1()),
        ("/?animal=whale", &[("version", "one")], v2()),
        ("/path2?animal=whale", &[("version", "two")], v3()),
        ("/path3?animal=shark", none, v1()),
        ("/path4?animal=kraken", &[("version", "three")], v1()),
        ("/?animal=shark", none, Outcome::NotFound),
        ("/path4?animal=kraken", none, Outcome::NotFound),
        ("/path5?animal=hydra", none, v1()),
        ("/?animal=hydra", &[("version", "four")], v3()),
    ];
    for (path, headers, outcome) in cases {
        expect(&r, SAME, 80, &request("GET", path, headers), outcome);
    }
}

#[test]
fn httproute_method_matching() {
    // HTTPRouteMethodMatching.
    let r = router(&["httproute-method-matching"]);
    assert_accepted(&r.translation, Http, (INFRA, "method-matching"), SAME);
    let none: &[(&str, &str)] = &[];
    let cases: &[(&str, &str, &[(&str, &str)], Outcome)] = &[
        ("POST", "/", none, v1()),
        ("GET", "/", none, v2()),
        ("HEAD", "/", none, Outcome::NotFound),
        ("GET", "/path1", none, v1()),
        ("PUT", "/", &[("version", "one")], v2()),
        ("POST", "/path2", &[("version", "two")], v3()),
        ("PATCH", "/path3", none, v1()),
        ("DELETE", "/path4", &[("version", "three")], v1()),
        ("PUT", "/", none, Outcome::NotFound),
        ("DELETE", "/path4", none, Outcome::NotFound),
        ("PATCH", "/path5", none, v1()),
        ("PATCH", "/", &[("version", "four")], v2()),
    ];
    for (method, path, headers, outcome) in cases {
        expect(&r, SAME, 80, &request(method, path, headers), outcome);
    }
}

fn header_rules(
    routed: &gateway_support::Routed,
    response: bool,
) -> rdock_model::middleware::HeaderRules {
    routed
        .middlewares
        .iter()
        .find_map(|m| match m {
            Middleware::Headers(h) => Some(if response {
                h.response.clone()
            } else {
                h.request.clone()
            }),
            _ => None,
        })
        .unwrap()
}

#[test]
fn httproute_response_header_modification() {
    // HTTPRouteResponseHeaderModification.
    let r = router(&["httproute-response-header-modifier"]);
    assert_accepted(
        &r.translation,
        Http,
        (INFRA, "response-header-modifier"),
        SAME,
    );
    let set = r.route(SAME, 80, &get("/set"));
    assert_eq!(set.outcome, v1());
    assert_eq!(
        header_rules(&set, true).set["X-Header-Set"],
        "set-overwrites-values"
    );
    let add = r.route(SAME, 80, &get("/add"));
    assert_eq!(
        header_rules(&add, true).add["X-Header-Add"],
        "add-appends-values"
    );
    let remove = r.route(SAME, 80, &get("/remove"));
    assert_eq!(
        header_rules(&remove, true).remove,
        vec!["X-Header-Remove".to_owned()]
    );
}

/// The status and `Location` the client receives for GET `path` on `gw:port` (the redirect
/// middleware executed, with the Gateway address `192.0.2.1` as the request's host, or
/// `example.org` on the HTTPS listener).
fn executed(r: &Router, gw: (&str, &str), port: u16, path: &str) -> (u16, String) {
    let host = if port == 443 { "example.org" } else { "" };
    let req = Request {
        host,
        path,
        method: "GET",
        headers: &[],
    };
    let (status, location) = r
        .execute(gw, port, &req)
        .unwrap_or_else(|| panic!("no redirect sent for {gw:?} {path}"));
    (status, location.unwrap_or_default())
}

fn redirect(
    r: &Router,
    gw: (&str, &str),
    port: u16,
    path: &str,
) -> rdock_model::middleware::RedirectConfig {
    let routed = r.route(gw, port, &get(path));
    routed
        .redirect()
        .cloned()
        .unwrap_or_else(|| panic!("no redirect for {path}: {routed:?}"))
}

#[test]
fn httproute_redirect_port() {
    // HTTPRoutePortRedirect: HTTPRouteRedirectPort.
    let r = router(&["httproute-redirect-port"]);
    assert_accepted(&r.translation, Http, (INFRA, "redirect-port"), SAME);
    for (path, status, host) in [
        ("/port", 302, None),
        ("/port-and-host", 302, Some("example.org")),
        ("/port-and-status", 301, None),
        ("/port-and-host-and-status", 302, Some("example.org")),
    ] {
        let rd = redirect(&r, SAME, 80, path);
        assert_eq!(rd.port, Some(8083), "{path}");
        assert_eq!(rd.status, Some(status), "{path}");
        assert_eq!(rd.hostname.as_deref(), host, "{path}");
        assert_eq!(rd.scheme, None);
        let host = host.unwrap_or("192.0.2.1");
        assert_eq!(
            executed(&r, SAME, 80, path),
            (status, format!("http://{host}:8083{path}"))
        );
    }
}

#[test]
fn httproute_redirect_scheme() {
    // HTTPRouteSchemeRedirect: HTTPRouteRedirectScheme.
    let r = router(&["httproute-redirect-scheme"]);
    assert_accepted(&r.translation, Http, (INFRA, "redirect-scheme"), SAME);
    for (path, status, host) in [
        ("/scheme", 302, None),
        ("/scheme-and-host", 302, Some("example.org")),
        ("/scheme-and-status", 301, None),
        ("/scheme-and-host-and-status", 302, Some("example.org")),
    ] {
        let rd = redirect(&r, SAME, 80, path);
        assert_eq!(rd.scheme, Some(RedirectScheme::Https), "{path}");
        // With a scheme and no port, the scheme's default port (the middleware's rule).
        assert_eq!(rd.port, None, "{path}");
        assert_eq!(rd.status, Some(status), "{path}");
        assert_eq!(rd.hostname.as_deref(), host, "{path}");
        let host = host.unwrap_or("192.0.2.1");
        assert_eq!(
            executed(&r, SAME, 80, path),
            (status, format!("https://{host}{path}"))
        );
    }
}

#[test]
fn httproute_redirect_port_and_scheme() {
    use RedirectScheme::{Http as H, Https as S};
    // HTTPRoutePortRedirect + GatewayPort8080: HTTPRouteRedirectPortAndScheme.
    let r = router(&["httproute-redirect-port-and-scheme"]);
    let gw8080 = (INFRA, "same-namespace-with-http-listener-on-8080");
    let https = (INFRA, "same-namespace-with-https-listener");
    assert_accepted(
        &r.translation,
        Http,
        (INFRA, "http-route-for-listener-on-port-80"),
        SAME,
    );
    assert_accepted(
        &r.translation,
        Http,
        (INFRA, "http-route-for-listener-on-port-8080"),
        gw8080,
    );
    assert_accepted(
        &r.translation,
        Http,
        (INFRA, "http-route-for-listener-on-port-443"),
        https,
    );
    // (gateway, listener port, path, scheme, port in the configuration, the `Location` the
    // upstream test expects: its scheme, host and port, the request's path)
    let cases = [
        (
            SAME,
            80,
            "/scheme-nil-and-port-nil",
            None,
            Some(80),
            "http://example.org",
        ),
        (
            SAME,
            80,
            "/scheme-nil-and-port-80",
            None,
            Some(80),
            "http://example.org",
        ),
        (
            SAME,
            80,
            "/scheme-nil-and-port-8080",
            None,
            Some(8080),
            "http://example.org:8080",
        ),
        (
            SAME,
            80,
            "/scheme-https-and-port-nil",
            Some(S),
            None,
            "https://example.org",
        ),
        (
            SAME,
            80,
            "/scheme-https-and-port-443",
            Some(S),
            Some(443),
            "https://example.org",
        ),
        (
            SAME,
            80,
            "/scheme-https-and-port-8443",
            Some(S),
            Some(8443),
            "https://example.org:8443",
        ),
        (
            gw8080,
            8080,
            "/scheme-nil-and-port-nil",
            None,
            Some(8080),
            "http://example.org:8080",
        ),
        (
            gw8080,
            8080,
            "/scheme-nil-and-port-80",
            None,
            Some(80),
            "http://example.org",
        ),
        (
            gw8080,
            8080,
            "/scheme-https-and-port-nil",
            Some(S),
            None,
            "https://example.org",
        ),
        (
            https,
            443,
            "/scheme-nil-and-port-nil",
            None,
            Some(443),
            "https://example.org",
        ),
        (
            https,
            443,
            "/scheme-nil-and-port-443",
            None,
            Some(443),
            "https://example.org",
        ),
        (
            https,
            443,
            "/scheme-nil-and-port-8443",
            None,
            Some(8443),
            "https://example.org:8443",
        ),
        (
            https,
            443,
            "/scheme-http-and-port-nil",
            Some(H),
            None,
            "http://example.org",
        ),
        (
            https,
            443,
            "/scheme-http-and-port-80",
            Some(H),
            Some(80),
            "http://example.org",
        ),
        (
            https,
            443,
            "/scheme-http-and-port-8080",
            Some(H),
            Some(8080),
            "http://example.org:8080",
        ),
    ];
    for (gw, port, path, scheme, redirect_port, origin) in cases {
        let rd = redirect(&r, gw, port, path);
        assert_eq!(rd.scheme, scheme, "{gw:?} {path}");
        assert_eq!(rd.port, redirect_port, "{gw:?} {path}");
        assert_eq!(rd.hostname.as_deref(), Some("example.org"), "{gw:?} {path}");
        assert_eq!(rd.status, Some(302));
        assert_eq!(
            executed(&r, gw, port, path),
            (302, format!("{origin}{path}")),
            "{gw:?} {path}"
        );
    }
}

#[test]
fn httproute_redirect_path() {
    // HTTPRoutePathRedirect: HTTPRouteRedirectPath.
    let r = router(&["httproute-redirect-path"]);
    assert_accepted(&r.translation, Http, (INFRA, "redirect-path"), SAME);
    let rd = redirect(&r, SAME, 80, "/original-prefix/lemon");
    let prefix = rd.prefix.unwrap();
    assert_eq!(
        (prefix.from.as_str(), prefix.to.as_str()),
        ("/original-prefix", "/replacement-prefix")
    );
    assert_eq!(rd.status, Some(302));
    let rd = redirect(&r, SAME, 80, "/full/path/original");
    assert_eq!(rd.path.as_deref(), Some("/full-path-replacement"));
    let rd = redirect(&r, SAME, 80, "/path-and-host");
    assert_eq!(rd.hostname.as_deref(), Some("example.org"));
    assert_eq!(rd.prefix.unwrap().to, "/replacement-prefix");
    let rd = redirect(&r, SAME, 80, "/path-and-status");
    assert_eq!(rd.status, Some(301));
    let rd = redirect(&r, SAME, 80, "/full-path-and-host");
    assert_eq!(
        (rd.hostname.as_deref(), rd.path.as_deref()),
        (Some("example.org"), Some("/replacement-full"))
    );
    let rd = redirect(&r, SAME, 80, "/full-path-and-status");
    assert_eq!(
        (rd.status, rd.path.as_deref()),
        (Some(301), Some("/replacement-full"))
    );
    // Executed, as the upstream test expects them.
    for (path, status, location) in [
        (
            "/original-prefix/lemon",
            302,
            "http://192.0.2.1/replacement-prefix/lemon",
        ),
        (
            "/full/path/original",
            302,
            "http://192.0.2.1/full-path-replacement",
        ),
        (
            "/path-and-host",
            302,
            "http://example.org/replacement-prefix",
        ),
        (
            "/path-and-status",
            301,
            "http://192.0.2.1/replacement-prefix",
        ),
        (
            "/full-path-and-host",
            302,
            "http://example.org/replacement-full",
        ),
        (
            "/full-path-and-status",
            301,
            "http://192.0.2.1/replacement-full",
        ),
    ] {
        assert_eq!(
            executed(&r, SAME, 80, path),
            (status, location.to_owned()),
            "{path}"
        );
    }
}

#[test]
fn httproute_303_307_308_redirects() {
    // HTTPRoute303RedirectStatusCode, HTTPRoute307RedirectStatusCode,
    // HTTPRoute308RedirectStatusCode: HTTPRoute303Redirect, HTTPRoute307Redirect,
    // HTTPRoute308Redirect.
    let r = router(&[
        "httproute-303-redirect",
        "httproute-307-redirect",
        "httproute-308-redirect",
    ]);
    for (route, path, status) in [
        ("303-redirect", "/see-other", 303),
        ("307-redirect", "/temporary", 307),
        ("308-redirect", "/permanent", 308),
    ] {
        assert_accepted(&r.translation, Http, (INFRA, route), SAME);
        let rd = redirect(&r, SAME, 80, path);
        assert_eq!(rd.status, Some(status), "{route}");
        assert_eq!(executed(&r, SAME, 80, path).0, status, "{route}");
    }
}

#[test]
fn httproute_rewrite_host() {
    // HTTPRouteHostRewrite: HTTPRouteRewriteHost.
    let r = router(&["httproute-rewrite-host"]);
    assert_accepted(&r.translation, Http, (INFRA, "rewrite-host"), SAME);
    let host = |path: &'static str| Request {
        host: "rewrite.example",
        path,
        method: "GET",
        headers: &[],
    };
    for (path, rewritten, outcome) in [
        ("/one", "one.example.org", v1()),
        ("/two", "example.org", v2()),
        ("/rewrite-host-and-modify-headers", "test.example.org", v2()),
    ] {
        let routed = r.route(SAME, 80, &host(path));
        assert_eq!(routed.outcome, outcome, "{path}");
        assert_eq!(
            header_rules(&routed, false).set["Host"],
            rewritten,
            "{path}"
        );
        // The Host header set by the rewrite is passed on to the backend.
        let service =
            &r.translation.fragment.services[routed.route.unwrap().service.as_ref().unwrap()];
        assert!(service.pass_host_header);
    }
    let routed = r.route(SAME, 80, &host("/rewrite-host-and-modify-headers"));
    let all: Vec<_> = routed
        .middlewares
        .iter()
        .filter_map(|m| match m {
            Middleware::Headers(h) => Some(h.request.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(all[1].set["X-Header-Set"], "set-overwrites-values");
    assert_eq!(all[1].remove, vec!["X-Header-Remove".to_owned()]);
}

#[test]
fn httproute_rewrite_path() {
    // HTTPRoutePathRewrite: HTTPRouteRewritePath.
    let r = router(&["httproute-rewrite-path"]);
    assert_accepted(&r.translation, Http, (INFRA, "rewrite-path"), SAME);
    // (request path, the path the backend receives)
    for (path, expected) in [
        ("/prefix/one/two", "/one/two"),
        ("/strip-prefix/three", "/three"),
        ("/strip-prefix", "/"),
        ("/full/one/two", "/one"),
        ("/full/rewrite-path-and-modify-headers/test", "/test"),
        ("/prefix/rewrite-path-and-modify-headers/one", "/prefix/one"),
    ] {
        let routed = r.route(SAME, 80, &get(path));
        assert_eq!(routed.outcome, v1(), "{path}");
        let rewritten = routed
            .middlewares
            .iter()
            .find_map(|m| match m {
                Middleware::ReplacePath(p) => Some(p.path.clone()),
                Middleware::Rewrite(rw) => {
                    let out = regex::Regex::new(&rw.regex)
                        .unwrap()
                        .replace_all(path, rw.replacement.as_str())
                        .into_owned();
                    Some(if out.is_empty() { "/".to_owned() } else { out })
                }
                _ => None,
            })
            .unwrap();
        assert_eq!(rewritten, expected, "{path}");
    }
}

#[test]
fn httproute_request_mirror() {
    // HTTPRouteRequestMirror: HTTPRouteRequestMirror.
    let r = router(&["httproute-request-mirror"]);
    assert_accepted(&r.translation, Http, (INFRA, "request-mirror"), SAME);
    assert_resolved(
        &r.translation,
        Http,
        (INFRA, "request-mirror"),
        SAME,
        true,
        "",
    );
    for path in ["/mirror", "/mirror-and-modify-headers"] {
        let routed = r.route(SAME, 80, &get(path));
        assert_eq!(routed.outcome, v1(), "{path}");
        let mirror = routed.route.unwrap().mirror.unwrap();
        assert_eq!(mirror.percent, 100);
        let service = &r.translation.fragment.services[&mirror.service];
        assert_ne!(service.backends.len(), 0);
    }
}

#[test]
fn httproute_listener_port_matching() {
    // HTTPRouteParentRefPort: HTTPRouteListenerPortMatching.
    let r = router(&["httproute-listener-port-matching"]);
    let gw = (INFRA, "httproute-listener-port-matching");
    for route in ["backend-v1", "backend-v2", "backend-v3"] {
        assert_accepted(&r.translation, Http, (INFRA, route), gw);
    }
    let host = |h: &'static str| Request {
        host: h,
        path: "/",
        method: "GET",
        headers: &[],
    };
    expect(&r, gw, 80, &host("foo.com"), &v1());
    expect(&r, gw, 8080, &host("foo.com:8080"), &v2());
    expect(&r, gw, 8080, &host("bar.com:8080"), &v2());
    expect(&r, gw, 8090, &host("foo.com:8090"), &v3());
    expect(&r, gw, 8090, &host("bar.com:8090"), &Outcome::NotFound);
}

#[test]
fn httproute_invalid_parent_ref_section_name_not_matching_port() {
    // HTTPRouteParentRefPort: HTTPRouteInvalidParentRefSectionNameNotMatchingPort.
    let r = router(&["httproute-invalid-parentref-section-name-not-matching-port"]);
    let gw = (
        INFRA,
        "gateway-with-one-not-matching-port-and-section-name-route",
    );
    let p = gateway_support::parent(
        &r.translation,
        Http,
        (INFRA, "httproute-listener-section-name-not-matching-port"),
        gw,
    );
    gateway_support::assert_condition(&p.conditions, "Accepted", false, "NoMatchingParent");
    let g = gateway_support::gateway(&r.translation, gw.0, gw.1);
    assert_eq!(g.listeners[0].attached_routes, 0);
}

#[test]
fn httproute_backend_protocol_h2c() {
    // HTTPRouteBackendProtocolH2C: `appProtocol: kubernetes.io/h2c`.
    let r = router(&["httproute-backend-protocol-h2c"]);
    assert_accepted(&r.translation, Http, (INFRA, "backend-protocol-h2c"), SAME);
    let routed = r.route(SAME, 80, &get("/"));
    assert_eq!(routed.outcome, v1());
    let service = &r.translation.fragment.services[routed.route.unwrap().service.as_ref().unwrap()];
    assert_eq!(service.scheme, Scheme::H2c);
    // The slice port of `second-port` (3001), not the first one.
    assert!(
        service
            .backends
            .iter()
            .all(|b| b.address.to_string().ends_with(":3001"))
    );
}

#[test]
fn httproute_backend_protocol_websocket() {
    // HTTPRouteBackendProtocolWebSocket: `appProtocol: kubernetes.io/ws`.
    let r = router(&["httproute-backend-protocol-websocket"]);
    assert_accepted(&r.translation, Http, (INFRA, "backend-protocol-ws"), SAME);
    let routed = r.route(SAME, 80, &get("/ws"));
    assert_eq!(routed.outcome, v1());
    let service = &r.translation.fragment.services[routed.route.unwrap().service.as_ref().unwrap()];
    // HTTP/1.1, where upgrades are relayed.
    assert_eq!(service.scheme, Scheme::Http);
}

#[test]
fn httproute_named_rule() {
    // HTTPRouteNamedRouteRule: HTTPRouteNamedRule.
    let r = router(&["httproute-named-rule"]);
    assert_accepted(&r.translation, Http, (INFRA, "http-named-rules"), SAME);
    expect(&r, SAME, 80, &get("/named"), &v1());
    expect(&r, SAME, 80, &get("/unnamed"), &v2());
}

#[test]
fn grpc_route_named_rule() {
    // GRPCRouteNamedRouteRule: GRPCRouteNamedRule.
    let r = router(&["grpcroute-named-rule"]);
    assert_accepted(&r.translation, Grpc, (INFRA, "grpc-named-rules"), SAME);
    let svc = "/gateway_api_conformance.echo_basic.grpcecho.GrpcEcho";
    expect(
        &r,
        SAME,
        80,
        &get(&format!("{svc}/Echo")),
        &backends(&["grpc-infra-backend-v1"]),
    );
    expect(
        &r,
        SAME,
        80,
        &get(&format!("{svc}/EchoTwo")),
        &backends(&["grpc-infra-backend-v2"]),
    );
}
