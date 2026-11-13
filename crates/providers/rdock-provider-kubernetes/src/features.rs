//! The Gateway API features this controller claims in `GatewayClass.status.supportedFeatures`
//! (ADR-0029, "Only what works is claimed").
//!
//! This is the single list. A feature is added here only together with a test that proves
//! it (a translator test on fixtures in `tests/gateway_conformance.rs`,
//! `tests/gateway_extended.rs`, `tests/gateway_listenerset.rs` or `tests/gateway_udp.rs` that transcribes the upstream conformance test and, once CI
//! runs it, the upstream conformance test itself). With no feature flags, the conformance
//! suite runs exactly these features, so a feature listed without working support fails the
//! suite, and one missing from the list is skipped.
//!
//! Deliberately not claimed (the data plane or the translator cannot do it exactly):
//! `HTTPRouteRequestTimeout` (no total request deadline), `HTTPRouteBackendTimeout` (the
//! route's `read` timeout bounds each wait for response data, not the whole response),
//! `HTTPRouteRetry*` (no per-route retry policy), `HTTPRouteRequestMultipleMirrors`,
//! `HTTPRouteRequestPercentageMirror` (fractions are rounded to whole percents),
//! `HTTPRouteBackendRequestHeaderModification` (filters on one of several backends),
//! `HTTPRouteCORS`, `HTTPRouteBackendURLRewrite`, `HTTPRouteDestinationPortMatching`,
//! `GRPCRouteRequestHeaderModifier` (its test expects the filters of several rules with
//! identical matches to combine), `GatewayHTTPListenerIsolation`,
//! `GatewayRouteHostnameIntersectionPrecedence`, `GatewayStaticAddresses`,
//! `GatewayAddressEmpty`, `GatewayInfrastructure`, client certificate validation,
//! `TLSRouteModeTerminate`, `TLSRouteModeMixed`, `BackendTLSPolicy`.
//!
//! `UDPRoute` is claimed with every upstream test gated on it transcribed in
//! `tests/gateway_udp.rs` (v0.8, ADR-0030).

/// Supported feature names (e.g. `Gateway`, `HTTPRoute`, `HTTPRouteQueryParamMatching`),
/// sorted.
pub const SUPPORTED: &[&str] = &[
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
    "ListenerSet",
    "ReferenceGrant",
    "TCPRoute",
    "TLSRoute",
    "UDPRoute",
];

#[cfg(test)]
mod tests {
    #[test]
    fn the_list_is_sorted_and_unique() {
        assert!(super::SUPPORTED.windows(2).all(|w| w[0] < w[1]));
    }
}
