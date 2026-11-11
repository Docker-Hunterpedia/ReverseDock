//! The Gateway API features this controller claims in `GatewayClass.status.supportedFeatures`
//! (ADR-0029, "Only what works is claimed").
//!
//! This is the single list. A feature is added here only together with a test that proves
//! it (a translator test on fixtures and, once CI runs it, the upstream conformance test).
//! With no feature flags, the conformance suite runs exactly these features, so a feature
//! listed without working support fails the suite, and one missing from the list is skipped.

/// Supported feature names (e.g. `Gateway`, `HTTPRoute`, `HTTPRouteQueryParamMatching`),
/// sorted. Empty until the translators land.
pub const SUPPORTED: &[&str] = &[];

#[cfg(test)]
mod tests {
    #[test]
    fn the_list_is_sorted_and_unique() {
        assert!(super::SUPPORTED.windows(2).all(|w| w[0] < w[1]));
    }
}
