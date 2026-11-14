//! The kinds of answers rdock produces itself, and their RFC 9457 problem types (F-GW-04,
//! ADR-0030). Each kind has a stable type URI under the documentation site's problem
//! reference, a title and a generic detail that never names an address, a backend or a
//! secret. Statuses without a kind of their own are `about:blank` with the reason phrase as
//! the title (RFC 9457 §4.2.1).

/// Where the problem types are documented; a type is this URL and `#<slug>`.
pub const PROBLEM_BASE: &str = "https://reversedock.oday-bakkour.com/docs/reference/problems/";

/// A kind of answer rdock produces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProblemKind {
    /// 400: the request is malformed (a repeated credential, a missing `Host`).
    BadRequest,
    /// 401: a credential is missing or not valid.
    Unauthenticated,
    /// 403: the client is known but not allowed (a network rule, a group restriction).
    Forbidden,
    /// 403: the client's key is banned for a while by an `abuse` middleware.
    Banned,
    /// 400: the request does not match the route's schemas (`validate`); the answer lists the
    /// errors in `errors`.
    ValidationFailed,
    /// 404: no route matches, or nothing is found at the path.
    NotFound,
    /// 405: the method is not allowed here.
    MethodNotAllowed,
    /// 408: the request body did not arrive in time.
    RequestTimeout,
    /// 413: the request body is larger than allowed.
    PayloadTooLarge,
    /// 414: the request target is too long.
    UriTooLong,
    /// 415: the request body's content type is not accepted (`validate`, `transform`).
    UnsupportedMediaType,
    /// 417: an `Expect` value other than `100-continue`.
    ExpectationFailed,
    /// 422: a `transform` request patch could not be applied (a `test` operation failed or a
    /// location is missing).
    PatchFailed,
    /// 429: a rate limit or a cap on requests in flight.
    RateLimited,
    /// 429: the consumer's quota for the current window is used up.
    QuotaExceeded,
    /// 431: the request headers are too large or too many.
    HeadersTooLarge,
    /// 500: rdock failed itself (a plugin panicked).
    InternalError,
    /// 502: the backend or an agent could not be reached or answered badly.
    BadGateway,
    /// 503: no backend can take the request now.
    ServiceUnavailable,
    /// 503: the route is in maintenance.
    Maintenance,
    /// 503: an `admission` middleware sheds load: more requests are in flight than the
    /// backend handles well.
    Overloaded,
    /// 401: an OIDC login could not be completed (the provider refused it, the login
    /// expired or its answer did not verify).
    LoginFailed,
    /// 503: the OpenID Connect provider cannot be reached, so no new login can start.
    IdentityProviderUnavailable,
    /// 504: the backend, an agent or the cache lock did not answer in time.
    GatewayTimeout,
}

impl ProblemKind {
    /// Every kind, for the reference page and the tests.
    pub const ALL: [Self; 24] = [
        Self::BadRequest,
        Self::ValidationFailed,
        Self::Unauthenticated,
        Self::LoginFailed,
        Self::Forbidden,
        Self::Banned,
        Self::NotFound,
        Self::MethodNotAllowed,
        Self::RequestTimeout,
        Self::PayloadTooLarge,
        Self::UriTooLong,
        Self::UnsupportedMediaType,
        Self::ExpectationFailed,
        Self::PatchFailed,
        Self::RateLimited,
        Self::QuotaExceeded,
        Self::HeadersTooLarge,
        Self::InternalError,
        Self::BadGateway,
        Self::ServiceUnavailable,
        Self::Maintenance,
        Self::Overloaded,
        Self::IdentityProviderUnavailable,
        Self::GatewayTimeout,
    ];

    /// The kind rdock uses for `status` when the answer names none.
    #[must_use]
    pub fn for_status(status: u16) -> Option<Self> {
        Some(match status {
            400 => Self::BadRequest,
            401 => Self::Unauthenticated,
            403 => Self::Forbidden,
            404 => Self::NotFound,
            405 => Self::MethodNotAllowed,
            408 => Self::RequestTimeout,
            413 => Self::PayloadTooLarge,
            414 => Self::UriTooLong,
            415 => Self::UnsupportedMediaType,
            417 => Self::ExpectationFailed,
            429 => Self::RateLimited,
            431 => Self::HeadersTooLarge,
            500 => Self::InternalError,
            502 => Self::BadGateway,
            503 => Self::ServiceUnavailable,
            504 => Self::GatewayTimeout,
            _ => return None,
        })
    }

    /// The status of answers of this kind.
    #[must_use]
    pub fn status(self) -> u16 {
        match self {
            Self::BadRequest | Self::ValidationFailed => 400,
            Self::Unauthenticated | Self::LoginFailed => 401,
            Self::Forbidden | Self::Banned => 403,
            Self::NotFound => 404,
            Self::MethodNotAllowed => 405,
            Self::RequestTimeout => 408,
            Self::PayloadTooLarge => 413,
            Self::UriTooLong => 414,
            Self::UnsupportedMediaType => 415,
            Self::ExpectationFailed => 417,
            Self::PatchFailed => 422,
            Self::RateLimited | Self::QuotaExceeded => 429,
            Self::HeadersTooLarge => 431,
            Self::InternalError => 500,
            Self::BadGateway => 502,
            Self::ServiceUnavailable
            | Self::Maintenance
            | Self::Overloaded
            | Self::IdentityProviderUnavailable => 503,
            Self::GatewayTimeout => 504,
        }
    }

    /// The feature of the maturity registry (`rdock_model::maturity`) that owns this kind's
    /// type URI and status: `problem-types` (stable, ADR-0033 lists problem types as a stable
    /// surface) for the kinds rdock's own answers use whatever is configured; a kind only one
    /// beta feature produces names that feature (`validate` and `transform` produce
    /// `validation-failed` and `patch-failed`). The settings that choose problem details stay
    /// with `validation-and-transformation`. The compatibility snapshot
    /// (`schema/compat/problems.json`) carries it, so removing or renumbering a stable type
    /// fails the compatibility check.
    #[must_use]
    pub fn feature(self) -> &'static str {
        match self {
            Self::Banned => "abuse",
            Self::QuotaExceeded => "consumers",
            Self::Overloaded => "admission-control",
            Self::LoginFailed | Self::IdentityProviderUnavailable => "oidc",
            Self::ValidationFailed | Self::PatchFailed => "validation-and-transformation",
            _ => "problem-types",
        }
    }

    /// The last part of the type URI.
    #[must_use]
    pub fn slug(self) -> &'static str {
        match self {
            Self::BadRequest => "bad-request",
            Self::ValidationFailed => "validation-failed",
            Self::UnsupportedMediaType => "unsupported-media-type",
            Self::PatchFailed => "patch-failed",
            Self::Unauthenticated => "unauthenticated",
            Self::Forbidden => "forbidden",
            Self::Banned => "banned",
            Self::NotFound => "not-found",
            Self::MethodNotAllowed => "method-not-allowed",
            Self::RequestTimeout => "request-timeout",
            Self::PayloadTooLarge => "payload-too-large",
            Self::UriTooLong => "uri-too-long",
            Self::ExpectationFailed => "expectation-failed",
            Self::RateLimited => "rate-limited",
            Self::QuotaExceeded => "quota-exceeded",
            Self::HeadersTooLarge => "headers-too-large",
            Self::InternalError => "internal-error",
            Self::BadGateway => "bad-gateway",
            Self::ServiceUnavailable => "service-unavailable",
            Self::Maintenance => "maintenance",
            Self::Overloaded => "overloaded",
            Self::LoginFailed => "login-failed",
            Self::IdentityProviderUnavailable => "identity-provider-unavailable",
            Self::GatewayTimeout => "gateway-timeout",
        }
    }

    /// The type URI.
    #[must_use]
    pub fn type_uri(self) -> String {
        format!("{PROBLEM_BASE}#{}", self.slug())
    }

    /// A short, stable summary (RFC 9457 `title`).
    #[must_use]
    pub fn title(self) -> &'static str {
        match self {
            Self::BadRequest => "Bad request",
            Self::ValidationFailed => "Request validation failed",
            Self::UnsupportedMediaType => "Unsupported media type",
            Self::PatchFailed => "Request transformation failed",
            Self::Unauthenticated => "Authentication required",
            Self::Forbidden => "Forbidden",
            Self::Banned => "Banned",
            Self::NotFound => "Not found",
            Self::MethodNotAllowed => "Method not allowed",
            Self::RequestTimeout => "Request timeout",
            Self::PayloadTooLarge => "Request body too large",
            Self::UriTooLong => "Request target too long",
            Self::ExpectationFailed => "Expectation failed",
            Self::RateLimited => "Rate limit exceeded",
            Self::QuotaExceeded => "Quota exceeded",
            Self::HeadersTooLarge => "Request headers too large",
            Self::InternalError => "Internal error",
            Self::BadGateway => "Bad gateway",
            Self::ServiceUnavailable => "Service unavailable",
            Self::Maintenance => "Down for maintenance",
            Self::Overloaded => "Overloaded",
            Self::LoginFailed => "Login failed",
            Self::IdentityProviderUnavailable => "Identity provider unavailable",
            Self::GatewayTimeout => "Gateway timeout",
        }
    }

    /// The default explanation (RFC 9457 `detail`). Generic on purpose: it names no host,
    /// address, backend, file or setting value.
    #[must_use]
    pub fn detail(self) -> &'static str {
        match self {
            Self::BadRequest => "The request is malformed or repeats a credential.",
            Self::ValidationFailed => {
                "The request does not match the schema of this route. `errors` lists where."
            }
            Self::UnsupportedMediaType => "The request body's content type is not accepted here.",
            Self::PatchFailed => {
                "The request body cannot be transformed for this route: it lacks a value the route expects."
            }
            Self::Unauthenticated => "The request carries no valid credential for this route.",
            Self::Forbidden => "The request is not allowed on this route.",
            Self::Banned => {
                "Too many failed or refused requests came from this client. It is refused for a while."
            }
            Self::NotFound => "Nothing is served at this address.",
            Self::MethodNotAllowed => "This method is not allowed at this address.",
            Self::RequestTimeout => "The request body did not arrive in time.",
            Self::PayloadTooLarge => "The request body is larger than this route accepts.",
            Self::UriTooLong => "The request target is longer than allowed.",
            Self::ExpectationFailed => "Only `Expect: 100-continue` is supported.",
            Self::RateLimited => {
                "Too many requests. Wait for the time given in `Retry-After` before retrying."
            }
            Self::QuotaExceeded => {
                "The request quota for the current window is used up. It renews at the time given in `Retry-After`."
            }
            Self::HeadersTooLarge => "The request headers are larger or more than allowed.",
            Self::InternalError => "The proxy could not complete the request.",
            Self::BadGateway => "The upstream service could not be reached or answered badly.",
            Self::ServiceUnavailable => "The service cannot take the request now.",
            Self::Maintenance => "The service is down for maintenance.",
            Self::Overloaded => {
                "The service has more requests than it can handle well and sheds some. Retry after the time given in `Retry-After`."
            }
            Self::LoginFailed => {
                "The login could not be completed. Open the page again to start a new login."
            }
            Self::IdentityProviderUnavailable => {
                "The identity provider cannot be reached, so a new login cannot start. Try again later."
            }
            Self::GatewayTimeout => "The upstream service did not answer in time.",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_have_unique_slugs_and_their_status_maps_back() {
        let mut slugs = std::collections::BTreeSet::new();
        for kind in ProblemKind::ALL {
            assert!(slugs.insert(kind.slug()), "{kind:?}");
            assert!(kind.type_uri().starts_with("https://"));
            if !matches!(
                kind,
                ProblemKind::QuotaExceeded
                    | ProblemKind::Maintenance
                    | ProblemKind::Overloaded
                    | ProblemKind::ValidationFailed
                    | ProblemKind::PatchFailed
                    | ProblemKind::LoginFailed
                    | ProblemKind::IdentityProviderUnavailable
                    | ProblemKind::Banned
            ) {
                assert_eq!(ProblemKind::for_status(kind.status()), Some(kind));
            }
        }
        assert_eq!(ProblemKind::for_status(418), None);
    }

    /// The type URIs point at headings of the reference page, so each must have one.
    #[test]
    fn every_kind_is_documented() {
        let page = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../apps/website/src/content/docs/docs/reference/problems.mdx"
        ))
        .unwrap();
        for kind in ProblemKind::ALL {
            assert!(
                page.contains(&format!(
                    "### `{}`\n\n**{} — {}.**",
                    kind.slug(),
                    kind.status(),
                    kind.title()
                )),
                "{kind:?} is missing from reference/problems.mdx"
            );
        }
    }
}
