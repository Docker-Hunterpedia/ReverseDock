//! Condition types and reasons of the Gateway API (v1.7.0, `apis/v1/*_types.go`), and a
//! constructor for [`DesiredCondition`].

use crate::translate::DesiredCondition;

/// Condition types.
pub mod types {
    /// `Accepted`.
    pub const ACCEPTED: &str = "Accepted";
    /// `Programmed`.
    pub const PROGRAMMED: &str = "Programmed";
    /// `ResolvedRefs`.
    pub const RESOLVED_REFS: &str = "ResolvedRefs";
    /// `Conflicted`.
    pub const CONFLICTED: &str = "Conflicted";
    /// `SupportedVersion` (GatewayClass).
    pub const SUPPORTED_VERSION: &str = "SupportedVersion";
    /// `PartiallyInvalid` (routes).
    pub const PARTIALLY_INVALID: &str = "PartiallyInvalid";
}

/// Condition reasons.
pub mod reasons {
    /// `Accepted`.
    pub const ACCEPTED: &str = "Accepted";
    /// `Programmed`.
    pub const PROGRAMMED: &str = "Programmed";
    /// `ResolvedRefs`.
    pub const RESOLVED_REFS: &str = "ResolvedRefs";
    /// `SupportedVersion`.
    pub const SUPPORTED_VERSION: &str = "SupportedVersion";
    /// `UnsupportedVersion`.
    pub const UNSUPPORTED_VERSION: &str = "UnsupportedVersion";
    /// `InvalidParameters`.
    pub const INVALID_PARAMETERS: &str = "InvalidParameters";
    /// `ListenersNotValid` (Gateway `Accepted`).
    pub const LISTENERS_NOT_VALID: &str = "ListenersNotValid";
    /// `UnsupportedAddress` (Gateway `Accepted`).
    pub const UNSUPPORTED_ADDRESS: &str = "UnsupportedAddress";
    /// `AddressNotAssigned` (Gateway `Programmed`).
    pub const ADDRESS_NOT_ASSIGNED: &str = "AddressNotAssigned";
    /// `Invalid` (Gateway and listener `Programmed`).
    pub const INVALID: &str = "Invalid";
    /// `Pending` (`Programmed`, route `Accepted`).
    pub const PENDING: &str = "Pending";
    /// `UnsupportedProtocol` (listener `Accepted`, route `ResolvedRefs`).
    pub const UNSUPPORTED_PROTOCOL: &str = "UnsupportedProtocol";
    /// `UnsupportedValue` (listener and route `Accepted`, `PartiallyInvalid`).
    pub const UNSUPPORTED_VALUE: &str = "UnsupportedValue";
    /// `InvalidCertificateRef` (listener `ResolvedRefs`).
    pub const INVALID_CERTIFICATE_REF: &str = "InvalidCertificateRef";
    /// `InvalidRouteKinds` (listener `ResolvedRefs`).
    pub const INVALID_ROUTE_KINDS: &str = "InvalidRouteKinds";
    /// `RefNotPermitted` (listener and route `ResolvedRefs`).
    pub const REF_NOT_PERMITTED: &str = "RefNotPermitted";
    /// `HostnameConflict` (listener `Conflicted`).
    pub const HOSTNAME_CONFLICT: &str = "HostnameConflict";
    /// `ProtocolConflict` (listener `Conflicted`).
    pub const PROTOCOL_CONFLICT: &str = "ProtocolConflict";
    /// `NoConflicts` (listener `Conflicted`).
    pub const NO_CONFLICTS: &str = "NoConflicts";
    /// `NotAllowedByListeners` (route `Accepted`).
    pub const NOT_ALLOWED_BY_LISTENERS: &str = "NotAllowedByListeners";
    /// `NoMatchingListenerHostname` (route `Accepted`).
    pub const NO_MATCHING_LISTENER_HOSTNAME: &str = "NoMatchingListenerHostname";
    /// `NoMatchingParent` (route `Accepted`).
    pub const NO_MATCHING_PARENT: &str = "NoMatchingParent";
    /// `IncompatibleFilters` (route `Accepted`).
    pub const INCOMPATIBLE_FILTERS: &str = "IncompatibleFilters";
    /// `InvalidKind` (route `ResolvedRefs`).
    pub const INVALID_KIND: &str = "InvalidKind";
    /// `BackendNotFound` (route `ResolvedRefs`).
    pub const BACKEND_NOT_FOUND: &str = "BackendNotFound";
    /// `NotAllowed` (ListenerSet `Accepted`).
    pub const NOT_ALLOWED: &str = "NotAllowed";
    /// `ParentNotAccepted` (ListenerSet `Accepted`).
    pub const PARENT_NOT_ACCEPTED: &str = "ParentNotAccepted";
    /// `ParentNotProgrammed` (ListenerSet `Programmed`).
    pub const PARENT_NOT_PROGRAMMED: &str = "ParentNotProgrammed";
    /// `NoValidCACertificate` (BackendTLSPolicy `ResolvedRefs`).
    pub const INVALID_CA_CERTIFICATE_REF: &str = "InvalidCACertificateRef";
    /// `InvalidKind` for policies (BackendTLSPolicy `ResolvedRefs`).
    pub const INVALID_CA_CERTIFICATE_KIND: &str = "InvalidKind";
    /// `Conflicted` (policy `Accepted`).
    pub const CONFLICTED: &str = "Conflicted";
    /// `NoValidCACertificate` (policy `Accepted`).
    pub const NO_VALID_CA_CERTIFICATE: &str = "NoValidCACertificate";
}

/// A condition with `observedGeneration` set to `generation`.
#[must_use]
pub fn condition(
    kind: &str,
    status: bool,
    reason: &str,
    message: impl Into<String>,
    generation: Option<i64>,
) -> DesiredCondition {
    DesiredCondition {
        kind: kind.to_owned(),
        status,
        reason: reason.to_owned(),
        message: message.into(),
        observed_generation: generation,
    }
}
