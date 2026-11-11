//! The inventory: everything the watches have seen, as plain data. The runtime keeps it
//! current from one reflector per kind; the translator reads it and nothing else, so it can
//! be built by hand in tests.
//!
//! Every namespaced object is keyed by `(namespace, name)`; cluster-scoped objects by name.
//! Secrets and ConfigMaps never carry their data here: the translator only learns whether
//! they exist and are usable, and the runtime writes the referenced ones to files.

use std::collections::{BTreeMap, BTreeSet};

use k8s_openapi::api::core::v1::Service;
use k8s_openapi::api::discovery::v1::EndpointSlice;
use k8s_openapi::api::networking::v1::{Ingress, IngressClass};

use crate::api::{
    BackendTLSPolicy, GRPCRoute, Gateway, GatewayClass, GatewayStatusAddress, HTTPRoute,
    ListenerSet, ReferenceGrant, TCPRoute, TLSRoute, UDPRoute,
};

/// `(namespace, name)` of a namespaced object.
pub type ObjectKey = (String, String);

/// Every watched object, by key.
#[derive(Debug, Clone, Default)]
pub struct Inventory {
    /// GatewayClasses by name (cluster-scoped), of every controller.
    pub gateway_classes: BTreeMap<String, GatewayClass>,
    /// Gateways of every class.
    pub gateways: BTreeMap<ObjectKey, Gateway>,
    /// HTTPRoutes.
    pub http_routes: BTreeMap<ObjectKey, HTTPRoute>,
    /// GRPCRoutes.
    pub grpc_routes: BTreeMap<ObjectKey, GRPCRoute>,
    /// TLSRoutes.
    pub tls_routes: BTreeMap<ObjectKey, TLSRoute>,
    /// TCPRoutes.
    pub tcp_routes: BTreeMap<ObjectKey, TCPRoute>,
    /// UDPRoutes.
    pub udp_routes: BTreeMap<ObjectKey, UDPRoute>,
    /// ReferenceGrants.
    pub reference_grants: BTreeMap<ObjectKey, ReferenceGrant>,
    /// ListenerSets.
    pub listener_sets: BTreeMap<ObjectKey, ListenerSet>,
    /// BackendTLSPolicies.
    pub backend_tls_policies: BTreeMap<ObjectKey, BackendTLSPolicy>,
    /// Services (backends, `ExternalName`, and the per-Gateway Services).
    pub services: BTreeMap<ObjectKey, Service>,
    /// EndpointSlices by their own name; the Service they belong to is their
    /// `kubernetes.io/service-name` label (see [`Inventory::endpoint_slices_of`]).
    pub endpoint_slices: BTreeMap<ObjectKey, EndpointSlice>,
    /// Secrets, without their data.
    pub secrets: BTreeMap<ObjectKey, SecretInfo>,
    /// ConfigMaps, without their data.
    pub config_maps: BTreeMap<ObjectKey, ConfigMapInfo>,
    /// Namespaces by name, with their labels (for `allowedRoutes` selectors).
    pub namespaces: BTreeMap<String, BTreeMap<String, String>>,
    /// Ingresses (only when `providers.kubernetes.ingress.enabled`).
    pub ingresses: BTreeMap<ObjectKey, Ingress>,
    /// IngressClasses by name (cluster-scoped; only when Ingress is enabled).
    pub ingress_classes: BTreeMap<String, IngressClass>,
    /// The per-Gateway Services the controller provisioned, by Gateway key (ADR-0029,
    /// "Shape"): their ports are the record of the internal port allocation.
    pub gateway_services: BTreeMap<ObjectKey, GatewayService>,
    /// The `gateway.networking.k8s.io/bundle-version` annotation of the installed CRDs, when
    /// known.
    pub crd_bundle_version: Option<String>,
    /// Gateway API kinds whose CRD is not installed (e.g. `TLSRoute`); they are skipped, not
    /// fatal.
    pub missing_kinds: BTreeSet<String>,
}

impl Inventory {
    /// The EndpointSlices of Service `namespace/service` (label `kubernetes.io/service-name`).
    pub fn endpoint_slices_of<'a>(
        &'a self,
        namespace: &'a str,
        service: &'a str,
    ) -> impl Iterator<Item = &'a EndpointSlice> + 'a {
        self.endpoint_slices
            .iter()
            .filter(move |((ns, _), _)| ns == namespace)
            .map(|(_, slice)| slice)
            .filter(move |slice| {
                slice
                    .metadata
                    .labels
                    .as_ref()
                    .and_then(|labels| labels.get(SERVICE_NAME_LABEL))
                    .is_some_and(|name| name == service)
            })
    }
}

/// The label that ties an EndpointSlice to its Service.
pub const SERVICE_NAME_LABEL: &str = "kubernetes.io/service-name";

/// What the translator may know about a Secret: that it exists, its type, and whether it
/// holds a usable certificate and key. Never the bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretInfo {
    /// Namespace.
    pub namespace: String,
    /// Name.
    pub name: String,
    /// `type` of the Secret, e.g. `kubernetes.io/tls`.
    pub kind: String,
    /// For TLS use: `Ok` when `tls.crt` and `tls.key` are present and parse as a certificate
    /// chain and a matching private key; otherwise why not, for the `ResolvedRefs` message.
    pub valid: Result<(), String>,
}

/// What the translator may know about a ConfigMap: that it exists, and whether it holds a
/// usable CA bundle (`ca.crt`, for BackendTLSPolicy). Never the bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigMapInfo {
    /// Namespace.
    pub namespace: String,
    /// Name.
    pub name: String,
    /// `Ok` when `ca.crt` is present and holds at least one PEM certificate; otherwise why
    /// not.
    pub ca_bundle: Result<(), String>,
}

/// A per-Gateway Service as it exists in the cluster.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GatewayService {
    /// Namespace of the Service.
    pub namespace: String,
    /// Name of the Service ([`crate::translate::gateway_service_name`]).
    pub name: String,
    /// TCP listener port (the Service's `port`) → internal port (its `targetPort`), which
    /// every replica opens as a listener. Every Gateway protocol but `UDP` is served over TCP.
    pub ports: BTreeMap<u16, u16>,
    /// UDP listener port → internal port. A TCP and a UDP listener may share a port number;
    /// each gets its own internal port.
    pub udp_ports: BTreeMap<u16, u16>,
    /// The Service's addresses: load-balancer ingress (IPs and host names), or its cluster
    /// IP for `ClusterIP`; they become the Gateway's `status.addresses`.
    pub addresses: Vec<GatewayStatusAddress>,
}
