//! The pure half of the provider (ADR-0029): [`translate`] turns an [`Inventory`] into the
//! fragment the engine merges, the diagnostics, the desired status of every object and the
//! desired per-Gateway Services. It does no I/O and reads no clock, so the same inputs give
//! the same output on every replica, and it is tested on fixtures without a cluster.
//!
//! [`translate`] calls [`crate::gateway::translate`] and [`crate::ingress::translate`] and
//! merges their outputs; each owns its own module.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use rdock_config::merge::Fragment;
use rdock_model::Diagnostic;
use rdock_model::providers::KubernetesProvider;

use crate::api::{GatewayStatusAddress, ParentReference, RouteGroupKind, SupportedFeature};
use crate::inventory::{Inventory, ObjectKey};

/// The controller name of the IngressClasses we serve (`spec.controller`).
pub const INGRESS_CONTROLLER: &str = "reversedock.dev/ingress-controller";
/// Label on a per-Gateway Service: the Gateway's name (the Gateway API's well-known label).
pub const GATEWAY_NAME_LABEL: &str = "gateway.networking.k8s.io/gateway-name";
/// Label on a per-Gateway Service: the Gateway's namespace.
pub const GATEWAY_NAMESPACE_LABEL: &str = "reversedock.dev/gateway-namespace";
/// Annotation on a per-Gateway Service: the exact namespace of its Gateway. With
/// [`GATEWAY_NAME_ANNOTATION`] it ties the Service to its Gateway (a label value cannot hold
/// a Gateway name over 63 characters, so the labels only select).
pub const GATEWAY_NAMESPACE_ANNOTATION: &str = "reversedock.dev/gateway-namespace";
/// Annotation on a per-Gateway Service: the exact name of its Gateway.
pub const GATEWAY_NAME_ANNOTATION: &str = "reversedock.dev/gateway-name";
/// Label on everything the controller creates, to find (and delete) it again.
pub const MANAGED_BY_LABEL: &str = "app.kubernetes.io/managed-by";
/// Value of [`MANAGED_BY_LABEL`].
pub const MANAGED_BY: &str = "reversedock";

/// What the translator needs besides the inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    /// `providers.kubernetes`.
    pub provider: KubernetesProvider,
    /// The controller's own namespace (the per-Gateway Services and the Lease live there
    /// unless `gateway.service_namespace` says otherwise).
    pub controller_namespace: String,
    /// rdock's data directory; Secret and ConfigMap files are written below it
    /// ([`secret_paths`], [`config_map_path`]).
    pub data_dir: PathBuf,
}

impl Settings {
    /// The namespace of the per-Gateway Services.
    #[must_use]
    pub fn service_namespace(&self) -> &str {
        self.provider
            .gateway
            .service_namespace
            .as_deref()
            .unwrap_or(&self.controller_namespace)
    }
}

/// The certificate and key files of Secret `namespace/name`:
/// `<data dir>/kubernetes/secrets/<namespace>/<name>/{tls.crt,tls.key}` (ADR-0029). The
/// runtime writes them (directory 0700, files 0600, atomically); the translator names them in
/// `certificates` entries.
#[must_use]
pub fn secret_paths(data_dir: &Path, namespace: &str, name: &str) -> (PathBuf, PathBuf) {
    let dir = data_dir
        .join("kubernetes")
        .join("secrets")
        .join(namespace)
        .join(name);
    (dir.join("tls.crt"), dir.join("tls.key"))
}

/// The CA bundle file of ConfigMap `namespace/name` (its `ca.crt`, for BackendTLSPolicy):
/// `<data dir>/kubernetes/configmaps/<namespace>/<name>/ca.crt`.
#[must_use]
pub fn config_map_path(data_dir: &Path, namespace: &str, name: &str) -> PathBuf {
    data_dir
        .join("kubernetes")
        .join("configmaps")
        .join(namespace)
        .join(name)
        .join("ca.crt")
}

/// The name of the Service provisioned for Gateway `namespace/name` (ADR-0029):
/// `<namespace>-<name>` made a DNS-1035 label (`.` becomes `-`, a leading digit gets a `g`
/// in front) and cut to 52 characters, then `-` and 10 hexadecimal digits of a hash of the
/// exact `namespace/name`. The hash is always there, so Gateways `a/b-c` and `a-b/c` (the
/// same readable part) never share a Service; at most 63 characters.
#[must_use]
pub fn gateway_service_name(namespace: &str, name: &str) -> String {
    let hash = format!(
        "{:010x}",
        crate::gateway::names::fnv64(&format!("{namespace}/{name}")) >> 24
    );
    let mut readable: String = format!("{namespace}-{name}")
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    if !readable.starts_with(|c: char| c.is_ascii_lowercase()) {
        readable.insert(0, 'g');
    }
    let mut head: String = readable.chars().take(63 - 1 - hash.len()).collect();
    while head.ends_with('-') {
        head.pop();
    }
    format!("{head}-{hash}")
}

/// The value of [`GATEWAY_NAME_LABEL`] for a Gateway named `name`: the name itself, or (over
/// the 63 characters a label value may hold) a readable part and a hash of the whole. Only
/// for selecting; the exact Gateway is in [`GATEWAY_NAME_ANNOTATION`].
#[must_use]
pub fn gateway_label_value(name: &str) -> String {
    if name.len() <= 63 {
        name.to_owned()
    } else {
        crate::gateway::names::object_name("", &[name], name)
    }
}

/// Everything one translation produces.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Translation {
    /// Listeners, certificates, routes, services and middlewares for the engine
    /// (`name@kubernetes` once merged).
    pub fragment: Fragment,
    /// Problems found, also reported in the objects' status where the specification has a
    /// place for them.
    pub diagnostics: Vec<Diagnostic>,
    /// The status every object of ours should have.
    pub status: DesiredStatus,
    /// The per-Gateway Services that should exist (the leader creates, updates and deletes
    /// to match).
    pub services: Vec<DesiredService>,
    /// Secrets (`namespace`, `name`) to materialise as files ([`secret_paths`]): exactly the
    /// ones the fragment's certificates name. Files of other Secrets are removed.
    pub secrets: BTreeSet<ObjectKey>,
    /// ConfigMaps (`namespace`, `name`) whose `ca.crt` to materialise as a file
    /// ([`config_map_path`]).
    pub config_maps: BTreeSet<ObjectKey>,
}

impl Translation {
    /// Adds `other`'s output to this one. Objects with the same name in a fragment section
    /// are a bug in the translators (they use distinct prefixes); the later one wins and a
    /// diagnostic says so.
    pub fn merge(&mut self, other: Translation) {
        let Translation {
            fragment,
            diagnostics,
            status,
            services,
            secrets,
            config_maps,
        } = other;
        let mut clashes = Vec::new();
        extend(
            &mut self.fragment.routes,
            fragment.routes,
            "routes",
            &mut clashes,
        );
        extend(
            &mut self.fragment.services,
            fragment.services,
            "services",
            &mut clashes,
        );
        extend(
            &mut self.fragment.middlewares,
            fragment.middlewares,
            "middlewares",
            &mut clashes,
        );
        extend(
            &mut self.fragment.tcp_routes,
            fragment.tcp_routes,
            "tcp_routes",
            &mut clashes,
        );
        extend(
            &mut self.fragment.tcp_services,
            fragment.tcp_services,
            "tcp_services",
            &mut clashes,
        );
        extend(
            &mut self.fragment.udp_routes,
            fragment.udp_routes,
            "udp_routes",
            &mut clashes,
        );
        extend(
            &mut self.fragment.udp_services,
            fragment.udp_services,
            "udp_services",
            &mut clashes,
        );
        extend(
            &mut self.fragment.listeners,
            fragment.listeners,
            "listeners",
            &mut clashes,
        );
        extend(
            &mut self.fragment.certificates,
            fragment.certificates,
            "certificates",
            &mut clashes,
        );
        self.diagnostics.extend(clashes);
        self.diagnostics.extend(diagnostics);
        self.status.merge(status);
        self.services.extend(services);
        self.secrets.extend(secrets);
        self.config_maps.extend(config_maps);
    }
}

fn extend<T>(
    into: &mut BTreeMap<String, T>,
    from: BTreeMap<String, T>,
    section: &str,
    clashes: &mut Vec<Diagnostic>,
) {
    for (name, value) in from {
        if into.insert(name.clone(), value).is_some() {
            clashes.push(Diagnostic::warning(
                rdock_model::path_key(section, &name),
                "two Kubernetes translations produced the same name; the later one is used",
            ));
        }
    }
}

/// Translates the inventory: the Gateway API, then Ingress (when enabled), merged.
#[must_use]
pub fn translate(inventory: &Inventory, settings: &Settings) -> Translation {
    let mut translation = Translation::default();
    if settings.provider.gateway.enabled {
        translation.merge(crate::gateway::translate(inventory, settings));
    }
    if settings.provider.ingress.enabled {
        translation.merge(crate::ingress::translate(inventory, settings));
    }
    // A diagnostic about a shared object (a Service referenced by many routes) once.
    let mut seen = BTreeSet::new();
    translation
        .diagnostics
        .retain(|d| seen.insert((d.path.clone(), d.message.clone())));
    translation
}

/// A condition as the translator wants it. The runtime turns it into a metav1 `Condition`,
/// keeping `lastTransitionTime` when `status` is unchanged (the translator reads no clock).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DesiredCondition {
    /// `type`, e.g. `Accepted`.
    pub kind: String,
    /// `status`: `True` or `False` (`Unknown` is never written).
    pub status: bool,
    /// `reason`, e.g. `Accepted`, `NotAllowedByListeners`.
    pub reason: String,
    /// `message`.
    pub message: String,
    /// `observedGeneration`: the object's `metadata.generation` the condition was computed
    /// from.
    pub observed_generation: Option<i64>,
}

/// The route kinds that carry `status.parents`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RouteKind {
    /// `HTTPRoute`.
    Http,
    /// `GRPCRoute`.
    Grpc,
    /// `TLSRoute`.
    Tls,
    /// `TCPRoute`.
    Tcp,
    /// `UDPRoute`.
    Udp,
}

impl RouteKind {
    /// The `kind` as the Gateway API writes it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http => crate::api::kinds::HTTP_ROUTE,
            Self::Grpc => crate::api::kinds::GRPC_ROUTE,
            Self::Tls => crate::api::kinds::TLS_ROUTE,
            Self::Tcp => crate::api::kinds::TCP_ROUTE,
            Self::Udp => crate::api::kinds::UDP_ROUTE,
        }
    }
}

/// A route, by kind and key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RouteRef {
    /// Kind.
    pub kind: RouteKind,
    /// Namespace.
    pub namespace: String,
    /// Name.
    pub name: String,
}

/// The desired status of every object this controller is responsible for, keyed like the
/// inventory so the runtime can diff against the live objects. Objects that are not listed
/// are not ours and are never written. Each entry holds only what this controller owns:
/// the runtime merges it into the live status, preserving other controllers' conditions and
/// `parents[]`/`ancestors[]` entries (ADR-0029, "Status").
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DesiredStatus {
    /// GatewayClasses with our controller name.
    pub gateway_classes: BTreeMap<String, DesiredGatewayClass>,
    /// Gateways of our classes.
    pub gateways: BTreeMap<ObjectKey, DesiredGateway>,
    /// Routes: our entries of `status.parents` (`controllerName` is ours).
    pub routes: BTreeMap<RouteRef, Vec<DesiredRouteParent>>,
    /// ListenerSets attached to our Gateways.
    pub listener_sets: BTreeMap<ObjectKey, DesiredListenerSet>,
    /// BackendTLSPolicies: our entries of `status.ancestors`.
    pub backend_tls_policies: BTreeMap<ObjectKey, Vec<DesiredPolicyAncestor>>,
    /// Ingresses we claim: `status.loadBalancer.ingress`.
    pub ingresses: BTreeMap<ObjectKey, Vec<LoadBalancerAddress>>,
}

impl DesiredStatus {
    /// Adds `other`'s entries; entries for the same object are combined (lists appended).
    pub fn merge(&mut self, other: DesiredStatus) {
        self.gateway_classes.extend(other.gateway_classes);
        self.gateways.extend(other.gateways);
        for (route, parents) in other.routes {
            self.routes.entry(route).or_default().extend(parents);
        }
        self.listener_sets.extend(other.listener_sets);
        for (policy, ancestors) in other.backend_tls_policies {
            self.backend_tls_policies
                .entry(policy)
                .or_default()
                .extend(ancestors);
        }
        self.ingresses.extend(other.ingresses);
    }
}

/// Desired status of a GatewayClass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DesiredGatewayClass {
    /// `Accepted`, `SupportedVersion`.
    pub conditions: Vec<DesiredCondition>,
    /// `status.supportedFeatures` ([`crate::features::SUPPORTED`]), sorted.
    pub supported_features: Vec<SupportedFeature>,
}

/// Desired status of a Gateway.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DesiredGateway {
    /// `Accepted`, `Programmed`.
    pub conditions: Vec<DesiredCondition>,
    /// `status.addresses` (from the per-Gateway Service).
    pub addresses: Vec<GatewayStatusAddress>,
    /// `status.listeners`, in the order of `spec.listeners`.
    pub listeners: Vec<DesiredListener>,
    /// `status.attachedListenerSets`.
    pub attached_listener_sets: Option<i32>,
}

/// Desired status of one listener (of a Gateway or a ListenerSet).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DesiredListener {
    /// Listener name.
    pub name: String,
    /// `supportedKinds`.
    pub supported_kinds: Vec<RouteGroupKind>,
    /// `attachedRoutes`.
    pub attached_routes: i32,
    /// `Accepted`, `Programmed`, `ResolvedRefs`, `Conflicted`.
    pub conditions: Vec<DesiredCondition>,
}

/// Our entry in a route's `status.parents`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DesiredRouteParent {
    /// The parentRef as written in the route.
    pub parent_ref: ParentReference,
    /// `Accepted`, `ResolvedRefs`, `PartiallyInvalid`.
    pub conditions: Vec<DesiredCondition>,
}

/// Desired status of a ListenerSet.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DesiredListenerSet {
    /// `Accepted`, `Programmed`.
    pub conditions: Vec<DesiredCondition>,
    /// `status.listeners`.
    pub listeners: Vec<DesiredListener>,
}

/// Our entry in a policy's `status.ancestors`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DesiredPolicyAncestor {
    /// The ancestor (a Gateway).
    pub ancestor_ref: ParentReference,
    /// `Accepted`, `ResolvedRefs`.
    pub conditions: Vec<DesiredCondition>,
}

/// One address of an Ingress's `status.loadBalancer.ingress`.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct LoadBalancerAddress {
    /// An IP address.
    pub ip: Option<String>,
    /// A host name.
    pub hostname: Option<String>,
}

/// A per-Gateway Service that should exist (ADR-0029, "Shape"). The leader keeps the
/// existing port assignments of the live Service ([`crate::inventory::GatewayService`]) and
/// allocates internal ports for new listener ports from `gateway.port_range`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DesiredService {
    /// Namespace of the Service ([`Settings::service_namespace`]).
    pub namespace: String,
    /// Name ([`gateway_service_name`]).
    pub name: String,
    /// The Gateway it serves (`namespace`, `name`).
    pub gateway: ObjectKey,
    /// The TCP listener ports the Gateway wants (every protocol but `UDP`), sorted and unique.
    pub ports: Vec<u16>,
    /// The UDP listener ports the Gateway wants, sorted and unique.
    pub udp_ports: Vec<u16>,
    /// Labels: [`GATEWAY_NAME_LABEL`] ([`gateway_label_value`]), [`GATEWAY_NAMESPACE_LABEL`],
    /// [`MANAGED_BY_LABEL`] and the Gateway's `spec.infrastructure.labels`.
    pub labels: BTreeMap<String, String>,
    /// The Gateway's `spec.infrastructure.annotations`; the runtime adds
    /// [`GATEWAY_NAMESPACE_ANNOTATION`] and [`GATEWAY_NAME_ANNOTATION`].
    pub annotations: BTreeMap<String, String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A Service name must be a DNS-1035 label: at most 63 characters of `a-z`, `0-9` and
    /// `-`, starting with a letter and ending with a letter or digit.
    fn dns1035(name: &str) -> bool {
        name.len() <= 63
            && name.starts_with(|c: char| c.is_ascii_lowercase())
            && name.ends_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
            && name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    }

    #[test]
    fn service_names_fit_63_characters_and_are_stable() {
        let short = gateway_service_name("infra", "web");
        assert!(short.starts_with("infra-web-"), "{short}");
        assert!(dns1035(&short), "{short}");
        let long = gateway_service_name("gateway-conformance-infra", &"g".repeat(60));
        assert!(long.len() <= 63);
        assert!(long.starts_with("gateway-conformance-infra-ggg"));
        assert_eq!(
            long,
            gateway_service_name("gateway-conformance-infra", &"g".repeat(60))
        );
        assert_ne!(
            long,
            gateway_service_name("gateway-conformance-infra", &"g".repeat(61))
        );
    }

    #[test]
    fn service_names_never_collide_across_namespaces() {
        // `a/b-c` and `a-b/c` read the same once joined with `-`.
        assert_ne!(
            gateway_service_name("a", "b-c"),
            gateway_service_name("a-b", "c")
        );
        assert_ne!(
            gateway_service_name("team", "x"),
            gateway_service_name("team-x", "")
        );
    }

    #[test]
    fn service_names_are_valid_dns_labels() {
        for (ns, name) in [
            ("apps", "web.example.com"),
            ("1team", "web"),
            ("apps", &"a".repeat(253)),
            ("apps", &format!("{}-{}", "a".repeat(49), "b".repeat(10))),
            (&"n".repeat(63), &"g".repeat(253)),
            ("apps", &format!("{}.x", "a".repeat(52))),
        ] {
            let svc = gateway_service_name(ns, name);
            assert!(dns1035(&svc), "{ns}/{name} -> {svc}");
        }
    }

    #[test]
    fn gateway_label_values_fit_63_characters() {
        assert_eq!(gateway_label_value("web"), "web");
        let long = gateway_label_value(&"g".repeat(253));
        assert!(long.len() <= 63, "{long}");
        assert_ne!(long, gateway_label_value(&"g".repeat(252)));
    }

    #[test]
    fn secret_files_live_below_the_data_directory() {
        let (crt, key) = secret_paths(Path::new("/var/lib/rdock"), "apps", "web-tls");
        assert_eq!(
            crt,
            Path::new("/var/lib/rdock/kubernetes/secrets/apps/web-tls/tls.crt")
        );
        assert_eq!(
            key,
            Path::new("/var/lib/rdock/kubernetes/secrets/apps/web-tls/tls.key")
        );
        assert_eq!(
            config_map_path(Path::new("/d"), "apps", "ca"),
            Path::new("/d/kubernetes/configmaps/apps/ca/ca.crt")
        );
    }

    #[test]
    fn an_empty_inventory_translates_to_nothing() {
        let settings = Settings {
            provider: KubernetesProvider {
                ingress: rdock_model::providers::KubernetesIngress {
                    enabled: true,
                    ..Default::default()
                },
                ..Default::default()
            },
            controller_namespace: "rdock-system".to_owned(),
            data_dir: PathBuf::from("/d"),
        };
        assert_eq!(settings.service_namespace(), "rdock-system");
        assert_eq!(
            translate(&Inventory::default(), &settings),
            Translation::default()
        );
    }
}
