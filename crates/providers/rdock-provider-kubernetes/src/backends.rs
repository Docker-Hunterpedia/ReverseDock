//! Kubernetes Service → backend addresses (ADR-0029, "Backends"; research §4.3), shared by the
//! Gateway API and Ingress translators.
//!
//! - A reference names a Service and one of its ports, by number ([`PortRef::Number`],
//!   Gateway API `backendRef.port`) or by name ([`PortRef::Name`], Ingress
//!   `service.port.name`).
//! - The addresses are the union of the Service's EndpointSlices (label
//!   `kubernetes.io/service-name`), de-duplicated by address and port, in a stable order.
//!   The port to dial is the slice port whose `name` equals the Service port's name (both
//!   empty for an unnamed port): Kubernetes has already resolved a named `targetPort` per
//!   pod there, so `targetPort` is never read. IPv6 addresses are bracketed.
//! - Conditions (a missing condition defaults as the API documents: `ready` true, `serving`
//!   like `ready`, `terminating` false): `ready` endpoints are the pool. Endpoints that are
//!   `serving` and `terminating` are what kube-proxy falls back to when nothing is ready;
//!   they become **backup** backends (`Backend.backup`: used only when no primary backend
//!   is available, which also covers ready endpoints ejected by health checks) while a
//!   ready endpoint exists, and the primary pool when none does (the model refuses a pool of
//!   backups only). Endpoints that are not serving are left out.
//! - Loopback, link-local and unspecified endpoint addresses are never used
//!   ([`refused_address`]): whoever may write a Service's EndpointSlices could otherwise
//!   point rdock at its own admin listener or a metadata service. One warning per Service
//!   names them ([`refused_diagnostic`]).
//! - A Service without any usable endpoint resolves to an empty list; callers answer 503
//!   for it ([`respond`]), as the Gateway API recommends.
//! - Headless Services (`clusterIP: None`) have slices like any other. `ExternalName`
//!   Services have none: they are refused unless allowed (CVE-2021-25740), and then resolve
//!   to the external name and the Service port.
//! - `appProtocol` picks the scheme ([`scheme`]).

use std::collections::BTreeMap;

use k8s_openapi::api::core::v1::{Service as KubeService, ServicePort};
use rdock_model::service::{
    Backend, LoadBalancer, Respond, Scheme, Service, SplitTarget, TcpService, TcpTimeouts, Timeouts,
};
use rdock_model::values::BackendAddress;

use crate::inventory::Inventory;

/// A port of a Service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortRef<'a> {
    /// The Service port number (`spec.ports[].port`).
    Number(u16),
    /// The Service port name (`spec.ports[].name`).
    Name(&'a str),
}

/// What a Service port resolves to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceBackends {
    /// Namespace of the Service.
    pub namespace: String,
    /// Name of the Service.
    pub name: String,
    /// The Service port number.
    pub port: u16,
    /// The Service port name, when it has one.
    pub port_name: Option<String>,
    /// The Service port's `appProtocol`.
    pub app_protocol: Option<String>,
    /// Where to send traffic.
    pub targets: Targets,
    /// Endpoint addresses left out because they are loopback, link-local or unspecified
    /// ([`refused_address`]), sorted and unique; [`refused_diagnostic`] reports them.
    pub refused: Vec<String>,
}

/// The targets of a Service port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Targets {
    /// Pod addresses from EndpointSlices; empty when no endpoint is usable.
    Endpoints(Vec<Backend>),
    /// An `ExternalName` Service (only when allowed): the external name and the port.
    External {
        /// The DNS name.
        host: String,
        /// The Service port.
        port: u16,
    },
}

impl Targets {
    /// The backends: the endpoints, or the external name as one backend.
    #[must_use]
    pub fn backends(&self) -> Vec<Backend> {
        match self {
            Self::Endpoints(backends) => backends.clone(),
            Self::External { host, port } => vec![Backend::new(BackendAddress::Tcp {
                host: host.clone(),
                port: *port,
            })],
        }
    }
}

/// Why a Service port cannot be resolved.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BackendError {
    /// No such Service.
    #[error("Service {namespace}/{name} does not exist")]
    ServiceNotFound {
        /// Namespace.
        namespace: String,
        /// Name.
        name: String,
    },
    /// The Service has no such port.
    #[error("Service {namespace}/{name} has no port {port}")]
    PortNotFound {
        /// Namespace.
        namespace: String,
        /// Name.
        name: String,
        /// The port as referenced.
        port: String,
    },
    /// The reference names no port and the Service has several.
    #[error("a port is required for Service {namespace}/{name}")]
    PortRequired {
        /// Namespace.
        namespace: String,
        /// Name.
        name: String,
    },
    /// An `ExternalName` Service while they are not allowed.
    #[error(
        "Service {namespace}/{name} is of type ExternalName, which is refused unless providers.kubernetes.gateway.allow_external_name is set"
    )]
    ExternalNameNotAllowed {
        /// Namespace.
        namespace: String,
        /// Name.
        name: String,
    },
}

/// Resolves port `port` of Service `namespace/name` (`None`: the only port of a single-port
/// Service).
///
/// # Errors
///
/// When the Service or the port does not exist, or the Service is an `ExternalName` one and
/// `allow_external_name` is off.
pub fn resolve(
    inventory: &Inventory,
    namespace: &str,
    name: &str,
    port: Option<PortRef<'_>>,
    allow_external_name: bool,
) -> Result<ServiceBackends, BackendError> {
    resolve_protocol(inventory, namespace, name, port, allow_external_name, "TCP")
}

/// [`resolve`] for a transport: a port number that a Service has twice (`TCP` and `UDP` 53)
/// resolves to the entry of `protocol` (`TCP` or `UDP`); one it has once resolves to that
/// entry, whatever its protocol.
///
/// # Errors
///
/// As [`resolve`].
pub fn resolve_protocol(
    inventory: &Inventory,
    namespace: &str,
    name: &str,
    port: Option<PortRef<'_>>,
    allow_external_name: bool,
    protocol: &str,
) -> Result<ServiceBackends, BackendError> {
    let key = (namespace.to_owned(), name.to_owned());
    let Some(service) = inventory.services.get(&key) else {
        return Err(BackendError::ServiceNotFound {
            namespace: namespace.to_owned(),
            name: name.to_owned(),
        });
    };
    let service_port = find_port(service, namespace, name, port, protocol)?;
    let external = service.spec.as_ref().and_then(|spec| {
        (spec.type_.as_deref() == Some("ExternalName"))
            .then(|| spec.external_name.clone().unwrap_or_default())
    });
    let port_number = u16::try_from(service_port.port).unwrap_or(0);
    let targets = match external {
        Some(_) if !allow_external_name => {
            return Err(BackendError::ExternalNameNotAllowed {
                namespace: namespace.to_owned(),
                name: name.to_owned(),
            });
        }
        Some(host) => Targets::External {
            host: host.trim_end_matches('.').to_owned(),
            port: port_number,
        },
        None => Targets::Endpoints(endpoints(inventory, namespace, name, &service_port)),
    };
    let refused = if matches!(targets, Targets::Endpoints(_)) {
        refused_addresses(inventory, namespace, name)
    } else {
        Vec::new()
    };
    Ok(ServiceBackends {
        refused,
        namespace: namespace.to_owned(),
        name: name.to_owned(),
        port: port_number,
        port_name: service_port.name.clone().filter(|n| !n.is_empty()),
        app_protocol: service_port.app_protocol.clone(),
        targets,
    })
}

/// The Service port `port` refers to.
fn find_port(
    service: &KubeService,
    namespace: &str,
    name: &str,
    port: Option<PortRef<'_>>,
    protocol: &str,
) -> Result<ServicePort, BackendError> {
    let ports = service
        .spec
        .as_ref()
        .and_then(|spec| spec.ports.as_deref())
        .unwrap_or_default();
    let found = match port {
        Some(PortRef::Number(number)) => {
            let numbered = || ports.iter().filter(|p| p.port == i32::from(number));
            numbered()
                .find(|p| p.protocol.as_deref().unwrap_or("TCP") == protocol)
                .or_else(|| numbered().next())
        }
        Some(PortRef::Name(port_name)) => {
            ports.iter().find(|p| p.name.as_deref() == Some(port_name))
        }
        None if ports.len() == 1 => ports.first(),
        None => {
            return Err(BackendError::PortRequired {
                namespace: namespace.to_owned(),
                name: name.to_owned(),
            });
        }
    };
    found.cloned().ok_or_else(|| BackendError::PortNotFound {
        namespace: namespace.to_owned(),
        name: name.to_owned(),
        port: match port {
            Some(PortRef::Number(n)) => n.to_string(),
            Some(PortRef::Name(n)) => n.to_owned(),
            None => String::new(),
        },
    })
}

/// The backends of `service_port` of Service `namespace/service`, from its EndpointSlices.
#[must_use]
pub fn endpoints(
    inventory: &Inventory,
    namespace: &str,
    service: &str,
    service_port: &ServicePort,
) -> Vec<Backend> {
    let wanted = service_port.name.as_deref().unwrap_or_default();
    // address → ready (true wins over a serving-and-terminating sighting in another slice),
    // with the endpoint's zone and topology hints (`hints.forZones`).
    let mut seen: BTreeMap<String, Sighting> = BTreeMap::new();
    for slice in inventory.endpoint_slices_of(namespace, service) {
        let Some(port) = slice
            .ports
            .iter()
            .flatten()
            .find(|p| p.name.as_deref().unwrap_or_default() == wanted)
            .and_then(|p| p.port)
            .and_then(|p| u16::try_from(p).ok())
            .filter(|p| *p != 0)
        else {
            continue;
        };
        let ipv6 = slice.address_type == "IPv6";
        for endpoint in &slice.endpoints {
            let conditions = endpoint.conditions.clone().unwrap_or_default();
            let ready = conditions.ready.unwrap_or(true);
            let serving = conditions.serving.unwrap_or(ready);
            let terminating = conditions.terminating.unwrap_or(false);
            let usable = if ready {
                Some(true)
            } else if serving && terminating {
                Some(false)
            } else {
                None
            };
            let Some(ready) = usable else { continue };
            let sighting = Sighting {
                ready,
                zone: endpoint.zone.clone().filter(|z| !z.is_empty()),
                for_zones: endpoint
                    .hints
                    .as_ref()
                    .and_then(|h| h.for_zones.as_ref())
                    .map(|zones| {
                        zones
                            .iter()
                            .map(|z| z.name.clone())
                            .filter(|z| !z.is_empty())
                            .collect()
                    })
                    .unwrap_or_default(),
            };
            for address in endpoint.addresses.iter().filter(|a| !refused_address(a)) {
                let address = if ipv6 || address.contains(':') {
                    format!("[{}]:{port}", address.trim_matches(['[', ']']))
                } else {
                    format!("{address}:{port}")
                };
                match seen.get_mut(&address) {
                    // A ready sighting replaces a terminating one, zone and hints included.
                    Some(entry) if ready && !entry.ready => *entry = sighting.clone(),
                    Some(_) => {}
                    None => {
                        seen.insert(address, sighting.clone());
                    }
                }
            }
        }
    }
    let any_ready = seen.values().any(|s| s.ready);
    // Some endpoints with hints and some without: Kubernetes is moving to or from Topology
    // Aware Routing, and kube-proxy then uses every endpoint ("Safeguards", Topology Aware
    // Routing, kubernetes.io, checked 2026-11-13). Zones are dropped too, so nothing filters.
    let with_hints = seen.values().filter(|s| !s.for_zones.is_empty()).count();
    if with_hints > 0 && with_hints < seen.len() {
        for sighting in seen.values_mut() {
            sighting.zone = None;
            sighting.for_zones.clear();
        }
    }
    seen.into_iter()
        .filter_map(|(address, sighting)| {
            let address = address.parse::<BackendAddress>().ok()?;
            Some(Backend {
                backup: any_ready && !sighting.ready,
                zone: sighting.zone,
                for_zones: sighting.for_zones,
                ..Backend::new(address)
            })
        })
        .collect()
}

/// One endpoint address as an EndpointSlice reports it.
#[derive(Debug, Clone)]
struct Sighting {
    ready: bool,
    zone: Option<String>,
    for_zones: Vec<String>,
}

/// Whether an EndpointSlice address must never be dialled: loopback (`127.0.0.0/8`, `::1`),
/// link-local (`169.254.0.0/16`, `fe80::/10`: cloud metadata services) and unspecified
/// (`0.0.0.0`, `::`), also as IPv4-mapped IPv6. Anyone who may write EndpointSlices for a
/// Service could otherwise point rdock at its own admin listener on loopback or at the node's
/// metadata service. Host names and unparsable values are left to the address parser.
#[must_use]
pub fn refused_address(address: &str) -> bool {
    let Ok(ip) = address.trim_matches(['[', ']']).parse::<std::net::IpAddr>() else {
        return false;
    };
    let ip = match ip {
        std::net::IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map_or(std::net::IpAddr::V6(v6), std::net::IpAddr::V4),
        v4 @ std::net::IpAddr::V4(_) => v4,
    };
    match ip {
        std::net::IpAddr::V4(v4) => v4.is_loopback() || v4.is_link_local() || v4.is_unspecified(),
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback() || v6.is_unspecified() || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// The refused addresses ([`refused_address`]) among the endpoints of Service
/// `namespace/service`, sorted and unique.
fn refused_addresses(inventory: &Inventory, namespace: &str, service: &str) -> Vec<String> {
    let refused: std::collections::BTreeSet<String> = inventory
        .endpoint_slices_of(namespace, service)
        .flat_map(|slice| &slice.endpoints)
        .flat_map(|endpoint| &endpoint.addresses)
        .filter(|address| refused_address(address))
        .cloned()
        .collect();
    refused.into_iter().collect()
}

/// One warning for a Service whose EndpointSlices hold refused addresses, or `None`.
#[must_use]
pub fn refused_diagnostic(resolved: &ServiceBackends) -> Option<rdock_model::Diagnostic> {
    (!resolved.refused.is_empty()).then(|| {
        rdock_model::Diagnostic::warning(
            crate::gateway::object_path(
                &crate::gateway::object_id("Service", &resolved.namespace, &resolved.name),
                "",
            ),
            format!(
                "endpoint addresses {} are loopback, link-local or unspecified and are never used",
                resolved.refused.join(", ")
            ),
        )
    })
}

/// The scheme for a Service port's `appProtocol` (GEP-1911): `kubernetes.io/h2c` → `h2c`;
/// `kubernetes.io/wss`, `https` and `kubernetes.io/https` → `https`; `kubernetes.io/ws`
/// and `http` → `http` (WebSocket upgrades need nothing more); anything else, or none,
/// → `default`.
#[must_use]
pub fn scheme(app_protocol: Option<&str>, default: Scheme) -> Scheme {
    match app_protocol.map(str::to_ascii_lowercase).as_deref() {
        Some("kubernetes.io/h2c") => Scheme::H2c,
        Some("kubernetes.io/wss" | "https" | "kubernetes.io/https") => Scheme::Https,
        Some("kubernetes.io/ws" | "http") => Scheme::Http,
        _ => default,
    }
}

/// An HTTP service over `backends`; a Service without usable endpoints answers 503
/// instead (the model needs at least one backend).
#[must_use]
pub fn http_service(backends: Vec<Backend>, scheme: Scheme) -> Service {
    if backends.is_empty() {
        return respond(503);
    }
    Service {
        backends,
        scheme,
        ..base()
    }
}

/// A service that answers every request with `status`.
#[must_use]
pub fn respond(status: u16) -> Service {
    Service {
        respond: Some(Respond { status }),
        ..base()
    }
}

/// A weighted split over other services (`(service name, weight)`, weights above 0).
#[must_use]
pub fn split(targets: Vec<(String, u32)>) -> Service {
    Service {
        split: targets
            .into_iter()
            .map(|(service, weight)| SplitTarget { service, weight })
            .collect(),
        ..base()
    }
}

/// A UDP service over `backends` (at least one), every setting at its default.
#[must_use]
pub fn udp_service(backends: Vec<Backend>) -> rdock_model::service::UdpService {
    rdock_model::service::UdpService {
        backends,
        load_balancer: rdock_model::service::UdpLoadBalancer::default(),
        timeouts: rdock_model::service::UdpTimeouts::default(),
        responses: None,
        requests: None,
        health: rdock_model::service::UdpHealth::default(),
    }
}

/// A TCP service over `backends` (at least one).
#[must_use]
pub fn tcp_service(backends: Vec<Backend>) -> TcpService {
    TcpService {
        backends,
        proxy_protocol: None,
        timeouts: TcpTimeouts::default(),
    }
}

/// A service with no targets and every setting at its default.
fn base() -> Service {
    Service {
        backends: Vec::new(),
        split: Vec::new(),
        respond: None,
        scheme: Scheme::Http,
        load_balancer: LoadBalancer::default(),
        health: None,
        retries: None,
        timeouts: Timeouts::default(),
        tls: None,
        sticky: None,
        pass_host_header: true,
        max_requests: None,
        max_connections_per_backend: None,
        failover: rdock_model::service::Failover::Strict,
        overprovisioning: None,
        locality: None,
        hedge: None,
    }
}

#[cfg(test)]
mod tests {
    use k8s_openapi::api::core::v1::ServiceSpec;
    use k8s_openapi::api::discovery::v1::{
        Endpoint, EndpointConditions, EndpointPort, EndpointSlice,
    };
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

    use super::*;
    use crate::inventory::SERVICE_NAME_LABEL;

    fn service(ports: &[(Option<&str>, u16)], external: Option<&str>) -> KubeService {
        KubeService {
            metadata: ObjectMeta {
                name: Some("svc".into()),
                namespace: Some("ns".into()),
                ..ObjectMeta::default()
            },
            spec: Some(ServiceSpec {
                ports: Some(
                    ports
                        .iter()
                        .map(|(name, port)| ServicePort {
                            name: name.map(str::to_owned),
                            port: i32::from(*port),
                            ..ServicePort::default()
                        })
                        .collect(),
                ),
                type_: external.map(|_| "ExternalName".to_owned()),
                external_name: external.map(str::to_owned),
                ..ServiceSpec::default()
            }),
            status: None,
        }
    }

    fn endpoint(address: &str, ready: Option<bool>, serving: bool, terminating: bool) -> Endpoint {
        Endpoint {
            addresses: vec![address.to_owned()],
            conditions: Some(EndpointConditions {
                ready,
                serving: Some(serving),
                terminating: Some(terminating),
            }),
            ..Endpoint::default()
        }
    }

    fn slice(
        name: &str,
        address_type: &str,
        ports: &[(Option<&str>, i32)],
        endpoints: Vec<Endpoint>,
    ) -> EndpointSlice {
        EndpointSlice {
            metadata: ObjectMeta {
                name: Some(name.into()),
                namespace: Some("ns".into()),
                labels: Some([(SERVICE_NAME_LABEL.to_owned(), "svc".to_owned())].into()),
                ..ObjectMeta::default()
            },
            address_type: address_type.to_owned(),
            endpoints,
            ports: Some(
                ports
                    .iter()
                    .map(|(name, port)| EndpointPort {
                        name: name.map(str::to_owned),
                        port: Some(*port),
                        ..EndpointPort::default()
                    })
                    .collect(),
            ),
        }
    }

    fn inventory(service: KubeService, slices: Vec<EndpointSlice>) -> Inventory {
        let mut inventory = Inventory::default();
        inventory
            .services
            .insert(("ns".into(), "svc".into()), service);
        for s in slices {
            let name = s.metadata.name.clone().unwrap_or_default();
            inventory.endpoint_slices.insert(("ns".into(), name), s);
        }
        inventory
    }

    fn addresses(resolved: &ServiceBackends) -> Vec<(String, bool)> {
        resolved
            .targets
            .backends()
            .iter()
            .map(|b| (b.address.to_string(), b.backup))
            .collect()
    }

    #[test]
    fn zones_and_topology_hints_are_kept() {
        use k8s_openapi::api::discovery::v1::{EndpointHints, ForZone};
        let zoned = |address: &str, zone: &str, hints: &[&str], ready: bool| Endpoint {
            zone: Some(zone.to_owned()),
            hints: (!hints.is_empty()).then(|| EndpointHints {
                for_zones: Some(
                    hints
                        .iter()
                        .map(|z| ForZone {
                            name: (*z).to_owned(),
                        })
                        .collect(),
                ),
                ..EndpointHints::default()
            }),
            ..endpoint(address, Some(ready), true, !ready)
        };
        let inv = inventory(
            service(&[(Some("http"), 80)], None),
            vec![
                slice(
                    "a",
                    "IPv4",
                    &[(Some("http"), 8080)],
                    vec![
                        zoned("10.0.0.1", "eu-1a", &["eu-1a"], true),
                        zoned("10.0.0.2", "eu-1b", &["eu-1c", "eu-1b"], true),
                        zoned("10.0.0.3", "eu-1c", &["eu-1c"], true),
                        // Terminating here, ready (with other hints) in the next slice.
                        zoned("10.0.0.4", "eu-1a", &["eu-1a"], false),
                    ],
                ),
                slice(
                    "b",
                    "IPv4",
                    &[(Some("http"), 8080)],
                    vec![zoned("10.0.0.4", "eu-1a", &["eu-1b"], true)],
                ),
            ],
        );
        let resolved = resolve(&inv, "ns", "svc", None, false).unwrap();
        let backends: Vec<(String, Option<String>, Vec<String>)> = resolved
            .targets
            .backends()
            .into_iter()
            .map(|b| (b.address.to_string(), b.zone, b.for_zones))
            .collect();
        let s = |v: &str| v.to_owned();
        assert_eq!(
            backends,
            vec![
                (s("10.0.0.1:8080"), Some(s("eu-1a")), vec![s("eu-1a")]),
                (
                    s("10.0.0.2:8080"),
                    Some(s("eu-1b")),
                    vec![s("eu-1c"), s("eu-1b")]
                ),
                (s("10.0.0.3:8080"), Some(s("eu-1c")), vec![s("eu-1c")]),
                (s("10.0.0.4:8080"), Some(s("eu-1a")), vec![s("eu-1b")]),
            ]
        );
        // One endpoint without a hint: a transition; nothing is filtered by zone.
        let inv = inventory(
            service(&[(Some("http"), 80)], None),
            vec![slice(
                "a",
                "IPv4",
                &[(Some("http"), 8080)],
                vec![
                    zoned("10.0.0.1", "eu-1a", &["eu-1a"], true),
                    zoned("10.0.0.2", "eu-1b", &[], true),
                ],
            )],
        );
        let resolved = resolve(&inv, "ns", "svc", None, false).unwrap();
        assert!(
            resolved
                .targets
                .backends()
                .iter()
                .all(|b| b.zone.is_none() && b.for_zones.is_empty())
        );
    }

    #[test]
    fn named_ports_dual_stack_and_dedup() {
        let inv = inventory(
            service(&[(Some("http"), 8080), (Some("admin"), 9090)], None),
            vec![
                slice(
                    "a",
                    "IPv4",
                    &[(Some("http"), 3000), (Some("admin"), 3001)],
                    vec![
                        endpoint("10.0.0.2", Some(true), true, false),
                        endpoint("10.0.0.1", None, true, false),
                    ],
                ),
                // The same endpoint seen again in another slice.
                slice(
                    "b",
                    "IPv4",
                    &[(Some("http"), 3000)],
                    vec![endpoint("10.0.0.1", Some(true), true, false)],
                ),
                slice(
                    "c",
                    "IPv6",
                    &[(Some("http"), 3000)],
                    vec![endpoint("fd00::1", Some(true), true, false)],
                ),
                // A slice without the port is ignored.
                slice(
                    "d",
                    "IPv4",
                    &[(Some("other"), 1)],
                    vec![endpoint("10.9.9.9", Some(true), true, false)],
                ),
            ],
        );
        let resolved = resolve(&inv, "ns", "svc", Some(PortRef::Number(8080)), false).unwrap();
        assert_eq!(resolved.port_name.as_deref(), Some("http"));
        assert_eq!(
            addresses(&resolved),
            vec![
                ("10.0.0.1:3000".to_owned(), false),
                ("10.0.0.2:3000".to_owned(), false),
                ("[fd00::1]:3000".to_owned(), false),
            ]
        );
        let admin = resolve(&inv, "ns", "svc", Some(PortRef::Name("admin")), false).unwrap();
        assert_eq!(admin.port, 9090);
        assert_eq!(addresses(&admin).len(), 2);
    }

    #[test]
    fn loopback_link_local_and_unspecified_addresses_are_refused() {
        let inv = inventory(
            service(&[(None, 80)], None),
            vec![
                slice(
                    "a",
                    "IPv4",
                    &[(None, 2080)],
                    vec![
                        endpoint("10.0.0.1", Some(true), true, false),
                        endpoint("127.0.0.1", Some(true), true, false),
                        endpoint("169.254.169.254", Some(true), true, false),
                        endpoint("0.0.0.0", Some(true), true, false),
                    ],
                ),
                slice(
                    "b",
                    "IPv6",
                    &[(None, 2080)],
                    vec![
                        endpoint("::1", Some(true), true, false),
                        endpoint("fe80::1", Some(true), true, false),
                        endpoint("::", Some(true), true, false),
                        endpoint("::ffff:127.0.0.1", Some(true), true, false),
                        endpoint("fd00::1", Some(true), true, false),
                    ],
                ),
            ],
        );
        let resolved = resolve(&inv, "ns", "svc", Some(PortRef::Number(80)), false).unwrap();
        assert_eq!(
            addresses(&resolved),
            vec![
                ("10.0.0.1:2080".to_owned(), false),
                ("[fd00::1]:2080".to_owned(), false),
            ]
        );
        assert_eq!(
            resolved.refused,
            vec![
                "0.0.0.0",
                "127.0.0.1",
                "169.254.169.254",
                "::",
                "::1",
                "::ffff:127.0.0.1",
                "fe80::1"
            ]
        );
        let diagnostic = refused_diagnostic(&resolved).unwrap();
        assert!(diagnostic.message.contains("127.0.0.1"), "{diagnostic:?}");
    }

    #[test]
    fn terminating_endpoints_are_backups_only_while_something_is_ready() {
        let terminating = endpoint("10.0.0.3", Some(false), true, true);
        let gone = endpoint("10.0.0.4", Some(false), false, true);
        let not_ready = endpoint("10.0.0.5", Some(false), false, false);
        let inv = inventory(
            service(&[(None, 80)], None),
            vec![slice(
                "a",
                "IPv4",
                &[(None, 8080)],
                vec![
                    endpoint("10.0.0.1", Some(true), true, false),
                    terminating.clone(),
                    gone.clone(),
                    not_ready.clone(),
                ],
            )],
        );
        let resolved = resolve(&inv, "ns", "svc", Some(PortRef::Number(80)), false).unwrap();
        assert_eq!(
            addresses(&resolved),
            vec![
                ("10.0.0.1:8080".to_owned(), false),
                ("10.0.0.3:8080".to_owned(), true)
            ]
        );
        let inv = inventory(
            service(&[(None, 80)], None),
            vec![slice(
                "a",
                "IPv4",
                &[(None, 8080)],
                vec![terminating, gone, not_ready],
            )],
        );
        let resolved = resolve(&inv, "ns", "svc", None, false).unwrap();
        assert_eq!(
            addresses(&resolved),
            vec![("10.0.0.3:8080".to_owned(), false)]
        );
    }

    #[test]
    fn errors_external_names_and_empty_services() {
        let inv = inventory(service(&[(None, 80), (Some("b"), 81)], None), vec![]);
        assert!(matches!(
            resolve(&inv, "ns", "nope", Some(PortRef::Number(80)), false),
            Err(BackendError::ServiceNotFound { .. })
        ));
        assert!(matches!(
            resolve(&inv, "ns", "svc", Some(PortRef::Number(99)), false),
            Err(BackendError::PortNotFound { .. })
        ));
        assert!(matches!(
            resolve(&inv, "ns", "svc", None, false),
            Err(BackendError::PortRequired { .. })
        ));
        let empty = resolve(&inv, "ns", "svc", Some(PortRef::Number(80)), false).unwrap();
        assert_eq!(empty.targets, Targets::Endpoints(Vec::new()));
        assert_eq!(
            http_service(empty.targets.backends(), Scheme::Http),
            respond(503)
        );

        let inv = inventory(service(&[(None, 443)], Some("api.example.com.")), vec![]);
        assert!(matches!(
            resolve(&inv, "ns", "svc", Some(PortRef::Number(443)), false),
            Err(BackendError::ExternalNameNotAllowed { .. })
        ));
        let external = resolve(&inv, "ns", "svc", Some(PortRef::Number(443)), true).unwrap();
        assert_eq!(
            addresses(&external),
            vec![("api.example.com:443".to_owned(), false)]
        );
    }

    #[test]
    fn app_protocols() {
        assert_eq!(scheme(Some("kubernetes.io/h2c"), Scheme::Http), Scheme::H2c);
        assert_eq!(scheme(Some("kubernetes.io/ws"), Scheme::H2c), Scheme::Http);
        assert_eq!(
            scheme(Some("kubernetes.io/wss"), Scheme::Http),
            Scheme::Https
        );
        assert_eq!(scheme(Some("HTTPS"), Scheme::Http), Scheme::Https);
        assert_eq!(scheme(None, Scheme::H2c), Scheme::H2c);
        assert_eq!(
            scheme(Some("example.com/custom"), Scheme::Http),
            Scheme::Http
        );
    }
}
