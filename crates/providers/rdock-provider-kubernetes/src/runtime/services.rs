//! The per-Gateway Services (ADR-0029, "Shape"), written by the leader only.
//!
//! The Services' ports are the record of the internal port allocation: [`allocate`] is a pure
//! function of the managed Services as they exist and the desired set, so a second replica
//! that wrongly believes it leads computes the same objects, and a lost race (409) is simply
//! retried on the next pass. Services are written with server-side apply under our field
//! manager, only when they differ from what is wanted, and deleted (by label) when their
//! Gateway is no longer desired.

use std::collections::{BTreeMap, BTreeSet};

use k8s_openapi::api::core::v1::Service;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::api::{Api, DeleteParams, Patch, PatchParams, Preconditions};
use rdock_model::Diagnostic;
use rdock_model::providers::KubernetesServiceType;
use serde_json::json;

use crate::api::GatewayStatusAddress;
use crate::inventory::{GatewayService, ObjectKey};
use crate::translate::{
    DesiredService, GATEWAY_NAME_ANNOTATION, GATEWAY_NAME_LABEL, GATEWAY_NAMESPACE_ANNOTATION,
    GATEWAY_NAMESPACE_LABEL, MANAGED_BY, MANAGED_BY_LABEL, Settings, gateway_label_value,
};

/// The field manager of everything this controller writes with server-side apply.
pub const FIELD_MANAGER: &str = "reversedock.dev/gateway-controller";
/// Annotation holding a hash of the configuration we applied, so a change that removes one of
/// our labels or annotations is noticed.
pub const CONFIG_ANNOTATION: &str = "reversedock.dev/service-config";

/// Listener port → internal port, by Service name.
pub type PortMap = BTreeMap<String, BTreeMap<u16, u16>>;

/// The outcome of [`allocate`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Allocation {
    /// Listener port → internal port for every desired Service.
    pub ports: PortMap,
    /// `(Service, listener port)` pairs that got no internal port: the range is exhausted.
    pub unmapped: Vec<(String, u16)>,
}

/// Allocates internal ports (`targetPort`) from `range` for every desired Service.
///
/// - An existing assignment is kept when the port is still wanted, inside the range and not
///   already kept for another Service (on a clash, the Service whose name sorts first keeps
///   it).
/// - New listener ports get the lowest port that no managed Service uses: two Gateways never
///   share an internal port, and a port freed in this pass (a removed listener, a deleted
///   Service) is not handed out again before the Service that held it is gone.
/// - When the range is exhausted, the pair is left out and reported in `unmapped`.
#[must_use]
pub fn allocate(
    range: (u16, u16),
    existing: &PortMap,
    desired: &[(String, Vec<u16>)],
) -> Allocation {
    let (start, end) = range;
    let in_range = |p: u16| start <= p && p <= end;
    let mut wanted: BTreeMap<&str, BTreeSet<u16>> = BTreeMap::new();
    for (name, ports) in desired {
        wanted
            .entry(name.as_str())
            .or_default()
            .extend(ports.iter().copied());
    }
    let busy: BTreeSet<u16> = existing
        .values()
        .flat_map(|m| m.values().copied())
        .collect();
    let mut claimed: BTreeSet<u16> = BTreeSet::new();
    let mut allocation = Allocation::default();
    for (name, ports) in &wanted {
        let entry = allocation.ports.entry((*name).to_owned()).or_default();
        for port in ports {
            if let Some(&target) = existing.get(*name).and_then(|m| m.get(port))
                && in_range(target)
                && claimed.insert(target)
            {
                entry.insert(*port, target);
            }
        }
    }
    let mut next = start;
    for (name, ports) in &wanted {
        for port in ports {
            if allocation
                .ports
                .get(*name)
                .is_some_and(|m| m.contains_key(port))
            {
                continue;
            }
            // Every port below `next` is taken, so the search resumes there.
            if let Some(free) = (next..=end).find(|p| !busy.contains(p) && !claimed.contains(p)) {
                claimed.insert(free);
                next = free;
                allocation
                    .ports
                    .entry((*name).to_owned())
                    .or_default()
                    .insert(*port, free);
            } else {
                next = end;
                allocation.unmapped.push(((*name).to_owned(), *port));
            }
        }
    }
    allocation
}

/// The listener ports of a live Service: `port` → numeric `targetPort`.
#[must_use]
pub fn ports_of(service: &Service) -> BTreeMap<u16, u16> {
    service
        .spec
        .as_ref()
        .and_then(|s| s.ports.as_ref())
        .into_iter()
        .flatten()
        .filter_map(|p| {
            let port = u16::try_from(p.port).ok()?;
            let target = match p.target_port.as_ref()? {
                IntOrString::Int(t) => u16::try_from(*t).ok()?,
                IntOrString::String(s) => s.parse().ok()?,
            };
            Some((port, target))
        })
        .collect()
}

/// A managed Service as the translator sees it ([`GatewayService`]), keyed by its Gateway:
/// the exact namespace and name in the annotations [`GATEWAY_NAMESPACE_ANNOTATION`] and
/// [`GATEWAY_NAME_ANNOTATION`] (labels cannot hold a Gateway name over 63 characters; they
/// only select). A Service without them belongs to no Gateway and is deleted as stale.
///
/// Addresses: the load-balancer ingress (IP addresses and host names) for `LoadBalancer`;
/// the cluster IPs for `ClusterIP` and `NodePort` (a `NodePort` Service is also reachable on
/// every node's address at its node port, which `status.addresses` cannot express, and
/// reading nodes is not in the RBAC).
#[must_use]
pub fn gateway_service(service: &Service) -> Option<(ObjectKey, GatewayService)> {
    let annotations = service.metadata.annotations.as_ref()?;
    let gateway = (
        annotations.get(GATEWAY_NAMESPACE_ANNOTATION)?.clone(),
        annotations.get(GATEWAY_NAME_ANNOTATION)?.clone(),
    );
    let spec = service.spec.as_ref();
    let kind = spec.and_then(|s| s.type_.as_deref()).unwrap_or("ClusterIP");
    let mut addresses = Vec::new();
    if kind == "LoadBalancer" {
        for ingress in service
            .status
            .as_ref()
            .and_then(|s| s.load_balancer.as_ref())
            .and_then(|l| l.ingress.as_ref())
            .into_iter()
            .flatten()
        {
            if let Some(ip) = ingress.ip.as_ref().filter(|ip| !ip.is_empty()) {
                addresses.push(address("IPAddress", ip));
            }
            if let Some(host) = ingress.hostname.as_ref().filter(|h| !h.is_empty()) {
                addresses.push(address("Hostname", host));
            }
        }
    } else {
        let ips: Vec<String> = spec
            .and_then(|s| s.cluster_ips.clone())
            .filter(|ips| !ips.is_empty())
            .or_else(|| spec.and_then(|s| s.cluster_ip.clone()).map(|ip| vec![ip]))
            .unwrap_or_default();
        for ip in ips.iter().filter(|ip| !ip.is_empty() && *ip != "None") {
            addresses.push(address("IPAddress", ip));
        }
    }
    Some((
        gateway,
        GatewayService {
            namespace: service.metadata.namespace.clone().unwrap_or_default(),
            name: service.metadata.name.clone().unwrap_or_default(),
            ports: ports_of(service),
            addresses,
        },
    ))
}

fn address(kind: &str, value: &str) -> GatewayStatusAddress {
    GatewayStatusAddress {
        kind: Some(kind.to_owned()),
        value: value.to_owned(),
    }
}

fn service_type(kind: KubernetesServiceType) -> &'static str {
    match kind {
        KubernetesServiceType::LoadBalancer => "LoadBalancer",
        KubernetesServiceType::ClusterIp => "ClusterIP",
        KubernetesServiceType::NodePort => "NodePort",
    }
}

/// The labels of a managed Service: the desired ones, then ours (which win). The Gateway
/// name label holds [`gateway_label_value`] (hashed over 63 characters).
fn labels_of(desired: &DesiredService) -> BTreeMap<String, String> {
    let mut labels = desired.labels.clone();
    labels.insert(MANAGED_BY_LABEL.to_owned(), MANAGED_BY.to_owned());
    labels.insert(
        GATEWAY_NAME_LABEL.to_owned(),
        gateway_label_value(&desired.gateway.1),
    );
    labels.insert(
        GATEWAY_NAMESPACE_LABEL.to_owned(),
        desired.gateway.0.clone(),
    );
    labels
}

/// The annotations of a managed Service: the desired ones, then the exact Gateway (which
/// wins), the key that ties the Service to its Gateway.
fn annotations_of(desired: &DesiredService) -> BTreeMap<String, String> {
    let mut annotations = desired.annotations.clone();
    annotations.insert(
        GATEWAY_NAMESPACE_ANNOTATION.to_owned(),
        desired.gateway.0.clone(),
    );
    annotations.insert(
        GATEWAY_NAME_ANNOTATION.to_owned(),
        desired.gateway.1.clone(),
    );
    annotations
}

/// FNV-1a, 64 bits: stable across versions and platforms.
fn fnv64(data: &[u8]) -> u64 {
    data.iter().fold(0xcbf2_9ce4_8422_2325_u64, |h, b| {
        (h ^ u64::from(*b)).wrapping_mul(0x0100_0000_01b3)
    })
}

/// The server-side apply manifest of a managed Service.
#[must_use]
pub fn manifest(
    desired: &DesiredService,
    ports: &BTreeMap<u16, u16>,
    settings: &Settings,
) -> serde_json::Value {
    let labels = labels_of(desired);
    let mut annotations = annotations_of(desired);
    let selector = &settings.provider.gateway.pod_selector;
    let kind = service_type(settings.provider.gateway.service_type);
    let port_list: Vec<serde_json::Value> = ports
        .iter()
        .map(|(port, target)| {
            json!({ "name": format!("port-{port}"), "protocol": "TCP", "port": port, "targetPort": target })
        })
        .collect();
    // Everything above in a canonical form (BTreeMaps, sorted ports): its hash changes exactly
    // when what we apply changes.
    let canonical = json!({
        "labels": labels, "annotations": annotations, "selector": selector,
        "type": kind, "ports": port_list,
    });
    let hash = format!("{:016x}", fnv64(canonical.to_string().as_bytes()));
    annotations.insert(CONFIG_ANNOTATION.to_owned(), hash);
    json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": desired.name,
            "namespace": desired.namespace,
            "labels": labels,
            "annotations": annotations,
        },
        "spec": { "type": kind, "selector": selector, "ports": port_list },
    })
}

/// Whether the live Service differs from `manifest` in anything we apply.
#[must_use]
pub fn differs(live: Option<&Service>, manifest: &serde_json::Value) -> bool {
    let Some(live) = live else { return true };
    let str_map = |v: &serde_json::Value| -> BTreeMap<String, String> {
        serde_json::from_value(v.clone()).unwrap_or_default()
    };
    let want_labels = str_map(&manifest["metadata"]["labels"]);
    let want_annotations = str_map(&manifest["metadata"]["annotations"]);
    let have_labels = live.metadata.labels.clone().unwrap_or_default();
    let have_annotations = live.metadata.annotations.clone().unwrap_or_default();
    let subset = |want: &BTreeMap<String, String>, have: &BTreeMap<String, String>| {
        want.iter().all(|(k, v)| have.get(k) == Some(v))
    };
    if !subset(&want_labels, &have_labels) || !subset(&want_annotations, &have_annotations) {
        return true;
    }
    let spec = live.spec.clone().unwrap_or_default();
    if spec.type_.as_deref().unwrap_or("ClusterIP")
        != manifest["spec"]["type"].as_str().unwrap_or("")
        || spec.selector.unwrap_or_default() != str_map(&manifest["spec"]["selector"])
    {
        return true;
    }
    let have_ports: BTreeSet<(String, String, i32, String)> = spec
        .ports
        .unwrap_or_default()
        .into_iter()
        .map(|p| {
            let target = match p.target_port {
                Some(IntOrString::Int(t)) => t.to_string(),
                Some(IntOrString::String(s)) => s,
                None => String::new(),
            };
            (
                p.name.unwrap_or_default(),
                p.protocol.unwrap_or_else(|| "TCP".to_owned()),
                p.port,
                target,
            )
        })
        .collect();
    let want_ports: BTreeSet<(String, String, i32, String)> = manifest["spec"]["ports"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|p| {
            (
                p["name"].as_str().unwrap_or_default().to_owned(),
                p["protocol"].as_str().unwrap_or_default().to_owned(),
                i32::try_from(p["port"].as_i64().unwrap_or_default()).unwrap_or_default(),
                p["targetPort"].as_i64().unwrap_or_default().to_string(),
            )
        })
        .collect();
    have_ports != want_ports
}

/// What one reconciliation pass did, for logs and tests.
#[derive(Debug, Default)]
pub struct Outcome {
    /// Problems to report beside the translation's diagnostics (exhausted port range).
    pub diagnostics: Vec<Diagnostic>,
}

/// Brings the managed Services in `settings.service_namespace()` in line with `desired`.
/// `live` holds the managed Services by name. `leading` is asked before every apply and
/// delete: a replica that lost its Lease during the pass writes nothing more.
pub async fn reconcile(
    api: &Api<Service>,
    settings: &Settings,
    live: &BTreeMap<String, Service>,
    desired: &[DesiredService],
    errors: &mut super::status::ErrorLog,
    leading: &(dyn Fn() -> bool + Send + Sync),
) -> Outcome {
    let mut outcome = Outcome::default();
    let range = settings.provider.gateway.ports().unwrap_or((20000, 29999));
    let existing: PortMap = live.iter().map(|(n, s)| (n.clone(), ports_of(s))).collect();
    let wanted: Vec<(String, Vec<u16>)> = desired
        .iter()
        .filter(|d| d.namespace == settings.service_namespace())
        .map(|d| (d.name.clone(), d.ports.clone()))
        .collect();
    let allocation = allocate(range, &existing, &wanted);
    for (name, port) in &allocation.unmapped {
        outcome.diagnostics.push(
            Diagnostic::warning(
                "providers.kubernetes.gateway.port_range",
                format!(
                    "no internal port left in `{}` for port {port} of Service `{name}`; that listener stays unprogrammed",
                    settings.provider.gateway.port_range
                ),
            )
            .with_hint("widen `providers.kubernetes.gateway.port_range`"),
        );
    }
    let params = PatchParams::apply(FIELD_MANAGER).force();
    for service in desired {
        if service.namespace != settings.service_namespace() {
            continue;
        }
        let ports = allocation
            .ports
            .get(&service.name)
            .cloned()
            .unwrap_or_default();
        if ports.is_empty() {
            continue; // a Service needs at least one port
        }
        let manifest = manifest(service, &ports, settings);
        let current = live.get(&service.name);
        let key = format!("Service {}", service.name);
        if !differs(current, &manifest) {
            errors.settled(&key);
            continue;
        }
        if !errors.due(&key) || !leading() {
            continue;
        }
        let patch = Patch::Apply(&manifest);
        let call = api.patch(&service.name, &params, &patch);
        match tokio::time::timeout(super::CALL_TIMEOUT, call).await {
            Ok(Ok(_)) => {
                errors.clear(&key);
                tracing::info!(provider = crate::PROVIDER, service = %service.name,
                    namespace = %service.namespace, gateway = %format!("{}/{}", service.gateway.0, service.gateway.1),
                    ports = ?ports, created = current.is_none(), "applied the per-Gateway Service");
            }
            Ok(Err(kube::Error::Api(status))) if status.code == 409 => errors.conflict(&key),
            Ok(Err(err)) => errors.failed(&key, &err.to_string()),
            Err(_) => errors.failed(&key, "the request timed out"),
        }
    }
    let keep: BTreeSet<&str> = wanted.iter().map(|(n, _)| n.as_str()).collect();
    delete_stale(api, live, &keep, errors, leading).await;
    outcome
}

/// Deletes the managed Services whose Gateway is no longer desired.
async fn delete_stale(
    api: &Api<Service>,
    live: &BTreeMap<String, Service>,
    keep: &BTreeSet<&str>,
    errors: &mut super::status::ErrorLog,
    leading: &(dyn Fn() -> bool + Send + Sync),
) {
    for (name, service) in live {
        if keep.contains(name.as_str()) {
            continue;
        }
        let key = format!("Service {name} (delete)");
        if !errors.due(&key) || !leading() {
            continue;
        }
        let params = DeleteParams {
            preconditions: Some(Preconditions {
                uid: service.metadata.uid.clone(),
                resource_version: None,
            }),
            ..DeleteParams::default()
        };
        match tokio::time::timeout(super::CALL_TIMEOUT, api.delete(name, &params)).await {
            Ok(Ok(_)) => {
                errors.clear(&key);
                tracing::info!(provider = crate::PROVIDER, service = %name,
                    "deleted the per-Gateway Service of a Gateway that is gone");
            }
            Ok(Err(kube::Error::Api(status))) if status.code == 404 => errors.clear(&key),
            // Replaced meanwhile (another uid): decided again on the next pass.
            Ok(Err(kube::Error::Api(status))) if status.code == 409 => errors.conflict(&key),
            Ok(Err(err)) => errors.failed(&key, &err.to_string()),
            Err(_) => errors.failed(&key, "the request timed out"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(entries: &[(&str, &[(u16, u16)])]) -> PortMap {
        entries
            .iter()
            .map(|(n, ports)| ((*n).to_owned(), ports.iter().copied().collect()))
            .collect()
    }

    fn want(entries: &[(&str, &[u16])]) -> Vec<(String, Vec<u16>)> {
        entries
            .iter()
            .map(|(n, ports)| ((*n).to_owned(), ports.to_vec()))
            .collect()
    }

    #[test]
    fn new_ports_get_the_lowest_free_internal_ports() {
        let a = allocate(
            (20000, 20010),
            &PortMap::new(),
            &want(&[("a", &[443, 80]), ("b", &[80])]),
        );
        assert_eq!(
            a.ports,
            map(&[("a", &[(80, 20000), (443, 20001)]), ("b", &[(80, 20002)])])
        );
        assert_eq!(a.unmapped, Vec::new());
    }

    #[test]
    fn existing_assignments_are_kept() {
        let existing = map(&[("a", &[(80, 20005)]), ("b", &[(80, 20001)])]);
        let a = allocate(
            (20000, 20010),
            &existing,
            &want(&[("a", &[80, 443]), ("b", &[80])]),
        );
        assert_eq!(
            a.ports,
            map(&[("a", &[(80, 20005), (443, 20000)]), ("b", &[(80, 20001)])])
        );
    }

    #[test]
    fn two_gateways_never_share_an_internal_port() {
        // A race left two Services on the same target port: the first by name keeps it.
        let existing = map(&[("a", &[(80, 20000)]), ("b", &[(80, 20000)])]);
        let a = allocate(
            (20000, 20010),
            &existing,
            &want(&[("a", &[80]), ("b", &[80])]),
        );
        assert_eq!(
            a.ports,
            map(&[("a", &[(80, 20000)]), ("b", &[(80, 20001)])])
        );
    }

    #[test]
    fn ports_freed_in_this_pass_are_not_reused() {
        // Gateway c is gone and a dropped its port 443: their ports stay busy in this pass.
        let existing = map(&[("a", &[(80, 20000), (443, 20001)]), ("c", &[(80, 20002)])]);
        let a = allocate(
            (20000, 20010),
            &existing,
            &want(&[("a", &[80]), ("d", &[80])]),
        );
        assert_eq!(
            a.ports,
            map(&[("a", &[(80, 20000)]), ("d", &[(80, 20003)])])
        );
        // Next pass, with c deleted and a updated: the lowest port is free again.
        let existing = map(&[("a", &[(80, 20000)]), ("d", &[(80, 20003)])]);
        let a = allocate(
            (20000, 20010),
            &existing,
            &want(&[("a", &[80]), ("d", &[80]), ("e", &[80])]),
        );
        assert_eq!(a.ports["e"], BTreeMap::from([(80, 20001)]));
    }

    #[test]
    fn an_exhausted_range_leaves_ports_unmapped() {
        let a = allocate(
            (20000, 20001),
            &PortMap::new(),
            &want(&[("a", &[80, 443]), ("b", &[80])]),
        );
        assert_eq!(
            a.ports,
            map(&[("a", &[(80, 20000), (443, 20001)]), ("b", &[])])
        );
        assert_eq!(a.unmapped, vec![("b".to_owned(), 80)]);
        // The range ends at 65535 without overflowing.
        let a = allocate((65535, 65535), &PortMap::new(), &want(&[("a", &[80, 443])]));
        assert_eq!(a.ports, map(&[("a", &[(80, 65535)])]));
        assert_eq!(a.unmapped, vec![("a".to_owned(), 443)]);
    }

    #[test]
    fn assignments_outside_a_changed_range_are_replaced() {
        let existing = map(&[("a", &[(80, 30000)])]);
        let a = allocate((20000, 20010), &existing, &want(&[("a", &[80])]));
        assert_eq!(a.ports, map(&[("a", &[(80, 20000)])]));
    }

    #[test]
    fn allocation_is_a_pure_function_of_its_inputs() {
        let existing = map(&[("b", &[(80, 20003)]), ("a", &[(8080, 20001)])]);
        let desired = want(&[("c", &[80]), ("a", &[8080, 80]), ("b", &[80, 81])]);
        let mut reversed = desired.clone();
        reversed.reverse();
        assert_eq!(
            allocate((20000, 20010), &existing, &desired),
            allocate((20000, 20010), &existing, &reversed)
        );
    }

    fn settings() -> Settings {
        let mut provider = rdock_model::providers::KubernetesProvider::default();
        provider.gateway.service_type = KubernetesServiceType::ClusterIp;
        provider.gateway.pod_selector = BTreeMap::from([("app".to_owned(), "rdock".to_owned())]);
        Settings {
            provider,
            controller_namespace: "rdock-system".to_owned(),
            data_dir: "/d".into(),
        }
    }

    fn desired() -> DesiredService {
        DesiredService {
            namespace: "rdock-system".to_owned(),
            name: "apps-web".to_owned(),
            gateway: ("apps".to_owned(), "web".to_owned()),
            ports: vec![80],
            labels: BTreeMap::from([("team".to_owned(), "a".to_owned())]),
            annotations: BTreeMap::from([("note".to_owned(), "x".to_owned())]),
        }
    }

    #[test]
    fn the_manifest_and_the_live_service_compare() {
        let ports = BTreeMap::from([(80, 20000)]);
        let m = manifest(&desired(), &ports, &settings());
        assert_eq!(m["spec"]["type"], "ClusterIP");
        assert_eq!(m["spec"]["ports"][0]["name"], "port-80");
        assert_eq!(m["spec"]["ports"][0]["targetPort"], 20000);
        assert_eq!(m["metadata"]["labels"][MANAGED_BY_LABEL], MANAGED_BY);
        assert_eq!(m["metadata"]["labels"][GATEWAY_NAME_LABEL], "web");
        assert_eq!(m["metadata"]["labels"][GATEWAY_NAMESPACE_LABEL], "apps");
        assert!(differs(None, &m));
        // The live object as the API server returns it: our fields plus defaults and others.
        let mut live: Service = serde_json::from_value(m.clone()).unwrap();
        live.metadata
            .annotations
            .get_or_insert_default()
            .insert("cloud".to_owned(), "y".to_owned());
        live.spec.get_or_insert_default().cluster_ip = Some("10.96.0.10".to_owned());
        assert!(!differs(Some(&live), &m));
        let (gateway, service) = gateway_service(&live).unwrap();
        assert_eq!(gateway, ("apps".to_owned(), "web".to_owned()));
        assert_eq!(service.ports, ports);
        assert_eq!(service.addresses, vec![address("IPAddress", "10.96.0.10")]);
        // A removed annotation changes the hash; another target port is a difference.
        let mut d = desired();
        d.annotations.clear();
        assert!(differs(Some(&live), &manifest(&d, &ports, &settings())));
        assert!(differs(
            Some(&live),
            &manifest(&desired(), &BTreeMap::from([(80, 20001)]), &settings())
        ));
    }

    #[test]
    fn a_gateway_name_over_63_characters_keys_its_service_exactly() {
        let name = "g".repeat(253);
        let mut d = desired();
        d.gateway.1.clone_from(&name);
        d.name = crate::translate::gateway_service_name("apps", &name);
        let m = manifest(&d, &BTreeMap::from([(80, 20000)]), &settings());
        let label = m["metadata"]["labels"][GATEWAY_NAME_LABEL]
            .as_str()
            .unwrap();
        assert!(label.len() <= 63, "label value too long: {}", label.len());
        let live: Service = serde_json::from_value(m).unwrap();
        let (gateway, _) = gateway_service(&live).unwrap();
        assert_eq!(gateway, ("apps".to_owned(), name));
    }

    #[test]
    fn load_balancer_addresses_come_from_the_ingress() {
        let mut s = settings();
        s.provider.gateway.service_type = KubernetesServiceType::LoadBalancer;
        let mut live: Service =
            serde_json::from_value(manifest(&desired(), &BTreeMap::from([(80, 20000)]), &s))
                .unwrap();
        live.spec.get_or_insert_default().cluster_ip = Some("10.96.0.10".to_owned());
        let (_, service) = gateway_service(&live).unwrap();
        assert!(
            service.addresses.is_empty(),
            "no address until the load balancer assigns one"
        );
        live.status = Some(serde_json::from_value(json!({
            "loadBalancer": { "ingress": [{ "ip": "203.0.113.7" }, { "hostname": "lb.example" }] }
        })).unwrap());
        let (_, service) = gateway_service(&live).unwrap();
        assert_eq!(
            service.addresses,
            vec![
                address("IPAddress", "203.0.113.7"),
                address("Hostname", "lb.example")
            ]
        );
    }
}
