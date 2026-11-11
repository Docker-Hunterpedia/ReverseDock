//! Gateways and their listeners (`gateway_types.go`), the internal listeners and the
//! per-Gateway Services (ADR-0029, "Shape").
//!
//! Listener validation, in this order:
//! - **Protocol:** `HTTP`, `HTTPS`, `TLS` with `mode: Passthrough` and `TCP` are supported.
//!   `UDP` and unknown protocols are `Accepted=False/UnsupportedProtocol`; `TLS` with
//!   `mode: Terminate` is `Accepted=False/UnsupportedValue` (TLS termination for TLSRoutes
//!   is not claimed, see the core test `TLSRouteListenerTerminateNotSupported`).
//! - **Route kinds:** `HTTP`/`HTTPS` take HTTPRoute and GRPCRoute, `TLS` TLSRoute, `TCP`
//!   TCPRoute. `allowedRoutes.kinds` narrows that; a kind the listener cannot take is left
//!   out of `supportedKinds` and makes `ResolvedRefs=False/InvalidRouteKinds`.
//! - **Certificates** (`HTTPS`): every `certificateRefs` entry must be a core `Secret`
//!   (`InvalidCertificateRef`), allowed by a ReferenceGrant when in another namespace
//!   (`RefNotPermitted`, checked before existence so a missing grant is reported even for a
//!   missing Secret), exist, be of type `kubernetes.io/tls` and hold a valid certificate and
//!   key (`InvalidCertificateRef`).
//! - **Conflicts:** per port, `HTTP` cannot share with `HTTPS`/`TLS`, and `TCP` shares with
//!   nothing (`ProtocolConflict`); listeners of one protocol family on one port need distinct
//!   host names (`HostnameConflict`). Conflicted listeners are all refused
//!   (`Accepted=False`, the conflict as reason), none is picked as the winner.
//!
//! A listener is **programmed** when it is accepted, unconflicted, its references resolve
//! and the Gateway's Service maps its port to an internal port; until the Service has the
//! port it is `Programmed=False/Pending`, and no internal listener is opened for that port.
//! One internal listener exists per (Gateway, port): `http` for `HTTP`; `https` when an
//! `HTTPS` listener is programmed on the port (with the certificates of every programmed
//! `HTTPS` listener of the port; TLS passthrough routes share it by SNI); `tcp` for `TCP`
//! and for a port with only TLS passthrough listeners.
//!
//! The Gateway is `Accepted=True/Accepted` when every listener is valid, `True` with
//! `ListenersNotValid` when some are, and `False/ListenersNotValid` when none is. Requested
//! addresses (`spec.addresses`, the Extended `GatewayStaticAddresses`) are not supported:
//! an address with a value makes the Gateway `Accepted=False/UnsupportedAddress`; an entry
//! without a value asks the implementation to choose, which it does. `spec.infrastructure`
//! `parametersRef` is refused (`InvalidParameters`). `Programmed` needs the Service and an
//! address (`AddressNotAssigned` until then) and every port mapped (`Pending`).

use std::collections::{BTreeMap, BTreeSet};

use rdock_model::config::{Certificate, Listener as ModelListener, ListenerProtocol, ListenerTls};
use rdock_model::values::ListenAddress;

use super::conditions::{condition, reasons, types};
use super::grants::{Referrer, Target};
use super::{Context, RouteSet, object_id};
use crate::api::{
    GROUP, Gateway, GatewayStatusAddress, LabelSelector, Listener, RouteGroupKind, from_namespaces,
    kinds, protocols, tls_modes,
};
use crate::inventory::{GatewayService, ObjectKey};
use crate::translate::{
    DesiredGateway, DesiredListener, DesiredService, GATEWAY_NAME_LABEL, GATEWAY_NAMESPACE_LABEL,
    MANAGED_BY, MANAGED_BY_LABEL, RouteKind, gateway_label_value, gateway_service_name,
    secret_paths,
};

/// A failed check: a condition reason and a message.
pub type Failure = (&'static str, String);

/// The protocol of a listener, as the translator understands it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// `HTTP`.
    Http,
    /// `HTTPS` (terminated).
    Https,
    /// `TLS` with `mode: Passthrough`.
    TlsPassthrough,
    /// `TLS` with `mode: Terminate` (not supported).
    TlsTerminate,
    /// `TCP`.
    Tcp,
    /// `UDP` (not supported).
    Udp,
    /// Anything else (not supported).
    Unknown,
}

impl Protocol {
    fn of(listener: &Listener) -> Self {
        match listener.protocol.as_str() {
            protocols::HTTP => Self::Http,
            protocols::HTTPS => Self::Https,
            protocols::TLS => match listener.tls.as_ref().and_then(|t| t.mode.as_deref()) {
                Some(tls_modes::PASSTHROUGH) => Self::TlsPassthrough,
                _ => Self::TlsTerminate,
            },
            protocols::TCP => Self::Tcp,
            protocols::UDP => Self::Udp,
            _ => Self::Unknown,
        }
    }

    /// The route kinds a listener of this protocol takes.
    #[must_use]
    pub fn kinds(self) -> &'static [RouteKind] {
        match self {
            Self::Http | Self::Https => &[RouteKind::Http, RouteKind::Grpc],
            Self::TlsPassthrough => &[RouteKind::Tls],
            Self::Tcp => &[RouteKind::Tcp],
            Self::TlsTerminate | Self::Udp | Self::Unknown => &[],
        }
    }

    /// Listeners of one family may share a port when their host names differ.
    fn family(self) -> Option<char> {
        match self {
            Self::Http => Some('h'),
            Self::Https | Self::TlsPassthrough => Some('s'),
            Self::Tcp => Some('t'),
            Self::TlsTerminate | Self::Udp | Self::Unknown => None,
        }
    }
}

/// Which namespaces routes may attach from.
#[derive(Debug, Clone, PartialEq)]
pub enum Namespaces {
    /// The Gateway's own.
    Same,
    /// Every namespace.
    All,
    /// Namespaces whose labels match.
    Selector(LabelSelector),
    /// None.
    None,
}

/// One listener of a Gateway, evaluated.
#[derive(Debug, Clone)]
pub struct ListenerState {
    /// Name.
    pub name: String,
    /// Port.
    pub port: u16,
    /// Protocol.
    pub protocol: Protocol,
    /// Host name, lower case.
    pub hostname: Option<String>,
    /// `allowedRoutes.namespaces`.
    pub namespaces: Namespaces,
    /// Route kinds that may attach.
    pub kinds: Vec<RouteKind>,
    /// `Accepted`.
    pub accepted: Result<(), Failure>,
    /// `ResolvedRefs`.
    pub resolved: Result<(), Failure>,
    /// `Conflicted` reason, when conflicted.
    pub conflict: Option<&'static str>,
    /// Valid certificate Secrets.
    pub certificates: Vec<ObjectKey>,
    /// `Programmed`.
    pub programmed: Result<(), Failure>,
    /// The internal listener (fragment name), when programmed.
    pub internal: Option<String>,
    /// Routes accepted on this listener.
    pub attached: RouteSet,
}

impl ListenerState {
    /// Whether routes may attach (the listener is accepted and not conflicted).
    #[must_use]
    pub fn active(&self) -> bool {
        self.accepted.is_ok() && self.conflict.is_none()
    }
}

/// A Gateway of ours, evaluated.
#[derive(Debug, Clone)]
pub struct GatewayState<'a> {
    /// Key.
    pub key: ObjectKey,
    /// The object.
    pub gateway: &'a Gateway,
    /// `metadata.generation`.
    pub generation: Option<i64>,
    /// `Accepted`.
    pub accepted: Result<(), Failure>,
    /// Listeners in spec order.
    pub listeners: Vec<ListenerState>,
    /// The Gateway's Service, when it exists.
    pub service: Option<&'a GatewayService>,
}

impl GatewayState<'_> {
    /// `Kind/namespace/name` of the Gateway.
    #[must_use]
    pub fn id(&self) -> String {
        object_id(kinds::GATEWAY, &self.key.0, &self.key.1)
    }
}

/// Evaluates the Gateways of the accepted classes in `ours`.
pub fn evaluate(cx: &mut Context<'_>, ours: &BTreeSet<String>) {
    let controller = cx.settings.provider.controller_name.clone();
    for (key, gateway) in &cx.inventory.gateways {
        let class = &gateway.spec.gateway_class_name;
        let Some(class_object) = cx.inventory.gateway_classes.get(class) else {
            continue;
        };
        if class_object.spec.controller_name != controller {
            continue;
        }
        let state = evaluate_gateway(cx, key, gateway, ours.contains(class));
        cx.gateway_index.insert(key.clone(), cx.gateways.len());
        cx.gateways.push(state);
    }
    open_listeners(cx);
}

fn evaluate_gateway<'a>(
    cx: &mut Context<'a>,
    key: &ObjectKey,
    gateway: &'a Gateway,
    class_accepted: bool,
) -> GatewayState<'a> {
    let id = object_id(kinds::GATEWAY, &key.0, &key.1);
    let mut listeners: Vec<ListenerState> = gateway
        .spec
        .listeners
        .iter()
        .enumerate()
        .map(|(i, l)| evaluate_listener(cx, &id, key, i, l))
        .collect();
    mark_conflicts(&mut listeners);
    for (i, l) in listeners.iter().enumerate() {
        if let Some(reason) = l.conflict {
            cx.warn(
                &id,
                &format!(".spec.listeners[{i}]"),
                format!(
                    "listener `{}` conflicts with another listener ({reason}); it is not used",
                    l.name
                ),
            );
        }
    }
    let active = listeners.iter().filter(|l| l.active()).count();
    let requested: Vec<&str> = gateway
        .spec
        .addresses
        .iter()
        .map(|a| a.value.as_str())
        .filter(|v| !v.is_empty())
        .collect();
    let accepted = if !class_accepted {
        Err((
            reasons::PENDING,
            format!(
                "GatewayClass `{}` is not accepted",
                gateway.spec.gateway_class_name
            ),
        ))
    } else if !requested.is_empty() {
        cx.warn(
            &id,
            ".spec.addresses",
            "requested addresses are not supported; the address comes from the Gateway's Service",
        );
        Err((
            reasons::UNSUPPORTED_ADDRESS,
            format!(
                "requested addresses ({}) are not supported: the Gateway's address is the one its Service gets",
                requested.join(", ")
            ),
        ))
    } else if gateway
        .spec
        .infrastructure
        .as_ref()
        .is_some_and(|i| i.parameters_ref.is_some())
    {
        cx.warn(&id, ".spec.infrastructure.parametersRef", "not supported");
        Err((
            reasons::INVALID_PARAMETERS,
            "infrastructure.parametersRef is not supported".to_owned(),
        ))
    } else if active == 0 {
        Err((
            reasons::LISTENERS_NOT_VALID,
            "no listener is valid".to_owned(),
        ))
    } else {
        Ok(())
    };
    GatewayState {
        key: key.clone(),
        gateway,
        generation: gateway.metadata.generation,
        accepted,
        listeners,
        service: cx.inventory.gateway_services.get(key),
    }
}

fn evaluate_listener(
    cx: &mut Context<'_>,
    id: &str,
    key: &ObjectKey,
    index: usize,
    listener: &Listener,
) -> ListenerState {
    let field = format!(".spec.listeners[{index}]");
    let protocol = Protocol::of(listener);
    let accepted = match protocol {
        Protocol::Udp => Err((
            reasons::UNSUPPORTED_PROTOCOL,
            "UDP listeners are not supported yet (planned for v0.8)".to_owned(),
        )),
        Protocol::Unknown => Err((
            reasons::UNSUPPORTED_PROTOCOL,
            format!("protocol `{}` is not supported", listener.protocol),
        )),
        Protocol::TlsTerminate => Err((
            reasons::UNSUPPORTED_VALUE,
            "TLS listeners support `mode: Passthrough` only; terminate TLS with an HTTPS listener"
                .to_owned(),
        )),
        _ => Ok(()),
    };
    if let Err((_, message)) = &accepted {
        cx.warn(id, &field, message.clone());
    }
    let (kinds, kinds_resolved) = route_kinds(listener, protocol);
    let mut resolved = kinds_resolved;
    let mut certificates = Vec::new();
    if protocol == Protocol::Https && accepted.is_ok() {
        let (valid, failure) = certificate_refs(cx, key, listener);
        certificates = valid;
        if resolved.is_ok()
            && let Some(failure) = failure
        {
            resolved = Err(failure);
        }
    }
    if let Err((_, message)) = &resolved {
        cx.warn(id, &field, message.clone());
    }
    if listener
        .tls
        .as_ref()
        .is_some_and(|tls| !tls.options.is_empty())
    {
        cx.warn(
            id,
            &format!("{field}.tls.options"),
            "TLS options are implementation-specific and none are supported; they are ignored",
        );
    }
    let namespaces = listener
        .allowed_routes
        .as_ref()
        .and_then(|a| a.namespaces.as_ref());
    let namespaces = match namespaces.and_then(|n| n.from.as_deref()) {
        None | Some(from_namespaces::SAME) => Namespaces::Same,
        Some(from_namespaces::ALL) => Namespaces::All,
        // A missing selector selects nothing (Go's `LabelSelectorAsSelector(nil)`); an
        // empty one (`selector: {}`) selects every namespace, as an empty
        // `metav1.LabelSelector` does.
        Some(from_namespaces::SELECTOR) => {
            if let Some(selector) = namespaces.and_then(|n| n.selector.clone()) {
                Namespaces::Selector(selector)
            } else {
                cx.warn(
                    id,
                    &format!("{field}.allowedRoutes.namespaces.selector"),
                    "`from: Selector` needs a `selector`; without one no route may attach",
                );
                Namespaces::None
            }
        }
        Some(other) => {
            if other != from_namespaces::NONE {
                cx.warn(
                    id,
                    &format!("{field}.allowedRoutes.namespaces.from"),
                    format!("`{other}` is not a known value; no route may attach"),
                );
            }
            Namespaces::None
        }
    };
    ListenerState {
        name: listener.name.clone(),
        port: listener.port,
        protocol,
        hostname: listener
            .hostname
            .as_deref()
            .filter(|h| !h.is_empty())
            .map(str::to_ascii_lowercase),
        namespaces,
        kinds,
        accepted,
        resolved,
        conflict: None,
        certificates,
        programmed: Err((reasons::INVALID, String::new())),
        internal: None,
        attached: RouteSet::new(),
    }
}

/// The route kinds a listener takes, and whether `allowedRoutes.kinds` named one it cannot.
fn route_kinds(listener: &Listener, protocol: Protocol) -> (Vec<RouteKind>, Result<(), Failure>) {
    let supported = protocol.kinds();
    let wanted = listener
        .allowed_routes
        .as_ref()
        .map(|a| a.kinds.as_slice())
        .unwrap_or_default();
    if wanted.is_empty() {
        return (supported.to_vec(), Ok(()));
    }
    let mut kinds = Vec::new();
    let mut invalid = Vec::new();
    for wanted in wanted {
        let group_ok = wanted.group.as_deref().is_none_or(|g| g == GROUP);
        let kind = supported.iter().find(|k| k.as_str() == wanted.kind);
        match kind {
            Some(kind) if group_ok => {
                if !kinds.contains(kind) {
                    kinds.push(*kind);
                }
            }
            _ => invalid.push(wanted.kind.clone()),
        }
    }
    let resolved = if invalid.is_empty() {
        Ok(())
    } else {
        Err((
            reasons::INVALID_ROUTE_KINDS,
            format!(
                "route kinds not supported on a {} listener: {}",
                listener.protocol,
                invalid.join(", ")
            ),
        ))
    };
    (kinds, resolved)
}

/// The usable certificate Secrets of an HTTPS listener, and the first problem found.
fn certificate_refs(
    cx: &Context<'_>,
    gateway: &ObjectKey,
    listener: &Listener,
) -> (Vec<ObjectKey>, Option<Failure>) {
    let refs = listener
        .tls
        .as_ref()
        .map(|t| t.certificate_refs.as_slice())
        .unwrap_or_default();
    if refs.is_empty() {
        return (
            Vec::new(),
            Some((
                reasons::INVALID_CERTIFICATE_REF,
                "an HTTPS listener needs tls.certificateRefs".to_owned(),
            )),
        );
    }
    let mut valid = Vec::new();
    let mut failure = None;
    for r in refs {
        let group = r.group.as_deref().unwrap_or_default();
        let kind = r.kind.as_deref().unwrap_or("Secret");
        let namespace = r.namespace.clone().unwrap_or_else(|| gateway.0.clone());
        let problem = if !group.is_empty() || kind != "Secret" {
            Some((
                reasons::INVALID_CERTIFICATE_REF,
                format!(
                    "certificate reference to `{kind}` in group `{group}` is not supported; use a Secret"
                ),
            ))
        } else if !super::grants::allowed(
            cx.inventory,
            Referrer {
                group: GROUP,
                kind: kinds::GATEWAY,
                namespace: &gateway.0,
            },
            Target {
                group: "",
                kind: "Secret",
                namespace: &namespace,
                name: &r.name,
            },
        ) {
            Some((
                reasons::REF_NOT_PERMITTED,
                format!(
                    "no ReferenceGrant in namespace `{namespace}` allows this Gateway to use Secret `{}`",
                    r.name
                ),
            ))
        } else {
            match cx
                .inventory
                .secrets
                .get(&(namespace.clone(), r.name.clone()))
            {
                None => Some((
                    reasons::INVALID_CERTIFICATE_REF,
                    format!("Secret {namespace}/{} does not exist", r.name),
                )),
                Some(secret) if secret.kind != "kubernetes.io/tls" => Some((
                    reasons::INVALID_CERTIFICATE_REF,
                    format!(
                        "Secret {namespace}/{} is of type `{}`, not kubernetes.io/tls",
                        r.name, secret.kind
                    ),
                )),
                Some(secret) => match &secret.valid {
                    Ok(()) => None,
                    Err(why) => Some((
                        reasons::INVALID_CERTIFICATE_REF,
                        format!("Secret {namespace}/{} is not usable: {why}", r.name),
                    )),
                },
            }
        };
        match problem {
            None => {
                let key = (namespace, r.name.clone());
                if !valid.contains(&key) {
                    valid.push(key);
                }
            }
            Some(problem) => {
                if failure.is_none() {
                    failure = Some(problem);
                }
            }
        }
    }
    (valid, failure)
}

/// Marks conflicted listeners (see the module documentation).
pub fn mark_conflicts(listeners: &mut [ListenerState]) {
    let mut by_port: BTreeMap<u16, Vec<usize>> = BTreeMap::new();
    for (i, l) in listeners.iter().enumerate() {
        if l.accepted.is_ok() && l.protocol.family().is_some() {
            by_port.entry(l.port).or_default().push(i);
        }
    }
    for indexes in by_port.values() {
        let families: BTreeSet<char> = indexes
            .iter()
            .filter_map(|&i| listeners[i].protocol.family())
            .collect();
        let tcp = indexes
            .iter()
            .filter(|&&i| listeners[i].protocol == Protocol::Tcp)
            .count();
        if families.len() > 1 || tcp > 1 {
            for &i in indexes {
                listeners[i].conflict = Some(reasons::PROTOCOL_CONFLICT);
            }
            continue;
        }
        let mut by_host: BTreeMap<Option<&str>, Vec<usize>> = BTreeMap::new();
        for &i in indexes {
            by_host
                .entry(listeners[i].hostname.as_deref())
                .or_default()
                .push(i);
        }
        let conflicted: Vec<usize> = by_host
            .values()
            .filter(|v| v.len() > 1)
            .flatten()
            .copied()
            .collect();
        for i in conflicted {
            listeners[i].conflict = Some(reasons::HOSTNAME_CONFLICT);
        }
    }
}

/// Opens the internal listeners of every accepted Gateway whose Service maps the port, and
/// asks for the Services.
fn open_listeners(cx: &mut Context<'_>) {
    let service_namespace = cx.settings.service_namespace().to_owned();
    let data_dir = cx.settings.data_dir.clone();
    for index in 0..cx.gateways.len() {
        let gw = &cx.gateways[index];
        if gw.accepted.is_err() {
            for l in &mut cx.gateways[index].listeners {
                l.programmed = Err((reasons::INVALID, "the Gateway is not accepted".to_owned()));
            }
            continue;
        }
        let key = gw.key.clone();
        let ports: BTreeSet<u16> = gw
            .listeners
            .iter()
            .filter(|l| l.active())
            .map(|l| l.port)
            .collect();
        let infrastructure = gw.gateway.spec.infrastructure.clone().unwrap_or_default();
        let mut labels = infrastructure.labels.clone();
        labels.insert(GATEWAY_NAME_LABEL.to_owned(), gateway_label_value(&key.1));
        labels.insert(GATEWAY_NAMESPACE_LABEL.to_owned(), key.0.clone());
        labels.insert(MANAGED_BY_LABEL.to_owned(), MANAGED_BY.to_owned());
        cx.out.services.push(DesiredService {
            namespace: service_namespace.clone(),
            name: gateway_service_name(&key.0, &key.1),
            gateway: key.clone(),
            ports: ports.iter().copied().collect(),
            labels,
            annotations: infrastructure.annotations.clone(),
        });
        let mapped = gw.service.map(|s| s.ports.clone()).unwrap_or_default();
        for port in ports {
            open_port(cx, index, port, mapped.get(&port).copied(), &data_dir);
        }
    }
}

/// The internal listener of one Gateway port.
fn open_port(
    cx: &mut Context<'_>,
    index: usize,
    port: u16,
    target: Option<u16>,
    data_dir: &std::path::Path,
) {
    let key = cx.gateways[index].key.clone();
    let on_port: Vec<usize> = cx.gateways[index]
        .listeners
        .iter()
        .enumerate()
        .filter(|(_, l)| l.active() && l.port == port)
        .map(|(i, _)| i)
        .collect();
    let ready: Vec<usize> = on_port
        .iter()
        .copied()
        .filter(|&i| cx.gateways[index].listeners[i].resolved.is_ok())
        .collect();
    for &i in &on_port {
        let l = &mut cx.gateways[index].listeners[i];
        if let Err((_, message)) = &l.resolved {
            l.programmed = Err((reasons::INVALID, message.clone()));
        } else if target.is_none() {
            l.programmed = Err((
                reasons::PENDING,
                format!("waiting for the Gateway's Service to map port {port}"),
            ));
        }
    }
    let Some(target) = target else { return };
    if ready.is_empty() {
        return;
    }
    let listeners = &cx.gateways[index].listeners;
    let protocols: BTreeSet<_> = ready
        .iter()
        .map(|&i| match listeners[i].protocol {
            Protocol::Http => 'h',
            Protocol::Https => 's',
            Protocol::TlsPassthrough => 'p',
            _ => 't',
        })
        .collect();
    let protocol = if protocols.contains(&'h') {
        ListenerProtocol::Http
    } else if protocols.contains(&'s') {
        ListenerProtocol::Https
    } else {
        ListenerProtocol::Tcp
    };
    let mut certificate_names = Vec::new();
    if protocol == ListenerProtocol::Https {
        let secrets: Vec<ObjectKey> = ready
            .iter()
            .flat_map(|&i| listeners[i].certificates.clone())
            .collect();
        for secret in secrets {
            let name = certificate_name(&secret);
            if !certificate_names.contains(&name) {
                let (cert_file, key_file) = secret_paths(data_dir, &secret.0, &secret.1);
                cx.out.fragment.certificates.insert(
                    name.clone(),
                    Certificate {
                        cert_file,
                        key_file,
                        key_password: None,
                    },
                );
                certificate_names.push(name);
                cx.out.secrets.insert(secret);
            }
        }
    }
    let name = internal_listener_name(&key, port);
    let mut model = ModelListener::new(ListenAddress::any(target));
    model.protocol = Some(protocol);
    if protocol == ListenerProtocol::Https {
        model.tls = Some(ListenerTls {
            certificates: certificate_names,
            ..ListenerTls::default()
        });
    }
    cx.out.fragment.listeners.insert(name.clone(), model);
    for i in ready {
        let l = &mut cx.gateways[index].listeners[i];
        l.programmed = Ok(());
        l.internal = Some(name.clone());
    }
}

/// The fragment name of the internal listener of Gateway `key`, port `port`.
#[must_use]
pub fn internal_listener_name(key: &ObjectKey, port: u16) -> String {
    super::names::object_name(
        "gw",
        &[&key.0, &key.1, &port.to_string()],
        &format!("listener/{}/{}/{port}", key.0, key.1),
    )
}

/// The fragment name of the certificate of Secret `key`.
#[must_use]
pub fn certificate_name(key: &ObjectKey) -> String {
    super::names::object_name(
        "cert",
        &[&key.0, &key.1],
        &format!("secret/{}/{}", key.0, key.1),
    )
}

/// Writes the Gateway and listener status, once routes have attached.
pub fn finish(cx: &mut Context<'_>) {
    for gw in &cx.gateways {
        let generation = gw.generation;
        let listeners: Vec<DesiredListener> = gw
            .listeners
            .iter()
            .map(|l| listener_status(l, generation))
            .collect();
        let mut conditions = Vec::new();
        let invalid = gw.listeners.iter().filter(|l| !l.active()).count();
        match &gw.accepted {
            Ok(()) if invalid == 0 => conditions.push(condition(
                types::ACCEPTED,
                true,
                reasons::ACCEPTED,
                "accepted",
                generation,
            )),
            Ok(()) => conditions.push(condition(
                types::ACCEPTED,
                true,
                reasons::LISTENERS_NOT_VALID,
                format!(
                    "{invalid} of {} listeners are not valid",
                    gw.listeners.len()
                ),
                generation,
            )),
            Err((reason, message)) => conditions.push(condition(
                types::ACCEPTED,
                false,
                reason,
                message.clone(),
                generation,
            )),
        }
        let addresses: Vec<GatewayStatusAddress> =
            gw.service.map(|s| s.addresses.clone()).unwrap_or_default();
        let unmapped: Vec<u16> = gw
            .listeners
            .iter()
            .filter(|l| l.active())
            .map(|l| l.port)
            .filter(|p| gw.service.is_none_or(|s| !s.ports.contains_key(p)))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let programmed = if gw.accepted.is_err() {
            condition(
                types::PROGRAMMED,
                false,
                reasons::INVALID,
                "the Gateway is not accepted",
                generation,
            )
        } else if gw.service.is_none() || addresses.is_empty() {
            condition(
                types::PROGRAMMED,
                false,
                reasons::ADDRESS_NOT_ASSIGNED,
                "waiting for the Gateway's Service to get an address",
                generation,
            )
        } else if !unmapped.is_empty() {
            condition(
                types::PROGRAMMED,
                false,
                reasons::PENDING,
                format!("waiting for the Gateway's Service to map ports {unmapped:?}"),
                generation,
            )
        } else {
            condition(
                types::PROGRAMMED,
                true,
                reasons::PROGRAMMED,
                "programmed",
                generation,
            )
        };
        conditions.push(programmed);
        cx.out.status.gateways.insert(
            gw.key.clone(),
            DesiredGateway {
                conditions,
                addresses: if gw.accepted.is_ok() {
                    addresses
                } else {
                    Vec::new()
                },
                listeners,
                attached_listener_sets: None,
            },
        );
    }
}

fn listener_status(l: &ListenerState, generation: Option<i64>) -> DesiredListener {
    let accepted = match (&l.accepted, l.conflict) {
        (Err((reason, message)), _) => {
            condition(types::ACCEPTED, false, reason, message.clone(), generation)
        }
        (Ok(()), Some(reason)) => condition(
            types::ACCEPTED,
            false,
            reason,
            "the listener conflicts with another listener",
            generation,
        ),
        (Ok(()), None) => condition(
            types::ACCEPTED,
            true,
            reasons::ACCEPTED,
            "accepted",
            generation,
        ),
    };
    let programmed = match &l.programmed {
        Ok(()) => condition(
            types::PROGRAMMED,
            true,
            reasons::PROGRAMMED,
            "programmed",
            generation,
        ),
        Err((reason, message)) => {
            let message = if message.is_empty() {
                "the listener is not accepted".to_owned()
            } else {
                message.clone()
            };
            condition(types::PROGRAMMED, false, reason, message, generation)
        }
    };
    let resolved = match &l.resolved {
        Ok(()) => condition(
            types::RESOLVED_REFS,
            true,
            reasons::RESOLVED_REFS,
            "references resolved",
            generation,
        ),
        Err((reason, message)) => condition(
            types::RESOLVED_REFS,
            false,
            reason,
            message.clone(),
            generation,
        ),
    };
    let conflicted = match l.conflict {
        Some(reason) => condition(
            types::CONFLICTED,
            true,
            reason,
            "another listener has the same port and host name, or an incompatible protocol on the same port",
            generation,
        ),
        None => condition(
            types::CONFLICTED,
            false,
            reasons::NO_CONFLICTS,
            "no conflicts",
            generation,
        ),
    };
    DesiredListener {
        name: l.name.clone(),
        supported_kinds: if l.accepted.is_ok() {
            l.kinds
                .iter()
                .map(|k| RouteGroupKind {
                    group: Some(GROUP.to_owned()),
                    kind: k.as_str().to_owned(),
                })
                .collect()
        } else {
            Vec::new()
        },
        attached_routes: i32::try_from(l.attached.len()).unwrap_or(i32::MAX),
        conditions: vec![accepted, programmed, resolved, conflicted],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listener(name: &str, port: u16, protocol: Protocol, host: Option<&str>) -> ListenerState {
        ListenerState {
            name: name.to_owned(),
            port,
            protocol,
            hostname: host.map(str::to_owned),
            namespaces: Namespaces::Same,
            kinds: protocol.kinds().to_vec(),
            accepted: Ok(()),
            resolved: Ok(()),
            conflict: None,
            certificates: Vec::new(),
            programmed: Ok(()),
            internal: None,
            attached: RouteSet::new(),
        }
    }

    fn conflicts(mut listeners: Vec<ListenerState>) -> Vec<Option<&'static str>> {
        mark_conflicts(&mut listeners);
        listeners.iter().map(|l| l.conflict).collect()
    }

    #[test]
    fn listener_conflicts() {
        use Protocol::{Http, Https, Tcp, TlsPassthrough, Udp};
        // Distinct host names on one port: fine.
        assert_eq!(
            conflicts(vec![
                listener("a", 80, Http, Some("a.com")),
                listener("b", 80, Http, None),
                listener("c", 80, Http, Some("*.a.com")),
            ]),
            vec![None, None, None]
        );
        // The same host name twice.
        assert_eq!(
            conflicts(vec![
                listener("a", 443, Https, Some("a.com")),
                listener("b", 443, TlsPassthrough, Some("a.com")),
                listener("c", 443, Https, Some("b.com")),
            ]),
            vec![
                Some(reasons::HOSTNAME_CONFLICT),
                Some(reasons::HOSTNAME_CONFLICT),
                None
            ]
        );
        // HTTP and HTTPS on one port, TCP with anything.
        assert_eq!(
            conflicts(vec![
                listener("a", 8080, Http, Some("a.com")),
                listener("b", 8080, Https, Some("b.com")),
                listener("c", 9000, Tcp, None),
                listener("d", 9000, Tcp, None),
                listener("e", 9001, Tcp, None),
                listener("f", 9001, Udp, None),
            ]),
            vec![
                Some(reasons::PROTOCOL_CONFLICT),
                Some(reasons::PROTOCOL_CONFLICT),
                Some(reasons::PROTOCOL_CONFLICT),
                Some(reasons::PROTOCOL_CONFLICT),
                None,
                None
            ]
        );
    }

    #[test]
    fn internal_names_fit_even_for_long_gateway_names() {
        let long = "a".repeat(253);
        let name = internal_listener_name(&("gateway-conformance-infra".into(), long), 443);
        assert!(name.len() <= 63, "{name}");
        assert!(name.starts_with("gw-gateway-conformance-infra-aaa"));
    }
}
