//! The Ingress translator (W-K8S-02, ADR-0029, "Ingress"): claiming, the `pathType` table of
//! the Kubernetes documentation, hosts, precedence, backends, TLS, cert-manager's solver,
//! the ingress-nginx annotations and the status.
//!
//! Every translation is assembled with a file configuration that has `web` (plain) and
//! `websecure` (TLS) listeners and compiled by the real data plane; requests are resolved
//! with the router's `explain`, so a row passes only when the proxy would route it so.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::needless_pass_by_value,
    clippy::similar_names,
    clippy::assert_is_empty,
    clippy::assigning_clones,
    clippy::cloned_ref_to_slice_refs,
    clippy::format_collect,
    clippy::format_push_string,
    clippy::manual_assert_eq,
    clippy::redundant_closure_for_method_calls
)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use k8s_openapi::api::core::v1::Service;
use k8s_openapi::api::discovery::v1::{Endpoint, EndpointConditions, EndpointPort, EndpointSlice};
use k8s_openapi::api::networking::v1::{Ingress, IngressClass};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use rdock_config::merge::{Snapshot, assemble};
use rdock_model::Diagnostic;
use rdock_model::middleware::{Middleware, RedirectConfig, RedirectScheme};
use rdock_model::providers::{KubernetesIngress, KubernetesProvider};
use rdock_model::route::{Route, RouteTls};
use rdock_model::service::Scheme;
use rdock_provider_kubernetes::inventory::{Inventory, SERVICE_NAME_LABEL, SecretInfo};
use rdock_provider_kubernetes::translate::{
    INGRESS_CONTROLLER, LoadBalancerAddress, Settings, Translation, secret_paths,
};
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use serde_json::Value;

// ---------------------------------------------------------------------------------------
// The simulated cluster.

struct World {
    inventory: Inventory,
    settings: Settings,
    /// Pod IP → `namespace/service`.
    pods: BTreeMap<String, String>,
    created: u32,
    dir: tempfile::TempDir,
}

fn ingress_settings(f: impl FnOnce(&mut KubernetesIngress)) -> Settings {
    let mut ingress = KubernetesIngress {
        enabled: true,
        ..KubernetesIngress::default()
    };
    f(&mut ingress);
    Settings {
        provider: KubernetesProvider {
            ingress,
            ..KubernetesProvider::default()
        },
        controller_namespace: "rdock-system".to_owned(),
        data_dir: std::path::PathBuf::new(),
    }
}

impl World {
    /// An empty cluster with our IngressClass `rdock`.
    fn new() -> Self {
        Self::with(|i| i.publish_address = Some("203.0.113.1".to_owned()))
    }

    fn with(f: impl FnOnce(&mut KubernetesIngress)) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut settings = ingress_settings(f);
        settings.data_dir = dir.path().to_owned();
        let mut world = Self {
            inventory: Inventory::default(),
            settings,
            pods: BTreeMap::new(),
            created: 0,
            dir,
        };
        world.apply(&format!(
            "apiVersion: networking.k8s.io/v1\nkind: IngressClass\nmetadata: {{name: rdock}}\nspec: {{controller: {INGRESS_CONTROLLER}}}\n"
        ));
        world
    }

    /// Applies multi-document YAML: Ingress, IngressClass and Service (which gets one ready
    /// pod and its EndpointSlice).
    fn apply(&mut self, text: &str) {
        let docs: Vec<Value> = serde_saphyr::from_multiple(text).unwrap();
        for mut doc in docs {
            self.created += 1;
            let n = self.created;
            let meta = doc["metadata"].as_object_mut().unwrap();
            meta.entry("creationTimestamp")
                .or_insert(Value::from(format!(
                    "2026-01-01T{:02}:{:02}:{:02}Z",
                    n / 3600,
                    (n / 60) % 60,
                    n % 60
                )));
            let name = meta["name"].as_str().unwrap().to_owned();
            let namespace = meta
                .get("namespace")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            let key = (namespace.clone(), name.clone());
            match doc["kind"].as_str().unwrap() {
                "Ingress" => {
                    let ingress: Ingress = serde_json::from_value(doc).unwrap();
                    self.inventory.ingresses.insert(key, ingress);
                }
                "IngressClass" => {
                    let class: IngressClass = serde_json::from_value(doc).unwrap();
                    self.inventory.ingress_classes.insert(name, class);
                }
                "Service" => {
                    let service: Service = serde_json::from_value(doc).unwrap();
                    let external = service
                        .spec
                        .as_ref()
                        .is_some_and(|s| s.type_.as_deref() == Some("ExternalName"));
                    let ports: Vec<EndpointPort> = service
                        .spec
                        .as_ref()
                        .and_then(|s| s.ports.clone())
                        .unwrap_or_default()
                        .into_iter()
                        .map(|p| EndpointPort {
                            name: p.name,
                            port: Some(p.port),
                            protocol: None,
                            app_protocol: p.app_protocol,
                        })
                        .collect();
                    self.inventory.services.insert(key.clone(), service);
                    if !external {
                        let ip = format!("10.1.{n}.1");
                        self.pods.insert(ip.clone(), format!("{namespace}/{name}"));
                        self.slice(&namespace, &name, Some(&ip), ports);
                    }
                }
                other => panic!("unexpected kind {other}"),
            }
        }
    }

    fn slice(
        &mut self,
        namespace: &str,
        service: &str,
        ip: Option<&str>,
        ports: Vec<EndpointPort>,
    ) {
        let slice = EndpointSlice {
            metadata: ObjectMeta {
                name: Some(format!("{service}-slice")),
                namespace: Some(namespace.to_owned()),
                labels: Some([(SERVICE_NAME_LABEL.to_owned(), service.to_owned())].into()),
                ..ObjectMeta::default()
            },
            address_type: "IPv4".to_owned(),
            endpoints: ip
                .into_iter()
                .map(|ip| Endpoint {
                    addresses: vec![ip.to_owned()],
                    conditions: Some(EndpointConditions {
                        ready: Some(true),
                        serving: Some(true),
                        terminating: Some(false),
                    }),
                    ..Endpoint::default()
                })
                .collect(),
            ports: Some(ports),
        };
        self.inventory
            .endpoint_slices
            .insert((namespace.to_owned(), format!("{service}-slice")), slice);
    }

    /// Makes the Service have no ready endpoint.
    fn drain(&mut self, namespace: &str, service: &str) {
        let slice = self
            .inventory
            .endpoint_slices
            .get_mut(&(namespace.to_owned(), format!("{service}-slice")))
            .unwrap();
        slice.endpoints.clear();
    }

    fn secret(&mut self, name: &str, valid: Result<(), &str>) {
        self.inventory.secrets.insert(
            ("apps".to_owned(), name.to_owned()),
            SecretInfo {
                namespace: "apps".to_owned(),
                name: name.to_owned(),
                kind: "kubernetes.io/tls".to_owned(),
                valid: valid.map_err(str::to_owned),
            },
        );
    }

    fn translate(&self) -> Translation {
        rdock_provider_kubernetes::ingress::translate(&self.inventory, &self.settings)
    }

    fn router(&self) -> Router {
        Router::new(self, self.translate())
    }
}

/// `Service apps/<name>` with ports `(name, number)`.
fn service(name: &str, ports: &[(&str, u16)]) -> String {
    let ports: String = ports
        .iter()
        .map(|(n, p)| {
            if n.is_empty() {
                format!("    - port: {p}\n")
            } else {
                format!("    - name: {n}\n      port: {p}\n")
            }
        })
        .collect();
    format!(
        "apiVersion: v1\nkind: Service\nmetadata: {{name: {name}, namespace: apps}}\nspec:\n  ports:\n{ports}---\n"
    )
}

/// The standard backends: `web`, `api`, `admin` and `solver`, port 80 (`web` also by name).
fn services() -> String {
    [
        service("web", &[("http", 80), ("metrics", 9100)]),
        service("api", &[("", 80)]),
        service("admin", &[("", 80)]),
        service("solver", &[("", 80)]),
        service("root", &[("", 80)]),
    ]
    .concat()
}

/// An Ingress of our class `rdock`.
fn ingress(name: &str, annotations: &[(&str, &str)], spec: &str) -> String {
    let annotations: String = annotations
        .iter()
        .map(|(k, v)| format!("    {k}: \"{v}\"\n"))
        .collect();
    let annotations = if annotations.is_empty() {
        String::new()
    } else {
        format!("  annotations:\n{annotations}")
    };
    format!(
        "apiVersion: networking.k8s.io/v1\nkind: Ingress\nmetadata:\n  name: {name}\n  namespace: apps\n{annotations}spec:\n  ingressClassName: rdock\n{spec}---\n"
    )
}

/// `rules:` with one rule (optional host) and the given `(pathType, path, service)` paths.
fn rules(host: Option<&str>, paths: &[(&str, &str, &str)]) -> String {
    let mut out = String::from("  rules:\n");
    match host {
        Some(h) => out.push_str(&format!("    - host: \"{h}\"\n      http:\n")),
        None => out.push_str("    - http:\n"),
    }
    out.push_str("        paths:\n");
    for (kind, path, svc) in paths {
        out.push_str(&format!(
            "          - path: \"{path}\"\n            pathType: {kind}\n            backend: {{service: {{name: {svc}, port: {{number: 80}}}}}}\n"
        ));
    }
    out
}

fn default_backend(svc: &str) -> String {
    format!("  defaultBackend: {{service: {{name: {svc}, port: {{number: 80}}}}}}\n")
}

// ---------------------------------------------------------------------------------------
// Routing through the real data plane.

#[derive(Debug, Clone, PartialEq, Eq)]
enum Outcome {
    /// No route: 404.
    NotFound,
    /// The listener's automatic http→https redirect answers.
    AutoRedirect,
    /// Backends (`namespace/service`).
    Backends(BTreeSet<String>),
    /// A service that answers with a status.
    Status(u16),
}

struct Routed {
    outcome: Outcome,
    route: Option<Route>,
    middlewares: Vec<Middleware>,
}

impl Routed {
    fn redirect(&self) -> Option<&RedirectConfig> {
        self.middlewares.iter().find_map(|m| match m {
            Middleware::Redirect(r) => Some(r),
            _ => None,
        })
    }
}

struct Router {
    translation: Translation,
    runtime: rdock_proxy::Runtime,
    pods: BTreeMap<String, String>,
    /// DER of the certificate written for each Secret.
    certificates: BTreeMap<String, Vec<u8>>,
    diagnostics: Vec<Diagnostic>,
}

const HOSTS: &[&str] = &[
    "secure.example.org",
    "*.wild.example.org",
    "other.example.org",
];

/// The file configuration the fragment is merged into.
const BASE: &str = "acme: false\nlisteners:\n  web: { address: \"127.0.0.1:1\" }\n  websecure: { address: \"127.0.0.1:2\", tls: {} }\ndefaults:\n  listeners: [websecure]\n";

impl Router {
    fn new(world: &World, translation: Translation) -> Self {
        let ca = rdock_testkit::certs::TestCa::new();
        let mut certificates = BTreeMap::new();
        for (ns, name) in &translation.secrets {
            let (crt, key) = secret_paths(world.dir.path(), ns, name);
            std::fs::create_dir_all(crt.parent().unwrap()).unwrap();
            let issued = ca.issue(crt.parent().unwrap(), "issued", HOSTS);
            let der = CertificateDer::from_pem_slice(issued.cert_pem.as_bytes()).unwrap();
            certificates.insert(name.clone(), der.as_ref().to_vec());
            std::fs::rename(&issued.cert, &crt).unwrap();
            std::fs::rename(&issued.key, &key).unwrap();
        }
        let base = rdock_config::load_str(BASE, rdock_config::Format::Yaml).unwrap();
        assert!(!base.has_errors(), "{:?}", base.diagnostics);
        let snapshot = Snapshot {
            provider: "kubernetes".to_owned(),
            fragment: translation.fragment.clone(),
            diagnostics: Vec::new(),
            revision: None,
        };
        let merged = assemble(&base.config, &[&snapshot], &BTreeSet::new());
        assert_eq!(merged.errors, Vec::new(), "assemble errors");
        assert_eq!(merged.skipped, Vec::new(), "objects left out by assemble");
        let compiled = rdock_proxy::compile(
            &merged.config,
            &rdock_proxy::CompileEnv {
                mode: rdock_proxy::Mode::Run,
                generation: 1,
                dns: &rdock_proxy::upstream::Dns::default(),
                client: Arc::new(rdock_middleware::HttpClient::default()),
                previous: None,
                cloudflare: &rdock_proxy::forwarded::CloudflareRanges::default(),
                backends: &rdock_balancer::Registry::default(),
                sticky_key: b"test",
                live: &rdock_observability::live::Live::default(),
                caches: None,
            },
        );
        let errors: Vec<_> = compiled
            .diagnostics
            .iter()
            .filter(|d| d.is_error())
            .collect();
        assert!(errors.is_empty(), "compile errors: {errors:#?}");
        Self {
            diagnostics: compiled.diagnostics.clone(),
            runtime: compiled.runtime.unwrap(),
            translation,
            pods: world.pods.clone(),
            certificates,
        }
    }

    /// Routes a `GET` for `path` to `host` arriving on listener `web` or `websecure`.
    fn go(&self, listener: &str, host: &str, path: &str) -> Routed {
        let explained = rdock_proxy::explain::explain(
            &self.runtime,
            listener,
            &rdock_proxy::explain::Request {
                host: host.to_owned(),
                path: path.to_owned(),
                method: "GET".to_owned(),
                headers: http::HeaderMap::new(),
                client_ip: None,
            },
        )
        .unwrap_or_else(|e| panic!("{e}"));
        let Some(name) = explained["outcome"]["route"].as_str() else {
            let outcome = if explained["outcome"]["result"] == "https redirect" {
                Outcome::AutoRedirect
            } else {
                Outcome::NotFound
            };
            return Routed {
                outcome,
                route: None,
                middlewares: Vec::new(),
            };
        };
        let fragment = &self.translation.fragment;
        let route = fragment.routes[name.strip_suffix("@kubernetes").unwrap()].clone();
        let middlewares = route
            .middlewares
            .iter()
            .map(|m| fragment.middlewares[m].clone())
            .collect();
        let service = &fragment.services[route.service.as_deref().unwrap()];
        let outcome = match &service.respond {
            Some(respond) => Outcome::Status(respond.status),
            None => Outcome::Backends(
                service
                    .backends
                    .iter()
                    .map(|b| {
                        let address = b.address.to_string();
                        let ip = address.rsplit_once(':').unwrap().0;
                        self.pods
                            .get(ip)
                            .cloned()
                            .unwrap_or_else(|| format!("unknown {address}"))
                    })
                    .collect(),
            ),
        };
        Routed {
            outcome,
            route: Some(route),
            middlewares,
        }
    }

    /// The Service (`name` without namespace) a request reaches, or `None` when it does not
    /// reach one.
    fn svc(&self, listener: &str, host: &str, path: &str) -> Option<String> {
        match self.go(listener, host, path).outcome {
            Outcome::Backends(set) => {
                assert_eq!(set.len(), 1, "{set:?}");
                set.into_iter()
                    .next()
                    .map(|s| s.trim_start_matches("apps/").to_owned())
            }
            _ => None,
        }
    }

    /// The certificate (DER) the TLS listener presents for `sni`.
    fn certificate(&self, sni: &str) -> Option<Vec<u8>> {
        self.runtime
            .certificates
            .get(sni)
            .map(|key| key.cert[0].as_ref().to_vec())
    }
}

fn warnings(t: &Translation) -> Vec<String> {
    t.diagnostics
        .iter()
        .map(|d| format!("{}: {}", d.path, d.message))
        .collect()
}

fn has_warning(t: &Translation, needle: &str) -> bool {
    warnings(t).iter().any(|w| w.contains(needle))
}

fn world_with(ingresses: &[String]) -> World {
    let mut world = World::new();
    world.apply(&services());
    for text in ingresses {
        world.apply(text);
    }
    world
}

// ---------------------------------------------------------------------------------------
// Claiming.

#[test]
fn claiming_matrix() {
    fn ingress_doc(name: &str, class: Option<&str>, annotation: Option<&str>) -> String {
        let annotation = annotation
            .map(|a| format!("  annotations:\n    kubernetes.io/ingress.class: \"{a}\"\n"))
            .unwrap_or_default();
        let class = class
            .map(|c| format!("  ingressClassName: {c}\n"))
            .unwrap_or_default();
        format!(
            "apiVersion: networking.k8s.io/v1\nkind: Ingress\nmetadata:\n  name: {name}\n  namespace: apps\n{annotation}spec:\n{class}  defaultBackend: {{service: {{name: web, port: {{number: 80}}}}}}\n---\n"
        )
    }
    let foreign = format!(
        "apiVersion: networking.k8s.io/v1\nkind: IngressClass\nmetadata: {{name: nginx}}\nspec: {{controller: k8s.io/ingress-nginx}}\n---\napiVersion: networking.k8s.io/v1\nkind: IngressClass\nmetadata: {{name: ours-too}}\nspec: {{controller: {INGRESS_CONTROLLER}}}\n---\n"
    );
    let docs = [
        ingress_doc("by-field", Some("rdock"), None),
        ingress_doc("by-second-class", Some("ours-too"), None),
        ingress_doc("by-annotation", None, Some("reversedock")),
        ingress_doc("field-wins-over-annotation", Some("rdock"), Some("nginx")),
        ingress_doc("foreign-field", Some("nginx"), None),
        ingress_doc("unknown-class", Some("missing"), None),
        ingress_doc("foreign-annotation", None, Some("nginx")),
        ingress_doc("classless", None, None),
        ingress_doc("empty-annotation-is-classless", None, Some("")),
    ];
    let claimed = |world: &World| -> Vec<String> {
        let t = world.translate();
        let mut names: Vec<String> = t.status.ingresses.keys().map(|k| k.1.clone()).collect();
        names.sort();
        names
    };
    let build = |f: &dyn Fn(&mut KubernetesIngress), default_class: bool| {
        let mut world = World::with(|i| f(i));
        world.apply(&services());
        world.apply(&foreign);
        if default_class {
            world.apply(&format!(
                "apiVersion: networking.k8s.io/v1\nkind: IngressClass\nmetadata:\n  name: dflt\n  annotations: {{ingressclass.kubernetes.io/is-default-class: \"true\"}}\nspec: {{controller: {INGRESS_CONTROLLER}}}\n---\n"
            ));
        }
        for doc in &docs {
            world.apply(doc);
        }
        world
    };
    let always = [
        "by-annotation",
        "by-field",
        "by-second-class",
        "field-wins-over-annotation",
    ];
    // Default settings: class-less Ingresses are not ours.
    let world = build(&|_| {}, false);
    assert_eq!(claimed(&world), always);
    // Unclaimed Ingresses leave nothing: only the claimed ones have routes.
    let t = world.translate();
    assert_eq!(t.fragment.routes.len(), 4, "{:?}", t.fragment.routes.keys());
    for name in t.fragment.routes.keys() {
        assert!(
            !name.contains("foreign") && !name.contains("classless") && !name.contains("unknown"),
            "{name}"
        );
    }
    // A foreign Ingress produces no diagnostics either (the status one is for ours).
    assert!(
        t.diagnostics
            .iter()
            .all(|d| !d.path.contains("foreign") && !d.path.contains("classless"))
    );
    // Our IngressClass is the cluster default: class-less Ingresses are ours.
    let world = build(&|_| {}, true);
    let mut with_default = always.to_vec();
    with_default.extend(["classless", "empty-annotation-is-classless"]);
    with_default.sort_unstable();
    assert_eq!(claimed(&world), with_default);
    // claim_without_class.
    let world = build(&|i| i.claim_without_class = true, false);
    assert_eq!(claimed(&world), with_default);
    // A custom class name for the annotation.
    let world = build(&|i| i.class = "nginx".to_owned(), false);
    let mut custom = vec![
        "by-field",
        "by-second-class",
        "field-wins-over-annotation",
        "foreign-annotation",
    ];
    custom.sort_unstable();
    assert_eq!(claimed(&world), custom);
}

// ---------------------------------------------------------------------------------------
// The pathType table of the Kubernetes documentation.

type Row<'a> = (
    &'a [(&'a str, &'a str, &'a str)],
    Option<&'a str>,
    &'a [(&'a str, Option<&'a str>)],
);

#[test]
fn the_path_type_table() {
    // (paths, defaultBackend, requests → the Service reached; None: 404)
    let rows: &[Row<'_>] = &[
        // Prefix / matches all paths.
        (
            &[("Prefix", "/", "web")],
            None,
            &[
                ("/", Some("web")),
                ("/aaa/bbb", Some("web")),
                ("/x?y=1", Some("web")),
            ],
        ),
        // Exact is case sensitive and exact about the trailing slash.
        (
            &[("Exact", "/foo", "web")],
            None,
            &[
                ("/foo", Some("web")),
                ("/bar", None),
                ("/foo/", None),
                ("/FOO", None),
                ("/foo/bar", None),
            ],
        ),
        (
            &[("Exact", "/foo/", "web")],
            None,
            &[("/foo/", Some("web")), ("/foo", None)],
        ),
        // Prefix /foo and /foo/ both match /foo and /foo/.
        (
            &[("Prefix", "/foo", "web")],
            None,
            &[
                ("/foo", Some("web")),
                ("/foo/", Some("web")),
                ("/foo/bar", Some("web")),
                ("/foobar", None),
                ("/Foo", None),
            ],
        ),
        (
            &[("Prefix", "/foo/", "web")],
            None,
            &[
                ("/foo", Some("web")),
                ("/foo/", Some("web")),
                ("/foo/x", Some("web")),
                ("/fooo", None),
            ],
        ),
        // Prefix works on path elements.
        (
            &[("Prefix", "/aaa/bb", "web")],
            None,
            &[("/aaa/bbb", None), ("/aaa/bb", Some("web"))],
        ),
        (
            &[("Prefix", "/aaa/bbb", "web")],
            None,
            &[
                ("/aaa/bbb", Some("web")),
                ("/aaa/bbb/", Some("web")),
                ("/aaa/bbb/ccc", Some("web")),
                ("/aaa/bbbxyz", None),
            ],
        ),
        (
            &[("Prefix", "/aaa/bbb/", "web")],
            None,
            &[("/aaa/bbb", Some("web"))],
        ),
        // ImplementationSpecific is a Prefix.
        (
            &[("ImplementationSpecific", "/foo", "web")],
            None,
            &[
                ("/foo", Some("web")),
                ("/foo/bar", Some("web")),
                ("/foobar", None),
            ],
        ),
        // The longest matching path wins.
        (
            &[
                ("Prefix", "/", "root"),
                ("Prefix", "/aaa", "api"),
                ("Prefix", "/aaa/bbb", "web"),
            ],
            None,
            &[
                ("/aaa/bbb", Some("web")),
                ("/aaa/bbb/", Some("web")),
                ("/aaa/bbb/ccc", Some("web")),
                ("/aaa/ccc", Some("api")),
                ("/aaa", Some("api")),
                ("/ccc", Some("root")),
                ("/aaa/bbbxyz", Some("api")),
            ],
        ),
        // The order the paths are written in does not matter.
        (
            &[
                ("Prefix", "/aaa/bbb", "web"),
                ("Prefix", "/aaa", "api"),
                ("Prefix", "/", "root"),
            ],
            None,
            &[
                ("/aaa/bbb/x", Some("web")),
                ("/aaa/x", Some("api")),
                ("/x", Some("root")),
            ],
        ),
        // Two prefixes and no default: unmatched requests are 404; with one they use it.
        (
            &[("Prefix", "/aaa", "api"), ("Prefix", "/ccc", "web")],
            None,
            &[
                ("/aaa/ccc", Some("api")),
                ("/ccc", Some("web")),
                ("/bbb", None),
            ],
        ),
        (
            &[("Prefix", "/aaa", "api"), ("Prefix", "/ccc", "web")],
            Some("root"),
            &[
                ("/aaa/ccc", Some("api")),
                ("/ccc/aaa", Some("web")),
                ("/bbb", Some("root")),
            ],
        ),
        // Exact before Prefix on a tie.
        (
            &[("Prefix", "/foo", "api"), ("Exact", "/foo", "web")],
            None,
            &[
                ("/foo", Some("web")),
                ("/foo/", Some("api")),
                ("/foo/bar", Some("api")),
            ],
        ),
        (
            &[("Exact", "/foo", "web"), ("Prefix", "/foo", "api")],
            None,
            &[("/foo", Some("web")), ("/foo/bar", Some("api"))],
        ),
        // Prefix /foo/ and Exact /foo are the same length once the slash is ignored.
        (
            &[("Prefix", "/foo/", "api"), ("Exact", "/foo", "web")],
            None,
            &[("/foo", Some("web")), ("/foo/x", Some("api"))],
        ),
    ];
    for (paths, default, requests) in rows {
        let spec = format!(
            "{}{}",
            rules(None, paths),
            default.map(default_backend).unwrap_or_default()
        );
        let world = world_with(&[ingress("t", &[], &spec)]);
        let router = world.router();
        for (path, expected) in *requests {
            let routed = router.go("web", "any.example.com", path);
            let got = match &routed.outcome {
                Outcome::Backends(set) => set
                    .iter()
                    .next()
                    .map(|s| s.trim_start_matches("apps/").to_owned()),
                Outcome::NotFound => None,
                other => panic!("{paths:?} {path}: {other:?}"),
            };
            assert_eq!(
                got.as_deref(),
                *expected,
                "paths {paths:?} default {default:?}: request {path}"
            );
        }
        // Nothing of this is on the TLS listener: no certificate, no TLS routes.
        assert_eq!(
            router.go("websecure", "any.example.com", "/").outcome,
            Outcome::NotFound
        );
    }
}

#[test]
fn invalid_and_regex_like_paths() {
    let spec = "  rules:\n    - http:\n        paths:\n          - {path: relative, pathType: Prefix, backend: {service: {name: web, port: {number: 80}}}}\n          - {path: \"/x\", pathType: Weird, backend: {service: {name: web, port: {number: 80}}}}\n          - {pathType: Exact, backend: {service: {name: web, port: {number: 80}}}}\n          - {path: \"/re(/|$)(.*)\", pathType: ImplementationSpecific, backend: {service: {name: api, port: {number: 80}}}}\n          - {pathType: ImplementationSpecific, backend: {service: {name: root, port: {number: 80}}}}\n";
    let world = world_with(&[ingress("t", &[], spec)]);
    let router = world.router();
    let t = &router.translation;
    assert!(
        has_warning(t, "`relative` must start with `/`"),
        "{:?}",
        warnings(t)
    );
    assert!(has_warning(t, "pathType `Weird` is not known"));
    assert!(has_warning(t, "must start with `/` for pathType Exact"));
    assert!(has_warning(t, "regular expressions are not supported"));
    // An ImplementationSpecific path without a value is `/`; the regex-looking path is a
    // literal prefix.
    assert_eq!(router.svc("web", "h", "/anything").as_deref(), Some("root"));
    assert_eq!(
        router.svc("web", "h", "/re(/|$)(.*)/x").as_deref(),
        Some("api")
    );
    // Every diagnostic names the Ingress and the field.
    assert!(
        t.diagnostics
            .iter()
            .any(|d| d.path == "kubernetes[\"Ingress/apps/t\"].spec.rules[0].http.paths[0]"),
        "{:?}",
        t.diagnostics
    );
}

// ---------------------------------------------------------------------------------------
// Hosts and precedence.

#[test]
fn hosts_and_wildcards() {
    let world = world_with(&[
        ingress(
            "exact",
            &[],
            &rules(Some("a.foo.com"), &[("Prefix", "/", "web")]),
        ),
        ingress(
            "wild",
            &[],
            &rules(Some("*.foo.com"), &[("Prefix", "/", "api")]),
        ),
        ingress("any", &[], &rules(None, &[("Prefix", "/", "root")])),
    ]);
    let router = world.router();
    let reach = |host: &str| router.svc("web", host, "/x");
    // Exact host: only that host (case-insensitive, with a port).
    assert_eq!(reach("a.foo.com").as_deref(), Some("web"));
    assert_eq!(reach("A.Foo.com").as_deref(), Some("web"));
    assert_eq!(reach("a.foo.com:8080").as_deref(), Some("web"));
    // `*.foo.com` covers exactly one label: bar.foo.com yes, baz.bar.foo.com and foo.com no.
    assert_eq!(reach("bar.foo.com").as_deref(), Some("api"));
    assert_eq!(reach("baz.bar.foo.com").as_deref(), Some("root"));
    assert_eq!(reach("foo.com").as_deref(), Some("root"));
    // No host: every other host. Exact beats wildcard beats no host for the same path.
    assert_eq!(reach("other.example.com").as_deref(), Some("root"));
    assert_eq!(reach("").as_deref(), Some("root"));
}

#[test]
fn host_specificity_outranks_path_length() {
    let world = world_with(&[
        ingress(
            "any",
            &[],
            &rules(None, &[("Exact", "/long/path/here", "root")]),
        ),
        ingress(
            "wild",
            &[],
            &rules(Some("*.foo.com"), &[("Prefix", "/", "api")]),
        ),
        ingress(
            "exact",
            &[],
            &rules(Some("a.foo.com"), &[("Prefix", "/", "web")]),
        ),
    ]);
    let router = world.router();
    assert_eq!(
        router.svc("web", "a.foo.com", "/long/path/here").as_deref(),
        Some("web")
    );
    assert_eq!(
        router.svc("web", "b.foo.com", "/long/path/here").as_deref(),
        Some("api")
    );
    assert_eq!(
        router.svc("web", "c.bar.com", "/long/path/here").as_deref(),
        Some("root")
    );
}

#[test]
fn ties_go_to_the_older_ingress_and_the_earlier_path() {
    // Same host and path in two Ingresses: the older one wins whatever its name.
    let world = world_with(&[
        ingress(
            "zzz-old",
            &[],
            &rules(Some("a.foo.com"), &[("Prefix", "/x", "web")]),
        ),
        ingress(
            "aaa-new",
            &[],
            &rules(Some("a.foo.com"), &[("Prefix", "/x", "api")]),
        ),
    ]);
    assert_eq!(
        world.router().svc("web", "a.foo.com", "/x").as_deref(),
        Some("web")
    );
    // The same path twice in one Ingress: the first.
    let world = world_with(&[ingress(
        "t",
        &[],
        &rules(None, &[("Prefix", "/x", "api"), ("Prefix", "/x", "web")]),
    )]);
    assert_eq!(world.router().svc("web", "h", "/x").as_deref(), Some("api"));
    // Priorities are explicit and positive; the default backend is below every rule.
    let world = world_with(&[ingress(
        "t",
        &[],
        &format!(
            "{}{}",
            rules(None, &[("Prefix", "/", "api")]),
            default_backend("web")
        ),
    )]);
    let t = world.translate();
    let priorities: BTreeMap<&str, i64> = t
        .fragment
        .routes
        .iter()
        .map(|(n, r)| (n.as_str(), r.priority))
        .collect();
    assert!(priorities.values().all(|p| *p > 0), "{priorities:?}");
    let default = t
        .fragment
        .routes
        .iter()
        .find(|(n, _)| n.contains("default"))
        .unwrap()
        .1
        .priority;
    assert!(
        t.fragment
            .routes
            .values()
            .filter(|r| r.priority > default)
            .count()
            == 1
    );
}

#[test]
fn default_backend_serves_unmatched_paths_and_hosts() {
    let world = world_with(&[
        ingress(
            "app",
            &[],
            &format!(
                "{}{}",
                rules(Some("a.foo.com"), &[("Prefix", "/api", "api")]),
                default_backend("root")
            ),
        ),
        // A second Ingress, with only a rule.
        ingress(
            "other",
            &[],
            &rules(Some("b.foo.com"), &[("Exact", "/only", "web")]),
        ),
    ]);
    let router = world.router();
    assert_eq!(
        router.svc("web", "a.foo.com", "/api/x").as_deref(),
        Some("api")
    );
    // The host matches a rule but none of its paths: the default backend.
    assert_eq!(
        router.svc("web", "a.foo.com", "/other").as_deref(),
        Some("root")
    );
    // No rule for the host at all: the default backend too.
    assert_eq!(
        router.svc("web", "zzz.foo.com", "/x").as_deref(),
        Some("root")
    );
    // Rules of other Ingresses still outrank it.
    assert_eq!(
        router.svc("web", "b.foo.com", "/only").as_deref(),
        Some("web")
    );
    assert_eq!(
        router.svc("web", "b.foo.com", "/nope").as_deref(),
        Some("root")
    );
    // An Ingress with only a default backend and no rules.
    let world = world_with(&[ingress("d", &[], &default_backend("web"))]);
    assert_eq!(world.router().svc("web", "x", "/y").as_deref(), Some("web"));
}

// ---------------------------------------------------------------------------------------
// Backends.

#[test]
fn named_and_numbered_ports() {
    let spec = "  rules:\n    - http:\n        paths:\n          - {path: /name, pathType: Prefix, backend: {service: {name: web, port: {name: http}}}}\n          - {path: /number, pathType: Prefix, backend: {service: {name: web, port: {number: 80}}}}\n          - {path: /metrics, pathType: Prefix, backend: {service: {name: web, port: {name: metrics}}}}\n          - {path: /single, pathType: Prefix, backend: {service: {name: api}}}\n";
    let world = world_with(&[ingress("t", &[], spec)]);
    let router = world.router();
    let addresses = |path: &str| -> Vec<String> {
        let routed = router.go("web", "h", path);
        let service = &router.translation.fragment.services
            [routed.route.unwrap().service.as_deref().unwrap()];
        service
            .backends
            .iter()
            .map(|b| b.address.to_string())
            .collect()
    };
    assert_eq!(addresses("/name"), addresses("/number"));
    assert_eq!(addresses("/metrics").len(), 1);
    assert!(
        addresses("/metrics")[0].ends_with(":9100"),
        "{:?}",
        addresses("/metrics")
    );
    assert_eq!(router.svc("web", "h", "/single").as_deref(), Some("api"));
    // The same Service port from several paths is one fragment service.
    let routes = &router.translation.fragment.routes;
    let services: BTreeSet<_> = routes.values().filter_map(|r| r.service.clone()).collect();
    assert_eq!(services.len(), 3, "{services:?}");
    assert!(
        router.translation.diagnostics.is_empty(),
        "{:?}",
        warnings(&router.translation)
    );
}

#[test]
fn unusable_backends_answer_503() {
    let mut world = World::new();
    world.apply(&services());
    world.apply(&format!(
        "{}{}",
        service("quiet", &[("", 80)]),
        "apiVersion: v1\nkind: Service\nmetadata: {name: ext, namespace: apps}\nspec: {type: ExternalName, externalName: db.example.com, ports: [{port: 80}]}\n---\n"
    ));
    world.drain("apps", "quiet");
    let spec = "  rules:\n    - http:\n        paths:\n          - {path: /noservice, pathType: Prefix, backend: {service: {name: ghost, port: {number: 80}}}}\n          - {path: /noport, pathType: Prefix, backend: {service: {name: web, port: {number: 81}}}}\n          - {path: /noname, pathType: Prefix, backend: {service: {name: web, port: {name: nope}}}}\n          - {path: /quiet, pathType: Prefix, backend: {service: {name: quiet, port: {number: 80}}}}\n          - {path: /external, pathType: Prefix, backend: {service: {name: ext, port: {number: 80}}}}\n          - {path: /resource, pathType: Prefix, backend: {resource: {apiGroup: k8s.example.com, kind: StorageBucket, name: icons}}}\n          - {path: /ok, pathType: Prefix, backend: {service: {name: web, port: {number: 80}}}}\n";
    world.apply(&ingress("t", &[], spec));
    let router = world.router();
    for path in ["/noservice", "/noport", "/noname", "/quiet", "/external"] {
        assert_eq!(
            router.go("web", "h", path).outcome,
            Outcome::Status(503),
            "{path}"
        );
    }
    assert_eq!(router.svc("web", "h", "/ok").as_deref(), Some("web"));
    // A resource backend leaves its path out: nothing matches (404), with a diagnostic.
    assert_eq!(
        router.go("web", "h", "/resource").outcome,
        Outcome::NotFound
    );
    let t = &router.translation;
    assert!(
        has_warning(t, "Service apps/ghost does not exist"),
        "{:?}",
        warnings(t)
    );
    assert!(has_warning(t, "Service apps/web has no port 81"));
    assert!(has_warning(t, "has no port nope"));
    assert!(has_warning(t, "ExternalName"));
    assert!(has_warning(t, "resource backends"));
    // No diagnostic for the Service without endpoints (it is transient), and none for /ok.
    assert!(!has_warning(t, "quiet"));
    assert_eq!(t.diagnostics.len(), 5, "{:?}", warnings(t));
}

#[test]
fn app_protocol_and_services_are_named_deterministically() {
    let mut world = World::new();
    world.apply(&format!(
        "apiVersion: v1\nkind: Service\nmetadata: {{name: grpc, namespace: apps}}\nspec: {{ports: [{{port: 80, appProtocol: kubernetes.io/h2c}}]}}\n---\n{}",
        service("web", &[("", 80)])
    ));
    world.apply(&ingress(
        "t",
        &[],
        &rules(None, &[("Prefix", "/grpc", "grpc"), ("Prefix", "/", "web")]),
    ));
    let a = world.translate();
    let b = world.translate();
    assert_eq!(a, b);
    let schemes: Vec<Scheme> = a.fragment.services.values().map(|s| s.scheme).collect();
    assert_eq!(schemes.len(), 2);
    assert!(schemes.contains(&Scheme::Http) && schemes.contains(&Scheme::H2c));
    for name in a
        .fragment
        .routes
        .keys()
        .chain(a.fragment.services.keys())
        .chain(a.fragment.middlewares.keys())
        .chain(a.fragment.certificates.keys())
    {
        assert!(name.len() <= 63, "{name}");
    }
}

// ---------------------------------------------------------------------------------------
// TLS and cert-manager.

fn tls(hosts: &[&str], secret: &str) -> String {
    let hosts = hosts
        .iter()
        .map(|h| format!("\"{h}\""))
        .collect::<Vec<_>>()
        .join(", ");
    format!("  tls:\n    - hosts: [{hosts}]\n      secretName: {secret}\n")
}

#[test]
fn tls_hosts_are_served_on_websecure_and_others_on_web() {
    let mut world = world_with(&[
        ingress(
            "secure",
            &[],
            &format!(
                "{}{}",
                tls(&["secure.example.org"], "secure-tls"),
                rules(
                    Some("secure.example.org"),
                    &[("Prefix", "/", "web"), ("Exact", "/health", "api")]
                )
            ),
        ),
        ingress(
            "plain",
            &[],
            &rules(Some("plain.example.org"), &[("Prefix", "/", "root")]),
        ),
    ]);
    world.secret("secure-tls", Ok(()));
    let router = world.router();
    let t = &router.translation;
    assert_eq!(t.diagnostics, Vec::new());
    // One certificate, from the Secret's files; the Secret is to be materialised.
    assert_eq!(
        t.secrets,
        BTreeSet::from([("apps".to_owned(), "secure-tls".to_owned())])
    );
    assert_eq!(t.fragment.certificates.len(), 1);
    let (crt, key) = secret_paths(world.dir.path(), "apps", "secure-tls");
    let cert = t.fragment.certificates.values().next().unwrap();
    assert_eq!((&cert.cert_file, &cert.key_file), (&crt, &key));
    // The TLS host: routes on websecure with that certificate, presented for its name.
    assert_eq!(
        router
            .svc("websecure", "secure.example.org", "/x")
            .as_deref(),
        Some("web")
    );
    assert_eq!(
        router
            .svc("websecure", "secure.example.org", "/health")
            .as_deref(),
        Some("api")
    );
    assert_eq!(
        router.certificate("secure.example.org"),
        Some(router.certificates["secure-tls"].clone())
    );
    let routed = router.go("websecure", "secure.example.org", "/x");
    match routed.route.unwrap().tls.unwrap() {
        RouteTls::Options(o) => {
            assert!(!o.auto);
            assert!(o.certificate.is_some_and(|c| c.starts_with("icert-")));
        }
        other @ RouteTls::Mode(_) => panic!("{other:?}"),
    }
    // The same host on web is redirected to HTTPS (ssl-redirect is on by default with TLS).
    let plain = router.go("web", "secure.example.org", "/x");
    let redirect = plain.redirect().unwrap();
    assert_eq!(redirect.scheme, Some(RedirectScheme::Https));
    assert_eq!(redirect.status, Some(308));
    // The non-TLS host: on web only, nothing on websecure.
    assert_eq!(
        router.svc("web", "plain.example.org", "/x").as_deref(),
        Some("root")
    );
    assert_eq!(
        router.go("websecure", "plain.example.org", "/x").outcome,
        Outcome::NotFound
    );
    assert!(
        router
            .go("web", "plain.example.org", "/x")
            .redirect()
            .is_none()
    );
    // The compiled data plane has no complaints.
    assert!(
        router.diagnostics.iter().all(|d| !d.is_error()),
        "{:?}",
        router.diagnostics
    );
}

#[test]
fn wildcard_tls_hosts_and_tls_without_hosts() {
    let mut world = world_with(&[
        ingress(
            "wild",
            &[],
            &format!(
                "{}{}",
                tls(&["*.wild.example.org"], "wild-tls"),
                rules(Some("*.wild.example.org"), &[("Prefix", "/", "web")])
            ),
        ),
        // The entry names no hosts: it covers every host of the Ingress.
        ingress(
            "all",
            &[],
            &format!(
                "  tls:\n    - secretName: other-tls\n{}",
                rules(Some("other.example.org"), &[("Prefix", "/", "api")])
            ),
        ),
    ]);
    world.secret("wild-tls", Ok(()));
    world.secret("other-tls", Ok(()));
    let router = world.router();
    assert_eq!(router.translation.diagnostics, Vec::new());
    assert_eq!(
        router
            .svc("websecure", "x.wild.example.org", "/")
            .as_deref(),
        Some("web")
    );
    assert_eq!(
        router.go("websecure", "a.b.wild.example.org", "/").outcome,
        Outcome::NotFound
    );
    assert_eq!(
        router.svc("websecure", "other.example.org", "/").as_deref(),
        Some("api")
    );
    assert_eq!(
        router.certificate("other.example.org"),
        Some(router.certificates["other-tls"].clone())
    );
    assert!(
        router
            .go("web", "x.wild.example.org", "/")
            .redirect()
            .is_some()
    );
}

#[test]
fn missing_invalid_and_unnamed_secrets_keep_the_routes_without_tls() {
    let build = |secret: Option<Result<(), &str>>, entry: &str| {
        let mut world = world_with(&[ingress(
            "t",
            &[],
            &format!(
                "{entry}{}",
                rules(Some("secure.example.org"), &[("Prefix", "/", "web")])
            ),
        )]);
        if let Some(valid) = secret {
            world.secret("s", valid);
        }
        world.router()
    };
    for (router, expect) in [
        (
            build(None, &tls(&["secure.example.org"], "s")),
            "Secret apps/s does not exist",
        ),
        (
            build(
                Some(Err("tls.key is missing")),
                &tls(&["secure.example.org"], "s"),
            ),
            "tls.key is missing",
        ),
        (
            build(None, "  tls:\n    - hosts: [secure.example.org]\n"),
            "names no secretName",
        ),
    ] {
        let t = &router.translation;
        assert!(has_warning(t, expect), "{:?}", warnings(t));
        assert!(
            t.diagnostics.iter().all(|d| d
                .path
                .starts_with("kubernetes[\"Ingress/apps/t\"].spec.tls[0]")),
            "{:?}",
            t.diagnostics
        );
        assert!(t.fragment.certificates.is_empty());
        assert!(t.secrets.is_empty());
        // The route is kept and served over plain HTTP: no redirect to a port without TLS.
        assert_eq!(
            router.svc("web", "secure.example.org", "/x").as_deref(),
            Some("web")
        );
        assert!(
            router
                .go("web", "secure.example.org", "/x")
                .redirect()
                .is_none()
        );
        assert_eq!(
            router.go("websecure", "secure.example.org", "/x").outcome,
            Outcome::NotFound
        );
    }
}

fn solver_ingress(name: &str, class: &str, host: &str, token: &str, kind: &str) -> String {
    // What cert-manager creates (research §4.5): a temporary Ingress with an Exact path (since
    // 1.18; ImplementationSpecific before), the class set by the issuer, a labelled name.
    format!(
        "apiVersion: networking.k8s.io/v1\nkind: Ingress\nmetadata:\n  name: {name}\n  namespace: apps\n  labels: {{acme.cert-manager.io/http01-solver: \"true\"}}\n  annotations:\n    nginx.ingress.kubernetes.io/whitelist-source-range: \"0.0.0.0/0,::/0\"\nspec:\n{class}  rules:\n    - host: {host}\n      http:\n        paths:\n          - path: /.well-known/acme-challenge/{token}\n            pathType: {kind}\n            backend: {{service: {{name: solver, port: {{number: 80}}}}}}\n---\n"
    )
}

#[test]
fn cert_manager_solver_outranks_the_application_and_stays_on_plain_http() {
    let app = ingress(
        "app",
        &[("nginx.ingress.kubernetes.io/force-ssl-redirect", "true")],
        &format!(
            "{}{}",
            tls(&["secure.example.org"], "secure-tls"),
            rules(Some("secure.example.org"), &[("Prefix", "/", "web")])
        ),
    );
    for (class, kind) in [
        ("  ingressClassName: rdock\n", "Exact"),
        ("  ingressClassName: rdock\n", "ImplementationSpecific"),
    ] {
        let mut world = world_with(&[
            app.clone(),
            solver_ingress(
                "cm-acme-http-solver-x",
                class,
                "secure.example.org",
                "tok-1",
                kind,
            ),
        ]);
        world.secret("secure-tls", Ok(()));
        let router = world.router();
        let challenge = "/.well-known/acme-challenge/tok-1";
        // Plain HTTP: the challenge reaches the solver, not the redirect, and not the app.
        let routed = router.go("web", "secure.example.org", challenge);
        assert_eq!(
            routed.outcome,
            Outcome::Backends(BTreeSet::from(["apps/solver".to_owned()])),
            "{kind}"
        );
        assert!(routed.redirect().is_none());
        // Every other plain request, including other tokens, is redirected to HTTPS.
        for path in ["/", "/app", "/.well-known/acme-challenge/other"] {
            let routed = router.go("web", "secure.example.org", path);
            assert_eq!(
                routed.redirect().unwrap().scheme,
                Some(RedirectScheme::Https),
                "{path}"
            );
        }
        // Over HTTPS the application serves everything; the application's `Prefix /` never
        // shadows the challenge on a listener that has both.
        assert_eq!(
            router
                .svc("websecure", "secure.example.org", "/")
                .as_deref(),
            Some("web")
        );
        // The same host without TLS (the Secret does not exist yet: first issuance): the
        // solver still outranks the application's `Prefix /`.
    }
    // Before the certificate exists: the application is plain, the solver still wins.
    let world = world_with(&[
        app.clone(),
        solver_ingress(
            "cm-acme-http-solver-y",
            "  ingressClassName: rdock\n",
            "secure.example.org",
            "tok-2",
            "Exact",
        ),
    ]);
    let router = world.router();
    assert!(has_warning(&router.translation, "does not exist"));
    assert_eq!(
        router
            .svc(
                "web",
                "secure.example.org",
                "/.well-known/acme-challenge/tok-2"
            )
            .as_deref(),
        Some("solver")
    );
    // The whole host is plain: force-ssl-redirect redirects the application, never the
    // challenge, even inside the application's own Ingress (cert-manager's edit-in-place).
    assert!(
        router
            .go("web", "secure.example.org", "/x")
            .redirect()
            .is_some()
    );
}

#[test]
fn cert_manager_solver_edited_into_the_application_ingress() {
    let mut world = world_with(&[ingress(
        "app",
        &[],
        &format!(
            "{}{}",
            tls(&["secure.example.org"], "secure-tls"),
            rules(
                Some("secure.example.org"),
                &[
                    ("Prefix", "/", "web"),
                    ("Exact", "/.well-known/acme-challenge/tok", "solver"),
                ]
            )
        ),
    )]);
    world.secret("secure-tls", Ok(()));
    let router = world.router();
    let challenge = "/.well-known/acme-challenge/tok";
    // On plain HTTP the challenge is served (and nothing else is); on HTTPS it is too.
    assert_eq!(
        router
            .svc("web", "secure.example.org", challenge)
            .as_deref(),
        Some("solver")
    );
    assert!(
        router
            .go("web", "secure.example.org", "/")
            .redirect()
            .is_some()
    );
    assert_eq!(
        router
            .svc("websecure", "secure.example.org", challenge)
            .as_deref(),
        Some("solver")
    );
    assert_eq!(
        router
            .svc("websecure", "secure.example.org", "/")
            .as_deref(),
        Some("web")
    );
}

#[test]
fn the_solver_ingress_may_use_the_class_annotation() {
    let solver = "apiVersion: networking.k8s.io/v1\nkind: Ingress\nmetadata:\n  name: cm-solver\n  namespace: apps\n  annotations:\n    kubernetes.io/ingress.class: reversedock\nspec:\n  rules:\n    - host: secure.example.org\n      http:\n        paths:\n          - {path: /.well-known/acme-challenge/t, pathType: Exact, backend: {service: {name: solver, port: {number: 80}}}}\n---\n";
    let world = world_with(&[
        ingress(
            "app",
            &[],
            &rules(Some("secure.example.org"), &[("Prefix", "/", "web")]),
        ),
        solver.to_owned(),
    ]);
    let router = world.router();
    assert_eq!(
        router
            .svc("web", "secure.example.org", "/.well-known/acme-challenge/t")
            .as_deref(),
        Some("solver")
    );
    assert_eq!(
        router.svc("web", "secure.example.org", "/x").as_deref(),
        Some("web")
    );
}

// ---------------------------------------------------------------------------------------
// Annotations.

const NGINX: &str = "nginx.ingress.kubernetes.io/";

fn annotated(annotations: &[(&str, &str)], paths: &[(&str, &str, &str)]) -> Router {
    let annotations: Vec<(String, &str)> = annotations
        .iter()
        .map(|(k, v)| (format!("{NGINX}{k}"), *v))
        .collect();
    let refs: Vec<(&str, &str)> = annotations.iter().map(|(k, v)| (k.as_str(), *v)).collect();
    world_with(&[ingress("t", &refs, &rules(Some("app.example.com"), paths))]).router()
}

#[test]
fn ssl_redirects_without_tls() {
    // ssl-redirect without a certificate does nothing; force-ssl-redirect redirects.
    let router = annotated(&[("ssl-redirect", "true")], &[("Prefix", "/", "web")]);
    assert!(
        router
            .go("web", "app.example.com", "/")
            .redirect()
            .is_none()
    );
    let router = annotated(&[("force-ssl-redirect", "true")], &[("Prefix", "/", "web")]);
    let routed = router.go("web", "app.example.com", "/x");
    let redirect = routed.redirect().unwrap();
    assert_eq!(redirect.scheme, Some(RedirectScheme::Https));
    assert_eq!(redirect.status, Some(308));
    assert!(router.translation.diagnostics.is_empty());
}

#[test]
fn ssl_redirect_false_serves_tls_hosts_on_both_listeners() {
    let mut world = world_with(&[ingress(
        "t",
        &[(&format!("{NGINX}ssl-redirect"), "false")],
        &format!(
            "{}{}",
            tls(&["secure.example.org"], "secure-tls"),
            rules(Some("secure.example.org"), &[("Prefix", "/", "web")])
        ),
    )]);
    world.secret("secure-tls", Ok(()));
    let router = world.router();
    assert_eq!(
        router.svc("web", "secure.example.org", "/x").as_deref(),
        Some("web")
    );
    assert_eq!(
        router
            .svc("websecure", "secure.example.org", "/x")
            .as_deref(),
        Some("web")
    );
    assert!(
        router
            .go("web", "secure.example.org", "/x")
            .redirect()
            .is_none()
    );
}

#[test]
fn rewrite_target_without_capture_groups() {
    let router = annotated(
        &[("rewrite-target", "/new")],
        &[("Prefix", "/old", "web"), ("Exact", "/exact", "api")],
    );
    // ingress-nginx ≥ 0.22 rewrites the whole URI to the target: only capture groups carry
    // parts of the request path over (its rewrite example, checked 2026-11-11), so
    // `/old/x` becomes `/new`, as for an `Exact` path.
    let routed = router.go("web", "app.example.com", "/old/x");
    assert!(
        matches!(routed.middlewares.as_slice(), [Middleware::ReplacePath(p)] if p.path == "/new"),
        "{:?}",
        routed.middlewares
    );
    let routed = router.go("web", "app.example.com", "/exact");
    assert!(
        matches!(routed.middlewares.as_slice(), [Middleware::ReplacePath(p)] if p.path == "/new"),
        "{:?}",
        routed.middlewares
    );
    // A capture group is a diagnostic and the rewrite is not applied; the Ingress is served.
    let router = annotated(&[("rewrite-target", "/$2")], &[("Prefix", "/old", "web")]);
    let routed = router.go("web", "app.example.com", "/old/x");
    assert_eq!(routed.middlewares, Vec::new());
    assert_eq!(
        routed.outcome,
        Outcome::Backends(BTreeSet::from(["apps/web".to_owned()]))
    );
    assert!(has_warning(&router.translation, "capture groups"));
    assert!(
        router
            .translation
            .diagnostics
            .iter()
            .any(|d| d.path == "kubernetes[\"Ingress/apps/t\"].metadata.annotations[\"nginx.ingress.kubernetes.io/rewrite-target\"]"),
        "{:?}",
        router.translation.diagnostics
    );
}

#[test]
fn backend_protocols() {
    for (value, scheme) in [
        ("HTTP", Scheme::Http),
        ("HTTPS", Scheme::Https),
        ("GRPC", Scheme::H2c),
        ("GRPCS", Scheme::Https),
    ] {
        let router = annotated(&[("backend-protocol", value)], &[("Prefix", "/", "web")]);
        let routed = router.go("web", "app.example.com", "/");
        let service = &router.translation.fragment.services
            [routed.route.unwrap().service.as_deref().unwrap()];
        assert_eq!(service.scheme, scheme, "{value}");
        assert!(router.translation.diagnostics.is_empty());
    }
    let router = annotated(&[("backend-protocol", "FCGI")], &[("Prefix", "/", "web")]);
    assert!(has_warning(&router.translation, "FCGI"));
    assert_eq!(
        router.svc("web", "app.example.com", "/").as_deref(),
        Some("web")
    );
}

#[test]
fn body_size_whitelist_and_cors() {
    // proxy-body-size.
    let router = annotated(&[("proxy-body-size", "16m")], &[("Prefix", "/", "web")]);
    assert_eq!(
        router
            .go("web", "app.example.com", "/")
            .route
            .unwrap()
            .max_body
            .map(|b| b.as_u64()),
        Some(16 << 20)
    );
    let router = annotated(&[("proxy-body-size", "0")], &[("Prefix", "/", "web")]);
    assert_eq!(
        router
            .go("web", "app.example.com", "/")
            .route
            .unwrap()
            .max_body
            .map(|b| b.as_u64()),
        Some(u64::MAX)
    );
    let router = annotated(&[("proxy-body-size", "lots")], &[("Prefix", "/", "web")]);
    assert!(has_warning(&router.translation, "not an NGINX size"));
    assert_eq!(
        router
            .go("web", "app.example.com", "/")
            .route
            .unwrap()
            .max_body,
        None
    );

    // whitelist-source-range.
    let router = annotated(
        &[("whitelist-source-range", "10.0.0.0/8, 192.0.2.7")],
        &[("Prefix", "/", "web")],
    );
    match router
        .go("web", "app.example.com", "/")
        .middlewares
        .as_slice()
    {
        [Middleware::IpAllow(list)] => {
            let cidrs: Vec<String> = list.cidrs.iter().map(ToString::to_string).collect();
            assert_eq!(cidrs, ["10.0.0.0/8", "192.0.2.7/32"]);
        }
        other => panic!("{other:?}"),
    }
    // Nothing usable: fail closed, 403.
    let router = annotated(
        &[("whitelist-source-range", "nope")],
        &[("Prefix", "/", "web")],
    );
    assert_eq!(
        router.go("web", "app.example.com", "/").outcome,
        Outcome::Status(403)
    );
    assert!(has_warning(&router.translation, "refused (403)"));

    // CORS.
    let router = annotated(
        &[
            ("enable-cors", "true"),
            (
                "cors-allow-origin",
                "https://a.example.com, https://b.example.com",
            ),
            ("cors-allow-methods", "GET, POST"),
            ("cors-allow-headers", "X-Token"),
            ("cors-allow-credentials", "true"),
            ("cors-max-age", "600"),
        ],
        &[("Prefix", "/", "web")],
    );
    match router
        .go("web", "app.example.com", "/")
        .middlewares
        .as_slice()
    {
        [Middleware::Cors(cors)] => {
            assert_eq!(cors.allowed_origins.len(), 2);
            assert_eq!(cors.allowed_methods, ["GET", "POST"]);
            assert_eq!(cors.allowed_headers, ["X-Token"]);
            assert!(cors.allow_credentials);
            assert_eq!(
                cors.max_age,
                Some(rdock_model::values::Duration::from_secs(600))
            );
        }
        other => panic!("{other:?}"),
    }
    assert!(router.translation.diagnostics.is_empty());
    // Defaults: any origin, credentials off.
    let router = annotated(&[("enable-cors", "true")], &[("Prefix", "/", "web")]);
    assert!(matches!(
        router.go("web", "app.example.com", "/").middlewares.as_slice(),
        [Middleware::Cors(c)] if c.allowed_origins == ["*"] && !c.allow_credentials
    ));
    // Chain order: the access check first, then CORS, then the rewrite.
    let router = annotated(
        &[
            ("enable-cors", "true"),
            ("whitelist-source-range", "10.0.0.0/8"),
            ("rewrite-target", "/r"),
        ],
        &[("Prefix", "/p", "web")],
    );
    let kinds: Vec<&str> = router
        .go("web", "app.example.com", "/p")
        .middlewares
        .iter()
        .map(|m| match m {
            Middleware::IpAllow(_) => "ip_allow",
            Middleware::Cors(_) => "cors",
            Middleware::ReplacePath(_) => "rewrite",
            _ => "other",
        })
        .collect();
    assert_eq!(kinds, ["ip_allow", "cors", "rewrite"]);
}

#[test]
fn app_root_and_redirects() {
    // app-root: `/` is redirected, everything else is served.
    let router = annotated(
        &[("app-root", "/app1")],
        &[("Prefix", "/", "web"), ("Prefix", "/app1", "api")],
    );
    let routed = router.go("web", "app.example.com", "/");
    let redirect = routed.redirect().unwrap();
    assert_eq!(redirect.path.as_deref(), Some("/app1"));
    assert_eq!(redirect.status, Some(302));
    assert_eq!(
        router.svc("web", "app.example.com", "/other").as_deref(),
        Some("web")
    );
    assert_eq!(
        router.svc("web", "app.example.com", "/app1/x").as_deref(),
        Some("api")
    );
    // Without a path `/` in the Ingress there is nothing to redirect.
    let router = annotated(&[("app-root", "/app1")], &[("Prefix", "/app1", "api")]);
    assert_eq!(
        router.go("web", "app.example.com", "/").outcome,
        Outcome::NotFound
    );

    // permanent-redirect and temporal-redirect redirect everything to the URL.
    let router = annotated(
        &[("permanent-redirect", "https://new.example.com/landing")],
        &[("Prefix", "/", "web"), ("Exact", "/a", "api")],
    );
    for path in ["/", "/a", "/zzz"] {
        let routed = router.go("web", "app.example.com", path);
        let redirect = routed.redirect().unwrap();
        assert_eq!(redirect.status, Some(301), "{path}");
        assert_eq!(
            redirect.replacement.as_deref(),
            Some("https://new.example.com/landing")
        );
    }
    let router = annotated(
        &[("temporal-redirect", "https://t.example.com/$x")],
        &[("Prefix", "/", "web")],
    );
    let routed = router.go("web", "app.example.com", "/");
    let redirect = routed.redirect().unwrap();
    assert_eq!(redirect.status, Some(302));
    // A `$` in the URL is literal, not a capture group.
    assert_eq!(
        redirect.replacement.as_deref(),
        Some("https://t.example.com/$$x")
    );
    let router = annotated(
        &[
            ("permanent-redirect", "https://n.example.com"),
            ("permanent-redirect-code", "308"),
        ],
        &[("Prefix", "/", "web")],
    );
    assert_eq!(
        router
            .go("web", "app.example.com", "/")
            .redirect()
            .unwrap()
            .status,
        Some(308)
    );
    // The redirect is never applied to an ACME challenge path in the same Ingress.
    let router = annotated(
        &[("permanent-redirect", "https://n.example.com")],
        &[
            ("Prefix", "/", "web"),
            ("Exact", "/.well-known/acme-challenge/t", "solver"),
        ],
    );
    assert_eq!(
        router
            .svc("web", "app.example.com", "/.well-known/acme-challenge/t")
            .as_deref(),
        Some("solver")
    );
}

#[test]
fn unsupported_annotations_snippets_and_traefik() {
    let annotations = [
        (format!("{NGINX}limit-rps"), "5".to_owned()),
        (format!("{NGINX}use-regex"), "true".to_owned()),
        (
            format!("{NGINX}configuration-snippet"),
            "more_set_headers x;".to_owned(),
        ),
        (
            format!("{NGINX}server-snippet"),
            "location /x { return 200; }".to_owned(),
        ),
        (
            "traefik.ingress.kubernetes.io/router.entrypoints".to_owned(),
            "websecure".to_owned(),
        ),
        (
            "traefik.ingress.kubernetes.io/router.middlewares".to_owned(),
            "ns-m@kubernetescrd".to_owned(),
        ),
        (
            "cert-manager.io/cluster-issuer".to_owned(),
            "letsencrypt".to_owned(),
        ),
    ];
    let refs: Vec<(&str, &str)> = annotations
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let world = world_with(&[ingress(
        "t",
        &refs,
        &rules(Some("app.example.com"), &[("Prefix", "/", "web")]),
    )]);
    let router = world.router();
    let t = &router.translation;
    // The Ingress is served, without any of it.
    assert_eq!(
        router.svc("web", "app.example.com", "/").as_deref(),
        Some("web")
    );
    assert_eq!(
        router.go("web", "app.example.com", "/").middlewares,
        Vec::new()
    );
    // One diagnostic per annotation, nothing for cert-manager's.
    assert_eq!(t.diagnostics.len(), 6, "{:?}", warnings(t));
    let about = |annotation: &str| -> &Diagnostic {
        t.diagnostics
            .iter()
            .find(|d| d.path.contains(annotation))
            .unwrap_or_else(|| panic!("no diagnostic for {annotation}: {:?}", warnings(t)))
    };
    assert!(about("limit-rps").message.contains("ingress2gateway"));
    assert!(about("use-regex").message.contains("not supported"));
    assert!(about("configuration-snippet").message.contains("refused"));
    assert!(
        about("configuration-snippet")
            .message
            .contains("served without it")
    );
    assert!(about("server-snippet").message.contains("refused"));
    assert!(about("router.entrypoints").message.contains("Traefik"));
    assert!(
        about("router.middlewares")
            .message
            .contains("not supported")
    );
}

#[test]
fn with_nginx_annotations_off_only_snippets_and_traefik_speak() {
    let annotations = [
        (format!("{NGINX}ssl-redirect"), "true".to_owned()),
        (format!("{NGINX}force-ssl-redirect"), "true".to_owned()),
        (format!("{NGINX}rewrite-target"), "/x".to_owned()),
        (format!("{NGINX}proxy-body-size"), "1m".to_owned()),
        (format!("{NGINX}limit-rps"), "5".to_owned()),
        (format!("{NGINX}auth-snippet"), "x".to_owned()),
        (
            "traefik.ingress.kubernetes.io/router.tls".to_owned(),
            "true".to_owned(),
        ),
    ];
    let refs: Vec<(&str, &str)> = annotations
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let mut world = World::with(|i| {
        i.nginx_annotations = false;
        i.publish_address = Some("203.0.113.1".to_owned());
    });
    world.apply(&services());
    world.apply(&ingress(
        "t",
        &refs,
        &rules(Some("app.example.com"), &[("Prefix", "/p", "web")]),
    ));
    let router = world.router();
    let routed = router.go("web", "app.example.com", "/p/x");
    // Served as if the annotations were not there: no redirect, no rewrite, no limit.
    assert_eq!(
        routed.outcome,
        Outcome::Backends(BTreeSet::from(["apps/web".to_owned()]))
    );
    assert_eq!(routed.middlewares, Vec::new());
    assert_eq!(routed.route.unwrap().max_body, None);
    let t = &router.translation;
    assert_eq!(t.diagnostics.len(), 2, "{:?}", warnings(t));
    assert!(has_warning(t, "auth-snippet"));
    assert!(has_warning(t, "router.tls"));
}

// ---------------------------------------------------------------------------------------
// Status.

fn address(ip: Option<&str>, hostname: Option<&str>) -> LoadBalancerAddress {
    LoadBalancerAddress {
        ip: ip.map(str::to_owned),
        hostname: hostname.map(str::to_owned),
    }
}

fn two_ingresses(world: &mut World) {
    world.apply(&services());
    world.apply(&ingress("one", &[], &default_backend("web")));
    world.apply(&ingress("two", &[], &default_backend("api")));
    // Not ours.
    world.apply(
        "apiVersion: networking.k8s.io/v1\nkind: Ingress\nmetadata: {name: foreign, namespace: apps}\nspec: {ingressClassName: nginx, defaultBackend: {service: {name: web, port: {number: 80}}}}\n---\n",
    );
}

#[test]
fn status_from_publish_address() {
    for (value, expected) in [
        ("203.0.113.7", address(Some("203.0.113.7"), None)),
        ("2001:db8::1", address(Some("2001:db8::1"), None)),
        ("lb.example.com", address(None, Some("lb.example.com"))),
    ] {
        let mut world = World::with(|i| i.publish_address = Some(value.to_owned()));
        two_ingresses(&mut world);
        let t = world.translate();
        assert_eq!(
            t.status.ingresses.len(),
            2,
            "foreign Ingresses get no status"
        );
        for (key, addresses) in &t.status.ingresses {
            assert_eq!(addresses, &[expected.clone()], "{key:?}");
        }
        assert!(t.diagnostics.is_empty(), "{:?}", warnings(&t));
    }
}

#[test]
fn status_from_publish_service() {
    let build = |service: &str| {
        let mut world = World::with(|i| i.publish_service = Some("rdock-system/rdock".to_owned()));
        two_ingresses(&mut world);
        world.apply(service);
        world.translate()
    };
    // A load balancer with an IP and a host name.
    let t = build(
        "apiVersion: v1\nkind: Service\nmetadata: {name: rdock, namespace: rdock-system}\nspec: {type: LoadBalancer, ports: [{port: 80}]}\nstatus:\n  loadBalancer:\n    ingress:\n      - ip: 192.0.2.10\n      - hostname: lb.example.net\n      - ip: 192.0.2.10\n",
    );
    assert_eq!(
        t.status.ingresses[&("apps".to_owned(), "one".to_owned())],
        [
            address(None, Some("lb.example.net")),
            address(Some("192.0.2.10"), None),
        ]
    );
    assert_eq!(t.status.ingresses.len(), 2);
    assert!(t.diagnostics.is_empty());
    // A ClusterIP Service: its cluster IP.
    let t = build(
        "apiVersion: v1\nkind: Service\nmetadata: {name: rdock, namespace: rdock-system}\nspec: {type: ClusterIP, clusterIP: 10.96.0.5, ports: [{port: 80}]}\n",
    );
    assert_eq!(
        t.status.ingresses[&("apps".to_owned(), "two".to_owned())],
        [address(Some("10.96.0.5"), None)]
    );
    // A load balancer without an address yet, and a missing Service: empty, one diagnostic
    // in total.
    let t = build(
        "apiVersion: v1\nkind: Service\nmetadata: {name: rdock, namespace: rdock-system}\nspec: {type: LoadBalancer, ports: [{port: 80}]}\n",
    );
    assert!(t.status.ingresses.values().all(Vec::is_empty));
    assert_eq!(t.diagnostics.len(), 1, "{:?}", warnings(&t));
    let t = build(
        "apiVersion: v1\nkind: Service\nmetadata: {name: other, namespace: rdock-system}\nspec: {ports: [{port: 80}]}\n",
    );
    assert!(t.status.ingresses.values().all(Vec::is_empty));
    assert_eq!(t.diagnostics.len(), 1);
    assert!(has_warning(&t, "does not exist"));
    // publish_address wins over publish_service.
    let mut world = World::with(|i| {
        i.publish_service = Some("rdock-system/rdock".to_owned());
        i.publish_address = Some("198.51.100.1".to_owned());
    });
    two_ingresses(&mut world);
    let t = world.translate();
    assert_eq!(
        t.status.ingresses[&("apps".to_owned(), "one".to_owned())],
        [address(Some("198.51.100.1"), None)]
    );
}

#[test]
fn nothing_configured_is_one_diagnostic_in_total() {
    let mut world = World::with(|_| {});
    two_ingresses(&mut world);
    let t = world.translate();
    assert_eq!(t.status.ingresses.len(), 2);
    assert!(t.status.ingresses.values().all(Vec::is_empty));
    assert_eq!(t.diagnostics.len(), 1, "{:?}", warnings(&t));
    assert!(t.diagnostics[0].message.contains("publish_service"));
    // No claimed Ingress: nothing at all, not even that diagnostic.
    let world = World::with(|_| {});
    assert_eq!(world.translate(), Translation::default());
}

// ---------------------------------------------------------------------------------------
// Everything together.

#[test]
fn a_busy_cluster_assembles_with_nothing_left_out() {
    let mut world = World::with(|i| i.publish_address = Some("203.0.113.9".to_owned()));
    world.apply(&services());
    world.apply(&ingress(
        "app",
        &[
            (&format!("{NGINX}rewrite-target"), "/"),
            (&format!("{NGINX}enable-cors"), "true"),
            (&format!("{NGINX}proxy-body-size"), "64m"),
            (&format!("{NGINX}whitelist-source-range"), "10.0.0.0/8,2001:db8::/32"),
            (&format!("{NGINX}app-root"), "/app"),
            (&format!("{NGINX}backend-protocol"), "HTTPS"),
        ],
        &format!(
            "{}{}{}",
            tls(&["secure.example.org", "*.wild.example.org"], "secure-tls"),
            "  rules:\n    - host: secure.example.org\n      http:\n        paths:\n          - {path: /, pathType: Prefix, backend: {service: {name: web, port: {number: 80}}}}\n          - {path: /api, pathType: Prefix, backend: {service: {name: api, port: {number: 80}}}}\n          - {path: /admin, pathType: Exact, backend: {service: {name: admin, port: {number: 80}}}}\n    - host: \"*.wild.example.org\"\n      http:\n        paths:\n          - {path: /, pathType: ImplementationSpecific, backend: {service: {name: web, port: {number: 80}}}}\n    - http:\n        paths:\n          - {path: /plain, pathType: Prefix, backend: {service: {name: root, port: {number: 80}}}}\n",
            default_backend("root")
        ),
    ));
    world.apply(&solver_ingress(
        "solver",
        "  ingressClassName: rdock\n",
        "secure.example.org",
        "abc",
        "Exact",
    ));
    world.secret("secure-tls", Ok(()));
    // `Router::new` asserts that assemble leaves nothing out and the data plane compiles.
    let router = world.router();
    assert_eq!(router.translation.diagnostics, Vec::new());
    assert_eq!(router.translation.status.ingresses.len(), 2);
    // Every route is deterministic and carries an explicit priority; names are unique
    // because they are keys; the fragment has no listeners (Ingress opens no ports).
    let fragment = &router.translation.fragment;
    assert!(fragment.listeners.is_empty());
    assert!(
        fragment
            .routes
            .values()
            .all(|r| r.priority > 0 && r.listeners.is_none())
    );
    assert_eq!(router.translation, world.translate());
}
