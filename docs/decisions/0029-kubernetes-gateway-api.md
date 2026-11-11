# ADR-0029: v0.7: a Gateway API controller in the same binary, one Service per Gateway in front of a shared data plane, providers that contribute listeners and certificates, Ingress as a translation

- Status: accepted
- Date: 2026-11-11

## Context
v0.7 makes ReverseDock a Kubernetes Gateway API controller (W-K8S-01), translates Ingress for migrations (W-K8S-02), reads EndpointSlices and TLS Secrets and works with cert-manager (W-K8S-03), elects a leader and runs with scoped RBAC (W-K8S-04), and ships a Helm chart, Kustomize and raw manifests (W-K8S-05). The config model already has `providers.kubernetes`; `rdock run` refuses it as "planned for v0.7". [Research](../research/v0.7-kubernetes.md) checked the facts on 2026-11-11. The findings that shape this decision:
- Gateway API v1.7.0 (2026-10-29) has every kind of W-K8S-01 as `v1` in the Standard channel, and `GATEWAY-TCP` and `GATEWAY-UDP` are regular conformance profiles.
- The conformance suite dials `Gateway.status.addresses[0]` on the listener's port and creates several Gateways that each listen on port 80 without a hostname; two core tests need each Gateway to answer with its own routes. One shared address cannot pass.
- With no feature flags the suite runs exactly the features in `GatewayClass.status.supportedFeatures`; a skipped core test makes a profile `partial`.
- The gateway-api crate 0.22.0 needs Rust 1.92 (our MSRV is 1.89) and kube 4, and is generated from Gateway API v1.5.1. kube 5.0.0 with rustls and ring builds on our pins and MSRV with no banned crate; kube has no leader election.
- A provider fragment carries routes, services, middlewares and TCP routes and services only; listeners and certificates belong to the file configuration ([ADR-0009](0009-provider-ownership-and-merge.md), [ADR-0018](0018-docker-provider-and-merge.md)). Snapshots are stored on disk and shown by the admin API.
- Listener changes apply in process ([ADR-0012](0012-own-listeners-pingora-http-engine.md)).
- `PathPrefix` is a string prefix; `redirect` cannot set a hostname, a path or a status code; nothing answers a fixed status for a share of a route; client-go style leader election gives no fencing; replicas share no ACME storage until v0.9.
- Nested Kubernetes nodes do not run in the development sandbox, so the conformance suite and the Helm install can be proven only in CI.

## Decision

### Shape
- **One binary, one Deployment.** `rdock run` with `providers.kubernetes` is controller and data plane together; there is no separate mode flag, the provider section is the switch (the `--mode kubernetes` wording in the architecture is dropped). Every replica watches, translates and serves the same way.
- **One Service per Gateway, a shared data plane.** For each accepted Gateway the controller creates a Service in its own namespace (`<gateway namespace>-<gateway name>`, hashed to 63 characters, labelled `gateway.networking.k8s.io/gateway-name` and `reversedock.dev/gateway-namespace`), selecting the rdock pods, with `port` = the listener's port and `targetPort` = an internal port allocated per (Gateway, listener port) from `providers.kubernetes.gateway.port_range` (default 20000–29999). The Service's ports are the record of the allocation: the leader allocates (keeping existing assignments), every replica reads the Service and opens exactly those internal listeners, so replicas never disagree. `status.addresses` is the Service's load-balancer ingress (or its cluster IP for `ClusterIP`). Services of Gateways that are gone are deleted by label; `spec.infrastructure` labels and annotations are copied onto the Service. A Deployment per Gateway is not built; a host-port DaemonSet is a chart option documented with its limit (one Gateway per port).
- **Target:** Gateway API v1.7.0, Standard channel, `v1` only. Controller name `reversedock.dev/gateway-controller`. An older or missing CRD bundle is reported in the GatewayClass `SupportedVersion` condition and in a diagnostic; kinds whose CRD is absent are skipped, not fatal.

### Crate and client
- `rdock-provider-kubernetes` on **kube 5.0.0** (`client`, `rustls-tls`, `ring`, `runtime`, `derive`; no default features) and k8s-openapi 0.29.0 (`v1_33`). The Gateway API kinds are **our own types** (`#[derive(CustomResource)]`, `schema = "disabled"`, only the fields we read, unknown fields ignored); the gateway-api crate is not used.
- The crate keeps the Docker provider's split: **`translate(&Inventory, &Settings) -> Translation`** is pure and returns the fragment, the diagnostics, the desired status of every object and the desired per-Gateway Services; the runtime half owns the API server. Status is half of the core conformance tests, so it is computed by the same pure function and tested on fixtures without a cluster.
- **Watching:** one `reflector` per kind with the default backoff (`ListWatch`), no `Controller` and no per-object reconciler. Any change marks the inventory dirty; a translation runs at most every 100 ms and its snapshot is published only when it differs. The first snapshot waits for every store. When the API server is unreachable the last snapshot stays in service and the provider is reported degraded, as with Docker.
- Kinds watched: GatewayClass, Gateway, HTTPRoute, GRPCRoute, TLSRoute, TCPRoute, UDPRoute, ReferenceGrant, ListenerSet, BackendTLSPolicy, Service, EndpointSlice, Secret, ConfigMap (CA bundles for BackendTLSPolicy), Namespace (for `allowedRoutes` selectors), Ingress and IngressClass (when Ingress is on). `providers.kubernetes.namespaces` limits the namespaced watches.
- Client configuration is kube's inference: in-cluster service account, else `providers.kubernetes.kubeconfig` or `KUBECONFIG`.

### Providers may contribute listeners and certificates
- `Fragment` gains `listeners` and `certificates`. They merge like other provider objects under `name@provider` keys, pass the same validator and are left out one by one when invalid. The file configuration still owns defaults and every setting; a provider listener never replaces a file listener, and a provider listener whose address a file listener already binds is left out with a diagnostic.
- Only providers on an allow-list in the merge code may contribute them (`kubernetes`); Docker and Swarm labels cannot open ports or name certificate files.
- **Key material never enters a fragment.** The provider writes each referenced `kubernetes.io/tls` Secret to `<data dir>/kubernetes/secrets/<namespace>/<name>/{tls.crt,tls.key}` (directory 0700, files 0600, written atomically, removed when no listener refers to them) and contributes a `certificates` entry naming those files. A changed Secret changes the files and triggers a reload. In the chart the data directory is a memory-backed `emptyDir`.
- A Gateway listener's certificates apply to that listener only: two Gateways may present different certificates for the same hostname. If the certificate index cannot do this per listener today, it is extended.

### Translating the Gateway API
- **Listeners:** each (Gateway, port) becomes one internal listener: `http` for `HTTP`, `https` for `HTTPS` and for `TLS` with termination, `tcp` for `TCP` and for a port that holds only `TLS` passthrough listeners. Listener hostnames, `allowedRoutes` (namespaces `Same`, `All`, `Selector`; kinds), `sectionName` and `port` on parentRefs, hostname intersection and the conflict rules follow the specification; a route is bound only to the internal listeners of the Gateways that accepted it, with the intersected hostnames.
- **Matches:** exact path → `Path`; prefix → ``Path(`/a`) || PathPrefix(`/a/`)`` (the router keeps its string prefix); regular expressions → `PathRegexp`, `HeaderRegexp`, `QueryRegexp`; method, headers and query parameters as they are. Each match becomes a route with an **explicit priority** that encodes the specification's order: hostname specificity, exact path, prefix length, method, header count, query count, then creation time, namespace and name, then rule order.
- **Backends:** a `backendRef` to a Service resolves through its EndpointSlices to pod addresses (union of slices, de-duplicated; port by name through the Service; `ready` endpoints in the pool, `serving && terminating` drained and used only when nothing else is ready). Weights become a `split`. `appProtocol` `kubernetes.io/h2c` selects `h2c`; GRPCRoute backends default to `h2c`. `ExternalName` Services are refused by default (`allow_external_name: true` opts in). A Service without ready endpoints answers 503.
- **Invalid references answer 500.** A new service form answers a fixed status and takes no backends; an invalid `backendRef` (unknown kind, missing Service, no ReferenceGrant) becomes such a service in the rule's split, so its weighted share answers 500 as the specification requires.
- **Filters:** `RequestHeaderModifier` and `ResponseHeaderModifier` → `headers`; `RequestRedirect` → `redirect`, which gains `hostname`, `path`, `prefix` and `status` (301, 302, 303, 307, 308); `URLRewrite` → `replace_path`, an anchored `rewrite` and the `Host` request header; `RequestMirror` → `mirror` (one target; a percentage or fraction); `CORS` → `cors`. `ExtensionRef`, `ExternalAuth` and several mirrors are not supported: the rule is rejected with `UnsupportedValue` and never half-applied. Filters on a backendRef are supported for header modification only.
- **Timeouts and retries:** `timeouts.backendRequest` → the route's `read` timeout; `timeouts.request` and `retry` are claimed only when the data plane honours them exactly (a total request timeout is added if it is a small change; otherwise the feature is left out of `supportedFeatures`).
- **GRPCRoute:** service and method → `/service/method` paths (exact, prefix for service-only, regex), headers as above. **TLSRoute:** `Passthrough` → TCP routes with `HostSNI`; `Terminate` → TCP routes with termination when the listener has certificates. **TCPRoute** → ``HostSNI(`*`)`` on a `tcp` listener. **UDPRoute:** the listener reports `UnsupportedProtocol` until M-L4-04 (v0.8).
- **ReferenceGrant** is checked for every cross-namespace reference (route → Service, Gateway → Secret, policy → ConfigMap); removing a grant revokes on the next translation. **ListenerSet** listeners are merged into their parent Gateway when it allows them. **BackendTLSPolicy** sets `https` with the policy's hostname and CA bundle (ConfigMap, written to a file like Secrets, or the system roots).
- **Only what works is claimed.** `GatewayClass.status.supportedFeatures` lists exactly the features with a passing test; the list lives in one place in the crate and the conformance options file skips nothing silently.

### Status and leader election
- Status is written with a merge patch on `/status`, only when it differs from what is stored, with `observedGeneration` on every condition; conditions and `parents[]` entries of other controllers are preserved (read, merge by type or by `controllerName`, write). Objects of other classes are never touched.
- **Leader election is our own Lease loop** (`coordination.k8s.io/v1`, client-go's algorithm: lease 15 s, renew deadline 10 s, retry 2 s, optimistic concurrency on `resourceVersion`), in the controller's namespace, named `providers.kubernetes.leader_election.lease` (default `reversedock-leader`). Only the leader writes status, Events and the per-Gateway Services. **Serving and readiness never depend on leadership**: a replica is Ready after its first full sync, so a pod never takes traffic with an empty routing table and a lost Lease never stops traffic. Because there is no fencing, every write is idempotent and derived from the same inputs on every replica. `leader_election.enabled: false` (single replica, or out of cluster) makes the instance the writer.

### Ingress (W-K8S-02)
- Off by default: `providers.kubernetes.ingress.enabled`. An Ingress is claimed when its `ingressClassName` names an IngressClass whose `spec.controller` is `reversedock.dev/ingress-controller`, or the deprecated `kubernetes.io/ingress.class` annotation equals `ingress.class` (default `reversedock`); Ingresses without a class only when our IngressClass is the cluster default or `ingress.claim_without_class: true`.
- Semantics as specified: `Exact`, `Prefix` (by segment) and `ImplementationSpecific` (treated as `Prefix`), one-label host wildcards, longest path first and `Exact` before `Prefix`, `defaultBackend`, named and numbered Service ports, `spec.tls` Secrets (a missing Secret keeps the route and reports a diagnostic). Routes attach to the file configuration's default listeners; Ingress opens no ports. `status.loadBalancer` is published from `ingress.publish_service` (`namespace/name`) or `ingress.publish_address`.
- ingress-nginx annotations (`ingress.nginx_annotations`, default on) that map one to one onto an existing middleware are honoured (`ssl-redirect`, `force-ssl-redirect`, `rewrite-target` without capture groups, `backend-protocol`, `proxy-body-size`, `whitelist-source-range`, `enable-cors` and its origins, methods and headers, `app-root`, `permanent-redirect`, `temporal-redirect`); every other annotation of that prefix is a diagnostic naming it; `*-snippet` annotations are refused. Users are pointed at ingress2gateway for conversion to the Gateway API.

### cert-manager and ACME (W-K8S-03)
- cert-manager is the supported way to get certificates in a cluster: it fills the Secrets that Gateways and Ingresses name. Its HTTP-01 solver creates an HTTPRoute or an Ingress with an exact path; exact paths already outrank prefixes, and routes for `/.well-known/acme-challenge/` are also exempt from our http→https redirect so the challenge is answered over plain HTTP. A missing or invalid Secret leaves the listener up without that certificate (`ResolvedRefs=False`), and the Secret watch picks the certificate up when it appears.
- `acme` together with `providers.kubernetes` is refused by `rdock validate` and `rdock run` unless `providers.kubernetes.allow_acme: true`, which the documentation limits to one replica with a persistent data directory (replicas share nothing until v0.9).

### Configuration
```yaml
providers:
  kubernetes:
    kubeconfig: null                  # path; default in-cluster, then KUBECONFIG
    namespaces: []                    # empty = all
    controller_name: reversedock.dev/gateway-controller
    gateway:
      enabled: true
      service_type: load_balancer     # load_balancer | cluster_ip | node_port
      service_namespace: null         # default: the pod's namespace
      pod_selector: {}                # labels of the rdock pods; default from the pod's own labels
      port_range: "20000-29999"
      allow_external_name: false
    ingress:
      enabled: false
      class: reversedock
      claim_without_class: false
      publish_service: null           # namespace/name
      publish_address: null
      nginx_annotations: true
    leader_election:
      enabled: true
      lease: reversedock-leader
    allow_acme: false
```
`gateway_class` and the boolean `ingress` of the unreleased model are replaced by this shape (GatewayClasses are selected by `controller_name`, as the specification says). The pod's namespace, name and labels come from the service-account namespace file and the downward API (`RDOCK_POD_NAMESPACE`, `RDOCK_POD_NAME`).

### Packaging and CI (W-K8S-05)
- **Chart** `deploy/helm/reversedock` (`apiVersion: v2`, works with Helm 3 and 4, `values.schema.json`): ServiceAccount; a ClusterRole that reads the kinds above and writes only their `status` and Events; a Role in the release namespace for the Lease and the per-Gateway Services; Deployment (2 replicas, PodDisruptionBudget, topology spread; `runAsNonRoot`, read-only root file system, all capabilities dropped, `RuntimeDefault` seccomp, no CPU limit); a ConfigMap with `rdock.yaml`; admin and metrics Service; the `GatewayClass` and an optional `IngressClass`; ServiceMonitor and HPA off by default; namespaced mode (`watchNamespaces`) with Roles instead of the ClusterRole. **The chart does not contain the Gateway API CRDs**; the docs give the upstream install command.
- **Raw manifests** `deploy/kubernetes/install.yaml` are the committed output of `helm template`, with a `kustomization.yaml` beside it; CI fails when they are stale. `examples/kubernetes/` holds a Gateway, an HTTPRoute and an Ingress example.
- **Conformance harness** `tests/conformance/gateway-api/`: a Go module that runs the upstream suite at v1.7.0 from an options file (profiles `GATEWAY-HTTP`, `GATEWAY-GRPC`, `GATEWAY-TLS`, `GATEWAY-TCP`), features inferred from `supportedFeatures`, every skipped test listed with a reason.
- **CI** (`.github/workflows/kubernetes.yml`): `chart` (lint, template with three value sets through kubeconform, manifests in sync), `gateway-conformance` (kind, cloud-provider-kind for Service addresses with its own Gateway controller disabled, CRDs, chart install, the suite, report and logs as artifacts) and `helm-k3s` (k3s without Traefik, install, the example, upgrade, uninstall). The two cluster jobs are **informational** until the core tests of HTTP, GRPC and TLS pass in CI; they then become required and the report is submitted upstream. Controller tests against a real API server (kube-apiserver and etcd, no nodes) run in the `rust` job when the binaries are present and are skipped otherwise.

## Consequences
- `gate.rs` stops refusing `providers.kubernetes`; the schema, the website reference and the status badges change (`just schema`, `pnpm gen`). The roadmap's "done when" is met only when the CI jobs pass; until then the release notes say "implemented, conformance run in CI pending" and no conformance claim is made.
- Model changes: `KubernetesProvider` is reshaped (it never shipped); `Fragment` gains `listeners` and `certificates`; `redirect` gains `hostname`, `path`, `prefix`, `status`; services gain a fixed-status form. Existing configurations keep their meaning.
- New dependencies: kube, k8s-openapi and what they bring (43 crates, one new duplicate, no new TLS or crypto stack). The cargo feature `kubernetes` is on by default; a build without it warns when the section is set.
- The provider can write to the cluster (status, Events, one Lease, Services in one namespace) and to its own data directory. It never reads pods or nodes and never writes Secrets.
- A listener per Gateway port means a cluster with many Gateways opens many sockets in the shared pods; the port range bounds it (10,000 by default) and running out is a `Programmed=False` condition, not a crash.
- Requirements and roadmap text about Gateway API versions and provisional TCP/UDP tests is corrected; [architecture §4 and §12](../05-architecture.md) are updated to match.
