# ReverseDock Helm chart

Runs ReverseDock as a Kubernetes controller and data plane in one Deployment
([ADR-0029](../../../docs/decisions/0029-kubernetes-gateway-api.md)). It serves Gateway API
resources (`HTTPRoute`, `GRPCRoute`, `TLSRoute`, `TCPRoute`) and, when switched on, `Ingress`.

The chart works with Helm 3 and Helm 4 and needs Kubernetes 1.33 or later. It is a pre-release:
the version follows the workspace version.

**Conformance.** The Gateway API conformance suite runs in CI
(`.github/workflows/kubernetes.yml`). No conformance claim is made yet, and the chart does not
state one. `GatewayClass.status.supportedFeatures` lists only what has a passing test.

## How it runs

- One Deployment (two replicas) is controller and proxy together. Every replica watches the
  API server, translates and serves; one replica at a time, chosen with a Lease, writes status
  and Services (no Kubernetes Events are written in v0.7). Serving and readiness never depend
  on leadership.
- For each Gateway the controller creates a Service of its own in the release namespace. The
  Service selects the rdock pods; the Gateway's `status.addresses` is that Service's address.
- The chart never grants access to pods or nodes and never lets rdock write Secrets.
- Pods run as uid 65532, with a read-only root file system, no capabilities, `RuntimeDefault`
  seccomp and no CPU limit. The data directory is a memory-backed `emptyDir`, because it holds
  the key files written from TLS Secrets.

## Install

> **Build the image first.** The chart's default image tag is its `appVersion`, `0.6.0-alpha.1`:
> a released image that **does not contain the Kubernetes provider**. Until a release contains
> it, build the image from this checkout, make it available to the cluster, and pass it with
> `image.repository` and `image.tag`:
>
> ```sh
> docker build --tag rdock:dev .          # or: just docker rdock:dev
> kind load docker-image rdock:dev        # local kind cluster; or push to a registry the nodes pull from
> helm install reversedock deploy/helm/reversedock -n reversedock-system --create-namespace \
>   --set image.repository=rdock --set image.tag=dev
> ```

1. Install the Gateway API CRDs, version 1.7.0, Standard channel. **The chart does not contain
   them**: they belong to the cluster, not to one release, and Helm never upgrades or deletes
   CRDs. Use the upstream command, and run it again before an upgrade that changes the version:

   ```sh
   kubectl apply --server-side -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.7.0/standard-install.yaml
   ```

   Some distributions (k3s with its bundled Traefik) already install older CRDs. rdock reports
   an older or missing bundle in the `SupportedVersion` condition of the GatewayClass and skips
   kinds whose CRD is absent.

2. Install the chart:

   ```sh
   helm install reversedock oci://ghcr.io/docker-hunterpedia/charts/reversedock \
     --namespace reversedock-system --create-namespace
   ```

   The chart is pushed to that registry by the release workflow; until a release has published
   it, install from a checkout with the image you built (see the note above):
   `helm install reversedock deploy/helm/reversedock -n reversedock-system --create-namespace --set image.repository=rdock --set image.tag=dev`.

3. Check it:

   ```sh
   kubectl -n reversedock-system get pods
   kubectl get gatewayclass reversedock
   ```

Then create a Gateway: see [examples/kubernetes](../../../examples/kubernetes/README.md).

## Values

The same text is in [values.yaml](values.yaml); [values.schema.json](values.schema.json) rejects
unknown keys and wrong types on `helm install`, `upgrade` and `lint`.

| Value | Default | Description |
|---|---|---|
| `nameOverride` | `""` | Overrides the chart name in resource names and labels. Changing it changes the pod selector, so it cannot be changed on an existing release. |
| `fullnameOverride` | `""` | Overrides the full resource name (default: the release name). |
| `commonLabels` | `{}` | Labels added to every object the chart creates (not to the pod selector). |
| `image.repository` | `ghcr.io/docker-hunterpedia/rdock` | Image repository. Release images are published to this repository by the release workflow. |
| `image.tag` | `""` | Image tag. Empty means the chart's appVersion. |
| `image.digest` | `""` | Image digest (sha256:...). When set, the tag is kept for readability and the digest is used. |
| `image.pullPolicy` | `IfNotPresent` | Image pull policy. |
| `imagePullSecrets` | `[]` | Secrets for pulling the image from a private registry, as a list of `{name: ...}`. |
| `kind` | `Deployment` | `Deployment` (default) or `DaemonSet`. A DaemonSet runs one pod per node and can map host ports (see `daemonSet`); it ignores `replicaCount`, `autoscaling` and `topologySpread`. |
| `replicaCount` | `2` | Number of replicas of a Deployment. Ignored when `autoscaling.enabled` is true. Every replica serves traffic; only one at a time writes status and Services. |
| `drainTimeoutSeconds` | `10` | Seconds open requests may finish after SIGTERM (`lifecycle.drain_timeout` in rdock.yaml). `terminationGracePeriodSeconds` is this value plus 15. |
| `logLevel` | `info` | Application log filter (`RDOCK_LOG`), for example `info` or `info,rdock_proxy=debug`. |
| `logFormat` | `json` | Application log format (`RDOCK_LOG_FORMAT`): `auto`, `json` or `text`. |
| `watchNamespaces` | `[]` | Namespaces to watch. Empty means every namespace and the chart renders one ClusterRole. With `[a, b]` it renders a Role and RoleBinding in each namespace, a small ClusterRole for GatewayClasses, IngressClasses, Namespaces and CRDs, and sets `providers.kubernetes.namespaces`. |
| `kubeconfig` | `""` | Path to a kubeconfig, only for running outside a cluster. Leave empty in a cluster: the service account is used. |
| `gatewayClass.create` | `true` | Create the GatewayClass. It needs the Gateway API CRDs to exist before the install. |
| `gatewayClass.name` | `reversedock` | Name of the GatewayClass that Gateways refer to. |
| `gatewayClass.controllerName` | `reversedock.dev/gateway-controller` | Controller name the GatewayClass is bound to (`providers.kubernetes.controller_name`). Change it only when you run two controllers of this kind in one cluster. |
| `gatewayClass.description` | `ReverseDock, a reverse proxy on Cloudflare Pingora.` | Description of the GatewayClass. |
| `gateway.enabled` | `true` | Serve Gateway API resources (`providers.kubernetes.gateway.enabled`). |
| `gateway.serviceType` | `load_balancer` | Type of the Service the controller creates for each Gateway: `load_balancer`, `cluster_ip` or `node_port` (`providers.kubernetes.gateway.service_type`). |
| `gateway.portRange` | `"20000-29999"` | Range of internal ports allocated to Gateway listeners, `from-to` (`providers.kubernetes.gateway.port_range`). It bounds the number of Gateway ports. |
| `gateway.allowExternalName` | `false` | Allow backendRefs to ExternalName Services (`allow_external_name`). Refused by default (CVE-2021-25740). |
| `ingress.enabled` | `false` | Translate networking.k8s.io/v1 Ingress resources (`providers.kubernetes.ingress.enabled`). Adds the Ingress RBAC rules and the file-owned `web` and `websecure` listeners. |
| `ingress.class` | `reversedock` | Class name claimed through the deprecated `kubernetes.io/ingress.class` annotation, and the name of the IngressClass when `ingressClass.create` is true. |
| `ingress.claimWithoutClass` | `false` | Also claim Ingresses without a class (`claim_without_class`). |
| `ingress.publishService` | `""` | `namespace/name` of the Service whose address is written to `status.loadBalancer` of claimed Ingresses. Empty means the chart's own `ingress.service` when it is enabled. |
| `ingress.publishAddress` | `""` | Address written to `status.loadBalancer` instead (IP or host name). |
| `ingress.nginxAnnotations` | `true` | Honour ingress-nginx annotations that map onto a middleware (`nginx_annotations`). |
| `ingress.ports` | (map) | Container ports of the file-owned Ingress listeners `web` (plain HTTP) and `websecure` (HTTPS). Unprivileged ports need no capability. |
| `ingress.service` | (map) | A Service that exposes the Ingress listeners (80 -> http, 443 -> https). |
| `ingress.service.enabled` | `false` | Create the Service. |
| `ingress.service.type` | `LoadBalancer` | Service type. |
| `ingress.service.annotations` | `{}` | Annotations of the Service, for example cloud load balancer settings. |
| `ingress.service.externalTrafficPolicy` | `""` | `Cluster` or `Local`. `Local` keeps client addresses on most clouds. |
| `ingress.service.loadBalancerClass` | `""` | `spec.loadBalancerClass`, when your cluster has more than one. |
| `ingress.service.httpPort` | `80` | Port the Service listens on for HTTP. |
| `ingress.service.httpsPort` | `443` | Port the Service listens on for HTTPS. |
| `ingressClass.create` | `false` | Create an IngressClass named `ingress.class` with controller `reversedock.dev/ingress-controller`. Off by default. |
| `ingressClass.default` | `false` | Mark the IngressClass as the cluster default (`ingressclass.kubernetes.io/is-default-class`). Only one class should be the default. |
| `leaderElection.enabled` | `true` | Elect one replica as the writer of status and Services (`providers.kubernetes.leader_election.enabled`). Serving never depends on leadership. With one replica or `false`, the instance is always the writer. |
| `leaderElection.lease` | `reversedock-leader` | Name of the Lease in the release namespace. |
| `allowAcme` | `false` | Allow automatic ACME together with the Kubernetes provider (`allow_acme`). Refused otherwise. Replicas share no ACME storage until v0.9, so use `replicaCount: 1` and a persistent `data.existingClaim`. cert-manager is the supported way to get certificates. |
| `config.extra` | `{}` | Extra rdock.yaml, merged over what the chart renders: maps merge, lists and scalars replace. Use it for listeners, middlewares, observability or limits. |
| `admin.port` | `2080` | Port of the admin API. |
| `admin.network.enabled` | `false` | Listen on the pod address instead of loopback, to serve /metrics and /healthz to Prometheus and kubelet over TLS. Needs `tlsSecretName`. Off by default: rdock refuses a network admin listener without TLS, and probes then run `rdock healthcheck` in the container, which talks to the local admin socket. |
| `admin.network.tlsSecretName` | `""` | Name of a `kubernetes.io/tls` Secret in the release namespace with the admin certificate. The chart does not create one. |
| `admin.network.allowedHosts` | `[]` | Host names the admin API answers to, besides `localhost` and the admin Service names. |
| `admin.network.service` | (map) | Create the admin Service (port name `admin`). |
| `admin.network.service.type` | `ClusterIP` | Service type. |
| `admin.network.service.annotations` | `{}` | Annotations of the admin Service. |
| `data` | (map) | Data directory (`RDOCK_DATA_DIR`). It holds TLS key files written from Secrets, so by default it is memory-backed and never reaches a node disk. |
| `data.medium` | `Memory` | Medium of the emptyDir. `Memory` keeps key material off disk; empty uses node storage. |
| `data.sizeLimit` | `64Mi` | Size limit of the emptyDir. |
| `data.existingClaim` | `""` | Use this PersistentVolumeClaim instead of an emptyDir (needed for ACME; one replica). |
| `probes.startup.periodSeconds` | `2` | Seconds between startup probes. |
| `probes.startup.failureThreshold` | `60` | Failures before the container is restarted (period x threshold = time to first sync). |
| `probes.startup.timeoutSeconds` | `3` | Probe timeout in seconds. |
| `probes.readiness.periodSeconds` | `5` | Seconds between readiness probes. |
| `probes.readiness.failureThreshold` | `3` | Failures before the pod leaves the Service endpoints. |
| `probes.readiness.timeoutSeconds` | `3` | Probe timeout in seconds. |
| `probes.liveness.periodSeconds` | `20` | Seconds between liveness probes. |
| `probes.liveness.failureThreshold` | `6` | Failures before the container is restarted. Kept high: liveness only has to catch a stuck process. |
| `probes.liveness.timeoutSeconds` | `3` | Probe timeout in seconds. |
| `resources` | (map) | Resources of the container. No CPU limit by design: throttling a proxy adds tail latency. |
| `podSecurityContext` | (map) | Pod security context. Matches the Pod Security "restricted" profile. |
| `securityContext` | (map) | Container security context. Matches the Pod Security "restricted" profile. |
| `serviceAccount.create` | `true` | Create the ServiceAccount. |
| `serviceAccount.name` | `""` | Name of the ServiceAccount. Empty means the full name of the release. |
| `serviceAccount.annotations` | `{}` | Annotations of the ServiceAccount, for example for workload identity. |
| `podLabels` | `{}` | Labels added to the pods. |
| `podAnnotations` | `{}` | Annotations added to the pods. |
| `workloadAnnotations` | `{}` | Annotations of the Deployment or DaemonSet. |
| `priorityClassName` | `""` | Name of a PriorityClass for the pods. |
| `nodeSelector` | `{}` | Node selector of the pods. |
| `tolerations` | `[]` | Tolerations of the pods. |
| `affinity` | `{}` | Affinity of the pods. |
| `extraEnv` | `[]` | Extra environment variables of the container, as Kubernetes `env` entries. Do not put secrets in values; reference a Secret with `valueFrom`. |
| `extraVolumes` | `[]` | Extra volumes of the pod. |
| `extraVolumeMounts` | `[]` | Extra volume mounts of the container. |
| `topologySpread.enabled` | `true` | Spread pods over nodes (Deployment only). |
| `topologySpread.maxSkew` | `1` | Maximum skew. |
| `topologySpread.whenUnsatisfiable` | `ScheduleAnyway` | `ScheduleAnyway` keeps pods schedulable on small clusters; `DoNotSchedule` is strict. |
| `topologySpread.topologyKey` | `kubernetes.io/hostname` | Topology key. |
| `podDisruptionBudget.enabled` | `true` | Create a PodDisruptionBudget. |
| `podDisruptionBudget.maxUnavailable` | `1` | Pods that may be unavailable during voluntary disruptions. Keep at least two replicas when the budget is on. |
| `autoscaling.enabled` | `false` | Create a HorizontalPodAutoscaler (Deployment only). |
| `autoscaling.minReplicas` | `2` | Minimum replicas. |
| `autoscaling.maxReplicas` | `6` | Maximum replicas. |
| `autoscaling.targetCPUUtilizationPercentage` | `75` | Target average CPU utilisation in percent of the CPU request. |
| `daemonSet.hostPorts.enabled` | `false` | Map host ports to the Ingress listeners (needs `kind: DaemonSet` and `ingress.enabled: true`). Limit: a host port belongs to one pod per node, so only one listener per host port exists on a node; Gateway listeners are reached through their Services, not through host ports. |
| `daemonSet.hostPorts.http` | `80` | Host port mapped to `ingress.ports.http`. |
| `daemonSet.hostPorts.https` | `443` | Host port mapped to `ingress.ports.https`. |
| `daemonSet.privilegedPorts` | `none` | How a container may bind ports below 1024, only needed when `ingress.ports` are below 1024: `none`, `sysctl` (the safe sysctl net.ipv4.ip_unprivileged_port_start=0 on the pod) or `capability` (adds NET_BIND_SERVICE, for runtimes that reject the sysctl). |
| `metrics.serviceMonitor.enabled` | `false` | Create a Prometheus Operator ServiceMonitor. Needs `admin.network.enabled`, the `monitoring.coreos.com/v1` CRD and a token Secret (rdock's /metrics needs a token with the `metrics` role). |
| `metrics.serviceMonitor.labels` | `{}` | Labels of the ServiceMonitor, for example the `release` label your Prometheus selects. |
| `metrics.serviceMonitor.interval` | `30s` | Scrape interval. |
| `metrics.serviceMonitor.scrapeTimeout` | `10s` | Scrape timeout. |
| `metrics.serviceMonitor.tokenSecret` | (map) | Secret and key that hold the API token. |
| `metrics.serviceMonitor.tlsConfig` | (map) | TLS settings of the scrape. The admin certificate is yours: set `ca` or, for a self-signed one, `insecureSkipVerify: true`. |
| `networkPolicy.enabled` | `false` | Create a NetworkPolicy for the pods (ingress rules only; egress is not restricted). |
| `networkPolicy.allowFrom` | `[]` | Peers allowed to reach the data-plane ports. Empty allows every source. |
| `networkPolicy.adminFrom` | `[]` | Peers allowed to reach the admin port (only with `admin.network.enabled`). Empty allows every source in the cluster; use it to limit to your Prometheus namespace. |

## How values map to `rdock.yaml`

The ConfigMap holds the file `rdock.yaml`; its checksum is on the pod template, so a change
rolls the pods.

| Value | `rdock.yaml` key |
|---|---|
| `watchNamespaces` | `providers.kubernetes.namespaces` |
| `kubeconfig` | `providers.kubernetes.kubeconfig` |
| `gatewayClass.controllerName` | `providers.kubernetes.controller_name` |
| `gateway.enabled`, `.serviceType`, `.portRange`, `.allowExternalName` | `providers.kubernetes.gateway.enabled`, `.service_type`, `.port_range`, `.allow_external_name` |
| (release namespace) | `providers.kubernetes.gateway.service_namespace` |
| (the pod selector labels) | `providers.kubernetes.gateway.pod_selector` |
| `ingress.enabled`, `.class`, `.claimWithoutClass`, `.nginxAnnotations` | `providers.kubernetes.ingress.enabled`, `.class`, `.claim_without_class`, `.nginx_annotations` |
| `ingress.publishService`, `.publishAddress` | `providers.kubernetes.ingress.publish_service`, `.publish_address` |
| `leaderElection.enabled`, `.lease` | `providers.kubernetes.leader_election.enabled`, `.lease` |
| `allowAcme` | `providers.kubernetes.allow_acme` |
| `drainTimeoutSeconds` | `lifecycle.drain_timeout` |
| `admin.port`, `admin.network.*` | `admin.listener`, `admin.tls`, `admin.allowed_hosts` |
| `ingress.ports.*` (Ingress on) | `listeners.web` and `listeners.websecure`, and `defaults.listeners` |
| `config.extra` | merged over everything above |

`pod_selector` is the selector of the Deployment. Do not change `nameOverride` on a live
release: it changes the selector and the Services the controller made would no longer match.

## Ingress

`ingress.enabled: true` translates Ingresses whose class is yours. The chart then also opens two
file-owned listeners, `web` on 8080 and `websecure` on 8443, which Ingress routes attach to.
Set `ingress.service.enabled: true` to expose them with a `LoadBalancer` Service on ports 80 and
443; its address is then published to the status of the Ingresses. Set `ingressClass.create:
true` to create the IngressClass `reversedock` (controller `reversedock.dev/ingress-controller`);
`ingressClass.default: true` makes it the cluster default. ingress-nginx annotations that map
one to one onto a middleware are honoured; every other annotation of that prefix is reported.
For new work use the Gateway API; [ingress2gateway](https://github.com/kubernetes-sigs/ingress2gateway)
converts existing Ingresses.

## Namespaced mode

```yaml
watchNamespaces: [team-a, team-b]
```

The chart renders a Role and RoleBinding in each namespace for the namespaced kinds, and a small
ClusterRole for GatewayClasses, Namespaces (for `allowedRoutes` selectors), CRDs and, with Ingress,
IngressClasses. The Role in the release namespace for the Lease and the per-Gateway Services is
always there. The namespaces must exist before the install.

## Host ports (DaemonSet)

```yaml
kind: DaemonSet
ingress: { enabled: true }
daemonSet:
  hostPorts: { enabled: true, http: 80, https: 443 }
```

runs one pod per node and maps host ports 80 and 443 to the Ingress listeners 8080 and 8443,
which needs no capability. This suits a single node or bare metal without a load balancer.
**The limit:** a host port belongs to one process per node, so only one set of listeners can
use it; Gateway listeners are not mapped to host ports and are reached through the Services the
controller creates (use `gateway.serviceType: node_port` or `cluster_ip` there). Only if you set
`ingress.ports` below 1024 does `daemonSet.privilegedPorts` matter: `sysctl` sets
`net.ipv4.ip_unprivileged_port_start=0` on the pod (a safe sysctl since Kubernetes 1.22),
`capability` adds `NET_BIND_SERVICE` for runtimes that refuse the sysctl.

## Certificates and cert-manager

cert-manager is the supported way to get certificates in a cluster. It fills the `kubernetes.io/tls`
Secrets that Gateways and Ingresses name; rdock reads them, writes the key files into its
memory-backed data directory and reloads when a Secret changes. Until a Gateway listener's
Secret exists and holds a valid pair, that listener reports `ResolvedRefs=False` and
`Programmed=False` and is not served (other listeners are unaffected); it is programmed as soon as
the Secret appears. See
[examples/kubernetes/cert-manager.yaml](../../../examples/kubernetes/cert-manager.yaml).

**Automatic ACME is not configured by the chart.** rdock refuses `acme` together with the
Kubernetes provider unless `allowAcme: true`. Replicas share no ACME storage until v0.9, so with
`allowAcme` use `replicaCount: 1` and a persistent volume (`data.existingClaim`); the chart
refuses more than one replica with it.

## Admin API, probes and metrics

By default the admin listener is on loopback, because rdock refuses a network admin listener
without TLS. Probes then run `rdock healthcheck` in the container, which asks `/readyz` on the
local admin socket. Readiness is true after the first full sync on every replica and does not
depend on leadership. To serve `/healthz`, `/readyz` and `/metrics` on the pod address, create a
`kubernetes.io/tls` Secret and set `admin.network.enabled: true` and `admin.network.tlsSecretName`;
probes then use HTTPS with `Host: localhost`, and the chart creates the Service
`<release>-admin`. `/metrics` needs an API token with the `metrics` role; give it to the
ServiceMonitor with `metrics.serviceMonitor.tokenSecret`. The ServiceMonitor is created only when
the `monitoring.coreos.com/v1` API is present. rdock keeps tokens in its data directory, which is
an `emptyDir` by default.

## RBAC

Cluster-wide mode (the default):

| API group | Resources | Verbs |
|---|---|---|
| `gateway.networking.k8s.io` | `gatewayclasses`, `gateways`, `httproutes`, `grpcroutes`, `tlsroutes`, `tcproutes`, `udproutes`, `referencegrants`, `listenersets`, `backendtlspolicies` | get, list, watch |
| `gateway.networking.k8s.io` | `*/status` of the same kinds except `referencegrants` | update, patch |
| core | `services`, `secrets`, `configmaps`, `namespaces` | get, list, watch |
| `discovery.k8s.io` | `endpointslices` | get, list, watch |
| `apiextensions.k8s.io` | `customresourcedefinitions` | get, list, watch |
| `networking.k8s.io` | `ingresses`, `ingressclasses` (only with `ingress.enabled`) | get, list, watch |
| `networking.k8s.io` | `ingresses/status` (only with `ingress.enabled`) | update, patch |

In the release namespace: `coordination.k8s.io` `leases` with `create` (it cannot be limited by
`resourceNames`) and `get`, `update` on the one Lease; core `services` with get, list, watch,
create, update, patch, delete, for the per-Gateway Services. There is no access to pods or nodes,
and no write access to Secrets.

## Upgrade

```sh
kubectl apply --server-side -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.7.0/standard-install.yaml   # only when the CRD version changes
helm upgrade reversedock oci://ghcr.io/docker-hunterpedia/charts/reversedock -n reversedock-system
```

Pods roll one at a time (`maxUnavailable: 0`) and a new pod is Ready only after its first full
sync, so it never takes traffic with an empty routing table.

## Uninstall

```sh
helm uninstall reversedock -n reversedock-system
```

Services the controller made for Gateways are not part of the release. Delete the Gateways first,
so the controller removes their Services, or delete them by label afterwards:
`kubectl -n reversedock-system delete service -l reversedock.dev/gateway-namespace`.
The Gateway API CRDs stay; remove them only if nothing else uses them.

## Raw manifests and examples

[deploy/kubernetes](../../kubernetes/README.md) holds `install.yaml`, the rendered default chart,
and a Kustomize base. [examples/kubernetes](../../../examples/kubernetes/README.md) has a
Gateway, routes, an Ingress and a cert-manager snippet.

## Tests

`ci/` holds three value sets used by CI: `daemonset-values.yaml`, `namespaced-values.yaml` and
`ingress-values.yaml`.

```sh
helm lint --strict deploy/helm/reversedock
helm lint --strict deploy/helm/reversedock -f deploy/helm/reversedock/ci/ingress-values.yaml
helm template reversedock deploy/helm/reversedock -n reversedock-system | kubeconform -strict -ignore-missing-schemas -
```
