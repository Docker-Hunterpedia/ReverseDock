# Kubernetes manifests

Plain manifests and a Kustomize base for ReverseDock as a Gateway API controller, for clusters
without Helm. They are the committed output of the [Helm chart](../helm/reversedock/README.md)
with default values, rendered into the namespace `reversedock-system`.

| File | What it is |
|---|---|
| `install.yaml` | ServiceAccount, ClusterRole and binding, Role and binding, ConfigMap, Deployment, PodDisruptionBudget, GatewayClass. **Generated; do not edit.** |
| `namespace.yaml` | The namespace `reversedock-system`, with the Pod Security `restricted` profile enforced. |
| `kustomization.yaml` | A base that lists both files, for overlays. |

`scripts/render-kubernetes-manifests.sh` rewrites `install.yaml`; with `--check` it fails when the
committed file is stale (CI runs it). Render with the Helm version CI uses, as output can differ
slightly between Helm versions.

## Install

1. Install the Gateway API CRDs, version 1.7.0, Standard channel. These manifests do not contain
   them, and the GatewayClass in `install.yaml` needs them:

   ```sh
   kubectl apply --server-side -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.7.0/standard-install.yaml
   ```

2. Apply the base:

   ```sh
   kubectl apply -k deploy/kubernetes
   ```

   or, from a release, `kubectl apply -f namespace.yaml -f install.yaml`.

3. Check it:

   ```sh
   kubectl -n reversedock-system get pods
   kubectl get gatewayclass reversedock
   ```

Then create a Gateway: see [examples/kubernetes](../../examples/kubernetes/README.md).

## Change it with Kustomize

Do not edit `install.yaml`. Make an overlay in your own repository:

```yaml
# overlay/kustomization.yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - github.com/Docker-Hunterpedia/ReverseDock/deploy/kubernetes?ref=<release tag>
images:
  - name: ghcr.io/docker-hunterpedia/rdock
    newTag: <version>
patches:
  - target: { kind: Deployment, name: reversedock }
    patch: |-
      - op: replace
        path: /spec/replicas
        value: 3
```

Settings that live in `rdock.yaml` (Ingress, namespaces, extra listeners) are easier to change
through the chart's values; render your own file with
`helm template reversedock deploy/helm/reversedock -n reversedock-system -f my-values.yaml`.

## Remove

```sh
kubectl delete -k deploy/kubernetes
```

Delete your Gateways first so the controller removes the Services it made for them. The Gateway
API CRDs stay.
