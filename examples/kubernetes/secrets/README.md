# Secrets from an external store

Three ways to get a secret from a store into ReverseDock on Kubernetes. Each one ends in a
**file** (read through a `${file:…}` reference) or a **`kubernetes.io/tls` Secret** (read by the
Kubernetes provider for a Gateway listener). ReverseDock itself has no code for these tools.
The guide [Secrets and environment variables](../../../apps/website/src/content/docs/docs/guides/secrets.mdx)
says when a rotated value is picked up.

> **These manifests are NOT exercised by CI.** They were written against each project's
> documentation and checked only for YAML well-formedness. The stores, roles, policies and
> operators are yours; every host name, path and key here is a placeholder.

| Files | Tool |
|---|---|
| [external-secrets.yaml](external-secrets.yaml), [external-secrets-values.yaml](external-secrets-values.yaml) | External Secrets Operator: one Secret mounted as a file, one `kubernetes.io/tls` Secret for the Gateway of [../gateway.yaml](../gateway.yaml). Assumes a `ClusterSecretStore` named `example`; its configuration is out of scope. |
| [secrets-store-csi.yaml](secrets-store-csi.yaml), [secrets-store-csi-values.yaml](secrets-store-csi-values.yaml) | Secrets Store CSI driver with the Vault provider: a `SecretProviderClass` and a CSI volume. |
| [vault-agent-values.yaml](vault-agent-values.yaml) | Vault Agent Injector: annotations that render `/vault/secrets/alert-token`. |

The values files are for [deploy/helm/reversedock](../../../deploy/helm/reversedock) (`extraVolumes`,
`extraVolumeMounts`, `podAnnotations`, `config.extra`). Mount volumes as plain volumes, never
with `subPath` (Kubernetes does not update those), and do not pass secrets as environment
variables if they will rotate (an environment is fixed when the container starts).

Outside Kubernetes, [../../secrets](../../secrets) renders a file with an OpenBao Agent in Compose.

## What these examples refer to

Checked on 2026-11-11.

- ExternalSecret fields (`secretStoreRef`, `refreshInterval`, `target.creationPolicy`, `target.template.type`, templated `data`): [External Secrets Operator, ExternalSecret API](https://external-secrets.io/latest/api/externalsecret/).
- `SecretProviderClass` and the CSI volume (`driver: secrets-store.csi.k8s.io`, `volumeAttributes.secretProviderClass`): [Secrets Store CSI Driver, usage](https://secrets-store-csi-driver.sigs.k8s.io/getting-started/usage). The Vault provider's `roleName` and `objects` parameters: [Vault CSI provider](https://developer.hashicorp.com/vault/docs/deploy/kubernetes/csi), whose own example still writes `apiVersion: …/v1alpha1`; the driver's usage page uses `v1`, which these files use. Rotation is an alpha feature of the driver, off by default ([Secret auto rotation](https://secrets-store-csi-driver.sigs.k8s.io/topics/secret-auto-rotation)).
- Injector annotations (`agent-inject`, `role`, `agent-inject-secret-<name>`, `agent-inject-template-<name>`; files appear under `/vault/secrets`): [Vault Agent Injector](https://developer.hashicorp.com/vault/docs/deploy/kubernetes/injector) and [its annotations](https://developer.hashicorp.com/vault/docs/deploy/kubernetes/injector/annotations).
- Volumes that hold a Secret are updated eventually, after "the kubelet sync period + cache propagation delay", and `subPath` mounts are not updated: [Kubernetes, Secrets](https://kubernetes.io/docs/concepts/configuration/secret/#using-secrets-as-files-from-a-pod).
