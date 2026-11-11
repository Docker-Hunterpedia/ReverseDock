# rdock-provider-kubernetes

Kubernetes provider (W-K8S-01…05, ADR-0029): a Gateway API controller and Ingress
translation in the same process as the data plane. Every replica watches, translates and
serves; only the leader writes status, Events and the per-Gateway Services.

**Status:** v0.7, in progress. Shared types are in place; the translators and the cluster
runtime are stubs. Design: [ADR-0029](../../../docs/decisions/0029-kubernetes-gateway-api.md).

Modules (each has one owner, so they can change independently):

- `api`: our own Gateway API v1 types (v1.7.0, Standard channel), `#[derive(CustomResource)]`
  with the schema disabled; unknown fields and enum values never fail deserialisation.
  Tested on the upstream conformance manifests in `tests/fixtures/upstream`.
- `inventory`: everything the watches have seen, as plain data (Secrets and ConfigMaps
  without their bytes).
- `translate`: `translate(&Inventory, &Settings) -> Translation`, pure: the fragment, the
  diagnostics, the desired status of every object, the per-Gateway Services, and the Secrets
  and ConfigMaps to write as files (`secret_paths`, `config_map_path`).
- `gateway`, `ingress`: the two translators `translate` calls.
- `features`: the single list of claimed Gateway API features (only those with a passing
  test).
- `runtime`: `run(settings, RunContext, tx, shutdown)`, the watch loop, leader election,
  status writes and Service provisioning.

Built on kube 5 with rustls and ring (ADR-0013) and k8s-openapi 0.29 (`v1_33`).
