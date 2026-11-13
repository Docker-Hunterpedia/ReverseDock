# rdock-provider-kubernetes

Kubernetes provider (W-K8S-01…05, ADR-0029): a Gateway API controller and Ingress
translation in the same process as the data plane. Every replica watches, translates and
serves; only the leader writes status and the per-Gateway Services (the controller writes no
Kubernetes Events yet).

**Status:** v0.7, implemented: the Gateway API translator, the Ingress translator and the cluster runtime are in place. It passes the upstream Gateway API v1.7.0 conformance suite in CI on kind (`GATEWAY-HTTP`, `GATEWAY-GRPC`, `GATEWAY-TLS` and `GATEWAY-TCP`: all core tests and every claimed extended feature; 2026-11-11, commit `19e88cc`), and the Helm install is tested on k3s in CI; it is not released and no report has been submitted upstream. v0.8 adds UDPRoute and `UDP` listeners (ADR-0030): its upstream tests pass against the translator (`tests/gateway_udp.rs`), and `GATEWAY-UDP` passes in the conformance job on kind (2026-11-12, commit `43d81de`: core 21 passed, extended 7 passed). Design: [ADR-0029](../../../docs/decisions/0029-kubernetes-gateway-api.md); user documentation: the website pages "Kubernetes" (install), "Kubernetes Gateway API" and "Kubernetes Ingress".

Modules (each has one owner, so they can change independently):

- `api`: our own Gateway API v1 types (v1.7.0, Standard channel), `#[derive(CustomResource)]`
  with the schema disabled; unknown fields and enum values never fail deserialisation.
  Tested on the upstream conformance manifests in `tests/fixtures/upstream`.
- `inventory`: everything the watches have seen, as plain data (Secrets and ConfigMaps
  without their bytes).
- `translate`: `translate(&Inventory, &Settings) -> Translation`, pure: the fragment, the
  diagnostics, the desired status of every object, the per-Gateway Services, and the Secrets
  and ConfigMaps to write as files (`secret_paths`, `config_map_path`).
- `gateway`, `ingress`: the two translators `translate` calls. ListenerSets are part of the
  Gateway translator (`gateway::listener_sets`): their listeners join the parent Gateway's;
  the upstream tests gated on the `ListenerSet` feature are transcribed in
  `tests/gateway_listenerset.rs`.
- `features`: the single list of claimed Gateway API features (only those with a passing
  test).
- `runtime`: `run(settings, RunContext, tx, shutdown)`, the watch loop, leader election,
  status writes and Service provisioning. Its tests against a real API server
  (`tests/runtime_cluster.rs`) run when `RDOCK_TEST_KUBECONFIG` names a kubeconfig with the
  Gateway API v1.7.0 standard CRDs installed, and are skipped otherwise.
  For example `RDOCK_TEST_KUBECONFIG=/path/to/kubeconfig cargo test -p rdock-provider-kubernetes
  --test runtime_cluster`. They are not wired into CI.

Built on kube 5 with rustls and ring (ADR-0013) and k8s-openapi 0.29 (`v1_33`).
