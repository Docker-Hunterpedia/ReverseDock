# Gateway API conformance harness

Runs the upstream Gateway API conformance suite, version **v1.7.0** (Standard channel), against ReverseDock on a kind cluster, and judges the report. The design is in [ADR-0029](../../../docs/decisions/0029-kubernetes-gateway-api.md) ("Packaging and CI"); the suite's facts are in [the v0.7 research](../../../docs/research/v0.7-kubernetes.md) §2.2 and §5.

> **Status: passes in CI; not released; no report submitted upstream.** On 2026-11-11, on commit `19e88cc` ([run](https://github.com/Docker-Hunterpedia/ReverseDock/actions/runs/43046671411)), the `gateway-conformance` job of [`.github/workflows/kubernetes.yml`](../../../.github/workflows/kubernetes.yml) ran the suite v1.7.0 (Standard channel CRDs) on kind (kind v0.33.0, node image v1.37.0, addresses from cloud-provider-kind) against the chart-installed controller, with the features inferred from `GatewayClass.status.supportedFeatures`, and reported, with no test skipped and none failed:
>
> | Profile | Core | Extended |
> |---|---|---|
> | `GATEWAY-HTTP` | success, 40 passed | success, 31 passed |
> | `GATEWAY-GRPC` | success, 17 passed | success, 7 passed |
> | `GATEWAY-TLS` | success, 21 passed | success, 8 passed |
> | `GATEWAY-TCP` | success, 20 passed | success, 7 passed |
>
> `GATEWAY-UDP` (core features only: `Gateway`, `ReferenceGrant`, `UDPRoute`) joined `options.yaml` with UDP routes (v0.8, [ADR-0030](../../../docs/decisions/0030-v0-8-cache-extensibility-gateway.md)); its nine tests are transcribed against the translator in `crates/providers/rdock-provider-kubernetes/tests/gateway_udp.rs` and pass there, but the profile has **not run in CI yet**: the table above predates it, and only the kind run proves that cloud-provider-kind forwards the per-Gateway Service's UDP ports.
>
> "Extended success" means every test for the extended features this implementation claims ([`features.rs`](../../../crates/providers/rdock-provider-kubernetes/src/features.rs)) passed; it does not mean every extended feature of the Gateway API is supported. The same core results were obtained on two earlier commits the same day, before ListenerSet support was added. The job now fails the workflow (no `--allow-partial`); adding it to the repository ruleset's required checks is a maintainer action. No report has been submitted to the upstream Gateway API repository, because reports require a released version (see "Reports"), and the software is not released.

## Files

| File | What it is |
|---|---|
| `conformance_test.go` | `TestConformance`: calls the upstream `conformance.RunConformance`. Build tag `conformance`, so `go vet ./...` and `go test ./...` elsewhere never compile it. |
| `options_test.go` | `TestOptionsFile`: loads `options.yaml` strictly (a misspelled key fails in seconds instead of being ignored by the upstream loader). Needs no cluster. |
| `options.yaml` | Gateway class `reversedock`, the five profiles, the implementation block, `skipTests`. Keys are the json tags of `suite.ConfigurableOptions`. |
| `kind.yaml` | kind v0.33.0 cluster: Kubernetes v1.37.0 (tag and digest from kind's own defaults), one control plane and one worker. |
| `run.sh` | Cluster, CRDs, image, cloud-provider-kind, `helm install --wait`, the suite, `check-report.py`; diagnostics on failure. Idempotent. |
| `install-tools.sh` | Pinned, SHA-256-verified kind, kubectl, helm (4 and 3), kubeconform and cloud-provider-kind for Linux x86-64. CI uses it. |
| `install-gateway-crds.sh` | The Gateway API v1.7.0 Standard CRDs, checksum-verified, applied server-side. The chart never installs CRDs. |
| `check-report.py` | Prints a table per profile (core and extended result, counts, skipped and failed test names) to stdout and `$GITHUB_STEP_SUMMARY`; fails on the conditions below. |
| `test_check_report.py` | Offline tests of `check-report.py` (`python3 -I tests/conformance/gateway-api/test_check_report.py`). |
| `reports/v1.7.0/` | Committed report YAML. Empty: **reports are added by release PRs**, never by a pull request that changes code. |

## Run it locally

You need Docker, `kind`, `kubectl`, `helm`, `cloud-provider-kind`, Go and Python 3 on a Linux machine (bash 4.4 or newer). Go fetches the 1.27 toolchain the suite needs through `GOTOOLCHAIN=auto`.

```sh
just docker rdock:ci                                              # or any image with an explicit tag
tests/conformance/gateway-api/install-tools.sh                    # optional, Linux x86-64: the CI versions
RDOCK_IMAGE=rdock:ci tests/conformance/gateway-api/run.sh         # or: just conformance rdock:ci
```

A full run takes 15 to 30 minutes. Everything lands in `tests/conformance/gateway-api/out/` (git-ignored): `report.yaml`, `summary.txt`, `go-test.log`, `supported-features.txt`, `cloud-provider-kind.log`, and after a failure `diagnostics/` (the Gateway API objects as YAML, events, controller logs and kind's logs). `KEEP_CLUSTER=1` keeps the cluster for inspection; the settings are listed at the top of `run.sh`.

How addresses work: the suite connects to `Gateway.status.addresses[0]` on the listener's port, so that address must answer from the machine running the tests. `cloud-provider-kind` gives every `LoadBalancer` Service such an address on kind's Docker network. It also runs a Gateway API controller of its own by default, which `run.sh` turns off (`--gateway-channel disabled`, checked against v0.12.0), so the only controller for the class is ReverseDock.

Features are never listed in `options.yaml`: the suite reads `GatewayClass.status.supportedFeatures`, which the controller publishes from what it implements, and fails when that is empty.

## Skipping a test

`skipTests` in `options.yaml` is empty and is meant to stay close to empty. Every entry needs a reason and an issue link in the comment directly above it. `check-report.py` fails the run when an entry lacks either, and when an entry is stale: not listed under `skippedTests` in the report, because the test now passes, does not apply, or is misspelled. A skipped core test makes the profile `partial` at best, and upstream accepts a v1.7 `partial` result with at most five skipped tests.

## What fails

| Condition | Result |
|---|---|
| Report missing, unreadable, or not for Gateway API v1.7.0 / Standard | error |
| `skipTests` entry without reason and issue link; stale skip | error, always |
| A profile of `options.yaml` is missing from the report | error |
| A profile's core or extended result is `failure` | error |
| A core with no test at all (nothing proven) | error |
| `partial` with more than five skipped tests | error |

`--allow-partial` (`RDOCK_ALLOW_PARTIAL=1`) is for local runs only: CI never passes it, so there a failure in any of the last four rows fails the job. It turns those rows into warnings in the summary and tolerates `go test` failing. It never hides a missing report, a stale skip or a skip without a reason.

## Reports

A report is evidence for upstream's [implementations table](https://gateway-api.sigs.k8s.io/implementations/), not a CI by-product. When the core tests of all profiles pass, a release PR commits the unmodified `report.yaml` as `reports/v1.7.0/standard-<version>-default-report.yaml` and sends it upstream following [conformance/reports/README.md](https://github.com/kubernetes-sigs/gateway-api/blob/v1.7.0/conformance/reports/README.md) (a folder `conformance/reports/v1.7.0/Docker-Hunterpedia-ReverseDock/` with a `README.md`: table of contents and a "Reproduce" section that points at this file). `implementation.version` must be a tag or commit, never a branch; `run.sh` fills it from `RDOCK_VERSION` or `git describe`.

## Pins

| What | Version | Where it is pinned |
|---|---|---|
| Gateway API and the suite | v1.7.0 | `go.mod`, `install-gateway-crds.sh` (with the bundle's SHA-256), `options.yaml` |
| kind, node image | v0.33.0, Kubernetes v1.37.0 | `install-tools.sh`, `kind.yaml` |
| cloud-provider-kind | v0.12.0 | `install-tools.sh` |
| kubectl, Helm | v1.37.2, v4.3.1 and v3.22.1 | `install-tools.sh` |
| kubeconform | v0.8.0, schemas for Kubernetes 1.37.2 | `install-tools.sh`, the workflow |
| k3s (`helm-k3s` job) | v1.37.2+k3s1 | the workflow, with the SHA-256 of its install script |

Bump them together, with the dated source in the pull request (the project's documentation rules).
