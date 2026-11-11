#!/usr/bin/env bash
# Run the upstream Gateway API conformance suite (v1.7.0) against ReverseDock on a kind cluster.
#
#   RDOCK_IMAGE=rdock:ci tests/conformance/gateway-api/run.sh
#
# Steps: kind cluster -> Gateway API Standard CRDs -> load the image -> cloud-provider-kind (the
# Service addresses the suite connects to; its own Gateway controller is disabled) -> helm
# install -> go test -> check-report.py. Safe to run again: an existing cluster is reused and the
# chart is upgraded in place. README.md explains the settings and the output files.
#
# This script has not run in the repository's development sandbox (no nested Kubernetes there);
# the `gateway-conformance` job of .github/workflows/kubernetes.yml is where it is proven.
#
# Settings (environment):
#   RDOCK_IMAGE          image to test, with an explicit tag               (default rdock:ci)
#   RDOCK_IMAGE_ARCHIVE  `docker save` tarball to `docker load` first      (default none)
#   RDOCK_VERSION        implementation.version in the report: a tag or commit
#                                                                          (default git describe)
#   RDOCK_ALLOW_PARTIAL  1: failures, missing profiles and too many skips are warnings;
#                        the exit status then only reflects setup errors and stale skips
#                                                                          (default 0)
#   RDOCK_HELM_ARGS      extra arguments for `helm upgrade --install`, split on spaces
#   CLUSTER_NAME         kind cluster name                                 (default rdock-conformance)
#   KEEP_CLUSTER         1: do not delete the cluster at the end           (default 0)
#   OUT_DIR              where reports and logs go                         (default ./out here)
#   GO_TEST_TIMEOUT      go test -timeout                                  (default 40m)
#   GATEWAY_API_VERSION  must match go.mod and options.yaml                (default v1.7.0)
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/../../.." && pwd)

RDOCK_IMAGE=${RDOCK_IMAGE:-rdock:ci}
RDOCK_IMAGE_ARCHIVE=${RDOCK_IMAGE_ARCHIVE:-}
RDOCK_ALLOW_PARTIAL=${RDOCK_ALLOW_PARTIAL:-0}
RDOCK_HELM_ARGS=${RDOCK_HELM_ARGS:-}
CLUSTER_NAME=${CLUSTER_NAME:-rdock-conformance}
KEEP_CLUSTER=${KEEP_CLUSTER:-0}
OUT_DIR=${OUT_DIR:-$SCRIPT_DIR/out}
GO_TEST_TIMEOUT=${GO_TEST_TIMEOUT:-40m}
GATEWAY_API_VERSION=${GATEWAY_API_VERSION:-v1.7.0}
# Names fixed by the chart (deploy/helm/reversedock) and ADR-0029.
RELEASE=${RELEASE:-reversedock}
NAMESPACE=${NAMESPACE:-reversedock-system}
GATEWAY_CLASS=${GATEWAY_CLASS:-reversedock}
CHART_DIR=$REPO_ROOT/deploy/helm/reversedock
CONTEXT="kind-$CLUSTER_NAME"

mkdir -p "$OUT_DIR"
OUT_DIR=$(cd "$OUT_DIR" && pwd)
# A kubeconfig of our own, outside OUT_DIR (which CI uploads): neither the caller's
# ~/.kube/config nor $KUBECONFIG is touched, and no client certificate lands in an artifact.
WORK_DIR=$(mktemp -d)
export KUBECONFIG="$WORK_DIR/kubeconfig"
CPK_PID=""
CREATED_CLUSTER=0
DIAGNOSTICS_DONE=0

log() { printf '\n==> %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

require() {
  local tool
  for tool in "$@"; do
    command -v "$tool" > /dev/null 2>&1 || die "$tool is not installed (tests/conformance/gateway-api/install-tools.sh installs the CI versions of kind, kubectl, helm and cloud-provider-kind)"
  done
}

# Everything a person needs to find out why a run failed. Every command may fail on its own.
collect_diagnostics() {
  ((DIAGNOSTICS_DONE == 0)) || return 0
  DIAGNOSTICS_DONE=1
  local dir=$OUT_DIR/diagnostics kind
  mkdir -p "$dir"
  log "Collecting diagnostics in $dir"
  for kind in gatewayclasses gateways httproutes grpcroutes tlsroutes tcproutes udproutes \
              referencegrants listenersets backendtlspolicies; do
    kubectl get "$kind" -A -o yaml > "$dir/$kind.yaml" 2>&1 || true
  done
  kubectl get services,endpointslices,pods -A -o yaml > "$dir/workloads.yaml" 2>&1 || true
  kubectl get events -A --sort-by=.lastTimestamp > "$dir/events.txt" 2>&1 || true
  kubectl -n "$NAMESPACE" describe pods > "$dir/controller-pods.txt" 2>&1 || true
  kubectl -n "$NAMESPACE" logs -l "app.kubernetes.io/name=reversedock,app.kubernetes.io/instance=$RELEASE" \
    --all-containers --prefix --tail=-1 --max-log-requests=20 > "$dir/controller.log" 2>&1 || true
  kubectl -n "$NAMESPACE" logs -l "app.kubernetes.io/name=reversedock,app.kubernetes.io/instance=$RELEASE" \
    --all-containers --prefix --previous --tail=-1 --max-log-requests=20 > "$dir/controller-previous.log" 2>&1 || true
  kind export logs "$dir/kind" --name "$CLUSTER_NAME" > /dev/null 2>&1 || true
}

cleanup() {
  local status=$?
  if ((status != 0)) && [[ -s "$KUBECONFIG" ]]; then
    collect_diagnostics
  fi
  if [[ -n "$CPK_PID" ]]; then
    kill "$CPK_PID" 2> /dev/null || true
    wait "$CPK_PID" 2> /dev/null || true
  fi
  if [[ "$KEEP_CLUSTER" != 1 && "$CREATED_CLUSTER" == 1 ]]; then
    kind delete cluster --name "$CLUSTER_NAME" > /dev/null 2>&1 || true
  fi
  rm -rf "$WORK_DIR"
  exit "$status"
}
trap cleanup EXIT

create_cluster() {
  if kind get clusters 2> /dev/null | grep -qx "$CLUSTER_NAME"; then
    log "Reusing the kind cluster $CLUSTER_NAME"
    kind export kubeconfig --name "$CLUSTER_NAME" --kubeconfig "$KUBECONFIG"
  else
    log "Creating the kind cluster $CLUSTER_NAME"
    kind create cluster --name "$CLUSTER_NAME" --config "$SCRIPT_DIR/kind.yaml" \
      --kubeconfig "$KUBECONFIG" --wait 180s
    CREATED_CLUSTER=1
  fi
  kubectl config use-context "$CONTEXT" > /dev/null
}

install_crds() {
  log "Installing the Gateway API $GATEWAY_API_VERSION Standard CRDs"
  GATEWAY_API_VERSION=$GATEWAY_API_VERSION "$SCRIPT_DIR/install-gateway-crds.sh"
}

load_image() {
  if [[ -n "$RDOCK_IMAGE_ARCHIVE" ]]; then
    log "Loading $RDOCK_IMAGE_ARCHIVE into Docker"
    docker load --input "$RDOCK_IMAGE_ARCHIVE"
  fi
  docker image inspect "$RDOCK_IMAGE" > /dev/null 2>&1 \
    || die "image $RDOCK_IMAGE not found in Docker (build it with 'just docker $RDOCK_IMAGE')"
  log "Loading $RDOCK_IMAGE into the kind nodes"
  kind load docker-image "$RDOCK_IMAGE" --name "$CLUSTER_NAME"
}

# cloud-provider-kind turns Services of type LoadBalancer into addresses reachable from this
# host, which is what the suite needs: it joins Gateway.status.addresses[0] with the listener
# port (research v0.7 §5). It also runs a Gateway API controller of its own by default; that
# one must be off, or two controllers would fight over the CRDs (flags verified against the
# source of v0.12.0, cmd/app.go).
start_cloud_provider_kind() {
  log "Starting cloud-provider-kind"
  cloud-provider-kind --gateway-channel disabled --enable-default-ingress=false \
    > "$OUT_DIR/cloud-provider-kind.log" 2>&1 &
  CPK_PID=$!
  local i
  for i in $(seq 1 60); do
    kill -0 "$CPK_PID" 2> /dev/null || { cat "$OUT_DIR/cloud-provider-kind.log" >&2; die "cloud-provider-kind exited"; }
    grep -q "Starting service controller" "$OUT_DIR/cloud-provider-kind.log" && return 0
    # The log line is not a documented interface; a process that stays up for 20 s is good enough.
    if ((i >= 20)); then
      echo "warning: no 'Starting service controller' line after ${i}s; continuing, the process is running" >&2
      return 0
    fi
    sleep 1
  done
}

install_chart() {
  log "Installing the chart as release $RELEASE in $NAMESPACE"
  [[ "${RDOCK_IMAGE##*/}" == *:* ]] || die "RDOCK_IMAGE needs an explicit tag, e.g. rdock:ci"
  local -a extra=()
  if [[ -n "$RDOCK_HELM_ARGS" ]]; then
    read -r -a extra <<< "$RDOCK_HELM_ARGS"
  fi
  helm upgrade --install "$RELEASE" "$CHART_DIR" \
    --namespace "$NAMESPACE" --create-namespace \
    --set "image.repository=${RDOCK_IMAGE%:*}" \
    --set "image.tag=${RDOCK_IMAGE##*:}" \
    --set image.pullPolicy=Never \
    --wait --timeout 5m \
    "${extra[@]}"

  # The suite infers the features it runs from GatewayClass.status.supportedFeatures and fails
  # when that is empty, so wait for the controller to publish it.
  kubectl wait --for=condition=Accepted --timeout=120s "gatewayclass/$GATEWAY_CLASS"
  local features="" i
  for i in $(seq 1 60); do
    features=$(kubectl get "gatewayclass/$GATEWAY_CLASS" -o jsonpath='{range .status.supportedFeatures[*]}{.name}{" "}{end}')
    [[ -n "$features" ]] && break
    sleep 2
  done
  [[ -n "$features" ]] || die "GatewayClass $GATEWAY_CLASS has no status.supportedFeatures after 120 s; the suite cannot infer features"
  echo "supportedFeatures: $features" | tee "$OUT_DIR/supported-features.txt"
}

run_suite() {
  local version=${RDOCK_VERSION:-$(git -C "$REPO_ROOT" describe --tags --always 2> /dev/null || echo unknown)}
  [[ "$version" != unknown ]] || die "set RDOCK_VERSION: upstream wants a tag or commit in the report"
  rm -f "$OUT_DIR/report.yaml"

  log "Checking options.yaml (strict, offline)"
  (cd "$SCRIPT_DIR" && go test -tags conformance -count=1 -run '^TestOptionsFile$' ./...)

  log "Running the suite (version $version, timeout $GO_TEST_TIMEOUT)"
  SUITE_STATUS=0
  (
    cd "$SCRIPT_DIR"
    go test -tags conformance -count=1 -v -timeout "$GO_TEST_TIMEOUT" -run '^TestConformance$' ./... \
      -args --conformance-options-file "$SCRIPT_DIR/options.yaml" \
      --version "$version" --report-output "$OUT_DIR/report.yaml"
  ) 2>&1 | tee "$OUT_DIR/go-test.log" || SUITE_STATUS=$?
  # pipefail makes the status of the pipeline that of go test, not of tee.
}

check_report() {
  log "Judging the report"
  [[ -s "$OUT_DIR/report.yaml" ]] || die "the suite wrote no report (see $OUT_DIR/go-test.log)"
  local -a flags=()
  if [[ "$RDOCK_ALLOW_PARTIAL" == 1 ]]; then
    flags+=(--allow-partial)
  fi
  python3 "$SCRIPT_DIR/check-report.py" --report "$OUT_DIR/report.yaml" \
    --options "$SCRIPT_DIR/options.yaml" --gateway-api-version "$GATEWAY_API_VERSION" "${flags[@]}" \
    | tee "$OUT_DIR/summary.txt"
}

main() {
  require docker kind kubectl helm cloud-provider-kind go python3
  create_cluster
  install_crds
  load_image
  start_cloud_provider_kind
  install_chart
  SUITE_STATUS=0
  run_suite
  if ((SUITE_STATUS != 0)); then
    collect_diagnostics
  fi
  check_report
  if ((SUITE_STATUS != 0)); then
    if [[ "$RDOCK_ALLOW_PARTIAL" == 1 ]]; then
      echo "warning: go test exited with status $SUITE_STATUS; tolerated because RDOCK_ALLOW_PARTIAL=1" >&2
    else
      die "go test exited with status $SUITE_STATUS"
    fi
  fi
}

main "$@"
