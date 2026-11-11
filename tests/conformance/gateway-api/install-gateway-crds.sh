#!/usr/bin/env bash
# Install the Gateway API Standard-channel CRDs (and the upstream safe-upgrades
# ValidatingAdmissionPolicy) of the version the conformance suite is pinned to. The chart never
# installs CRDs (ADR-0029); this is the command the docs give users, plus an integrity check.
#
#   install-gateway-crds.sh          uses the current kubectl context (or $KUBECONFIG)
#
# The bundle is over 1 MiB, so it must be applied server-side (client-side apply would exceed
# the annotation size limit).
set -euo pipefail

GATEWAY_API_VERSION=${GATEWAY_API_VERSION:-v1.7.0}
# SHA-256 of standard-install.yaml of v1.7.0, computed 2026-11-11. Set it empty to skip the check
# for another version (then bump the pin together with go.mod and options.yaml).
if [[ "$GATEWAY_API_VERSION" == "v1.7.0" ]]; then
  GATEWAY_API_CRDS_SHA256=${GATEWAY_API_CRDS_SHA256-4e2602c4cbe1afbc394d86f4ac6522e1a5263b01133bba1e40a6d1a549e753a1}
else
  GATEWAY_API_CRDS_SHA256=${GATEWAY_API_CRDS_SHA256-}
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
bundle="$work/standard-install.yaml"

curl --silent --show-error --fail --location --retry 3 --output "$bundle" \
  "https://github.com/kubernetes-sigs/gateway-api/releases/download/${GATEWAY_API_VERSION}/standard-install.yaml"
if [[ -n "$GATEWAY_API_CRDS_SHA256" ]]; then
  echo "${GATEWAY_API_CRDS_SHA256}  ${bundle}" | sha256sum --check --quiet -
fi

kubectl apply --server-side --force-conflicts -f "$bundle"

# The CRDs must be served before anything creates a GatewayClass.
kubectl get crd -o name | grep -F 'gateway.networking.k8s.io' |
  xargs kubectl wait --for=condition=Established --timeout=120s
