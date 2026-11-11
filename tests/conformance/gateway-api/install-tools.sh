#!/usr/bin/env bash
# Install the pinned command-line tools the Kubernetes CI jobs and run.sh need, into one
# directory, each verified against a SHA-256 taken from the project's own release (checked
# 2026-11-11). Linux x86-64 only: that is what the GitHub runners are. On any other machine
# install the tools with your package manager at the versions below (README.md).
#
#   install-tools.sh [tool ...]     tools: kind kubectl helm helm3 kubeconform cloud-provider-kind
#                                   (no argument installs all of them)
#
# TOOLS_DIR (default ~/.rdock-tools/bin) is where they go. In GitHub Actions the directory is
# also appended to $GITHUB_PATH. `helm` is Helm 4 and `helm3` is Helm 3: the chart must lint
# and render with both (ADR-0029).
set -euo pipefail

KIND_VERSION=0.33.0
KIND_SHA256=aee6151561422756b764a4ae28e7f44cda5af5a9eead3cc9985112b1de8d8e0d
KUBECTL_VERSION=1.37.2
KUBECTL_SHA256=c04487523e7aa7d1493f7808174c899db93d7a9cf57531420cd76b9bd415f8f4
HELM_VERSION=4.3.1
HELM_SHA256=0403a88ae20913d11b10a2467b50087721fea7581736da6b9d3992f5357fe54b
HELM3_VERSION=3.22.1
HELM3_SHA256=896cf63684a42a723d61c980369d6e588330927deb13676ca0d85006dd6da0ea
KUBECONFORM_VERSION=0.8.0
KUBECONFORM_SHA256=9bc2bffbf71f261128533edaf912153948b7ff238f9a531ae6d34466ec287883
CLOUD_PROVIDER_KIND_VERSION=0.12.0
CLOUD_PROVIDER_KIND_SHA256=5716aca8f01a85172c12f3b6329c70f151bec02c91b6f600c9f230845ee138e6

TOOLS_DIR=${TOOLS_DIR:-$HOME/.rdock-tools/bin}

if [[ "$(uname -s)-$(uname -m)" != "Linux-x86_64" ]]; then
  echo "install-tools.sh supports Linux x86-64 only; install these versions yourself: kind ${KIND_VERSION}, kubectl ${KUBECTL_VERSION}, helm ${HELM_VERSION} (and ${HELM3_VERSION}), kubeconform ${KUBECONFORM_VERSION}, cloud-provider-kind ${CLOUD_PROVIDER_KIND_VERSION}" >&2
  exit 1
fi

mkdir -p "$TOOLS_DIR"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# download URL SHA256 FILE: fetch and verify before anything is extracted or executed.
download() {
  local url=$1 sha=$2 file=$3
  curl --silent --show-error --fail --location --retry 3 --output "$file" "$url"
  echo "${sha}  ${file}" | sha256sum --check --quiet -
}

# install_binary NAME URL SHA256: a single static binary.
install_binary() {
  local name=$1 url=$2 sha=$3
  download "$url" "$sha" "$work/$name"
  install -m 0755 "$work/$name" "$TOOLS_DIR/$name"
}

# install_tarball NAME URL SHA256 MEMBER: one file of a .tar.gz, installed as NAME.
install_tarball() {
  local name=$1 url=$2 sha=$3 member=$4
  download "$url" "$sha" "$work/$name.tar.gz"
  tar --extract --gzip --file "$work/$name.tar.gz" --directory "$work" "$member"
  install -m 0755 "$work/$member" "$TOOLS_DIR/$name"
}

install_tool() {
  case $1 in
    kind)
      install_binary kind "https://github.com/kubernetes-sigs/kind/releases/download/v${KIND_VERSION}/kind-linux-amd64" "$KIND_SHA256" ;;
    kubectl)
      install_binary kubectl "https://dl.k8s.io/release/v${KUBECTL_VERSION}/bin/linux/amd64/kubectl" "$KUBECTL_SHA256" ;;
    helm)
      install_tarball helm "https://get.helm.sh/helm-v${HELM_VERSION}-linux-amd64.tar.gz" "$HELM_SHA256" linux-amd64/helm ;;
    helm3)
      install_tarball helm3 "https://get.helm.sh/helm-v${HELM3_VERSION}-linux-amd64.tar.gz" "$HELM3_SHA256" linux-amd64/helm ;;
    kubeconform)
      install_tarball kubeconform "https://github.com/yannh/kubeconform/releases/download/v${KUBECONFORM_VERSION}/kubeconform-linux-amd64.tar.gz" "$KUBECONFORM_SHA256" kubeconform ;;
    cloud-provider-kind)
      install_tarball cloud-provider-kind "https://github.com/kubernetes-sigs/cloud-provider-kind/releases/download/v${CLOUD_PROVIDER_KIND_VERSION}/cloud-provider-kind_${CLOUD_PROVIDER_KIND_VERSION}_linux_amd64.tar.gz" "$CLOUD_PROVIDER_KIND_SHA256" cloud-provider-kind ;;
    *)
      echo "unknown tool: $1 (kind kubectl helm helm3 kubeconform cloud-provider-kind)" >&2
      exit 2 ;;
  esac
  echo "installed $1 in $TOOLS_DIR"
}

if [[ $# -eq 0 ]]; then
  set -- kind kubectl helm helm3 kubeconform cloud-provider-kind
fi
for tool in "$@"; do
  install_tool "$tool"
done

if [[ -n "${GITHUB_PATH:-}" ]]; then
  echo "$TOOLS_DIR" >> "$GITHUB_PATH"
fi
