# Developer recipes. `just` lists them; `just ci` runs what the required CI checks run.

set shell := ["bash", "-euo", "pipefail", "-c"]

msrv := "1.89"

default:
    @just --list

# Everything the Rust and docs CI jobs check
ci: fmt-check clippy test doc deny docs-check compat-test lint-workflows

# Format all crates
fmt:
    cargo fmt --all

# Fail if formatting is needed
fmt-check:
    cargo fmt --all -- --check

# Lint with warnings as errors (pedantic set, see Cargo.toml)
clippy:
    cargo clippy --workspace --all-targets --locked -- -D warnings

# Unit, integration, property and doc tests
test:
    cargo nextest run --workspace --locked
    cargo test --workspace --doc --locked

# Build the API docs with warnings as errors
doc:
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked

# Licenses, advisories, bans, sources
deny:
    cargo deny check

# Links, generated feature matrix, GitHub YAML
docs-check:
    python3 -I scripts/check-docs.py

# Lint GitHub workflows, including their shell scripts (needs actionlint and shellcheck)
lint-workflows:
    actionlint

# Regenerate schema/rdock.v1.json and schema/openapi.json after changing rdock-model or the admin API
schema:
    cargo run --quiet --locked -p rdock -- schema > schema/rdock.v1.json
    cargo run --quiet --locked -p rdock -- schema --openapi > schema/openapi.json

# Regenerate schema/compat/ (ADR-0033) after changing metrics, the CLI, JSON outputs, the access log, problem types, RDOCK_* variables, labels or the image
compat:
    for s in metrics cli access-log problems env deprecations; do cargo run --quiet --locked -p rdock -- schema --compat "$s" > "schema/compat/$s.json"; done
    RDOCK_UPDATE_GOLDEN=1 cargo test --quiet --locked -p rdock-provider-docker --test conformance label_snapshot_is_current
    python3 -I scripts/compat.py snapshot image > schema/compat/image.json

# The compatibility gate against the last release tag (needs `git fetch --tags`; report mode before 1.0.0-rc.1, RDOCK_COMPAT_MODE forces one)
compat-check:
    cargo build --quiet --locked -p rdock
    python3 -I scripts/compat.py check --rdock target/debug/rdock

# The gate's own tests (standard library only)
compat-test:
    python3 -I scripts/test_compat.py

# Regenerate the TypeScript types (apps/dashboard/src/api) and the Go client (clients/go) from schema/openapi.json
clients:
    pnpm --dir apps/dashboard gen:api
    cd clients/go && go generate ./...

# Check the minimum supported Rust version
msrv:
    rustup toolchain install {{msrv}} --profile minimal
    cargo +{{msrv}} check --workspace --all-targets --locked

# WASM plugins (experimental, cargo feature `wasm`, ADR-0030): clippy with the feature, the
# example guest, the WASM tests, and the MSRV check with the feature. Not part of `ci`.
wasm:
    rustup target add wasm32-wasip2
    cargo clippy --workspace --all-targets --locked --features rdock/wasm,rdock-wasm/testing -- -D warnings
    cd examples/plugins/wasm-header && cargo fmt --check && cargo clippy --locked --release --target wasm32-wasip2 -- -D warnings
    cargo test --locked -p rdock-wasm --features wasm,testing
    cargo test --locked -p rdock-middleware --features wasm wasm::
    cargo test --locked -p rdock-proxy --features wasm --lib gate::
    cargo test --locked -p rdock --features wasm --test e2e_wasm --test cli
    rustup toolchain install {{msrv}} --profile minimal
    cargo +{{msrv}} check -p rdock -p rdock-wasm --all-targets --locked --features rdock/wasm,rdock-wasm/testing

# HTTP/3 ingress (experimental, cargo feature `http3`, ADR-0032): clippy with the feature, the
# HTTP/3 unit and end-to-end tests, and the MSRV check with the feature. Not part of `ci`.
# `scripts/http3-curl.sh` (Docker) adds curl over HTTP/3 against a running rdock.
http3:
    cargo clippy --workspace --all-targets --locked --features rdock/http3 -- -D warnings
    cargo test --locked -p rdock-proxy --features http3 --lib
    cargo test --locked -p rdock-model --lib http3
    cargo test --locked -p rdock --features http3 --test e2e_http3 --test cli
    rustup toolchain install {{msrv}} --profile minimal
    cargo +{{msrv}} check --workspace --all-targets --locked --features rdock/http3

# Validate configuration files, e.g. `just validate examples/config/rdock.full.yaml`
validate +files:
    cargo run --quiet --locked -p rdock -- validate {{files}}

# Build the container image
docker tag="rdock:dev":
    docker build --tag {{tag}} .
    docker run --rm {{tag}} version

# Build the image with symbols and frame pointers for perf (benchmarks/README.md, "Profiling")
docker-profiling tag="rdock:profiling":
    docker build --tag {{tag}} --build-arg CARGO_PROFILE=profiling --build-arg RUSTFLAGS="-C force-frame-pointers=yes" .

# Rebuild the Graphify code graph (optional tool, see docs/06-repo-layout.md)
graph:
    graphify update .

# Website: dev server at http://localhost:4321 (apps/website)
website:
    pnpm install
    cargo build -p rdock
    pnpm --filter @reversedock/website dev

# Website: everything the `website` CI job checks
website-check:
    pnpm install --frozen-lockfile
    cargo build --locked -p rdock
    cd apps/website && pnpm gen && git diff --exit-code -- src/content/docs
    cd apps/website && pnpm check:status && pnpm check:snippets && pnpm check && pnpm build && pnpm check:a11y && pnpm check:playground

# Helm chart: lint, render every value set through kubeconform, raw manifests in sync, kustomize (needs helm, kubectl, kubeconform; `just ci` does not run it)
chart:
    helm lint --strict deploy/helm/reversedock
    for v in deploy/helm/reversedock/ci/*.yaml; do helm lint --strict deploy/helm/reversedock --values "$v"; done
    helm template reversedock deploy/helm/reversedock --namespace reversedock-system --kube-version 1.37.2 | kubeconform -strict -summary -ignore-missing-schemas -kubernetes-version 1.37.2 -
    for v in deploy/helm/reversedock/ci/*.yaml; do helm template reversedock deploy/helm/reversedock --namespace reversedock-system --kube-version 1.37.2 --values "$v" | kubeconform -strict -summary -ignore-missing-schemas -kubernetes-version 1.37.2 -; done
    scripts/render-kubernetes-manifests.sh --check
    kubectl kustomize deploy/kubernetes | kubeconform -strict -summary -ignore-missing-schemas -kubernetes-version 1.37.2 -

# Re-render deploy/kubernetes/install.yaml from the chart after changing it
k8s-manifests:
    scripts/render-kubernetes-manifests.sh

# Gateway API conformance suite on a local kind cluster (needs Docker, kind, kubectl, helm, cloud-provider-kind, Go; builds nothing: `just docker rdock:ci` first), e.g. `just conformance rdock:dev`
conformance image="rdock:ci":
    RDOCK_IMAGE={{image}} tests/conformance/gateway-api/run.sh
