# Developer recipes. `just` lists them; `just ci` runs what the required CI checks run.

set shell := ["bash", "-euo", "pipefail", "-c"]

msrv := "1.89"

default:
    @just --list

# Everything the Rust and docs CI jobs check
ci: fmt-check clippy test doc deny docs-check lint-workflows

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

# Regenerate the TypeScript types (apps/dashboard/src/api) and the Go client (clients/go) from schema/openapi.json
clients:
    pnpm --dir apps/dashboard gen:api
    cd clients/go && go generate ./...

# Check the minimum supported Rust version
msrv:
    rustup toolchain install {{msrv}} --profile minimal
    cargo +{{msrv}} check --workspace --all-targets --locked

# Validate configuration files, e.g. `just validate examples/config/rdock.full.yaml`
validate +files:
    cargo run --quiet --locked -p rdock -- validate {{files}}

# Build the container image
docker tag="rdock:dev":
    docker build --tag {{tag}} .
    docker run --rm {{tag}} version

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
