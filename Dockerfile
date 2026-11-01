# syntax=docker/dockerfile:1
#
# ReverseDock built from source: a static, non-root image.
#   docker build -t rdock:dev .
#   docker run -d -p 80:80 -v "$PWD/rdock.yaml:/etc/rdock/rdock.yaml:ro" -v rdock-data:/var/lib/rdock rdock:dev
# Release images are built from the signed release binaries instead (Dockerfile.release).

ARG RUST_VERSION=1.99.1
ARG NODE_VERSION=24.18.0

# The dashboard (apps/dashboard), embedded into the binary at build time (ADR-0024).
FROM node:${NODE_VERSION}-alpine AS dashboard
WORKDIR /src
RUN corepack enable
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml ./
COPY packages packages
COPY apps/dashboard apps/dashboard
# The configuration editor imports the JSON Schema.
COPY schema schema
COPY apps/website/package.json apps/website/package.json
RUN pnpm install --frozen-lockfile --filter @reversedock/dashboard... \
 && pnpm --dir apps/dashboard build

FROM rust:${RUST_VERSION}-alpine AS build
# Use the image's toolchain and skip the rustfmt/clippy components listed in rust-toolchain.toml.
ARG RUST_VERSION
ENV RUSTUP_TOOLCHAIN=${RUST_VERSION}
ARG RDOCK_BUILD_COMMIT=docker
ENV RDOCK_BUILD_COMMIT=${RDOCK_BUILD_COMMIT}
# Extra Cargo features; only the isolation test sets one (fault-injection, benchmarks/isolation).
ARG CARGO_FEATURES=
# Pingora builds zlib-ng with CMake; ring and zstd need a C compiler.
RUN apk add --no-cache musl-dev cmake make
WORKDIR /src
COPY . .
COPY --from=dashboard /src/apps/dashboard/dist apps/dashboard/dist
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p rdock --features "${CARGO_FEATURES}" \
 && install -D -m 0755 target/release/rdock /out/rdock \
 && mkdir -p /out/data

FROM gcr.io/distroless/static-debian13:nonroot
LABEL org.opencontainers.image.title="ReverseDock" \
      org.opencontainers.image.description="Open-source reverse proxy on Cloudflare Pingora" \
      org.opencontainers.image.source="https://github.com/Docker-Hunterpedia/ReverseDock" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /out/rdock /usr/local/bin/rdock
COPY --from=build --chown=65532:65532 /out/data /var/lib/rdock
USER nonroot:nonroot
EXPOSE 80 443
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
  CMD ["/usr/local/bin/rdock", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/rdock"]
CMD ["run"]
