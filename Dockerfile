# syntax=docker/dockerfile:1
#
# Static, non-root ReverseDock image (M0 skeleton: `rdock validate`, `schema`, `version`).
# Build:  docker build -t rdock:dev .
# Run:    docker run --rm -v "$PWD/rdock.yaml:/etc/rdock/rdock.yaml:ro" rdock:dev validate /etc/rdock/rdock.yaml

ARG RUST_VERSION=1.99.1

FROM rust:${RUST_VERSION}-alpine AS build
# Use the image's toolchain and skip the rustfmt/clippy components listed in rust-toolchain.toml.
ARG RUST_VERSION
ENV RUSTUP_TOOLCHAIN=${RUST_VERSION}
ARG RDOCK_BUILD_COMMIT=docker
ENV RDOCK_BUILD_COMMIT=${RDOCK_BUILD_COMMIT}
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p rdock \
 && install -D -m 0755 target/release/rdock /out/rdock

FROM gcr.io/distroless/static-debian13:nonroot
LABEL org.opencontainers.image.title="ReverseDock" \
      org.opencontainers.image.description="Open-source reverse proxy on Cloudflare Pingora" \
      org.opencontainers.image.source="https://github.com/Docker-Hunterpedia/ReverseDock" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /out/rdock /usr/local/bin/rdock
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/rdock"]
CMD ["version"]
