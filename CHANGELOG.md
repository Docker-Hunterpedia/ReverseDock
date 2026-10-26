# Changelog

All notable changes to ReverseDock are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/). From M0 onward this file is generated from Conventional Commits with git-cliff.

## [Unreleased]

## [0.1.0-alpha.2] — first published pre-release

### Fixed
- Release workflow: in the checksum step, ` #` inside a plain YAML scalar started a comment and cut the shell command short, so `v0.1.0-alpha.1` was tagged but never published. Checksums and the SBOM are now produced on every pull request that touches the build, and only the publish job (tags) holds write permissions.

### Added
- `actionlint` with shellcheck in the required `docs` check and in `just ci`.

## [0.1.0-alpha.1] — M0 foundations (tagged, not published)

### Added
- Cargo workspace with all crates of the architecture; skeleton crates document their milestone.
- `rdock-rules`: Traefik v3 compatible rule parser (HTTP and TCP matchers, `!`, `&&`, `||`, parentheses, backtick and double-quoted strings), validation, canonical printing and property tests.
- `rdock-model`: configuration types for listeners, routes, services, middlewares, TCP, certificates, ACME, providers, security, admin and observability; typed values (durations, sizes, addresses, networks); semantic validation with paths and hints; JSON Schema (`schema/rdock.v1.json`).
- `rdock-config`: YAML (serde-saphyr, YAML 1.2 booleans) and JSON loading, unknown-key warnings with suggestions, `--strict` mode.
- `rdock validate`, `rdock schema`, `rdock version`.
- CI: rust (fmt, clippy pedantic, nextest, doc), msrv (1.89), cargo-deny, Docker build, Semgrep; release workflow with signed checksums, SBOM and provenance; static non-root Dockerfile.
- ADR-0011 (YAML parser and MSRV).

### Earlier
- Design plan: vision, verified research, feature-parity matrix, requirements, architecture, roadmap, Harbor UI design system, ADR-0001…0010.
- Repository governance: contributing guide, code of conduct, security policy, support and governance docs, issue forms, PR template, CODEOWNERS, docs/DCO/PR-title CI checks, protected `main` and release tags.
