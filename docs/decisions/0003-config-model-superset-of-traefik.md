# ADR-0003: Internal model is a superset of Traefik's dynamic configuration

- Status: accepted · Date: 2026-10-26

## Context
Traefik-label compatibility is a P0 differentiator. Kubernetes Gateway API routes and Caddy-style structured matches must map to the same engine. If the internal model differs structurally from Traefik's (entrypoints → routers → services → middlewares), label compatibility becomes a lossy reinterpretation.

## Decision
`rdock-model` uses `listeners`, `routes`, `services`, `middlewares` (+ `tcp_routes`/`tcp_services`, `certificates`, `acme`, `providers`, `security`, `admin`, `observability`) with Traefik's rule grammar as one accepted form of `match` and a structured form as the other. YAML is the human format, JSON the canonical one; a JSON Schema is generated from the Rust types and committed.

## Consequences
- Traefik labels and dynamic YAML translate 1:1 for the supported subset; unsupported semantics are diagnostics, never silent.
- Structured matches (Kubernetes `HTTPRoute`, UI forms) compile into the same AST.
- Config is strongly typed; unknown keys are warnings by default and errors with `--strict`.
