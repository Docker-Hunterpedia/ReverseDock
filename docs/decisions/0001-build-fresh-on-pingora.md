# ADR-0001: Build fresh on Pingora 0.9 instead of forking Pingap

- Status: accepted · Date: 2026-10-26

## Context
Pingap (Apache-2.0) already offers a UI, ACME, plugins and Docker-label discovery on Pingora. Forking would give a faster first demo. But Pingap's model is NGINX-like (`servers → locations → upstreams`, TOML/HCL/KDL), has no provider abstraction, no Traefik-label compatibility, no Swarm/Kubernetes, no L4 and no HTTP/3 plan. ReverseDock's core promise is a unified provider engine with Traefik-compatible semantics.

## Decision
Start a new workspace on Pingora 0.9. Study and credit Pingap (UI-in-binary, dry-run diff, 15-minute traffic view) and Zentinel (agent isolation, status-code retries) where useful.

## Consequences
- Slower first demo; we own routing, config, TLS, ACME from day one.
- Freedom to design the model as a Traefik superset (ADR-0003) and to keep providers first-class.
- Pingora API churn is absorbed by a thin adapter in `rdock-proxy`; one upgrade PR per Pingora release.
