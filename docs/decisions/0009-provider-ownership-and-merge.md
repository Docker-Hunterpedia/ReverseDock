# ADR-0009: Provider-namespaced ownership and deterministic merge

- Status: accepted · Date: 2026-10-26

## Context
File, Docker, Swarm, Kubernetes and the API can all define routes. Without explicit ownership, one source silently overwrites another and operators cannot tell where a route came from.

## Decision
Every object is owned by exactly one provider and named `name@provider`. Providers emit complete snapshots; a snapshot that fails validation keeps that provider's previous valid snapshot and marks it degraded; other providers still apply. Overlapping routes resolve by `priority → rule length → provider order (file > api > kubernetes > swarm > docker) → name`, with losers flagged *shadowed*. Secrets cannot be expressed in labels. The API provider is the only one the dashboard can mutate.

## Consequences
- The UI shows an owner badge and read-only views for non-API objects.
- Conflicts are diagnostics with deep links, never silent.
- GitOps mode is simply "file wins"; nothing special is needed.
