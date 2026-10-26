# ADR-0008: Listener-set changes need a restart until the supervisor model lands

- Status: accepted (supersedes the first draft that used in-process self-upgrade) · Date: 2026-10-26

## Context
Pingora binds listeners when services start; there is no public API to add or remove listening sockets at runtime. Pingora's zero-downtime path is a *process upgrade*: a new process inherits the listening fds over an upgrade socket and the old one drains. That works under a supervisor that starts the new process, but not when `rdock` itself is PID 1 in a container (or tini's only child): when the old process exits, the container exits. The admin listener (ADR-0007) is also outside Pingora's fd transfer, so a child would collide with the parent on `127.0.0.1:2080`.

## Decision
- Route, service, middleware, certificate, limit and provider changes hot-swap in memory (`ArcSwap`) with no restart.
- A change to the **listener set** (ports, protocols, TLS-vs-plain, PROXY protocol) is applied to the desired state and persisted, but the running process keeps its current listeners and marks the generation `restart required` (CLI `rdock status`, API, dashboard banner, `rdock_restart_required` metric). Validation rejects a listener whose port is already in use before anything is applied.
- With `--restart-on-listener-change` (set in the official image and systemd unit), the process drains and exits with code 3 so the supervisor (Docker restart policy, systemd, Kubernetes) brings it back on the new listeners. Downtime is the restart time; existing connections get the drain window.
- Zero-downtime listener changes come with the v0.9 supervisor/worker model (H-PERF-04): a small parent that owns the admin and upgrade sockets and re-execs workers over Pingora's fd transfer.

## Consequences
- Honest behaviour on every platform; nothing silently fails under PID 1.
- The dashboard explains "requires restart" before applying such a change; most deployments never change listeners after setup (`:80`/`:443`).
- `rdock validate` reports listener diffs so GitOps pipelines can plan a restart.
