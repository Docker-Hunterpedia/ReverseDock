# rdock-provider-swarm

Docker Swarm provider (W-SWM-01…03, ADR-0026):
the running tasks of each service become the Docker translator's containers, with the
service's `deploy.labels`, so native `rdock.*` labels and the Traefik subset work as they do
for containers.

- `convert`: services, tasks and networks into translator input (pure; tested from recorded
  Engine API JSON in `tests/fixtures`).
- `tasks`: our own `GET /tasks` client, because bollard 0.21.1 has no `NetworksAttachments`.
- `watch`: the loop. Swarm sends no task events, so services and tasks are listed every
  `providers.swarm.poll_interval` (5 s), and at once on `service`, `node`, `network`,
  `secret` and `config` events. The last snapshot stays in service while the manager is
  unreachable.

Only read calls are made; a socket proxy with `SERVICES`, `TASKS`, `NETWORKS`, `NODES`,
`EVENTS` and `CONTAINERS` read access on a manager is enough.
