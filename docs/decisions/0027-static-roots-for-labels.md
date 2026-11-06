# ADR-0027: Docker labels may serve static files only inside `providers.docker.static_roots`

- Status: accepted
- Date: 2026-11-07

## Context
[ADR-0026](0026-swarm-l4-static.md) adds a `static` middleware and the Docker label shorthand `rdock.static.root`. A label is written by whoever can start a container, which is not necessarily whoever runs ReverseDock. Until now labels could not name files on the proxy's host at all ([ADR-0018](0018-docker-provider-and-merge.md), [ADR-0016](0016-config-references-and-secrets.md): `${…}` is refused in labels), so a container could not read ReverseDock's secrets. A `static` root taken from a label breaks that promise: `rdock.static.root=/` or `=/var/lib/rdock` would serve the proxy's own certificates, ACME account key, admin users and configuration to anyone.

## Decision
- A `static` middleware defined by a Docker (or Swarm) label may only use a root inside one of the directories listed in `providers.docker.static_roots` (for Swarm, `providers.swarm.static_roots`). The list is empty by default, so label-defined static sites are off until the operator names where they may live.
- The check resolves links before comparing (a root that is a symlink to outside the list is refused) and runs when the configuration is compiled; a refused label is reported with its exact name like every other refused label, and the rest of the container's labels still apply.
- `static` middlewares in `rdock.yaml` or through the admin API are not restricted: those are written by the operator.

## Consequences
- Following the design rule (every option, safe by default): the capability exists for every provider, and the unsafe combination (labels naming arbitrary host paths) is refused with a diagnostic instead of silently allowed.
- Operators who want label-defined sites add one line, for example `static_roots: [/srv/www]`, and mount the sites there.
- The Swarm provider (#190) applies the same rule with its own list.
