# rdock-migrate

Migration assistants (F-MGMT-03): `rdock migrate traefik` turns Traefik labels in a Docker Compose file, or a Traefik dynamic configuration (file provider), into an `rdock.yaml` fragment.

- Labels go through the Docker provider's own translator (`rdock-provider-docker::labels`), so the result is what the Docker provider would build from the same labels. Compose service names become backend hosts; a service without `expose`, `ports` or a port label gets port 80, with a note.
- A dynamic configuration is flattened into the same label form; every `loadBalancer.servers` URL becomes a backend. `tcp`, `udp` and `tls` sections are noted, not migrated.
- The output leaves out settings equal to their defaults and starts with a comment listing everything that was not migrated, and why.

An NGINX directive subset is planned later (P3).
