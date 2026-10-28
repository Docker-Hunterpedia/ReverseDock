# Docker provider examples

Each directory is a complete Compose project; `config/` is mounted at `/etc/rdock`. CI validates every `config/rdock.yaml` with `rdock validate --strict` and every `compose.yaml` with `docker compose config`.

| Directory | Shows |
|---|---|
| [`labels/`](labels/) | Routes from `rdock.*` and `traefik.*` labels, with read access through the socket's group |
| [`socket-proxy/`](socket-proxy/) | The same through a read-only socket proxy on an internal network (recommended) |
| [`https/`](https/) | Automatic HTTPS for a labelled container, starting on Let's Encrypt staging |
| [`cloudflare-tunnel/`](cloudflare-tunnel/) | Behind a Cloudflare Tunnel with a `cloudflared` sidecar and no inbound ports |

Guides: [Docker containers and labels](https://github.com/Docker-Hunterpedia/ReverseDock/blob/main/apps/website/src/content/docs/docs/guides/docker-labels.mdx), [Docker socket access](https://github.com/Docker-Hunterpedia/ReverseDock/blob/main/apps/website/src/content/docs/docs/guides/docker-socket.mdx), [Automatic HTTPS](https://github.com/Docker-Hunterpedia/ReverseDock/blob/main/apps/website/src/content/docs/docs/guides/automatic-https.mdx), [Behind Cloudflare](https://github.com/Docker-Hunterpedia/ReverseDock/blob/main/apps/website/src/content/docs/docs/guides/cloudflare.mdx) and [Dokploy, Coolify and Portainer](https://github.com/Docker-Hunterpedia/ReverseDock/blob/main/apps/website/src/content/docs/docs/guides/platforms.mdx).

The image tag `0.2.0-alpha.1` is the first build with the Docker provider, `0.3.0-alpha.1` the first with automatic HTTPS.
