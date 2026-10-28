# ADR-0021: Routes with `tls: off` attach to the plain-HTTP listeners

- Status: accepted
- Date: 2026-10-28

## Context
A route without `listeners` attaches to `defaults.listeners`. The default is `[websecure]`, and zero-config mode in v0.3 uses it too ([ADR-0020](0020-automatic-https.md)). A route that asks for `tls: off` (in the file, or with the `rdock.tls=off` label) then lands on an HTTPS listener without a certificate request, so no client can ever reach it. Before v0.3 this was hidden: zero-config only had the plain listener `web`, and a file with `tls: off` routes usually listed `web` explicitly. Traefik attaches a router without `entrypoints` to every entry point; we do not copy that, because it would serve every HTTPS route over plain HTTP as well.

## Decision
A route without `listeners` whose TLS mode is `off` (set on the route, or inherited from `defaults.tls`) attaches to every plain-HTTP listener instead of `defaults.listeners`. If there is no plain-HTTP listener, `defaults.listeners` is used as before. Routes with `listeners`, and routes with TLS (`auto`, or detailed TLS settings), are unchanged. The rule lives in one place, `Config::route_listeners`, which the validator and the compiler both use.

## Consequences
- `rdock.tls=off` on a container is served on `:80` in zero-config mode, while other containers get HTTPS on `:443`.
- A file whose `defaults.tls: off` routes relied on `defaults.listeners` naming an HTTPS listener changes behaviour; that configuration could not serve those routes before, so nothing that worked breaks. The changelog says so.
- Explicit `listeners` always win, so anyone can still attach a plain route anywhere.
