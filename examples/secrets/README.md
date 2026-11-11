# A rendered secret file outside Kubernetes

An OpenBao Agent logs in with AppRole, renders `secret/data/rdock/backend` (KV v2) to a file in a
shared volume, and ReverseDock refers to that file with `${file:/run/rendered/backend-key}`.

> **NOT exercised by CI.** Written from the documentation checked on 2026-11-11 and checked only
> for YAML well-formedness. The server, the AppRole and its policy, and the secret are yours.
> The image tag `openbao/openbao:2.7.2` exists on Docker Hub; that the image's entrypoint runs
> `bao agent` as written has not been tried.

| File | Purpose |
|---|---|
| [compose.yaml](compose.yaml) | The agent and ReverseDock sharing the `rendered` volume. |
| [agent.hcl](agent.hcl) | `vault`, `auto_auth` (AppRole), `template_config` and one `template`. |
| [backend-key.ctmpl](backend-key.ctmpl) | The template: the `api_key` field of the KV v2 secret. |
| [config/rdock.yaml](config/rdock.yaml) | A route whose middleware sends the key to the backend. |

The agent re-renders non-leased secrets such as KV v2 every `static_secret_render_interval`
(default 5 minutes), so the file changes soon after the secret does. ReverseDock does not watch
files read through `${file:…}`: run `docker compose exec rdock rdock reload` after a rotation.

Vault works the same way with `vault agent`; Vault is under the Business Source License and OpenBao
under MPL-2.0 (see the research note, section 5).

Sources, checked 2026-11-11: [OpenBao Agent template](https://openbao.org/docs/agent-and-proxy/agent/template/),
[Vault Agent template](https://developer.hashicorp.com/vault/docs/agent-and-proxy/agent/template),
[AppRole auto-auth](https://developer.hashicorp.com/vault/docs/agent-and-proxy/autoauth/methods/approle).
