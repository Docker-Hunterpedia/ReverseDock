# WAF example: OWASP CRS as an rdock agent

A [Compose file](compose.yaml) that puts a CRS web application firewall in front of a demo application, with rdock asking the WAF about every request through an `agent` middleware with `protocol: forward` (F-EXT-04, [ADR-0030](../../docs/decisions/0030-v0-8-cache-extensibility-gateway.md)).

```
client ──▶ rdock ──(1) the request, replayed──▶ waf (ModSecurity + CRS) ──▶ waf-sink (answers 200)
             │                                   2xx = allow, 403 = blocked
             └──(2) the original request, if allowed──▶ app
```

- **waf**: `owasp/modsecurity-crs:4.30.0-nginx-alpine-202611090911`, the CRS project's reverse-proxy image (ModSecurity v3.0.17 on nginx 1.30.6 with CRS 4.30.0), pinned by digest `sha256:b8d5bbf8…1bdc`, the tag's digest on Docker Hub, checked on 2026-11-12 and pulled with that digest. CRS defaults: blocking at paranoia level 1, inbound anomaly threshold 5.
- **waf-sink**: what the WAF forwards allowed requests to. The WAF is itself a reverse proxy; here its only job is to answer, so rdock reads its 2xx as "allow".
- **app**: the demo application (`traefik/whoami`, pinned by digest).
- **rdock**: [rdock.yaml](rdock.yaml); `max_body: 128KiB`, `on_error: deny`, cookies and credentials sent to the WAF (they are not by default).

## Run it

```sh
docker build -t rdock:ci ../..       # or set RDOCK_IMAGE to an rdock image you have
./smoke.sh                           # starts everything, checks it, stops it
```

[`smoke.sh`](smoke.sh) checks that a clean request gets `200` from the application, that a path traversal and an SQL injection in the query and a cross-site scripting payload in a form body get `403` from the WAF, that a clean form post passes, and that with the WAF container stopped requests are refused (`502` when the WAF refuses connections, `504` when it does not answer within `timeout`, `503` while the breaker is open). CI runs it in the `waf-example` job.

## What this does and does not do

- The request is evaluated by the WAF first, then rdock proxies the **original** request to the application. The WAF never talks to the application.
- Request bodies up to `max_body` are inspected; a longer body with a declared length is refused with `413` (`on_oversize: reject`). `on_oversize: skip` would send such requests to the WAF without their body, uninspected.
- **Limitation:** for a request with a body, the verdict comes after rdock has connected to the application and sent it the request head (Pingora 0.9.1 reads the body only once the upstream request has started); the body is withheld until the WAF has answered, and a refusal closes that connection. A request without a body is decided before rdock connects to the application at all.
- **Responses are not inspected** (the agent sees requests only), so CRS's response rules (data leakage) do not apply.
- The WAF parses the request rdock sends, which is the normalised request rdock received: method, path, query, the allowed headers and the body.
- The WAF's traffic is plain HTTP on the Compose network; `rdock validate` warns about it. Use `https://` with `tls` settings when the WAF runs on another host.
- One WAF container is a single point of failure; with `on_error: deny` its outage refuses traffic. Run several replicas behind a name, or choose `on_error: allow` knowingly.

Guide: [Agents](../../apps/website/src/content/docs/guides/agents.mdx).
