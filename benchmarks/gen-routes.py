"""Writes the `routes` scenario's configurations: COUNT hosts, each its own route to one backend.

    python3 -I gen-routes.py configs/routes 1000
"""
import pathlib
import sys

out, count = pathlib.Path(sys.argv[1]), int(sys.argv[2])
out.mkdir(parents=True, exist_ok=True)
hosts = [f"site{i}.test" for i in range(count)]

routes = "\n".join(f'  r{i}: {{ match: "Host(`{h}`)", service: app }}' for i, h in enumerate(hosts))
(out / "rdock.yaml").write_text(f"""listeners:
  web: {{ address: ":8080" }}
defaults: {{ listeners: [web], tls: off }}
routes:
{routes}
services:
  app:
    backends: [{{ address: "backend:80" }}]
observability:
  access_log: {{ format: off }}
admin: {{ enabled: false }}
""")

servers = "\n".join(
    f"  server {{ listen 8080; server_name {h}; location / {{ proxy_pass http://backend; proxy_http_version 1.1; "
    'proxy_set_header Connection ""; proxy_set_header Host $host; } }'
    for h in hosts
)
(out / "nginx.conf").write_text(f"""worker_processes 2;
events {{ worker_connections 8192; }}
http {{
  access_log off;
  server_names_hash_bucket_size 64;
  server_names_hash_max_size 4096;
  upstream backend {{ server backend:80; keepalive 256; }}
{servers}
}}
""")

# Plain ACLs, evaluated in order: the way a hand-written HAProxy configuration routes hosts.
rules = "\n".join(f"  use_backend app if {{ hdr(host) -i {h} }}" for h in hosts)
(out / "haproxy.cfg").write_text(f"""global
  nbthread 2
  maxconn 20000
defaults
  mode http
  timeout connect 5s
  timeout client 60s
  timeout server 60s
  option http-keep-alive
  http-reuse always
frontend web
  bind :8080
{rules}
backend app
  server backend backend:80
""")

sites = "\n".join(f"http://{h}:8080 {{\n  reverse_proxy backend:80\n}}" for h in hosts)
(out / "Caddyfile").write_text(f"{{\n  auto_https off\n  admin off\n}}\n{sites}\n")

routers = "\n".join(f'    r{i}: {{ rule: "Host(`{h}`)", service: app, entryPoints: [web] }}' for i, h in enumerate(hosts))
(out / "traefik-dynamic.yml").write_text(f"""http:
  routers:
{routers}
  services:
    app:
      loadBalancer:
        servers: [{{ url: "http://backend:80" }}]
""")
