// Content of the landing page. Statuses follow docs/07-roadmap.md; `kind` picks the badge colour.
import release from './release.json';

type Kind = 'shipped' | 'next' | 'planned';
const image = `${release.image}:${release.version}`;
const archive = `rdock-${release.version}-x86_64-unknown-linux-musl`;

export const pillars: { eyebrow: string; badge: string; kind: Kind; title: string; body: string }[] = [
  { eyebrow: 'Engine', badge: 'shipped', kind: 'shipped', title: 'Rust on Pingora', body: 'The HTTP engine Cloudflare runs at its edge, with our own listeners on top. HTTP/1.1, HTTP/2, h2c, WebSocket, SSE and gRPC.' },
  { eyebrow: 'Operations', badge: 'shipped', kind: 'shipped', title: 'Reloads that drop nothing', body: 'Edit the file, send SIGHUP or call the API. A broken config is refused and the last good one keeps serving.' },
  { eyebrow: 'Docker', badge: 'shipped', kind: 'shipped', title: 'Labels on your containers', body: 'Route containers from rdock.* labels, with the common Traefik labels understood as they are.' },
  { eyebrow: 'TLS', badge: 'shipped', kind: 'shipped', title: 'Automatic HTTPS', body: "Certificates from Let's Encrypt, renewed on schedule, including wildcards through DNS-01." },
];

export const guides: { title: string; badge: string; kind: Kind; body: string; href: string }[] = [
  { title: 'From Traefik', badge: 'guide', kind: 'shipped', body: 'Rules carry over; routers and services map one to one.', href: '/docs/migrate/from-traefik/' },
  { title: 'From NGINX', badge: 'guide', kind: 'shipped', body: 'server and location blocks to hosts, paths and middlewares.', href: '/docs/migrate/from-nginx/' },
  { title: 'From Caddy', badge: 'planned', kind: 'planned', body: 'Caddyfile sites to routes, automatic HTTPS included.', href: '/docs/project/roadmap/' },
  { title: 'From Nginx Proxy Manager', badge: 'planned', kind: 'planned', body: 'Proxy hosts from the UI to one versioned YAML file.', href: '/docs/project/roadmap/' },
];

export const features: { title: string; status: string; kind: Kind; body: string }[] = [
  { title: 'Traefik v3 rules', status: 'v0.1', kind: 'shipped', body: 'Host, Path, PathPrefix, Headers, Query, Method and ClientIP, with the same priorities.' },
  { title: 'TLS with your certificates', status: 'v0.1', kind: 'shipped', body: 'SNI, wildcards, a default certificate, encrypted keys; swapped on file change.' },
  { title: 'Fifteen middlewares', status: 'v0.1', kind: 'shipped', body: 'Headers, redirects, rewrites, basic and forward auth, IP filters, rate limits, CORS, gzip, error pages, maintenance.' },
  { title: 'Smuggling defenses', status: 'v0.1', kind: 'shipped', body: 'Strict framing, size limits, header deadlines and fuzz-tested parsers.' },
  { title: 'Metrics and access logs', status: 'v0.1', kind: 'shipped', body: 'Prometheus /metrics and JSON access logs with request IDs.' },
  { title: 'Last-known-good', status: 'v0.1', kind: 'shipped', body: 'Config history on disk; a broken file at boot falls back to the last one that worked.' },
  { title: 'Docker labels', status: 'v0.2', kind: 'shipped', body: 'Opt-in per container, network selection, live on container events.' },
  { title: 'rdock migrate traefik', status: 'v0.2', kind: 'shipped', body: 'Turns Traefik labels into rdock.yaml and lists what does not carry over.' },
  { title: 'Automatic HTTPS', status: 'v0.3', kind: 'shipped', body: 'ACME HTTP-01, TLS-ALPN-01 and DNS-01, with ARI renewals.' },
  { title: 'Health checks and retries', status: 'v0.4', kind: 'shipped', body: 'Active and passive checks, consistent hashing, sticky sessions, retry budgets.' },
  { title: 'mTLS, JWT and tracing', status: 'v0.4', kind: 'shipped', body: 'Client certificates, Cloudflare origin pulls, JWT on ring, OpenTelemetry spans.' },
  { title: 'Dashboard', status: 'v0.5', kind: 'next', body: 'Built into the binary: routes, certificates, live logs and metrics.' },
  { title: 'Kubernetes Gateway API', status: 'v0.7', kind: 'planned', body: 'A Gateway API controller, checked with the upstream conformance tests.' },
];

export const compare = [
  { row: 'Written in', rd: 'Rust (Pingora)', traefik: 'Go', caddy: 'Go', nginx: 'C' },
  { row: 'License', rd: 'Apache-2.0', traefik: 'MIT', caddy: 'Apache-2.0', nginx: 'BSD-2-Clause' },
  { row: 'Traefik rule syntax', rd: 'Yes', traefik: 'Yes', caddy: 'No', nginx: 'No' },
  { row: 'Docker labels', rd: 'Yes', traefik: 'Yes', caddy: 'With a plugin', nginx: 'No' },
  { row: 'Automatic HTTPS', rd: 'Yes, ARI-aware', traefik: 'Yes', caddy: 'Yes', nginx: 'With certbot' },
  { row: 'Reload without dropping requests', rd: 'Yes', traefik: 'Yes', caddy: 'Yes', nginx: 'Yes' },
];

export const installs = [
  {
    id: 'docker',
    label: 'Docker',
    note: 'Mount the folder holding rdock.yaml, and a volume for state.',
    code: `docker run -d --name rdock \\\n  -p 80:80 -p 443:443 \\\n  -v "$PWD/config:/etc/rdock:ro" \\\n  -v rdock-data:/var/lib/rdock \\\n  ${image}`,
  },
  {
    id: 'compose',
    label: 'Compose',
    note: 'Read-only root filesystem and a health check included.',
    code: `services:\n  rdock:\n    image: ${image}\n    ports: ["80:80", "443:443"]\n    volumes:\n      - ./config:/etc/rdock:ro\n      - rdock-data:/var/lib/rdock\n    read_only: true\n\nvolumes:\n  rdock-data:`,
  },
  {
    id: 'binary',
    label: 'Linux binary',
    note: 'Static musl builds for x86-64 and ARM64; macOS for development.',
    code: `curl -LO ${release.repo}/releases/download/v${release.version}/${archive}.tar.gz\ntar -xzf ${archive}.tar.gz\nsudo install ${archive}/rdock /usr/local/bin/\nrdock validate /etc/rdock/rdock.yaml`,
  },
  {
    id: 'systemd',
    label: 'systemd',
    note: 'Runs unprivileged with CAP_NET_BIND_SERVICE; reload with systemctl reload.',
    code: 'sudo install -m 0644 deploy/systemd/rdock.service /etc/systemd/system/\nsudo systemctl daemon-reload\nsudo systemctl enable --now rdock\nsudo systemctl reload rdock   # after editing /etc/rdock/rdock.yaml',
  },
];

export const trust = [
  { title: 'Free forever', body: 'Apache-2.0 with a DCO. No open core, no enterprise edition, no account.' },
  { title: 'Signed releases', body: 'Keyless cosign signatures, an SPDX SBOM and build provenance for every archive and image.' },
  { title: 'Fuzzed parsers', body: 'Differential HTTP/1 framing, the rule parser and the config loader run under cargo-fuzz every week.' },
  { title: 'No telemetry', body: 'The binary never phones home. The admin API listens on localhost unless you say otherwise.' },
];
