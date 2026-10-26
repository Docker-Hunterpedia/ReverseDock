This comparison covers NGINX Open Source, Traefik Proxy OSS, Caddy, HAProxy Community, Envoy, Pingap, and Cloudflare Pingora, with a proposed implementation path for our new open-source reverse proxy.

The goal is to identify exactly what we can reuse from Pingora, what requires custom implementation, and where our project can offer something competitors don't provide together.

## Important findings

Several details materially affect the roadmap:

- Pingora is a framework, not a finished proxy product. HTTP/1.1, HTTP/2, connection pooling, load-balancing primitives, and graceful reloads are available, but we still need to build the configuration and integration layers. Its caching integration is experimental.

  ![](https://www.google.com/s2/favicons?domain=https://github.com&sz=32)

  GitHub

  
- Pingap is a serious starting-point alternative. It already includes Docker discovery, ACME automation, caching, 30+ plugins, a web admin interface, Prometheus, and OpenTelemetry.

  ![](https://www.google.com/s2/favicons?domain=https://pingap.io&sz=32)

  [pingap.io](http://pingap.io)

  +1

  
- NGINX OSS has HTTP/3, but its documented HTTP/3 module is still marked experimental and isn't built by default.

  ![](https://www.google.com/s2/favicons?domain=https://nginx.org&sz=32)

  [nginx.org](http://nginx.org)

  
- HAProxy Community now has experimental native ACME support in versions 3.2 and later. It should not automatically be classified as requiring Certbot.

  ![](https://www.google.com/s2/favicons?domain=https://www.haproxy.com&sz=32)

  HAProxy config tutorials

  
- Traefik Proxy OSS and Traefik Hub are different products. Some functionality, including the documented Hub JWT and distributed rate-limit middleware, is not part of the same open-source feature set.

  ![](https://www.google.com/s2/favicons?domain=https://doc.traefik.io&sz=32)

  Traefik

  +1

  

## Matrix legend


| Code | Interpretation                                                           |
| ---- | ------------------------------------------------------------------------ |
| ✅    | Built in or officially available                                         |
| ◐    | Partial, limited, or requires an extension                               |
| 🔌   | Requires external component/controller                                   |
| 🧪   | Experimental                                                             |
| —    | No documented native support in the compared scope                       |
| 🛠️  | Pingora provides building blocks, but product implementation is required |


Scope rule: We compare the free/open-source distributions, not paid enterprise editions. A project running inside Docker doesn't count as having native Docker service discovery.

## Download the complete matrix

Reverse Proxy Feature-Parity Matrix

Excel · 171 capabilities · 7 existing technologies · 45 proposed modules

Download the complete feature-parity matrix

The workbook contains five sheets:

- Feature Matrix: All 171 features, competitor statuses, technical caveats, effort, target phase, and source URLs.
- Overview: Comparison legend and release priorities.
- Implementation Backlog: Module-level feature counts and priorities.
- Source Library: 26 official documentation references.
- 20 Critical Decisions: The most important architecture decisions before development.

## 1. Feature-parity highlights

These are the most relevant comparisons from the full workbook.

### Basic protocols and routing


| Capability      | NGINX | Traefik | Caddy | HAProxy | Envoy | Pingap | Pingora |
| --------------- | ----- | ------- | ----- | ------- | ----- | ------ | ------- |
| HTTP/1.1 proxy  | ✅     | ✅       | ✅     | ✅       | ✅     | ✅      | ✅       |
| HTTP/2          | ✅     | ✅       | ✅     | ✅       | ✅     | ✅      | ✅       |
| HTTP/3 frontend | 🧪    | ✅       | ✅     | ✅       | ✅     | —      | —       |
| WebSockets      | ✅     | ✅       | ✅     | ✅       | ✅     | ✅      | ✅       |
| gRPC proxy      | ✅     | ✅       | ✅     | ✅       | ✅     | ◐      | ✅       |
| TCP proxy       | ✅     | ✅       | 🔌    | ✅       | ✅     | —      | 🛠️     |
| UDP proxy       | ✅     | ✅       | 🔌    | ◐       | ✅     | —      | 🛠️     |


HTTP/3 deserves its own development track. Pingora's documented feature list is focused on HTTP/1.1 and HTTP/2, while Envoy documents HTTP/3 in both downstream and upstream configurations.

![](https://www.google.com/s2/favicons?domain=https://github.com&sz=32)

GitHub

+1



### HTTPS, reliability, and caching


| Capability                     | NGINX | Traefik | Caddy | HAProxy | Envoy | Pingap | Pingora |
| ------------------------------ | ----- | ------- | ----- | ------- | ----- | ------ | ------- |
| Automatic ACME HTTPS           | 🔌    | ✅       | ✅     | 🧪      | 🔌    | ✅      | 🛠️     |
| DNS-01 / wildcard certificates | 🔌    | ✅       | 🔌    | 🧪      | 🔌    | ✅      | 🛠️     |
| Active health checks           | 🔌    | ✅       | ✅     | ✅       | ✅     | ✅      | ✅       |
| Passive health checks          | ✅     | ✅       | ✅     | ✅       | ✅     | ✅      | 🛠️     |
| Response caching               | ✅     | 🔌      | 🔌    | ✅       | ✅     | ✅      | 🧪      |
| Persistent disk cache          | ✅     | 🔌      | 🔌    | —       | ✅     | ✅      | 🧪      |
| Circuit breaking               | ◐     | ✅       | ◐     | ✅       | ✅     | ✅      | 🛠️     |


HAProxy's native cache is memory-based and has specific object and caching restrictions. Envoy offers an HTTP cache filter with in-memory and filesystem storage options.

![](https://www.google.com/s2/favicons?domain=https://www.haproxy.com&sz=32)

HAProxy config tutorials

+1



### Infrastructure integrations


| Integration                       | NGINX | Traefik | Caddy | HAProxy | Envoy | Pingap | Pingora |
| --------------------------------- | ----- | ------- | ----- | ------- | ----- | ------ | ------- |
| Docker container discovery        | 🔌    | ✅       | 🔌    | 🔌      | 🔌    | ✅      | 🛠️     |
| Docker Compose labels             | 🔌    | ✅       | 🔌    | 🔌      | 🔌    | ✅      | 🛠️     |
| Traefik-label compatibility       | —     | ✅       | —     | —       | —     | —      | 🛠️     |
| Docker Swarm discovery            | 🔌    | ✅       | 🔌    | 🔌      | 🔌    | —      | 🛠️     |
| Kubernetes Ingress controller     | 🔌    | ✅       | 🔌    | 🔌      | 🔌    | —      | 🛠️     |
| Kubernetes Gateway API controller | 🔌    | ✅       | 🔌    | 🔌      | 🔌    | —      | 🛠️     |
| Cloudflare DNS-01 integration     | 🔌    | ✅       | 🔌    | 🔌      | 🔌    | ✅      | 🛠️     |


Here, 🔌 includes separate controllers and automation. For example, an Envoy-based Kubernetes controller is not automatically part of the standalone Envoy proxy binary. Traefik's provider system is a particularly strong reference for discovery.

![](https://www.google.com/s2/favicons?domain=https://doc.traefik.io&sz=32)

Traefik

+2



### Security and management


| Capability                   | NGINX | Traefik | Caddy | HAProxy | Envoy | Pingap | Pingora |
| ---------------------------- | ----- | ------- | ----- | ------- | ----- | ------ | ------- |
| Basic authentication         | ✅     | ✅       | ✅     | ✅       | ✅     | ✅      | 🛠️     |
| JWT validation               | 🔌    | 🔌      | 🔌    | 🔌      | ✅     | ✅      | 🛠️     |
| WAF integration              | 🔌    | 🔌      | 🔌    | 🔌      | 🔌    | ◐      | 🛠️     |
| Editable web dashboard       | 🔌    | ◐       | 🔌    | 🔌      | 🔌    | ✅      | 🛠️     |
| Live configuration REST API  | 🔌    | 🔌      | ✅     | ◐       | ◐     | ◐      | 🛠️     |
| Third-party extension system | ✅     | ✅       | ✅     | ◐       | ✅     | ✅      | 🛠️     |


Traefik's OSS dashboard provides visibility, but is not equivalent to a complete graphical route-management platform. The editable web administration experience is one area where Pingap already provides significant functionality.

![](https://www.google.com/s2/favicons?domain=https://pingap.io&sz=32)

[pingap.io](http://pingap.io)

+1



## 2. Our implementation gap analysis

Counts are proposed requirements, not a percentage of completed development.

# 59

P0 · Basics

# 58

P1 · Production

# 35

P2 · Advanced

# 19

P3 · Scale

Feature requirements by release priority

020406080P0 · BasicsP1 · ProductionP2 · AdvancedP3 · Scale

The project shouldn't try to deliver all 171 capabilities in its first release. The primary P0 outcome should be a stable proxy that can realistically replace Traefik for common Docker-based deployments.

## 3. Highest-value implementation priorities


| Priority | Capability                       | Why it matters                     |
| -------- | -------------------------------- | ---------------------------------- |
| P0       | Pingora routing engine           | Core of the entire project         |
| P0       | Docker and Compose discovery     | Immediate practical adoption       |
| P0       | Traefik-label compatibility      | Reduces migration effort           |
| P0       | Automatic ACME HTTPS             | Caddy-like user experience         |
| P0       | Cloudflare DNS and trusted IPs   | Reliable HTTPS behind Cloudflare   |
| P1       | Health checks and load balancing | Production reliability             |
| P1       | REST API and dashboard           | Simple operations                  |
| P1       | Docker Swarm                     | Multi-node Docker deployments      |
| P2       | Kubernetes Gateway API           | Cloud-native adoption              |
| P2       | Production HTTP cache            | Compete with NGINX caching         |
| P2       | TCP and UDP capabilities         | Broadening beyond HTTP             |
| P3       | Distributed control plane        | Multi-region and large deployments |


## 4. The biggest architectural conclusion

The research suggests we should think about this project as two products inside one ecosystem:

Core Proxy — Rust / Pingora

High-performance HTTP proxy, TLS, routing, load balancing, security primitives, and local configuration. Deployable independently as one binary.

Optional Management Ecosystem

Docker/Swarm/Kubernetes controllers, multi-instance control plane, dashboard, management API, metrics, and extensibility.

The product can then serve three audiences without forcing every deployment into a complex architecture: a developer with one VPS, a platform managing many containers, and a company operating multiple clusters.

My conclusion: The largest opportunity is not to outperform HAProxy in raw throughput immediately. It is to build a proxy that combines the deployment simplicity of Caddy, the service discovery of Traefik, and the programmability of Pingora, with an architecture that can later support more demanding features.