# rdock-testkit

Test harness for the end-to-end suites in `crates/rdock/tests/`: a backend that speaks HTTP/1.1, h2c and TLS (with WebSocket, server-sent events and gRPC-style trailers), a throw-away certificate authority, HTTP/1.1, h2c, TLS and raw-byte clients, and a launcher that runs the real `rdock` binary with a generated configuration and talks to its admin API.

`pebble`: Pebble, Let's Encrypt's test CA, and `pebble-challtestsrv` in Docker, resolving every name to the Docker host (v0.3). Toxiproxy and more container helpers join with v0.4.

`fake_api`: an in-process HTTP API fake for API clients: a route table (method and path pattern to status, headers and body, or a closure for stateful answers), a record of every request, guards and failure injection per route (v0.6). `dns_contract`: the contract every DNS-01 adapter runs against its provider's fake (ADR-0026).

`proxy_protocol`: PROXY protocol v1 and v2 headers for tests, and `haproxy`: HAProxy in Docker as an independent `send-proxy`/`send-proxy-v2` sender (v0.6).

`tcp`: a plain TCP echo backend that can read a PROXY protocol header first, for TCP routes (v0.6). `postgres`: PostgreSQL 17 with TLS in Docker and `psql` from the same image.

`udp`: a UDP echo backend that names itself and can answer more than once, a DNS-shaped backend, a port where nothing listens, and client helpers, for UDP routes (v0.8).

`origin`: a scripted origin for cache tests: per-path status, headers, body (repeated for large objects), delays before the head and between chunks, `304` for a matching `If-None-Match`, a dropped connection, and a stop that refuses further connects; every request is counted and recorded (v0.8).

`agent`: a scriptable stub agent (plain or TLS) for the `agent` middleware's tests: it records each request (method, target, headers, body, time) and answers what its handler returns, optionally after a delay (v0.8).
