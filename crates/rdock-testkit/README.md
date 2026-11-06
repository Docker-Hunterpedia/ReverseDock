# rdock-testkit

Test harness for the end-to-end suites in `crates/rdock/tests/`: a backend that speaks HTTP/1.1, h2c and TLS (with WebSocket, server-sent events and gRPC-style trailers), a throw-away certificate authority, HTTP/1.1, h2c, TLS and raw-byte clients, and a launcher that runs the real `rdock` binary with a generated configuration and talks to its admin API.

`pebble`: Pebble, Let's Encrypt's test CA, and `pebble-challtestsrv` in Docker, resolving every name to the Docker host (v0.3). Toxiproxy and more container helpers join with v0.4.

`fake_api`: an in-process HTTP API fake for API clients: a route table (method and path pattern to status, headers and body, or a closure for stateful answers), a record of every request, guards and failure injection per route (v0.6). `dns_contract`: the contract every DNS-01 adapter runs against its provider's fake (ADR-0026).

`proxy_protocol`: PROXY protocol v1 and v2 headers for tests, and `haproxy`: HAProxy in Docker as an independent `send-proxy`/`send-proxy-v2` sender (v0.6).
