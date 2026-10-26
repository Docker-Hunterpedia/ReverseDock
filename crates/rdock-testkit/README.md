# rdock-testkit

Test harness for the end-to-end suites in `crates/rdock/tests/`: a backend that speaks HTTP/1.1, h2c and TLS (with WebSocket, server-sent events and gRPC-style trailers), a throw-away certificate authority, HTTP/1.1, h2c, TLS and raw-byte clients, and a launcher that runs the real `rdock` binary with a generated configuration and talks to its admin API.

Pebble (ACME), toxiproxy and container helpers join with v0.3 and v0.4.
