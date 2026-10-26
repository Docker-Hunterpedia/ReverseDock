# rdock-observability

Access logs with redaction, Prometheus metrics, OpenTelemetry traces and the in-memory ring buffer that feeds the dashboard.

**v0.1:** application logs (JSON in containers or when stdout is not a terminal, text otherwise), the access log written from its own thread (JSON or text, to stdout or a file), and Prometheus metrics for requests, latency, upstream errors, connections, TLS handshakes, reloads and certificate expiry. Tracing lands in v0.4, the dashboard ring buffer in v0.5. Design: [architecture §14](../../docs/05-architecture.md).
