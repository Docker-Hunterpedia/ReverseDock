//! Prometheus metrics. Label values come from configuration (listener, route and service names)
//! or small fixed sets (method, status class), never from request data, so cardinality stays
//! bounded.

use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounterVec, IntGaugeVec, Opts, Registry, TextEncoder,
};
pub use prometheus::{IntCounter, IntGauge};

/// Methods reported as themselves; others count as `OTHER`.
const KNOWN_METHODS: [&str; 9] = [
    "GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "CONNECT", "TRACE",
];

/// The metrics of one process.
#[derive(Debug, Clone)]
pub struct Metrics {
    registry: Registry,
    /// Live feeds for the admin API's log and event streams.
    pub feeds: crate::feed::Feeds,
    /// Alerts delivered by channel and result (`sent`, `failed`).
    pub alerts_sent: IntCounterVec,
    /// Requests by listener, route, service, method and status class.
    pub requests: IntCounterVec,
    /// Request duration by listener and route.
    pub duration: HistogramVec,
    /// Upstream errors by service and kind (`connect`, `timeout`).
    pub upstream_errors: IntCounterVec,
    /// Open client connections by listener.
    pub connections: IntGaugeVec,
    /// Accepted client connections by listener.
    pub connections_total: IntCounterVec,
    /// TLS handshakes that failed, by listener.
    pub tls_handshake_errors: IntCounterVec,
    /// Connections closed by the PROXY protocol step, by listener and reason (`untrusted`,
    /// `missing`, `malformed`, `timeout`, `too_large`).
    pub proxy_protocol_rejected: IntCounterVec,
    /// Open TCP-route connections by listener and route.
    pub tcp_connections: IntGaugeVec,
    /// Bytes relayed by TCP routes, by route and direction (`in` from the client, `out` to it).
    pub tcp_bytes: IntCounterVec,
    /// Connections a `tcp` listener closed without relaying them, by listener and reason
    /// (`no_route`, `bad_client_hello`, `denied`, `in_flight`, `no_backend`, `connect_failed`).
    pub tcp_rejected: IntCounterVec,
    /// Open UDP sessions by listener and route.
    pub udp_sessions: IntGaugeVec,
    /// Datagrams relayed by UDP routes, by route and direction (`in` from the client, `out`
    /// to it).
    pub udp_datagrams: IntCounterVec,
    /// Bytes relayed by UDP routes, by route and direction.
    pub udp_bytes: IntCounterVec,
    /// Datagrams a `udp` listener dropped, by listener and reason (`no_route`, `denied`,
    /// `session_limit`, `client_limit`, `no_backend`, `socket_error`, `queue_full`,
    /// `oversize`, `backend_unreachable`, `closing`).
    pub udp_dropped: IntCounterVec,
    /// UDP sessions that ended, by route and reason (`idle`, `responses`,
    /// `backend_unreachable`, `error`, `closed`).
    pub udp_session_ends: IntCounterVec,
    /// Generation of the configuration in use.
    pub config_generation: IntGauge,
    /// Configuration reloads by result (`applied`, `rejected`).
    pub config_reloads: IntCounterVec,
    /// Expiry of each certificate, in seconds since the Unix epoch.
    pub cert_expiry: IntGaugeVec,
    /// Failed attempts to issue or renew an automatic certificate, by its first name.
    pub cert_renewal_failures: IntCounterVec,
    /// ACME orders by CA host and result (`issued`, `failed`).
    pub acme_orders: IntCounterVec,
    /// Whether each backend takes traffic (1) or not (0), by service and address.
    pub backend_up: IntGaugeVec,
    /// Backend ejections by passive health, by service and address.
    pub backend_ejections: IntCounterVec,
    /// Retries by service and reason (`connect`, `reset`, `timeout`, `502` …).
    pub retries: IntCounterVec,
    /// Retries not made because the service's retry budget was used up.
    pub retry_budget_exhausted: IntCounterVec,
    /// Answers of each backend by service, backend address and status class.
    pub backend_requests: IntCounterVec,
    /// Time from sending a request to a backend to its response headers, by service.
    pub upstream_duration: HistogramVec,
    /// Mirrored copies by target service and outcome (`sent`, `failed`, `dropped`,
    /// `too_large`, `no_backend`).
    pub mirrors: IntCounterVec,
    /// Requests on caching routes by store, route and outcome (`hit`, `stale`,
    /// `revalidated`, `expired`, `miss`, `bypass`).
    pub cache_requests: IntCounterVec,
    /// Objects in each cache store.
    pub cache_objects: IntGaugeVec,
    /// Bytes in each cache store.
    pub cache_bytes: IntGaugeVec,
    /// Cache objects evicted by store and reason (`size`, `count`).
    pub cache_evictions: IntCounterVec,
    /// Requests that waited for another request to fill the cache, by store.
    pub cache_lock_waits: IntCounterVec,
    /// Disk cache objects dropped at start by store and reason (`corrupt`, `partial`).
    pub cache_dropped: IntCounterVec,
}

/// Creates `metric` and registers it in `registry`.
fn registered<M: prometheus::core::Collector + Clone + 'static>(
    registry: &Registry,
    metric: prometheus::Result<M>,
) -> prometheus::Result<M> {
    let metric = metric?;
    registry.register(Box::new(metric.clone()))?;
    Ok(metric)
}

fn counters(
    registry: &Registry,
    name: &str,
    help: &str,
    labels: &[&str],
) -> prometheus::Result<IntCounterVec> {
    registered(registry, IntCounterVec::new(Opts::new(name, help), labels))
}

fn gauges(
    registry: &Registry,
    name: &str,
    help: &str,
    labels: &[&str],
) -> prometheus::Result<IntGaugeVec> {
    registered(registry, IntGaugeVec::new(Opts::new(name, help), labels))
}

impl Metrics {
    /// Creates and registers every metric. `version` and `commit` label `rdock_build_info`.
    // A flat list of metric declarations; splitting it would only scatter them.
    #[allow(clippy::too_many_lines)]
    pub fn new(version: &str, commit: &str) -> prometheus::Result<Self> {
        let registry = Registry::new();
        let requests = counters(
            &registry,
            "rdock_http_requests_total",
            "HTTP requests handled.",
            &["listener", "route", "service", "method", "status_class"],
        )?;
        let duration = registered(
            &registry,
            HistogramVec::new(
                HistogramOpts::new(
                    "rdock_http_request_duration_seconds",
                    "Time from request headers to the end of the response.",
                )
                .buckets(vec![
                    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0,
                ]),
                &["listener", "route"],
            ),
        )?;
        let upstream_errors = counters(
            &registry,
            "rdock_upstream_errors_total",
            "Failed requests to backends.",
            &["service", "kind"],
        )?;
        let connections = gauges(
            &registry,
            "rdock_connections_open",
            "Open client connections.",
            &["listener"],
        )?;
        let connections_total = counters(
            &registry,
            "rdock_connections_total",
            "Accepted client connections.",
            &["listener"],
        )?;
        let tls_handshake_errors = counters(
            &registry,
            "rdock_tls_handshake_errors_total",
            "Failed TLS handshakes.",
            &["listener"],
        )?;
        let proxy_protocol_rejected = counters(
            &registry,
            "rdock_proxy_protocol_rejected_total",
            "Connections closed for their PROXY protocol header, or its absence.",
            &["listener", "reason"],
        )?;
        let tcp_connections = gauges(
            &registry,
            "rdock_tcp_connections",
            "Open connections of TCP routes.",
            &["listener", "route"],
        )?;
        let tcp_bytes = counters(
            &registry,
            "rdock_tcp_bytes_total",
            "Bytes relayed by TCP routes (`in` from the client, `out` to the client).",
            &["route", "direction"],
        )?;
        let tcp_rejected = counters(
            &registry,
            "rdock_tcp_rejected_total",
            "TCP connections closed without being relayed.",
            &["listener", "reason"],
        )?;
        let udp_sessions = gauges(
            &registry,
            "rdock_udp_sessions",
            "Open sessions of UDP routes.",
            &["listener", "route"],
        )?;
        let udp_datagrams = counters(
            &registry,
            "rdock_udp_datagrams_total",
            "Datagrams relayed by UDP routes (`in` from the client, `out` to the client).",
            &["route", "direction"],
        )?;
        let udp_bytes = counters(
            &registry,
            "rdock_udp_bytes_total",
            "Bytes relayed by UDP routes (`in` from the client, `out` to the client).",
            &["route", "direction"],
        )?;
        let udp_dropped = counters(
            &registry,
            "rdock_udp_dropped_total",
            "Datagrams a UDP listener dropped instead of relaying them.",
            &["listener", "reason"],
        )?;
        let udp_session_ends = counters(
            &registry,
            "rdock_udp_session_ends_total",
            "UDP sessions that ended, by why.",
            &["route", "reason"],
        )?;
        let config_generation = registered(
            &registry,
            IntGauge::new(
                "rdock_config_generation",
                "Generation of the configuration in use.",
            ),
        )?;
        let config_reloads = counters(
            &registry,
            "rdock_config_reloads_total",
            "Configuration reload attempts.",
            &["result"],
        )?;
        let cert_expiry = gauges(
            &registry,
            "rdock_cert_expiry_timestamp_seconds",
            "Expiry of each certificate.",
            &["name"],
        )?;
        let cert_renewal_failures = counters(
            &registry,
            "rdock_cert_renewal_failures_total",
            "Failed attempts to issue or renew an automatic certificate.",
            &["name"],
        )?;
        let acme_orders = counters(
            &registry,
            "rdock_acme_orders_total",
            "ACME certificate orders.",
            &["ca", "result"],
        )?;
        let backend_up = gauges(
            &registry,
            "rdock_backend_up",
            "Whether a backend takes traffic (health checks and ejection).",
            &["service", "backend"],
        )?;
        let backend_ejections = counters(
            &registry,
            "rdock_backend_ejections_total",
            "Backends ejected after repeated failures.",
            &["service", "backend"],
        )?;
        let retries = counters(
            &registry,
            "rdock_retries_total",
            "Requests sent again to a backend after a failure.",
            &["service", "reason"],
        )?;
        let retry_budget_exhausted = counters(
            &registry,
            "rdock_retry_budget_exhausted_total",
            "Retries refused because the retry budget was used up.",
            &["service"],
        )?;
        let backend_requests = counters(
            &registry,
            "rdock_backend_requests_total",
            "Answers from each backend.",
            &["service", "backend", "status_class"],
        )?;
        let upstream_duration = registered(
            &registry,
            HistogramVec::new(
                HistogramOpts::new(
                    "rdock_upstream_duration_seconds",
                    "Time from sending a request to a backend to its response headers.",
                )
                .buckets(vec![
                    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0,
                ]),
                &["service"],
            ),
        )?;
        let alerts_sent = counters(
            &registry,
            "rdock_alerts_sent_total",
            "Alerts delivered, by channel and result.",
            &["channel", "result"],
        )?;
        let mirrors = counters(
            &registry,
            "rdock_mirror_requests_total",
            "Copies of requests sent to mirror services.",
            &["service", "outcome"],
        )?;
        let build_info = gauges(
            &registry,
            "rdock_build_info",
            "Version of the running binary.",
            &["version", "commit"],
        )?;
        build_info.with_label_values(&[version, commit]).set(1);
        let cache_requests = counters(
            &registry,
            "rdock_cache_requests_total",
            "Requests on caching routes, by outcome.",
            &["store", "route", "status"],
        )?;
        let cache_objects = gauges(
            &registry,
            "rdock_cache_objects",
            "Objects in a cache store.",
            &["store"],
        )?;
        let cache_bytes = gauges(
            &registry,
            "rdock_cache_bytes",
            "Bytes in a cache store.",
            &["store"],
        )?;
        let cache_evictions = counters(
            &registry,
            "rdock_cache_evictions_total",
            "Cache objects evicted to stay within a store's limits.",
            &["store", "reason"],
        )?;
        let cache_lock_waits = counters(
            &registry,
            "rdock_cache_lock_waits_total",
            "Requests that waited for another request to fill the cache.",
            &["store"],
        )?;
        let cache_dropped = counters(
            &registry,
            "rdock_cache_dropped_total",
            "Disk cache objects dropped at start because they were damaged or incomplete.",
            &["store", "reason"],
        )?;
        Ok(Self {
            cache_requests,
            cache_objects,
            cache_bytes,
            cache_evictions,
            cache_lock_waits,
            cache_dropped,
            registry,
            feeds: crate::feed::Feeds::default(),
            alerts_sent,
            requests,
            duration,
            upstream_errors,
            connections,
            connections_total,
            tls_handshake_errors,
            proxy_protocol_rejected,
            tcp_connections,
            tcp_bytes,
            tcp_rejected,
            udp_sessions,
            udp_datagrams,
            udp_bytes,
            udp_dropped,
            udp_session_ends,
            config_generation,
            config_reloads,
            cert_expiry,
            cert_renewal_failures,
            acme_orders,
            backend_up,
            backend_ejections,
            retries,
            retry_budget_exhausted,
            backend_requests,
            upstream_duration,
            mirrors,
        })
    }

    /// Records one finished request.
    pub fn observe_request(
        &self,
        labels: (&str, &str, &str),
        method: &str,
        status: u16,
        seconds: f64,
    ) {
        let (listener, route, service) = labels;
        let method = KNOWN_METHODS
            .iter()
            .find(|m| **m == method)
            .copied()
            .unwrap_or("OTHER");
        self.requests
            .with_label_values(&[listener, route, service, method, status_class(status)])
            .inc();
        self.duration
            .with_label_values(&[listener, route])
            .observe(seconds);
    }

    /// The Prometheus text exposition of every metric.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = Vec::new();
        // Encoding gathered metric families into a Vec cannot fail.
        let _ = TextEncoder::new().encode(&self.registry.gather(), &mut out);
        String::from_utf8(out).unwrap_or_default()
    }
}

/// `1xx` … `5xx`.
#[must_use]
pub fn status_class(status: u16) -> &'static str {
    match status {
        100..=199 => "1xx",
        200..=299 => "2xx",
        300..=399 => "3xx",
        400..=499 => "4xx",
        _ => "5xx",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_registered_metrics() {
        let m = Metrics::new("0.1.0", "abc").unwrap();
        m.observe_request(("web", "app", "app"), "GET", 200, 0.02);
        m.observe_request(("web", "app", "app"), "BREW", 503, 0.5);
        m.config_generation.set(3);
        let text = m.render();
        assert!(text.contains(
            "rdock_http_requests_total{listener=\"web\",method=\"GET\",route=\"app\",service=\"app\",status_class=\"2xx\"} 1"
        ), "{text}");
        assert!(text.contains("method=\"OTHER\""), "{text}");
        assert!(text.contains("rdock_config_generation 3"), "{text}");
        assert!(
            text.contains("rdock_build_info{commit=\"abc\",version=\"0.1.0\"} 1"),
            "{text}"
        );
    }
}
