//! Prometheus metrics. Label values come from configuration (listener, route and service names)
//! or small fixed sets (method, status class), never from request data, so cardinality stays
//! bounded.

use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry,
    TextEncoder,
};

/// Methods reported as themselves; others count as `OTHER`.
const KNOWN_METHODS: [&str; 9] = [
    "GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "CONNECT", "TRACE",
];

/// The metrics of one process.
#[derive(Debug, Clone)]
pub struct Metrics {
    registry: Registry,
    /// Requests by listener, route, service, method and status class.
    pub requests: IntCounterVec,
    /// Request duration by listener and route.
    pub duration: HistogramVec,
    /// Upstream errors by service and kind (`connect`, `timeout`, `other`).
    pub upstream_errors: IntCounterVec,
    /// Open client connections by listener.
    pub connections: IntGaugeVec,
    /// Accepted client connections by listener.
    pub connections_total: IntCounterVec,
    /// TLS handshakes that failed, by listener.
    pub tls_handshake_errors: IntCounterVec,
    /// Generation of the configuration in use.
    pub config_generation: IntGauge,
    /// Configuration reloads by result (`applied`, `rejected`, `unchanged`).
    pub config_reloads: IntCounterVec,
    /// Expiry of each certificate, in seconds since the Unix epoch.
    pub cert_expiry: IntGaugeVec,
}

impl Metrics {
    /// Creates and registers every metric. `version` and `commit` label `rdock_build_info`.
    pub fn new(version: &str, commit: &str) -> prometheus::Result<Self> {
        let registry = Registry::new();
        let requests = IntCounterVec::new(
            Opts::new("rdock_http_requests_total", "HTTP requests handled."),
            &["listener", "route", "service", "method", "status_class"],
        )?;
        let duration = HistogramVec::new(
            HistogramOpts::new(
                "rdock_http_request_duration_seconds",
                "Time from request headers to the end of the response.",
            )
            .buckets(vec![
                0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0,
            ]),
            &["listener", "route"],
        )?;
        let upstream_errors = IntCounterVec::new(
            Opts::new(
                "rdock_upstream_errors_total",
                "Failed requests to backends.",
            ),
            &["service", "kind"],
        )?;
        let connections = IntGaugeVec::new(
            Opts::new("rdock_connections_open", "Open client connections."),
            &["listener"],
        )?;
        let connections_total = IntCounterVec::new(
            Opts::new("rdock_connections_total", "Accepted client connections."),
            &["listener"],
        )?;
        let tls_handshake_errors = IntCounterVec::new(
            Opts::new("rdock_tls_handshake_errors_total", "Failed TLS handshakes."),
            &["listener"],
        )?;
        let config_generation = IntGauge::new(
            "rdock_config_generation",
            "Generation of the configuration in use.",
        )?;
        let config_reloads = IntCounterVec::new(
            Opts::new(
                "rdock_config_reloads_total",
                "Configuration reload attempts.",
            ),
            &["result"],
        )?;
        let cert_expiry = IntGaugeVec::new(
            Opts::new(
                "rdock_cert_expiry_timestamp_seconds",
                "Expiry of each certificate.",
            ),
            &["name"],
        )?;
        let build_info = IntGaugeVec::new(
            Opts::new("rdock_build_info", "Version of the running binary."),
            &["version", "commit"],
        )?;
        build_info.with_label_values(&[version, commit]).set(1);
        for collector in [
            Box::new(requests.clone()) as Box<dyn prometheus::core::Collector>,
            Box::new(duration.clone()),
            Box::new(upstream_errors.clone()),
            Box::new(connections.clone()),
            Box::new(connections_total.clone()),
            Box::new(tls_handshake_errors.clone()),
            Box::new(config_generation.clone()),
            Box::new(config_reloads.clone()),
            Box::new(cert_expiry.clone()),
            Box::new(build_info),
        ] {
            registry.register(collector)?;
        }
        Ok(Self {
            registry,
            requests,
            duration,
            upstream_errors,
            connections,
            connections_total,
            tls_handshake_errors,
            config_generation,
            config_reloads,
            cert_expiry,
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
