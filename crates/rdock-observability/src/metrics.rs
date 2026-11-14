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
    /// TLS connections between accept and the end of their handshake, by listener.
    pub tls_handshakes_in_flight: IntGaugeVec,
    /// Times a listener stopped accepting because `tls.max_handshakes` was reached (new
    /// connections waited in the listen backlog meanwhile), by listener.
    pub tls_handshake_waits: IntCounterVec,
    /// The proxy runtime's thread settings in effect (`kind`: `worker`, `max_blocking`).
    pub runtime_threads: IntGaugeVec,
    /// Binary upgrades this process started, by `result` (`ok`, `failed`, `refused`).
    pub upgrades: IntCounterVec,
    /// Connections the previous process still serves while it drains after a binary upgrade.
    pub upgrade_draining_connections: IntGauge,
    /// Binary upgrades behind this process (0 for a process started normally).
    pub upgrade_generation: IntGauge,
    /// When the previous process's drain ends (Unix seconds); 0 when none drains.
    pub upgrade_drain_deadline: IntGauge,
    /// Connections closed by the PROXY protocol step, by listener and reason (`untrusted`,
    /// `missing`, `malformed`, `timeout`, `too_large`).
    pub proxy_protocol_rejected: IntCounterVec,
    /// HTTP/3 (experimental, ADR-0032): QUIC connections that completed their handshake, by
    /// listener.
    pub http3_connections_total: IntCounterVec,
    /// HTTP/3: open QUIC connections by listener.
    pub http3_connections: IntGaugeVec,
    /// HTTP/3: QUIC Retry packets sent, by listener.
    pub http3_retries: IntCounterVec,
    /// HTTP/3: QUIC connections that ended or were refused, by listener and reason (`idle`,
    /// `client`, `drained`, `limit`, `client_limit`, `handshake`, `protocol`, `reset_flood`).
    pub http3_connections_closed: IntCounterVec,
    /// HTTP/3: request streams reset (or answered 431) before the pipeline because their
    /// header section was malformed, by listener and reason.
    pub http3_malformed_requests: IntCounterVec,
    /// HTTP/3: requests answered, by listener and status class.
    pub http3_requests: IntCounterVec,
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
    /// 1 for each experimental feature the applied configuration uses, 0 for the others
    /// (ADR-0033).
    pub experimental_in_use: IntGaugeVec,
    /// 1 for each deprecated element the applied configuration uses (ADR-0033).
    pub deprecated_in_use: IntGaugeVec,
    /// Expiry of each certificate, in seconds since the Unix epoch.
    pub cert_expiry: IntGaugeVec,
    /// Failed attempts to issue or renew an automatic certificate, by its first name.
    pub cert_renewal_failures: IntCounterVec,
    /// ACME orders by CA host and result (`issued`, `failed`).
    pub acme_orders: IntCounterVec,
    /// The control-plane bundle revision this data plane serves (0 without a control plane).
    pub cluster_bundle_revision: IntGauge,
    /// Bundles received from the control plane, by result (`ack`, `nack`, `refused`).
    pub cluster_bundles: IntCounterVec,
    /// Whether the data plane's last request to its control plane succeeded (1) or not (0).
    pub cluster_control_connected: IntGauge,
    /// Certificate leases asked for, by result (`acquired`, `busy`, `lost`, `error`).
    pub cluster_leases: IntCounterVec,
    /// Challenge barriers, by result (`complete`: every live member confirmed; `timeout`).
    pub cluster_barriers: IntCounterVec,
    /// Whether the store of cluster-scoped limits answers (1) or limits fall back to each
    /// instance's share (0).
    pub cluster_limits_store_up: IntGauge,
    /// Claims of cluster-scoped limits, by outcome (`granted`, `exhausted`, `forced`,
    /// `failed`).
    pub cluster_limit_claims: IntCounterVec,
    /// Instances sharing cluster-scoped limits, as this instance last counted them.
    pub cluster_limits_members: IntGauge,
    /// The control plane's latest published revision (control plane only).
    pub control_revision: IntGauge,
    /// Enrolled data planes by state (`synced`, `stale`, `error`, `away`, `revoked`; control
    /// plane only).
    pub control_instances: IntGaugeVec,
    /// Whether each backend takes traffic (1) or not (0), by service and address.
    pub backend_up: IntGaugeVec,
    /// Backend ejections by passive health, by service and address.
    pub backend_ejections: IntCounterVec,
    /// Backend ejections by an outlier detector, by service, address and detector.
    pub outlier_ejections: IntCounterVec,
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
    /// Panics caught in native plugin hooks, by plugin name (ADR-0030).
    pub plugin_panics: IntCounterVec,
    /// Failed calls into WASM plugins by middleware and reason (`fuel`, `timeout`, `memory`,
    /// `trap`, `invalid`) (ADR-0030).
    pub wasm_failures: IntCounterVec,
    /// Agent calls by middleware and result (`allow`, `deny`, `error`, `timeout`,
    /// `breaker_open`, `skipped`, `oversize`).
    pub agent_requests: IntCounterVec,
    /// Duration of agent calls by middleware.
    pub agent_duration: HistogramVec,
    /// Whether an agent's circuit breaker is open (1) or closed (0), by middleware.
    pub agent_breaker_open: IntGaugeVec,
    /// Headers an agent asked to set that were not applied, by middleware and reason
    /// (`not_allowed`, `too_late`, `invalid`).
    pub agent_ignored_headers: IntCounterVec,
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
    /// Requests with a consumer, by consumer, route and status class (F-GW-01). At most
    /// `MAX_CONSUMER_LABELS` consumers get their own series; the rest share `_other`.
    pub consumer_requests: IntCounterVec,
    consumers_seen: std::sync::Arc<std::sync::Mutex<std::collections::HashSet<String>>>,
    /// Metering events delivered or given up, by sink and result (`sent`, `failed`).
    pub metering_events: IntCounterVec,
    /// Metering events dropped by sink and reason (`queue_full`, `undeliverable`).
    pub metering_dropped: IntCounterVec,
    /// Requests checked by `validate`, by middleware and result (`valid`, `invalid`,
    /// `reported`, `unknown_operation`, `unsupported_media_type`).
    pub validation_requests: IntCounterVec,
    /// Bodies `transform` left unchanged, by middleware and reason (`not_json`, `encoded`,
    /// `too_large`, `status`, `invalid_json`, `patch_failed`).
    pub transform_skipped: IntCounterVec,
    /// Failed reads of `${vault:…}` references after the first (the last value stays in use).
    pub vault_refresh_failures: prometheus::IntCounter,
    /// OIDC logins by middleware and result (`success`, `denied`, `failed`,
    /// `provider_error`, `unavailable`).
    pub oidc_logins: IntCounterVec,
    /// `rdock_quota_overflows_total{middleware,class}`: requests counted on a shared counter
    /// because their class of quota keys was full.
    pub quota_overflows: IntCounterVec,
    /// OIDC session refreshes by middleware and result (`success`, `failed`).
    pub oidc_refreshes: IntCounterVec,
    /// Failed requests to OIDC providers by middleware and operation (`discovery`, `jwks`,
    /// `token`, `refresh`).
    pub oidc_provider_errors: IntCounterVec,
    /// `rdock_geoip_build_timestamp_seconds{database}`: build time of each GeoIP database
    /// (`country`, `asn`) from its metadata.
    pub geoip_build: IntGaugeVec,
    /// `rdock_geoip_database_age_seconds{database}`: age of each GeoIP database, computed when
    /// the metrics are read.
    pub geoip_age: IntGaugeVec,
    geoip_epochs: std::sync::Arc<std::sync::Mutex<std::collections::BTreeMap<String, u64>>>,
    /// `rdock_abuse_actions_total{middleware,action}`: requests an `abuse` middleware denied
    /// (`deny`), held (`tarpit`) or tagged (`tag`) because their key is banned, and bans
    /// started (`ban`).
    pub abuse_actions: IntCounterVec,
    /// `rdock_abuse_bans`: keys banned right now, all `abuse` middlewares together.
    pub abuse_bans: IntGauge,
    /// `rdock_abuse_bans_refused_total{middleware}`: bans not started because the ban list
    /// was full.
    pub abuse_bans_refused: IntCounterVec,
    /// `rdock_admission_limit{middleware}`: the current adaptive limit of each `admission`
    /// middleware (`min` while `gradient` measures the no-load latency).
    pub admission_limit: IntGaugeVec,
    /// `rdock_admission_in_flight{middleware}`: requests admitted and not finished.
    pub admission_in_flight: IntGaugeVec,
    /// `rdock_admission_shed_total{middleware,class}`: requests answered `503` by an
    /// `admission` middleware, by the route's `priority_class`.
    pub admission_shed: IntCounterVec,
    /// `rdock_backend_addresses_refused_total{service}`: resolved backend addresses of a
    /// tenant's service that its tenant may not reach (ADR-0031), never connected to.
    pub backend_addresses_refused: IntCounterVec,
}

/// Distinct consumers that get their own `rdock_consumer_requests_total` series; later ones
/// are counted under `OTHER_CONSUMERS`, so a large consumer base cannot blow up the metrics.
pub const MAX_CONSUMER_LABELS: usize = 1000;
/// The `consumer` label of consumers past [`MAX_CONSUMER_LABELS`].
pub const OTHER_CONSUMERS: &str = "_other";

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
        let tls_handshakes_in_flight = gauges(
            &registry,
            "rdock_tls_handshakes_in_flight",
            "TLS connections accepted whose handshake has not finished.",
            &["listener"],
        )?;
        let tls_handshake_waits = counters(
            &registry,
            "rdock_tls_handshake_waits_total",
            "Times the listener stopped accepting because tls.max_handshakes was reached; new connections waited in the listen backlog.",
            &["listener"],
        )?;
        let runtime_threads = gauges(
            &registry,
            "rdock_runtime_threads",
            "Thread settings of the proxy runtime (worker threads, most blocking threads).",
            &["kind"],
        )?;
        let upgrades = counters(
            &registry,
            "rdock_upgrades_total",
            "Binary upgrades started by this process, by result (ok, failed, refused).",
            &["result"],
        )?;
        let upgrade_draining_connections = registered(
            &registry,
            IntGauge::new(
                "rdock_upgrade_draining_connections",
                "Connections the previous process still serves while it drains after a binary upgrade.",
            ),
        )?;
        let upgrade_generation = registered(
            &registry,
            IntGauge::new(
                "rdock_upgrade_generation",
                "Binary upgrades behind this process (0 for a process started normally).",
            ),
        )?;
        let upgrade_drain_deadline = registered(
            &registry,
            IntGauge::new(
                "rdock_upgrade_drain_deadline_seconds",
                "When the previous process's drain ends, in Unix seconds; 0 when none drains.",
            ),
        )?;
        let proxy_protocol_rejected = counters(
            &registry,
            "rdock_proxy_protocol_rejected_total",
            "Connections closed for their PROXY protocol header, or its absence.",
            &["listener", "reason"],
        )?;
        let http3_connections_total = counters(
            &registry,
            "rdock_http3_connections_total",
            "QUIC connections of HTTP/3 listeners that completed their handshake.",
            &["listener"],
        )?;
        let http3_connections = gauges(
            &registry,
            "rdock_http3_connections",
            "Open QUIC connections of HTTP/3 listeners.",
            &["listener"],
        )?;
        let http3_retries = counters(
            &registry,
            "rdock_http3_retries_total",
            "QUIC Retry packets sent by HTTP/3 listeners.",
            &["listener"],
        )?;
        let http3_connections_closed = counters(
            &registry,
            "rdock_http3_connections_closed_total",
            "QUIC connections of HTTP/3 listeners that ended or were refused, by reason.",
            &["listener", "reason"],
        )?;
        let http3_malformed_requests = counters(
            &registry,
            "rdock_http3_malformed_requests_total",
            "HTTP/3 requests reset before the pipeline because their header section was malformed.",
            &["listener", "reason"],
        )?;
        let http3_requests = counters(
            &registry,
            "rdock_http3_requests_total",
            "HTTP/3 requests answered, by status class.",
            &["listener", "status_class"],
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
        let experimental_in_use = gauges(
            &registry,
            "rdock_experimental_feature_in_use",
            "1 when the applied configuration uses this experimental feature, else 0.",
            &["feature"],
        )?;
        let deprecated_in_use = gauges(
            &registry,
            "rdock_deprecated_config_in_use",
            "1 when the applied configuration uses this deprecated element.",
            &["element"],
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
        let cluster_bundle_revision = registered(
            &registry,
            IntGauge::new(
                "rdock_cluster_bundle_revision",
                "The control-plane bundle revision this data plane serves; 0 without a control plane.",
            ),
        )?;
        let cluster_bundles = counters(
            &registry,
            "rdock_cluster_bundles_total",
            "Bundles received from the control plane, by result (ack, nack, refused).",
            &["result"],
        )?;
        let cluster_control_connected = registered(
            &registry,
            IntGauge::new(
                "rdock_cluster_control_connected",
                "Whether the data plane's last request to its control plane succeeded (1) or not (0).",
            ),
        )?;
        let cluster_leases = counters(
            &registry,
            "rdock_cluster_leases_total",
            "Certificate leases asked for, by result (acquired, busy, lost, error).",
            &["result"],
        )?;
        let cluster_limits_store_up = registered(
            &registry,
            IntGauge::new(
                "rdock_cluster_limits_store_up",
                "Whether the store of cluster-scoped limits answers (1) or limits fall back to each instance's share (0).",
            ),
        )?;
        let cluster_limit_claims = counters(
            &registry,
            "rdock_cluster_limit_claims_total",
            "Claims of cluster-scoped limits, by outcome (granted, exhausted, forced, failed).",
            &["outcome"],
        )?;
        let cluster_limits_members = registered(
            &registry,
            IntGauge::new(
                "rdock_cluster_limits_members",
                "Instances sharing cluster-scoped limits, as this instance last counted them.",
            ),
        )?;
        let cluster_barriers = counters(
            &registry,
            "rdock_cluster_challenge_barriers_total",
            "Challenge barriers, by result (complete, timeout).",
            &["result"],
        )?;
        let control_revision = registered(
            &registry,
            IntGauge::new(
                "rdock_control_revision",
                "The control plane's latest published revision.",
            ),
        )?;
        let control_instances = gauges(
            &registry,
            "rdock_control_instances",
            "Enrolled data planes by state (synced, stale, error, away, revoked).",
            &["state"],
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
            "Backends ejected by passive health: repeated failures or an outlier detector.",
            &["service", "backend"],
        )?;
        let outlier_ejections = counters(
            &registry,
            "rdock_backend_outlier_ejections_total",
            "Backends ejected by an outlier detector (success_rate or failure_percentage); also counted in rdock_backend_ejections_total.",
            &["service", "backend", "detector"],
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
        let plugin_panics = counters(
            &registry,
            "rdock_plugin_panics_total",
            "Panics caught in native plugin hooks; each answered its request with 500.",
            &["plugin"],
        )?;
        let wasm_failures = counters(
            &registry,
            "rdock_wasm_failures_total",
            "Failed calls into WASM plugins; each followed the middleware's on_error.",
            &["middleware", "reason"],
        )?;
        let agent_requests = counters(
            &registry,
            "rdock_agent_requests_total",
            "Calls to out-of-process agents, by result.",
            &["agent", "result"],
        )?;
        let agent_duration = registered(
            &registry,
            HistogramVec::new(
                HistogramOpts::new(
                    "rdock_agent_duration_seconds",
                    "Time an agent took to answer.",
                )
                .buckets(vec![
                    0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
                ]),
                &["agent"],
            ),
        )?;
        let agent_breaker_open = gauges(
            &registry,
            "rdock_agent_breaker_open",
            "Whether an agent's circuit breaker is open (1) or closed (0).",
            &["agent"],
        )?;
        let agent_ignored_headers = counters(
            &registry,
            "rdock_agent_ignored_headers_total",
            "Headers an agent asked to set on the request that were not applied, by reason.",
            &["agent", "reason"],
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
        let consumer_requests = counters(
            &registry,
            "rdock_consumer_requests_total",
            "Requests attributed to a consumer, by consumer, route and status class.",
            &["consumer", "route", "status_class"],
        )?;
        let metering_events = counters(
            &registry,
            "rdock_metering_events_total",
            "Usage metering events by sink and result (sent, failed).",
            &["sink", "result"],
        )?;
        let metering_dropped = counters(
            &registry,
            "rdock_metering_dropped_total",
            "Usage metering events dropped, by sink and reason (queue_full, undeliverable).",
            &["sink", "reason"],
        )?;
        let validation_requests = counters(
            &registry,
            "rdock_validation_requests_total",
            "Requests checked by validate middlewares, by result.",
            &["middleware", "result"],
        )?;
        let transform_skipped = counters(
            &registry,
            "rdock_transform_skipped_total",
            "Bodies a transform middleware left unchanged, by reason.",
            &["middleware", "reason"],
        )?;
        let vault_refresh_failures = registered(
            &registry,
            prometheus::IntCounter::new(
                "rdock_vault_refresh_failures_total",
                "Failed refreshes of Vault references; the last values stay in use.",
            ),
        )?;
        let quota_overflows = counters(
            &registry,
            "rdock_quota_overflows_total",
            "Requests a quota counted on a shared counter because its keys of that class were full, by middleware and class.",
            &["middleware", "class"],
        )?;
        let oidc_logins = counters(
            &registry,
            "rdock_oidc_logins_total",
            "OIDC logins completed or refused, by middleware and result.",
            &["middleware", "result"],
        )?;
        let geoip_build = gauges(
            &registry,
            "rdock_geoip_build_timestamp_seconds",
            "Build time of each GeoIP database, from its metadata.",
            &["database"],
        )?;
        let geoip_age = gauges(
            &registry,
            "rdock_geoip_database_age_seconds",
            "Age of each GeoIP database (now minus its build time).",
            &["database"],
        )?;
        let abuse_actions = counters(
            &registry,
            "rdock_abuse_actions_total",
            "Requests of banned keys denied, held or tagged, and bans started, by abuse middleware.",
            &["middleware", "action"],
        )?;
        let abuse_bans = registered(
            &registry,
            IntGauge::new(
                "rdock_abuse_bans",
                "Keys banned by abuse middlewares right now.",
            ),
        )?;
        let abuse_bans_refused = counters(
            &registry,
            "rdock_abuse_bans_refused_total",
            "Bans not started because the ban list was full.",
            &["middleware"],
        )?;
        let admission_limit = gauges(
            &registry,
            "rdock_admission_limit",
            "Current adaptive concurrency limit of each admission middleware.",
            &["middleware"],
        )?;
        let admission_in_flight = gauges(
            &registry,
            "rdock_admission_in_flight",
            "Requests in flight under each admission middleware.",
            &["middleware"],
        )?;
        let admission_shed = counters(
            &registry,
            "rdock_admission_shed_total",
            "Requests shed with 503 by admission middlewares, by priority class.",
            &["middleware", "class"],
        )?;
        let backend_addresses_refused = counters(
            &registry,
            "rdock_backend_addresses_refused_total",
            "Resolved backend addresses of tenant services that the tenant may not reach; never connected to.",
            &["service"],
        )?;
        let oidc_refreshes = counters(
            &registry,
            "rdock_oidc_refreshes_total",
            "OIDC session refreshes, by middleware and result.",
            &["middleware", "result"],
        )?;
        let oidc_provider_errors = counters(
            &registry,
            "rdock_oidc_provider_errors_total",
            "Failed requests to OIDC providers, by middleware and operation.",
            &["middleware", "operation"],
        )?;
        Ok(Self {
            admission_limit,
            admission_in_flight,
            admission_shed,
            backend_addresses_refused,
            quota_overflows,
            oidc_logins,
            oidc_refreshes,
            geoip_build,
            geoip_age,
            geoip_epochs: std::sync::Arc::default(),
            abuse_actions,
            abuse_bans,
            abuse_bans_refused,
            oidc_provider_errors,
            validation_requests,
            transform_skipped,
            vault_refresh_failures,
            consumer_requests,
            consumers_seen: std::sync::Arc::default(),
            metering_events,
            metering_dropped,
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
            tls_handshakes_in_flight,
            tls_handshake_waits,
            runtime_threads,
            upgrades,
            upgrade_draining_connections,
            upgrade_generation,
            upgrade_drain_deadline,
            proxy_protocol_rejected,
            http3_connections_total,
            http3_connections,
            http3_retries,
            http3_connections_closed,
            http3_malformed_requests,
            http3_requests,
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
            experimental_in_use,
            deprecated_in_use,
            cert_expiry,
            cert_renewal_failures,
            acme_orders,
            cluster_bundle_revision,
            cluster_bundles,
            cluster_control_connected,
            cluster_leases,
            cluster_barriers,
            cluster_limits_store_up,
            cluster_limit_claims,
            cluster_limits_members,
            control_revision,
            control_instances,
            backend_up,
            backend_ejections,
            outlier_ejections,
            retries,
            retry_budget_exhausted,
            backend_requests,
            upstream_duration,
            mirrors,
            plugin_panics,
            wasm_failures,
            agent_requests,
            agent_duration,
            agent_breaker_open,
            agent_ignored_headers,
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

    /// Counts one finished request of `consumer` on `route`.
    pub fn observe_consumer(&self, consumer: &str, route: &str, status: u16) {
        let label = {
            let mut seen = self
                .consumers_seen
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if seen.contains(consumer) {
                consumer
            } else if seen.len() < MAX_CONSUMER_LABELS {
                seen.insert(consumer.to_owned());
                consumer
            } else {
                OTHER_CONSUMERS
            }
        };
        self.consumer_requests
            .with_label_values(&[label, route, status_class(status)])
            .inc();
    }

    /// Records the build time of the GeoIP database in `role` (`country`, `asn`).
    pub fn set_geoip_build(&self, role: &str, epoch: u64) {
        self.geoip_build
            .with_label_values(&[role])
            .set(i64::try_from(epoch).unwrap_or(i64::MAX));
        if let Ok(mut epochs) = self.geoip_epochs.lock() {
            epochs.insert(role.to_owned(), epoch);
        }
    }

    /// The Prometheus text exposition of every metric.
    #[must_use]
    pub fn render(&self) -> String {
        if let Ok(epochs) = self.geoip_epochs.lock() {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            for (role, epoch) in epochs.iter() {
                self.geoip_age
                    .with_label_values(&[role])
                    .set(i64::try_from(now.saturating_sub(*epoch)).unwrap_or(i64::MAX));
            }
        }
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
