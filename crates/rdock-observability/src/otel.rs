//! OpenTelemetry traces (M-OBS-01, ADR-0022): one server span per request and one client span
//! per upstream attempt, with the stable HTTP semantic conventions, W3C Trace Context
//! propagation and parent-based ratio sampling. Spans are exported in batches over OTLP/HTTP
//! (protobuf) by the SDK's own thread; when the collector is slow the queue drops spans instead
//! of slowing requests.

use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use opentelemetry::propagation::TextMapPropagator;
use opentelemetry::trace::{
    Span as _, SpanKind, Status, TraceContextExt, Tracer as _, TracerProvider as _,
};
use opentelemetry::{Context, KeyValue};
use opentelemetry_http::{HeaderExtractor, HeaderInjector, HttpError};
use opentelemetry_otlp::{WithExportConfig, WithHttpConfig};
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::{
    BatchConfigBuilder, BatchSpanProcessor, Sampler, SdkTracerProvider,
};

/// Time allowed for one export request.
const EXPORT_TIMEOUT: Duration = Duration::from_secs(10);
/// Spans queued for export; more are dropped.
const QUEUE: usize = 4096;

/// Why tracing could not start.
#[derive(Debug, thiserror::Error)]
#[error("cannot start OpenTelemetry tracing: {0}")]
pub struct TracingError(String);

/// The tracer of one configuration (endpoint and sampling).
pub struct Tracer {
    provider: SdkTracerProvider,
    sdk: opentelemetry_sdk::trace::SdkTracer,
    endpoint: String,
    ratio: f64,
}

impl std::fmt::Debug for Tracer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tracer")
            .field("endpoint", &self.endpoint)
            .field("ratio", &self.ratio)
            .finish_non_exhaustive()
    }
}

impl Drop for Tracer {
    fn drop(&mut self) {
        // Sends what is queued; a configuration change or shutdown loses no finished span.
        let _ = self.provider.shutdown_with_timeout(Duration::from_secs(5));
    }
}

/// A span in progress; dropping it ends it.
pub type Span = opentelemetry_sdk::trace::Span;

impl Tracer {
    /// Spans to `otlp` (a base URL such as `http://tempo:4318`, to which `/v1/traces` is added,
    /// or the full traces URL), sampling `ratio` of new traces and following the caller's
    /// decision for continued ones. Must be called inside a tokio runtime, which sends exports.
    pub fn new(otlp: &url::Url, ratio: f64, version: &str) -> Result<Self, TracingError> {
        let endpoint = traces_endpoint(otlp);
        let runtime =
            tokio::runtime::Handle::try_current().map_err(|e| TracingError(e.to_string()))?;
        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_http()
            .with_endpoint(endpoint.clone())
            .with_timeout(EXPORT_TIMEOUT)
            .with_http_client(ExportClient::new(runtime))
            .build()
            .map_err(|e| TracingError(e.to_string()))?;
        let processor = BatchSpanProcessor::builder(exporter)
            .with_batch_config(
                BatchConfigBuilder::default()
                    .with_max_queue_size(QUEUE)
                    .build(),
            )
            .build();
        let resource = opentelemetry_sdk::Resource::builder()
            .with_service_name("rdock")
            .with_attributes([KeyValue::new("service.version", version.to_owned())])
            .build();
        let provider = SdkTracerProvider::builder()
            .with_span_processor(processor)
            .with_sampler(Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(
                ratio,
            ))))
            .with_resource(resource)
            .build();
        let sdk = provider.tracer("rdock");
        Ok(Self {
            provider,
            sdk,
            endpoint,
            ratio,
        })
    }

    /// Whether this tracer was built for these settings.
    #[must_use]
    pub fn is_for(&self, otlp: &url::Url, ratio: f64) -> bool {
        self.endpoint == traces_endpoint(otlp) && (self.ratio - ratio).abs() < f64::EPSILON
    }

    /// Starts the server span of a request, continuing a trace from `traceparent`.
    pub fn server(
        &self,
        headers: &http::HeaderMap,
        method: &str,
        attributes: Vec<KeyValue>,
    ) -> Context {
        let parent = TraceContextPropagator::new().extract(&HeaderExtractor(headers));
        let span = self
            .sdk
            .span_builder(method.to_owned())
            .with_kind(SpanKind::Server)
            .with_attributes(attributes)
            .start_with_context(&self.sdk, &parent);
        parent.with_span(span)
    }

    /// Starts a client span for one upstream attempt under `server`.
    pub fn client(&self, server: &Context, method: &str, attributes: Vec<KeyValue>) -> Span {
        self.sdk
            .span_builder(method.to_owned())
            .with_kind(SpanKind::Client)
            .with_attributes(attributes)
            .start_with_context(&self.sdk, server)
    }
}

/// Writes `traceparent` (and `tracestate`) for `span` under `server` into `headers`.
pub fn inject(server: &Context, span: &Span, headers: &mut http::HeaderMap) {
    let cx = server.with_remote_span_context(span.span_context().clone());
    TraceContextPropagator::new().inject_context(&cx, &mut HeaderInjector(headers));
}

/// Ends `span` with the response status: 5xx is an error for both kinds; 4xx only for client
/// spans (OpenTelemetry HTTP semantic conventions).
pub fn finish(span: &mut Span, status: u16, client: bool) {
    span.set_attribute(KeyValue::new(
        "http.response.status_code",
        i64::from(status),
    ));
    if status >= 500 || (client && status >= 400) {
        span.set_status(Status::error(""));
        span.set_attribute(KeyValue::new("error.type", status.to_string()));
    }
    span.end();
}

/// Ends `span` with a transport error such as a connect failure.
pub fn fail(span: &mut Span, error_type: &str) {
    span.set_status(Status::error(error_type.to_owned()));
    span.set_attribute(KeyValue::new("error.type", error_type.to_owned()));
    span.end();
}

/// Renames the server span to `{method} {route}` once the route is known, and records it.
pub fn set_route(server: &Context, method: &str, route: &str) {
    let span = server.span();
    span.update_name(format!("{method} {route}"));
    span.set_attribute(KeyValue::new("http.route", route.to_owned()));
}

/// Ends the server span of a request.
pub fn end_server(server: &Context, status: u16) {
    let span = server.span();
    span.set_attribute(KeyValue::new(
        "http.response.status_code",
        i64::from(status),
    ));
    if status >= 500 {
        span.set_status(Status::error(""));
        span.set_attribute(KeyValue::new("error.type", status.to_string()));
    }
    span.end();
}

fn traces_endpoint(otlp: &url::Url) -> String {
    let text = otlp.as_str().trim_end_matches('/');
    if otlp.path().trim_end_matches('/').is_empty() {
        format!("{text}/v1/traces")
    } else {
        text.to_owned()
    }
}

/// The OTLP exporter's HTTP client: hyper with rustls on ring and the OS roots. The SDK exports
/// from its own thread, so each request is run on the tokio runtime captured at start.
#[derive(Debug)]
struct ExportClient {
    runtime: tokio::runtime::Handle,
    client: hyper_util::client::legacy::Client<
        hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
        Full<Bytes>,
    >,
}

impl ExportClient {
    fn new(runtime: tokio::runtime::Handle) -> Self {
        let _guard = runtime.enter();
        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_platform_verifier()
            .https_or_http()
            .enable_http1()
            .build();
        let client =
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .build(https);
        Self { runtime, client }
    }
}

#[async_trait]
impl opentelemetry_http::HttpClient for ExportClient {
    async fn send_bytes(
        &self,
        request: http::Request<Bytes>,
    ) -> Result<http::Response<Bytes>, HttpError> {
        let client = self.client.clone();
        let request = request.map(Full::new);
        let task = self.runtime.spawn(async move {
            let response = tokio::time::timeout(EXPORT_TIMEOUT, client.request(request))
                .await
                .map_err(|_| "the OTLP collector did not answer in time")??;
            let (parts, body) = response.into_parts();
            let body = Limited::new(body, 1024 * 1024)
                .collect()
                .await
                .map_err(|e| e.to_string())?
                .to_bytes();
            Ok::<_, HttpError>(http::Response::from_parts(parts, body))
        });
        task.await?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_traces_path_is_added_to_a_base_url() {
        let base: url::Url = "http://tempo:4318".parse().unwrap();
        assert_eq!(traces_endpoint(&base), "http://tempo:4318/v1/traces");
        let full: url::Url = "https://otlp.example.com/otlp/v1/traces".parse().unwrap();
        assert_eq!(
            traces_endpoint(&full),
            "https://otlp.example.com/otlp/v1/traces"
        );
    }
}
