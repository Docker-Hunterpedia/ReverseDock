#![doc = include_str!("../README.md")]

mod access;
pub mod alerts;
pub mod feed;
pub mod live;
mod logging;
pub mod metering;
mod metrics;
pub mod otel;
pub mod vault;

pub use access::{AccessLog, AccessRecord, rfc3339};
pub use alerts::deliver::private as is_private_address;
pub use logging::{LogFormat, init_logging};
pub use metrics::{
    IntCounter, IntGauge, METRIC_FEATURES, MetricInfo, Metrics, metric_feature, status_class,
};
pub use opentelemetry::KeyValue;
pub use otel::{Tracer, TracingError};
