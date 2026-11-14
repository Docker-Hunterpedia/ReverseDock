//! Application logs: `tracing` to standard error, as JSON lines or text. Pingora and rustls log
//! through the `log` crate, which the subscriber bridges into `tracing`.

use std::io::IsTerminal;

use tracing_subscriber::EnvFilter;

/// Application log format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    /// JSON when standard error is not a terminal (containers, systemd), text otherwise.
    Auto,
    /// One JSON object per line.
    Json,
    /// Human-readable text.
    Text,
}

/// Installs the global subscriber. `filter` uses the `RUST_LOG` syntax, e.g. `info` or
/// `info,rdock_proxy=debug`.
pub fn init_logging(format: LogFormat, filter: &str) -> Result<(), String> {
    let filter = EnvFilter::try_new(filter).map_err(|e| format!("invalid log filter: {e}"))?;
    let json = match format {
        LogFormat::Json => true,
        LogFormat::Text => false,
        LogFormat::Auto => !std::io::stderr().is_terminal(),
    };
    // A log line that cannot be written (standard error redirected to a file on a full disk)
    // is dropped. With internal-error logging on, the subscriber reports it with `eprintln!`,
    // which panics when standard error cannot be written either: a full disk took the proxy
    // down (found by the chaos suite, ADR-0033).
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .log_internal_errors(false)
        .with_target(true);
    let result = if json {
        builder.json().flatten_event(true).try_init()
    } else {
        builder
            .with_ansi(std::io::stderr().is_terminal())
            .try_init()
    };
    result.map_err(|e| format!("cannot install the logger: {e}"))
}
