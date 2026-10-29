//! The access log: one line per request on standard output, written by a dedicated thread so a
//! slow log consumer never blocks request handling (lines are dropped and counted instead).

use std::io::{BufWriter, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::time::{SystemTime, UNIX_EPOCH};

use rdock_model::settings::{AccessLog as AccessLogConfig, LogFormat};
use serde::Serialize;

/// Lines buffered before new ones are dropped.
const QUEUE: usize = 16_384;

/// One request, as logged. Query strings are not logged (only their length) because they often
/// carry tokens; headers listed in `observability.access_log.redact` are replaced by `***`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct AccessRecord {
    /// Time the request started (RFC 3339, UTC).
    pub ts: String,
    /// Request ID.
    pub request_id: String,
    /// Client IP after trusted-proxy handling.
    pub client_ip: String,
    /// Method.
    pub method: String,
    /// Host without port.
    pub host: String,
    /// Path as received.
    pub path: String,
    /// Length of the query string.
    pub query_len: usize,
    /// `HTTP/1.1` or `HTTP/2`.
    pub proto: String,
    /// Status sent to the client.
    pub status: u16,
    /// Request body bytes received.
    pub bytes_in: usize,
    /// Response body bytes sent.
    pub bytes_out: usize,
    /// Total time in milliseconds.
    pub duration_ms: f64,
    /// Listener name.
    pub listener: String,
    /// Matched route.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route: Option<String>,
    /// Service.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    /// Backend address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream: Option<String>,
    /// TLS version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_version: Option<String>,
    /// TLS cipher suite.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_cipher: Option<String>,
    /// TLS server name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    /// User authenticated by a middleware.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// `User-Agent`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    /// `Referer` without its query string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub referer: Option<String>,
    /// `CF-Ray`, when the request came through Cloudflare.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cf_ray: Option<String>,
    /// Error that ended the request, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// The access-log writer.
#[derive(Debug)]
pub struct AccessLog {
    sender: Option<SyncSender<Vec<u8>>>,
    config: AccessLogConfig,
    redact: Vec<String>,
    dropped: AtomicU64,
}

impl AccessLog {
    /// Starts the writer thread for `config` (no thread when the log is off).
    #[must_use]
    pub fn new(config: &AccessLogConfig) -> Self {
        let sender = (config.format != LogFormat::Off).then(|| {
            let (sender, receiver) = sync_channel(QUEUE);
            std::thread::Builder::new()
                .name("rdock-access-log".to_owned())
                .spawn(move || write_lines(&receiver))
                .ok()
                .map(|_| sender)
        });
        Self {
            sender: sender.flatten(),
            config: config.clone(),
            redact: config
                .redact
                .iter()
                .map(|h| h.to_ascii_lowercase())
                .collect(),
            dropped: AtomicU64::new(0),
        }
    }

    /// The configuration this writer was started with.
    #[must_use]
    pub fn config(&self) -> &AccessLogConfig {
        &self.config
    }

    /// Whether `record` is logged when the sampling draw is `draw` (in `[0, 1)`).
    fn keeps(&self, record: &AccessRecord, draw: f64) -> bool {
        record.status >= 400 || record.error.is_some() || draw < self.config.sample
    }

    /// Whether the header `name` (lower case) is redacted.
    #[must_use]
    pub fn redacts(&self, name: &str) -> bool {
        self.redact.iter().any(|r| r == name)
    }

    /// Queues a record, unless `sample` leaves out this successful request. Never blocks.
    pub fn write(&self, record: &AccessRecord) {
        let Some(sender) = &self.sender else { return };
        if !self.keeps(record, fastrand::f64()) {
            return;
        }
        let mut line = match self.config.format {
            LogFormat::Json => serde_json::to_vec(record).unwrap_or_default(),
            LogFormat::Text => text_line(record).into_bytes(),
            LogFormat::Off => return,
        };
        line.push(b'\n');
        match sender.try_send(line) {
            Ok(()) => {}
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Lines dropped because the writer could not keep up.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

fn write_lines(receiver: &Receiver<Vec<u8>>) {
    let mut out = BufWriter::new(std::io::stdout());
    while let Ok(line) = receiver.recv() {
        let _ = out.write_all(&line);
        while let Ok(more) = receiver.try_recv() {
            let _ = out.write_all(&more);
        }
        let _ = out.flush();
    }
}

fn text_line(r: &AccessRecord) -> String {
    format!(
        "{} {} \"{} {} {}\" {} {} {:.1}ms route={} service={} upstream={} id={}",
        r.ts,
        r.client_ip,
        r.method,
        r.path,
        r.proto,
        r.status,
        r.bytes_out,
        r.duration_ms,
        r.route.as_deref().unwrap_or("-"),
        r.service.as_deref().unwrap_or("-"),
        r.upstream.as_deref().unwrap_or("-"),
        r.request_id
    )
}

/// `SystemTime` as RFC 3339 in UTC with milliseconds, e.g. `2026-10-26T16:13:05.123Z`.
#[must_use]
pub fn rfc3339(time: SystemTime) -> String {
    let since = time.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = since.as_secs();
    let days = i64::try_from(secs / 86_400).unwrap_or(0);
    let rem = secs % 86_400;
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        rem / 3_600,
        (rem % 3_600) / 60,
        rem % 60,
        since.subsec_millis()
    )
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn formats_timestamps() {
        let t = UNIX_EPOCH + Duration::from_millis(1_793_031_185_123);
        assert_eq!(rfc3339(t), "2026-10-26T16:13:05.123Z");
        assert_eq!(rfc3339(UNIX_EPOCH), "1970-01-01T00:00:00.000Z");
        let leap = UNIX_EPOCH + Duration::from_secs(951_782_400);
        assert_eq!(rfc3339(leap), "2000-02-29T00:00:00.000Z");
    }

    #[test]
    fn redaction_and_text_lines() {
        let log = AccessLog::new(&AccessLogConfig {
            format: LogFormat::Off,
            redact: vec!["User-Agent".into()],
            sample: 1.0,
        });
        assert!(log.redacts("user-agent"));
        assert!(!log.redacts("referer"));
        log.write(&AccessRecord::default());
        assert_eq!(log.dropped(), 0);
        let line = text_line(&AccessRecord {
            method: "GET".into(),
            path: "/".into(),
            proto: "HTTP/1.1".into(),
            status: 200,
            ..AccessRecord::default()
        });
        assert!(line.contains("\"GET / HTTP/1.1\" 200"), "{line}");
    }

    #[test]
    fn sampling_keeps_every_error() {
        let log = AccessLog::new(&AccessLogConfig {
            format: LogFormat::Off,
            redact: Vec::new(),
            sample: 0.1,
        });
        let ok = AccessRecord {
            status: 200,
            ..AccessRecord::default()
        };
        assert!(log.keeps(&ok, 0.05));
        assert!(!log.keeps(&ok, 0.5));
        let server_error = AccessRecord {
            status: 502,
            ..AccessRecord::default()
        };
        assert!(log.keeps(&server_error, 0.99));
        let not_found = AccessRecord {
            status: 404,
            ..AccessRecord::default()
        };
        assert!(log.keeps(&not_found, 0.99));
        let failed = AccessRecord {
            status: 200,
            error: Some("reset".into()),
            ..AccessRecord::default()
        };
        assert!(log.keeps(&failed, 0.99));
    }
}
