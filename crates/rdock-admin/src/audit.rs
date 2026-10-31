//! The audit log (ADR-0024): one JSON line per admin write, login, MFA event, refusal and
//! session end, in `$RDOCK_DATA_DIR/audit/` (mode 0600). Each line carries a sequence number
//! and the SHA-256 of the previous line, across rotated files, so a removed or edited line
//! breaks the chain; [`verify`] (`rdock audit verify`) checks it. Never a secret.

use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{SyncSender, TrySendError};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use ring::digest::{SHA256, digest};
use serde_json::{Value, json};

/// The `prev` of the very first record.
const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
/// Records waiting for the syslog forwarder; past it they are dropped (and counted in the log).
const FORWARD_QUEUE: usize = 1024;

/// How a record ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Done.
    Ok,
    /// Refused: wrong credentials, missing role, rate limit.
    Denied,
    /// Tried and failed (for example a rejected configuration).
    Failed,
}

impl Outcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Denied => "denied",
            Self::Failed => "failed",
        }
    }
}

/// One thing that happened.
#[derive(Debug, Clone)]
pub struct Event {
    /// User name, `token:<id>`, `cli`, `bootstrap`, or `-` when unknown.
    pub actor: String,
    /// `password`, `session`, `token`, `socket`, `bootstrap`, `totp`, `recovery_code`.
    pub method: &'static str,
    /// Client address, when the request came over TCP.
    pub client: Option<IpAddr>,
    /// What was done, for example `login`, `user.create`, `config.reload`.
    pub action: &'static str,
    /// What it was done to, for example a user name or token ID.
    pub resource: Option<String>,
    /// How it ended.
    pub outcome: Outcome,
    /// Why, for refusals and failures.
    pub reason: Option<String>,
    /// Hashes of the configuration before and after a change.
    pub config: Option<(String, String)>,
}

impl Event {
    /// An event with the usual defaults; set the rest with struct update syntax.
    #[must_use]
    pub fn new(actor: impl Into<String>, method: &'static str, action: &'static str) -> Self {
        Self {
            actor: actor.into(),
            method,
            client: None,
            action,
            resource: None,
            outcome: Outcome::Ok,
            reason: None,
            config: None,
        }
    }
}

struct Writer {
    file: Option<File>,
    size: u64,
    seq: u64,
    prev: String,
}

/// The log: one writer, records appended under a lock.
pub struct Audit {
    dir: PathBuf,
    max_bytes: u64,
    retention: Duration,
    writer: Mutex<Writer>,
    forward: Option<SyncSender<String>>,
    /// The events stream, which shows admin actions as they happen.
    events: std::sync::OnceLock<std::sync::Arc<crate::stream::Hub>>,
}

fn sha256_hex(bytes: &[u8]) -> String {
    crate::hex(digest(&SHA256, bytes).as_ref())
}

/// The log files, oldest first (`audit-<first sequence number>.jsonl`).
fn files(dir: &Path) -> io::Result<Vec<PathBuf>> {
    let mut found: Vec<(u64, PathBuf)> = match std::fs::read_dir(dir) {
        Ok(entries) => entries
            .filter_map(Result::ok)
            .filter_map(|e| {
                let name = e.file_name().into_string().ok()?;
                let seq = name
                    .strip_prefix("audit-")?
                    .strip_suffix(".jsonl")?
                    .parse()
                    .ok()?;
                Some((seq, e.path()))
            })
            .collect(),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(err) => return Err(err),
    };
    found.sort();
    Ok(found.into_iter().map(|(_, path)| path).collect())
}

fn last_line(path: &Path) -> io::Result<Option<String>> {
    let mut last = None;
    for line in BufReader::new(File::open(path)?).lines() {
        let line = line?;
        if !line.is_empty() {
            last = Some(line);
        }
    }
    Ok(last)
}

fn open_append(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path)
}

impl Audit {
    /// Opens the log in `dir`, continuing the chain of the newest file.
    pub fn open(
        dir: &Path,
        max_bytes: u64,
        retention: Duration,
        forward: Option<&rdock_model::settings::AuditForward>,
    ) -> io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        std::fs::set_permissions(dir, std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
        let (seq, prev) = match files(dir)?.last() {
            Some(path) => match last_line(path)? {
                Some(line) => {
                    let record: Value = serde_json::from_str(&line)
                        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
                    let seq = record["seq"].as_u64().unwrap_or(0);
                    (seq, sha256_hex(line.as_bytes()))
                }
                None => (0, GENESIS.to_owned()),
            },
            None => (0, GENESIS.to_owned()),
        };
        Ok(Self {
            dir: dir.to_owned(),
            max_bytes,
            retention,
            writer: Mutex::new(Writer {
                file: None,
                size: 0,
                seq,
                prev,
            }),
            forward: forward.map(syslog::start),
            events: std::sync::OnceLock::new(),
        })
    }

    /// Also publishes every record on the events stream (`type: admin`).
    pub(crate) fn set_events(&self, hub: std::sync::Arc<crate::stream::Hub>) {
        let _ = self.events.set(hub);
    }

    /// Appends a record. A failure to write is logged and never fails the request.
    pub fn record(&self, event: Event) {
        if let Err(err) = self.append(event) {
            tracing::error!(error = %err, dir = %self.dir.display(), "cannot write the audit log");
        }
    }

    fn append(&self, event: Event) -> io::Result<()> {
        let mut writer = self.writer.lock().unwrap_or_else(PoisonError::into_inner);
        let seq = writer.seq + 1;
        let mut record = json!({
            "time": rdock_observability::rfc3339(SystemTime::now()),
            "seq": seq,
            "actor": event.actor,
            "method": event.method,
            "client": event.client,
            "action": event.action,
            "resource": event.resource,
            "result": event.outcome.as_str(),
            "reason": event.reason,
            "prev": writer.prev,
        });
        if let Some((before, after)) = event.config {
            record["config_before"] = json!(before);
            record["config_after"] = json!(after);
        }
        let line = record.to_string();
        if writer.file.is_none() || writer.size + line.len() as u64 + 1 > self.max_bytes {
            let path = self.dir.join(format!("audit-{seq:012}.jsonl"));
            writer.file = Some(open_append(&path)?);
            writer.size = 0;
            self.prune();
        }
        if let Some(file) = writer.file.as_mut() {
            file.write_all(line.as_bytes())?;
            file.write_all(b"\n")?;
            file.sync_data()?;
        }
        writer.size += line.len() as u64 + 1;
        writer.seq = seq;
        writer.prev = sha256_hex(line.as_bytes());
        if let Some(hub) = self.events.get() {
            let mut event = record;
            event["type"] = json!("admin");
            hub.publish(event);
        }
        if let Some(forward) = &self.forward
            && let Err(TrySendError::Full(_)) = forward.try_send(line)
        {
            tracing::warn!("the audit forwarder is behind; a record was not forwarded");
        }
        Ok(())
    }

    /// Deletes files older than the retention, keeping the newest so the chain continues.
    fn prune(&self) {
        let Ok(list) = files(&self.dir) else { return };
        let Some((_, older)) = list.split_last() else {
            return;
        };
        for path in older {
            let old = std::fs::metadata(path)
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.elapsed().ok())
                .is_some_and(|age| age > self.retention);
            if old && let Err(err) = std::fs::remove_file(path) {
                tracing::warn!(file = %path.display(), error = %err, "cannot remove an old audit file");
            }
        }
    }

    /// Up to `limit` records, newest first, with a sequence number below `before`.
    pub fn recent(&self, limit: usize, before: Option<u64>) -> io::Result<Vec<Value>> {
        let mut out = Vec::new();
        for path in files(&self.dir)?.iter().rev() {
            let mut lines: Vec<Value> = BufReader::new(File::open(path)?)
                .lines()
                .map_while(Result::ok)
                .filter_map(|line| serde_json::from_str(&line).ok())
                .filter(|r: &Value| before.is_none_or(|b| r["seq"].as_u64().is_some_and(|s| s < b)))
                .collect();
            lines.reverse();
            for record in lines {
                if out.len() == limit {
                    return Ok(out);
                }
                out.push(record);
            }
        }
        Ok(out)
    }
}

/// What [`verify`] found.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Every link holds.
    Intact {
        /// Records checked.
        records: u64,
        /// Files checked.
        files: usize,
    },
    /// The first broken link.
    Broken {
        /// The file.
        file: PathBuf,
        /// Line number in it, from 1.
        line: usize,
        /// What is wrong.
        reason: String,
    },
}

/// Checks the chain of every file in `dir`. Rotated files removed by the retention break the
/// chain only at the oldest kept file, whose first record links to one that is gone; that link
/// is accepted.
pub fn verify(dir: &Path) -> io::Result<Verdict> {
    let list = files(dir)?;
    let mut prev: Option<(u64, String)> = None;
    let mut records = 0;
    for path in &list {
        for (index, line) in BufReader::new(File::open(path)?).lines().enumerate() {
            let line = line?;
            let broken = |reason: String| Verdict::Broken {
                file: path.clone(),
                line: index + 1,
                reason,
            };
            let Ok(record) = serde_json::from_str::<Value>(&line) else {
                return Ok(broken("not a JSON record".into()));
            };
            let seq = record["seq"].as_u64().unwrap_or(0);
            let previous_hash = record["prev"].as_str().unwrap_or_default();
            if let Some((last_seq, last_hash)) = &prev {
                if seq != last_seq + 1 {
                    return Ok(broken(format!("sequence {seq} follows {last_seq}")));
                }
                if previous_hash != last_hash {
                    return Ok(broken("the previous line was changed or removed".into()));
                }
            } else if seq == 1 && previous_hash != GENESIS {
                return Ok(broken("the first record does not start the chain".into()));
            }
            prev = Some((seq, sha256_hex(line.as_bytes())));
            records += 1;
        }
    }
    Ok(Verdict::Intact {
        records,
        files: list.len(),
    })
}

mod syslog {
    //! A background thread sends each record as an RFC 5424 message, over UDP or TCP with
    //! octet counting (RFC 6587), reconnecting after errors. Never on the request path.

    use std::io::Write;
    use std::net::{TcpStream, UdpSocket};
    use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
    use std::time::Duration;

    use rdock_model::settings::{AuditForward, SyslogTransport};

    /// `authpriv` (10) × 8 + `notice` (5).
    const PRI: u8 = 85;

    fn message(record: &str) -> String {
        let time = rdock_observability::rfc3339(std::time::SystemTime::now());
        format!("<{PRI}>1 {time} - rdock - audit - {record}")
    }

    pub(super) fn start(forward: &AuditForward) -> SyncSender<String> {
        let (tx, rx) = sync_channel::<String>(super::FORWARD_QUEUE);
        let target = forward.syslog.clone();
        let transport = forward.transport;
        let spawned = std::thread::Builder::new()
            .name("rdock-audit-syslog".into())
            .spawn(move || run(&target, transport, &rx));
        if let Err(err) = spawned {
            tracing::error!(error = %err, "cannot start the audit forwarder");
        }
        tx
    }

    fn run(target: &str, transport: SyslogTransport, rx: &Receiver<String>) {
        let mut tcp: Option<TcpStream> = None;
        let udp = UdpSocket::bind("0.0.0.0:0").ok();
        while let Ok(record) = rx.recv() {
            let message = message(&record);
            let sent = match transport {
                SyslogTransport::Udp => udp
                    .as_ref()
                    .ok_or_else(|| std::io::Error::other("no UDP socket"))
                    .and_then(|s| s.send_to(message.as_bytes(), target).map(|_| ())),
                SyslogTransport::Tcp => {
                    if tcp.is_none() {
                        tcp = TcpStream::connect(target).ok();
                        if let Some(stream) = &tcp {
                            let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
                        }
                    }
                    match tcp.as_mut() {
                        Some(stream) => write!(stream, "{} {message}", message.len()),
                        None => Err(std::io::Error::other("not connected")),
                    }
                }
            };
            if let Err(err) = sent {
                tcp = None;
                tracing::warn!(error = %err, target, "cannot forward an audit record");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn audit(dir: &Path, max_bytes: u64) -> Audit {
        Audit::open(dir, max_bytes, Duration::from_secs(86_400), None).unwrap()
    }

    fn login(actor: &str) -> Event {
        Event::new(actor, "password", "login")
    }

    #[test]
    fn records_chain_across_rotation_and_restarts() {
        let dir = tempfile::tempdir().unwrap();
        let log = audit(dir.path(), 400);
        for name in ["a", "b", "c", "d", "e"] {
            log.record(login(name));
        }
        drop(log);
        let again = audit(dir.path(), 400);
        again.record(Event {
            outcome: Outcome::Denied,
            reason: Some("wrong password".into()),
            ..login("f")
        });
        assert!(
            files(dir.path()).unwrap().len() > 1,
            "400-byte files rotate"
        );
        assert_eq!(
            verify(dir.path()).unwrap(),
            Verdict::Intact {
                records: 6,
                files: files(dir.path()).unwrap().len()
            }
        );
        let recent = again.recent(2, None).unwrap();
        assert_eq!(recent[0]["actor"], "f");
        assert_eq!(recent[0]["result"], "denied");
        assert_eq!(recent[1]["seq"], 5);
        let mode = std::os::unix::fs::PermissionsExt::mode(
            &std::fs::metadata(&files(dir.path()).unwrap()[0])
                .unwrap()
                .permissions(),
        );
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn an_edited_or_removed_line_breaks_the_chain() {
        let dir = tempfile::tempdir().unwrap();
        let log = audit(dir.path(), 1 << 20);
        for name in ["a", "b", "c"] {
            log.record(login(name));
        }
        let path = files(dir.path()).unwrap()[0].clone();
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, text.replace("\"actor\":\"b\"", "\"actor\":\"x\"")).unwrap();
        assert!(matches!(
            verify(dir.path()).unwrap(),
            Verdict::Broken { line: 3, .. }
        ));

        let lines: Vec<&str> = text.lines().collect();
        std::fs::write(&path, format!("{}\n{}\n", lines[0], lines[2])).unwrap();
        assert!(matches!(
            verify(dir.path()).unwrap(),
            Verdict::Broken { line: 2, .. }
        ));
    }
}
