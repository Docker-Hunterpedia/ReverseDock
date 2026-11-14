//! The audit log (ADR-0024): one JSON line per admin write, login, MFA event, refusal and
//! session end, in `$RDOCK_DATA_DIR/audit/` (mode 0600). Each line carries a sequence number
//! and the SHA-256 of the previous line, across rotated files, so a removed or edited line
//! breaks the chain; [`verify`] (`rdock audit verify`) checks it. Never a secret.
//!
//! **A full disk** (ADR-0033): a mutating admin call first asks [`Audit::prepare`] for room,
//! which reserves [`RESERVE`] bytes past the end of the newest file (`fallocate` with
//! `KEEP_SIZE`, or a free-space check where the file system cannot reserve). When that fails,
//! the call is refused with `507` before it changes anything, so no change is applied and then
//! left unaudited for lack of space. A record that still cannot be written (an I/O error other
//! than space) is cut off the file again, so the chain never ends in half a record, and counted;
//! the next [`Audit::prepare`] first writes an `audit.gap` record that says how many records
//! were lost, and refuses the call if even that cannot be written.

use std::collections::HashMap;
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
/// Bytes reserved past the end of the log before a mutating call: a few dozen records.
pub const RESERVE: u64 = 16 * 1024;

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
    /// The tenant of a tenant-scoped caller (H-SEC-07); such callers read only their tenant's
    /// records.
    pub tenant: Option<String>,
    /// How many refusals like this one (same action and client) were not written in the
    /// window before it ([`Audit::record`] coalesces refusals); in a summary record (its
    /// reason starts with `summary:`), how many it stands for.
    pub repeated: u64,
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
            tenant: None,
            repeated: 0,
        }
    }
}

struct Writer {
    file: Option<File>,
    /// The file `file` writes, or the newest file when none is open yet.
    path: Option<PathBuf>,
    /// Bytes of complete records in `path`; a write that fails is cut back to this.
    size: u64,
    seq: u64,
    prev: String,
    /// `path` may end in part of a record (a failed write that could not be cut off, or a
    /// crash): it is cut back to `size` before the next record is appended.
    torn: bool,
    /// Records that could not be written since the last one that was.
    lost: u64,
}

/// The log: one writer, records appended under a lock.
pub struct Audit {
    dir: PathBuf,
    max_bytes: u64,
    retention: Duration,
    writer: Mutex<Writer>,
    forward: Option<SyncSender<String>>,
    /// Records that could not be written, for `rdock_admin_audit_write_failures_total`.
    write_failures: std::sync::atomic::AtomicU64,
    /// Mutating calls refused by [`Audit::prepare`], for `rdock_admin_audit_refusals_total`.
    refusals: std::sync::atomic::AtomicU64,
    /// The events stream, which shows admin actions as they happen.
    events: std::sync::OnceLock<std::sync::Arc<crate::stream::Hub>>,
    /// Security-relevant records also raise an alert (`observability.alerts`, rule `security`).
    alerts: std::sync::OnceLock<rdock_observability::alerts::AlertSink>,
    /// Refusals written in the current window, by what and from where, with how many more
    /// came since (see [`Audit::coalesce`]).
    repeats: Mutex<Repeats>,
}

/// How long refusals of one kind from one client are written as one record.
const REPEAT_WINDOW: Duration = Duration::from_secs(60);
/// Refusal kinds tracked at once. One client holds at most one per action (a handful), so it
/// takes thousands of clients to fill; past it, each new client gets one entry for all its
/// refusals ([`OVERFLOW_KEYS`] of them), and past those they share one.
const REPEAT_KEYS: usize = 4096;
/// Per-client entries past [`REPEAT_KEYS`].
const OVERFLOW_KEYS: usize = 1024;

/// The refusals being coalesced and when entries past their window were last cleared.
struct Repeats {
    map: HashMap<String, Repeat>,
    pruned: std::time::Instant,
}

/// A refusal kind in its window: when the window started, how many records were not written
/// since, and the first one, which a summary is written from when the window ends unseen.
struct Repeat {
    since: std::time::Instant,
    skipped: u64,
    first: Event,
}

impl Repeat {
    /// The record written for refusals counted but not written when their entry is dropped:
    /// the first one's fields, `repeated` set, and the reason marked as a summary.
    fn summary(self) -> Option<Event> {
        (self.skipped > 0).then(|| Event {
            repeated: self.skipped,
            reason: Some(format!(
                "summary: {} more refusals like this one in the window were not written",
                self.skipped
            )),
            ..self.first
        })
    }
}

/// The client a refusal is coalesced by: an IPv4 address, or the /64 of an IPv6 one, which
/// one subscriber usually holds.
fn client_key(client: Option<IpAddr>) -> String {
    match client {
        Some(IpAddr::V6(v6)) if v6.to_ipv4_mapped().is_none() => {
            let prefix = u128::from(v6) & !((1u128 << 64) - 1);
            format!("{}/64", std::net::Ipv6Addr::from(prefix))
        }
        Some(IpAddr::V6(v6)) => v6
            .to_ipv4_mapped()
            .map(|v4| v4.to_string())
            .unwrap_or_default(),
        Some(ip) => ip.to_string(),
        None => "-".to_owned(),
    }
}

/// The key a refusal is coalesced under: what was refused and the client. Not the name the
/// caller typed or the reason, which the caller chooses: one client gets one entry per action
/// however many names it tries.
fn repeat_key(event: &Event) -> String {
    format!("{}\u{0}{}", event.action, client_key(event.client))
}

fn sha256_hex(bytes: &[u8]) -> String {
    crate::hex(digest(&SHA256, bytes).as_ref())
}

impl Drop for Audit {
    /// Refusals counted but not written yet are summarised before the log closes.
    fn drop(&mut self) {
        self.flush_repeats();
    }
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

/// The last complete line of `path` and the length of the file up to the end of it. Bytes
/// after the last newline are part of a record whose write did not finish: not a record.
fn last_line(path: &Path) -> io::Result<(Option<String>, u64)> {
    let bytes = std::fs::read(path)?;
    let complete = bytes.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
    let text = String::from_utf8_lossy(&bytes[..complete]);
    let last = text
        .lines()
        .rev()
        .find(|line| !line.is_empty())
        .map(str::to_owned);
    Ok((last, complete as u64))
}

fn open_append(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path)
}

/// The last sequence number, the hash of the last line, and the newest file with the length
/// of its complete records.
type Head = (u64, String, Option<(PathBuf, u64)>);

/// The end of the chain in `dir`: the last sequence number, the hash of the last line, the
/// newest file and the length of its complete records.
fn head(dir: &Path) -> io::Result<Head> {
    let Some(path) = files(dir)?.pop() else {
        return Ok((0, GENESIS.to_owned(), None));
    };
    match last_line(&path)? {
        (Some(line), complete) => {
            let record: Value = serde_json::from_str(&line)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
            let seq = record["seq"].as_u64().unwrap_or(0);
            Ok((seq, sha256_hex(line.as_bytes()), Some((path, complete))))
        }
        (None, complete) => Ok((0, GENESIS.to_owned(), Some((path, complete)))),
    }
}

/// A writer at the end of the chain `head` found.
fn writer_at(seq: u64, prev: String, newest: Option<(PathBuf, u64)>) -> io::Result<Writer> {
    let (path, size, torn) = match newest {
        Some((path, complete)) => {
            let len = std::fs::metadata(&path)?.len();
            (Some(path), complete, len != complete)
        }
        None => (None, 0, false),
    };
    Ok(Writer {
        file: None,
        path,
        size,
        seq,
        prev,
        torn,
        lost: 0,
    })
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
        let (seq, prev, newest) = head(dir)?;
        let mut writer = writer_at(seq, prev, newest)?;
        // A new process starts a new file, as before. A torn end of the old one (a crash
        // during a write) is cut off first, so `rdock audit verify` does not read it as a
        // damaged record later; if that fails it is logged and left (the chain stays valid
        // from the next file on).
        if writer.torn
            && let Some(path) = writer.path.clone()
        {
            let cut = open_append(&path).and_then(|file| {
                writer.file = Some(file);
                repair(&mut writer)
            });
            if let Err(err) = cut {
                tracing::warn!(file = %path.display(), error = %err,
                    "cannot cut the incomplete last record of the audit log");
            }
            writer.file = None;
        }
        writer.path = None;
        writer.size = 0;
        writer.torn = false;
        Ok(Self {
            dir: dir.to_owned(),
            max_bytes,
            retention,
            writer: Mutex::new(writer),
            forward: forward.map(syslog::start),
            write_failures: std::sync::atomic::AtomicU64::new(0),
            refusals: std::sync::atomic::AtomicU64::new(0),
            events: std::sync::OnceLock::new(),
            alerts: std::sync::OnceLock::new(),
            repeats: Mutex::new(Repeats {
                map: HashMap::new(),
                pruned: std::time::Instant::now(),
            }),
        })
    }

    /// Reads the end of the chain from the files again and appends to the newest one. A binary
    /// upgrade calls this when the process becomes the log's writer: the other process may have
    /// appended records since this one opened the log.
    ///
    /// # Errors
    ///
    /// The files cannot be read; the chain in memory is unchanged.
    pub fn resync(&self) -> io::Result<()> {
        let (seq, prev, newest) = head(&self.dir)?;
        let mut fresh = writer_at(seq, prev, newest)?;
        if let Some(path) = &fresh.path {
            fresh.file = Some(open_append(path)?);
            repair(&mut fresh)?;
        }
        let mut writer = self.writer.lock().unwrap_or_else(PoisonError::into_inner);
        fresh.lost = writer.lost;
        *writer = fresh;
        Ok(())
    }

    /// Makes sure the record of a mutating call can be written before the call changes
    /// anything (ADR-0033): writes the `audit.gap` record first when records were lost, then
    /// reserves [`RESERVE`] bytes past the end of the newest file.
    ///
    /// # Errors
    ///
    /// No room, or the gap record cannot be written: the caller refuses the call (`507`).
    pub fn prepare(&self) -> io::Result<()> {
        let mut writer = self.writer.lock().unwrap_or_else(PoisonError::into_inner);
        if writer.lost > 0 {
            let lost = writer.lost;
            let gap = Event {
                outcome: Outcome::Failed,
                reason: Some(format!(
                    "{lost} audit record(s) could not be written before this one"
                )),
                ..Event::new("rdock", "-", "audit.gap")
            };
            let record = self.append_locked(&mut writer, gap)?;
            writer.lost = 0;
            drop(writer);
            self.announce(record);
            tracing::warn!(lost, "the audit log takes records again");
            writer = self.writer.lock().unwrap_or_else(PoisonError::into_inner);
        }
        let reserve = RESERVE.min(self.max_bytes / 2).max(1);
        if writer.file.is_none() || (writer.size > 0 && writer.size + reserve > self.max_bytes) {
            let seq = writer.seq + 1;
            self.open_file(&mut writer, seq)?;
        }
        let Some(file) = writer.file.as_ref() else {
            return Err(io::Error::other("the audit log has no open file"));
        };
        // `fallocate` with `KEEP_SIZE` is not bound by the file-size limit, appends are.
        if rdock_config::disk::file_size_limit().is_some_and(|limit| writer.size + reserve > limit)
        {
            return Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                "the process's file-size limit leaves no room for the next audit record",
            ));
        }
        if !rdock_config::disk::reserve(file, writer.size, reserve)? {
            rdock_config::disk::check_room(&self.dir, reserve).map_err(io::Error::other)?;
        }
        Ok(())
    }

    /// Opens the file the next record goes to: the newest one (cut back to its complete
    /// records) when it can still take records, else a new one named after `seq`.
    fn open_file(&self, writer: &mut Writer, seq: u64) -> io::Result<()> {
        let reusable = writer.file.is_none()
            && writer.path.is_some()
            && writer.size + RESERVE.min(self.max_bytes / 2) <= self.max_bytes;
        if reusable && let Some(path) = writer.path.clone() {
            writer.file = Some(open_append(&path)?);
            return repair(writer);
        }
        let path = self.dir.join(format!("audit-{seq:012}.jsonl"));
        let file = open_append(&path)?;
        writer.size = file.metadata()?.len();
        writer.torn = false;
        writer.file = Some(file);
        writer.path = Some(path);
        self.prune();
        repair(writer)
    }

    /// Also publishes every record on the events stream (`type: admin`).
    pub(crate) fn set_events(&self, hub: std::sync::Arc<crate::stream::Hub>) {
        let _ = self.events.set(hub);
    }

    /// Raises a `security` alert for the records that call for one.
    pub(crate) fn set_alerts(&self, sink: rdock_observability::alerts::AlertSink) {
        let _ = self.alerts.set(sink);
    }

    /// Appends a record. A failure to write is logged and counted, and the next
    /// [`Audit::prepare`] records the gap; it never fails the request, so a call that
    /// [`Audit::prepare`] admitted, a login or a refusal is answered either way.
    pub fn record(&self, event: Event) {
        let (event, summaries) = self.coalesce(event);
        for summary in summaries.into_iter().chain(event) {
            self.write(summary);
        }
    }

    fn write(&self, event: Event) {
        let action = event.action;
        let actor = event.actor.clone();
        let mut writer = self.writer.lock().unwrap_or_else(PoisonError::into_inner);
        match self.append_locked(&mut writer, event) {
            Ok(record) => {
                drop(writer);
                self.announce(record);
            }
            Err(err) => {
                writer.lost += 1;
                drop(writer);
                self.write_failures
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                tracing::error!(error = %err, dir = %self.dir.display(), action, actor = %actor,
                    "cannot write the audit log; the record is lost and the next mutating call records the gap");
            }
        }
    }

    /// Writes a summary of every refusal counted but not written yet (at shutdown).
    pub fn flush_repeats(&self) {
        let pending: Vec<Repeat> = {
            let mut repeats = self.repeats.lock().unwrap_or_else(PoisonError::into_inner);
            repeats.map.drain().map(|(_, r)| r).collect()
        };
        for summary in pending.into_iter().filter_map(Repeat::summary) {
            self.write(summary);
        }
    }

    /// Refusals (`denied`) of unidentified callers of one kind from one client are written once per
    /// [`REPEAT_WINDOW`]: the first is written, the others are counted, and the first one of
    /// the next window says how many were not written (`repeated`); when no next one comes, a
    /// summary record says it once the entry is cleared (at most a window later, or at
    /// shutdown). Anyone who can reach the admin listener can cause refusals, so without this
    /// each would cost a synchronous write and disk space, and a flood could fill the disk the
    /// log shares. Returns the event when it is to be written, and the summaries to write
    /// before it.
    fn coalesce(&self, mut event: Event) -> (Option<Event>, Vec<Event>) {
        // Refusals of callers who are not known: unknown tokens, logins and setup attempts
        // (whatever name they type), and rate-limited ones. A known caller's refusals are
        // each written: the caller can be told apart and revoked.
        let unidentified = event.actor == "-"
            || matches!(event.action, "login" | "setup")
            || event.reason.as_deref() == Some("rate limited");
        if event.outcome != Outcome::Denied || !unidentified {
            return (Some(event), Vec::new());
        }
        let now = std::time::Instant::now();
        let mut repeats = self.repeats.lock().unwrap_or_else(PoisonError::into_inner);
        let mut summaries = Vec::new();
        if repeats.map.len() >= REPEAT_KEYS || now.duration_since(repeats.pruned) >= REPEAT_WINDOW {
            repeats.pruned = now;
            let expired: Vec<String> = repeats
                .map
                .iter()
                .filter(|(_, r)| now.duration_since(r.since) >= REPEAT_WINDOW)
                .map(|(k, _)| k.clone())
                .collect();
            for key in expired {
                if let Some(summary) = repeats.map.remove(&key).and_then(Repeat::summary) {
                    summaries.push(summary);
                }
            }
        }
        let mut key = repeat_key(&event);
        if repeats.map.len() >= REPEAT_KEYS && !repeats.map.contains_key(&key) {
            key = format!("\u{0}overflow\u{0}{}", client_key(event.client));
            if repeats.map.len() >= REPEAT_KEYS + OVERFLOW_KEYS && !repeats.map.contains_key(&key) {
                "\u{0}overflow".clone_into(&mut key);
            }
        }
        let written = match repeats.map.get_mut(&key) {
            Some(repeat) if now.duration_since(repeat.since) < REPEAT_WINDOW => {
                repeat.skipped += 1;
                None
            }
            Some(repeat) => {
                event.repeated = std::mem::take(&mut repeat.skipped);
                repeat.since = now;
                repeat.first = event.clone();
                Some(event)
            }
            None => {
                repeats.map.insert(
                    key,
                    Repeat {
                        since: now,
                        skipped: 0,
                        first: event.clone(),
                    },
                );
                Some(event)
            }
        };
        (written, summaries)
    }

    /// Whether records were lost since the last one written.
    pub fn has_gap(&self) -> bool {
        self.writer
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .lost
            > 0
    }

    /// Counts a mutating call refused because [`Audit::prepare`] failed.
    pub fn refused(&self) {
        self.refusals
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// How many mutating calls were refused since the start.
    pub fn refusals(&self) -> u64 {
        self.refusals.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// How many records could not be written since the start.
    pub fn write_failures(&self) -> u64 {
        self.write_failures
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Writes one record at the end of the chain; on any error the file is cut back to its
    /// last complete record and the chain in memory is unchanged.
    fn append_locked(&self, writer: &mut Writer, event: Event) -> io::Result<Value> {
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
        if let Some(tenant) = event.tenant {
            record["tenant"] = json!(tenant);
        }
        if event.repeated > 0 {
            record["repeated"] = json!(event.repeated);
        }
        let line = record.to_string();
        let length = line.len() as u64 + 1;
        if writer.file.is_none() {
            self.open_file(writer, seq)?;
        }
        if writer.size > 0 && writer.size + length > self.max_bytes {
            writer.file = None;
            writer.path = None;
            self.open_file(writer, seq)?;
        }
        let mut bytes = line.clone().into_bytes();
        bytes.push(b'\n');
        let written = match writer.file.as_mut() {
            Some(file) => file.write_all(&bytes).and_then(|()| file.sync_data()),
            None => Err(io::Error::other("the audit log has no open file")),
        };
        if let Err(err) = written {
            // Never leave half a record: the next one would be appended to it and break the
            // chain. If the cut fails too, it is retried before the next write.
            writer.torn = true;
            if repair(writer).is_err() {
                writer.file = None;
            }
            return Err(err);
        }
        writer.size += length;
        writer.seq = seq;
        writer.prev = sha256_hex(line.as_bytes());
        Ok(record)
    }

    /// Alerts, the events stream and the forwarder for a record that was written.
    fn announce(&self, record: Value) {
        let line = record.to_string();
        if let Some(sink) = self.alerts.get()
            && let Some(summary) = security_summary(&record)
        {
            sink.raise(rdock_observability::alerts::Alert::firing(
                rdock_model::settings::AlertRule::Security,
                alert_key(&record),
                summary,
                record.clone(),
            ));
        }
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
        self.recent_of(limit, before, None)
    }

    /// [`recent`](Self::recent), only the records of `tenant` when given.
    pub fn recent_of(
        &self,
        limit: usize,
        before: Option<u64>,
        tenant: Option<&str>,
    ) -> io::Result<Vec<Value>> {
        let mut out = Vec::new();
        for path in files(&self.dir)?.iter().rev() {
            let mut lines: Vec<Value> = BufReader::new(File::open(path)?)
                .lines()
                .map_while(Result::ok)
                .filter_map(|line| serde_json::from_str(&line).ok())
                .filter(|r: &Value| before.is_none_or(|b| r["seq"].as_u64().is_some_and(|s| s < b)))
                .filter(|r: &Value| tenant.is_none_or(|t| r["tenant"].as_str() == Some(t)))
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

/// The alert line for audit records that an operator should hear about at once.
/// The alert key of a security record. Refusals are keyed by what was refused and from where
/// (the client as [`client_key`] groups it; not the name typed, which the caller chooses), so
/// `min_interval` holds back repeats (anyone can cause them); other records (an admin
/// created, an MFA removed) are each their own alert.
fn alert_key(record: &Value) -> String {
    let action = record["action"].as_str().unwrap_or_default();
    if record["result"] == "denied" {
        let client = record["client"].as_str().and_then(|c| c.parse().ok());
        format!("security:{action}:{}", client_key(client))
    } else {
        format!("security:{action}:{}", record["seq"])
    }
}

fn security_summary(record: &Value) -> Option<String> {
    let text = |field: &str| record[field].as_str().unwrap_or("-").to_owned();
    let (actor, resource, client) = (text("actor"), text("resource"), text("client"));
    match (record["action"].as_str()?, record["result"].as_str()?) {
        ("login", "denied") if record["reason"] == "rate limited" => Some(format!(
            "Repeated failed admin logins for {actor} from {client}; logins are being slowed down"
        )),
        ("user.create", "ok") => Some(format!("{actor} created the admin user {resource}")),
        ("user.change", "ok") => Some(format!(
            "{actor} changed the admin user {resource} ({})",
            text("reason")
        )),
        ("user.delete", "ok") => Some(format!("{actor} deleted the admin user {resource}")),
        ("mfa.remove", "ok") => Some(format!("{actor} turned off their two-step verification")),
        ("token.new_address", "ok") => Some(format!(
            "API token {resource} was used from a new address, {client}"
        )),
        _ => None,
    }
}

/// Cuts the open file back to its complete records when a write may have left part of one.
fn repair(writer: &mut Writer) -> io::Result<()> {
    if !writer.torn {
        return Ok(());
    }
    if let Some(file) = writer.file.as_ref() {
        file.set_len(writer.size)?;
        file.sync_data()?;
        writer.torn = false;
    }
    Ok(())
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
    //! A background thread sends each record as an RFC 5424 message, over UDP, TCP with octet
    //! counting (RFC 6587) or TLS (RFC 5425), reconnecting after errors. Never on the request path.

    use std::io::Write;
    use std::net::{TcpStream, UdpSocket};
    use std::path::Path;
    use std::sync::Arc;
    use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
    use std::time::Duration;

    use rdock_model::settings::{AuditForward, SyslogTransport};
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, ServerName};
    use rustls_platform_verifier::BuilderVerifierExt;

    /// `authpriv` (10) × 8 + `notice` (5).
    const PRI: u8 = 85;

    fn message(record: &str) -> String {
        let time = rdock_observability::rfc3339(std::time::SystemTime::now());
        format!("<{PRI}>1 {time} - rdock - audit - {record}")
    }

    pub(super) fn start(forward: &AuditForward) -> SyncSender<String> {
        let (tx, rx) = sync_channel::<String>(super::FORWARD_QUEUE);
        let forward = forward.clone();
        let spawned = std::thread::Builder::new()
            .name("rdock-audit-syslog".into())
            .spawn(move || run(&forward, &rx));
        if let Err(err) = spawned {
            tracing::error!(error = %err, "cannot start the audit forwarder");
        }
        tx
    }

    fn tls_config(ca_file: Option<&Path>) -> Result<rustls::ClientConfig, String> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| e.to_string())?;
        let verified = match ca_file {
            Some(path) => {
                let mut roots = rustls::RootCertStore::empty();
                let certificates =
                    CertificateDer::pem_file_iter(path).map_err(|e| e.to_string())?;
                for certificate in certificates {
                    roots
                        .add(certificate.map_err(|e| e.to_string())?)
                        .map_err(|e| e.to_string())?;
                }
                builder.with_root_certificates(roots)
            }
            None => builder
                .with_platform_verifier()
                .map_err(|e| e.to_string())?,
        };
        Ok(verified.with_no_client_auth())
    }

    /// A new stream to the server, encrypted when `tls` is set.
    fn connect(
        target: &str,
        tls: Option<&Arc<rustls::ClientConfig>>,
    ) -> std::io::Result<Box<dyn Write>> {
        let stream = TcpStream::connect(target)?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        let Some(config) = tls else {
            return Ok(Box::new(stream));
        };
        let host = target.rsplit_once(':').map_or(target, |(host, _)| host);
        let host = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_owned();
        let name = ServerName::try_from(host).map_err(std::io::Error::other)?;
        let connection =
            rustls::ClientConnection::new(config.clone(), name).map_err(std::io::Error::other)?;
        Ok(Box::new(rustls::StreamOwned::new(connection, stream)))
    }

    fn run(forward: &AuditForward, rx: &Receiver<String>) {
        let target = forward.syslog.as_str();
        let tls = (forward.transport == SyslogTransport::Tls)
            .then(|| tls_config(forward.ca_file.as_deref()));
        let tls = match tls.transpose() {
            Ok(tls) => tls.map(Arc::new),
            Err(err) => {
                // Records are never sent in clear text in place of TLS.
                tracing::error!(error = %err, "audit forwarding is off: cannot set up TLS");
                return;
            }
        };
        let mut open: Option<Box<dyn Write>> = None;
        let udp = UdpSocket::bind("0.0.0.0:0").ok();
        while let Ok(record) = rx.recv() {
            let message = message(&record);
            let sent = if forward.transport == SyslogTransport::Udp {
                udp.as_ref()
                    .ok_or_else(|| std::io::Error::other("no UDP socket"))
                    .and_then(|s| s.send_to(message.as_bytes(), target).map(|_| ()))
            } else {
                let framed = format!("{} {message}", message.len());
                let stream = match open.take() {
                    Some(stream) => Ok(stream),
                    None => connect(target, tls.as_ref()),
                };
                stream.and_then(|mut stream| {
                    stream.write_all(framed.as_bytes())?;
                    stream.flush()?;
                    open = Some(stream);
                    Ok(())
                })
            };
            if let Err(err) = sent {
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
    fn a_resync_continues_the_chain_another_writer_extended() {
        let dir = tempfile::tempdir().unwrap();
        // The new process opens the log while the old one still writes it (binary upgrade).
        let old = audit(dir.path(), 1 << 20);
        old.record(login("a"));
        let new = audit(dir.path(), 1 << 20);
        old.record(login("b"));
        old.record(login("c"));
        // `go`: the old process writes no more; the new one takes the end of the chain.
        new.resync().unwrap();
        new.record(login("d"));
        assert_eq!(
            verify(dir.path()).unwrap(),
            Verdict::Intact {
                records: 4,
                files: 1
            },
            "appended to the newest file, continuing its chain"
        );
        assert_eq!(new.recent(1, None).unwrap()[0]["seq"], 4);
    }

    /// ADR-0033: a record that cannot be written (here every write to `/dev/full` fails with
    /// `ENOSPC`) is counted, and the next `prepare` writes the gap record before anything
    /// else; the chain verifies.
    #[test]
    fn a_lost_record_is_followed_by_a_gap_record() {
        if !Path::new("/dev/full").exists() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let log = audit(dir.path(), 1 << 20);
        let first = dir.path().join("audit-000000000001.jsonl");
        std::os::unix::fs::symlink("/dev/full", &first).unwrap();
        log.record(login("a"));
        assert_eq!(log.write_failures(), 1);
        assert!(log.has_gap());
        std::fs::remove_file(&first).unwrap();
        log.prepare().unwrap();
        assert!(!log.has_gap());
        log.record(login("b"));
        let recent = log.recent(10, None).unwrap();
        assert_eq!(recent[1]["action"], "audit.gap");
        assert_eq!(recent[1]["seq"], 1);
        assert!(
            recent[1]["reason"]
                .as_str()
                .unwrap()
                .starts_with("1 audit record"),
            "{recent:?}"
        );
        assert_eq!(recent[0]["actor"], "b");
        assert_eq!(
            verify(dir.path()).unwrap(),
            Verdict::Intact {
                records: 2,
                files: 1
            }
        );
    }

    /// A file that ends in part of a record (a write cut short) is cut back before the next
    /// record, so the chain never breaks at a torn tail.
    #[test]
    fn a_torn_tail_is_cut_off_before_the_next_record() {
        let dir = tempfile::tempdir().unwrap();
        let log = audit(dir.path(), 1 << 20);
        log.record(login("a"));
        log.record(login("b"));
        let path = files(dir.path()).unwrap()[0].clone();
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(b"{\"time\":\"2026-").unwrap();
        drop(file);
        assert!(matches!(
            verify(dir.path()).unwrap(),
            Verdict::Broken { .. }
        ));
        // The handover path re-reads the end of the chain and repairs the file.
        log.resync().unwrap();
        log.record(login("c"));
        assert_eq!(
            verify(dir.path()).unwrap(),
            Verdict::Intact {
                records: 3,
                files: 1
            }
        );
        // `prepare` reserves room without changing the file's size.
        let before = std::fs::metadata(&path).unwrap().len();
        log.prepare().unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), before);
        log.record(login("d"));
        assert!(matches!(
            verify(dir.path()).unwrap(),
            Verdict::Intact { records: 4, .. }
        ));
    }

    #[test]
    fn a_torn_tail_is_cut_off_when_the_log_is_opened_again() {
        let dir = tempfile::tempdir().unwrap();
        let log = audit(dir.path(), 1 << 20);
        log.record(login("a"));
        log.record(login("b"));
        drop(log);
        let path = files(dir.path()).unwrap()[0].clone();
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(b"{\"time\":\"2026-").unwrap();
        drop(file);
        // A restart after a crash: the old file's partial record is cut, not left behind.
        let log = audit(dir.path(), 1 << 20);
        log.record(login("c"));
        assert_eq!(
            verify(dir.path()).unwrap(),
            Verdict::Intact {
                records: 3,
                files: 2
            }
        );
    }

    #[test]
    fn refusals_from_one_client_are_written_once_per_window() {
        let dir = tempfile::tempdir().unwrap();
        let log = audit(dir.path(), 1 << 20);
        let refusal = |client: &str| Event {
            client: Some(client.parse().unwrap()),
            outcome: Outcome::Denied,
            reason: Some("unknown, expired or revoked token".into()),
            ..Event::new("-", "token", "auth")
        };
        for _ in 0..10_000 {
            log.record(refusal("203.0.113.7"));
        }
        // Another address of the same /64 is the same client; another client is not.
        for _ in 0..100 {
            log.record(refusal("2001:db8:1:2::1"));
            log.record(refusal("2001:db8:1:2::2"));
        }
        log.record(refusal("198.51.100.1"));
        // Successful records are never coalesced.
        log.record(login("a"));
        log.record(login("a"));
        let records = log.recent(100, None).unwrap();
        assert_eq!(records.len(), 5, "{records:?}");
        assert_eq!(
            verify(dir.path()).unwrap(),
            Verdict::Intact {
                records: 5,
                files: 1
            }
        );
        // The next window's first record carries the count of those not written.
        {
            let mut repeats = log.repeats.lock().unwrap();
            for repeat in repeats.map.values_mut() {
                repeat.since -= REPEAT_WINDOW;
            }
        }
        log.record(refusal("203.0.113.7"));
        let newest = &log.recent(1, None).unwrap()[0];
        assert_eq!(newest["repeated"], 9_999, "{newest}");
    }

    #[test]
    fn one_client_cannot_crowd_out_other_clients_refusals() {
        let dir = tempfile::tempdir().unwrap();
        let log = audit(dir.path(), 1 << 22);
        let login = |name: String, client: &str| Event {
            client: Some(client.parse().unwrap()),
            outcome: Outcome::Denied,
            reason: Some("rate limited".into()),
            ..Event::new(name, "password", "login")
        };
        // 5,000 names from one address: one entry, one record.
        for i in 0..5_000 {
            log.record(login(format!("a{i:04}"), "203.0.113.7"));
        }
        assert_eq!(log.repeats.lock().unwrap().map.len(), 1);
        // Another client's refusal is still written.
        log.record(login("admin".into(), "198.51.100.1"));
        assert_eq!(log.recent(10, None).unwrap().len(), 2);
        // Past the table, each new client still gets its own entry.
        {
            let mut repeats = log.repeats.lock().unwrap();
            for i in 0..REPEAT_KEYS {
                let first = login("x".into(), "192.0.2.1");
                repeats.map.insert(
                    format!("filler{i}"),
                    Repeat {
                        since: std::time::Instant::now(),
                        skipped: 0,
                        first,
                    },
                );
            }
        }
        log.record(login("b".into(), "192.0.2.10"));
        log.record(login("c".into(), "192.0.2.11"));
        log.record(login("c".into(), "192.0.2.11"));
        assert_eq!(log.recent(10, None).unwrap().len(), 4);
    }

    #[test]
    fn counts_of_refusals_not_written_are_summarised_when_their_entry_ends() {
        let dir = tempfile::tempdir().unwrap();
        let log = audit(dir.path(), 1 << 20);
        let refusal = Event {
            client: Some("203.0.113.7".parse().unwrap()),
            outcome: Outcome::Denied,
            reason: Some("unknown, expired or revoked token".into()),
            ..Event::new("-", "token", "auth")
        };
        for _ in 0..50 {
            log.record(refusal.clone());
        }
        // The window ends with no refusal from that client; the next refusal from anyone
        // clears the entry and writes its count.
        {
            let mut repeats = log.repeats.lock().unwrap();
            repeats.pruned -= REPEAT_WINDOW;
            for repeat in repeats.map.values_mut() {
                repeat.since -= REPEAT_WINDOW;
            }
        }
        log.record(Event {
            client: Some("198.51.100.1".parse().unwrap()),
            ..refusal.clone()
        });
        let records = log.recent(10, None).unwrap();
        assert_eq!(records.len(), 3, "{records:?}");
        let summary = records
            .iter()
            .find(|r| {
                r["reason"]
                    .as_str()
                    .is_some_and(|t| t.starts_with("summary:"))
            })
            .unwrap();
        assert_eq!(summary["repeated"], 49);
        // At shutdown, what is still counted is written too.
        for _ in 0..5 {
            log.record(refusal.clone());
        }
        drop(log);
        let log = audit(dir.path(), 1 << 20);
        let newest = &log.recent(1, None).unwrap()[0];
        assert_eq!(newest["repeated"], 4, "{newest}");
    }

    #[test]
    fn repeated_refusals_share_an_alert_key() {
        let denied = |seq: u64| {
            json!({ "seq": seq, "action": "login", "result": "denied", "actor": "admin",
                    "client": "203.0.113.7", "reason": "rate limited" })
        };
        assert_eq!(alert_key(&denied(1)), alert_key(&denied(2)));
        // The name typed does not make a new key; the /64 of an IPv6 client is one client.
        let mut other_name = denied(3);
        other_name["actor"] = json!("a0001");
        assert_eq!(alert_key(&denied(1)), alert_key(&other_name));
        let v6 = |c: &str| json!({ "action": "login", "result": "denied", "client": c });
        assert_eq!(
            alert_key(&v6("2001:db8:1:2::1")),
            alert_key(&v6("2001:db8:1:2::9"))
        );
        assert_ne!(
            alert_key(&v6("2001:db8:1:2::1")),
            alert_key(&v6("2001:db8:1:3::1"))
        );
        let created = |seq: u64| json!({ "seq": seq, "action": "user.create", "result": "ok" });
        assert_ne!(alert_key(&created(1)), alert_key(&created(2)));
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
