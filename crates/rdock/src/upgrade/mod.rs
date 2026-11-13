//! In-place binary upgrade by peer handover (H-PERF-04, ADR-0031 "Binary upgrade").
//!
//! The running process checks the new binary, has it validate the configuration, starts it
//! with one end of a Unix socket pair as its standard input and sends it a manifest with the
//! listening sockets, the admin sockets, the data directory's lock and the TLS ticket keys
//! ([`wire`]). The new process builds everything without accepting and answers `ready`; the old
//! one stops accepting and stops its shared-state writers, answers `go`, and once the new one
//! reports `serving` it tells systemd the new main pid, closes its listening sockets and drains
//! for at most `upgrade.drain`. If the new process exits, or does not report in time, the old
//! one accepts again and restarts its writers: nothing was closed.

pub(crate) mod inherit;
pub(crate) mod wire;

use std::io::Read;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rdock_admin::UpgradeOutcome;
use rdock_proxy::DataPlane;
use serde_json::json;
use tokio::sync::oneshot;

use crate::datadir::DataDirLock;
use crate::engine::Engine;
use crate::run::Writers;
use crate::zero_config::Source;
use wire::{Channel, Manifest, Message, SocketEntry, TicketClass};

/// The diagnostic for an upgrade asked of PID 1 (a container's entry point): the old process
/// exiting would end the container.
pub(crate) const PID1_REFUSAL: &str = "rdock is PID 1 (a container's entry point): when the old process exits after an in-place upgrade, the container ends with it; replace the container with one from the new image instead (a rolling update in Kubernetes or Swarm, `docker compose up -d` elsewhere)";

/// A request to upgrade: from `rdock upgrade` (with a reply) or `SIGUSR2`.
pub(crate) struct Trigger {
    /// The binary; `upgrade.binary` when `None`.
    pub(crate) binary: Option<PathBuf>,
    /// Who asked (`cli`, `token:…`, a user, or `signal`).
    pub(crate) actor: String,
    /// Where the outcome goes (none for a signal).
    pub(crate) reply: Option<oneshot::Sender<UpgradeOutcome>>,
}

/// What the run loop passes to [`perform`].
pub(crate) struct Context<'a> {
    pub(crate) args: &'a crate::RunArgs,
    pub(crate) source: &'a Source,
    pub(crate) engine: &'a Arc<Engine>,
    pub(crate) plane: &'a Arc<DataPlane>,
    pub(crate) admin: Option<&'a rdock_admin::Running>,
    pub(crate) admin_gate: &'a tokio::sync::watch::Sender<bool>,
    pub(crate) lock: &'a DataDirLock,
    pub(crate) writers: &'a mut Writers,
}

/// The old process after a successful handover: what it needs while it drains.
pub(crate) struct Draining {
    pub(crate) channel: Channel,
    pub(crate) drain: Option<Duration>,
    /// The quota counts when this process stopped writing them.
    pub(crate) quota_base: Vec<(String, Arc<rdock_limits::quota::QuotaCounter>, QuotaBase)>,
    /// The new process; never waited for (it is the main process now, and outlives this one).
    pub(crate) child: Child,
}

type QuotaBase = (i64, std::collections::HashMap<String, u64>);

/// How [`perform`] ended.
pub(crate) enum Outcome {
    /// The new process serves; drain.
    Serving(Box<Draining>, serde_json::Value),
    /// Not attempted; nothing changed.
    Refused(serde_json::Value),
    /// Attempted and rolled back; this process serves on.
    Failed(serde_json::Value),
}

impl Outcome {
    pub(crate) fn to_admin(&self) -> UpgradeOutcome {
        match self {
            Self::Serving(_, v) => UpgradeOutcome::Serving(v.clone()),
            Self::Refused(v) => UpgradeOutcome::Refused(v.clone()),
            Self::Failed(v) => UpgradeOutcome::Failed(v.clone()),
        }
    }
}

/// Faults for the upgrade tests (`RDOCK_UPGRADE_FAULT`): only in debug builds and builds with
/// the `fault-injection` feature, never in a release binary. Each one can only make an upgrade
/// fail, never succeed where it should not.
pub(crate) fn fault() -> Option<String> {
    if cfg!(any(debug_assertions, feature = "fault-injection")) {
        std::env::var("RDOCK_UPGRADE_FAULT").ok()
    } else {
        None
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Whether this process is PID 1.
fn is_pid1() -> bool {
    std::process::id() == 1 || fault().as_deref() == Some("pid1")
}

/// A checked binary: its path, SHA-256 and, when keys are trusted, the key that signed it.
#[derive(Debug)]
pub(crate) struct Checked {
    pub(crate) path: PathBuf,
    pub(crate) sha256: String,
    pub(crate) signed_by: Option<String>,
}

/// The checks of ADR-0031 on the binary at `path`: a regular file, owned by root or the user
/// rdock runs as, not writable by the group or others; when `trusted_keys` is not empty,
/// `<path>.minisig` must be a minisign signature of it by one of them. The file is opened once
/// and every check (and the hash) uses that open file.
pub(crate) fn check_binary(path: &Path, trusted_keys: &[String]) -> Result<Checked, String> {
    use std::os::unix::fs::MetadataExt;
    if !path.is_absolute() {
        return Err(format!("{} is not an absolute path", path.display()));
    }
    let mut file =
        std::fs::File::open(path).map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    let meta = file
        .metadata()
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    if !meta.file_type().is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    let mode = meta.mode() & 0o7777;
    if mode & 0o022 != 0 {
        return Err(format!(
            "{} is writable by its group or others (mode {mode:o}); allow writes by its owner only",
            path.display()
        ));
    }
    let uid = rustix::process::geteuid().as_raw();
    if meta.uid() != 0 && meta.uid() != uid {
        return Err(format!(
            "{} is owned by uid {}, not by root or the user rdock runs as (uid {uid})",
            path.display(),
            meta.uid()
        ));
    }
    if mode & 0o111 == 0 {
        return Err(format!("{} is not executable", path.display()));
    }
    // Whoever may rename files in its directory could swap the binary after these checks and
    // before it runs: the directory must be as private as the file (a sticky directory such as
    // /tmp only lets a file's owner rename it).
    let dir = path.parent().unwrap_or(Path::new("/"));
    let dir_meta =
        std::fs::metadata(dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
    let dir_mode = dir_meta.mode() & 0o7777;
    if dir_meta.uid() != 0 && dir_meta.uid() != uid {
        return Err(format!(
            "its directory {} is owned by uid {}, not by root or the user rdock runs as (uid {uid})",
            dir.display(),
            dir_meta.uid()
        ));
    }
    if dir_mode & 0o022 != 0 && dir_mode & 0o1000 == 0 {
        return Err(format!(
            "its directory {} is writable by its group or others (mode {dir_mode:o}), who could replace the file",
            dir.display()
        ));
    }
    let keys = trusted_keys
        .iter()
        .map(|k| rdock_credentials::minisign::PublicKey::parse(k))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("upgrade.trusted_keys: {e}"))?;
    let mut context = ring::digest::Context::new(&ring::digest::SHA256);
    let mut whole = Vec::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        if n == 0 {
            break;
        }
        context.update(&buf[..n]);
        if !keys.is_empty() {
            whole.extend_from_slice(&buf[..n]);
        }
    }
    let sha256 = hex(context.finish().as_ref());
    let signed_by = if keys.is_empty() {
        None
    } else {
        let mut sig_path = path.as_os_str().to_owned();
        sig_path.push(".minisig");
        let text = std::fs::read_to_string(&sig_path).map_err(|e| {
            format!(
                "upgrade.trusted_keys is set, but the signature {} cannot be read: {e}",
                PathBuf::from(&sig_path).display()
            )
        })?;
        let signature = rdock_credentials::minisign::Signature::parse(&text)
            .map_err(|e| format!("{}: {e}", PathBuf::from(&sig_path).display()))?;
        let key = signature
            .verify(&whole, &keys)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        Some(key.id_hex())
    };
    Ok(Checked {
        path: path.to_owned(),
        sha256,
        signed_by,
    })
}

/// Runs `<binary> validate <config>`; the configuration must have no errors.
async fn validate_with(binary: &Path, source: &Source, timeout: Duration) -> Result<(), String> {
    let Source::File(config) = source else {
        // Zero-config mode has no file; the new process builds the same document.
        return Ok(());
    };
    let mut command = tokio::process::Command::new(binary);
    command
        .arg("validate")
        .arg(config)
        .stdin(Stdio::null())
        .kill_on_drop(true);
    let output = tokio::time::timeout(timeout, command.output())
        .await
        .map_err(|_| format!("`{} validate` did not finish in time", binary.display()))?
        .map_err(|e| format!("cannot run {}: {e}", binary.display()))?;
    if output.status.success() {
        Ok(())
    } else {
        let text = String::from_utf8_lossy(&output.stdout).into_owned()
            + &String::from_utf8_lossy(&output.stderr);
        Err(format!(
            "the new binary refuses the configuration ({}): {}",
            output.status,
            text.trim()
        ))
    }
}

/// The arguments the new process runs with: the old one's, plus `--inherit`.
fn child_args(args: &crate::RunArgs, source: &Source) -> Vec<std::ffi::OsString> {
    let mut out: Vec<std::ffi::OsString> = vec!["run".into(), "--inherit".into()];
    if let Source::File(path) = source {
        out.push("--config".into());
        out.push(path.into());
    }
    out.push("--data-dir".into());
    out.push(args.data_dir.clone().into());
    if args.no_watch {
        out.push("--no-watch".into());
    }
    out.push("--log".into());
    out.push(args.log.clone().into());
    out.push("--log-format".into());
    out.push(
        match args.log_format {
            crate::LogFormatArg::Auto => "auto",
            crate::LogFormatArg::Json => "json",
            crate::LogFormatArg::Text => "text",
        }
        .into(),
    );
    out
}

/// The TLS ticket keys for the manifest.
fn ticket_keys(plane: &DataPlane) -> Vec<TicketClass> {
    use base64::Engine as _;
    let b64 = |k: &rdock_tls::tickets::TicketKey| {
        base64::engine::general_purpose::STANDARD.encode(k.expose())
    };
    plane
        .tickets()
        .export()
        .into_iter()
        .map(|class| TicketClass {
            class: hex(&class.class),
            current: b64(&class.keys.current),
            previous: class.keys.previous.iter().map(b64).collect(),
            rotated_at: class.keys.rotated_at,
        })
        .collect()
}

/// Performs a binary upgrade (the old process's side).
pub(crate) async fn perform(cx: Context<'_>, trigger: &Trigger) -> Outcome {
    let metrics = cx.plane.metrics().clone();
    let outcome = attempt(cx, trigger).await;
    let result = match &outcome {
        Outcome::Serving(..) => "ok",
        Outcome::Refused(_) => "refused",
        Outcome::Failed(_) => "failed",
    };
    metrics.upgrades.with_label_values(&[result]).inc();
    outcome
}

async fn attempt(cx: Context<'_>, trigger: &Trigger) -> Outcome {
    let refused = |error: String, sha: Option<&str>| {
        tracing::warn!(error = %error, "binary upgrade refused");
        Outcome::Refused(json!({ "error": error, "sha256": sha }))
    };
    if !cfg!(target_os = "linux") {
        return refused(
            "in-place binary upgrades are only supported on Linux; restart rdock with the new binary".into(),
            None,
        );
    }
    if is_pid1() {
        return refused(PID1_REFUSAL.into(), None);
    }
    let config = cx.engine.config().await.unwrap_or_default();
    let settings = config.upgrade.clone().unwrap_or_default();
    let binary = trigger
        .binary
        .clone()
        .unwrap_or_else(|| settings.binary.clone());
    let keys = settings.trusted_keys.clone();
    let checked = match tokio::task::spawn_blocking(move || check_binary(&binary, &keys)).await {
        Ok(Ok(checked)) => checked,
        Ok(Err(error)) => return refused(error, None),
        Err(_) => return refused("the binary check did not finish".into(), None),
    };
    let sha = checked.sha256.clone();
    let start_timeout = settings.start_timeout.as_std();
    if let Err(error) = validate_with(&checked.path, cx.source, start_timeout).await {
        return refused(error, Some(&sha));
    }
    let drain = settings.drain.get();
    tracing::info!(binary = %checked.path.display(), sha256 = %sha, signed_by = checked.signed_by.as_deref(), actor = %trigger.actor, "binary upgrade: starting the new process");
    // From here the new process reads the users, tokens and configuration: nothing may change
    // them in this one until the handover ends.
    let admin = cx.admin;
    if let Some(admin) = admin {
        admin.set_read_only(true);
    }
    let result = handover(cx, trigger, &checked, start_timeout, drain).await;
    if result.is_err()
        && let Some(admin) = admin
    {
        // The new process may have appended to the audit log before it was stopped.
        admin.resync_audit();
        admin.set_read_only(false);
    }
    match result {
        Ok(draining) => {
            let pid = draining.child.id();
            tracing::info!(
                new_pid = pid,
                "binary upgrade: the new process serves; draining"
            );
            Outcome::Serving(
                draining,
                json!({ "pid": pid, "previous_pid": std::process::id(), "sha256": sha, "binary": checked.path, "drain_seconds": drain.map(|d| d.as_secs()) }),
            )
        }
        Err(error) => {
            tracing::error!(error = %error, "binary upgrade failed; this process serves on");
            Outcome::Failed(json!({ "error": error, "sha256": sha }))
        }
    }
}

/// Starts the new process, hands over and waits for it to serve; on any failure undoes what
/// was paused and returns the reason.
async fn handover(
    cx: Context<'_>,
    trigger: &Trigger,
    checked: &Checked,
    start_timeout: Duration,
    drain: Option<Duration>,
) -> Result<Box<Draining>, String> {
    let listeners = cx.plane.listener_handles().await?;
    // The new process's cache stores walk their directories at start and remove unfinished
    // files: this one stops filling them now (and fills again if the upgrade fails).
    cx.plane.set_cache_bypass(true);
    let plane = cx.plane;
    let result = spawn_and_hand_over(cx, trigger, checked, start_timeout, drain, listeners).await;
    if result.is_err() {
        plane.set_cache_bypass(false);
    }
    result
}

/// The protocol of [`handover`] from the spawn on.
#[allow(clippy::too_many_lines)] // the protocol's steps, in order
async fn spawn_and_hand_over(
    cx: Context<'_>,
    trigger: &Trigger,
    checked: &Checked,
    start_timeout: Duration,
    drain: Option<Duration>,
    listeners: Vec<rdock_proxy::ListenerHandle>,
) -> Result<Box<Draining>, String> {
    let (ours, theirs) =
        UnixStream::pair().map_err(|e| format!("cannot make a socket pair: {e}"))?;
    let mut command = Command::new(&checked.path);
    command
        .args(child_args(cx.args, cx.source))
        .stdin(Stdio::from(OwnedFd::from(theirs)));
    let mut child = command
        .spawn()
        .map_err(|e| format!("cannot start {}: {e}", checked.path.display()))?;
    let channel = Channel::new(ours);

    // The manifest and the descriptors, in the same order.
    let mut entries = vec![SocketEntry::Lock];
    let mut fds: Vec<BorrowedFd<'_>> = vec![cx.lock.file().as_fd()];
    for l in &listeners {
        entries.push(SocketEntry::Listener {
            name: l.name.clone(),
            address: l.address,
            udp: l.udp,
            options: l.options,
        });
        fds.push(l.fd.as_fd());
    }
    if let Some(admin) = cx.admin {
        let (tcp, unix) = admin.sockets();
        if let Some(tcp) = tcp {
            entries.push(SocketEntry::AdminTcp);
            fds.push(tcp.as_fd());
        }
        if let Some((unix, path)) = unix {
            entries.push(SocketEntry::AdminUnix {
                path: path.to_owned(),
            });
            fds.push(unix.as_fd());
        }
    }
    let manifest = Manifest {
        protocol: wire::PROTOCOL,
        data_format: crate::datadir::DATA_FORMAT,
        generation: cx
            .engine
            .upgrade_generation
            .load(std::sync::atomic::Ordering::SeqCst)
            + 1,
        previous_pid: std::process::id(),
        triggered_by: trigger.actor.clone(),
        method: if trigger.reply.is_some() {
            "socket"
        } else {
            "signal"
        }
        .to_owned(),
        binary: checked.path.clone(),
        binary_sha256: checked.sha256.clone(),
        drain_deadline: drain.map_or(0, |d| unix_now() + d.as_secs()),
        sockets: entries,
        ticket_keys: ticket_keys(cx.plane),
    };
    let sent = channel.send(&Message::Manifest(Box::new(manifest)), &fds);
    drop(fds);
    drop(listeners);
    if let Err(err) = sent {
        kill(&mut child);
        return Err(format!("cannot hand over to the new process: {err}"));
    }

    // Wait for `ready`; the reader also notices the child exiting (end of file).
    let ready = blocking_expect(&channel, "ready", start_timeout).await;
    if let Err(err) = ready {
        let status = kill(&mut child);
        return Err(format!(
            "the new process did not become ready ({err}){status}"
        ));
    }

    // Stop accepting (connections wait in the shared backlogs) and stop the writers.
    cx.plane.set_accepting(false);
    cx.admin_gate.send_replace(false);
    cx.writers.stop().await;
    let quota_base: Vec<_> = cx
        .plane
        .quotas()
        .counters()
        .into_iter()
        .map(|(name, counter)| {
            let base = counter.snapshot();
            (name, counter, base)
        })
        .collect();

    let resume = |child: &mut Child| {
        let status = kill(child);
        cx.plane.set_accepting(true);
        cx.admin_gate.send_replace(true);
        status
    };
    if let Err(err) = channel.send(&Message::Go, &[]) {
        let status = resume(&mut child);
        cx.writers.start().await;
        return Err(format!(
            "cannot tell the new process to start ({err}){status}"
        ));
    }
    if let Err(err) = blocking_expect(&channel, "serving", start_timeout).await {
        let status = resume(&mut child);
        cx.writers.start().await;
        return Err(format!(
            "the new process did not start serving ({err}){status}"
        ));
    }
    notify_systemd(child.id());
    if let Some(admin) = cx.admin {
        admin.keep_socket_file();
    }
    Ok(Box::new(Draining {
        channel,
        drain,
        quota_base,
        child,
    }))
}

/// Waits for a message of `kind` without blocking the runtime.
async fn blocking_expect(
    channel: &Channel,
    kind: &'static str,
    timeout: Duration,
) -> Result<(), String> {
    let reader = channel.try_clone().map_err(|e| e.to_string())?;
    let started = Instant::now();
    let read = tokio::task::spawn_blocking(move || {
        // A read that times out is retried until the whole timeout has passed.
        loop {
            let left = timeout.saturating_sub(started.elapsed());
            if left.is_zero() {
                return Err(format!("no `{kind}` within {} s", timeout.as_secs()));
            }
            match reader.expect(kind, Some(left)) {
                Ok(_) => return Ok(()),
                Err(err)
                    if matches!(
                        err.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(err) => return Err(err.to_string()),
            }
        }
    })
    .await;
    read.unwrap_or_else(|_| Err("the handover reader stopped".into()))
}

/// Ends the new process if it still runs and reaps it (no zombie); describes how it ended.
fn kill(child: &mut Child) -> String {
    if let Ok(Some(status)) = child.try_wait() {
        return format!("; it exited with {status}");
    }
    let _ = child.kill();
    child
        .wait()
        .map(|status| format!("; it was stopped ({status})"))
        .unwrap_or_default()
}

/// Under systemd (`NOTIFY_SOCKET` set), the new process becomes the service's main process
/// (`NotifyAccess=main` lets this, the current main process, say so).
fn notify_systemd(pid: u32) {
    if std::env::var_os("NOTIFY_SOCKET").is_none() {
        return;
    }
    if let Err(err) = sd_notify::notify(&[
        sd_notify::NotifyState::MainPid(pid),
        sd_notify::NotifyState::Ready,
    ]) {
        tracing::warn!(error = %err, "cannot tell systemd the new main process");
    }
}

/// The old process's drain after a successful handover: closes its listening sockets (UDP
/// sessions end at once), lets connections finish for at most `upgrade.drain` and reports the
/// open count to the new process every second; at the end sends what the quotas counted.
pub(crate) async fn drain(plane: &Arc<DataPlane>, draining: Box<Draining>) {
    // A year stands for `unlimited`: tokio's timers need a finite deadline.
    let drain = draining.drain.unwrap_or(Duration::from_secs(365 * 86_400));
    let stopping = {
        let plane = plane.clone();
        tokio::spawn(async move { plane.stop_listeners(drain, Duration::ZERO, false).await })
    };
    let channel = &draining.channel;
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tokio::pin!(stopping);
    loop {
        tokio::select! {
            _ = &mut stopping => break,
            _ = tick.tick() => {
                let connections = plane.open_connections();
                // The new process may have gone; that is not this process's problem.
                let _ = channel.send(&Message::Draining { connections }, &[]);
            }
        }
    }
    let counters = draining
        .quota_base
        .iter()
        .filter_map(|(name, counter, base)| {
            let (start, increments) = counter.increments_since(base);
            (!increments.is_empty()).then(|| wire::QuotaIncrements {
                name: name.clone(),
                start,
                increments,
            })
        })
        .collect();
    let _ = channel.send(&Message::Quota { counters }, &[]);
    let _ = channel.send(&Message::Draining { connections: 0 }, &[]);
    let _ = channel.send(&Message::Done, &[]);
    tracing::info!("drain over; the old process exits");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn the_binary_checks_refuse_what_others_could_have_written() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rdock");
        std::fs::write(&path, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        let ok = check_binary(&path, &[]).unwrap();
        assert_eq!(ok.sha256.len(), 64);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o775)).unwrap();
        assert!(
            check_binary(&path, &[])
                .unwrap_err()
                .contains("writable by its group")
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o757)).unwrap();
        assert!(check_binary(&path, &[]).unwrap_err().contains("or others"));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            check_binary(&path, &[])
                .unwrap_err()
                .contains("not executable")
        );
        assert!(
            check_binary(dir.path(), &[])
                .unwrap_err()
                .contains("not a regular file")
        );
        assert!(
            check_binary(Path::new("rdock"), &[])
                .unwrap_err()
                .contains("absolute")
        );
        // A directory others may write to: they could swap the file after the checks.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(
            check_binary(&path, &[])
                .unwrap_err()
                .contains("who could replace the file")
        );
        // Sticky (like /tmp): only the file's owner may rename it.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o1777)).unwrap();
        assert!(check_binary(&path, &[]).is_ok());
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn a_trusted_key_needs_a_matching_signature() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rdock");
        std::fs::write(&path, b"test").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        // Test vectors of the `minisign-verify` crate (MIT, 0.2.4): a signature of "test".
        let key = "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3".to_owned();
        let sig = "untrusted comment: signature from minisign secret key\nRUQf6LRCGA9i559r3g7V1qNyJDApGip8MfqcadIgT9CuhV3EMhHoN1mGTkUidF/z7SrlQgXdy8ofjb7bNJJylDOocrCo8KLzZwo=\ntrusted comment: timestamp:1556193335\tfile:test\ny/rUw2y8/hOUYjZU71eHp/Wo1KZ40fGy2VJEDl34XMJM+TX48Ss/17u3IvIfbVR1FkZZSNCisQbuQY+bHwhEBg==\n";
        assert!(
            check_binary(&path, std::slice::from_ref(&key))
                .unwrap_err()
                .contains("cannot be read")
        );
        std::fs::write(dir.path().join("rdock.minisig"), sig).unwrap();
        let checked = check_binary(&path, std::slice::from_ref(&key)).unwrap();
        assert_eq!(checked.signed_by.as_deref(), Some("E7620F1842B4E81F"));
        std::fs::write(&path, b"Test").unwrap();
        assert!(
            check_binary(&path, &[key])
                .unwrap_err()
                .contains("does not match")
        );
    }
}
