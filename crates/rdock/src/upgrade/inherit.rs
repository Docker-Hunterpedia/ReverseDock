//! `rdock run --inherit`: the new process's side of a binary upgrade (ADR-0031). It reads the
//! manifest and the descriptors from its standard input (one end of the old process's socket
//! pair), adopts them, builds everything without accepting, reports `ready`, starts on `go` and
//! reports `serving`. Afterwards it follows the old process's drain reports.

use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rdock_proxy::{DataPlane, InheritedSocket};

use super::wire::{Channel, Manifest, Message, SocketEntry};

/// How long the new process waits for the manifest.
const MANIFEST_TIMEOUT: Duration = Duration::from_secs(30);

/// What the old process handed over.
pub(crate) struct Inherited {
    pub(crate) channel: Channel,
    pub(crate) generation: u64,
    pub(crate) triggered_by: String,
    pub(crate) method: String,
    pub(crate) binary: PathBuf,
    pub(crate) binary_sha256: String,
    pub(crate) previous_pid: u32,
    pub(crate) drain_deadline: u64,
    /// The data directory's lock file, already locked.
    pub(crate) lock: Option<std::fs::File>,
    pub(crate) listeners: Vec<(SocketEntry, OwnedFd)>,
    pub(crate) admin_tcp: Option<std::net::TcpListener>,
    pub(crate) admin_unix: Option<(std::os::unix::net::UnixListener, PathBuf)>,
    pub(crate) ticket_keys: Vec<rdock_tls::ClassKeys>,
}

/// Reads the handover from standard input. A manifest of a newer protocol or data format is
/// refused (and the old process told so) before anything is built.
#[allow(clippy::too_many_lines)] // the manifest's parts, one after another
pub(crate) fn receive() -> Result<Inherited, String> {
    let stdin = std::io::stdin()
        .as_fd()
        .try_clone_to_owned()
        .map_err(|e| format!("cannot use standard input: {e}"))?;
    let channel = Channel::new(UnixStream::from(stdin));
    let (message, fds) = channel
        .expect("manifest", Some(MANIFEST_TIMEOUT))
        .map_err(|e| {
            format!(
                "`--inherit` needs the handover socket of a running rdock on standard input: {e}"
            )
        })?;
    let Message::Manifest(manifest) = message else {
        return Err("no manifest".into());
    };
    if let Err(reason) = check(&manifest, fds.len()) {
        let _ = channel.send(
            &Message::Failed {
                reason: reason.clone(),
            },
            &[],
        );
        return Err(reason);
    }
    let Manifest {
        generation,
        previous_pid,
        triggered_by,
        method,
        binary,
        binary_sha256,
        drain_deadline,
        sockets,
        ticket_keys,
        ..
    } = *manifest;
    let mut lock = None;
    let mut listeners = Vec::new();
    let mut admin_tcp = None;
    let mut admin_unix = None;
    for (entry, fd) in sockets.into_iter().zip(fds) {
        match entry {
            SocketEntry::Lock => lock = Some(std::fs::File::from(fd)),
            SocketEntry::Listener { .. } => listeners.push((entry, fd)),
            SocketEntry::AdminTcp => admin_tcp = Some(std::net::TcpListener::from(fd)),
            SocketEntry::AdminUnix { path } => {
                admin_unix = Some((std::os::unix::net::UnixListener::from(fd), path));
            }
        }
    }
    if lock.is_none() {
        let reason = "the manifest has no data-directory lock".to_owned();
        let _ = channel.send(
            &Message::Failed {
                reason: reason.clone(),
            },
            &[],
        );
        return Err(reason);
    }
    let ticket_keys = ticket_keys
        .into_iter()
        .filter_map(|class| {
            use base64::Engine as _;
            let decode = |text: &str| -> Option<rdock_tls::tickets::TicketKey> {
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(text)
                    .ok()?;
                let bytes: [u8; 48] = bytes.try_into().ok()?;
                Some(rdock_tls::tickets::TicketKey::from_exposed(&bytes))
            };
            let mut id = [0u8; 32];
            if class.class.len() != 64 {
                return None;
            }
            for (i, byte) in id.iter_mut().enumerate() {
                *byte = u8::from_str_radix(class.class.get(2 * i..2 * i + 2)?, 16).ok()?;
            }
            Some(rdock_tls::ClassKeys {
                class: id,
                keys: rdock_tls::tickets::KeySet {
                    current: decode(&class.current)?,
                    previous: class.previous.iter().filter_map(|p| decode(p)).collect(),
                    rotated_at: class.rotated_at,
                },
            })
        })
        .collect();
    Ok(Inherited {
        channel,
        generation,
        triggered_by,
        method,
        binary,
        binary_sha256,
        previous_pid,
        drain_deadline,
        lock,
        listeners,
        admin_tcp,
        admin_unix,
        ticket_keys,
    })
}

fn check(manifest: &Manifest, fds: usize) -> Result<(), String> {
    if manifest.protocol > super::wire::PROTOCOL {
        return Err(format!(
            "the handover protocol {} is newer than this binary understands ({})",
            manifest.protocol,
            super::wire::PROTOCOL
        ));
    }
    if manifest.data_format > crate::datadir::DATA_FORMAT {
        return Err(format!(
            "the data directory's format {} is newer than this binary understands ({}); a downgrade across it is refused",
            manifest.data_format,
            crate::datadir::DATA_FORMAT
        ));
    }
    if manifest.sockets.len() != fds {
        return Err(format!(
            "the manifest lists {} sockets but {fds} arrived",
            manifest.sockets.len()
        ));
    }
    Ok(())
}

impl Inherited {
    /// Gives the listening sockets and the ticket keys to the data plane (before the first
    /// configuration is applied).
    pub(crate) fn hand_to(&mut self, plane: &DataPlane) -> Result<(), String> {
        plane
            .tickets()
            .import(std::mem::take(&mut self.ticket_keys));
        let mut sockets = Vec::new();
        for (entry, fd) in std::mem::take(&mut self.listeners) {
            let SocketEntry::Listener {
                name,
                address,
                udp,
                options,
            } = entry
            else {
                continue;
            };
            let socket = rdock_proxy::listener::Socket::from_fd(fd, udp)
                .map_err(|e| format!("listener `{name}` handed over unusable: {e}"))?;
            sockets.push(InheritedSocket {
                address,
                socket,
                options,
            });
        }
        plane.inherit(sockets);
        Ok(())
    }

    /// Tells the old process that everything is built, then waits for `go` without blocking
    /// the runtime. An error means the old process is gone or gave up: this process exits.
    pub(crate) async fn ready_and_wait(&self) -> Result<(), String> {
        if super::fault().as_deref() == Some("exit-before-ready") {
            return Err("fault injected: exit before ready".into());
        }
        self.channel
            .send(&Message::Ready, &[])
            .map_err(|e| format!("cannot report ready: {e}"))?;
        if super::fault().as_deref() == Some("exit-after-ready") {
            return Err("fault injected: exit after ready".into());
        }
        let reader = self.channel.try_clone().map_err(|e| e.to_string())?;
        tokio::task::spawn_blocking(move || reader.expect("go", None).map(|_| ()))
            .await
            .map_err(|_| "the handover reader stopped".to_owned())?
            .map_err(|e| format!("no `go` from the old process: {e}"))
    }

    /// Reports `serving` and follows the old process's drain reports until it exits.
    pub(crate) fn serving(self, plane: Arc<DataPlane>) -> Result<(), String> {
        self.channel
            .send(
                &Message::Serving {
                    pid: std::process::id(),
                },
                &[],
            )
            .map_err(|e| format!("cannot report serving: {e}"))?;
        let metrics = plane.metrics().clone();
        metrics
            .upgrade_drain_deadline
            .set(i64::try_from(self.drain_deadline).unwrap_or(i64::MAX));
        let channel = self.channel;
        let runtime = tokio::runtime::Handle::current();
        std::thread::Builder::new()
            .name("rdock-upgrade".into())
            .spawn(move || {
                loop {
                    match channel.recv(None) {
                        Ok((Message::Draining { connections }, _)) => metrics
                            .upgrade_draining_connections
                            .set(i64::try_from(connections).unwrap_or(i64::MAX)),
                        Ok((Message::Quota { counters }, _)) => {
                            let quotas = plane.quotas().clone();
                            runtime.spawn_blocking(move || {
                                let known = quotas.counters();
                                for counter in counters {
                                    if let Some((_, c)) =
                                        known.iter().find(|(name, _)| *name == counter.name)
                                    {
                                        c.add_increments(counter.start, &counter.increments);
                                    }
                                }
                            });
                        }
                        Ok((Message::Done, _)) | Err(_) => break,
                        Ok(_) => {}
                    }
                }
                metrics.upgrade_draining_connections.set(0);
                metrics.upgrade_drain_deadline.set(0);
            })
            .map(|_| ())
            .map_err(|e| format!("cannot follow the old process: {e}"))
    }
}
