//! Where listeners accept and serve connections (`runtime.model`, ADR-0026, #176).
//!
//! `steal` runs every listener on the caller's work-stealing runtime with one socket per
//! listener, as before. `per_core` starts one single-threaded tokio runtime per thread and gives
//! every listener one socket and one accept loop on each of them, so a connection is accepted,
//! served and proxied on one thread without waking another. On Linux each thread has its own
//! `SO_REUSEPORT` socket and the kernel spreads new connections across them by a hash of the
//! 4-tuple (socket(7)); elsewhere `SO_REUSEPORT` does not balance (macOS gives every connection
//! to one socket), so the threads accept from copies of one shared socket instead.

use std::future::Future;
use std::io;

use rdock_model::settings::{RuntimeModel, RuntimeSettings};
use rdock_model::values::ListenAddress;
use tokio::net::TcpListener;
use tokio::runtime::Handle;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

/// The threads the data plane's listeners run on, fixed for the life of the process.
pub(crate) struct Executor {
    settings: RuntimeSettings,
    threads: Threads,
}

enum Threads {
    /// The runtime that applies configurations (`steal`).
    Caller,
    /// One single-threaded runtime per thread (`per_core`).
    PerCore(Workers),
}

/// Running per-core threads. Dropping it ends them.
struct Workers {
    handles: Vec<Handle>,
    /// Never sent: dropping a sender ends its thread.
    _stop: Vec<oneshot::Sender<()>>,
}

impl Executor {
    /// Starts the threads `settings` asks for.
    pub(crate) fn start(settings: RuntimeSettings) -> io::Result<Self> {
        let threads = match settings.model {
            RuntimeModel::Steal => Threads::Caller,
            RuntimeModel::PerCore => {
                Threads::PerCore(Workers::start(settings.effective_threads())?)
            }
        };
        Ok(Self { settings, threads })
    }

    /// The settings these threads were started with.
    pub(crate) fn settings(&self) -> RuntimeSettings {
        self.settings
    }

    /// Opens the sockets of a listener on `address`: one for `steal`, one per thread for
    /// `per_core`, each registered with the runtime that accepts on it. Fails, like `steal`,
    /// when anything already listens on the address, rdock's own listeners included.
    pub(crate) fn bind(&self, address: &ListenAddress) -> io::Result<Vec<TcpListener>> {
        match &self.threads {
            Threads::Caller => {
                let socket = crate::listener::bind(address)?;
                Ok(vec![TcpListener::from_std(socket)?])
            }
            Threads::PerCore(workers) => workers.bind(address),
        }
    }

    /// Runs `task` on the thread that accepts on socket `index` of [`Executor::bind`].
    pub(crate) fn spawn<F>(&self, index: usize, task: F) -> JoinHandle<()>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        match &self.threads {
            Threads::Caller => tokio::spawn(task),
            Threads::PerCore(workers) => workers.handles[index % workers.handles.len()].spawn(task),
        }
    }
}

impl Workers {
    fn start(threads: usize) -> io::Result<Self> {
        let mut handles = Vec::with_capacity(threads);
        let mut stop = Vec::with_capacity(threads);
        for index in 0..threads {
            let (stop_tx, stop_rx) = oneshot::channel();
            handles.push(start_thread(index, stop_rx)?);
            stop.push(stop_tx);
        }
        tracing::info!(
            threads,
            "data plane runs one single-threaded runtime per thread (per_core)"
        );
        Ok(Self {
            handles,
            _stop: stop,
        })
    }

    #[cfg(target_os = "linux")]
    fn bind(&self, address: &ListenAddress) -> io::Result<Vec<TcpListener>> {
        // Sockets with SO_REUSEPORT share an address with any other such socket of the same
        // user, another rdock included; a plain bind first fails as `steal` would.
        drop(crate::listener::bind(address)?);
        let mut sockets = Vec::with_capacity(self.handles.len());
        for handle in &self.handles {
            let _runtime = handle.enter();
            // The others bind where the first did: the same family for `:port`, and the same
            // port when the address asks for any (`:0`).
            let socket = match sockets.first() {
                None => crate::listener::bind_any(address, reuseport_listener)?,
                Some(first) => reuseport_listener(TcpListener::local_addr(first)?)?,
            };
            sockets.push(socket);
        }
        Ok(sockets)
    }

    #[cfg(not(target_os = "linux"))]
    fn bind(&self, address: &ListenAddress) -> io::Result<Vec<TcpListener>> {
        let shared = crate::listener::bind(address)?;
        self.handles
            .iter()
            .map(|handle| {
                let _runtime = handle.enter();
                TcpListener::from_std(shared.try_clone()?)
            })
            .collect()
    }
}

/// Starts per-core thread `index`, which runs its runtime until `stop`'s sender is dropped.
/// The runtime is built on the thread so it is also dropped there, never inside the caller's
/// runtime (tokio refuses that).
fn start_thread(index: usize, stop: oneshot::Receiver<()>) -> io::Result<Handle> {
    let (started_tx, started_rx) = std::sync::mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name(format!("rdock-core-{index}"))
        .spawn(move || {
            match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => {
                    let _ = started_tx.send(Ok(runtime.handle().clone()));
                    runtime.block_on(async {
                        let _ = stop.await;
                    });
                }
                Err(err) => {
                    let _ = started_tx.send(Err(err));
                }
            }
        })?;
    started_rx
        .recv()
        .map_err(|_| io::Error::other("a per-core thread ended while starting"))?
}

/// Backlog of each per-core socket: the one `std::net::TcpListener::bind` uses, so a socket
/// queues as many connections in both models.
#[cfg(target_os = "linux")]
const BACKLOG: u32 = 128;

/// A listening socket with `SO_REUSEPORT`, registered with the current runtime. Like
/// `std::net::TcpListener::bind` it also sets `SO_REUSEADDR`.
#[cfg(target_os = "linux")]
fn reuseport_listener(address: std::net::SocketAddr) -> io::Result<TcpListener> {
    let socket = if address.is_ipv6() {
        tokio::net::TcpSocket::new_v6()?
    } else {
        tokio::net::TcpSocket::new_v4()?
    };
    socket.set_reuseaddr(true)?;
    socket.set_reuseport(true)?;
    socket.bind(address)?;
    socket.listen(BACKLOG)
}

#[cfg(test)]
mod tests {
    use rdock_model::settings::{RuntimeModel, RuntimeSettings};
    use rdock_model::values::ListenAddress;

    use super::Executor;

    fn per_core(threads: u16) -> Executor {
        Executor::start(RuntimeSettings {
            model: RuntimeModel::PerCore,
            threads: Some(threads),
        })
        .unwrap()
    }

    fn loopback(port: u16) -> ListenAddress {
        ListenAddress::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), port)
    }

    #[tokio::test]
    async fn steal_binds_one_socket() {
        let executor = Executor::start(RuntimeSettings::default()).unwrap();
        assert_eq!(executor.bind(&loopback(0)).unwrap().len(), 1);
    }

    #[tokio::test]
    async fn per_core_binds_one_socket_per_thread_on_one_address() {
        let executor = per_core(3);
        let first = executor.bind(&loopback(0)).unwrap();
        let port = first[0].local_addr().unwrap().port();
        let sockets = executor.bind(&loopback(port));
        assert!(
            sockets.is_err(),
            "an address in use must not be bound again"
        );
        drop(first);
        let sockets = executor.bind(&loopback(port)).unwrap();
        assert_eq!(sockets.len(), 3);
        assert!(
            sockets
                .iter()
                .all(|s| s.local_addr().unwrap().port() == port)
        );
    }

    #[tokio::test]
    async fn per_core_tasks_run_on_their_own_threads() {
        let executor = per_core(2);
        let mut names = Vec::new();
        for index in 0..2 {
            let (tx, rx) = tokio::sync::oneshot::channel();
            executor.spawn(index, async move {
                let _ = tx.send(std::thread::current().name().map(str::to_owned));
            });
            names.push(rx.await.unwrap());
        }
        assert_eq!(
            names,
            [
                Some("rdock-core-0".to_owned()),
                Some("rdock-core-1".to_owned())
            ]
        );
    }
}
