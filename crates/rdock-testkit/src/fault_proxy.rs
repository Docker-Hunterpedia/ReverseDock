//! A TCP proxy that can fail on command, for the rootless chaos tests (ADR-0033): what the
//! Toxiproxy-based tests do with Docker, without Docker. It forwards to one upstream
//! ([`Fault::Pass`]), resets every connection at once ([`Fault::Reset`], a backend that went
//! away), or accepts and never forwards ([`Fault::Blackhole`], a backend that hangs). A switch
//! away from `Pass` cuts the connections open at that moment.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};

use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

/// What the proxy does with connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    /// Forwards.
    Pass,
    /// Closes each connection at once.
    Reset,
    /// Accepts and never forwards.
    Blackhole,
}

struct State {
    fault: Fault,
    connections: Vec<JoinHandle<()>>,
}

/// A running proxy.
pub struct FaultProxy {
    /// Where it listens.
    pub addr: SocketAddr,
    state: Arc<Mutex<State>>,
    accept: JoinHandle<()>,
}

impl Drop for FaultProxy {
    fn drop(&mut self) {
        self.accept.abort();
        for c in self
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .connections
            .drain(..)
        {
            c.abort();
        }
    }
}

impl FaultProxy {
    /// Listens on `127.0.0.1:<port>` and forwards to `upstream`.
    pub async fn start(port: u16, upstream: SocketAddr) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let state = Arc::new(Mutex::new(State {
            fault: Fault::Pass,
            connections: Vec::new(),
        }));
        let shared = state.clone();
        let accept = tokio::spawn(async move {
            while let Ok((mut client, _)) = listener.accept().await {
                let fault = shared.lock().unwrap_or_else(PoisonError::into_inner).fault;
                let task = tokio::spawn(async move {
                    match fault {
                        Fault::Reset => drop(client),
                        Fault::Blackhole => {
                            let _held = client;
                            std::future::pending::<()>().await;
                        }
                        Fault::Pass => {
                            if let Ok(mut server) = TcpStream::connect(upstream).await {
                                let _ =
                                    tokio::io::copy_bidirectional(&mut client, &mut server).await;
                            }
                        }
                    }
                });
                let mut state = shared.lock().unwrap_or_else(PoisonError::into_inner);
                state.connections.retain(|t| !t.is_finished());
                state.connections.push(task);
            }
        });
        Self {
            addr,
            state,
            accept,
        }
    }

    /// Switches the behaviour; leaving `Pass` cuts the open connections.
    pub fn set(&self, fault: Fault) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if fault != Fault::Pass {
            for c in state.connections.drain(..) {
                c.abort();
            }
        }
        state.fault = fault;
    }
}
