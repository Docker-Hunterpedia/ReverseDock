//! Listener socket options, the TLS handshake bound and the runtime (H-PERF-01, ADR-0031).

use super::Validator;
use crate::config::{Listener, ListenerProtocol};
use crate::diagnostics::{Diagnostic, path_key};

/// Largest backlog accepted; the kernel caps it at `net.core.somaxconn` anyway.
const MAX_BACKLOG: u32 = 65_535;
/// Largest socket buffer accepted (the kernel caps it at `net.core.rmem_max`/`wmem_max`).
const MAX_BUFFER: u64 = 1 << 30;
/// Largest DSCP value (six bits).
const MAX_DSCP: u8 = 63;

impl Validator<'_> {
    pub(super) fn check_sockets(&mut self) {
        for (name, listener) in &self.config.listeners {
            let path = path_key("listeners", name);
            self.check_listener_socket(&path, listener);
            self.check_max_handshakes(&path, listener);
        }
        self.check_runtime();
    }

    fn check_listener_socket(&mut self, path: &str, listener: &Listener) {
        let socket = &listener.socket();
        let base = format!("{path}.socket");
        self.check_socket_transport(&base, listener);
        self.check_socket_values(&base, listener);
        // Options this platform cannot set are refused rather than ignored.
        if !cfg!(target_os = "linux") {
            for (field, set) in [
                ("user_timeout", socket.user_timeout.is_some()),
                ("fast_open", socket.fast_open.is_some()),
            ] {
                if set {
                    self.error(
                        format!("{base}.{field}"),
                        format!("`{field}` is only supported on Linux"),
                    );
                }
            }
        }
        if !cfg!(unix) && socket.reuse_port {
            self.error(
                format!("{base}.reuse_port"),
                "`reuse_port` is only supported on Unix",
            );
        }
    }

    /// Options that do not apply to a `udp` listener.
    fn check_socket_transport(&mut self, base: &str, listener: &Listener) {
        let socket = &listener.socket();
        let udp = listener.effective_protocol() == ListenerProtocol::Udp;
        // Options of TCP and its accepted connections.
        let tcp_only = [
            ("backlog", socket.backlog.is_some()),
            ("keepalive", socket.keepalive.is_some()),
            ("user_timeout", socket.user_timeout.is_some()),
            ("fast_open", socket.fast_open.is_some()),
        ];
        if udp {
            for (field, set) in tcp_only {
                if set {
                    self.error(
                        format!("{base}.{field}"),
                        format!("`{field}` is a TCP option; this listener is `udp`"),
                    );
                }
            }
            if socket.reuse_port {
                self.push(
                    Diagnostic::error(
                        format!("{base}.reuse_port"),
                        "`reuse_port` is not supported on `udp` listeners",
                    )
                    .with_hint(
                        "with several sockets on one port, a client's datagrams could reach a socket that does not hold its session (ADR-0031)",
                    ),
                );
            }
        }
    }

    /// Ranges.
    fn check_socket_values(&mut self, base: &str, listener: &Listener) {
        let socket = &listener.socket();
        if let Some(backlog) = socket.backlog
            && !(1..=MAX_BACKLOG).contains(&backlog)
        {
            self.error(
                format!("{base}.backlog"),
                format!("must be between 1 and {MAX_BACKLOG}"),
            );
        }
        for (field, size) in [
            ("receive_buffer", socket.receive_buffer),
            ("send_buffer", socket.send_buffer),
        ] {
            if let Some(size) = size
                && !(1..=MAX_BUFFER).contains(&size.as_u64())
            {
                self.error(
                    format!("{base}.{field}"),
                    "must be between 1 byte and 1 GiB",
                );
            }
        }
        if let Some(keepalive) = &socket.keepalive {
            for (field, zero) in [
                (
                    "idle",
                    keepalive.idle.is_some_and(|d| d.as_std().as_secs() == 0),
                ),
                (
                    "interval",
                    keepalive
                        .interval
                        .is_some_and(|d| d.as_std().as_secs() == 0),
                ),
                ("count", keepalive.count == Some(0)),
            ] {
                if zero {
                    self.error(
                        format!("{base}.keepalive.{field}"),
                        "must be at least 1 (seconds for durations)",
                    );
                }
            }
        }
        if socket
            .user_timeout
            .is_some_and(|d| d.as_std().as_millis() == 0)
        {
            self.error(format!("{base}.user_timeout"), "must be greater than zero");
        }
        if socket.fast_open == Some(0) {
            self.error(format!("{base}.fast_open"), "must be greater than zero");
        }
        if socket.dscp.is_some_and(|d| d > MAX_DSCP) {
            self.error(
                format!("{base}.dscp"),
                format!("must be between 0 and {MAX_DSCP}"),
            );
        }
        if socket.ipv6_only.is_some() && listener.address.ip().is_some_and(|ip| ip.is_ipv4()) {
            self.error(
                format!("{base}.ipv6_only"),
                format!(
                    "`ipv6_only` applies to IPv6 and all-interfaces addresses; `{}` is IPv4",
                    listener.address
                ),
            );
        }
    }

    /// `tls.max_handshakes` on a `tcp` listener is reported by the gate (planned); `http`
    /// and `udp` listeners have no `tls` at all.
    fn check_max_handshakes(&mut self, path: &str, listener: &Listener) {
        if listener.tls.as_ref().and_then(|t| t.max_handshakes) == Some(0) {
            self.error(
                format!("{path}.tls.max_handshakes"),
                "must be greater than zero",
            );
        }
    }

    fn check_runtime(&mut self) {
        let runtime = self.config.runtime.unwrap_or_default();
        for (field, value) in [
            ("worker_threads", runtime.worker_threads),
            ("max_blocking_threads", runtime.max_blocking_threads),
        ] {
            if value == Some(0) {
                self.error(format!("runtime.{field}"), "must be greater than zero");
            }
        }
    }
}
