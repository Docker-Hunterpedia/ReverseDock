//! HTTP/2 settings of listeners (H-PERF-03, ADR-0031). Ranges follow RFC 9113 §6.5.2; the
//! limits that protect against floods can be removed only with the word `unlimited`.

use super::Validator;
use crate::config::{FloodLimit, ListenerProtocol};
use crate::diagnostics::{Diagnostic, path_key};

/// Largest flow-control window (RFC 9113 §6.5.2, `SETTINGS_INITIAL_WINDOW_SIZE`).
const MAX_WINDOW: u64 = (1 << 31) - 1;
/// The protocol's initial window; the connection window cannot start below it.
const INITIAL_WINDOW: u64 = 65_535;
/// `SETTINGS_MAX_FRAME_SIZE` bounds (RFC 9113 §6.5.2).
const MIN_FRAME: u64 = 16_384;
const MAX_FRAME: u64 = 16_777_215;

impl Validator<'_> {
    pub(super) fn check_http2(&mut self) {
        for (name, listener) in &self.config.listeners {
            let Some(h2) = &listener.http2 else { continue };
            let base = format!("{}.http2", path_key("listeners", name));
            let protocol = listener.effective_protocol();
            if matches!(protocol, ListenerProtocol::Tcp | ListenerProtocol::Udp) {
                self.error(
                    base.clone(),
                    "`http2` applies to `http` and `https` listeners only",
                );
                continue;
            }
            for (field, value, ceiling) in [
                ("max_concurrent_streams", h2.max_concurrent_streams, 10_000),
                (
                    "max_pending_accept_reset_streams",
                    h2.max_pending_accept_reset_streams,
                    10_000,
                ),
                (
                    "max_local_error_reset_streams",
                    h2.max_local_error_reset_streams,
                    100_000,
                ),
            ] {
                match value {
                    Some(FloodLimit::Count(0)) => {
                        self.error(format!("{base}.{field}"), "must be greater than zero");
                    }
                    Some(FloodLimit::Count(n)) if n > ceiling => self.push(
                        Diagnostic::error(
                            format!("{base}.{field}"),
                            format!("{n} is above the ceiling of {ceiling}; to remove this flood limit, write `unlimited`"),
                        )
                        .with_hint("a limit this high protects nothing; `unlimited` says so explicitly"),
                    ),
                    Some(FloodLimit::Unlimited) => self.warning(
                        format!("{base}.{field}"),
                        "`unlimited` removes a protection against HTTP/2 floods",
                    ),
                    _ => {}
                }
            }
            let ranges = [
                (
                    "initial_stream_window",
                    h2.initial_stream_window,
                    1,
                    MAX_WINDOW,
                ),
                (
                    "initial_connection_window",
                    h2.initial_connection_window,
                    INITIAL_WINDOW,
                    MAX_WINDOW,
                ),
                ("max_frame_size", h2.max_frame_size, MIN_FRAME, MAX_FRAME),
                (
                    "max_header_list_size",
                    h2.max_header_list_size,
                    1 << 10,
                    16 << 20,
                ),
                ("max_send_buffer", h2.max_send_buffer, 16 << 10, 16 << 20),
            ];
            for (field, value, min, max) in ranges {
                if let Some(size) = value
                    && !(min..=max).contains(&size.as_u64())
                {
                    self.error(
                        format!("{base}.{field}"),
                        format!("must be between {min} and {max} bytes"),
                    );
                }
            }
        }
    }
}
