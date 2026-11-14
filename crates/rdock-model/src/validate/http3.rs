//! HTTP/3 settings of listeners (H-PERF-05, ADR-0032). Every value is bounded: the QUIC side has
//! no `unlimited`.

use super::{Validator, protocol_name};
use crate::config::{Http3Congestion, ListenerHttp3, ListenerProtocol};
use crate::diagnostics::{Diagnostic, path_key};

/// `advertise_max_age` bounds: 1 s to 30 days.
const MAX_AGE: (u64, u64) = (1, 30 * 86_400);
/// `max_idle` bounds: 1 s to 10 minutes.
const MAX_IDLE: (u64, u64) = (1, 600);
/// `max_concurrent_streams` ceiling (the HTTP/2 ceiling, ADR-0031).
const MAX_STREAMS: u32 = 10_000;
/// `max_header_size` floor.
const MIN_HEADER_SIZE: u64 = 1 << 10;
/// `max_connections` ceiling.
const MAX_CONNECTIONS: u32 = 1_000_000;
/// `client_ipv6_prefix` bounds.
const IPV6_PREFIX: (u8, u8) = (32, 128);
/// `stream_receive_window` bounds: 16 KiB to 16 MiB.
const STREAM_WINDOW: (u64, u64) = (16 << 10, 16 << 20);
/// `receive_window` and `send_window` bounds: 64 KiB to 64 MiB.
const CONNECTION_WINDOW: (u64, u64) = (64 << 10, 64 << 20);

impl Validator<'_> {
    pub(super) fn check_http3(&mut self) {
        for (name, listener) in &self.config.listeners {
            let Some(h3) = &listener.http3 else { continue };
            let base = format!("{}.http3", path_key("listeners", name));
            let protocol = listener.effective_protocol();
            if protocol != ListenerProtocol::Https {
                self.push(
                    Diagnostic::error(
                        base.clone(),
                        format!(
                            "`http3` applies to `https` listeners only; this one is `{}`",
                            protocol_name(protocol)
                        ),
                    )
                    .with_hint("HTTP/3 always runs over TLS 1.3 inside QUIC"),
                );
                continue;
            }
            self.check_http3_values(&base, h3);
            if !h3.enabled {
                continue;
            }
            // The listener owns the UDP socket of its address: a `udp` listener there would
            // take its datagrams.
            for (other_name, other) in &self.config.listeners {
                if other.effective_protocol() == ListenerProtocol::Udp
                    && other.address.overlaps(&listener.address)
                {
                    self.push(
                        Diagnostic::error(
                            format!("{base}.enabled"),
                            format!(
                                "the UDP port of `{}` belongs to HTTP/3 here, but the `udp` listener `{other_name}` (`{}`) uses it",
                                listener.address, other.address
                            ),
                        )
                        .with_hint("move the `udp` listener to another port or turn HTTP/3 off"),
                    );
                }
            }
        }
    }

    fn check_http3_values(&mut self, base: &str, h3: &ListenerHttp3) {
        let in_range = |value: u64, (min, max): (u64, u64)| (min..=max).contains(&value);
        if !in_range(h3.advertise_max_age.as_std().as_secs(), MAX_AGE)
            || h3.advertise_max_age.as_std().subsec_nanos() != 0
        {
            self.error(
                format!("{base}.advertise_max_age"),
                "must be whole seconds between 1s and 30d",
            );
        }
        if h3.advertise_port == Some(0) {
            self.error(format!("{base}.advertise_port"), "must be a port (1-65535)");
        }
        if !in_range(h3.max_idle.as_std().as_secs(), MAX_IDLE) {
            self.error(format!("{base}.max_idle"), "must be between 1s and 10m");
        }
        if !(1..=MAX_STREAMS).contains(&h3.max_concurrent_streams) {
            self.error(
                format!("{base}.max_concurrent_streams"),
                format!("must be between 1 and {MAX_STREAMS}"),
            );
        }
        let ceiling = ListenerHttp3::MAX_HEADER_SIZE_CEILING.as_u64();
        if !(MIN_HEADER_SIZE..=ceiling).contains(&h3.max_header_size.as_u64()) {
            self.push(
                Diagnostic::error(
                    format!("{base}.max_header_size"),
                    format!("must be between {MIN_HEADER_SIZE} and {ceiling} bytes"),
                )
                .with_hint("the header section of HTTP/3 requests is always bounded (ADR-0032)"),
            );
        }
        if !(1..=MAX_CONNECTIONS).contains(&h3.max_connections) {
            self.error(
                format!("{base}.max_connections"),
                format!("must be between 1 and {MAX_CONNECTIONS}"),
            );
        }
        if h3.max_connections_per_client == 0 || h3.max_connections_per_client > h3.max_connections
        {
            self.error(
                format!("{base}.max_connections_per_client"),
                "must be between 1 and `max_connections`",
            );
        }
        self.check_http3_memory(base, h3);
        if h3.congestion == Http3Congestion::Bbr {
            self.warning(
                format!("{base}.congestion"),
                "quinn 0.11 marks its BBR implementation experimental",
            );
        }
    }

    /// The client prefix, the flow-control windows and the worst-case memory they allow.
    fn check_http3_memory(&mut self, base: &str, h3: &ListenerHttp3) {
        if !(IPV6_PREFIX.0..=IPV6_PREFIX.1).contains(&h3.client_ipv6_prefix) {
            self.error(
                format!("{base}.client_ipv6_prefix"),
                format!(
                    "must be between {} and {} bits",
                    IPV6_PREFIX.0, IPV6_PREFIX.1
                ),
            );
        }
        let window =
            |v: &crate::values::ByteSize, (min, max): (u64, u64)| (min..=max).contains(&v.as_u64());
        if !window(&h3.stream_receive_window, STREAM_WINDOW) {
            self.error(
                format!("{base}.stream_receive_window"),
                "must be between 16KiB and 16MiB",
            );
        }
        for (key, value) in [
            ("receive_window", &h3.receive_window),
            ("send_window", &h3.send_window),
        ] {
            if !window(value, CONNECTION_WINDOW) {
                self.error(format!("{base}.{key}"), "must be between 64KiB and 64MiB");
            }
        }
        if h3.stream_receive_window > h3.receive_window {
            self.error(
                format!("{base}.stream_receive_window"),
                "must be at most `receive_window`",
            );
        }
        if h3.max_header_size > h3.receive_window {
            self.push(
                Diagnostic::error(
                    format!("{base}.max_header_size"),
                    "must be at most `receive_window`",
                )
                .with_hint(
                    "the incomplete header sections of a connection are held within `receive_window`",
                ),
            );
        }
        let memory = h3.worst_case_memory();
        if memory > ListenerHttp3::MEMORY_WARNING {
            self.push(
                Diagnostic::warning(
                    format!("{base}.max_connections"),
                    format!(
                        "the QUIC connections of this listener may hold up to {} MiB (max_connections × (2 × receive_window + send_window)), more than {} MiB",
                        memory >> 20,
                        ListenerHttp3::MEMORY_WARNING >> 20
                    ),
                )
                .with_hint("lower `max_connections` or the windows unless the host has this memory to spare"),
            );
        }
    }
}
