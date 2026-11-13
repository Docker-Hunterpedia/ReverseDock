//! HTTP/3 request headers: our QPACK decoding, validation and mapping never panic, round-trip,
//! and never produce an HTTP/1.1 head that frames differently (H-PERF-05, ADR-0032).
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| rdock_fuzz::http3_request(data));
