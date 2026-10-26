//! Differential HTTP/1 framing: what the proxy forwards must be exactly one request.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| rdock_fuzz::h1_framing(data));
