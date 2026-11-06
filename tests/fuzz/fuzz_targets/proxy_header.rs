//! PROXY protocol header parsing never panics and round-trips (M-L4-03).
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| rdock_fuzz::proxy_header(data));
