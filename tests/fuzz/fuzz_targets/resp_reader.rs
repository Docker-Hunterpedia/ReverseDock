//! Redis replies (RESP2): never a panic or an oversized reply; an encoded command reads back.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| rdock_fuzz::resp_reader(data));
