//! JA4 and JA3 of arbitrary bytes never panic and always have their fixed shape.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| rdock_fuzz::tls_fingerprint(data));
