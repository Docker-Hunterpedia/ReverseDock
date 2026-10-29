//! JWT verification never panics on any input (RFC 7515 parsing, key selection, claims).
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| rdock_fuzz::jwt_verify(data));
