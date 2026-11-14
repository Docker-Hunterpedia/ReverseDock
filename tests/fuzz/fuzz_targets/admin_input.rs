//! Every admin request body and query string, user names, token values and TOTP codes: refusals only.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| rdock_fuzz::admin_input(data));
