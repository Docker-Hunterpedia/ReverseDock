//! The `oidc` cookie decoder never panics on any input (cookie header splitting, chunk
//! joining, base64url, AEAD opening, JSON).
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| rdock_fuzz::oidc_cookie(data));
