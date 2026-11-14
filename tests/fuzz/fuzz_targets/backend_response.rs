//! A backend's response head: connection-specific headers removed, the rest kept, one head written back, the `Retry-After` pause capped.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| rdock_fuzz::backend_response(data));
