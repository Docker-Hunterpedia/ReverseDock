//! A CA's `Retry-After`, ARI windows and stored ACME records: never a panic, never a wait beyond the cap.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| rdock_fuzz::acme_answers(data));
