//! Docker label translation: no panic, deterministic, and a container that is not exposed gets no route.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| rdock_fuzz::docker_labels(data));
