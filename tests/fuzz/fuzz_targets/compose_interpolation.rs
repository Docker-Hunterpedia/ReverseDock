//! Compose interpolation and `rdock migrate traefik`: no panic, `$`-free text unchanged, no accounting error.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| rdock_fuzz::compose_interpolation(data));
