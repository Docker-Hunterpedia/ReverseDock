//! `rdock migrate caddy` on arbitrary JSON: no panic, no accounting error, YAML that reads.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| rdock_fuzz::migrate_caddy(data));
