//! The configuration loader never panics on arbitrary YAML or JSON.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| rdock_fuzz::config_loader(data));
