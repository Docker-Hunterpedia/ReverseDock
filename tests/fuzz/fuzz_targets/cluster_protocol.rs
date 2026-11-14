//! Compressed and JSON bundles and messages from the control plane: the bundle checks hold.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| rdock_fuzz::cluster_protocol(data));
