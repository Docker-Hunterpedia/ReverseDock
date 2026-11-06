//! The ClientHello peek never panics and never claims more bytes than it was given.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| rdock_fuzz::clienthello(data));
