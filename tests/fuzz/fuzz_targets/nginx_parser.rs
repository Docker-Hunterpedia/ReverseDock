//! The NGINX configuration parser of `rdock migrate nginx` never panics, keeps its nesting limit,
//! and reads a printed tree back to the same tree.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| rdock_fuzz::nginx_parser(data));
