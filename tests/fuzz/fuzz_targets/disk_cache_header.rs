//! The disk cache store's file-header decoder (F-WEB-03, ADR-0030) rejects arbitrary bytes
//! without panicking or allocating without bound; whatever header decodes is handed to
//! pingora-cache's `CacheMeta` decoder, which must not panic either.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| rdock_cache::fuzz_decode_disk_header(data));
