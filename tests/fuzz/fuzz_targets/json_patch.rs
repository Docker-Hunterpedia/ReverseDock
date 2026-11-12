//! JSON Pointer parsing and JSON Patch application for `transform` (F-GW-04, ADR-0030): never
//! a panic, pointers round-trip through escaping, and a patch is all or nothing.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| rdock_fuzz::json_patch(data));
