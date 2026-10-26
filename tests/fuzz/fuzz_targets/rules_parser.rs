//! The rule parser never panics, and the canonical form of a parsed rule parses to the same AST.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| rdock_fuzz::rules_parser(data));
