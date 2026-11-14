//! Rule evaluation against arbitrary requests: verdict, explanation, negation and canonical form agree; the forwarded path normalises to itself.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| rdock_fuzz::rules_eval(data));
