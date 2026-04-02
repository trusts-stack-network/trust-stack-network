#![no_main]
use libfuzzer_sys::fuzz_target;
use tsn_crypto::poseidon::hash;

fuzz_target!(|data: &[u8]| {
    // Doit terminer