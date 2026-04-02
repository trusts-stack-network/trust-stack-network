#![no_main]

use libfuzzer_sys::fuzz_target;
use trust_stack_network::crypto::legacy_vulnerable::derive_key_vulnerable;

fuzz_target!(|data: &[u8]| {
    // Test that key derivation doesn't panic on any input
    let _ = derive_key_vulnerable(data);
});