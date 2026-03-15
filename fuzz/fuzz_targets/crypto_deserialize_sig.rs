#![no_main]
use libfuzzer_sys::fuzz_target;
use tsn_crypto::signature::Signature;

fuzz_target!(|data: &[u8]| {
    // Signature ML-DSA-65 fait 2420 bytes
    let _ = Signature::from_bytes(data);
});