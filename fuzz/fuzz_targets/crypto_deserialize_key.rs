#![no_main]
use libfuzzer_sys::fuzz_target;
use tsn_crypto::keys::PublicKey;

fuzz_target!(|data: &[u8]| {
    // Le parser doit jamais paniquer
    let _ = PublicKey::from_bytes(data);
});