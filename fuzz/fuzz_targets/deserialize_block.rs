#![no_main]
use libfuzzer_sys::fuzz_target;
use tsn_crypto::proof::Proof;

fuzz_target!(|data: &[u8]| {
    let _ = Proof::deserialize(data);
});