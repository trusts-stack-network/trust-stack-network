#![no_main]
use libfuzzer_sys::fuzz_target;
use tsn_crypto::proof::{Proof, verify_proof};
use tsn_crypto::commitment::Commitment;

fuzz_target!(|data: &[u8]| {
    if data.len() < 128 {
        return;
    }
    
    // Fuzz la vérification de proof avec inputs malformés
    let proof = Proof::from_bytes(data);
    let commitment = Commitment::default();
    
    let _ = verify_proof(&proof, &commitment);
});