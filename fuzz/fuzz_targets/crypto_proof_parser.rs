#![no_main]
use libfuzzer_sys::fuzz_target;
use tsn_crypto::proof::{Proof, verify_proof};

fuzz_target!(|data: &[u8]| {
    // Try to deserialize a proof from arbitrary bytes
    match Proof::from_bytes(data) {
        Ok(proof) => {
            // Proof verification should handle invalid proofs gracefully
            let public_inputs = vec![0u8; 32]; // Dummy inputs
            let _ = verify_proof(&proof, &public_inputs);
        }
        Err(_) => {
            // Invalid proof bytes should not cause panics
        }
    }
});