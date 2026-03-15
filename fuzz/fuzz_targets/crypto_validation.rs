#![no_main]
use libfuzzer_sys::fuzz_target;
use tsn_crypto::{
    signature::{Signature, verify_signature},
    keys::PublicKey,
    commitment::Commitment,
    nullifier::Nullifier,
};

fuzz_target!(|data: &[u8]| {
    // Fuzz la validation de signature
    if data.len() >= 64 {
        let sig_bytes = &data[0..64];
        let msg = &data[64..];
        
        let sig = Signature::from_bytes(sig_bytes);
        let pubkey = PublicKey::from_bytes(&[0u8; 32]); // Clé dummy
        
        // Ne devrait pas paniquer même avec des inputs invalides
        let _ = verify_signature(&sig, msg, &pubkey);
    }
    
    // Fuzz la validation de commitment
    if data.len() >= 32 {
        let commitment_bytes = &data[0..32];
        let commitment = Commitment::from_bytes(commitment_bytes);
        
        // Vérifier que la validation ne panique pas
        let _ = commitment.validate();
    }
    
    // Fuzz la validation de nullifier
    if data.len() >= 32 {
        let nullifier_bytes = &data[0..32];
        let nullifier = Nullifier::from_bytes(nullifier_bytes);
        
        // Vérifier que la validation ne panique pas
        let _ = nullifier.validate();
    }
});