#![no_main]
use libfuzzer_sys::fuzz_target;
use tsn::crypto::{
    keys::{PublicKey, PrivateKey, Signature},
    commitment::Commitment,
    nullifier::Nullifier,
    note::Note,
    address::Address,
    proof::Proof
};

/// Fuzzer pour la désérialisation de structures cryptographiques
fuzz_target!(|data: &[u8]| {
    // Test désérialisation clé publique
    if data.len() >= 32 {
        let _ = PublicKey::from_bytes(&data[..32]);
    }
    
    // Test désérialisation signature
    if data.len() >= 64 {
        let _ = Signature::from_bytes(&data[..64]);
    }
    
    // Test désérialisation commitment
    if data.len() >= 32 {
        let _ = Commitment::from_bytes(&data[..32]);
    }
    
    // Test désérialisation nullifier
    if data.len() >= 32 {
        let _ = Nullifier::from_bytes(&data[..32]);
    }
    
    // Test désérialisation note
    if data.len() >= 128 {
        let _ = Note::from_bytes(&data[..128]);
    }
    
    // Test désérialisation adresse
    if data.len() >= 20 {
        let _ = Address::from_bytes(&data[..20]);
    }
    
    // Test désérialisation preuve
    if data.len() >= 192 {
        let _ = Proof::from_bytes(&data[..192]);
    }
});